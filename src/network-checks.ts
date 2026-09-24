import {
  Account,
  Contract,
  Keypair,
  Networks,
  scValToNative,
  TransactionBuilder,
  xdr,
} from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides } from './types.js';
import { isContractId, isInteger, isString } from './predicates.js';
import { currenciesOf } from './rules/currencies.js';
import { rpcUrlFor } from './rules/display-decimals-audit.js';

const PUBLIC_PASSPHRASE = 'Public Global Stellar Network ; September 2015';
const TESTNET_PASSPHRASE = 'Test SDF Network ; September 2015';

/** The Horizon instance serving the network a passphrase names; mainnet by default. */
export function horizonUrlFor(passphrase: string | undefined): string {
  return passphrase === TESTNET_PASSPHRASE
    ? 'https://horizon-testnet.stellar.org'
    : 'https://horizon.stellar.org';
}

/**
 * The authorization flags Horizon reports for an account.
 *
 * SEP-8 regulated assets rely on two of them: `auth_required`, which lets the
 * issuer approve who may hold the asset, and `auth_revocable`, which lets the
 * issuer freeze a holder.
 */
export interface IssuerFlags {
  authRequired: boolean;
  authRevocable: boolean;
}

/**
 * Fetches the flags of one issuer account from Horizon.
 *
 * Returns `undefined` — never throws — when the flags cannot be verified: a
 * 404 (account does not exist), a non-200 response, or an unparseable body
 * give the caller nothing to assert, so it degrades those to a warning.
 */
export async function checkIssuerFlags(
  issuerId: string,
  horizonUrl: string,
  fetchImpl: typeof fetch = fetch,
): Promise<IssuerFlags | undefined> {
  try {
    const response = await fetchImpl(`${horizonUrl}/accounts/${issuerId}`);
    if (!response.ok) return undefined;
    const body = (await response.json()) as { flags?: Record<string, unknown> };
    const flags = body.flags;
    if (typeof flags !== 'object' || flags === null) return undefined;
    return {
      authRequired: flags.auth_required === true,
      authRevocable: flags.auth_revocable === true,
    };
  } catch {
    return undefined;
  }
}

export async function checkNetworkAccounts(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
): Promise<Diagnostic[]> {
  const diagnostics: Diagnostic[] = [];

  const passphrase =
    typeof doc.NETWORK_PASSPHRASE === 'string' ? doc.NETWORK_PASSPHRASE : PUBLIC_PASSPHRASE;
  const horizonUrl = horizonUrlFor(passphrase);

  const accountsToCheck: { id: string; path: string }[] = [];

  if (typeof doc.SIGNING_KEY === 'string') {
    accountsToCheck.push({ id: doc.SIGNING_KEY, path: 'SIGNING_KEY' });
  }

  if (Array.isArray(doc.ACCOUNTS)) {
    doc.ACCOUNTS.forEach((acc, index) => {
      if (typeof acc === 'string') {
        accountsToCheck.push({ id: acc, path: `ACCOUNTS[${index}]` });
      }
    });
  }

  for (const acc of accountsToCheck) {
    try {
      const response = await fetchImpl(`${horizonUrl}/accounts/${acc.id}`);
      if (response.status === 404) {
        diagnostics.push({
          rule: 'network/account-exists',
          severity: 'warning',
          category: 'network',
          message: `Account ${acc.id} does not exist on the network`,
          path: acc.path,
          suggestion: 'Ensure the account is created and funded on the correct network.',
        });
      }
    } catch {
      diagnostics.push({
        rule: 'network/account-exists',
        severity: 'warning',
        category: 'network',
        message: `Could not verify account ${acc.id} due to a network error`,
        path: acc.path,
      });
    }
  }

  return diagnostics;
}

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules: RuleOverrides | undefined,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}

/** What one `decimals()` simulation against the Soroban RPC established. */
type DecimalsOutcome =
  { kind: 'ok'; decimals: number } | { kind: 'not-a-token' } | { kind: 'outage'; detail: string };

/**
 * Simulates `decimals()` on the contract through the Soroban RPC.
 *
 * `decimals()` is the lightest reliable SEP-41 probe: it is a required
 * read-only method of the token interface, and the same value is needed to
 * compare against the file's `display_decimals` — so one round trip answers
 * both "does this contract exist and behave like a SEP-41 token" and "does the
 * declared precision match". A JSON-RPC error means the simulation failed
 * (missing contract, missing entrypoint, trap), which is exactly the not-a-token
 * verdict; transport and shape failures are reported as an outage so a flaky
 * RPC never accuses a correct contract.
 */
async function simulateDecimals(
  contract: string,
  passphrase: string,
  rpcUrl: string,
  fetchImpl: typeof fetch,
): Promise<DecimalsOutcome> {
  let response: Response;
  try {
    const transaction = new TransactionBuilder(new Account(Keypair.random().publicKey(), '0'), {
      fee: '100',
      networkPassphrase: passphrase,
    })
      .addOperation(new Contract(contract).call('decimals'))
      .setTimeout(30)
      .build();

    response = await fetchImpl(rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'simulateTransaction',
        params: { transaction: transaction.toXDR() },
      }),
    });
  } catch (error) {
    return { kind: 'outage', detail: errorMessage(error) };
  }

  if (!response.ok) {
    return { kind: 'outage', detail: `the Soroban RPC returned HTTP ${response.status}` };
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    return { kind: 'outage', detail: 'the Soroban RPC did not return valid JSON' };
  }
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    return { kind: 'outage', detail: 'the Soroban RPC did not return a JSON-RPC response' };
  }

  const payload = body as Record<string, unknown>;
  if (payload.error !== undefined && payload.error !== null) {
    return { kind: 'not-a-token' };
  }

  const retval = (payload.result as { retval?: unknown } | undefined)?.retval;
  if (typeof retval !== 'string') {
    return { kind: 'outage', detail: 'the Soroban RPC returned no simulation result' };
  }

  let value: unknown;
  try {
    value = scValToNative(xdr.ScVal.fromXDR(retval, 'base64'));
  } catch {
    return { kind: 'outage', detail: 'the Soroban RPC returned an unreadable simulation result' };
  }

  // SEP-41's decimals() returns u32; anything else is not the token shape.
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    return { kind: 'not-a-token' };
  }
  return { kind: 'ok', decimals: value };
}

/**
 * Opt-in SEP-41 audit of every `contract` currency entry, for `--check-network`.
 *
 * The offline checksum rule proves a contract ID is well-formed; it cannot
 * prove the contract exists or is a token at all — the same class of failure
 * the checksum rules catch for issuers, one level deeper. This verifies the
 * contract answers the SEP-41 `decimals()` accessor and agrees with the file's
 * `display_decimals`. Every finding is a warning, including one per contract
 * when the RPC cannot be reached, so an outage degrades the check instead of
 * failing a run it could not complete — and the offline default, which never
 * calls this, is unchanged.
 */
export async function checkSep41Contracts(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: { rules?: RuleOverrides } = {},
): Promise<Diagnostic[]> {
  const passphrase = isString(doc.NETWORK_PASSPHRASE) ? doc.NETWORK_PASSPHRASE : Networks.PUBLIC;
  const rpcUrl = rpcUrlFor(passphrase);
  if (rpcUrl === undefined) return [];

  const diagnostics: Diagnostic[] = [];

  for (const [index, entry] of currenciesOf(doc).entries()) {
    // Pointer entries define their currency in another file; ids that fail the
    // checksum are already reported offline by currencies/issuer-or-contract.
    if (entry.toml !== undefined) continue;
    if (!isString(entry.contract) || !isContractId(entry.contract)) continue;

    const contractPath = `CURRENCIES[${index}].contract`;
    const outcome = await simulateDecimals(entry.contract, passphrase, rpcUrl, fetchImpl);

    if (outcome.kind === 'outage') {
      const severity = severityFor(SEP41_UNVERIFIED_RULE, 'warning', options.rules);
      if (severity !== undefined) {
        diagnostics.push({
          rule: SEP41_UNVERIFIED_RULE,
          severity,
          category: 'currencies',
          message: `Could not verify ${contractPath} is a SEP-41 token: ${outcome.detail}`,
          path: contractPath,
          suggestion: 'Confirm the Soroban RPC for this network is reachable and re-run.',
        });
      }
      continue;
    }

    if (outcome.kind === 'not-a-token') {
      const severity = severityFor(SEP41_TOKEN_RULE, 'warning', options.rules);
      if (severity !== undefined) {
        diagnostics.push({
          rule: SEP41_TOKEN_RULE,
          severity,
          category: 'currencies',
          message: `${contractPath} does not exist on the network or does not implement the SEP-41 token interface`,
          path: contractPath,
          suggestion:
            'Check the contract ID for a transcription error, or point at a contract that answers the SEP-41 decimals() accessor.',
        });
      }
      continue;
    }

    const declared = entry.display_decimals;
    if (!isInteger(declared) || declared === outcome.decimals) continue;

    const severity = severityFor(CONTRACT_MISMATCH_RULE, 'warning', options.rules);
    if (severity === undefined) continue;
    const path = `CURRENCIES[${index}].display_decimals`;
    diagnostics.push({
      rule: CONTRACT_MISMATCH_RULE,
      severity,
      category: 'currencies',
      message: `${path} is ${declared}, but the contract reports ${outcome.decimals}`,
      path,
      suggestion: `Set display_decimals to ${outcome.decimals} to match the Soroban contract.`,
    });
  }

  return diagnostics;
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const sep41Rules: Rule[] = [
  {
    id: SEP41_TOKEN_RULE,
    category: 'currencies',
    severity: 'warning',
    description: 'Contract currencies must exist on the network and implement SEP-41',
    run() {},
  },
  {
    id: SEP41_UNVERIFIED_RULE,
    category: 'currencies',
    severity: 'warning',
    description: 'An unreachable Soroban RPC degrades SEP-41 verification to a warning',
    run() {},
  },
];
