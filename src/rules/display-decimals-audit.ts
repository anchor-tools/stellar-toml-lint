import {
  Account,
  Contract,
  Keypair,
  Networks,
  scValToNative,
  TransactionBuilder,
  xdr,
} from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleContext, RuleOverrides } from '../types.js';

const MAX_CLASSIC_DECIMALS = 7;
const CONTRACT_MISMATCH_RULE = 'currencies/display-decimals-contract-mismatch';

interface AuditOptions {
  fetchImpl?: typeof fetch;
  rules?: RuleOverrides;
}

function currenciesOf(doc: Record<string, unknown>): Record<string, unknown>[] {
  const currencies = doc.CURRENCIES;
  if (!Array.isArray(currencies)) return [];
  return currencies.filter(
    (entry): entry is Record<string, unknown> =>
      typeof entry === 'object' && entry !== null && !Array.isArray(entry),
  );
}

function networkPassphraseOf(doc: Record<string, unknown>): string | undefined {
  return typeof doc.NETWORK_PASSPHRASE === 'string' ? doc.NETWORK_PASSPHRASE : undefined;
}

function rpcUrlFor(passphrase: string | undefined): string | undefined {
  switch (passphrase) {
    case Networks.PUBLIC:
      return 'https://soroban-rpc.mainnet.stellar.org';
    case Networks.TESTNET:
      return 'https://soroban-testnet.stellar.org';
    case Networks.FUTURENET:
      return 'https://rpc-futurenet.stellar.org';
    default:
      return undefined;
  }
}
export { rpcUrlFor };

function severityFor(rule: string, fallback: 'error' | 'warning', rules?: RuleOverrides) {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

function classicLimitDiagnostics(ctx: RuleContext): void {
  if (!ctx.options.checkNetwork) return;

  currenciesOf(ctx.doc).forEach((entry, index) => {
    if (entry.toml !== undefined || entry.contract !== undefined) return;
    if (
      typeof entry.display_decimals !== 'number' ||
      entry.display_decimals <= MAX_CLASSIC_DECIMALS
    ) {
      return;
    }

    ctx.report({
      rule: 'currencies/display-decimals-exceeds-network-limit',
      category: 'currencies',
      severity: 'error',
      message: `CURRENCIES[${index}].display_decimals exceeds the network limit of 7`,
      path: `CURRENCIES[${index}].display_decimals`,
      position: ctx.locate(`CURRENCIES[${index}].display_decimals`),
      suggestion: 'Set display_decimals to 7 or fewer for a classic asset.',
    });
  });
}

async function contractDecimals(
  contract: string,
  passphrase: string,
  rpcUrl: string,
  fetchImpl: typeof fetch,
): Promise<number | undefined> {
  try {
    const transaction = new TransactionBuilder(new Account(Keypair.random().publicKey(), '0'), {
      fee: '100',
      networkPassphrase: passphrase,
    })
      .addOperation(new Contract(contract).call('decimals'))
      .setTimeout(30)
      .build();

    const response = await fetchImpl(rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'simulateTransaction',
        params: { transaction: transaction.toXDR() },
      }),
    });
    if (!response.ok) return undefined;

    const body = (await response.json()) as { result?: { retval?: string } };
    const retval = body.result?.retval;
    if (typeof retval !== 'string') return undefined;

    const value = scValToNative(xdr.ScVal.fromXDR(retval, 'base64'));
    return typeof value === 'number' && Number.isInteger(value) ? value : undefined;
  } catch {
    return undefined;
  }
}

export async function checkDisplayDecimals(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: AuditOptions = {},
): Promise<Diagnostic[]> {
  const passphrase = networkPassphraseOf(doc);
  const rpcUrl = rpcUrlFor(passphrase);
  if (!passphrase || !rpcUrl) return [];

  const diagnostics: Diagnostic[] = [];
  for (const [index, entry] of currenciesOf(doc).entries()) {
    if (entry.toml !== undefined || typeof entry.contract !== 'string') continue;
    if (typeof entry.display_decimals !== 'number') continue;

    const actual = await contractDecimals(entry.contract, passphrase, rpcUrl, fetchImpl);
    if (actual === undefined || actual === entry.display_decimals) continue;

    const severity = severityFor(CONTRACT_MISMATCH_RULE, 'warning', options.rules);
    if (severity === undefined) continue;
    const path = `CURRENCIES[${index}].display_decimals`;
    diagnostics.push({
      rule: CONTRACT_MISMATCH_RULE,
      severity,
      category: 'currencies',
      message: `${path} is ${entry.display_decimals}, but the contract reports ${actual}`,
      path,
      suggestion: `Set display_decimals to ${actual} to match the Soroban contract.`,
    });
  }

  return diagnostics;
}

export const displayDecimalsRules: Rule[] = [
  {
    id: 'currencies/display-decimals-exceeds-network-limit',
    category: 'currencies',
    severity: 'error',
    description:
      'Classic assets must not declare more than 7 display decimals during network checks',
    run: classicLimitDiagnostics,
  },
  {
    id: CONTRACT_MISMATCH_RULE,
    category: 'currencies',
    severity: 'warning',
    description: 'A Soroban contract decimals value should match display_decimals',
    run() {},
  },
];
