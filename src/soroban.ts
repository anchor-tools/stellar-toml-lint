/**
 * Opt-in verification of Soroban contract liveliness.
 *
 * Contract state and the WASM blob behind a contract live on the ledger only
 * until their TTL expires; after that the storage is archived and the contract
 * can no longer be invoked. This audit queries the Soroban RPC's
 * `getLedgerEntries` for the contract instance and its WASM, compares each
 * `liveUntilLedgerSeq` against the network's `latestLedger`, and reports when
 * a renewal is due. Like the other network-bound checks it only runs under an
 * explicit flag (`--check-contracts`), never fails the run on an RPC outage,
 * and registers rule objects so `--list-rules` and `--off` know its ids.
 */
import { Address, xdr } from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides, Severity } from './types.js';
import { isString } from './predicates.js';
import { rpcUrlFor } from './rules/display-decimals-audit.js';
import { contractIdsOf } from './rules/currencies.js';
import { webAuthContractIdOf } from './rules/general.js';

/** Roughly a day of ledgers at ~5 seconds per ledger. */
const EXPIRING_WINDOW_LEDGERS = 17_280;

const TTL_EXPIRING_RULE = 'soroban/contract-ttl-expiring-soon';
const CONTRACT_EXPIRED_RULE = 'soroban/contract-expired';
const TTL_UNAVAILABLE_RULE = 'soroban/contract-ttl-unavailable';

interface ContractTtlOptions {
  rules?: RuleOverrides;
}

interface ContractAuditOptions extends ContractTtlOptions {
  rpcUrl?: string;
}

/** A contract to audit, with the file path that named it. */
interface ContractTarget {
  id: string;
  path: string;
}

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules?: RuleOverrides,
): Severity | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

/**
 * The ledger key of a contract's instance entry. A contract instance is a
 * single key in the `ContractData` table with the special
 * `ledgerKeyContractInstance` scval as its key.
 */
function contractDataInstanceKey(contractId: string): string {
  const key = xdr.LedgerKey.contractData(
    new xdr.LedgerKeyContractData({
      contract: new Address(contractId).toScAddress(),
      key: xdr.ScVal.scvLedgerKeyContractInstance(),
      durability: xdr.ContractDataDurability.persistent(),
    }),
  );
  return key.toXDR('base64');
}

/** The ledger key of the WASM blob a contract instance points at. */
function contractCodeKey(wasmHash: Buffer): string {
  const key = xdr.LedgerKey.contractCode(new xdr.LedgerKeyContractCode({ hash: wasmHash }));
  return key.toXDR('base64');
}

/**
 * The WASM hash referenced by a contract's instance entry, or `undefined`
 * when the entry does not describe a contract executable as WASM.
 */
function wasmHashOf(entryXdr: unknown): Buffer | undefined {
  if (!isString(entryXdr)) return undefined;
  try {
    const data = xdr.LedgerEntryData.fromXDR(entryXdr, 'base64');
    const contractData = data.contractData();
    const val = contractData.val();
    if (val.switch().name !== 'scvContractInstance') return undefined;
    const executable = val.instance().executable();
    if (executable.switch().name !== 'contractExecutableWasm') return undefined;
    return Buffer.from(executable.wasmHash());
  } catch {
    return undefined;
  }
}

interface LedgerEntryResult {
  /** The network's current ledger when the RPC answered. */
  latestLedger: number;
  /** `liveUntilLedgerSeq` of the looked-up entry, or `undefined` when absent. */
  liveUntil: number | undefined;
  /** The entry's raw `xdr`, so callers can inspect what it is. */
  entryXdr: unknown;
}

/**
 * GETs one entry by ledger key. `undefined` means the RPC could not answer
 * (unreachable, non-200, malformed JSON) — never throws. An empty `entries`
 * result is a valid answer that simply has no entry, and surfaces as
 * `liveUntil === undefined`.
 */
async function queryLedgerEntry(
  rpcUrl: string,
  key: string,
  fetchImpl: typeof fetch,
): Promise<LedgerEntryResult | undefined> {
  try {
    const response = await fetchImpl(rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'getLedgerEntries',
        params: { keys: [key] },
      }),
    });
    if (!response.ok) return undefined;

    const body = (await response.json()) as {
      result?: { latestLedger?: unknown; entries?: unknown };
    };
    const result = body.result;
    if (typeof result !== 'object' || result === null) return undefined;

    const latestLedger = Number(result.latestLedger);
    if (!Number.isInteger(latestLedger)) return undefined;

    const entries = Array.isArray(result.entries) ? result.entries : [];
    const entry = entries.find(
      (e): e is Record<string, unknown> => typeof e === 'object' && e !== null,
    );
    const liveUntil = Number(entry?.liveUntilLedgerSeq);
    return {
      latestLedger,
      liveUntil: Number.isInteger(liveUntil) ? liveUntil : undefined,
      entryXdr: entry?.xdr,
    };
  } catch {
    return undefined;
  }
}

/**
 * Verifies the TTL of one contract and its WASM against a Soroban RPC.
 *
 * The contract instance entry is read first; out of it comes the WASM hash,
 * which locates the code entry. The effective expiry is the earlier of the
 * two, compared against `latestLedger`. Diagnoses nothing while the TTL is
 * comfortably ahead, warns as renewal nears (~24h), and errors once expired
 * or archived.
 */
export async function checkContractTtl(
  contractId: string,
  rpcUrl: string,
  fetchImpl: typeof fetch = fetch,
  options: ContractTtlOptions = {},
): Promise<Diagnostic[]> {
  const subject = (detail: string): string => `Contract ${contractId}${detail ? ` ${detail}` : ''}`;

  const finding = (rule: string, fallback: 'error' | 'warning', detail: string): Diagnostic[] => {
    const severity = severityFor(rule, fallback, options.rules);
    if (severity === undefined) return [];
    return [{ rule, severity, category: 'network', message: subject(detail) }];
  };

  const instance = await queryLedgerEntry(rpcUrl, contractDataInstanceKey(contractId), fetchImpl);
  if (instance === undefined) {
    return finding(
      TTL_UNAVAILABLE_RULE,
      'warning',
      'could not be verified against the Soroban RPC',
    );
  }
  if (instance.liveUntil === undefined) {
    return finding(
      CONTRACT_EXPIRED_RULE,
      'error',
      'has expired or been archived, so it is no longer live on the network',
    );
  }

  let liveUntil = instance.liveUntil;
  const wasmHash = wasmHashOf(instance.entryXdr);
  if (wasmHash !== undefined) {
    const code = await queryLedgerEntry(rpcUrl, contractCodeKey(wasmHash), fetchImpl);
    if (code === undefined) {
      return finding(
        TTL_UNAVAILABLE_RULE,
        'warning',
        'WASM could not be verified against the Soroban RPC',
      );
    }
    if (code.liveUntil === undefined) {
      return finding(
        CONTRACT_EXPIRED_RULE,
        'error',
        'WASM has expired or been archived on the network',
      );
    }
    liveUntil = Math.min(liveUntil, code.liveUntil);
  }

  const remaining = liveUntil - instance.latestLedger;
  if (remaining <= 0) {
    return finding(
      CONTRACT_EXPIRED_RULE,
      'error',
      `has expired ${-remaining} ledgers ago and may have been archived`,
    );
  }
  if (remaining <= EXPIRING_WINDOW_LEDGERS) {
    return finding(
      TTL_EXPIRING_RULE,
      'warning',
      `expires in ${remaining} ledgers; renew the TTL before it does`,
    );
  }
  return [];
}

/**
 * Audits every contract the file declares — `[[CURRENCIES]].contract` and
 * `WEB_AUTH_CONTRACT_ID` — against Soroban. Silent when the network is
 * unknown (no RPC URL can be derived) unless `options.rpcUrl` is given.
 */
export async function checkContracts(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: ContractAuditOptions = {},
): Promise<Diagnostic[]> {
  const rpcUrl =
    options.rpcUrl ??
    rpcUrlFor(typeof doc.NETWORK_PASSPHRASE === 'string' ? doc.NETWORK_PASSPHRASE : undefined);
  if (!rpcUrl) return [];

  const targets: ContractTarget[] = [
    ...contractIdsOf(doc),
    ...(webAuthContractIdOf(doc) !== undefined ? [webAuthContractIdOf(doc) as ContractTarget] : []),
  ];
  if (targets.length === 0) return [];

  const diagnostics: Diagnostic[] = [];
  for (const target of targets) {
    diagnostics.push(...(await checkContractTtl(target.id, rpcUrl, fetchImpl, options)));
  }
  return diagnostics;
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const sorobanRules: Rule[] = [
  {
    id: TTL_EXPIRING_RULE,
    category: 'network',
    severity: 'warning',
    description: 'A Soroban contract or its WASM is within ~a day of its TTL expiring',
    run() {},
  },
  {
    id: CONTRACT_EXPIRED_RULE,
    category: 'network',
    severity: 'error',
    description: 'A Soroban contract or its WASM has expired or been archived on the network',
    run() {},
  },
  {
    id: TTL_UNAVAILABLE_RULE,
    category: 'network',
    severity: 'warning',
    description: 'A Soroban contract TTL could not be verified against the Soroban RPC',
    run() {},
  },
];

/** Rule ids emitted by {@link checkContractTtl}. */
export const sorobanRuleIds: readonly string[] = sorobanRules.map((rule) => rule.id);
