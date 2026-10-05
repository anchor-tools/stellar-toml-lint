/**
 * Shared Soroban RPC plumbing used by the on-chain contract audits.
 *
 * Every audit that inspects a deployed contract needs the same two things: the
 * ledger key of a contract's instance entry, and the WASM bytecode the instance
 * points at. Both are pure lookups against a Soroban RPC endpoint, so they live
 * here rather than being re-implemented per module. Nothing here throws on a
 * network fault: an unreachable or malformed RPC is reported as `undefined` and
 * the calling audit degrades to "could not verify", never a false finding.
 */
import { Address, xdr } from '@stellar/stellar-base';
import type { RuleOverrides, Severity } from '../types.js';
import { isString } from '../predicates.js';

/** How long one RPC request may take before it is abandoned. */
export const RPC_TIMEOUT_MS = 10_000;

/**
 * Resolves the severity an audit should use for a rule, honouring the caller's
 * `--off`/`--warn`/`--error` overrides. `undefined` means the rule is disabled
 * and the finding should be dropped.
 */
export function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules?: RuleOverrides,
): Severity | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

/** The ledger key of a contract's instance entry. */
export function contractDataInstanceKey(contractId: string): string {
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
export function contractCodeKey(wasmHash: Buffer): string {
  const key = xdr.LedgerKey.contractCode(new xdr.LedgerKeyContractCode({ hash: wasmHash }));
  return key.toXDR('base64');
}

/** One `getLedgerEntries` result for a single key. */
export interface LedgerEntryResult {
  /** The network's current ledger when the RPC answered. */
  latestLedger: number;
  /** `liveUntilLedgerSeq` of the entry, or `undefined` when it is absent. */
  liveUntil: number | undefined;
  /** The entry's raw `xdr`, so callers can inspect what it is. */
  entryXdr: unknown;
}

/**
 * GETs one entry by ledger key. `undefined` means the RPC could not answer
 * (unreachable, non-200, malformed JSON) — never throws. An empty `entries`
 * result is a valid answer that has no entry (`liveUntil === undefined`).
 */
export async function queryLedgerEntry(
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
      signal: AbortSignal.timeout(RPC_TIMEOUT_MS),
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

/** The WASM hash a contract instance entry points at, when it runs WASM. */
export function wasmHashOf(entryXdr: unknown): Buffer | undefined {
  if (!isString(entryXdr)) return undefined;
  try {
    const data = xdr.LedgerEntryData.fromXDR(entryXdr, 'base64');
    const val = data.contractData().val();
    if (val.switch().name !== 'scvContractInstance') return undefined;
    const executable = val.instance().executable();
    if (executable.switch().name !== 'contractExecutableWasm') return undefined;
    return Buffer.from(executable.wasmHash());
  } catch {
    return undefined;
  }
}

/** The raw `xdr` of a contract's instance entry, or `undefined` if absent. */
export async function fetchContractInstanceXdr(
  contractId: string,
  rpcUrl: string,
  fetchImpl: typeof fetch,
): Promise<unknown | undefined> {
  const instance = await queryLedgerEntry(rpcUrl, contractDataInstanceKey(contractId), fetchImpl);
  if (instance === undefined || instance.liveUntil === undefined) return undefined;
  return instance.entryXdr;
}

/** The WASM bytecode a contract instance points at, or `undefined`. */
export async function fetchContractWasm(
  contractId: string,
  rpcUrl: string,
  fetchImpl: typeof fetch,
): Promise<Buffer | undefined> {
  const instanceXdr = await fetchContractInstanceXdr(contractId, rpcUrl, fetchImpl);
  const wasmHash = wasmHashOf(instanceXdr);
  if (wasmHash === undefined) return undefined;

  const code = await queryLedgerEntry(rpcUrl, contractCodeKey(wasmHash), fetchImpl);
  if (code === undefined || code.liveUntil === undefined || !isString(code.entryXdr))
    return undefined;
  try {
    const data = xdr.LedgerEntryData.fromXDR(code.entryXdr, 'base64');
    if (data.switch().name !== 'contractCode') return undefined;
    return Buffer.from(data.contractCode().code());
  } catch {
    return undefined;
  }
}
