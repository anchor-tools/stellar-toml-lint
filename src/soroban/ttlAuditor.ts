/**
 * Soroban storage TTL auditor.
 *
 * Protocol 20 splits contract state into three storage classes — instance,
 * persistent, and temporary — and every ledger entry carries a
 * `liveUntilLedgerSeq`. Once the network passes that ledger the entry is
 * archived: the contract still exists, but an invocation that touches the
 * archived key fails until the entry is restored and its TTL extended. An
 * anchor that publishes contract addresses in `stellar.toml` is therefore
 * shipping state that can silently stop working, so this module reads the
 * entries behind each declared contract, reports how many ledgers are left,
 * and projects the resources an `extendFootprintTtlOp` needs to renew them.
 *
 * Two limits are deliberate. Soroban RPC can look entries up by key but cannot
 * enumerate a contract's storage, so the keys audited are the ones the
 * instance entry itself lists (its instance storage) plus any explicit keys
 * the caller supplies. And the cost projection is an estimate from the
 * protocol's per-entry resource charges — a simulation against the network is
 * still the only exact quote.
 */
import { Address, xdr } from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { specUrl } from '../spec.js';
import { isString } from '../predicates.js';
import { contractCodeKey, contractDataInstanceKey, wasmHashOf } from './ledgerKeys.js';

/** ~30 days of ledgers at the network's 5-second close time. */
export const DEFAULT_MIN_BUFFER_LEDGERS = 518_400;

/** ~5 days: below this the entry is one operational slip from archiving. */
export const DEFAULT_CRITICAL_BUFFER_LEDGERS = 86_400;

export const STORAGE_TTL_CRITICAL_RULE = 'soroban/storage-ttl-critical';
export const STORAGE_TTL_EXPIRING_RULE = 'soroban/storage-ttl-expiring-soon';
export const STORAGE_TTL_ARCHIVED_RULE = 'soroban/storage-ttl-archived';
export const STORAGE_TTL_UNAVAILABLE_RULE = 'soroban/storage-ttl-unavailable';

/** The storage class a ledger entry belongs to. */
export type StorageEntryKind = 'instance' | 'persistent' | 'temporary' | 'code';

export type TtlHealth = 'healthy' | 'expiring' | 'critical' | 'archived';

/** One ledger entry whose TTL was inspected. */
export interface StorageTtlEntry {
  /** Base64 `LedgerKey`. */
  key: string;
  kind: StorageEntryKind;
  /** Human-readable name of the key, when the caller supplied one. */
  label?: string;
  /** Dotted path in `stellar.toml` that named the contract, when known. */
  path?: string;
  liveUntilLedgerSeq?: number;
  lastModifiedLedgerSeq?: number;
  /** `liveUntilLedgerSeq - latestLedger`; negative once archived. */
  remainingLedgers?: number;
  health: TtlHealth;
}

/** A ledger key the caller asks the auditor to inspect explicitly. */
export interface StorageKeyTarget {
  /** Base64 `LedgerKey`. */
  key: string;
  kind?: StorageEntryKind;
  /** A human-readable name shown in diagnostics (for example `balance:alice`). */
  label?: string;
  /**
   * Treat the entry's absence from `getLedgerEntries` as archived. Defaults to
   * `true`: an explicitly named key is expected to exist.
   */
  required?: boolean;
}

export interface TtlAuditorOptions {
  rules?: RuleOverrides;
  /** Renewal horizon in ledgers; below it the entry is reported as expiring. */
  minBufferLedgers?: number;
  /** Below this many remaining ledgers the finding is an error. */
  criticalBufferLedgers?: number;
  /** Extra ledger keys to inspect, beyond the ones the instance entry lists. */
  storageKeys?: StorageKeyTarget[];
}

/** Resource projection for the `extendFootprintTtlOp` that renews the entries. */
export interface ExtendTtlCostEstimate {
  /** Number of ledger entries the operation extends. */
  entries: number;
  /** Ledger the TTL would be extended to (`latestLedger + buffer`). */
  extendToLedger: number;
  /** Ledgers actually added to the shortest-lived entry. */
  ledgerExtension: number;
  cpuInstructions: number;
  readBytes: number;
  writeBytes: number;
  /** Estimated resource fee, in stroops. */
  resourceFeeStroops: number;
  /** Total fee bid: resource fee plus the classic inclusion fee. */
  feeBidStroops: number;
}

/** The full result of auditing one contract. */
export interface TtlAuditReport {
  contractId: string;
  latestLedger: number;
  entries: StorageTtlEntry[];
  diagnostics: Diagnostic[];
  /** Cost of renewing every inspected entry, when at least one needs it. */
  extension?: ExtendTtlCostEstimate;
}

// ---------------------------------------------------------------------------
// Cost model
// ---------------------------------------------------------------------------

/** Classic inclusion fee per Soroban operation, in stroops. */
export const BASE_INCLUSION_FEE_STROOPS = 100;

/** Fixed CPU charged for the operation itself, before the per-entry work. */
export const EXTEND_CPU_BASE = 40_000;

/** CPU charged per ledger entry in the footprint. */
export const EXTEND_CPU_PER_ENTRY = 25_000;

/** Bytes read per ledger entry (key plus ledger-entry framing). */
export const EXTEND_READ_BYTES_PER_ENTRY = 64;

/** Bytes written per ledger entry when its TTL is bumped. */
export const EXTEND_WRITE_BYTES_PER_ENTRY = 128;

/** Read-rent charge per ledger entry per read byte, in stroops (protocol 20). */
export const RENT_STROOPS_PER_LEDGER_PER_ENTRY = 25;

/** Upper bound used when an entry has no usable TTL yet (for example archived). */
export const DEFAULT_EXTENSION_LEDGERS = DEFAULT_MIN_BUFFER_LEDGERS;

/**
 * Projects the resources an `extendFootprintTtlOp` needs to push `entries`
 * ledger entries out to `extendToLedger`.
 *
 * The numbers follow the protocol's per-entry CPU, read, and write charges and
 * the read-rent rate; they are a conservative estimate for planning and fee
 * budgeting, not a substitute for simulating the operation against the target
 * network before submitting it.
 */
export function estimateExtendTtlResources(
  entries: number,
  latestLedger: number,
  currentLiveUntil: number | undefined,
  extendToLedger: number,
): ExtendTtlCostEstimate {
  const count = Math.max(0, Math.trunc(entries));
  const extension =
    currentLiveUntil === undefined
      ? DEFAULT_EXTENSION_LEDGERS
      : Math.max(0, extendToLedger - currentLiveUntil);
  const effectiveExtension = Math.max(extension, 0);

  const cpuInstructions = EXTEND_CPU_BASE + count * EXTEND_CPU_PER_ENTRY;
  const readBytes = count * EXTEND_READ_BYTES_PER_ENTRY;
  const writeBytes = count * EXTEND_WRITE_BYTES_PER_ENTRY;
  const resourceFeeStroops =
    cpuInstructions + readBytes + count * effectiveExtension * RENT_STROOPS_PER_LEDGER_PER_ENTRY;

  return {
    entries: count,
    extendToLedger,
    ledgerExtension: effectiveExtension,
    cpuInstructions,
    readBytes,
    writeBytes,
    resourceFeeStroops,
    feeBidStroops: resourceFeeStroops + BASE_INCLUSION_FEE_STROOPS,
  };
}

// ---------------------------------------------------------------------------
// Ledger keys
// ---------------------------------------------------------------------------

function contractDataKeyFor(
  contractId: string,
  key: xdr.ScVal,
  durability: xdr.ContractDataDurability,
): string {
  return xdr.LedgerKey.contractData(
    new xdr.LedgerKeyContractData({
      contract: new Address(contractId).toScAddress(),
      key,
      durability,
    }),
  ).toXDR('base64');
}

/** The ledger key of a persistent contract-data entry. */
export function persistentStorageKey(contractId: string, key: xdr.ScVal): string {
  return contractDataKeyFor(contractId, key, xdr.ContractDataDurability.persistent());
}

/** The ledger key of a temporary contract-data entry. */
export function temporaryStorageKey(contractId: string, key: xdr.ScVal): string {
  return contractDataKeyFor(contractId, key, xdr.ContractDataDurability.temporary());
}

/**
 * The storage keys listed in a contract instance entry, as persistent and
 * temporary ledger keys.
 *
 * The instance entry holds the contract's *instance* storage map; its keys are
 * usable as `contractData` ledger keys too, but the entry itself does not say
 * which durability a key had, so both are produced and whichever exists is
 * reported by the RPC.
 */
export function storageKeysFromInstance(
  contractId: string,
  entryXdr: unknown,
): { key: string; kind: StorageEntryKind }[] {
  if (!isString(entryXdr)) return [];
  try {
    const data = xdr.LedgerEntryData.fromXDR(entryXdr, 'base64');
    const val = data.contractData().val();
    if (val.switch().name !== 'scvContractInstance') return [];

    const instance = val.instance();
    if (instance === null) return [];

    const keys: { key: string; kind: StorageEntryKind }[] = [];
    const seen = new Set<string>();
    for (const item of instance.storage() ?? []) {
      if (item === null) continue;
      for (const [kind, build] of [
        ['persistent', persistentStorageKey],
        ['temporary', temporaryStorageKey],
      ] as const) {
        const key = build(contractId, item.key());
        if (seen.has(key)) continue;
        seen.add(key);
        keys.push({ key, kind });
      }
    }
    return keys;
  } catch {
    return [];
  }
}

/** Builds the `LedgerKey` for the WASM code the instance points at. */
export function contractCodeEntryKey(entryXdr: unknown): string | undefined {
  const wasmHash = wasmHashOf(entryXdr);
  return wasmHash === undefined ? undefined : contractCodeKey(wasmHash);
}

// ---------------------------------------------------------------------------
// RPC
// ---------------------------------------------------------------------------

interface RawLedgerEntry {
  key: string;
  liveUntilLedgerSeq?: number;
  lastModifiedLedgerSeq?: number;
  xdr?: unknown;
}

interface LedgerEntriesResult {
  latestLedger: number;
  entries: Map<string, RawLedgerEntry>;
}

/**
 * Looks up a batch of ledger keys with one `getLedgerEntries` call.
 * `undefined` means the RPC could not answer at all; a valid answer that names
 * fewer entries than requested is returned, with the missing ones absent.
 */
export async function queryLedgerEntries(
  rpcUrl: string,
  keys: string[],
  fetchImpl: typeof fetch,
): Promise<LedgerEntriesResult | undefined> {
  if (keys.length === 0) return undefined;
  try {
    const response = await fetchImpl(rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'getLedgerEntries',
        params: { keys },
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

    const entries = new Map<string, RawLedgerEntry>();
    for (const candidate of Array.isArray(result.entries) ? result.entries : []) {
      if (typeof candidate !== 'object' || candidate === null) continue;
      const entry = candidate as Record<string, unknown>;
      if (!isString(entry.key)) continue;
      const liveUntil = Number(entry.liveUntilLedgerSeq);
      const lastModified = Number(entry.lastModifiedLedgerSeq);
      entries.set(entry.key, {
        key: entry.key,
        liveUntilLedgerSeq: Number.isInteger(liveUntil) ? liveUntil : undefined,
        lastModifiedLedgerSeq: Number.isInteger(lastModified) ? lastModified : undefined,
        ...(entry.xdr !== undefined ? { xdr: entry.xdr } : {}),
      });
    }

    return { latestLedger, entries };
  } catch {
    // A timeout or a malformed body is not a finding; the caller degrades.
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

export interface TtlThresholds {
  minBufferLedgers: number;
  criticalBufferLedgers: number;
}

/** Resolves the warning and critical horizons, keeping critical below warning. */
export function ttlThresholdsOf(options: TtlAuditorOptions = {}): TtlThresholds {
  const minBufferLedgers = options.minBufferLedgers ?? DEFAULT_MIN_BUFFER_LEDGERS;
  const requestedCritical = options.criticalBufferLedgers ?? DEFAULT_CRITICAL_BUFFER_LEDGERS;
  return {
    minBufferLedgers,
    criticalBufferLedgers: Math.min(requestedCritical, minBufferLedgers),
  };
}

/** Classifies the remaining ledgers of an entry against the two horizons. */
export function classifyTtl(remaining: number | undefined, thresholds: TtlThresholds): TtlHealth {
  if (remaining === undefined || remaining <= 0) return 'archived';
  if (remaining < thresholds.criticalBufferLedgers) return 'critical';
  if (remaining < thresholds.minBufferLedgers) return 'expiring';
  return 'healthy';
}

/** Ledgers expressed in days at the network's 5-second close time. */
export function ledgersToDays(ledgers: number): number {
  return Math.round((Math.max(0, ledgers) * 5) / 86_400);
}

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules?: RuleOverrides,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

function kindLabel(kind: StorageEntryKind): string {
  return kind === 'code' ? 'WASM code' : `${kind} storage`;
}

function entryLabel(target: { kind: StorageEntryKind; label?: string }): string {
  return target.label === undefined
    ? kindLabel(target.kind)
    : `${kindLabel(target.kind)} ${target.label}`;
}

function diagnosticFor(
  contractId: string,
  entry: StorageTtlEntry,
  thresholds: TtlThresholds,
  options: TtlAuditorOptions,
  latestLedger: number,
): Diagnostic | undefined {
  if (entry.health === 'healthy') return undefined;

  const base = {
    category: 'network' as const,
    path: entry.path ?? 'CURRENCIES.contract',
    helpUri: specUrl('general-information'),
  };
  const target = entryLabel(entry);

  if (entry.health === 'archived') {
    const severity = severityFor(STORAGE_TTL_ARCHIVED_RULE, 'error', options.rules);
    if (severity === undefined) return undefined;
    return {
      ...base,
      rule: STORAGE_TTL_ARCHIVED_RULE,
      severity,
      message: `Contract ${contractId} ${target} is archived (no live TTL at ledger ${latestLedger}); invocations that touch it will fail until it is restored`,
      suggestion:
        'Restore the archived entry with a restore-footprint operation, then extend its TTL and keep a renewal schedule that stays ahead of the buffer.',
    };
  }

  const remaining = entry.remainingLedgers ?? 0;
  const days = ledgersToDays(remaining);
  if (entry.health === 'critical') {
    const severity = severityFor(STORAGE_TTL_CRITICAL_RULE, 'error', options.rules);
    if (severity === undefined) return undefined;
    return {
      ...base,
      rule: STORAGE_TTL_CRITICAL_RULE,
      severity,
      message: `Contract ${contractId} ${target} expires in ${remaining} ledgers (~${days} days), below the ${thresholds.criticalBufferLedgers}-ledger critical buffer`,
      suggestion: `Extend the TTL with extendFootprintTtlOp before ledger ${entry.liveUntilLedgerSeq ?? latestLedger}; the operation needs about ${
        estimateExtendTtlResources(
          1,
          latestLedger,
          entry.liveUntilLedgerSeq,
          latestLedger + thresholds.minBufferLedgers,
        ).feeBidStroops
      } stroops per entry.`,
    };
  }

  const severity = severityFor(STORAGE_TTL_EXPIRING_RULE, 'warning', options.rules);
  if (severity === undefined) return undefined;
  return {
    ...base,
    rule: STORAGE_TTL_EXPIRING_RULE,
    severity,
    message: `Contract ${contractId} ${target} expires in ${remaining} ledgers (~${days} days), inside the ${thresholds.minBufferLedgers}-ledger renewal buffer`,
    suggestion:
      'Extend the TTL with extendFootprintTtlOp, or automate renewal so the entry never reaches its liveUntilLedgerSeq.',
  };
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

interface AuditedTarget {
  key: string;
  kind: StorageEntryKind;
  label?: string;
  path?: string;
  required: boolean;
}

/**
 * Audits storage TTLs for one contract.
 *
 * The instance entry is read first. From it come the storage keys the contract
 * keeps in instance storage and the WASM hash behind the contract, so a single
 * batched follow-up call inspects the instance, its code, and every derived
 * key. Caller-supplied keys are appended, and their absence is reported as
 * archived. Any RPC failure degrades to one `unavailable` warning rather than
 * an unhandled rejection.
 */
export async function auditContractStorageTtl(
  contractId: string,
  rpcUrl: string,
  fetchImpl: typeof fetch = fetch,
  options: TtlAuditorOptions = {},
): Promise<TtlAuditReport> {
  const thresholds = ttlThresholdsOf(options);
  const unavailable = (message: string): TtlAuditReport => {
    const severity = severityFor(STORAGE_TTL_UNAVAILABLE_RULE, 'warning', options.rules);
    return {
      contractId,
      latestLedger: 0,
      entries: [],
      diagnostics:
        severity === undefined
          ? []
          : [
              {
                rule: STORAGE_TTL_UNAVAILABLE_RULE,
                severity,
                category: 'network',
                message,
                path: 'CURRENCIES.contract',
                helpUri: specUrl('general-information'),
                suggestion:
                  'Re-run the TTL audit when the Soroban RPC is reachable; the storage state could not be read.',
              },
            ],
    };
  };

  const instanceKey = contractDataInstanceKey(contractId);
  const instance = await queryLedgerEntries(rpcUrl, [instanceKey], fetchImpl);
  if (instance === undefined) {
    return unavailable(
      `Contract ${contractId} storage TTL could not be verified against the Soroban RPC`,
    );
  }

  const instanceEntry = instance.entries.get(instanceKey);

  const targets: AuditedTarget[] = [
    { key: instanceKey, kind: 'instance', required: true, path: 'CURRENCIES.contract' },
  ];

  const codeKey =
    instanceEntry?.xdr === undefined ? undefined : contractCodeEntryKey(instanceEntry.xdr);
  if (codeKey !== undefined) {
    targets.push({ key: codeKey, kind: 'code', required: true, path: 'CURRENCIES.contract' });
  }

  for (const derived of instanceEntry === undefined
    ? []
    : storageKeysFromInstance(contractId, instanceEntry.xdr)) {
    targets.push({ key: derived.key, kind: derived.kind, required: false });
  }

  for (const explicit of options.storageKeys ?? []) {
    targets.push({
      key: explicit.key,
      kind: explicit.kind ?? 'persistent',
      required: explicit.required ?? true,
      ...(explicit.label !== undefined ? { label: explicit.label } : {}),
    });
  }

  const seen = new Set<string>();
  const uniqueTargets = targets.filter((target) => {
    if (seen.has(target.key)) return false;
    seen.add(target.key);
    return true;
  });

  const latestLedger = instance.latestLedger;
  const response = await queryLedgerEntries(
    rpcUrl,
    uniqueTargets.map((target) => target.key),
    fetchImpl,
  );
  const entries = response?.entries ?? instance.entries;
  const networkLedger = response?.latestLedger ?? latestLedger;

  const inspected: StorageTtlEntry[] = [];
  const diagnostics: Diagnostic[] = [];

  for (const target of uniqueTargets) {
    const raw = entries.get(target.key);
    if (raw === undefined && !target.required) continue;

    const remaining =
      raw?.liveUntilLedgerSeq === undefined ? undefined : raw.liveUntilLedgerSeq - networkLedger;
    const health = classifyTtl(remaining, thresholds);

    const entry: StorageTtlEntry = {
      key: target.key,
      kind: target.kind,
      health,
      ...(target.path !== undefined ? { path: target.path } : {}),
      ...(target.label !== undefined ? { label: target.label } : {}),
      ...(raw?.liveUntilLedgerSeq !== undefined
        ? { liveUntilLedgerSeq: raw.liveUntilLedgerSeq }
        : {}),
      ...(raw?.lastModifiedLedgerSeq !== undefined
        ? { lastModifiedLedgerSeq: raw.lastModifiedLedgerSeq }
        : {}),
      ...(remaining !== undefined ? { remainingLedgers: remaining } : {}),
    };
    inspected.push(entry);

    const diagnostic = diagnosticFor(contractId, entry, thresholds, options, networkLedger);
    if (diagnostic !== undefined) diagnostics.push(diagnostic);
  }

  const needsExtension = inspected.filter((entry) => entry.health !== 'healthy');
  const shortestLiveUntil = needsExtension.reduce<number | undefined>((shortest, entry) => {
    if (entry.liveUntilLedgerSeq === undefined) return shortest;
    return shortest === undefined
      ? entry.liveUntilLedgerSeq
      : Math.min(shortest, entry.liveUntilLedgerSeq);
  }, undefined);

  return {
    contractId,
    latestLedger: networkLedger,
    entries: inspected,
    diagnostics,
    ...(needsExtension.length > 0
      ? {
          extension: estimateExtendTtlResources(
            needsExtension.length,
            networkLedger,
            shortestLiveUntil,
            networkLedger + thresholds.minBufferLedgers,
          ),
        }
      : {}),
  };
}

/**
 * Audits every contract a document declares and flattens the reports into
 * diagnostics. Contracts named by `[[CURRENCIES]]` and
 * `WEB_AUTH_CONTRACT_ID` are covered; `undefined` when no RPC URL can be
 * derived and none was supplied.
 */
export async function auditTomlStorageTtl(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: TtlAuditorOptions & { rpcUrl?: string } = {},
): Promise<Diagnostic[]> {
  const rpcUrl =
    options.rpcUrl ??
    rpcUrlForPassphrase(
      typeof doc.NETWORK_PASSPHRASE === 'string' ? doc.NETWORK_PASSPHRASE : undefined,
    );
  if (!rpcUrl) return [];

  const targets = contractTargetsOf(doc);
  if (targets.length === 0) return [];

  const diagnostics: Diagnostic[] = [];
  for (const target of targets) {
    const report = await auditContractStorageTtl(target.id, rpcUrl, fetchImpl, options);
    diagnostics.push(...report.diagnostics);
  }
  return diagnostics;
}

/** The contract ids a document names, de-duplicated. */
export function contractTargetsOf(doc: Record<string, unknown>): { id: string; path: string }[] {
  const targets: { id: string; path: string }[] = [];
  const seen = new Set<string>();

  const push = (id: unknown, path: string): void => {
    if (!isString(id) || !/^C[A-Z2-7]{55}$/.test(id) || seen.has(id)) return;
    seen.add(id);
    targets.push({ id, path });
  };

  const currencies = doc.CURRENCIES;
  if (Array.isArray(currencies)) {
    currencies.forEach((entry, index) => {
      if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) return;
      push((entry as Record<string, unknown>).contract, `CURRENCIES[${index}].contract`);
    });
  }
  push(doc.WEB_AUTH_CONTRACT_ID, 'WEB_AUTH_CONTRACT_ID');

  return targets;
}

/**
 * Maps a passphrase to the public Soroban RPC, mirroring the rest of the
 * network checks. Unknown or absent passphrases yield `undefined`, which keeps
 * the audit silent offline.
 */
function rpcUrlForPassphrase(passphrase: string | undefined): string | undefined {
  switch (passphrase) {
    case 'Public Global Stellar Network ; September 2015':
      return 'https://soroban-rpc.mainnet.stellar.org';
    case 'Test SDF Network ; September 2015':
      return 'https://soroban-testnet.stellar.org';
    case 'Test SDF Future Network ; October 2022':
      return 'https://rpc-futurenet.stellar.org';
    default:
      return undefined;
  }
}

/**
 * The TTL daemon: audits a set of contracts in one pass and exposes the
 * per-contract reports so a monitor can page on the shortest remaining TTL
 * instead of only counting diagnostics.
 */
export class SorobanTtlAuditor {
  private readonly options: TtlAuditorOptions;

  constructor(options: TtlAuditorOptions = {}) {
    this.options = options;
  }

  /** Audits one contract. */
  async audit(
    contractId: string,
    rpcUrl: string,
    fetchImpl: typeof fetch = fetch,
  ): Promise<TtlAuditReport> {
    return auditContractStorageTtl(contractId, rpcUrl, fetchImpl, this.options);
  }

  /** Audits a list of contracts, in order. */
  async auditAll(
    contractIds: readonly string[],
    rpcUrl: string,
    fetchImpl: typeof fetch = fetch,
  ): Promise<TtlAuditReport[]> {
    const reports: TtlAuditReport[] = [];
    for (const contractId of contractIds) {
      reports.push(await this.audit(contractId, rpcUrl, fetchImpl));
    }
    return reports;
  }

  /** Audits a document's declared contracts and returns every diagnostic. */
  async auditDocument(
    doc: Record<string, unknown>,
    fetchImpl: typeof fetch = fetch,
  ): Promise<Diagnostic[]> {
    return auditTomlStorageTtl(doc, fetchImpl, this.options);
  }
}

export const ttlAuditorRules: Rule[] = [
  {
    id: STORAGE_TTL_ARCHIVED_RULE,
    category: 'network',
    severity: 'error',
    description: 'A Soroban contract storage entry has already been archived',
    run() {},
  },
  {
    id: STORAGE_TTL_CRITICAL_RULE,
    category: 'network',
    severity: 'error',
    description: 'A Soroban storage entry expires inside the critical TTL buffer',
    run() {},
  },
  {
    id: STORAGE_TTL_EXPIRING_RULE,
    category: 'network',
    severity: 'warning',
    description: 'A Soroban storage entry expires inside the renewal buffer',
    run() {},
  },
  {
    id: STORAGE_TTL_UNAVAILABLE_RULE,
    category: 'network',
    severity: 'warning',
    description: 'Soroban storage TTLs could not be verified against the Soroban RPC',
    run() {},
  },
];
