/**
 * Soroban contract instance storage footprint analyzer and rent / TTL cost estimator.
 *
 * Soroban state archiving requires contracts to pay rent for persistent and
 * temporary storage keys. If an anchor or token issuer does not monitor storage
 * footprint and TTL state on Soroban, instance storage or contract code can
 * become archived, freezing token operations.
 *
 * This audit queries the Soroban RPC for contract instance and code entries,
 * measures byte sizes, calculates ledger rent consumption, and projects TTL
 * expiration dates based on current ledger sequence.
 *
 * Runs under opt-in `--check-network --soroban-rent-audit`, never throws on an
 * RPC outage, and registers rule objects so `--list-rules` and
 * `--off`/`--warn`/`--error` know its ids.
 *
 * Diagnostics:
 * - `soroban/ttl-expiring-soon` (error)
 * - `soroban/high-storage-footprint` (warning)
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isString } from '../predicates.js';
import { rpcUrlFor } from '../rules/display-decimals-audit.js';
import { contractCurrenciesOf } from '../rules/currencies.js';
import {
  contractCodeKey,
  contractDataInstanceKey,
  queryLedgerEntry,
  severityFor,
  wasmHashOf,
} from './rpc.js';

export const TTL_EXPIRING_SOON_RULE = 'soroban/ttl-expiring-soon';
export const HIGH_STORAGE_FOOTPRINT_RULE = 'soroban/high-storage-footprint';

/** Average ledger close time on Stellar / Soroban in seconds. */
export const LEDGER_CLOSE_TIME_SECONDS = 5;

/** 30 days in seconds (30 * 24 * 60 * 60 = 2,592,000s). */
export const THIRTY_DAYS_SECONDS = 30 * 24 * 60 * 60;

/** Number of ledgers in 30 days at 5 seconds per ledger (518,400 ledgers). */
export const TTL_EXPIRING_THRESHOLD_LEDGERS = Math.floor(
  THIRTY_DAYS_SECONDS / LEDGER_CLOSE_TIME_SECONDS,
);

/** Default threshold for high storage footprint in bytes (64 KB). */
export const DEFAULT_MAX_STORAGE_BYTES = 64 * 1024;

/**
 * Standard baseline rent fee rate per byte per 100,000 ledgers in XLM.
 */
export const DEFAULT_RENT_FEE_PER_BYTE_PER_100K = 0.000025;

export interface StorageFootprintOptions {
  rules?: RuleOverrides;
  /** The file path that named the contract, attached to every diagnostic. */
  path?: string;
  /** Soroban RPC endpoint, overriding the one derived from the passphrase. */
  rpcUrl?: string;
  /** Custom threshold in bytes before high storage footprint warning fires. */
  maxStorageBytes?: number;
  /** Custom rent fee rate per byte per 100,000 ledgers in XLM. */
  rentFeeRate?: number;
}

export interface ContractStorageFootprint {
  instanceBytes: number;
  codeBytes: number;
  totalBytes: number;
  instanceTtl?: {
    latestLedger: number;
    liveUntil: number;
    remainingLedgers: number;
    remainingDays: number;
  };
  codeTtl?: {
    latestLedger: number;
    liveUntil: number;
    remainingLedgers: number;
    remainingDays: number;
  };
  projectedRentPer100kLedgers: number;
}

/**
 * Estimates remaining TTL in ledgers and days from latest ledger and liveUntil sequence.
 */
export function estimateTtlExpiration(
  latestLedger: number,
  liveUntil: number,
  ledgerCloseTimeSeconds: number = LEDGER_CLOSE_TIME_SECONDS,
): { remainingLedgers: number; remainingDays: number; isExpiringSoon: boolean } {
  const remainingLedgers = Math.max(0, liveUntil - latestLedger);
  const remainingDays = Number(((remainingLedgers * ledgerCloseTimeSeconds) / 86400).toFixed(2));
  const isExpiringSoon = remainingLedgers <= TTL_EXPIRING_THRESHOLD_LEDGERS;
  return { remainingLedgers, remainingDays, isExpiringSoon };
}

/**
 * Calculates projected rent cost for a given storage footprint over a number of ledgers.
 */
export function calculateProjectedRent(
  footprintBytes: number,
  ledgers: number = 100_000,
  feeRatePerBytePer100k: number = DEFAULT_RENT_FEE_PER_BYTE_PER_100K,
): number {
  const cost = footprintBytes * (ledgers / 100_000) * feeRatePerBytePer100k;
  return Number(cost.toFixed(6));
}

/**
 * Calculates total storage footprint from instance, code, and optional extra bytes.
 */
export function calculateStorageFootprint(
  instanceBytes: number,
  codeBytes: number,
  otherBytes: number = 0,
): number {
  return instanceBytes + codeBytes + otherBytes;
}

function footprintFinding(
  contractId: string,
  options: StorageFootprintOptions,
): (
  rule: string,
  fallback: 'error' | 'warning',
  detail: string,
  suggestion?: string,
) => Diagnostic[] {
  return (rule, fallback, detail, suggestion) => {
    const severity = severityFor(rule, fallback, options.rules);
    if (severity === undefined) return [];
    return [
      {
        rule,
        severity,
        category: 'network',
        message: `Contract ${contractId} ${detail}`,
        ...(options.path !== undefined ? { path: options.path } : {}),
        ...(suggestion !== undefined ? { suggestion } : {}),
      },
    ];
  };
}

/**
 * Queries on-chain storage footprint and TTL status for a single Soroban contract.
 * Returns `undefined` if the contract instance cannot be queried.
 */
export async function getContractStorageFootprint(
  contractId: string,
  rpcUrl: string,
  fetchImpl: typeof fetch = fetch,
  options: StorageFootprintOptions = {},
): Promise<ContractStorageFootprint | undefined> {
  const instanceKey = contractDataInstanceKey(contractId);
  const instance = await queryLedgerEntry(rpcUrl, instanceKey, fetchImpl);
  if (instance === undefined || instance.entryXdr === undefined) return undefined;

  let instanceBytes = 0;
  if (isString(instance.entryXdr)) {
    instanceBytes = Buffer.from(instance.entryXdr, 'base64').length;
  }

  let codeBytes = 0;
  let codeTtl: ContractStorageFootprint['codeTtl'];

  const wasmHash = wasmHashOf(instance.entryXdr);
  if (wasmHash !== undefined) {
    const codeKey = contractCodeKey(wasmHash);
    const code = await queryLedgerEntry(rpcUrl, codeKey, fetchImpl);
    if (code !== undefined && code.entryXdr !== undefined) {
      if (isString(code.entryXdr)) {
        codeBytes = Buffer.from(code.entryXdr, 'base64').length;
      }
      if (code.liveUntil !== undefined) {
        const est = estimateTtlExpiration(code.latestLedger, code.liveUntil);
        codeTtl = {
          latestLedger: code.latestLedger,
          liveUntil: code.liveUntil,
          remainingLedgers: est.remainingLedgers,
          remainingDays: est.remainingDays,
        };
      }
    }
  }

  let instanceTtl: ContractStorageFootprint['instanceTtl'];
  if (instance.liveUntil !== undefined) {
    const est = estimateTtlExpiration(instance.latestLedger, instance.liveUntil);
    instanceTtl = {
      latestLedger: instance.latestLedger,
      liveUntil: instance.liveUntil,
      remainingLedgers: est.remainingLedgers,
      remainingDays: est.remainingDays,
    };
  }

  const totalBytes = calculateStorageFootprint(instanceBytes, codeBytes);
  const projectedRentPer100kLedgers = calculateProjectedRent(
    totalBytes,
    100_000,
    options.rentFeeRate ?? DEFAULT_RENT_FEE_PER_BYTE_PER_100K,
  );

  return {
    instanceBytes,
    codeBytes,
    totalBytes,
    instanceTtl,
    codeTtl,
    projectedRentPer100kLedgers,
  };
}

/**
 * Audits a single contract's storage footprint and TTL state.
 */
export async function auditContractStorageFootprint(
  contractId: string,
  rpcUrl: string,
  fetchImpl: typeof fetch = fetch,
  options: StorageFootprintOptions = {},
): Promise<Diagnostic[]> {
  const footprint = await getContractStorageFootprint(contractId, rpcUrl, fetchImpl, options);
  if (footprint === undefined) return [];

  const diagnostics: Diagnostic[] = [];
  const finding = footprintFinding(contractId, options);
  const maxBytes = options.maxStorageBytes ?? DEFAULT_MAX_STORAGE_BYTES;

  // 1. Check TTL expiration within 30 days
  if (footprint.instanceTtl !== undefined) {
    const { remainingLedgers, remainingDays } = footprint.instanceTtl;
    if (remainingLedgers <= TTL_EXPIRING_THRESHOLD_LEDGERS) {
      diagnostics.push(
        ...finding(
          TTL_EXPIRING_SOON_RULE,
          'error',
          `instance entry TTL expires in ${remainingLedgers} ledgers (~${remainingDays} days), which is within the 30-day threshold`,
          'Extend the contract instance TTL via Soroban RPC extendFootprintTTLOp before it is archived.',
        ),
      );
    }
  }

  if (footprint.codeTtl !== undefined) {
    const { remainingLedgers, remainingDays } = footprint.codeTtl;
    if (remainingLedgers <= TTL_EXPIRING_THRESHOLD_LEDGERS) {
      diagnostics.push(
        ...finding(
          TTL_EXPIRING_SOON_RULE,
          'error',
          `code entry TTL expires in ${remainingLedgers} ledgers (~${remainingDays} days), which is within the 30-day threshold`,
          'Extend the contract code entry TTL via Soroban RPC extendFootprintTTLOp before it is archived.',
        ),
      );
    }
  }

  // 2. Check high storage footprint
  if (footprint.totalBytes > maxBytes) {
    const kb = (footprint.totalBytes / 1024).toFixed(2);
    const limitKb = (maxBytes / 1024).toFixed(0);
    diagnostics.push(
      ...finding(
        HIGH_STORAGE_FOOTPRINT_RULE,
        'warning',
        `total storage footprint is ${footprint.totalBytes} bytes (${kb} KB), exceeding the recommended threshold of ${limitKb} KB (projected rent cost: ${footprint.projectedRentPer100kLedgers.toFixed(4)} XLM per 100k ledgers)`,
        'Optimize contract bytecode size or storage layout to reduce ongoing state archival rent costs.',
      ),
    );
  }

  return diagnostics;
}

/**
 * Audits storage footprint and rent estimation for every contract declared in [[CURRENCIES]].
 */
export async function auditTomlStorageFootprint(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: StorageFootprintOptions = {},
): Promise<Diagnostic[]> {
  const passphrase =
    typeof doc.NETWORK_PASSPHRASE === 'string' ? doc.NETWORK_PASSPHRASE : undefined;
  const rpcUrl = options.rpcUrl ?? rpcUrlFor(passphrase);
  if (!rpcUrl) return [];

  const diagnostics: Diagnostic[] = [];
  for (const currency of contractCurrenciesOf(doc)) {
    diagnostics.push(
      ...(await auditContractStorageFootprint(currency.id, rpcUrl, fetchImpl, {
        ...options,
        path: currency.path,
      })),
    );
  }
  return diagnostics;
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const storageFootprintRules: Rule[] = [
  {
    id: TTL_EXPIRING_SOON_RULE,
    category: 'network',
    severity: 'error',
    description: 'A Soroban contract instance or code entry TTL is expiring within 30 days',
    run() {},
  },
  {
    id: HIGH_STORAGE_FOOTPRINT_RULE,
    category: 'network',
    severity: 'warning',
    description: 'A Soroban contract storage footprint exceeds recommended limits',
    run() {},
  },
];

/** Rule ids emitted by {@link auditTomlStorageFootprint}. */
export const storageFootprintRuleIds: readonly string[] = storageFootprintRules.map(
  (rule) => rule.id,
);
