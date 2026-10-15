/**
 * Soroban Instance Storage Integrity Auditor.
 *
 * Validates the raw LedgerEntryData XDR for contract instance keys stored in
 * instance storage. Ensures that critical keys (admin, decimal) contain
 * expected SCVal types and that their values agree with the stellar.toml.
 *
 * Runs under opt-in --check-network.
 * Queries getLedgerEntries for contract instance key.
 * Decodes SCVal entries stored in instance storage map.
 * Validates that Symbol("admin") is a valid Address SCVal.
 * Validates that Symbol("decimal") matches display_decimals in stellar.toml.
 * Emits soroban/corrupted-instance-storage-entry (error).
 * Emits soroban/instance-storage-data-mismatch (error).
 */

import { Address, xdr } from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';
import { isString, isInteger } from '../predicates.js';
import { rpcUrlFor } from '../rules/display-decimals-audit.js';
import { contractCurrenciesOf } from '../rules/currencies.js';
import { queryLedgerEntry, contractDataInstanceKey, type LedgerEntryResult } from './rpc.js';

export const CORRUPTED_ENTRY_RULE = 'soroban/corrupted-instance-storage-entry';
export const DATA_MISMATCH_RULE = 'soroban/instance-storage-data-mismatch';

const RPC_TIMEOUT_MS = 10_000;

export interface InstanceStorageAuditorOptions {
  rules?: RuleOverrides;
  path?: string;
  rpcUrl?: string;
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

function scString(val: xdr.ScVal): string | undefined {
  switch (val.switch().name) {
    case 'scvString':
    case 'scvSymbol':
      return val.value()!.toString();
    default:
      return undefined;
  }
}

/**
 * Extracts the instance storage map from a contract instance ledger entry.
 * Returns undefined if the entry is not a contract instance or has no storage.
 */
function instanceStorageOf(entryXdr: unknown): xdr.ScMapEntry[] | undefined {
  if (!isString(entryXdr)) return undefined;
  try {
    const data = xdr.LedgerEntryData.fromXDR(entryXdr, 'base64');
    if (data.switch().name !== 'contractData') return undefined;
    const val = data.contractData().val();
    if (val.switch().name !== 'scvContractInstance') return undefined;
    return val.instance().storage() ?? [];
  } catch {
    return undefined;
  }
}

/**
 * Validates a single contract's instance storage.
 */
export async function auditContractInstanceStorage(
  contractId: string,
  rpcUrl: string,
  displayDecimals: number | undefined,
  fetchImpl: typeof fetch = fetch,
  options: InstanceStorageAuditorOptions = {},
): Promise<Diagnostic[]> {
  const diagnostics: Diagnostic[] = [];
  const finding = (rule: string, fallback: 'error' | 'warning', detail: string, suggestion?: string): Diagnostic[] => {
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

  const instanceResult = await queryLedgerEntry(rpcUrl, contractDataInstanceKey(contractId), fetchImpl);
  if (instanceResult === undefined) {
    return finding(CORRUPTED_ENTRY_RULE, 'error', 'instance entry could not be fetched from Soroban RPC');
  }
  if (instanceResult.liveUntil === undefined) {
    return finding(CORRUPTED_ENTRY_RULE, 'error', 'has no live instance entry on the ledger');
  }

  const storage = instanceStorageOf(instanceResult.entryXdr);
  if (storage === undefined) {
    return finding(CORRUPTED_ENTRY_RULE, 'error', 'instance storage could not be decoded');
  }

  // Validate each entry in instance storage
  for (const entry of storage) {
    const keyName = scString(entry.key());
    const val = entry.val();
    const valType = val.switch().name;

    // Validate admin key - must be an Address SCVal
    if (keyName === 'admin' || keyName === 'owner') {
      if (valType !== 'scvAddress') {
        diagnostics.push(
          ...finding(
            CORRUPTED_ENTRY_RULE,
            'error',
            `instance storage key "${keyName}" is type ${valType}, expected Address`,
            `Ensure the contract's ${keyName} is set to a valid Stellar address (Account or Contract).`,
          ),
        );
      }
    }

    // Validate decimal key - must be U32 and match display_decimals
    if (keyName === 'decimal') {
      if (valType !== 'scvU32') {
        diagnostics.push(
          ...finding(
            CORRUPTED_ENTRY_RULE,
            'error',
            `instance storage key "decimal" is type ${valType}, expected U32`,
            'Ensure the contract stores decimals as an unsigned 32-bit integer.',
          ),
        );
      } else if (displayDecimals !== undefined) {
        const contractDecimal = val.u32();
        if (contractDecimal !== displayDecimals) {
          diagnostics.push(
            ...finding(
              DATA_MISMATCH_RULE,
              'error',
              `instance storage "decimal" is ${contractDecimal}, but stellar.toml declares display_decimals=${displayDecimals}`,
              `Align the contract's decimal value with the file's display_decimals (${displayDecimals}).`,
            ),
          );
        }
      }
    }
  }

  // Check for missing critical keys
  const hasAdmin = storage.some((e) => scString(e.key()) === 'admin' || scString(e.key()) === 'owner');
  if (!hasAdmin) {
    diagnostics.push(
      ...finding(
        CORRUPTED_ENTRY_RULE,
        'warning',
        'instance storage has no "admin" or "owner" key',
        'The contract should store an administrative address for upgrade authority.',
      ),
    );
  }

  return diagnostics;
}

/**
 * Audits instance storage for all token contracts declared in the file.
 */
export async function auditTomlInstanceStorage(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: InstanceStorageAuditorOptions = {},
): Promise<Diagnostic[]> {
  const passphrase =
    typeof doc.NETWORK_PASSPHRASE === 'string' ? doc.NETWORK_PASSPHRASE : undefined;
  const rpcUrl = options.rpcUrl ?? rpcUrlFor(passphrase);
  if (!rpcUrl) return [];

  const diagnostics: Diagnostic[] = [];
  for (const currency of contractCurrenciesOf(doc)) {
    if (!isString(currency.id) || !currency.id.startsWith('C')) continue;
    const displayDecimals = isInteger(currency.entry.display_decimals) ? currency.entry.display_decimals : undefined;
    diagnostics.push(
      ...(await auditContractInstanceStorage(
        currency.id,
        rpcUrl,
        displayDecimals,
        fetchImpl,
        { ...options, path: currency.path },
      )),
    );
  }
  return diagnostics;
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const instanceStorageAuditorRules: Rule[] = [
  {
    id: CORRUPTED_ENTRY_RULE,
    category: 'network',
    severity: 'error',
    description: 'Soroban contract instance storage contains a malformed or unexpected SCVal type',
    run() {},
  },
  {
    id: DATA_MISMATCH_RULE,
    category: 'network',
    severity: 'error',
    description: 'Soroban contract instance storage value disagrees with stellar.toml',
    run() {},
  },
];

/** Rule ids emitted by {@link auditTomlInstanceStorage}. */
export const instanceStorageAuditorRuleIds: readonly string[] = instanceStorageAuditorRules.map((rule) => rule.id);