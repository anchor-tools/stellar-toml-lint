import { Address, xdr } from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { specUrl } from '../spec.js';
import { isAccountId, isString } from '../predicates.js';
import {
  contractCodeKey,
  contractDataInstanceKey,
  queryLedgerEntry,
  specFunctionNames,
  wasmBytesOf,
  wasmHashOf,
} from '../soroban.js';

export const UNPROTECTED_UPGRADE_RULE = 'soroban/unprotected-upgrade-function';
export const SINGLE_SIGNER_UPGRADE_ADMIN_RULE = 'soroban/single-signer-upgrade-admin';

export const UPGRADE_FUNCTIONS = ['upgrade', 'set_wasm', 'update_wasm'];

interface AuditOptions {
  rules?: RuleOverrides;
  rpcUrl?: string;
  horizonUrl?: string;
  fetchImpl?: typeof fetch;
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

/**
 * Attempts to extract an admin address from a contract instance entry's storage.
 * Inspects `instance().storage()` key-value entries for common admin key names
 * ("admin", "Admin", "owner", "Owner", "governance", "Governance").
 */
export function extractAdminAddress(entryXdr: unknown): string | undefined {
  if (!isString(entryXdr)) return undefined;
  try {
    const data = xdr.LedgerEntryData.fromXDR(entryXdr, 'base64');
    const contractData = data.contractData();
    const val = contractData.val();
    if (val.switch().name !== 'scvContractInstance') return undefined;

    const storage = val.instance().storage();
    if (!storage) return undefined;
    for (const item of storage) {
      const k = item.key();
      let keyName = '';
      if (k.switch().name === 'scvSymbol') {
        keyName = k.sym().toString().toLowerCase();
      } else if (k.switch().name === 'scvString') {
        keyName = k.str().toString().toLowerCase();
      }

      if (['admin', 'owner', 'governance'].includes(keyName)) {
        const v = item.val();
        if (v.switch().name === 'scvAddress') {
          return Address.fromScAddress(v.address()).toString();
        }
      }
    }
  } catch {
    return undefined;
  }
  return undefined;
}

/**
 * Audits upgrade functions (`upgrade`, `set_wasm`, `update_wasm`) in Soroban contracts.
 * Emits `soroban/unprotected-upgrade-function` if upgrade functions are exposed without admin protection,
 * and `soroban/single-signer-upgrade-admin` if the upgrade admin account is single-signer.
 */
export async function auditUpgradeSecurity(
  contractId: string,
  rpcUrl: string,
  horizonUrl: string,
  fetchImpl: typeof fetch = fetch,
  options: AuditOptions = {},
): Promise<Diagnostic[]> {
  const diagnostics: Diagnostic[] = [];

  const instance = await queryLedgerEntry(rpcUrl, contractDataInstanceKey(contractId), fetchImpl);
  if (instance === undefined || instance.liveUntil === undefined) return diagnostics;

  const wasmHash = wasmHashOf(instance.entryXdr);
  if (wasmHash === undefined) return diagnostics;

  const code = await queryLedgerEntry(rpcUrl, contractCodeKey(wasmHash), fetchImpl);
  if (code === undefined) return diagnostics;

  const wasm = wasmBytesOf(code.entryXdr);
  if (wasm === undefined) return diagnostics;

  const functions = specFunctionNames(wasm);
  if (functions === undefined || functions.length === 0) return diagnostics;

  const exportedUpgradeFunctions = functions.filter((fn) => UPGRADE_FUNCTIONS.includes(fn));
  if (exportedUpgradeFunctions.length === 0) return diagnostics;

  const adminAddress = extractAdminAddress(instance.entryXdr);

  if (adminAddress === undefined) {
    const severity = severityFor(UNPROTECTED_UPGRADE_RULE, 'error', options.rules);
    if (severity !== undefined) {
      diagnostics.push({
        rule: UNPROTECTED_UPGRADE_RULE,
        severity,
        category: 'network',
        message: `Contract ${contractId} exports upgrade function (${exportedUpgradeFunctions.join(
          ', ',
        )}) without an admin authorization check or admin address set`,
        path: 'CURRENCIES.contract',
        helpUri: specUrl('general-information'),
        suggestion:
          'Enforce admin authorization (`require_auth`) on upgrade functions and store an admin address in contract storage.',
      });
    }
    return diagnostics;
  }

  if (isAccountId(adminAddress)) {
    try {
      const response = await fetchImpl(`${horizonUrl}/accounts/${adminAddress}`);
      if (response.ok) {
        const body = (await response.json()) as {
          thresholds?: Record<string, number>;
          num_signers?: number;
          signers?: unknown[];
        };

        const numSigners = body.num_signers ?? body.signers?.length ?? 1;
        const highThreshold = body.thresholds?.high_threshold ?? 0;

        if (numSigners <= 1 || highThreshold <= 1) {
          const severity = severityFor(SINGLE_SIGNER_UPGRADE_ADMIN_RULE, 'warning', options.rules);
          if (severity !== undefined) {
            diagnostics.push({
              rule: SINGLE_SIGNER_UPGRADE_ADMIN_RULE,
              severity,
              category: 'network',
              message: `Contract ${contractId} upgrade admin account ${adminAddress} is a single-signer account`,
              path: 'CURRENCIES.contract',
              helpUri: specUrl('general-information'),
              suggestion:
                'Secure contract upgrade admin accounts with multi-signature governance to prevent unauthorized code modifications.',
            });
          }
        }
      }
    } catch {
      // Degrade gracefully if Horizon query fails
    }
  }

  return diagnostics;
}

export const upgradeAuditorRules: Rule[] = [
  {
    id: UNPROTECTED_UPGRADE_RULE,
    category: 'network',
    severity: 'error',
    description:
      'Soroban contract upgrade functions must enforce authorization controls and admin protection',
    run() {},
  },
  {
    id: SINGLE_SIGNER_UPGRADE_ADMIN_RULE,
    category: 'network',
    severity: 'warning',
    description:
      'Soroban contract upgrade admin account should be secured by multi-signature thresholds',
    run() {},
  },
];
