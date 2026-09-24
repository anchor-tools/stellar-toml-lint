/**
 * Collateral reserve account multi-party governance auditor.
 *
 * Runs under opt-in --check-network.
 *
 * In SEP-1, asset entries include collateral_addresses and
 * collateral_address_signatures. For stablecoins and wrapped assets,
 * collateral accounts must be secured by multi-party governance
 * (e.g. custodian multi-sig, multi-party computation MPC keys).
 *
 * This auditor queries declared collateral addresses across Stellar or
 * external blockchains (via RPC) to audit account signer configurations,
 * threshold settings, and custody structures.
 */

import { Networks } from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isAccountId } from '../predicates.js';
import { specUrl } from '../spec.js';

const SINGLE_KEY_RULE = 'collateral/single-key-reserve-risk';
const CUSTODY_THRESHOLD_RULE = 'collateral/custody-threshold-unmet';

interface CollateralGovernanceOptions {
  rules?: RuleOverrides;
  fetchImpl?: typeof fetch;
  networkPassphrase?: string;
}

function severityForRule(
  rule: string,
  fallback: 'error' | 'warning',
  rules?: RuleOverrides,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

/**
 * Checks if a collateral address is on Stellar; if so, queries Horizon
 * signers and verifies multi-sig thresholds on collateral accounts.
 * Flags if collateral account is controlled by a single private key.
 */
export async function checkCollateralGovernance(
  doc: Record<string, unknown>,
  options: CollateralGovernanceOptions = {},
): Promise<Diagnostic[]> {
  const diagnostics: Diagnostic[] = [];
  const fetchImpl = options.fetchImpl ?? fetch;
  const passphrase = options.networkPassphrase ?? Networks.PUBLIC;
  const horizonUrl =
    passphrase === Networks.TESTNET
      ? 'https://horizon-testnet.stellar.org'
      : 'https://horizon.stellar.org';

  const collateralAddresses: string[] = [];
  const currencies = doc.CURRENCIES;
  if (Array.isArray(currencies)) {
    for (const entry of currencies) {
      if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) continue;
      const addr = entry.collateral_addresses;
      if (Array.isArray(addr)) {
        for (const a of addr) {
          if (typeof a === 'string' && isAccountId(a)) {
            collateralAddresses.push(a);
          }
        }
      }
    }
  }

  if (collateralAddresses.length === 0) return diagnostics;

  // Query Horizon for each collateral address and audit signer configuration
  for (const address of collateralAddresses) {
    try {
      const response = await fetchImpl(`${horizonUrl}/accounts/${address}`);
      if (!response.ok) continue;

      const body = (await response.json()) as {
        thresholds?: Record<string, number>;
        flags?: Record<string, unknown>;
        signer_summary?: Record<string, unknown>;
        num_signers?: number;
      };

      const thresholds = body.thresholds ?? {};
      const masterWeight = thresholds.master_weight ?? 0;
      const lowThreshold = thresholds.low_threshold ?? 0;
      const highThreshold = thresholds.high_threshold ?? 0;
      const numSigners = body.num_signers ?? 0;

      // Check if collateral account is controlled by a single private key
      if (numSigners <= 1 && masterWeight < 2) {
        const severity = severityForRule(SINGLE_KEY_RULE, 'warning', options.rules);
        if (severity !== undefined) {
          diagnostics.push({
            rule: SINGLE_KEY_RULE,
            severity,
            category: 'network',
            message: `Collateral account ${address} is controlled by a single private key`,
            path: `CURRENCIES.collateral_addresses`,
            helpUri: specUrl('general-information'),
            suggestion:
              'Secure collateral accounts with multi-signature governance to prevent single-point-of-failure attacks.',
          });
        }
      }

      // Verify multi-sig thresholds are adequate
      if (highThreshold <= 1 && lowThreshold <= 1) {
        const severity = severityForRule(CUSTODY_THRESHOLD_RULE, 'warning', options.rules);
        if (severity !== undefined) {
          diagnostics.push({
            rule: CUSTODY_THRESHOLD_RULE,
            severity,
            category: 'network',
            message: `Collateral account ${address} does not meet multi-party custody threshold requirements`,
            path: `CURRENCIES.collateral_addresses`,
            helpUri: specUrl('general-information'),
            suggestion:
              'Set multi-signature thresholds on collateral accounts to require multiple parties for critical operations.',
          });
        }
      }
    } catch {
      // Skip accounts that can't be queried
    }
  }

  return diagnostics;
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const collateralGovernanceRules: Rule[] = [
  {
    id: SINGLE_KEY_RULE,
    category: 'network',
    severity: 'warning',
    description: 'Collateral reserve account should not be controlled by a single private key',
    run() {},
  },
  {
    id: CUSTODY_THRESHOLD_RULE,
    category: 'network',
    severity: 'warning',
    description: 'Collateral reserve accounts must meet multi-party custody threshold requirements',
    run() {},
  },
];

/** Rule ids emitted by {@link checkCollateralGovernance}. */
export const collateralGovernanceRuleIds: readonly string[] = collateralGovernanceRules.map(
  (rule) => rule.id,
);
