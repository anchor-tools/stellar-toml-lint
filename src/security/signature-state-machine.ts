/**
 * Ed25519 threshold signature state-machine validator.
 *
 * Institutional anchors often hold assets in cold/warm multi-signature accounts
 * that require specific signer combinations. This module enumerates every
 * combination of the configured signers (the power set), computes the
 * cumulative weight of each, and flags schemes where a single compromised key
 * can reach the medium threshold on its own, where the weight distribution is
 * dangerously skewed, or where the high threshold is unreachable (a deadlock
 * that freezes funds).
 *
 * Runs offline: the signer set and thresholds are supplied by the caller (or
 * read from a Horizon account record elsewhere), so this validator is pure.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';

export const SECURITY_INSUFFICIENT_THRESHOLD_PROTECTION =
  'security/insufficient-threshold-protection';
export const SECURITY_UNBALANCED_SIGNER_WEIGHTS = 'security/unbalanced-signer-weights';

export const INSUFFICIENT_THRESHOLD_PROTECTION_RULE = SECURITY_INSUFFICIENT_THRESHOLD_PROTECTION;
export const UNBALANCED_SIGNER_WEIGHTS_RULE = SECURITY_UNBALANCED_SIGNER_WEIGHTS;

const SECURITY_SPEC = 'https://developers.stellar.org/docs/learn/encyclopedia/security/signatures-multisig';

export interface Signer {
  /** Stellar account id (or pre-auth-tx hash) of the signer. */
  key: string;
  /** Signing weight as configured on-chain. */
  weight: number;
}

export interface SignerThresholds {
  low: number;
  medium: number;
  high: number;
}

export interface SignatureScheme {
  signers: readonly Signer[];
  thresholds: SignerThresholds;
  /** Master key weight, when the account has one. Defaults to 0. */
  masterWeight?: number;
}

export interface SignatureStateMachineOptions {
  rules?: RuleOverrides;
}

export interface SignatureCombination {
  /** Signer keys included in this combination. */
  signatures: readonly string[];
  /** Cumulative weight of the combination. */
  weight: number;
  /** Whether the combination alone satisfies the medium threshold. */
  meetsMedium: boolean;
  /** Whether the combination alone satisfies the high threshold. */
  meetsHigh: boolean;
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

/** Every subset of `signers`, including the empty set (first entry). */
export function signerCombinations(signers: readonly Signer[]): Signer[][] {
  const combinations: Signer[][] = [[]];
  for (const signer of signers) {
    const additions = combinations.map((combination) => [...combination, signer]);
    combinations.push(...additions);
  }
  return combinations;
}

/**
 * Enumerate the non-empty combinations of a scheme with their cumulative
 * weights and whether each satisfies the medium/high thresholds.
 */
export function analyzeSignatureCombinations(
  scheme: SignatureScheme,
): SignatureCombination[] {
  return signerCombinations(scheme.signers)
    .filter((combination) => combination.length > 0)
    .map((combination) => {
      const weight = combination.reduce((sum, signer) => sum + signer.weight, 0);
      return {
        signatures: combination.map((signer) => signer.key),
        weight,
        meetsMedium: weight >= scheme.thresholds.medium,
        meetsHigh: weight >= scheme.thresholds.high,
      };
    });
}

/** Signers that, on their own, satisfy the medium threshold. */
export function singleSignerThresholdBreakers(scheme: SignatureScheme): Signer[] {
  return scheme.signers.filter(
    (signer) => signer.weight >= scheme.thresholds.medium && signer.weight > 0,
  );
}

export function checkSignatureStateMachine(
  scheme: SignatureScheme,
  options: SignatureStateMachineOptions = {},
): Diagnostic[] {
  const { rules } = options;
  const diagnostics: Diagnostic[] = [];
  const { signers, thresholds } = scheme;

  if (signers.length === 0) return diagnostics;

  const totalSignerWeight = signers.reduce((sum, signer) => sum + signer.weight, 0);
  const totalWeight = totalSignerWeight + (scheme.masterWeight ?? 0);

  const insecureSeverity = severityFor(
    SECURITY_INSUFFICIENT_THRESHOLD_PROTECTION,
    'warning',
    rules,
  );
  if (insecureSeverity !== undefined) {
    const singleKeyBreakers = singleSignerThresholdBreakers(scheme);
    if (singleKeyBreakers.length > 0) {
      diagnostics.push({
        rule: SECURITY_INSUFFICIENT_THRESHOLD_PROTECTION,
        severity: insecureSeverity,
        category: 'principals',
        message: `Signer ${singleKeyBreakers[0]?.key} alone meets the medium threshold of ${thresholds.medium}, so a single compromised key can move funds`,
        suggestion:
          'Lower individual signer weights (or raise the medium threshold) so no single key can authorize medium-risk operations without a co-signer.',
        helpUri: SECURITY_SPEC,
      });
    } else if (totalWeight < thresholds.high) {
      diagnostics.push({
        rule: SECURITY_INSUFFICIENT_THRESHOLD_PROTECTION,
        severity: insecureSeverity,
        category: 'principals',
        message: `The maximum achievable weight of ${totalWeight} is below the high threshold of ${thresholds.high}, which permanently locks the account`,
        suggestion:
          'Increase signer weights or lower the high threshold so the account can still authorize high-risk operations.',
        helpUri: SECURITY_SPEC,
      });
    }
  }

  const unbalancedSeverity = severityFor(SECURITY_UNBALANCED_SIGNER_WEIGHTS, 'warning', rules);
  if (unbalancedSeverity !== undefined && signers.length >= 2 && totalSignerWeight > 0) {
    const dominant = [...signers].sort((a, b) => b.weight - a.weight)[0];
    if (dominant !== undefined && dominant.weight > totalSignerWeight / 2) {
      diagnostics.push({
        rule: SECURITY_UNBALANCED_SIGNER_WEIGHTS,
        severity: unbalancedSeverity,
        category: 'principals',
        message: `Signer ${dominant.key} holds ${dominant.weight} of ${totalSignerWeight} total weight, giving it majority control of the account`,
        suggestion:
          'Rebalance signer weights so no single signer outweighs the rest of the quorum combined.',
        helpUri: SECURITY_SPEC,
      });
    }
  }

  return diagnostics;
}

export function checkSignatureStateMachineFromDocument(
  doc: Record<string, unknown>,
  options: SignatureStateMachineOptions = {},
): Diagnostic[] {
  const scheme = signatureSchemeFromDocument(doc);
  if (scheme === undefined) return [];
  return checkSignatureStateMachine(scheme, options);
}

/**
 * Best-effort extraction of a scheme from a parsed stellar.toml document.
 * Signers are not part of SEP-1, so this only fires when a document (or a
 * tooling fixture) carries an explicit `SIGNERS` / `THRESHOLDS` block.
 */
export function signatureSchemeFromDocument(
  doc: Record<string, unknown>,
): SignatureScheme | undefined {
  const rawSigners = doc.SIGNERS;
  const rawThresholds = doc.THRESHOLDS;
  if (!Array.isArray(rawSigners) || rawThresholds === undefined) return undefined;
  if (typeof rawThresholds !== 'object' || rawThresholds === null || Array.isArray(rawThresholds)) {
    return undefined;
  }

  const signers: Signer[] = [];
  for (const entry of rawSigners) {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) continue;
    const record = entry as Record<string, unknown>;
    const key = record.key ?? record.KEY;
    const weight = record.weight ?? record.WEIGHT;
    if (typeof key === 'string' && typeof weight === 'number' && Number.isFinite(weight)) {
      signers.push({ key, weight });
    }
  }
  if (signers.length === 0) return undefined;

  const thresholds = rawThresholds as Record<string, unknown>;
  const read = (value: unknown): number => (typeof value === 'number' && Number.isFinite(value) ? value : 0);

  return {
    signers,
    thresholds: {
      low: read(thresholds.low ?? thresholds.LOW),
      medium: read(thresholds.medium ?? thresholds.MEDIUM),
      high: read(thresholds.high ?? thresholds.HIGH),
    },
  };
}

export const signatureStateMachineRules: Rule[] = [
  {
    id: SECURITY_INSUFFICIENT_THRESHOLD_PROTECTION,
    category: 'principals',
    severity: 'warning',
    description:
      'No single signer should be able to reach the medium threshold, and the high threshold must be reachable',
    run() {},
  },
  {
    id: SECURITY_UNBALANCED_SIGNER_WEIGHTS,
    category: 'principals',
    severity: 'warning',
    description: 'No single signer should outweigh all other signers combined',
    run() {},
  },
];

export const signatureStateMachineRuleIds: readonly string[] = signatureStateMachineRules.map(
  (rule) => rule.id,
);
