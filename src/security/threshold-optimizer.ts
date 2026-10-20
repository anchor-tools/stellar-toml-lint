/**
 * Exact signer-coalition optimizer for Horizon account thresholds.
 *
 * Stellar account thresholds are a small 0/1 knapsack: every signer is either
 * present or absent, and a coalition wins when its weights meet a threshold.
 * The solver enumerates the power set (capped at 24 signers) and retains only
 * minimal winning coalitions, which makes the result useful during key
 * rotation instead of merely reporting the total signer weight.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { horizonUrlFor } from '../network-checks.js';

export const SECURITY_USELESS_SIGNER_DETECTED = 'security/useless-signer-detected';
export const SECURITY_UNINTENDED_VETO_KEY = 'security/unintended-veto-key';

export const USELESS_SIGNER_DETECTED_RULE = SECURITY_USELESS_SIGNER_DETECTED;
export const UNINTENDED_VETO_KEY_RULE = SECURITY_UNINTENDED_VETO_KEY;

export const MAX_OPTIMIZER_SIGNERS = 24;

export type ThresholdName = 'low' | 'medium' | 'high';

export interface ThresholdSigner {
  key: string;
  weight: number;
  type?: string;
}

export interface Thresholds {
  low: number;
  medium: number;
  high: number;
}

export interface ThresholdAccount {
  accountId: string;
  signers: readonly ThresholdSigner[];
  thresholds: Thresholds;
  masterWeight?: number;
  role?: string;
}

export interface SignerCoalition {
  keys: string[];
  weight: number;
}

export interface ThresholdOptimization {
  accountId: string;
  role: string;
  signers: ThresholdSigner[];
  thresholds: Thresholds;
  coalitions: Record<ThresholdName, SignerCoalition[]>;
  /** Alias kept intentionally descriptive for consumers rendering reports. */
  minimalCoalitions: Record<ThresholdName, SignerCoalition[]>;
  dummySigners: string[];
  vetoKeys: string[];
}

export interface ThresholdOptimizerOptions {
  rules?: RuleOverrides;
  horizonUrl?: string;
  fetchImpl?: typeof fetch;
  accounts?: readonly ThresholdAccount[];
}

interface AccountTarget {
  accountId: string;
  role: string;
  path: string;
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

function nonNegativeInteger(value: unknown, fallback = 0): number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 ? value : fallback;
}

function thresholdValue(value: unknown): number {
  return nonNegativeInteger(value);
}

function uniqueSigners(signers: readonly ThresholdSigner[]): ThresholdSigner[] {
  const seen = new Set<string>();
  return signers.filter((signer) => {
    if (seen.has(signer.key)) return false;
    seen.add(signer.key);
    return Number.isFinite(signer.weight) && signer.weight >= 0;
  });
}

/**
 * Finds every inclusion-minimal subset whose weight reaches `threshold`.
 * Empty threshold coalitions are represented by one empty coalition.
 */
export function solveMinimalWinningCoalitions(
  signers: readonly ThresholdSigner[],
  threshold: number,
): SignerCoalition[] {
  const normalized = uniqueSigners(signers).slice(0, MAX_OPTIMIZER_SIGNERS);
  const required = thresholdValue(threshold);
  if (required === 0) return [{ keys: [], weight: 0 }];
  if (normalized.length > MAX_OPTIMIZER_SIGNERS) return [];

  const coalitions: SignerCoalition[] = [];
  const selected: ThresholdSigner[] = [];
  const visit = (index: number, weight: number): void => {
    if (weight >= required) {
      // A winning set is minimal precisely when removing every selected signer
      // makes it lose.  This is cheaper and clearer than comparing all earlier
      // subsets, and remains exact for duplicate weights.
      if (selected.every((signer) => weight - signer.weight < required)) {
        coalitions.push({
          keys: selected.map((signer) => signer.key),
          weight,
        });
      }
      return;
    }
    if (index >= normalized.length) return;
    for (let cursor = index; cursor < normalized.length; cursor++) {
      const signer = normalized[cursor];
      if (signer === undefined) continue;
      selected.push(signer);
      visit(cursor + 1, weight + signer.weight);
      selected.pop();
    }
  };
  visit(0, 0);
  return coalitions;
}

export const minimalWinningCoalitions = solveMinimalWinningCoalitions;
export const findMinimalWinningCoalitions = solveMinimalWinningCoalitions;

function thresholdMap(input: {
  signers: readonly ThresholdSigner[];
  thresholds: Thresholds;
}): Record<ThresholdName, SignerCoalition[]> {
  return {
    low: solveMinimalWinningCoalitions(input.signers, input.thresholds.low),
    medium: solveMinimalWinningCoalitions(input.signers, input.thresholds.medium),
    high: solveMinimalWinningCoalitions(input.signers, input.thresholds.high),
  };
}

/** Solves all three thresholds and classifies non-contributing / veto keys. */
export function optimizeThresholds(input: ThresholdAccount): ThresholdOptimization {
  const signers = uniqueSigners(input.signers).slice(0, MAX_OPTIMIZER_SIGNERS);
  const thresholds = {
    low: thresholdValue(input.thresholds.low),
    medium: thresholdValue(input.thresholds.medium),
    high: thresholdValue(input.thresholds.high),
  };
  const coalitions = thresholdMap({ signers, thresholds });
  const winning = [...coalitions.low, ...coalitions.medium, ...coalitions.high];
  const dummySigners = signers
    .filter((signer) => !winning.some((coalition) => coalition.keys.includes(signer.key)))
    .map((signer) => signer.key);
  const vetoKeys = signers
    .filter((signer) =>
      (['low', 'medium', 'high'] as const).some((name) => {
        const threshold = thresholds[name];
        return (
          threshold > 0 &&
          signers.reduce((sum, item) => sum + item.weight, 0) - signer.weight < threshold
        );
      }),
    )
    .map((signer) => signer.key);

  return {
    accountId: input.accountId,
    role: input.role ?? 'account',
    signers,
    thresholds,
    coalitions,
    minimalCoalitions: coalitions,
    dummySigners,
    vetoKeys,
  };
}

export const analyzeThresholds = optimizeThresholds;
export const optimizeSignerWeights = optimizeThresholds;

function accountTargets(doc: Record<string, unknown>): AccountTarget[] {
  const targets: AccountTarget[] = [];
  if (typeof doc.SIGNING_KEY === 'string' && doc.SIGNING_KEY.trim() !== '') {
    targets.push({ accountId: doc.SIGNING_KEY.trim(), role: 'SIGNING_KEY', path: 'SIGNING_KEY' });
  }
  if (Array.isArray(doc.CURRENCIES)) {
    doc.CURRENCIES.forEach((entry, index) => {
      if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) return;
      const value = entry as Record<string, unknown>;
      if (typeof value.issuer !== 'string' || value.issuer.trim() === '') return;
      const accountId = value.issuer.trim();
      if (targets.some((target) => target.accountId === accountId)) return;
      const code = typeof value.code === 'string' ? value.code : 'asset';
      targets.push({ accountId, role: `issuer ${code}`, path: `CURRENCIES[${index}].issuer` });
    });
  }
  return targets;
}

function parseAccount(accountId: string, body: unknown): ThresholdAccount | undefined {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) return undefined;
  const record = body as Record<string, unknown>;
  if (!Array.isArray(record.signers)) return undefined;
  const signers: ThresholdSigner[] = record.signers.flatMap((entry) => {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) return [];
    const signer = entry as Record<string, unknown>;
    if (typeof signer.key !== 'string' || typeof signer.weight !== 'number') return [];
    return [
      {
        key: signer.key,
        weight: signer.weight,
        ...(typeof signer.type === 'string' ? { type: signer.type } : {}),
      },
    ];
  });
  const rawThresholds = record.thresholds;
  if (typeof rawThresholds !== 'object' || rawThresholds === null || Array.isArray(rawThresholds)) {
    return undefined;
  }
  const thresholds = rawThresholds as Record<string, unknown>;
  return {
    accountId,
    signers,
    thresholds: {
      low: thresholdValue(thresholds.low_threshold),
      medium: thresholdValue(thresholds.med_threshold),
      high: thresholdValue(thresholds.high_threshold),
    },
    ...(typeof record.master_key_weight === 'number'
      ? { masterWeight: record.master_key_weight }
      : {}),
  };
}

async function fetchAccount(
  accountId: string,
  horizonUrl: string,
  fetchImpl: typeof fetch,
): Promise<ThresholdAccount | undefined> {
  try {
    const response = await fetchImpl(
      `${horizonUrl.replace(/\/+$/, '')}/accounts/${encodeURIComponent(accountId)}`,
    );
    if (!response.ok) return undefined;
    return parseAccount(accountId, await response.json());
  } catch {
    return undefined;
  }
}

/** Queries Horizon for SIGNING_KEY and every unique issuer account. */
export async function checkThresholdOptimizer(
  doc: Record<string, unknown>,
  options: ThresholdOptimizerOptions = {},
): Promise<Diagnostic[]> {
  const targets = accountTargets(doc);
  if (targets.length === 0) return [];
  const passphrase =
    typeof doc.NETWORK_PASSPHRASE === 'string' ? doc.NETWORK_PASSPHRASE : undefined;
  const horizonUrl = options.horizonUrl ?? horizonUrlFor(passphrase);
  const fetchImpl = options.fetchImpl ?? fetch;
  const supplied = new Map((options.accounts ?? []).map((account) => [account.accountId, account]));
  const uselessSeverity = severityFor(SECURITY_USELESS_SIGNER_DETECTED, 'warning', options.rules);
  const vetoSeverity = severityFor(SECURITY_UNINTENDED_VETO_KEY, 'warning', options.rules);
  const diagnostics: Diagnostic[] = [];

  for (const target of targets) {
    const account =
      supplied.get(target.accountId) ??
      (await fetchAccount(target.accountId, horizonUrl, fetchImpl));
    if (account === undefined) continue;
    const result = optimizeThresholds({ ...account, role: target.role });
    if (uselessSeverity !== undefined && result.dummySigners.length > 0) {
      diagnostics.push({
        rule: SECURITY_USELESS_SIGNER_DETECTED,
        severity: uselessSeverity,
        category: 'principals',
        message: `${target.role} ${target.accountId} has signer(s) that do not appear in any minimal winning coalition: ${result.dummySigners.join(', ')}`,
        path: target.path,
        suggestion:
          'Remove zero-contribution signers or increase their weight so every published recovery key can help meet at least one threshold.',
      });
    }
    if (vetoSeverity !== undefined && result.vetoKeys.length > 0) {
      diagnostics.push({
        rule: SECURITY_UNINTENDED_VETO_KEY,
        severity: vetoSeverity,
        category: 'principals',
        message: `${target.role} ${target.accountId} has veto signer(s) whose removal makes at least one threshold unreachable: ${result.vetoKeys.join(', ')}`,
        path: target.path,
        suggestion:
          'Review whether each veto key is intentional and add independent weight so key loss cannot permanently block account operations.',
      });
    }
  }
  return diagnostics;
}

export const auditThresholds = checkThresholdOptimizer;
export const checkMultisigThresholds = checkThresholdOptimizer;

export const thresholdOptimizerRules: Rule[] = [
  {
    id: SECURITY_USELESS_SIGNER_DETECTED,
    category: 'principals',
    severity: 'warning',
    description: 'Every configured signer should contribute to a minimal winning coalition',
    run() {},
  },
  {
    id: SECURITY_UNINTENDED_VETO_KEY,
    category: 'principals',
    severity: 'warning',
    description: 'Signer loss should not make an account threshold permanently unreachable',
    run() {},
  },
];

export const thresholdOptimizerRuleIds: readonly string[] = thresholdOptimizerRules.map(
  (rule) => rule.id,
);
