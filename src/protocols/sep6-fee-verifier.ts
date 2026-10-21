/**
 * SEP-6 dynamic fee calculation verifier.
 *
 * Runs under opt-in `--check-network --verify-sep6`.
 *
 * Anchors price SEP-6 transfers with `GET /fee`, and tiered schedules are
 * normal: 0.5% below a threshold, 0.25% above it. What must never happen is a
 * fee curve that dips when the amount rises — a client that sizes a transfer
 * from a smaller sample then pays the larger amount can be charged more than
 * the quote it accepted — or a fee outside the `fee_minimum`/`fee_maximum`
 * bounds the same anchor publishes in `/info`.
 *
 * The verifier samples amounts from 1 to 100,000 units, in ascending order, and
 * checks three properties for every asset `/info` advertises:
 *
 *   1. `amount_fee` is strictly positive and never exceeds the amount;
 *   2. the curve is non-decreasing (monotonic);
 *   3. the fee stays inside the bounds declared in `/info`.
 *
 * Transport failures and auth rejections are silence: an unreachable transfer
 * server says nothing about the fee formula, and `sep6/...` schema rules
 * already cover a malformed `/info` entry.
 */

import type { Diagnostic, Rule, RuleCategory, RuleOverrides, Severity } from '../types.js';
import { isString, isUrl } from '../predicates.js';

export const NON_MONOTONIC_FEE_CURVE_RULE = 'sep6/non-monotonic-fee-curve';
export const FEE_EXCEEDS_DECLARED_BOUNDS_RULE = 'sep6/fee-exceeds-declared-bounds';

const SEP6_SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0006.md';

/**
 * Amounts sampled in ascending order. The set brackets the tiers anchors
 * commonly publish (10, 100, 1,000, 10,000) so a discontinuity at a threshold
 * lands between two adjacent samples.
 */
export const DEFAULT_FEE_SAMPLE_AMOUNTS: readonly number[] = [
  1, 5, 10, 25, 50, 100, 250, 500, 750, 1_000, 2_500, 5_000, 7_500, 10_000, 25_000, 50_000, 100_000,
];

const DEFAULT_MAX_TARGETS = 3;
const FEE_TOLERANCE = 1e-9;

export interface Sep6FeeVerifierOptions {
  rules?: RuleOverrides;
  /** Amounts to sample, ascending. Defaults to {@link DEFAULT_FEE_SAMPLE_AMOUNTS}. */
  amounts?: readonly number[];
  /** How many `/info` assets to sample, to bound the number of requests. */
  maxTargets?: number;
}

interface FeeBounds {
  minimum?: number;
  maximum?: number;
}

interface FeeTarget {
  operation: 'deposit' | 'withdraw';
  assetCode: string;
  path: string;
  bounds: FeeBounds;
}

function severityFor(
  rule: string,
  fallback: Severity,
  rules?: RuleOverrides,
): Severity | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override ?? fallback;
}

function report(
  diagnostics: Diagnostic[],
  rule: string,
  fallback: Severity,
  message: string,
  suggestion: string,
  rules?: RuleOverrides,
  extras: Partial<Diagnostic> = {},
): void {
  const severity = severityFor(rule, fallback, rules);
  if (severity === undefined) return;
  diagnostics.push({
    rule,
    severity,
    category: 'network' as RuleCategory,
    message,
    helpUri: SEP6_SPEC,
    suggestion,
    ...extras,
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Reads a numeric fee, accepting the string spelling some anchors return. */
function numberOf(value: unknown): number | undefined {
  if (typeof value === 'number') return Number.isFinite(value) ? value : undefined;
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : undefined;
  }
  return undefined;
}

function boundsOf(entry: Record<string, unknown>): FeeBounds {
  const nested = isRecord(entry.fee) ? entry.fee : {};
  const minimum = numberOf(nested.minimum) ?? numberOf(entry.fee_minimum);
  const maximum = numberOf(nested.maximum) ?? numberOf(entry.fee_maximum);
  const bounds: FeeBounds = {};
  if (minimum !== undefined) bounds.minimum = minimum;
  if (maximum !== undefined) bounds.maximum = maximum;
  return bounds;
}

/** Every asset `/info` prices, in declaration order, capped at `maxTargets`. */
function feeTargets(info: Record<string, unknown>, maxTargets: number): FeeTarget[] {
  const targets: FeeTarget[] = [];

  for (const operation of ['deposit', 'withdraw'] as const) {
    const map = info[operation];
    if (!isRecord(map)) continue;

    for (const [key, entry] of Object.entries(map)) {
      if (!isRecord(entry)) continue;
      const assetCode = key.split(':')[0];
      if (assetCode === undefined || assetCode === '') continue;
      targets.push({
        operation,
        assetCode,
        path: `TRANSFER_SERVER /info ${operation}.${key}`,
        bounds: boundsOf(entry),
      });
      if (targets.length >= maxTargets) return targets;
    }
  }

  return targets;
}

async function fetchInfo(
  base: string,
  fetchImpl: typeof fetch,
): Promise<Record<string, unknown> | undefined> {
  try {
    const response = await fetchImpl(`${base}/info`, { redirect: 'follow' });
    if (!response.ok) return undefined;
    const body: unknown = await response.json();
    return isRecord(body) ? body : undefined;
  } catch {
    return undefined;
  }
}

async function fetchFee(
  base: string,
  target: FeeTarget,
  amount: number,
  fetchImpl: typeof fetch,
): Promise<number | undefined> {
  const url = new URL(`${base}/fee`);
  url.searchParams.set('operation', target.operation);
  url.searchParams.set('asset_code', target.assetCode);
  url.searchParams.set('amount', String(amount));

  try {
    const response = await fetchImpl(url.toString(), { redirect: 'follow' });
    if (!response.ok) return undefined;
    const body: unknown = await response.json();
    if (!isRecord(body)) return undefined;
    return numberOf(body.fee) ?? numberOf(body.amount_fee);
  } catch {
    return undefined;
  }
}

function formatMoney(value: number): string {
  return Number.isInteger(value) ? String(value) : value.toFixed(7).replace(/0+$/, '');
}

/**
 * Samples the fee curve for each asset `/info` advertises and reports the first
 * non-monotonic segment and the first out-of-bounds quote per rule.
 */
export async function verifySep6FeeCurve(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: Sep6FeeVerifierOptions = {},
): Promise<Diagnostic[]> {
  const server = doc.TRANSFER_SERVER;
  if (!isString(server) || !isUrl(server)) return [];

  const base = server.replace(/\/+$/, '');
  const info = await fetchInfo(base, fetchImpl);
  if (info === undefined) return [];

  const amounts = options.amounts ?? DEFAULT_FEE_SAMPLE_AMOUNTS;
  const maxTargets = options.maxTargets ?? DEFAULT_MAX_TARGETS;
  const targets = feeTargets(info, maxTargets);
  const diagnostics: Diagnostic[] = [];

  for (const target of targets) {
    let previous: { amount: number; fee: number } | undefined;
    let reportedNonMonotonic = false;
    let reportedBounds = false;

    for (const amount of amounts) {
      if (!Number.isFinite(amount) || amount <= 0) continue;

      const fee = await fetchFee(base, target, amount, fetchImpl);
      if (fee === undefined) continue;

      // 1. A fee has to be positive and cannot exceed the transfer itself.
      if (!reportedBounds && (fee <= 0 || fee > amount)) {
        reportedBounds = true;
        report(
          diagnostics,
          FEE_EXCEEDS_DECLARED_BOUNDS_RULE,
          'error',
          `GET /fee returned ${formatMoney(fee)} ${target.assetCode} for a ${formatMoney(amount)} ${target.assetCode} ${target.operation}, which is ${fee <= 0 ? 'not positive' : 'larger than the transaction amount'}`,
          'Charge a strictly positive fee that never exceeds the amount being transferred.',
          options.rules,
          { path: target.path },
        );
      }

      // 2. The declared floor/ceiling must hold at every sample.
      const { minimum, maximum } = target.bounds;
      if (
        !reportedBounds &&
        ((minimum !== undefined && fee < minimum - FEE_TOLERANCE) ||
          (maximum !== undefined && fee > maximum + FEE_TOLERANCE))
      ) {
        reportedBounds = true;
        const declared =
          minimum !== undefined && maximum !== undefined
            ? `[${formatMoney(minimum)}, ${formatMoney(maximum)}]`
            : minimum !== undefined
              ? `at least ${formatMoney(minimum)}`
              : `at most ${formatMoney(maximum ?? 0)}`;
        report(
          diagnostics,
          FEE_EXCEEDS_DECLARED_BOUNDS_RULE,
          'error',
          `GET /fee returned ${formatMoney(fee)} for a ${formatMoney(amount)} ${target.assetCode} ${target.operation}, outside the ${declared} declared in /info`,
          'Make GET /fee respect the fee_minimum and fee_maximum bounds /info publishes.',
          options.rules,
          { path: target.path },
        );
      }

      // 3. Larger amounts must never be charged proportionally less.
      if (!reportedNonMonotonic && previous !== undefined && fee < previous.fee - FEE_TOLERANCE) {
        reportedNonMonotonic = true;
        report(
          diagnostics,
          NON_MONOTONIC_FEE_CURVE_RULE,
          'error',
          `GET /fee for ${target.assetCode} ${target.operation} dropped from ${formatMoney(previous.fee)} at amount ${formatMoney(previous.amount)} to ${formatMoney(fee)} at amount ${formatMoney(amount)}`,
          'Keep the fee curve non-decreasing so a larger transfer is never charged less than a smaller one.',
          options.rules,
          { path: target.path },
        );
      }

      previous = { amount, fee };
    }
  }

  return diagnostics;
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const sep6FeeVerifierRules: Rule[] = [
  {
    id: NON_MONOTONIC_FEE_CURVE_RULE,
    category: 'network',
    severity: 'error',
    description: 'SEP-6 GET /fee must produce a non-decreasing fee curve across sampled amounts',
    run() {},
  },
  {
    id: FEE_EXCEEDS_DECLARED_BOUNDS_RULE,
    category: 'network',
    severity: 'error',
    description:
      'SEP-6 GET /fee must be positive, within the amount, and inside the /info fee bounds',
    run() {},
  },
];
