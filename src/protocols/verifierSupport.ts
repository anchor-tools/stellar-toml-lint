/**
 * Small helpers shared by the opt-in protocol verifiers (SEP-30, SEP-38
 * promotions, federation SRV, ESG). Kept dependency-free on purpose: this
 * runs in other people's CI.
 */

import type { Diagnostic, RuleCategory, RuleOverrides, Severity } from '../types.js';

/** Removes trailing slashes in linear time (no backtracking regular expression). */
export function trimTrailingSlashes(value: string): string {
  let end = value.length;
  while (end > 0 && value.charCodeAt(end - 1) === 47) end--;
  return value.slice(0, end);
}

/** Removes trailing slashes in linear time (no backtracking regular expression). */
export function trimTrailingSlashes(value: string): string {
  let end = value.length;
  while (end > 0 && value.charCodeAt(end - 1) === 47) end--;
  return value.slice(0, end);
}

export function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Resolves the effective severity for a rule, or `undefined` when it is turned off. */
export function severityFor(
  rule: string,
  fallback: Severity,
  rules?: RuleOverrides,
): Severity | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' || override === 'info'
    ? override
    : fallback;
}

/**
 * `fetch` that gives up after `timeoutMs`. An unreachable anchor must cost the
 * user seconds, not a hung CI job.
 */
export async function fetchWithTimeout(
  fetchImpl: typeof fetch,
  url: string,
  init: RequestInit = {},
  timeoutMs = 5000,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetchImpl(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Decimal digits kept by {@link toScaled}. Stellar amounts have 7. */
export const AMOUNT_SCALE = 7;

/** Parses a non-negative decimal string into an exact integer of 10^-7 units. */
export function toScaled(value: string): bigint | undefined {
  const m = /^(\d+)(?:\.(\d+))?$/.exec(value.trim());
  if (!m) return undefined;
  const fraction = (m[2] ?? '').slice(0, AMOUNT_SCALE).padEnd(AMOUNT_SCALE, '0');
  return BigInt(m[1] as string) * 10n ** BigInt(AMOUNT_SCALE) + BigInt(fraction);
}

/**
 * `fee / amount` as a percentage in 1/10000ths of a percent (so 1.5% is
 * 15000n), computed with integers so rounding never hides a hidden fee.
 */
export function feePercentUnits(fee: string, amount: string): bigint | undefined {
  const f = toScaled(fee);
  const a = toScaled(amount);
  if (f === undefined || a === undefined || a === 0n) return undefined;
  return (f * 100n * 10000n) / a;
}

/** Builds a `push` that appends diagnostics, honouring rule overrides. */
export function createReporter(
  diagnostics: Diagnostic[],
  rules: RuleOverrides | undefined,
  helpUri: string,
  category: RuleCategory,
): (
  rule: string,
  fallback: 'error' | 'warning',
  message: string,
  path: string,
  suggestion: string,
) => void {
  return (rule, fallback, message, path, suggestion) => {
    const severity = severityFor(rule, fallback, rules);
    if (severity === undefined) return;
    diagnostics.push({ rule, severity, category, message, path, helpUri, suggestion });
  };
}
