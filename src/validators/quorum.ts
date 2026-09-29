/**
 * Validator quorum set simulator and intersection validator (issue #46).
 *
 * This module is the public surface of the quorum analysis engine for issue
 * #46. It re-exports the core algorithms from `quorum-solver.ts` under the
 * stable names the issue specifies, adds the `validators/fragile-quorum-set`
 * rule id (zero-BFT warning), and provides `simulateQuorumBft` — a
 * convenience function that wraps the solver into a single BFT result object
 * suitable for the CLI's quorum summary table.
 *
 * Algorithms implemented
 * ──────────────────────
 * 1. Quorum graph construction
 *    Reads inline `QUORUM_SET` tables or linked `CONFIG_URL` stellar-core.cfg
 *    files for each `[[VALIDATORS]]` entry and normalises them into an
 *    absolute-threshold form the solver can enumerate.
 *
 * 2. Quorum intersection verification
 *    Enumerates every minimal satisfying set (minimal quorum) of each
 *    validator's declared quorum set and checks that no pair is disjoint.
 *    A disjoint pair means two independent subsets of the network can each
 *    close a ledger, producing a split-brain / fork.
 *
 * 3. Byzantine Fault Tolerance (BFT) calculation
 *    Computes the minimal blocking sets — the smallest subsets of validators
 *    whose simultaneous failure prevents any quorum from forming — and derives
 *    the failure resilience: how many nodes can crash before consensus stalls.
 *    Zero resilience is reported as `validators/fragile-quorum-set` (warning).
 *
 * Rules emitted
 * ─────────────
 *   validators/fragile-quorum-set        (warning) — zero BFT / single-node failure stalls consensus
 *   validators/quorum-intersection-failure (error) — disjoint quorums can fork the network
 *
 * The existing `validators/fragile-quorum-threshold` rule (from quorum-solver)
 * continues to fire for below-67% thresholds; this module adds the explicit
 * BFT-zero case under its own id so the two concerns are independently
 * controllable with `--off` / `--warn` / `--error`.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { specUrl } from '../spec.js';
import {
  normalizeQuorumSet,
  minimalQuorums,
  minimalBlockingSets,
  failureResilience,
  findDisjointQuorumPair,
  parseCoreCfgQuorumSet,
  type QuorumSet,
} from './quorum-solver.js';

// ─── Rule IDs ────────────────────────────────────────────────────────────────

/**
 * Fired when a validator's quorum set has zero Byzantine Fault Tolerance —
 * a single node failure is enough to halt consensus for that validator.
 */
export const FRAGILE_QUORUM_SET_RULE = 'validators/fragile-quorum-set';

/**
 * Re-exported so callers only need to import from this module.
 * Fired when two validators can form disjoint quorums (network fork risk).
 */
export { QUORUM_INTERSECTION_FAILURE_RULE } from './quorum-solver.js';

// ─── Public types ─────────────────────────────────────────────────────────────

export interface QuorumSimulatorOptions {
  rules?: RuleOverrides;
  /** Override quorum sets keyed by public key, used in tests. */
  quorumSets?: Record<string, unknown>;
}

/**
 * The result of a BFT simulation for one validator's quorum set.
 */
export interface BftResult {
  /** The validator's public key. */
  publicKey: string;
  /** The TOML path reported in diagnostics. */
  path: string;
  /** Normalised quorum set, or `undefined` when parsing failed. */
  set: QuorumSet | undefined;
  /**
   * Number of simultaneous node failures the quorum set can tolerate before
   * consensus stalls. `0` means a single failure halts this validator.
   * `undefined` when the analysis was incomplete (capped).
   */
  bft: number | undefined;
  /** All minimal quorums enumerated, or `[]` when analysis was capped. */
  minimalQuorums: string[][];
  /** Whether the enumeration completed exhaustively (no cap hit). */
  complete: boolean;
}

// ─── Core simulation ──────────────────────────────────────────────────────────

/**
 * Fetches a validator's quorum set from a `CONFIG_URL` stellar-core.cfg.
 * Returns `undefined` on any network or parse failure — the caller degrades
 * gracefully rather than emitting false findings.
 */
async function fetchQuorumSetFromConfig(
  url: string,
  fetchImpl: typeof fetch,
): Promise<QuorumSet | undefined> {
  try {
    const response = await fetchImpl(url);
    if (!response.ok) return undefined;
    const text = await response.text();
    return parseCoreCfgQuorumSet(text);
  } catch {
    return undefined;
  }
}

/**
 * Resolves the quorum set for one `[[VALIDATORS]]` entry.
 *
 * Priority:
 *   1. `options.quorumSets[publicKey]` override (tests / programmatic use)
 *   2. Inline `QUORUM_SET` table in the entry
 *   3. Remote `CONFIG_URL` stellar-core.cfg
 */
async function resolveQuorumSet(
  entry: Record<string, unknown>,
  publicKey: string,
  fetchImpl: typeof fetch,
  options: QuorumSimulatorOptions,
): Promise<QuorumSet | undefined> {
  const override = options.quorumSets?.[publicKey];
  if (override !== undefined) return normalizeQuorumSet(override);
  if (entry.QUORUM_SET !== undefined) return normalizeQuorumSet(entry.QUORUM_SET);
  if (typeof entry.CONFIG_URL === 'string') {
    return fetchQuorumSetFromConfig(entry.CONFIG_URL, fetchImpl);
  }
  return undefined;
}

/**
 * Simulates the Byzantine Fault Tolerance of a single quorum set.
 *
 * @param publicKey  The validator's public key (used for path and messages).
 * @param index      Index in `[[VALIDATORS]]`, used to build the TOML path.
 * @param set        The normalised quorum set to analyse.
 * @returns          A `BftResult` with BFT figure and minimal quorums.
 */
export function simulateBft(publicKey: string, index: number, set: QuorumSet): BftResult {
  const path = `VALIDATORS[${index}].QUORUM_SET`;
  const { quorums, complete: qComplete } = minimalQuorums(set);
  const { blockingSets, complete: bComplete } = minimalBlockingSets(set, quorums);
  const complete = qComplete && bComplete && quorums.length > 0;
  const bft = complete ? failureResilience(blockingSets, bComplete) : undefined;

  return {
    publicKey,
    path,
    set,
    bft: typeof bft === 'number' ? bft : undefined,
    minimalQuorums: quorums,
    complete,
  };
}

/**
 * Runs the full quorum simulation for every `[[VALIDATORS]]` entry in a
 * stellar.toml document and returns per-validator BFT results.
 *
 * Entries without a resolvable quorum set are silently skipped — the audit
 * only ever reports what it can prove.
 */
export async function simulateQuorumBft(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: QuorumSimulatorOptions = {},
): Promise<BftResult[]> {
  const validators = Array.isArray(doc.VALIDATORS) ? doc.VALIDATORS : [];
  const results: BftResult[] = [];

  for (let index = 0; index < validators.length; index++) {
    const entry = validators[index];
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) continue;
    const record = entry as Record<string, unknown>;
    const publicKey = typeof record.PUBLIC_KEY === 'string' ? record.PUBLIC_KEY : undefined;
    if (publicKey === undefined) continue;

    const set = await resolveQuorumSet(record, publicKey, fetchImpl, options);
    if (set === undefined) continue;

    results.push(simulateBft(publicKey, index, set));
  }

  return results;
}

// ─── Diagnostic checker ───────────────────────────────────────────────────────

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
 * Audits the quorum sets declared in a stellar.toml document for:
 *
 *   - Zero BFT (single node failure stalls consensus) →
 *       `validators/fragile-quorum-set` (warning)
 *   - Disjoint quorum pairs (network fork risk) →
 *       `validators/quorum-intersection-failure` (error)
 *
 * Validators without a resolvable quorum set, unreachable CONFIG_URLs, and
 * analyses that hit the enumeration cap all degrade to silence.
 */
export async function auditQuorumSets(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: QuorumSimulatorOptions = {},
): Promise<Diagnostic[]> {
  const results = await simulateQuorumBft(doc, fetchImpl, options);
  if (results.length < 2) return [];

  const diagnostics: Diagnostic[] = [];

  // ── BFT-zero warning (validators/fragile-quorum-set) ──────────────────────
  for (const result of results) {
    if (!result.complete) continue;
    if (result.bft !== 0) continue;

    const severity = severityFor(FRAGILE_QUORUM_SET_RULE, 'warning', options.rules);
    if (severity === undefined) continue;

    diagnostics.push({
      rule: FRAGILE_QUORUM_SET_RULE,
      severity,
      category: 'validators',
      message:
        `Validator ${result.publicKey} has zero Byzantine Fault Tolerance — ` +
        'a single node failure is enough to halt consensus for this validator',
      path: result.path,
      helpUri: specUrl('validator-information'),
      suggestion:
        'Raise the quorum set threshold or add more validators so the cluster can survive ' +
        'at least one node failure without stalling.',
    });
  }

  // ── Quorum intersection check (validators/quorum-intersection-failure) ─────
  const { QUORUM_INTERSECTION_FAILURE_RULE } = await import('./quorum-solver.js');

  outer: for (let i = 0; i < results.length; i++) {
    for (let j = i + 1; j < results.length; j++) {
      const left = results[i];
      const right = results[j];
      if (left === undefined || right === undefined) continue;
      if (!left.complete || !right.complete) continue;

      const pair = findDisjointQuorumPair(
        { publicKey: left.publicKey, quorums: left.minimalQuorums },
        { publicKey: right.publicKey, quorums: right.minimalQuorums },
      );

      if (pair !== undefined) {
        const severity = severityFor(QUORUM_INTERSECTION_FAILURE_RULE, 'error', options.rules);
        if (severity !== undefined) {
          diagnostics.push({
            rule: QUORUM_INTERSECTION_FAILURE_RULE,
            severity,
            category: 'validators',
            message:
              `Quorum intersection can fail: ${left.publicKey} and ${right.publicKey} can form ` +
              `disjoint quorums (${pair[0].join(', ')} vs ${pair[1].join(', ')}), so the ` +
              'network can split-brain and close conflicting ledgers on each side',
            path: left.path,
            helpUri: specUrl('validator-information'),
            suggestion:
              'Redefine the quorum sets so every pair of quorums shares at least one ' +
              'validator, or add an overlapping high-threshold slice both sides must agree with.',
          });
        }
        break outer;
      }
    }
  }

  return diagnostics;
}

/**
 * Formats the BFT simulation results as a summary table string, suitable for
 * the `--audit-quorum` CLI output.
 *
 * Example output:
 *   Quorum set audit — 3 validators
 *   ─────────────────────────────────────────────
 *   GAOO…  BFT: 1  quorums: 3  complete: yes
 *   GAVL…  BFT: 1  quorums: 3  complete: yes
 *   GAYB…  BFT: 1  quorums: 3  complete: yes
 *   ─────────────────────────────────────────────
 *   Quorum intersection: SAFE
 */
export function formatQuorumSummaryTable(results: BftResult[], intersectionSafe: boolean): string {
  if (results.length === 0) return 'Quorum set audit — no validators with declared quorum sets.\n';

  const lines: string[] = [
    `Quorum set audit — ${results.length} validator${results.length === 1 ? '' : 's'}`,
    '─'.repeat(60),
  ];

  for (const r of results) {
    const key =
      r.publicKey.length > 8 ? `${r.publicKey.slice(0, 4)}…${r.publicKey.slice(-4)}` : r.publicKey;
    const bftStr = r.bft === undefined ? 'unknown' : r.bft === 0 ? '0 ⚠' : String(r.bft);
    const completeStr = r.complete ? 'yes' : 'partial';
    lines.push(
      `  ${key.padEnd(12)}  BFT: ${bftStr.padEnd(8)}  quorums: ${String(r.minimalQuorums.length).padEnd(5)}  complete: ${completeStr}`,
    );
  }

  lines.push('─'.repeat(60));
  lines.push(`  Quorum intersection: ${intersectionSafe ? 'SAFE ✓' : 'UNSAFE — fork risk ✗'}`);
  lines.push('');

  return lines.join('\n');
}

// ─── Rule registry ────────────────────────────────────────────────────────────

/**
 * Rule definitions for `--list-rules`, `--off`, `--warn`, `--error`, and SARIF.
 * Only the NEW rule introduced by this module (`fragile-quorum-set`) is
 * registered here. The `quorum-intersection-failure` rule is already
 * registered in `quorumSolverRules` (quorum-solver.ts) and must not be
 * duplicated in the global rule registry.
 */
export const quorumAuditRules: Rule[] = [
  {
    id: FRAGILE_QUORUM_SET_RULE,
    category: 'validators',
    severity: 'warning',
    description: 'A validator quorum set has zero BFT — one node failure stalls consensus',
    run() {},
  },
];

export const quorumAuditRuleIds: readonly string[] = quorumAuditRules.map((r) => r.id);
