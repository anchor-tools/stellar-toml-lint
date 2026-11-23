/**
 * Cross-chain bridge settlement latency SLA benchmark.
 *
 * Runs as `stellar-toml-lint benchmark-bridge-latency --receipts <file>`.
 *
 * Market makers price bridge transfers on how long a lock/burn on the origin
 * chain takes to turn into a mint/release on Stellar. This module pairs the
 * recorded receipts of both legs, normalises every timestamp to UTC
 * milliseconds, and reports mean, standard deviation and p99 settlement
 * latency per corridor, rating each corridor against an SLA and flagging
 * congested corridors and transfers that never settled.
 *
 * Block times differ per chain and drift within a chain, so a receipt that
 * only carries a block number is placed in time by linear interpolation
 * between the two nearest recorded checkpoints of that chain, never with an
 * assumed constant block time. The input is recorded evidence; nothing here
 * touches the network.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isString } from '../predicates.js';
import { isRecord, severityFor } from '../protocols/verifierSupport.js';

const INVALID_RULE = 'bridgelatency/invalid-receipt';
const NEGATIVE_RULE = 'bridgelatency/negative-latency';
const SLA_RULE = 'bridgelatency/sla-breach';
const CONGESTED_RULE = 'bridgelatency/congested-corridor';
const STALLED_RULE = 'bridgelatency/stalled-transfer';

const SPEC = 'https://developers.stellar.org/docs/learn/fundamentals/anchors';

export type CorridorRating = 'meets-sla' | 'degraded' | 'congested' | 'stalled' | 'no-data';

/** A block-number-to-time checkpoint for one chain. */
export interface BlockCheckpoint {
  block: number;
  /** UTC milliseconds. */
  time: number;
}

export interface LatencyOptions {
  rules?: RuleOverrides;
  /** Only benchmark this `<source>-<dest>` corridor. */
  corridor?: string;
  /** p99 at or below this meets the SLA. Default 900 s (15 min). */
  targetP99Seconds?: number;
  /** p99 above this marks the corridor congested. Default 3600 s. */
  congestedP99Seconds?: number;
  /** A transfer with no destination leg older than this is stalled. Default 7200 s. */
  stalledAfterSeconds?: number;
  /** Reference "now" in UTC milliseconds, for stall detection. */
  now?: number;
}

export interface CorridorBenchmark {
  corridor: string;
  settled: number;
  pending: number;
  stalled: number;
  meanSeconds: number;
  stdDevSeconds: number;
  p99Seconds: number;
  maxSeconds: number;
  rating: CorridorRating;
}

export interface LatencyResult {
  diagnostics: Diagnostic[];
  corridors: CorridorBenchmark[];
}

/**
 * Normalises a timestamp to UTC milliseconds. Numbers (and digit strings) are
 * Unix seconds below 1e12 and milliseconds above. ISO strings must carry an
 * explicit offset (`Z` or `±hh:mm`): a zone-less time is ambiguous across
 * the operators' timezones, so it is rejected rather than guessed.
 */
export function toUtcMillis(value: unknown): number | undefined {
  if (typeof value === 'string' && /^\d+$/.test(value)) value = Number(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || value < 0) return undefined;
    return value < 1e12 ? Math.round(value * 1000) : Math.round(value);
  }
  if (!isString(value)) return undefined;
  const iso = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:\d{2})$/i;
  if (!iso.test(value)) return undefined;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? undefined : ms;
}

/** Places `block` in time from a chain's checkpoints (piecewise linear). */
export function blockToMillis(block: number, checkpoints: BlockCheckpoint[]): number | undefined {
  const exact = checkpoints.find((c) => c.block === block);
  if (exact) return exact.time;
  if (checkpoints.length < 2) return undefined;
  const sorted = [...checkpoints].sort((a, b) => a.block - b.block);
  let i = sorted.findIndex((c) => c.block > block);
  // Outside the recorded range, extend the nearest segment.
  if (i <= 0) i = i === 0 ? 1 : sorted.length - 1;
  const a = sorted[i - 1] as BlockCheckpoint;
  const b = sorted[i] as BlockCheckpoint;
  if (a.block === b.block) return undefined;
  return Math.round(a.time + ((block - a.block) * (b.time - a.time)) / (b.block - a.block));
}

/** Nearest-rank percentile of an ascending array. */
export function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const rank = Math.max(1, Math.ceil((p / 100) * sorted.length));
  return sorted[Math.min(rank, sorted.length) - 1] as number;
}

function checkpointsOf(evidence: Record<string, unknown>): Map<string, BlockCheckpoint[]> {
  const out = new Map<string, BlockCheckpoint[]>();
  const raw = isRecord(evidence.blockCheckpoints) ? evidence.blockCheckpoints : {};
  for (const [chain, list] of Object.entries(raw)) {
    if (!Array.isArray(list)) continue;
    const points: BlockCheckpoint[] = [];
    for (const p of list) {
      const time = isRecord(p) ? toUtcMillis(p.timestamp) : undefined;
      if (isRecord(p) && Number.isInteger(p.block) && time !== undefined) {
        points.push({ block: p.block as number, time });
      }
    }
    out.set(chain.toLowerCase(), points);
  }
  return out;
}

const round = (n: number): number => Math.round(n * 1000) / 1000;

export class BridgeSettlementLatencyBenchmark {
  constructor(private readonly options: LatencyOptions = {}) {}

  run(evidence: unknown): LatencyResult {
    const diagnostics: Diagnostic[] = [];
    const push = (rule: string, fallback: 'error' | 'warning', message: string, path: string) => {
      const severity = severityFor(rule, fallback, this.options.rules);
      if (severity !== undefined) {
        diagnostics.push({ rule, severity, category: 'network', message, path, helpUri: SPEC });
      }
    };
    if (!isRecord(evidence) || !Array.isArray(evidence.receipts)) {
      push(INVALID_RULE, 'error', 'Evidence must be an object with a "receipts" array', 'receipts');
      return { diagnostics, corridors: [] };
    }
    const clocks = checkpointsOf(evidence);
    const now = this.options.now ?? Date.now();
    const stallMs = (this.options.stalledAfterSeconds ?? 7200) * 1000;
    const groups = new Map<string, { latencies: number[]; pending: number; stalled: number }>();

    const timeOf = (leg: Record<string, unknown>): number | undefined => {
      if (leg.timestamp !== undefined) return toUtcMillis(leg.timestamp);
      const chain = isString(leg.chain) ? leg.chain.toLowerCase() : '';
      return Number.isInteger(leg.blockNumber)
        ? blockToMillis(leg.blockNumber as number, clocks.get(chain) ?? [])
        : undefined;
    };

    evidence.receipts.forEach((receipt, i) => {
      const path = `receipts[${i}]`;
      if (!isRecord(receipt) || !isRecord(receipt.origin) || !isString(receipt.origin.chain)) {
        push(INVALID_RULE, 'error', `${path} has no origin leg with a chain`, path);
        return;
      }
      const id = isString(receipt.id) ? receipt.id : path;
      const dest = isRecord(receipt.destination) ? receipt.destination : undefined;
      const destChain = dest && isString(dest.chain) ? dest.chain : 'stellar';
      const corridor = (
        isString(receipt.corridor) ? receipt.corridor : `${receipt.origin.chain}-${destChain}`
      ).toLowerCase();
      if (this.options.corridor && corridor !== this.options.corridor.toLowerCase()) return;
      const group = groups.get(corridor) ?? { latencies: [], pending: 0, stalled: 0 };
      groups.set(corridor, group);

      const start = timeOf(receipt.origin);
      if (start === undefined) {
        push(INVALID_RULE, 'error', `${id}: origin leg has no usable UTC time`, `${path}.origin`);
        return;
      }
      if (dest === undefined) {
        group.pending++;
        if (now - start > stallMs) {
          group.stalled++;
          push(
            STALLED_RULE,
            'error',
            `${id}: no Stellar settlement ${Math.round((now - start) / 1000)} s after the origin lock`,
            path,
          );
        }
        return;
      }
      const end = timeOf(dest);
      if (end === undefined) {
        push(
          INVALID_RULE,
          'error',
          `${id}: destination leg has no usable UTC time`,
          `${path}.destination`,
        );
        return;
      }
      if (end < start) {
        push(
          NEGATIVE_RULE,
          'error',
          `${id}: settled ${(start - end) / 1000} s before the origin lock`,
          path,
        );
        return;
      }
      group.latencies.push((end - start) / 1000);
    });

    const target = this.options.targetP99Seconds ?? 900;
    const congested = this.options.congestedP99Seconds ?? 3600;
    const corridors: CorridorBenchmark[] = [];
    for (const [corridor, g] of [...groups].sort(([a], [b]) => a.localeCompare(b))) {
      const sorted = [...g.latencies].sort((a, b) => a - b);
      const n = sorted.length;
      const mean = n ? sorted.reduce((s, v) => s + v, 0) / n : 0;
      const variance = n ? sorted.reduce((s, v) => s + (v - mean) ** 2, 0) / n : 0;
      const p99 = percentile(sorted, 99);
      let performance: CorridorRating = 'meets-sla';
      if (n === 0) performance = 'no-data';
      else if (p99 > congested) performance = 'congested';
      else if (p99 > target) performance = 'degraded';
      if (performance === 'congested') {
        push(
          CONGESTED_RULE,
          'warning',
          `${corridor}: p99 settlement ${p99} s exceeds ${congested} s`,
          corridor,
        );
      } else if (performance === 'degraded') {
        push(
          SLA_RULE,
          'warning',
          `${corridor}: p99 settlement ${p99} s exceeds the ${target} s SLA`,
          corridor,
        );
      }
      // A corridor with stuck transfers is stalled whatever its settled latency.
      const rating: CorridorRating = g.stalled > 0 ? 'stalled' : performance;
      corridors.push({
        corridor,
        settled: n,
        pending: g.pending,
        stalled: g.stalled,
        meanSeconds: round(mean),
        stdDevSeconds: round(Math.sqrt(variance)),
        p99Seconds: round(p99),
        maxSeconds: round(sorted[n - 1] ?? 0),
        rating,
      });
    }
    return { diagnostics, corridors };
  }
}

export function benchmarkBridgeLatency(
  evidence: unknown,
  options: LatencyOptions = {},
): LatencyResult {
  return new BridgeSettlementLatencyBenchmark(options).run(evidence);
}

export function renderLatencyReport(corridors: CorridorBenchmark[]): string {
  const lines = ['Bridge settlement latency benchmark (seconds, UTC-normalised)'];
  if (corridors.length === 0) lines.push('  no matching corridors');
  for (const c of corridors) {
    lines.push(
      `  ${c.corridor}: ${c.rating.toUpperCase()} settled=${c.settled} pending=${c.pending} ` +
        `stalled=${c.stalled} mean=${c.meanSeconds} stddev=${c.stdDevSeconds} p99=${c.p99Seconds} max=${c.maxSeconds}`,
    );
  }
  return `${lines.join('\n')}\n`;
}

const def = (id: string, description: string): Rule => ({
  id,
  category: 'network',
  severity: 'warning',
  description,
  run() {},
});

export const bridgeLatencyRules: Rule[] = [
  def(INVALID_RULE, 'Bridge receipts must carry a chain and an unambiguous UTC time per leg'),
  def(NEGATIVE_RULE, 'A Stellar settlement cannot precede its origin-chain lock'),
  def(SLA_RULE, 'Corridor p99 settlement latency should stay within the SLA target'),
  def(CONGESTED_RULE, 'Corridor p99 settlement latency indicates congestion'),
  def(STALLED_RULE, 'Every origin-chain lock should settle on Stellar before the stall window'),
];

export const bridgeLatencyRuleIds: readonly string[] = bridgeLatencyRules.map((r) => r.id);
