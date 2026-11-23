/**
 * Stellar overlay transaction flood propagation and mempool eviction verifier.
 *
 * Transactions reach validators by flooding: every peer forwards the
 * `TRANSACTION` envelopes it accepts, and nodes fetch the transaction sets
 * that close ledgers with `GET_TX_SET`, answered by a `TX_SET` /
 * `GENERALIZED_TX_SET` or by `DONT_HAVE`. Each node keeps a bounded
 * transaction queue: when it is full, a new transaction is admitted only if
 * its fee per operation beats the cheapest queued ones, which are evicted;
 * otherwise it is rejected (`TRY_AGAIN_LATER`).
 *
 * `FloodPropagationVerifier` checks that machinery from three angles:
 *
 * 1. **Propagation metrics.** stellar-core's `/metrics` (flood duplicate
 *    ratio, `DONT_HAVE` / `GET_TX_SET` traffic, pending-transaction age
 *    buckets, bans) and `/info` (transaction set size, base fee).
 * 2. **Transaction set exchanges.** Recorded `GET_TX_SET` requests and their
 *    XDR responses: answered sets are decoded and their fee tiers extracted,
 *    `DONT_HAVE` misses and mismatched hashes are counted, malformed frames
 *    are reported.
 * 3. **Queue behavior under bursts.** A deterministic model of the eviction
 *    policy is driven with a burst of submissions across fee tiers to find the
 *    saturation point and entry fee, and any submission log, simulated or
 *    observed on a real node, is checked for fairness: a transaction must
 *    never be dropped while a lower-fee one stays queued, and a high-priority
 *    transaction must never be rejected while the queue still had room.
 *
 * Nothing is submitted to the network: bursts are simulated locally.
 */

import {
  TransactionBuilder,
  xdr,
  type FeeBumpTransaction,
  type Transaction,
} from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';

/** A transaction was dropped while a lower fee-rate transaction stayed queued. */
export const FLOOD_PRIORITY_INVERSION = 'overlay/flood-priority-inversion';
/** A high-priority transaction was rejected while the queue had room. */
export const FLOOD_PREMATURE_DROP = 'overlay/flood-premature-drop';
/** The queue reached capacity during the burst. */
export const FLOOD_QUEUE_SATURATED = 'overlay/flood-queue-saturated';
/** The queue crossed the pressure threshold during the burst. */
export const FLOOD_QUEUE_PRESSURE = 'overlay/flood-queue-pressure';
/** Too many `GET_TX_SET` requests were answered with `DONT_HAVE`. */
export const FLOOD_TXSET_UNAVAILABLE = 'overlay/flood-txset-unavailable';
/** A `DONT_HAVE` response names a hash that was never requested. */
export const FLOOD_DONT_HAVE_MISMATCH = 'overlay/flood-dont-have-mismatch';
/** Flooding receives far more duplicate than unique messages. */
export const FLOOD_DUPLICATE_OVERHEAD = 'overlay/flood-duplicate-overhead';
/** Transactions are stuck in the oldest pending-age bucket. */
export const FLOOD_STALE_PENDING = 'overlay/flood-stale-pending';
/** An overlay frame could not be decoded. */
export const FLOOD_MALFORMED_FRAME = 'overlay/flood-malformed-frame';
/** No propagation metrics were available. */
export const FLOOD_METRICS_UNAVAILABLE = 'overlay/flood-metrics-unavailable';

/** stellar-core's default `TRANSACTION_QUEUE_SIZE_MULTIPLIER`. */
export const DEFAULT_QUEUE_SIZE_MULTIPLIER = 2;
/** Transaction set size assumed when `/info` is unavailable. */
export const DEFAULT_MAX_TX_SET_OPS = 1000;
/** Base fee in stroops per operation. */
export const DEFAULT_BASE_FEE = 100;
/** Occupancy share that counts as pressure. */
export const QUEUE_PRESSURE_THRESHOLD = 0.8;
/** `DONT_HAVE` share of `GET_TX_SET` responses that is too high. */
export const DONT_HAVE_RATIO_THRESHOLD = 0.2;
/** Duplicate-to-unique flood ratio that is too high. */
export const DUPLICATE_RATIO_THRESHOLD = 2;
/** Replace-by-fee needs this multiple of the queued transaction's fee rate. */
export const REPLACE_BY_FEE_MULTIPLIER = 10;
/** Largest simulated burst. */
export const MAX_SIMULATED_SUBMISSIONS = 100000;

export type FeeTier = 'low' | 'medium' | 'high' | 'priority';
export const FEE_TIERS: readonly FeeTier[] = ['low', 'medium', 'high', 'priority'];
/** Fee per operation, as a multiple of the base fee, for each tier. */
export const FEE_TIER_MULTIPLIERS: Record<FeeTier, number> = {
  low: 1,
  medium: 2,
  high: 10,
  priority: 100,
};

/** One transaction offered to a queue. */
export interface QueuedTransaction {
  id: string;
  account: string;
  operations: number;
  /** Total inclusion fee in stroops. */
  fee: bigint;
  tier?: FeeTier;
}

export type SubmissionStatus = 'accepted' | 'rejected';
export type RejectReason = 'insufficient-fee' | 'account-pending' | 'too-large' | 'malformed';

/** One entry of a submission log, simulated or observed. */
export interface SubmissionEvent {
  tx: QueuedTransaction;
  status: SubmissionStatus;
  reason?: RejectReason;
  /** Ids of queued transactions evicted to admit this one. */
  evicted: string[];
  /** Id of this account's queued transaction that this one replaced by fee. */
  replaced?: string;
  /**
   * Ids that left the queue before this submission for reasons other than
   * eviction (included in a ledger, expired). Only observed logs use it.
   */
  removed?: string[];
  /** Queued operations after the submission. */
  occupancyOps: number;
}

/** Compares fee per operation exactly: negative when `a` pays less than `b`. */
export function compareFeeRate(a: QueuedTransaction, b: QueuedTransaction): number {
  const left = a.fee * BigInt(b.operations);
  const right = b.fee * BigInt(a.operations);
  return left < right ? -1 : left > right ? 1 : 0;
}

/** Total order used for eviction: fee per operation, then id. */
function evictionOrder(a: QueuedTransaction, b: QueuedTransaction): number {
  return compareFeeRate(a, b) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
}

/** Index of `tx` (or where it belongs) in a list kept in eviction order. */
function sortedIndex(list: QueuedTransaction[], tx: QueuedTransaction): number {
  let low = 0;
  let high = list.length;
  while (low < high) {
    const mid = (low + high) >>> 1;
    if (evictionOrder(list[mid] as QueuedTransaction, tx) < 0) low = mid + 1;
    else high = mid;
  }
  return low;
}

function insertSorted(list: QueuedTransaction[], tx: QueuedTransaction): void {
  list.splice(sortedIndex(list, tx), 0, tx);
}

function removeSorted(list: QueuedTransaction[], tx: QueuedTransaction): void {
  const index = sortedIndex(list, tx);
  if (list[index]?.id === tx.id) list.splice(index, 1);
}

/**
 * Deterministic model of stellar-core's transaction queue limits: a capacity
 * in operations, one pending transaction per account (replaceable by a 10x
 * fee bump), and fee-rate based eviction when full.
 */
export class TransactionQueueModel {
  readonly capacityOps: number;
  private readonly queue = new Map<string, QueuedTransaction>();
  /** The same transactions, cheapest first. */
  private readonly sorted: QueuedTransaction[] = [];
  private readonly byAccount = new Map<string, string>();
  private occupancy = 0;

  constructor(capacityOps: number) {
    if (!Number.isInteger(capacityOps) || capacityOps < 1) {
      throw new RangeError(`queue capacity must be a positive integer, got ${capacityOps}`);
    }
    this.capacityOps = capacityOps;
  }

  get occupancyOps(): number {
    return this.occupancy;
  }

  get size(): number {
    return this.queue.size;
  }

  has(id: string): boolean {
    return this.queue.has(id);
  }

  private remove(id: string): void {
    const tx = this.queue.get(id) as QueuedTransaction;
    this.queue.delete(id);
    removeSorted(this.sorted, tx);
    this.byAccount.delete(tx.account);
    this.occupancy -= tx.operations;
  }

  private admit(tx: QueuedTransaction): void {
    this.queue.set(tx.id, tx);
    insertSorted(this.sorted, tx);
    this.byAccount.set(tx.account, tx.id);
    this.occupancy += tx.operations;
  }

  submit(tx: QueuedTransaction): SubmissionEvent {
    const reject = (reason: RejectReason): SubmissionEvent => ({
      tx,
      status: 'rejected',
      reason,
      evicted: [],
      occupancyOps: this.occupancy,
    });
    if (tx.operations < 1 || tx.fee < 0n || this.queue.has(tx.id)) return reject('malformed');
    if (tx.operations > this.capacityOps) return reject('too-large');

    // One pending transaction per account; a replacement must bid 10x.
    const pendingId = this.byAccount.get(tx.account);
    const replacing = pendingId === undefined ? undefined : this.queue.get(pendingId);
    if (replacing !== undefined) {
      const bumped = { ...replacing, fee: replacing.fee * BigInt(REPLACE_BY_FEE_MULTIPLIER) };
      if (compareFeeRate(tx, bumped) < 0) return reject('account-pending');
    }

    // When full, evict the cheapest transactions, but only ones that pay a
    // strictly lower fee per operation than the newcomer.
    const occupancy = this.occupancy - (replacing?.operations ?? 0);
    const victims: QueuedTransaction[] = [];
    const needed = occupancy + tx.operations - this.capacityOps;
    if (needed > 0) {
      let freed = 0;
      for (const candidate of this.sorted) {
        if (candidate.id === replacing?.id) continue;
        if (freed >= needed || compareFeeRate(candidate, tx) >= 0) break;
        victims.push(candidate);
        freed += candidate.operations;
      }
      if (freed < needed) return reject('insufficient-fee');
    }

    if (replacing !== undefined) this.remove(replacing.id);
    for (const victim of victims) this.remove(victim.id);
    this.admit(tx);
    return {
      tx,
      status: 'accepted',
      evicted: victims.map((victim) => victim.id),
      ...(replacing === undefined ? {} : { replaced: replacing.id }),
      occupancyOps: this.occupancy,
    };
  }
}

/** Burst size per tier. */
export type BurstProfile = Record<FeeTier, number>;

/** A profile that offers 150% of `capacityOps`, mostly cheap transactions. */
export function defaultBurstProfile(capacityOps: number): BurstProfile {
  const total = Math.ceil(capacityOps * 1.5);
  return {
    low: Math.round(total * 0.5),
    medium: Math.round(total * 0.3),
    high: Math.round(total * 0.15),
    priority: Math.max(1, Math.round(total * 0.05)),
  };
}

/** Parses `low=200,medium=100,high=40,priority=10`. */
export function parseBurstProfile(text: string): BurstProfile {
  const profile: BurstProfile = { low: 0, medium: 0, high: 0, priority: 0 };
  for (const part of text.split(',')) {
    const [rawTier, rawCount] = part.split('=').map((piece) => piece.trim());
    if (!FEE_TIERS.includes(rawTier as FeeTier) || rawCount === undefined) {
      throw new Error(`invalid burst profile entry "${part}"; expected tier=count`);
    }
    const count = Number(rawCount);
    if (!Number.isInteger(count) || count < 0) {
      throw new Error(`burst profile count for ${rawTier} must be a non-negative integer`);
    }
    profile[rawTier as FeeTier] = count;
  }
  return profile;
}

/** Small, seeded PRNG so simulated bursts are reproducible. */
function mulberry32(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Builds an interleaved, reproducible burst of one-operation transactions. */
export function buildBurst(
  profile: BurstProfile,
  baseFee = DEFAULT_BASE_FEE,
  seed = 1,
): QueuedTransaction[] {
  const txs: QueuedTransaction[] = [];
  for (const tier of FEE_TIERS) {
    for (let index = 0; index < profile[tier]; index++) {
      txs.push({
        id: `${tier}-${index}`,
        account: `${tier}-account-${index}`,
        operations: 1,
        fee: BigInt(baseFee * FEE_TIER_MULTIPLIERS[tier]),
        tier,
      });
    }
  }
  if (txs.length > MAX_SIMULATED_SUBMISSIONS) {
    throw new RangeError(
      `burst has ${txs.length} submissions; at most ${MAX_SIMULATED_SUBMISSIONS} are simulated`,
    );
  }
  const random = mulberry32(seed);
  for (let index = txs.length - 1; index > 0; index--) {
    const swap = Math.floor(random() * (index + 1));
    [txs[index], txs[swap]] = [txs[swap] as QueuedTransaction, txs[index] as QueuedTransaction];
  }
  return txs;
}

/** Runs a burst through the queue model and returns the submission log. */
export function simulateBurst(
  model: TransactionQueueModel,
  burst: QueuedTransaction[],
): SubmissionEvent[] {
  return burst.map((tx) => model.submit(tx));
}

export interface TierOutcome {
  submitted: number;
  accepted: number;
  rejected: number;
  evicted: number;
  /** Still queued at the end of the log. */
  retained: number;
}

export interface FairnessViolation {
  rule: typeof FLOOD_PRIORITY_INVERSION | typeof FLOOD_PREMATURE_DROP;
  txId: string;
  message: string;
}

export interface QueueAnalysis {
  capacityOps: number;
  submissions: number;
  peakOccupancyOps: number;
  peakOccupancyRatio: number;
  /** 1-based submission at which the queue first reached capacity. */
  saturatedAt?: number;
  /** 1-based submission of the first eviction. */
  firstEvictionAt?: number;
  /** Lowest fee per operation (stroops) still queued once saturated. */
  entryFeePerOp?: number;
  rejectedByReason: Partial<Record<RejectReason, number>>;
  evictions: number;
  byTier: Partial<Record<FeeTier | 'untiered', TierOutcome>>;
  violations: FairnessViolation[];
}

const tierOf = (tx: QueuedTransaction): FeeTier | 'untiered' => tx.tier ?? 'untiered';

/**
 * Analyzes a submission log for occupancy and fairness. Works on simulated
 * logs and on logs observed from a node (rejections and evictions included).
 */
export function analyzeSubmissions(events: SubmissionEvent[], capacityOps: number): QueueAnalysis {
  const queued = new Map<string, QueuedTransaction>();
  const sorted: QueuedTransaction[] = [];
  const dequeue = (id: string): QueuedTransaction | undefined => {
    const tx = queued.get(id);
    if (tx === undefined) return undefined;
    queued.delete(id);
    removeSorted(sorted, tx);
    return tx;
  };
  const byTier: QueueAnalysis['byTier'] = {};
  const rejectedByReason: QueueAnalysis['rejectedByReason'] = {};
  const violations: FairnessViolation[] = [];
  let peak = 0;
  let saturatedAt: number | undefined;
  let firstEvictionAt: number | undefined;
  let evictions = 0;
  const tierStats = (tier: FeeTier | 'untiered') =>
    (byTier[tier] ??= { submitted: 0, accepted: 0, rejected: 0, evicted: 0, retained: 0 });
  // Fairness: nothing may be dropped while a cheaper transaction stays queued.
  const checkDrop = (victim: QueuedTransaction, verb: string) => {
    const cheaper = sorted[0];
    if (cheaper !== undefined && compareFeeRate(cheaper, victim) < 0) {
      violations.push({
        rule: FLOOD_PRIORITY_INVERSION,
        txId: victim.id,
        message: `Transaction ${victim.id} was ${verb} while ${cheaper.id}, paying a lower fee per operation, stayed queued`,
      });
    }
  };

  events.forEach((event, index) => {
    for (const id of event.removed ?? []) dequeue(id);
    const stats = tierStats(tierOf(event.tx));
    stats.submitted++;
    if (event.replaced !== undefined) dequeue(event.replaced);
    const victims: QueuedTransaction[] = [];
    for (const id of event.evicted) {
      const victim = dequeue(id);
      if (victim === undefined) continue;
      victims.push(victim);
      tierStats(tierOf(victim)).evicted++;
      evictions++;
      firstEvictionAt ??= index + 1;
    }
    for (const victim of victims) checkDrop(victim, 'evicted');

    if (event.status === 'accepted') {
      stats.accepted++;
      queued.set(event.tx.id, event.tx);
      insertSorted(sorted, event.tx);
    } else {
      stats.rejected++;
      const reason = event.reason ?? 'insufficient-fee';
      rejectedByReason[reason] = (rejectedByReason[reason] ?? 0) + 1;
      if (reason === 'insufficient-fee') {
        checkDrop(event.tx, 'rejected');
        // A high-priority transaction must not bounce off a queue with room.
        if (
          (event.tx.tier === 'high' || event.tx.tier === 'priority') &&
          event.occupancyOps + event.tx.operations <= capacityOps
        ) {
          violations.push({
            rule: FLOOD_PREMATURE_DROP,
            txId: event.tx.id,
            message: `${event.tx.tier} transaction ${event.tx.id} was rejected while the queue held ${event.occupancyOps}/${capacityOps} operations`,
          });
        }
      }
    }
    peak = Math.max(peak, event.occupancyOps);
    if (saturatedAt === undefined && event.occupancyOps >= capacityOps) saturatedAt = index + 1;
  });

  for (const tx of queued.values()) tierStats(tierOf(tx)).retained++;

  let entryFeePerOp: number | undefined;
  const cheapest = sorted[0];
  if (saturatedAt !== undefined && cheapest !== undefined) {
    entryFeePerOp = Number(cheapest.fee / BigInt(cheapest.operations)) + 1;
  }

  return {
    capacityOps,
    submissions: events.length,
    peakOccupancyOps: peak,
    peakOccupancyRatio: peak / capacityOps,
    ...(saturatedAt === undefined ? {} : { saturatedAt }),
    ...(firstEvictionAt === undefined ? {} : { firstEvictionAt }),
    ...(entryFeePerOp === undefined ? {} : { entryFeePerOp }),
    rejectedByReason,
    evictions,
    byTier,
    violations,
  };
}

/** Propagation figures read from stellar-core `/metrics`. */
export interface PropagationMetrics {
  floodUnique?: number;
  floodDuplicate?: number;
  dontHaveReceived?: number;
  getTxSetReceived?: number;
  transactionsReceived?: number;
  bannedTransactions?: number;
  /** `herder.pending-txs.age0..3` counts, oldest last. */
  pendingAge: number[];
}

function metricCount(metrics: Record<string, unknown>, name: string): number | undefined {
  const entry = metrics[name];
  if (typeof entry === 'number') return entry;
  if (typeof entry !== 'object' || entry === null) return undefined;
  const record = entry as Record<string, unknown>;
  for (const field of ['count', 'value', 'sum']) {
    if (typeof record[field] === 'number') return record[field] as number;
  }
  return undefined;
}

/** Reads the propagation metrics from a stellar-core `/metrics` document. */
export function parseCoreMetrics(document: unknown): PropagationMetrics {
  const root =
    typeof document === 'object' && document !== null ? (document as Record<string, unknown>) : {};
  const metrics =
    typeof root.metrics === 'object' && root.metrics !== null
      ? (root.metrics as Record<string, unknown>)
      : root;
  const pick = (...names: string[]) => {
    for (const name of names) {
      const value = metricCount(metrics, name);
      if (value !== undefined) return value;
    }
    return undefined;
  };
  const out: PropagationMetrics = { pendingAge: [] };
  const assign = (
    key: Exclude<keyof PropagationMetrics, 'pendingAge'>,
    value: number | undefined,
  ) => {
    if (value !== undefined) out[key] = value;
  };
  assign('floodUnique', pick('overlay.flood.unique_recv'));
  assign('floodDuplicate', pick('overlay.flood.duplicate_recv'));
  assign('dontHaveReceived', pick('overlay.recv.dont-have'));
  assign('getTxSetReceived', pick('overlay.recv.get-txset'));
  assign('transactionsReceived', pick('overlay.recv.transaction'));
  assign('bannedTransactions', pick('herder.pending-txs.banned'));
  for (let age = 0; age < 8; age++) {
    const value = pick(`herder.pending-txs.age${age}`);
    if (value === undefined) break;
    out.pendingAge.push(value);
  }
  return out;
}

/** Reads `maxTxSetSize` and `baseFee` from a stellar-core `/info` document. */
export function parseCoreInfo(document: unknown): { maxTxSetOps?: number; baseFee?: number } {
  const info =
    typeof document === 'object' && document !== null
      ? ((document as Record<string, unknown>).info ?? document)
      : {};
  const ledger =
    typeof info === 'object' && info !== null
      ? (info as Record<string, unknown>).ledger
      : undefined;
  const record =
    typeof ledger === 'object' && ledger !== null ? (ledger as Record<string, unknown>) : {};
  const out: { maxTxSetOps?: number; baseFee?: number } = {};
  if (typeof record.maxTxSetSize === 'number' && record.maxTxSetSize > 0) {
    out.maxTxSetOps = record.maxTxSetSize;
  }
  if (typeof record.baseFee === 'number' && record.baseFee > 0) out.baseFee = record.baseFee;
  return out;
}

/** One recorded overlay exchange: a request and the peer's response. */
export interface OverlayExchange {
  /** Base64 `StellarMessage` XDR sent to the peer. */
  request: string;
  /** Base64 `StellarMessage` XDR received, if any. */
  response?: string;
}

export interface ExchangeAnalysis {
  getTxSetRequests: number;
  answered: number;
  dontHave: number;
  /** `DONT_HAVE` responses whose hash matches no request. */
  mismatched: number;
  malformed: number;
  /** Transactions decoded from answered sets and flooded `TRANSACTION` frames. */
  transactions: QueuedTransaction[];
}

function decodeMessage(base64: string): xdr.StellarMessage | undefined {
  try {
    return xdr.StellarMessage.fromXDR(base64, 'base64');
  } catch {
    return undefined;
  }
}

function toQueued(
  envelope: xdr.TransactionEnvelope,
  index: number,
  passphrase: string,
): QueuedTransaction | undefined {
  try {
    const tx = TransactionBuilder.fromXDR(envelope, passphrase) as Transaction | FeeBumpTransaction;
    const inner = 'innerTransaction' in tx ? tx.innerTransaction : tx;
    const operations = inner.operations.length + ('innerTransaction' in tx ? 1 : 0);
    const source = 'innerTransaction' in tx ? tx.feeSource : tx.source;
    return { id: `tx-${index}`, account: source, operations, fee: BigInt(tx.fee) };
  } catch {
    return undefined;
  }
}

/** Assigns fee tiers relative to the base fee. */
export function tierForFeeRate(feePerOp: number, baseFee = DEFAULT_BASE_FEE): FeeTier {
  if (feePerOp >= baseFee * FEE_TIER_MULTIPLIERS.priority) return 'priority';
  if (feePerOp >= baseFee * FEE_TIER_MULTIPLIERS.high) return 'high';
  if (feePerOp >= baseFee * FEE_TIER_MULTIPLIERS.medium) return 'medium';
  return 'low';
}

/** Decodes recorded `GET_TX_SET` exchanges and flooded transactions. */
export function analyzeExchanges(
  exchanges: OverlayExchange[],
  passphrase: string,
  baseFee = DEFAULT_BASE_FEE,
): ExchangeAnalysis {
  const analysis: ExchangeAnalysis = {
    getTxSetRequests: 0,
    answered: 0,
    dontHave: 0,
    mismatched: 0,
    malformed: 0,
    transactions: [],
  };
  const requested = new Set<string>();
  const addEnvelope = (envelope: xdr.TransactionEnvelope) => {
    const tx = toQueued(envelope, analysis.transactions.length, passphrase);
    if (tx === undefined) {
      analysis.malformed++;
      return;
    }
    tx.tier = tierForFeeRate(Number(tx.fee / BigInt(tx.operations)), baseFee);
    analysis.transactions.push(tx);
  };

  for (const exchange of exchanges) {
    const request = decodeMessage(exchange.request);
    if (request === undefined) {
      analysis.malformed++;
      continue;
    }
    const kind = request.switch().name;
    if (kind === 'getTxSet') {
      analysis.getTxSetRequests++;
      requested.add(request.txSetHash().toString('hex'));
    } else if (kind === 'transaction') {
      addEnvelope(request.transaction());
    }
    if (exchange.response === undefined) continue;
    const response = decodeMessage(exchange.response);
    if (response === undefined) {
      analysis.malformed++;
      continue;
    }
    switch (response.switch().name) {
      case 'dontHave': {
        analysis.dontHave++;
        if (!requested.has(response.dontHave().reqHash().toString('hex'))) analysis.mismatched++;
        break;
      }
      case 'txSet': {
        analysis.answered++;
        for (const envelope of response.txSet().txes()) addEnvelope(envelope);
        break;
      }
      case 'generalizedTxSet': {
        analysis.answered++;
        try {
          for (const phase of response.generalizedTxSet().v1TxSet().phases()) {
            // Phase 0 holds classic transactions in maybe-discounted components;
            // later phase layouts (Soroban parallel sets) are not fee-tiered here.
            if (phase.switch() !== 0) continue;
            for (const component of phase.v0Components()) {
              for (const envelope of component.txsMaybeDiscountedFee().txes())
                addEnvelope(envelope);
            }
          }
        } catch {
          analysis.malformed++;
        }
        break;
      }
      case 'transaction': {
        addEnvelope(response.transaction());
        break;
      }
      default:
        break;
    }
  }
  return analysis;
}

export interface FloodPolicyInput {
  metrics?: unknown;
  info?: unknown;
  exchanges?: OverlayExchange[];
  /** Observed submission log from a node, checked for fairness as-is. */
  observed?: SubmissionEvent[];
}

export interface FloodVerifierOptions {
  rules?: RuleOverrides;
  /** Queue capacity in operations; derived from `/info` when omitted. */
  capacityOps?: number;
  queueSizeMultiplier?: number;
  profile?: BurstProfile;
  seed?: number;
  networkPassphrase?: string;
}

export interface FloodPolicyReport {
  ok: boolean;
  /** 0-100. */
  healthScore: number;
  grade: 'healthy' | 'degraded' | 'unhealthy';
  capacityOps: number;
  baseFee: number;
  thresholds: { pressureOps: number; saturationOps: number };
  metrics?: PropagationMetrics;
  exchanges?: ExchangeAnalysis;
  simulation: QueueAnalysis;
  observed?: QueueAnalysis;
  diagnostics: Diagnostic[];
}

function severityFor(
  rule: string,
  fallback: Severity,
  rules: RuleOverrides | undefined,
): Severity | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override ?? fallback;
}

/** Checks flood propagation and mempool eviction behavior. */
export class FloodPropagationVerifier {
  constructor(private readonly options: FloodVerifierOptions = {}) {}

  verify(input: FloodPolicyInput = {}): FloodPolicyReport {
    const diagnostics: Diagnostic[] = [];
    let penalty = 0;
    const emit = (
      rule: string,
      fallback: Severity,
      message: string,
      cost: number,
      suggestion?: string,
    ) => {
      penalty += cost;
      const severity = severityFor(rule, fallback, this.options.rules);
      if (severity === undefined) return;
      diagnostics.push({
        rule,
        severity,
        category: 'network',
        message,
        ...(suggestion === undefined ? {} : { suggestion }),
      });
    };

    const info = input.info === undefined ? {} : parseCoreInfo(input.info);
    const baseFee = info.baseFee ?? DEFAULT_BASE_FEE;
    const capacityOps =
      this.options.capacityOps ??
      (info.maxTxSetOps ?? DEFAULT_MAX_TX_SET_OPS) *
        (this.options.queueSizeMultiplier ?? DEFAULT_QUEUE_SIZE_MULTIPLIER);
    const thresholds = {
      pressureOps: Math.ceil(capacityOps * QUEUE_PRESSURE_THRESHOLD),
      saturationOps: capacityOps,
    };

    // Simulated burst against the node's configured queue.
    const profile = this.options.profile ?? defaultBurstProfile(capacityOps);
    const burst = buildBurst(profile, baseFee, this.options.seed ?? 1);
    const simulation = analyzeSubmissions(
      simulateBurst(new TransactionQueueModel(capacityOps), burst),
      capacityOps,
    );
    if (simulation.saturatedAt !== undefined) {
      emit(
        FLOOD_QUEUE_SATURATED,
        'info',
        `A ${simulation.submissions}-transaction burst saturates the ${capacityOps}-operation queue at submission ${simulation.saturatedAt}; transactions below ${simulation.entryFeePerOp ?? baseFee} stroops per operation are then rejected or evicted`,
        0,
        'Expect TRY_AGAIN_LATER for low-fee submissions during surges; raise TRANSACTION_QUEUE_SIZE_MULTIPLIER only with matching memory headroom.',
      );
    } else if (simulation.peakOccupancyOps >= thresholds.pressureOps) {
      emit(
        FLOOD_QUEUE_PRESSURE,
        'info',
        `A ${simulation.submissions}-transaction burst fills the queue to ${Math.round(simulation.peakOccupancyRatio * 100)}% of ${capacityOps} operations`,
        0,
      );
    }

    // Observed node behavior is checked for fairness exactly as recorded.
    const observed =
      input.observed === undefined ? undefined : analyzeSubmissions(input.observed, capacityOps);
    for (const analysis of observed === undefined ? [simulation] : [simulation, observed]) {
      for (const violation of analysis.violations) {
        emit(
          violation.rule,
          'error',
          violation.message,
          violation.rule === FLOOD_PREMATURE_DROP ? 15 : 10,
          violation.rule === FLOOD_PREMATURE_DROP
            ? 'A queue with room must admit valid transactions regardless of fee; check per-account limits and bans.'
            : 'Evict the lowest fee-per-operation transactions first so higher bids are never displaced by cheaper ones.',
        );
      }
    }

    let metrics: PropagationMetrics | undefined;
    if (input.metrics === undefined) {
      emit(
        FLOOD_METRICS_UNAVAILABLE,
        'info',
        'No stellar-core /metrics were available, so propagation metrics were not checked',
        0,
        'Pass --host for a reachable admin endpoint or --metrics-file with a saved /metrics response.',
      );
    } else {
      metrics = parseCoreMetrics(input.metrics);
      if (
        metrics.floodUnique !== undefined &&
        metrics.floodDuplicate !== undefined &&
        metrics.floodUnique > 0
      ) {
        const ratio = metrics.floodDuplicate / metrics.floodUnique;
        if (ratio > DUPLICATE_RATIO_THRESHOLD) {
          emit(
            FLOOD_DUPLICATE_OVERHEAD,
            'warning',
            `Flooding receives ${ratio.toFixed(1)} duplicate messages per unique one`,
            5,
            'Enable pull-mode flooding (adverts and demands) or reduce redundant peer connections.',
          );
        }
      }
      const stale = metrics.pendingAge.at(-1) ?? 0;
      if (metrics.pendingAge.length > 1 && stale > 0) {
        emit(
          FLOOD_STALE_PENDING,
          'warning',
          `${stale} pending transaction(s) sit in the oldest queue age bucket`,
          10,
          'Check for transactions with exhausted sequence numbers or fees too low to ever be included.',
        );
      }
      if (
        metrics.getTxSetReceived !== undefined &&
        metrics.dontHaveReceived !== undefined &&
        metrics.getTxSetReceived > 0 &&
        metrics.dontHaveReceived / metrics.getTxSetReceived > DONT_HAVE_RATIO_THRESHOLD
      ) {
        emit(
          FLOOD_TXSET_UNAVAILABLE,
          'warning',
          `Peers answered ${Math.round((metrics.dontHaveReceived / metrics.getTxSetReceived) * 100)}% of GET_TX_SET traffic with DONT_HAVE`,
          10,
          'Check that the node keeps recent transaction sets and stays in sync with its quorum.',
        );
      }
    }

    let exchanges: ExchangeAnalysis | undefined;
    if (input.exchanges !== undefined) {
      exchanges = analyzeExchanges(
        input.exchanges,
        this.options.networkPassphrase ?? 'Public Global Stellar Network ; September 2015',
        baseFee,
      );
      if (
        exchanges.getTxSetRequests > 0 &&
        exchanges.dontHave / exchanges.getTxSetRequests > DONT_HAVE_RATIO_THRESHOLD
      ) {
        emit(
          FLOOD_TXSET_UNAVAILABLE,
          'warning',
          `${exchanges.dontHave} of ${exchanges.getTxSetRequests} GET_TX_SET requests were answered with DONT_HAVE`,
          10,
          'The peer could not serve transaction sets it should hold; check its catch-up state.',
        );
      }
      if (exchanges.mismatched > 0) {
        emit(
          FLOOD_DONT_HAVE_MISMATCH,
          'error',
          `${exchanges.mismatched} DONT_HAVE response(s) named a transaction set hash that was never requested`,
          10,
          'The peer is answering for the wrong request; check its overlay implementation.',
        );
      }
      if (exchanges.malformed > 0) {
        emit(
          FLOOD_MALFORMED_FRAME,
          'warning',
          `${exchanges.malformed} overlay frame(s) could not be decoded as StellarMessage XDR`,
          5,
        );
      }
    }

    const healthScore = Math.max(0, 100 - penalty);
    return {
      ok: !diagnostics.some((d) => d.severity === 'error'),
      healthScore,
      grade: healthScore >= 80 ? 'healthy' : healthScore >= 50 ? 'degraded' : 'unhealthy',
      capacityOps,
      baseFee,
      thresholds,
      ...(metrics === undefined ? {} : { metrics }),
      ...(exchanges === undefined ? {} : { exchanges }),
      simulation,
      ...(observed === undefined ? {} : { observed }),
      diagnostics,
    };
  }
}

function occupancyBar(ratio: number): string {
  const filled = Math.min(20, Math.round(ratio * 20));
  return `[${'#'.repeat(filled)}${'.'.repeat(20 - filled)}]`;
}

function renderAnalysis(label: string, analysis: QueueAnalysis): string[] {
  const lines = [
    `  ${label}: ${analysis.submissions} submissions, peak ${analysis.peakOccupancyOps}/${analysis.capacityOps} ops ${occupancyBar(analysis.peakOccupancyRatio)} ${Math.round(analysis.peakOccupancyRatio * 100)}%`,
  ];
  if (analysis.saturatedAt !== undefined) {
    lines.push(
      `    saturated at submission ${analysis.saturatedAt}${analysis.entryFeePerOp === undefined ? '' : `, entry fee now ${analysis.entryFeePerOp} stroops/op`}`,
    );
  }
  const reasons = Object.entries(analysis.rejectedByReason)
    .map(([reason, count]) => `${reason} ${count}`)
    .join(', ');
  lines.push(
    `    evictions ${analysis.evictions}${reasons === '' ? '' : `, rejections: ${reasons}`}`,
  );
  for (const [tier, stats] of Object.entries(analysis.byTier)) {
    lines.push(
      `    ${tier.padEnd(9)} submitted ${stats.submitted}, accepted ${stats.accepted}, rejected ${stats.rejected}, evicted ${stats.evicted}, retained ${stats.retained}`,
    );
  }
  lines.push(
    `    fairness: ${analysis.violations.length === 0 ? 'no violations' : `${analysis.violations.length} violation(s)`}`,
  );
  return lines;
}

/** Human-readable report. */
export function renderFloodPolicyReport(report: FloodPolicyReport): string {
  const lines = [
    `Flood propagation and mempool policy`,
    `  queue: ${report.capacityOps} ops (pressure at ${report.thresholds.pressureOps}, saturation at ${report.thresholds.saturationOps}), base fee ${report.baseFee}`,
    ...renderAnalysis('simulated burst', report.simulation),
  ];
  if (report.observed !== undefined)
    lines.push(...renderAnalysis('observed submissions', report.observed));
  if (report.metrics !== undefined) {
    const m = report.metrics;
    lines.push(
      `  metrics: flood unique ${m.floodUnique ?? 'n/a'}, duplicate ${m.floodDuplicate ?? 'n/a'}, GET_TX_SET ${m.getTxSetReceived ?? 'n/a'}, DONT_HAVE ${m.dontHaveReceived ?? 'n/a'}, banned ${m.bannedTransactions ?? 'n/a'}`,
    );
    if (m.pendingAge.length > 0) lines.push(`    pending by age: ${m.pendingAge.join(' / ')}`);
  }
  if (report.exchanges !== undefined) {
    const e = report.exchanges;
    lines.push(
      `  exchanges: ${e.getTxSetRequests} GET_TX_SET, ${e.answered} answered, ${e.dontHave} DONT_HAVE (${e.mismatched} mismatched), ${e.malformed} malformed, ${e.transactions.length} transactions decoded`,
    );
  }
  lines.push(`  mempool health: ${report.healthScore}/100 (${report.grade})`);
  return `${lines.join('\n')}\n`;
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const floodPropagationRules: Rule[] = [
  [
    FLOOD_PRIORITY_INVERSION,
    'error',
    'The transaction queue must never drop a transaction while a lower fee-rate one stays queued',
  ],
  [
    FLOOD_PREMATURE_DROP,
    'error',
    'A transaction queue with room must not reject high-priority transactions',
  ],
  [
    FLOOD_QUEUE_SATURATED,
    'info',
    'Reports the burst size at which the transaction queue saturates',
  ],
  [
    FLOOD_QUEUE_PRESSURE,
    'info',
    'Reports transaction queue occupancy above the pressure threshold',
  ],
  [
    FLOOD_TXSET_UNAVAILABLE,
    'warning',
    'Peers should serve the transaction sets they are asked for',
  ],
  [FLOOD_DONT_HAVE_MISMATCH, 'error', 'DONT_HAVE responses must name a requested transaction set'],
  [
    FLOOD_DUPLICATE_OVERHEAD,
    'warning',
    'Transaction flooding should not be dominated by duplicate messages',
  ],
  [
    FLOOD_STALE_PENDING,
    'warning',
    'Pending transactions should not linger in the oldest queue age bucket',
  ],
  [FLOOD_MALFORMED_FRAME, 'warning', 'Overlay frames must decode as StellarMessage XDR'],
  [
    FLOOD_METRICS_UNAVAILABLE,
    'info',
    'Reports when stellar-core propagation metrics were unavailable',
  ],
].map(([id, severity, description]) => ({
  id: id as string,
  category: 'network' as const,
  severity: severity as Severity,
  description: description as string,
  run() {},
}));

export const floodPropagationRuleIds: readonly string[] = floodPropagationRules.map(
  (rule) => rule.id,
);
