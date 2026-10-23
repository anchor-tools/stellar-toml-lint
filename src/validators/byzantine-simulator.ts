/**
 * Byzantine node fault injector and consensus stall probability estimator
 * (issue #313).
 *
 * A validator's quorum set tells us which nodes it trusts, but not how it
 * behaves when some of those nodes equivocate, vote for conflicting ledgers, or
 * simply crash. This module injects adversarial faults into every declared
 * `[[VALIDATORS]]` quorum set and answers the operator's real question: given
 * `N` malicious or failed nodes, what is the exact probability that this
 * validator can no longer reach a quorum?
 *
 * Two complementary answers are produced:
 *
 *   - an exact combinatorial probability when the member universe is small
 *     enough to enumerate every `N`-of-`M` fault set, and a seeded Monte Carlo
 *     estimate otherwise;
 *   - the safety buffer, i.e. the smallest number of honest members that still
 *     contains a minimal quorum, and the fault tolerance, i.e. the largest
 *     number of simultaneous failures the set survives.
 *
 * The fault model is deliberately conservative: a Byzantine node withholds its
 * agreement (or votes for a conflicting value), so it contributes nothing to
 * any quorum. A nested inner set is satisfied only when its own threshold of
 * non-faulty children is satisfied, mirroring stellar-core's evaluation.
 *
 * Findings:
 *   - `validators/catastrophic-single-point-of-failure` (error) when one node's
 *     failure alone can stall the validator;
 *   - `validators/low-byzantine-fault-tolerance` (warning) when the set
 *     tolerates fewer faults than the BFT budget `floor((M - 1) / 3)` allows.
 *
 * Unreachable configs, malformed quorum sets, and capped analyses stay silent:
 * a simulator that guesses must never invent a critical failure.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { specUrl } from '../spec.js';
import {
  normalizeQuorumSet,
  minimalQuorums,
  minimalBlockingSets,
  failureResilience,
  parseCoreCfgQuorumSet,
  type QuorumSet,
} from './quorum-solver.js';

export const LOW_BYZANTINE_FAULT_TOLERANCE_RULE = 'validators/low-byzantine-fault-tolerance';
export const CATASTROPHIC_SINGLE_POINT_OF_FAILURE_RULE =
  'validators/catastrophic-single-point-of-failure';

/** Alias names used by earlier drafts of the issue. */
export const LOW_BYZANTINE_FAULT_TOLERANCE = LOW_BYZANTINE_FAULT_TOLERANCE_RULE;
export const CATASTROPHIC_SINGLE_POINT_OF_FAILURE = CATASTROPHIC_SINGLE_POINT_OF_FAILURE_RULE;

/** Default number of random fault sets sampled when exact enumeration is too large. */
export const DEFAULT_MONTE_CARLO_ITERATIONS = 10_000;

/** Above this many fault combinations the simulator switches to Monte Carlo. */
export const DEFAULT_MAX_EXACT_COMBINATIONS = 100_000;

/** Deterministic default seed, so two runs over the same input agree. */
export const DEFAULT_BYZANTINE_SEED = 0x5eed_313;

export interface ByzantineSimulatorOptions {
  rules?: RuleOverrides;
  /** Quorum sets keyed by public key, overriding the document (tests). */
  quorumSets?: Record<string, unknown>;
  /** Number of adversarial nodes to inject. Defaults to one. */
  byzantineNodes?: number;
  /** Monte Carlo sample count when exact enumeration is infeasible. */
  iterations?: number;
  /** Deterministic PRNG seed for the Monte Carlo path. */
  seed?: number;
  /** Upper bound on enumerated fault combinations. */
  maxExactCombinations?: number;
}

/** How a stall probability was obtained. */
export type ProbabilityMethod = 'exact' | 'monte-carlo';

/** The outcome of injecting `byzantineNodes` faults into one quorum set. */
export interface ByzantineSimulationResult {
  publicKey?: string;
  path?: string;
  set?: QuorumSet;
  /** Every distinct member the quorum set can ever rely on. */
  totalNodes: number;
  /** Number of adversarial nodes injected. */
  byzantineNodes: number;
  /** Probability the validator cannot satisfy its quorum. */
  stallProbability: number;
  /** Probability two disjoint honest quorums remain (a split vote). */
  splitVoteProbability: number;
  /** True when every sampled fault set stalls consensus. */
  alwaysStalls: boolean;
  /** How the probability was calculated. */
  method: ProbabilityMethod;
  /** Smallest number of honest members that still contains a minimal quorum. */
  safetyBuffer: number;
  /** Largest number of simultaneous failures the quorum set survives. */
  faultTolerance: number | undefined;
  /** The classical BFT budget `floor((totalNodes - 1) / 3)`. */
  byzantineBudget: number;
  /** Members whose individual failure alone stalls the validator. */
  criticalNodes: string[];
  /** Minimal quorums enumerated for the set. */
  minimalQuorums: string[][];
  /** Whether the quorum enumeration completed exhaustively. */
  complete: boolean;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : undefined;
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

/** Every distinct leaf member in declaration order. */
export function byzantineMembers(set: QuorumSet): string[] {
  const members: string[] = [];
  const seen = new Set<string>();
  const visit = (candidate: QuorumSet): void => {
    for (const child of candidate.inner) {
      if (typeof child === 'string') {
        if (!seen.has(child)) {
          seen.add(child);
          members.push(child);
        }
      } else {
        visit(child);
      }
    }
  };
  visit(set);
  return members;
}

/**
 * Evaluates a quorum set against the set of available (honest) members.
 * A nested child counts as one satisfied slice when its own threshold is met.
 */
export function quorumSatisfied(set: QuorumSet, available: ReadonlySet<string>): boolean {
  let satisfied = 0;
  for (const child of set.inner) {
    if (typeof child === 'string') {
      if (available.has(child)) satisfied++;
      continue;
    }
    if (quorumSatisfied(child, available)) satisfied++;
  }
  return satisfied >= set.threshold;
}

/** True when the named faulty nodes leave no quorum available. */
export function isStalled(set: QuorumSet, faulty: ReadonlySet<string>): boolean {
  const available = new Set(byzantineMembers(set).filter((member) => !faulty.has(member)));
  return !quorumSatisfied(set, available);
}

/**
 * Members whose removal alone stalls the quorum set. These are exactly the
 * single-member blocking sets — one key an adversary only has to compromise.
 */
export function findCriticalNodes(set: QuorumSet): string[] {
  return byzantineMembers(set).filter((member) => isStalled(set, new Set([member])));
}

/** Smallest minimal quorum: the safety buffer of honest members required. */
export function safetyBufferOf(quorums: readonly (readonly string[])[]): number {
  if (quorums.length === 0) return 0;
  return Math.min(...quorums.map((quorum) => new Set(quorum).size));
}

function combinationCount(n: number, k: number): number {
  if (k < 0 || k > n) return 0;
  const smaller = Math.min(k, n - k);
  let count = 1;
  for (let i = 1; i <= smaller; i++) {
    count = (count * (n - smaller + i)) / i;
    if (!Number.isFinite(count)) return Number.POSITIVE_INFINITY;
  }
  return Math.round(count);
}

/** Calls `visit` for every subset of `items` of size `size`. */
function forEachCombination(
  items: readonly string[],
  size: number,
  visit: (subset: string[]) => void,
): void {
  if (size < 0 || size > items.length) return;
  const chosen: string[] = [];
  const walk = (start: number): void => {
    if (chosen.length === size) {
      visit([...chosen]);
      return;
    }
    const remaining = size - chosen.length;
    for (let i = start; i <= items.length - remaining; i++) {
      chosen.push(items[i] as string);
      walk(i + 1);
      chosen.pop();
    }
  };
  walk(0);
}

/** Mulberry32: tiny deterministic PRNG for reproducible Monte Carlo runs. */
function mulberry32(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4_294_967_296;
  };
}

/** Draws `size` distinct items without replacement using a partial shuffle. */
function sampleWithoutReplacement(
  items: readonly string[],
  size: number,
  random: () => number,
): string[] {
  const copy = [...items];
  const take = Math.min(size, copy.length);
  for (let i = 0; i < take; i++) {
    const j = i + Math.floor(random() * (copy.length - i));
    const chosen = copy[i] as string;
    copy[i] = copy[j] as string;
    copy[j] = chosen;
  }
  return copy.slice(0, take);
}

/** True when two surviving minimal quorums are disjoint (a split is possible). */
function hasDisjointAvailableQuorums(
  quorums: readonly (readonly string[])[],
  available: ReadonlySet<string>,
): boolean {
  const surviving = quorums.filter((quorum) => quorum.every((member) => available.has(member)));
  const capped = surviving.slice(0, 500);
  for (let i = 0; i < capped.length; i++) {
    const left = capped[i];
    if (left === undefined) continue;
    for (let j = i + 1; j < capped.length; j++) {
      const right = capped[j];
      if (right === undefined) continue;
      if (left.every((member) => !right.includes(member))) return true;
    }
  }
  return false;
}

export interface StallProbabilityOptions {
  /** Number of adversarial nodes. Defaults to one. */
  byzantineNodes?: number;
  iterations?: number;
  seed?: number;
  maxExactCombinations?: number;
  /** Minimal quorums, when the caller already enumerated them. */
  quorums?: string[][];
}

export interface StallProbability {
  probability: number;
  splitVoteProbability: number;
  method: ProbabilityMethod;
  samples: number;
  stalls: number;
  splits: number;
  alwaysStalls: boolean;
}

/**
 * Estimates the probability that `byzantineNodes` random faulty members stall
 * the quorum set. Exact enumeration is used whenever the combination count is
 * below the cap; otherwise a seeded Monte Carlo sample is taken.
 */
export function estimateStallProbability(
  set: QuorumSet,
  options: StallProbabilityOptions = {},
): StallProbability {
  const members = byzantineMembers(set);
  const total = members.length;
  const requested = Math.max(0, Math.trunc(options.byzantineNodes ?? 1));
  const byzantineNodes = Math.min(requested, total);
  const quorums = options.quorums ?? minimalQuorums(set).quorums;
  const maxExact = options.maxExactCombinations ?? DEFAULT_MAX_EXACT_COMBINATIONS;
  const combinations = combinationCount(total, byzantineNodes);

  if (combinations <= maxExact) {
    let stalls = 0;
    let splits = 0;
    let samples = 0;
    forEachCombination(members, byzantineNodes, (faulty) => {
      samples++;
      const faultySet = new Set(faulty);
      const available = new Set(members.filter((member) => !faultySet.has(member)));
      if (!quorumSatisfied(set, available)) stalls++;
      else if (hasDisjointAvailableQuorums(quorums, available)) splits++;
    });
    return {
      probability: samples === 0 ? 0 : stalls / samples,
      splitVoteProbability: samples === 0 ? 0 : splits / samples,
      method: 'exact',
      samples,
      stalls,
      splits,
      alwaysStalls: samples > 0 && stalls === samples,
    };
  }

  const iterations = Math.max(1, Math.trunc(options.iterations ?? DEFAULT_MONTE_CARLO_ITERATIONS));
  const random = mulberry32(options.seed ?? DEFAULT_BYZANTINE_SEED);
  let stalls = 0;
  let splits = 0;
  for (let sample = 0; sample < iterations; sample++) {
    const faulty = sampleWithoutReplacement(members, byzantineNodes, random);
    const faultySet = new Set(faulty);
    const available = new Set(members.filter((member) => !faultySet.has(member)));
    if (!quorumSatisfied(set, available)) stalls++;
    else if (hasDisjointAvailableQuorums(quorums, available)) splits++;
  }
  return {
    probability: stalls / iterations,
    splitVoteProbability: splits / iterations,
    method: 'monte-carlo',
    samples: iterations,
    stalls,
    splits,
    alwaysStalls: stalls === iterations,
  };
}

/** Alias: the issue calls this a Monte Carlo harness. */
export const simulateByzantineFaults = estimateStallProbability;
export const monteCarloStallProbability = estimateStallProbability;

/** Computes the full resilience picture for one already-normalised set. */
export function analyseByzantineResilience(
  set: QuorumSet,
  options: StallProbabilityOptions = {},
): Omit<ByzantineSimulationResult, 'publicKey' | 'path'> {
  const members = byzantineMembers(set);
  const totalNodes = members.length;
  const { quorums, complete: quorumComplete } = minimalQuorums(set);
  const blocking = minimalBlockingSets(set, quorums);
  const resilience = failureResilience(blocking.blockingSets, blocking.complete);
  const faultTolerance = Number.isFinite(resilience) ? resilience : undefined;
  const requested = Math.max(0, Math.trunc(options.byzantineNodes ?? 1));
  const byzantineNodes = Math.min(requested, totalNodes);
  const probability = estimateStallProbability(set, {
    ...options,
    byzantineNodes,
    quorums,
  });

  return {
    set,
    totalNodes,
    byzantineNodes,
    stallProbability: probability.probability,
    splitVoteProbability: probability.splitVoteProbability,
    alwaysStalls: probability.alwaysStalls,
    method: probability.method,
    safetyBuffer: safetyBufferOf(quorums),
    faultTolerance,
    byzantineBudget: Math.max(0, Math.floor((totalNodes - 1) / 3)),
    criticalNodes: findCriticalNodes(set),
    minimalQuorums: quorums,
    complete:
      quorumComplete && blocking.complete && quorums.length > 0 && faultTolerance !== undefined,
  };
}

async function fetchCoreCfg(url: string, fetchImpl: typeof fetch): Promise<QuorumSet | undefined> {
  try {
    const response = await fetchImpl(url);
    if (!response.ok) return undefined;
    return parseCoreCfgQuorumSet(await response.text());
  } catch {
    return undefined;
  }
}

async function resolveSet(
  entry: Record<string, unknown>,
  publicKey: string,
  fetchImpl: typeof fetch,
  options: ByzantineSimulatorOptions,
): Promise<QuorumSet | undefined> {
  const override = options.quorumSets?.[publicKey];
  if (override !== undefined) return normalizeQuorumSet(override);
  if (entry.QUORUM_SET !== undefined) return normalizeQuorumSet(entry.QUORUM_SET);
  if (typeof entry.CONFIG_URL === 'string') return fetchCoreCfg(entry.CONFIG_URL, fetchImpl);
  return undefined;
}

function validatorEntries(doc: Record<string, unknown>): Record<string, unknown>[] {
  const list = Array.isArray(doc.VALIDATORS) ? doc.VALIDATORS : [];
  return list.filter((entry): entry is Record<string, unknown> => isRecord(entry));
}

/**
 * Simulates adversarial faults for every `[[VALIDATORS]]` entry that declares
 * an inline `QUORUM_SET` or a `CONFIG_URL`-linked stellar-core.cfg.
 */
export async function simulateByzantineResilience(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: ByzantineSimulatorOptions = {},
): Promise<ByzantineSimulationResult[]> {
  const results: ByzantineSimulationResult[] = [];
  const entries = validatorEntries(doc);

  for (let index = 0; index < entries.length; index++) {
    const entry = entries[index];
    if (entry === undefined) continue;
    const publicKey = stringValue(entry.PUBLIC_KEY);
    if (publicKey === undefined) continue;
    const set = await resolveSet(entry, publicKey, fetchImpl, options);
    if (set === undefined) continue;

    results.push({
      publicKey,
      path: `VALIDATORS[${index}].QUORUM_SET`,
      ...analyseByzantineResilience(set, options),
    });
  }
  return results;
}

function percent(value: number): string {
  return `${(value * 100).toFixed(value === 0 || value === 1 ? 0 : 1)}%`;
}

/**
 * Audits every declared quorum set by injecting `byzantineNodes` faults and
 * reporting catastrophic single points and below-budget fault tolerance.
 */
export async function checkByzantineResilience(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: ByzantineSimulatorOptions = {},
): Promise<Diagnostic[]> {
  const diagnostics: Diagnostic[] = [];
  const results = await simulateByzantineResilience(doc, fetchImpl, options);

  for (const result of results) {
    if (!result.complete || result.faultTolerance === undefined) continue;
    const path = result.path ?? 'VALIDATORS';

    if (result.faultTolerance === 0) {
      const severity = severityFor(
        CATASTROPHIC_SINGLE_POINT_OF_FAILURE_RULE,
        'error',
        options.rules,
      );
      if (severity !== undefined) {
        const single = estimateStallProbability(result.set as QuorumSet, {
          byzantineNodes: 1,
          ...(options.iterations === undefined ? {} : { iterations: options.iterations }),
          ...(options.seed === undefined ? {} : { seed: options.seed }),
          quorums: result.minimalQuorums,
        });
        const critical =
          result.criticalNodes.length > 0
            ? result.criticalNodes.slice(0, 4).join(', ') +
              (result.criticalNodes.length > 4 ? `, +${result.criticalNodes.length - 4} more` : '')
            : 'at least one member';
        diagnostics.push({
          rule: CATASTROPHIC_SINGLE_POINT_OF_FAILURE_RULE,
          severity,
          category: 'validators',
          message:
            `Validator ${result.publicKey ?? ''} can be stalled by a single Byzantine node: ` +
            `${critical} is a catastrophic single point of failure` +
            (single.probability > 0
              ? ` (one-node stall probability ${percent(single.probability)})`
              : ''),
          path,
          helpUri: specUrl('validator-information'),
          suggestion:
            'Add redundant members and spread the threshold across independent organisations so no ' +
            'single key can block every quorum slice.',
        });
      }
      continue;
    }

    if (result.faultTolerance < result.byzantineBudget) {
      const severity = severityFor(LOW_BYZANTINE_FAULT_TOLERANCE_RULE, 'warning', options.rules);
      if (severity === undefined) continue;
      const breaking = Math.min(result.totalNodes, result.faultTolerance + 1);
      const atBreaking = estimateStallProbability(result.set as QuorumSet, {
        byzantineNodes: breaking,
        ...(options.iterations === undefined ? {} : { iterations: options.iterations }),
        ...(options.seed === undefined ? {} : { seed: options.seed }),
        quorums: result.minimalQuorums,
      });
      diagnostics.push({
        rule: LOW_BYZANTINE_FAULT_TOLERANCE_RULE,
        severity,
        category: 'validators',
        message:
          `Validator ${result.publicKey ?? ''} tolerates only ${result.faultTolerance} ` +
          `simultaneous Byzantine fault${result.faultTolerance === 1 ? '' : 's'} of ` +
          `${result.totalNodes} members, below the BFT budget of ${result.byzantineBudget}; ` +
          `${breaking} faulty nodes stall consensus with probability ` +
          `${percent(atBreaking.probability)}`,
        path,
        helpUri: specUrl('validator-information'),
        suggestion:
          'Raise the quorum threshold and diversify slices so the set tolerates at least ' +
          'floor((members - 1) / 3) coordinated Byzantine failures.',
      });
    }
  }

  return diagnostics;
}

export const auditByzantineResilience = checkByzantineResilience;
export const checkByzantineFaults = checkByzantineResilience;
export const verifyByzantineResilience = checkByzantineResilience;

/** Rules registered so `--list-rules`, `--off`, and SARIF know the ids. */
export const byzantineSimulatorRules: Rule[] = [
  {
    id: LOW_BYZANTINE_FAULT_TOLERANCE_RULE,
    category: 'validators',
    severity: 'warning',
    description:
      'Declared quorum sets should tolerate at least floor((members - 1) / 3) Byzantine faults',
    run() {},
  },
  {
    id: CATASTROPHIC_SINGLE_POINT_OF_FAILURE_RULE,
    category: 'validators',
    severity: 'error',
    description:
      'No single Byzantine node should be able to stall a validator while the rest of the network is honest',
    run() {},
  },
];

export const byzantineSimulatorRuleIds: readonly string[] = byzantineSimulatorRules.map(
  (rule) => rule.id,
);
