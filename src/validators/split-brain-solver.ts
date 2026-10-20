/**
 * SCP quorum-set graph partitioning and split-brain solver (issue #310).
 *
 * Federated Byzantine Agreement keeps the network from forking only while every
 * pair of quorums intersects. The intersection check in `quorum-solver.ts`
 * answers the yes/no question — "can two disjoint quorums form right now?" —
 * but an operator whose quorums *do* intersect still needs to know how safe
 * that intersection is. Two quorums that share a single validator intersect
 * today and become disjoint the moment that one node fails or is steered by one
 * organisation: a bridge node, and a partition waiting to happen.
 *
 * This solver builds the directed trust graph the `[[VALIDATORS]]` quorum sets
 * declare, then measures the graph's resilience:
 *
 *   - the minimum node cut required to disconnect the declared quorums, i.e.
 *     how many nodes an adversary or an outage must remove before a disjoint
 *     pair exists (a cut of one is a single-point-of-partition);
 *   - the bridge nodes that form those one-member intersections, so the operator
 *     can name and diversify them;
 *   - single-organization choke points that control more than half of a slice,
 *     which is the same hazard expressed by operator rather than by key.
 *
 * It emits `validators/partition-vulnerability` (error) when the network is
 * partitionable by a small cut or an organisation concentration, and
 * `validators/critical-bridge-node` (warning) for each named bridge. An
 * intersecting graph with distributed intersection and no dominant
 * organisation stays silent; unreachable configs and capped analyses degrade to
 * silence because a solver that guesses must never produce a false error.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { specUrl } from '../spec.js';
import {
  normalizeQuorumSet,
  minimalQuorums,
  parseCoreCfgQuorumSet,
  type QuorumSet,
  type RawQuorumSet,
} from './quorum-solver.js';

export const PARTITION_VULNERABILITY_RULE = 'validators/partition-vulnerability';
export const CRITICAL_BRIDGE_NODE_RULE = 'validators/critical-bridge-node';

/**
 * A cut of this size or smaller is reported as a partition vulnerability. One
 * node is a single point of partition; zero means the network is already
 * partitionable and is reported for completeness.
 */
const DEFAULT_MAX_ALERT_CUT = 1;

/** A single organisation controlling more of a slice than this is a choke point. */
const ORGANIZATION_CHOKE_THRESHOLD = 0.5;

/** Upper bound on the pairwise quorum comparisons, to keep analysis bounded. */
const MAX_QUORUMS_PER_VALIDATOR = 500;

// ─── Public types ─────────────────────────────────────────────────────────────

export interface SplitBrainOptions {
  rules?: RuleOverrides;
  /** Quorum sets keyed by validator public key, overriding the document. */
  quorumSets?: Record<string, RawQuorumSet>;
  /** Explicit organisation per public key, overriding host/alias inference. */
  organizations?: Record<string, string>;
  /** Override the largest node cut still reported as a vulnerability. */
  maxAlertCut?: number;
}

/** One validator's declared quorum set, normalised and solved. */
export interface QuorumAnalysis {
  publicKey: string;
  path: string;
  set: QuorumSet;
  minimalQuorums: string[][];
}

/** The directed trust graph: each validator trusts the members it lists. */
export interface TrustGraph {
  nodes: string[];
  /** `edges.get(u)` is the set of nodes `u` lists in its quorum slices. */
  edges: Map<string, Set<string>>;
}

/** A member that is the *only* overlap between two validators' quorums. */
export interface BridgeNode {
  key: string;
  left: string;
  right: string;
}

/** An organisation owning more than half of one validator's slice. */
export interface ChokePoint {
  organization: string;
  publicKey: string;
  path: string;
  /** Fraction of the slice the organisation controls, e.g. `0.75`. */
  share: number;
  controlled: number;
  total: number;
}

// ─── Graph construction ───────────────────────────────────────────────────────

/** Every leaf member a quorum set can ever agree on, in declaration order. */
export function flattenMembers(set: QuorumSet): string[] {
  const members: string[] = [];
  const visit = (candidate: QuorumSet): void => {
    for (const child of candidate.inner) {
      if (typeof child === 'string') members.push(child);
      else visit(child);
    }
  };
  visit(set);
  return members;
}

/**
 * Builds the directed trust graph: an edge `u → v` means validator `u` lists
 * `v` in one of its quorum slices. Nodes include members that never appear as a
 * `[[VALIDATORS]]` entry, because a validator can trust a node it does not
 * itself declare.
 */
export function buildTrustGraph(analyses: readonly QuorumAnalysis[]): TrustGraph {
  const nodes = new Set<string>();
  const edges = new Map<string, Set<string>>();

  for (const analysis of analyses) {
    nodes.add(analysis.publicKey);
    const trusted = edges.get(analysis.publicKey) ?? new Set<string>();
    for (const member of flattenMembers(analysis.set)) {
      trusted.add(member);
      nodes.add(member);
    }
    edges.set(analysis.publicKey, trusted);
  }

  return { nodes: [...nodes].sort(), edges };
}

function intersection(a: readonly string[], b: readonly string[]): string[] {
  const setB = new Set(b);
  return a.filter((member) => setB.has(member));
}

/**
 * The minimum number of nodes whose removal makes the declared quorums
 * non-intersecting, or `undefined` when fewer than two quorum sets were solved.
 *
 * For a cross-validator quorum pair `(a, b)` the smallest cut that disconnects
 * them is exactly the size of their intersection: remove the shared members and
 * `a` and `b` are disjoint. The global minimum over every cross pair is therefore
 * the cheapest single partition an outage can create — `0` means two quorums are
 * already disjoint, `1` means one node's failure forks the network.
 */
export function minimumNodeCut(analyses: readonly QuorumAnalysis[]): number | undefined {
  if (analyses.length < 2) return undefined;
  let minimum = Number.POSITIVE_INFINITY;

  for (let i = 0; i < analyses.length; i++) {
    for (let j = i + 1; j < analyses.length; j++) {
      const left = analyses[i];
      const right = analyses[j];
      if (left === undefined || right === undefined) continue;
      for (const a of left.minimalQuorums) {
        for (const b of right.minimalQuorums) {
          minimum = Math.min(minimum, intersection(a, b).length);
        }
      }
    }
  }

  return Number.isFinite(minimum) ? minimum : undefined;
}

/**
 * Every member that is the sole intersection of some quorum pair across two
 * validators — the weak ties whose removal performs the minimum cut.
 */
export function findBridgeNodes(analyses: readonly QuorumAnalysis[]): BridgeNode[] {
  const bridges: BridgeNode[] = [];
  const seen = new Set<string>();

  for (let i = 0; i < analyses.length; i++) {
    for (let j = i + 1; j < analyses.length; j++) {
      const left = analyses[i];
      const right = analyses[j];
      if (left === undefined || right === undefined) continue;
      if (
        left.minimalQuorums.length > MAX_QUORUMS_PER_VALIDATOR ||
        right.minimalQuorums.length > MAX_QUORUMS_PER_VALIDATOR
      ) {
        continue;
      }
      for (const a of left.minimalQuorums) {
        for (const b of right.minimalQuorums) {
          const shared = intersection(a, b);
          if (shared.length !== 1) continue;
          const key = shared[0] as string;
          const dedupe = `${key}\u0000${left.publicKey}\u0000${right.publicKey}`;
          if (seen.has(dedupe)) continue;
          seen.add(dedupe);
          bridges.push({ key, left: left.publicKey, right: right.publicKey });
        }
      }
    }
  }

  return bridges;
}

/** Registrable-ish domain: the last two labels of a host, ignoring the port. */
function registrableDomain(host: string): string {
  const clean = (host.split(':')[0] ?? '').toLowerCase().replace(/\.$/, '');
  const parts = clean.split('.').filter((part) => part !== '');
  return parts.length <= 2 ? clean : parts.slice(-2).join('.');
}

/** The organisation a declared validator belongs to, or `undefined`. */
function organizationFor(
  publicKey: string,
  entry: Record<string, unknown>,
  override: Record<string, string>,
): string | undefined {
  if (override[publicKey] !== undefined) return override[publicKey];
  if (typeof entry.ORGANIZATION === 'string' && entry.ORGANIZATION.trim() !== '') {
    return entry.ORGANIZATION.trim();
  }
  if (typeof entry.HOST === 'string' && entry.HOST.trim() !== '') {
    const domain = registrableDomain(entry.HOST);
    if (domain !== '') return domain;
  }
  if (typeof entry.ALIAS === 'string' && entry.ALIAS.trim() !== '') return entry.ALIAS.trim();
  return undefined;
}

/**
 * Finds quorum slices where one organisation owns more than half of the members.
 * Such a slice is a choke point: the organisation can block or steer consensus
 * on its own, however many distinct keys the slice lists.
 */
export function findOrganizationChokePoints(
  analyses: readonly QuorumAnalysis[],
  organizationOf: (publicKey: string) => string | undefined,
  threshold: number = ORGANIZATION_CHOKE_THRESHOLD,
): ChokePoint[] {
  const chokePoints: ChokePoint[] = [];

  for (const analysis of analyses) {
    const members = flattenMembers(analysis.set);
    if (members.length === 0) continue;
    const counts = new Map<string, number>();
    let accounted = 0;
    for (const member of members) {
      const org = organizationOf(member);
      if (org === undefined) continue;
      counts.set(org, (counts.get(org) ?? 0) + 1);
      accounted += 1;
    }
    if (accounted === 0) continue;

    let top: { org: string; count: number } | undefined;
    for (const [org, count] of counts) {
      if (top === undefined || count > top.count) top = { org, count };
    }
    if (top === undefined) continue;
    const share = top.count / members.length;
    if (share > threshold) {
      chokePoints.push({
        organization: top.org,
        publicKey: analysis.publicKey,
        path: analysis.path,
        share,
        controlled: top.count,
        total: members.length,
      });
    }
  }

  return chokePoints;
}

// ─── Document analysis ────────────────────────────────────────────────────────

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function validatorEntries(doc: Record<string, unknown>): Record<string, unknown>[] {
  const list = Array.isArray(doc.VALIDATORS) ? doc.VALIDATORS : [];
  return list.filter((entry): entry is Record<string, unknown> => isRecord(entry));
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

/**
 * Solves the quorum sets declared by `[[VALIDATORS]]`, either inline as a
 * `QUORUM_SET` table or in a linked `stellar-core.cfg` named by `CONFIG_URL`.
 * Validators with no resolvable set are skipped.
 */
export async function analyzeQuorumSets(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch,
  options: SplitBrainOptions = {},
): Promise<QuorumAnalysis[]> {
  const analyses: QuorumAnalysis[] = [];
  const validators = validatorEntries(doc);

  for (let index = 0; index < validators.length; index++) {
    const entry = validators[index];
    if (entry === undefined) continue;
    const publicKey = typeof entry.PUBLIC_KEY === 'string' ? entry.PUBLIC_KEY : undefined;
    if (publicKey === undefined) continue;
    const path = `VALIDATORS[${index}].QUORUM_SET`;

    let set: QuorumSet | undefined;
    const override = options.quorumSets?.[publicKey];
    if (override !== undefined) {
      set = normalizeQuorumSet(override);
    } else if (entry.QUORUM_SET !== undefined) {
      set = normalizeQuorumSet(entry.QUORUM_SET);
    } else if (typeof entry.CONFIG_URL === 'string') {
      set = await fetchCoreCfg(entry.CONFIG_URL, fetchImpl);
    }
    if (set === undefined) continue;

    const { quorums } = minimalQuorums(set);
    if (quorums.length === 0) continue;
    analyses.push({ publicKey, path, set, minimalQuorums: quorums });
  }

  return analyses;
}

// ─── Diagnostics ──────────────────────────────────────────────────────────────

function report(
  diagnostics: Diagnostic[],
  rules: RuleOverrides | undefined,
  rule: string,
  fallback: 'error' | 'warning',
  finding: Omit<Diagnostic, 'rule' | 'severity' | 'category'>,
): void {
  const override = rules?.[rule];
  if (override === 'off') return;
  diagnostics.push({
    ...finding,
    rule,
    category: 'validators',
    severity: override === 'error' || override === 'warning' ? override : fallback,
  });
}

/**
 * Runs the partition analysis over a document and returns diagnostics.
 *
 * Silent unless it can prove a hazard: a cut at or below `maxAlertCut`, a named
 * bridge node, or an organisation controlling more than half a slice.
 */
export async function checkSplitBrain(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: SplitBrainOptions = {},
): Promise<Diagnostic[]> {
  const analyses = await analyzeQuorumSets(doc, fetchImpl, options);
  if (analyses.length < 2) return [];

  const maxCut = options.maxAlertCut ?? DEFAULT_MAX_ALERT_CUT;
  const diagnostics: Diagnostic[] = [];

  const organizations = options.organizations ?? {};
  const orgByKey = new Map<string, string>();
  for (const entry of validatorEntries(doc)) {
    const publicKey = typeof entry.PUBLIC_KEY === 'string' ? entry.PUBLIC_KEY : undefined;
    if (publicKey === undefined) continue;
    const organization = organizationFor(publicKey, entry, organizations);
    if (organization !== undefined) orgByKey.set(publicKey, organization);
  }
  const organizationOf = (key: string): string | undefined =>
    organizations[key] ?? orgByKey.get(key);

  const cut = minimumNodeCut(analyses);
  const bridges = findBridgeNodes(analyses);
  const chokePoints = findOrganizationChokePoints(analyses, organizationOf);

  if (cut !== undefined && cut <= maxCut) {
    const detail =
      cut === 0
        ? 'two validators already form disjoint quorums'
        : `removing ${cut} node${cut === 1 ? '' : 's'} disconnects the quorums`;
    report(diagnostics, options.rules, PARTITION_VULNERABILITY_RULE, 'error', {
      message:
        `The quorum graph is partitionable: ${detail}, so a ` +
        (cut === 0 ? 'network split can occur now' : 'single failure can split-brain the network'),
      path: analyses[0]?.path ?? 'VALIDATORS',
      helpUri: specUrl('validator-information'),
      suggestion:
        'Diversify every quorum slice so no small set of nodes (or one organisation) is the only ' +
        'thing holding two quorums together; add overlapping slices that both sides must agree with.',
    });
  }

  for (const bridge of bridges) {
    report(diagnostics, options.rules, CRITICAL_BRIDGE_NODE_RULE, 'warning', {
      message:
        `${bridge.key} is the only validator shared by the quorums of ` +
        `${bridge.left} and ${bridge.right}, so its failure can partition the network`,
      path: analyses.find((analysis) => analysis.publicKey === bridge.left)?.path ?? 'VALIDATORS',
      helpUri: specUrl('validator-information'),
      suggestion:
        `Make every quorum slice from ${bridge.left} and ${bridge.right} overlap on more than node ` +
        `${bridge.key}, or move it off the single point of intersection.`,
    });
  }

  for (const chokePoint of chokePoints) {
    const percent = Math.round(chokePoint.share * 100);
    report(diagnostics, options.rules, PARTITION_VULNERABILITY_RULE, 'error', {
      message:
        `Organization "${chokePoint.organization}" controls ${percent}% of the quorum slice ` +
        `declared by ${chokePoint.publicKey} (${chokePoint.controlled} of ${chokePoint.total} ` +
        'members), enough to steer or block consensus alone',
      path: chokePoint.path,
      helpUri: specUrl('validator-information'),
      suggestion:
        'Diversify the slice across at least three independent organisations so no single ' +
        'operator can reach a blocking share of it.',
    });
  }

  return diagnostics;
}

// ─── Rule registry ────────────────────────────────────────────────────────────

/** Rules registered so `--list-rules`, `--off`, and SARIF know the ids. */
export const splitBrainRules: Rule[] = [
  {
    id: PARTITION_VULNERABILITY_RULE,
    category: 'validators',
    severity: 'error',
    description:
      'Declared quorum sets must not be partitionable by a small node cut or a single organization',
    run() {},
  },
  {
    id: CRITICAL_BRIDGE_NODE_RULE,
    category: 'validators',
    severity: 'warning',
    description: 'No validator should be the only shared member holding two quorums together',
    run() {},
  },
];

export const splitBrainRuleIds: readonly string[] = splitBrainRules.map((rule) => rule.id);
