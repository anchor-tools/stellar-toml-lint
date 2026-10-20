/**
 * Overlay graph and hop-distance analyzer.
 *
 * The crawler already bounds the number of peers and nodes it visits.  This
 * module adds the graph interpretation: shortest directed peer paths from
 * every discovered node to a marked core / Tier-1 validator.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isHostPort, isString } from '../predicates.js';
import {
  crawlOverlayPeers,
  type CrawlOptions,
  type OverlayConnector,
  type PeerCrawlResult,
} from './crawler.js';

export const OVERLAY_HIGH_TOPOLOGICAL_DISTANCE = 'overlay/high-topological-distance';
export const OVERLAY_DISCONNECTED_PEER_COMPONENT = 'overlay/disconnected-peer-component';

export const HIGH_TOPOLOGICAL_DISTANCE_RULE = OVERLAY_HIGH_TOPOLOGICAL_DISTANCE;
export const DISCONNECTED_PEER_COMPONENT_RULE = OVERLAY_DISCONNECTED_PEER_COMPONENT;

export const DEFAULT_MAX_TOPOLOGICAL_HOPS = 3;

export interface TopologyOptions {
  rules?: RuleOverrides;
  connector?: OverlayConnector;
  crawl?: (seeds: string[], options?: CrawlOptions) => Promise<PeerCrawlResult>;
  tier1Hosts?: readonly string[];
  maxHops?: number;
  maxNodes?: number;
  maxDepth?: number;
  timeoutMs?: number;
}

export interface TopologyAnalysis {
  distances: Record<string, number | undefined>;
  unreachable: string[];
  highDistance: Array<{ address: string; hops: number }>;
  targets: string[];
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

function normalizeEndpoint(value: string): string | undefined {
  const raw = value.trim();
  if (!isHostPort(raw)) return undefined;
  if (raw.startsWith('[')) {
    const end = raw.indexOf(']');
    if (end < 0) return undefined;
    return `[${raw.slice(1, end).toLowerCase()}]:${raw.slice(end + 2)}`;
  }
  const separator = raw.lastIndexOf(':');
  return `${raw.slice(0, separator).toLowerCase()}:${raw.slice(separator + 1)}`;
}

function validatorEntries(doc: Record<string, unknown>): Array<Record<string, unknown>> {
  if (!Array.isArray(doc.VALIDATORS)) return [];
  return doc.VALIDATORS.filter(
    (entry): entry is Record<string, unknown> =>
      typeof entry === 'object' && entry !== null && !Array.isArray(entry),
  );
}

function declaredSeeds(doc: Record<string, unknown>): string[] {
  return validatorEntries(doc)
    .map((entry) => entry.HOST)
    .filter(isString)
    .map(normalizeEndpoint)
    .filter((value): value is string => value !== undefined);
}

function markedTier1(entry: Record<string, unknown>): boolean {
  const explicit = [entry.TIER_1, entry.TIER1, entry.tier1, entry.CORE, entry.core];
  if (explicit.some((value) => value === true)) return true;
  const tier = entry.TIER ?? entry.tier;
  if (tier === 1 || tier === '1' || tier === 'tier-1' || tier === 'Tier-1') return true;
  const labels = [entry.ALIAS, entry.DISPLAY_NAME, entry.ROLE, entry.role]
    .filter(isString)
    .join(' ')
    .toLowerCase();
  return /tier[-\s]?1|\bcore\b|\bsdf\b/.test(labels);
}

function tier1Seeds(doc: Record<string, unknown>, explicit?: readonly string[]): string[] {
  if (explicit !== undefined && explicit.length > 0) {
    return explicit.map(normalizeEndpoint).filter((value): value is string => value !== undefined);
  }
  const entries = validatorEntries(doc);
  const marked = entries
    .filter(markedTier1)
    .map((entry) => entry.HOST)
    .filter(isString)
    .map(normalizeEndpoint)
    .filter((value): value is string => value !== undefined);
  if (marked.length > 0) return [...new Set(marked)];

  // A file without an explicit tier marker still has a useful, conservative
  // interpretation: every declared validator is a possible anchor target.
  return declaredSeeds(doc);
}

function allGraphNodes(adjacency: Record<string, readonly string[]>): string[] {
  return [...new Set([...Object.keys(adjacency), ...Object.values(adjacency).flat()])];
}

/** Computes directed shortest paths from every graph node to any target. */
export function analyzeOverlayTopology(
  adjacency: Record<string, readonly string[]>,
  targets: readonly string[],
  maxHops = DEFAULT_MAX_TOPOLOGICAL_HOPS,
): TopologyAnalysis {
  const normalizedTargets = [
    ...new Set(
      targets.map(normalizeEndpoint).filter((value): value is string => value !== undefined),
    ),
  ];
  const distances: Record<string, number | undefined> = {};
  const highDistance: Array<{ address: string; hops: number }> = [];
  const unreachable: string[] = [];

  for (const start of allGraphNodes(adjacency)) {
    const queue: Array<{ address: string; hops: number }> = [{ address: start, hops: 0 }];
    const visited = new Set<string>([start]);
    let distance: number | undefined;
    while (queue.length > 0) {
      const current = queue.shift();
      if (current === undefined) break;
      if (normalizedTargets.includes(current.address)) {
        distance = current.hops;
        break;
      }
      for (const nextRaw of adjacency[current.address] ?? []) {
        const next = normalizeEndpoint(nextRaw);
        if (next === undefined || visited.has(next)) continue;
        visited.add(next);
        queue.push({ address: next, hops: current.hops + 1 });
      }
    }
    distances[start] = distance;
    if (distance === undefined) unreachable.push(start);
    else if (distance > maxHops) highDistance.push({ address: start, hops: distance });
  }

  return { distances, unreachable, highDistance, targets: normalizedTargets };
}

/** Crawls declared validators and reports excessive or disconnected paths. */
export async function checkOverlayTopology(
  doc: Record<string, unknown>,
  options: TopologyOptions = {},
): Promise<Diagnostic[]> {
  const seeds = [...new Set(declaredSeeds(doc))];
  if (seeds.length === 0) return [];
  const warningSeverity = severityFor(OVERLAY_HIGH_TOPOLOGICAL_DISTANCE, 'warning', options.rules);
  const errorSeverity = severityFor(OVERLAY_DISCONNECTED_PEER_COMPONENT, 'error', options.rules);
  if (warningSeverity === undefined && errorSeverity === undefined) return [];

  const targets = tier1Seeds(doc, options.tier1Hosts);
  const crawl = options.crawl ?? crawlOverlayPeers;
  const result = await crawl(seeds, {
    connector: options.connector,
    maxNodes: options.maxNodes ?? 256,
    maxDepth: options.maxDepth ?? 16,
    timeoutMs: options.timeoutMs,
  });
  const analysis = analyzeOverlayTopology(result.adjacency, targets, options.maxHops ?? 3);
  const pathByEndpoint = new Map<string, string>();
  validatorEntries(doc).forEach((entry, index) => {
    if (!isString(entry.HOST)) return;
    const endpoint = normalizeEndpoint(entry.HOST);
    if (endpoint !== undefined) pathByEndpoint.set(endpoint, `VALIDATORS[${index}].HOST`);
  });

  const diagnostics: Diagnostic[] = [];
  if (warningSeverity !== undefined) {
    for (const finding of analysis.highDistance) {
      diagnostics.push({
        rule: OVERLAY_HIGH_TOPOLOGICAL_DISTANCE,
        severity: warningSeverity,
        category: 'network',
        message: `${finding.address} is ${finding.hops} overlay hops from the nearest Tier-1 validator (maximum recommended distance is 3)`,
        path: pathByEndpoint.get(finding.address),
        suggestion:
          'Add a direct or redundant peer path to a core / Tier-1 validator so SCP and transaction messages do not depend on a long chain.',
      });
    }
  }

  if (errorSeverity !== undefined) {
    for (const address of analysis.unreachable) {
      diagnostics.push({
        rule: OVERLAY_DISCONNECTED_PEER_COMPONENT,
        severity: errorSeverity,
        category: 'network',
        message: `${address} is in a peer component with no path to a core or Tier-1 validator`,
        path: pathByEndpoint.get(address),
        suggestion:
          'Connect the validator to a reachable Tier-1 peer and confirm GET_PEERS exposes the route to the core overlay.',
      });
    }
  }
  return diagnostics;
}

export const auditOverlayTopology = checkOverlayTopology;
export const analyzePeerTopology = analyzeOverlayTopology;

export const topologyAnalyzerRules: Rule[] = [
  {
    id: OVERLAY_HIGH_TOPOLOGICAL_DISTANCE,
    category: 'network',
    severity: 'warning',
    description: 'Validator overlay paths should stay within three hops of Tier-1 peers',
    run() {},
  },
  {
    id: OVERLAY_DISCONNECTED_PEER_COMPONENT,
    category: 'network',
    severity: 'error',
    description: 'Validator overlay components must connect to a core or Tier-1 peer',
    run() {},
  },
];

export const topologyAnalyzerRuleIds: readonly string[] = topologyAnalyzerRules.map(
  (rule) => rule.id,
);
