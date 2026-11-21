import { parse as parseToml } from 'smol-toml';
import type { StellarToml } from '../types.js';

export interface QuorumSetDefinition {
  threshold?: number;
  thresholdPercent?: number;
  THRESHOLD_PERCENT?: number;
  THRESHOLD?: number;
  validators?: string[];
  VALIDATORS?: string[];
  innerQuorumSets?: QuorumSetDefinition[];
  INNER_QUORUM_SETS?: QuorumSetDefinition[];
  [key: string]: unknown;
}

export interface ValidatorQuorumDefinition {
  publicKey?: string;
  alias?: string;
  displayName?: string;
  PUBLIC_KEY?: string;
  ALIAS?: string;
  DISPLAY_NAME?: string;
  threshold?: number;
  thresholdPercent?: number;
  THRESHOLD_PERCENT?: number;
  THRESHOLD?: number;
  validators?: string[];
  VALIDATORS?: string[];
  innerQuorumSets?: QuorumSetDefinition[];
  INNER_QUORUM_SETS?: QuorumSetDefinition[];
  quorumSet?: QuorumSetDefinition;
  QUORUM_SET?: QuorumSetDefinition;
  [key: string]: unknown;
}

export interface FragmentationDetails {
  components: string[][];
  isolatedNodes: string[];
}

export interface QuorumIntersectionResult {
  hasQuorumIntersection: boolean;
  allMinimalQuorumsIntersect: boolean;
  minimalQuorums: string[][];
  intersectionNodes: string[];
  hasSplitBrainRisk: boolean;
  isFragmented: boolean;
  fragmentationDetails?: FragmentationDetails;
  graph: Record<string, string[]>;
  slices: Record<string, string[][]>;
  warnings: string[];
}

/**
 * Normalizes a node identifier, stripping leading '$' if present.
 */
function normalizeNodeId(raw: string): string {
  const trimmed = raw.trim();
  return trimmed.startsWith('$') ? trimmed.slice(1) : trimmed;
}

/**
 * Finds all combinations of k items from an array.
 */
function getCombinations<T>(items: T[], k: number): T[][] {
  if (k <= 0) return [[]];
  if (k > items.length) return [];
  if (k === items.length) return [items.slice()];
  const result: T[][] = [];

  function backtrack(start: number, current: T[]): void {
    if (current.length === k) {
      result.push([...current]);
      return;
    }
    for (let i = start; i < items.length; i++) {
      const item = items[i];
      if (item !== undefined) {
        current.push(item);
        backtrack(i + 1, current);
        current.pop();
      }
    }
  }

  backtrack(0, []);
  return result;
}

/**
 * Removes superset slices, leaving only minimal slices.
 */
function minimizeSlices(slices: string[][]): string[][] {
  const sorted = slices
    .map((s) => Array.from(new Set(s)).sort())
    .sort((a, b) => a.length - b.length);

  const minimal: string[][] = [];
  for (const candidate of sorted) {
    const isSuperset = minimal.some((m) => m.every((node) => candidate.includes(node)));
    if (!isSuperset) {
      minimal.push(candidate);
    }
  }
  return minimal;
}

export class QuorumSetIntersectionAuditor {
  /**
   * Resolves a QuorumSetDefinition into all concrete slices of node IDs.
   */
  public static expandQuorumSetSlices(
    qSet: QuorumSetDefinition,
    aliasMap?: Map<string, string>,
  ): string[][] {
    const rawValidators: string[] =
      qSet.validators ?? qSet.VALIDATORS ?? (Array.isArray(qSet['validators']) ? qSet['validators'] : []);
    const directValidators: string[] = rawValidators.map((v) => {
      const norm = normalizeNodeId(String(v));
      return aliasMap?.get(norm) ?? norm;
    });

    const rawInners: QuorumSetDefinition[] =
      qSet.innerQuorumSets ??
      qSet.INNER_QUORUM_SETS ??
      (Array.isArray(qSet['inner_quorum_sets']) ? (qSet['inner_quorum_sets'] as QuorumSetDefinition[]) : []);

    const totalElements = directValidators.length + rawInners.length;
    if (totalElements === 0) return [];

    let threshold = qSet.threshold ?? qSet.THRESHOLD;
    const thresholdPercent = qSet.thresholdPercent ?? qSet.THRESHOLD_PERCENT;

    if (threshold === undefined && thresholdPercent !== undefined) {
      threshold = Math.ceil((thresholdPercent * totalElements) / 100);
    }

    if (threshold === undefined) {
      // Default SCP threshold: standard 67% or majority
      threshold = Math.ceil((2 * totalElements) / 3);
    }

    if (threshold > totalElements || threshold <= 0) {
      return [];
    }

    // Expand all inner quorum sets recursively
    const innerSlicesList: string[][][] = rawInners.map((inner) =>
      QuorumSetIntersectionAuditor.expandQuorumSetSlices(inner, aliasMap),
    );

    // Each element in elements array is either a direct validator ({ type: 'validator', id: string })
    // or an inner quorum set ({ type: 'inner', slices: string[][] })
    type Element =
      | { type: 'validator'; id: string }
      | { type: 'inner'; slices: string[][] };

    const elements: Element[] = [
      ...directValidators.map((id) => ({ type: 'validator' as const, id })),
      ...innerSlicesList.map((slices) => ({ type: 'inner' as const, slices })),
    ];

    const combinations = getCombinations(elements, threshold);
    const generatedSlices: string[][] = [];

    for (const combo of combinations) {
      const directNodes: string[] = [];
      const innerGroups: string[][][] = [];

      for (const el of combo) {
        if (el.type === 'validator') {
          directNodes.push(el.id);
        } else {
          innerGroups.push(el.slices);
        }
      }

      if (innerGroups.length === 0) {
        generatedSlices.push(directNodes);
      } else {
        // Cartesian product of inner groups
        let currentProducts: string[][] = [directNodes];
        for (const innerGroup of innerGroups) {
          if (innerGroup.length === 0) {
            currentProducts = [];
            break;
          }
          const nextProducts: string[][] = [];
          for (const prod of currentProducts) {
            for (const slice of innerGroup) {
              nextProducts.push(Array.from(new Set([...prod, ...slice])));
            }
          }
          currentProducts = nextProducts;
        }
        for (const p of currentProducts) {
          generatedSlices.push(p);
        }
      }
    }

    return minimizeSlices(generatedSlices);
  }

  /**
   * Extracts validator quorum slices from stellar.toml or raw object.
   */
  public extractQuorumSlices(
    input: string | StellarToml | Record<string, unknown> | ValidatorQuorumDefinition[],
  ): Record<string, string[][]> {
    let doc: Record<string, unknown> = {};
    let validatorArray: ValidatorQuorumDefinition[] = [];

    if (typeof input === 'string') {
      try {
        doc = parseToml(input) as Record<string, unknown>;
      } catch (err) {
        throw new Error(`Failed to parse TOML: ${err instanceof Error ? err.message : String(err)}`);
      }
    } else if (Array.isArray(input)) {
      validatorArray = input;
    } else if (typeof input === 'object' && input !== null) {
      doc = input as Record<string, unknown>;
    }

    if (Array.isArray(doc['VALIDATORS'])) {
      validatorArray = doc['VALIDATORS'] as ValidatorQuorumDefinition[];
    } else if (Array.isArray(doc['validators'])) {
      validatorArray = doc['validators'] as ValidatorQuorumDefinition[];
    }

    // Build alias -> publicKey lookup map
    const aliasMap = new Map<string, string>();
    for (const val of validatorArray) {
      const pk = val.publicKey ?? val.PUBLIC_KEY;
      const alias = val.alias ?? val.ALIAS;
      const disp = val.displayName ?? val.DISPLAY_NAME;
      if (pk) {
        if (alias) aliasMap.set(alias, pk);
        if (disp) aliasMap.set(disp, pk);
      }
    }

    // Top-level quorum set if declared
    const topLevelQSet =
      (doc['QUORUM_SET'] as QuorumSetDefinition | undefined) ??
      (doc['quorum_set'] as QuorumSetDefinition | undefined);

    const result: Record<string, string[][]> = {};

    for (let i = 0; i < validatorArray.length; i++) {
      const val = validatorArray[i]!;
      const nodeId = val.publicKey ?? val.PUBLIC_KEY ?? val.alias ?? val.ALIAS ?? `validator-${i + 1}`;

      // Check if validator has an explicit quorum set or slice definition
      const explicitQSet =
        val.quorumSet ??
        val.QUORUM_SET ??
        (val.validators || val.VALIDATORS || val.threshold || val.THRESHOLD || val.thresholdPercent || val.THRESHOLD_PERCENT
          ? (val as QuorumSetDefinition)
          : undefined);

      const targetQSet = explicitQSet ?? topLevelQSet;

      if (targetQSet) {
        const rawSlices = QuorumSetIntersectionAuditor.expandQuorumSetSlices(targetQSet, aliasMap);
        // In SCP, a node always belongs to its own quorum slices
        const slicesWithSelf = rawSlices.map((s) => Array.from(new Set([nodeId, ...s])).sort());
        result[nodeId] = minimizeSlices(slicesWithSelf);
      } else {
        // Fallback: Default slice containing all known validators with majority threshold
        const allKeys = validatorArray
          .map((v) => v.publicKey ?? v.PUBLIC_KEY ?? v.alias ?? v.ALIAS)
          .filter((k): k is string => typeof k === 'string');

        if (allKeys.length > 0) {
          const threshold = Math.ceil((2 * allKeys.length) / 3);
          const rawSlices = getCombinations(allKeys, threshold);
          const slicesWithSelf = rawSlices.map((s) => Array.from(new Set([nodeId, ...s])).sort());
          result[nodeId] = minimizeSlices(slicesWithSelf);
        } else {
          result[nodeId] = [[nodeId]];
        }
      }
    }

    return result;
  }

  /**
   * Constructs the directed graph of quorum slices.
   * Edge (u, v) exists if v is present in at least one quorum slice of u.
   */
  public buildSliceGraph(slices: Record<string, string[][]>): Record<string, string[]> {
    const graph: Record<string, string[]> = {};
    for (const [node, nodeSlices] of Object.entries(slices)) {
      const neighbors = new Set<string>();
      for (const slice of nodeSlices) {
        for (const target of slice) {
          if (target !== node) {
            neighbors.add(target);
          }
        }
      }
      graph[node] = Array.from(neighbors).sort();
    }
    return graph;
  }

  /**
   * Finds all minimal quorums in the given quorum slice configuration.
   * A set Q is a quorum iff for every node u in Q, there exists a slice S in slices(u) with S subset of Q.
   * A quorum Q is minimal if no proper subset Q' of Q is a quorum.
   */
  public findMinimalQuorums(slices: Record<string, string[][]>): string[][] {
    const nodes = Object.keys(slices);
    if (nodes.length === 0) return [];

    const isQuorum = (candidate: Set<string>): boolean => {
      if (candidate.size === 0) return false;
      for (const node of candidate) {
        const nodeSlices = slices[node];
        if (!nodeSlices || nodeSlices.length === 0) return false;
        const hasSatisfiedSlice = nodeSlices.some((slice) =>
          slice.every((member) => candidate.has(member)),
        );
        if (!hasSatisfiedSlice) return false;
      }
      return true;
    };

    const minimalQuorums: string[][] = [];

    // Search subsets by increasing size to guarantee minimality
    const n = nodes.length;
    // Iterate through sizes 1..n
    for (let size = 1; size <= n; size++) {
      const combos = getCombinations(nodes, size);
      for (const combo of combos) {
        const candidateSet = new Set(combo);

        // Check if candidate is already a superset of an existing minimal quorum
        const hasSubsetQuorum = minimalQuorums.some((minQ) =>
          minQ.every((member) => candidateSet.has(member)),
        );
        if (hasSubsetQuorum) continue;

        if (isQuorum(candidateSet)) {
          minimalQuorums.push([...combo].sort());
        }
      }
    }

    return minimalQuorums;
  }

  /**
   * Calculates the intersection of all minimal quorums.
   */
  public calculateIntersection(minimalQuorums: string[][]): string[] {
    if (minimalQuorums.length === 0) return [];
    const first = minimalQuorums[0]!;
    return first.filter((node) => minimalQuorums.every((q) => q.includes(node))).sort();
  }

  /**
   * Detects split-brain risk: occurs when there exist two minimal quorums that do not intersect.
   */
  public detectSplitBrain(minimalQuorums: string[][]): boolean {
    if (minimalQuorums.length < 2) return false;
    for (let i = 0; i < minimalQuorums.length; i++) {
      const q1 = new Set(minimalQuorums[i]!);
      for (let j = i + 1; j < minimalQuorums.length; j++) {
        const q2 = minimalQuorums[j]!;
        const intersects = q2.some((node) => q1.has(node));
        if (!intersects) {
          return true; // Disjoint quorums found! Split-brain risk
        }
      }
    }
    return false;
  }

  /**
   * Detects quorum fragmentation and graph connectivity.
   */
  public detectFragmentation(
    graph: Record<string, string[]>,
    minimalQuorums: string[][],
    allNodes: string[],
  ): { isFragmented: boolean; components: string[][]; isolatedNodes: string[] } {
    if (allNodes.length === 0) {
      return { isFragmented: false, components: [], isolatedNodes: [] };
    }

    // Build undirected adjacency for connected components
    const adj = new Map<string, Set<string>>();
    for (const node of allNodes) {
      adj.set(node, new Set());
    }
    for (const [u, neighbors] of Object.entries(graph)) {
      if (!adj.has(u)) adj.set(u, new Set());
      for (const v of neighbors) {
        if (!adj.has(v)) adj.set(v, new Set());
        adj.get(u)!.add(v);
        adj.get(v)!.add(u);
      }
    }

    const visited = new Set<string>();
    const components: string[][] = [];

    for (const node of allNodes) {
      if (!visited.has(node)) {
        const component: string[] = [];
        const queue: string[] = [node];
        visited.add(node);
        while (queue.length > 0) {
          const curr = queue.shift()!;
          component.push(curr);
          const nbrs = adj.get(curr) ?? new Set();
          for (const neighbor of nbrs) {
            if (!visited.has(neighbor)) {
              visited.add(neighbor);
              queue.push(neighbor);
            }
          }
        }
        components.push(component.sort());
      }
    }

    const isolatedNodes = allNodes.filter((node) => {
      const outgoingToKnown = (graph[node] ?? []).filter((nbr) => allNodes.includes(nbr));
      const incomingFromKnown = allNodes.some(
        (other) => other !== node && (graph[other] ?? []).includes(node),
      );
      return outgoingToKnown.length === 0 && !incomingFromKnown;
    });

    const isFragmented =
      components.length > 1 ||
      isolatedNodes.length > 0 ||
      (allNodes.length > 0 && minimalQuorums.length === 0);

    return {
      isFragmented,
      components,
      isolatedNodes,
    };
  }

  /**
   * Audits the quorum slice configuration for quorum intersection,
   * split-brain vulnerability, and network fragmentation.
   */
  public audit(
    input: string | StellarToml | Record<string, unknown> | ValidatorQuorumDefinition[],
  ): QuorumIntersectionResult {
    const slices = this.extractQuorumSlices(input);
    const allNodes = Object.keys(slices).sort();
    const graph = this.buildSliceGraph(slices);
    const minimalQuorums = this.findMinimalQuorums(slices);
    const intersectionNodes = this.calculateIntersection(minimalQuorums);
    const hasSplitBrainRisk = this.detectSplitBrain(minimalQuorums);
    const fragmentation = this.detectFragmentation(graph, minimalQuorums, allNodes);

    const warnings: string[] = [];
    if (allNodes.length === 0) {
      warnings.push('No validators declared in configuration.');
    } else if (minimalQuorums.length === 0) {
      warnings.push('No viable quorum can be formed with the declared slices.');
    }

    if (hasSplitBrainRisk) {
      warnings.push('Split-brain risk detected: minimal quorums exist that have zero overlap.');
    }

    if (fragmentation.isFragmented) {
      if (fragmentation.components.length > 1) {
        warnings.push(
          `Quorum graph is fragmented into ${fragmentation.components.length} disconnected components.`,
        );
      }
      if (fragmentation.isolatedNodes.length > 0) {
        warnings.push(`Isolated validator nodes with no quorum connections: ${fragmentation.isolatedNodes.join(', ')}`);
      }
    }

    const hasQuorumIntersection = minimalQuorums.length > 0 && !hasSplitBrainRisk;
    const allMinimalQuorumsIntersect = minimalQuorums.length > 0 && intersectionNodes.length > 0;

    return {
      hasQuorumIntersection,
      allMinimalQuorumsIntersect,
      minimalQuorums,
      intersectionNodes,
      hasSplitBrainRisk,
      isFragmented: fragmentation.isFragmented,
      fragmentationDetails: {
        components: fragmentation.components,
        isolatedNodes: fragmentation.isolatedNodes,
      },
      graph,
      slices,
      warnings,
    };
  }
}
