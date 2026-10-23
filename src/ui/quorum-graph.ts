/**
 * Visual quorum graph explorer (issue #316).
 *
 * A text dump of `[[VALIDATORS]].QUORUM_SET` cannot convey how multi-tiered
 * quorum slices overlap, which nodes are load-bearing, or which organisation
 * owns them. This module builds the graph a quorum set actually describes —
 * validators, nested threshold slices, and leaf members — marks the members
 * whose individual failure stalls a validator, colour-codes nodes by their
 * organisation or domain, and renders it as terminal ASCII, Mermaid, or a
 * standalone interactive SVG.
 *
 * The graph is intentionally a projection of the quorum sets, not a trust
 * graph between validators: every edge means "this slice needs that member",
 * and every threshold node says how many of its children must agree. Minimal
 * quorum slices are enumerated with the same solver used by the offline quorum
 * audits, so the picture and the diagnostics can never disagree.
 */

import type { QuorumSet } from '../validators/quorum-solver.js';
import { analyzeQuorumSets, type QuorumAnalysis } from '../validators/split-brain-solver.js';
import { findCriticalNodes } from '../validators/byzantine-simulator.js';

export type QuorumGraphFormat = 'ascii' | 'svg' | 'mermaid';

export const QUORUM_GRAPH_FORMATS: readonly QuorumGraphFormat[] = ['ascii', 'svg', 'mermaid'];

export function isQuorumGraphFormat(value: string): value is QuorumGraphFormat {
  return (QUORUM_GRAPH_FORMATS as readonly string[]).includes(value);
}

export interface QuorumGraphNode {
  id: string;
  label: string;
  kind: 'validator' | 'quorum' | 'member';
  /** Public key for validator/member nodes. */
  publicKey?: string;
  /** Threshold of a quorum node (`threshold of inner.length`). */
  threshold?: number;
  /** Number of children in the slice. */
  total?: number;
  /** Weight of this node inside its parent slice. */
  weight?: number;
  organization?: string;
  /** True when this member alone can stall its validator. */
  critical?: boolean;
  /** Distance from the validator root. */
  depth: number;
}

export interface QuorumGraphEdge {
  from: string;
  to: string;
  label?: string;
}

export interface QuorumGraphValidator {
  publicKey: string;
  path: string;
  alias?: string;
  organization?: string;
  minimalQuorums: string[][];
  criticalNodes: string[];
}

export interface QuorumGraph {
  nodes: QuorumGraphNode[];
  edges: QuorumGraphEdge[];
  validators: QuorumGraphValidator[];
  organizations: string[];
  criticalNodes: string[];
}

export interface QuorumGraphOptions {
  /** Organisation override per public key. */
  organizations?: Record<string, string>;
  /** Display-label override per public key. */
  labels?: Record<string, string>;
  fetchImpl?: typeof fetch;
}

const ORG_PALETTE = [
  '#e3f2fd',
  '#e8f5e9',
  '#fff3e0',
  '#f3e5f5',
  '#e0f7fa',
  '#fce4ec',
  '#f1f8e9',
  '#ede7f6',
];

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : undefined;
}

/** Registrable-ish domain: the last two labels of a host, ignoring the port. */
function registrableDomain(host: string): string {
  const clean = (host.split(':')[0] ?? '').toLowerCase().replace(/\.$/, '');
  const parts = clean.split('.').filter((part) => part !== '');
  return parts.length <= 2 ? clean : parts.slice(-2).join('.');
}

function organizationForEntry(
  entry: Record<string, unknown>,
  overrides: Record<string, string>,
): string | undefined {
  const key = stringValue(entry.PUBLIC_KEY);
  if (key !== undefined && overrides[key] !== undefined) return overrides[key];
  if (typeof entry.ORGANIZATION === 'string' && entry.ORGANIZATION.trim() !== '') {
    return entry.ORGANIZATION.trim();
  }
  const host = stringValue(entry.HOST);
  if (host !== undefined) {
    const domain = registrableDomain(host);
    if (domain !== '') return domain;
  }
  return stringValue(entry.ALIAS);
}

function displayLabel(key: string, labels: Record<string, string>): string {
  const override = labels[key];
  if (override !== undefined && override.trim() !== '') return override.trim();
  return key;
}

function entryMaps(
  doc: Record<string, unknown>,
  options: QuorumGraphOptions,
): { organizations: Record<string, string>; labels: Record<string, string> } {
  const organizations: Record<string, string> = { ...(options.organizations ?? {}) };
  const labels: Record<string, string> = { ...(options.labels ?? {}) };
  const list = Array.isArray(doc.VALIDATORS) ? doc.VALIDATORS : [];
  for (const entry of list) {
    if (!isRecord(entry)) continue;
    const key = stringValue(entry.PUBLIC_KEY);
    if (key === undefined) continue;
    const org = organizationForEntry(entry, options.organizations ?? {});
    if (org !== undefined) organizations[key] = org;
    const alias = stringValue(entry.ALIAS) ?? stringValue(entry.DISPLAY_NAME);
    if (alias !== undefined && labels[key] === undefined) {
      labels[key] = `${alias} (${key})`;
    }
  }
  return { organizations, labels };
}

/** Every minimal quorum slice the document's validators declare. */
export function minimalQuorumSlices(
  analyses: readonly QuorumAnalysis[],
): Record<string, string[][]> {
  const slices: Record<string, string[][]> = {};
  for (const analysis of analyses) slices[analysis.publicKey] = analysis.minimalQuorums;
  return slices;
}

/**
 * Builds the visual graph from already-solved quorum analyses. Kept pure so
 * the renderers and tests do not need a transport.
 */
export function buildQuorumGraph(
  analyses: readonly QuorumAnalysis[],
  options: QuorumGraphOptions = {},
  doc: Record<string, unknown> = {},
): QuorumGraph {
  const maps = entryMaps(doc, options);
  const organizations = maps.organizations;
  const labels = maps.labels;
  const nodes = new Map<string, QuorumGraphNode>();
  const edges: QuorumGraphEdge[] = [];
  const nodeByMember = new Map<string, string>();
  const criticalUnion = new Set<string>();
  const organizationSet = new Set<string>();
  let nextId = 0;

  const addNode = (node: QuorumGraphNode): void => {
    nodes.set(node.id, node);
    if (node.organization !== undefined) organizationSet.add(node.organization);
  };

  const memberId = (key: string, depth: number): string => {
    const existing = nodeByMember.get(key);
    if (existing !== undefined) return existing;
    const id = `node_${nextId++}`;
    nodeByMember.set(key, id);
    const organization = organizations[key];
    addNode({
      id,
      label: displayLabel(key, labels),
      kind: 'member',
      publicKey: key,
      depth,
      ...(organization === undefined ? {} : { organization }),
    });
    return id;
  };

  const addSet = (set: QuorumSet, parent: string, depth: number, validatorKey: string): void => {
    const id = `quorum_${nextId++}`;
    const label = `${set.threshold}/${set.inner.length}`;
    addNode({
      id,
      label,
      kind: 'quorum',
      threshold: set.threshold,
      total: set.inner.length,
      weight: set.threshold / set.inner.length,
      depth,
    });
    edges.push({ from: parent, to: id, label });

    for (const child of set.inner) {
      if (typeof child === 'string') {
        const childId = memberId(child, depth + 1);
        edges.push({ from: id, to: childId, label: '1' });
        if (criticalUnion.has(child)) {
          const node = nodes.get(childId);
          if (node !== undefined) node.critical = true;
        }
        continue;
      }
      addSet(child, id, depth + 1, validatorKey);
    }
  };

  const validators: QuorumGraphValidator[] = [];
  for (const analysis of analyses) {
    const critical = findCriticalNodes(analysis.set);
    for (const key of critical) criticalUnion.add(key);
    const organization = organizations[analysis.publicKey];
    const id = `validator_${nextId++}`;
    addNode({
      id,
      label: displayLabel(analysis.publicKey, labels),
      kind: 'validator',
      publicKey: analysis.publicKey,
      depth: 0,
      ...(organization === undefined ? {} : { organization }),
    });
    addSet(analysis.set, id, 1, analysis.publicKey);
    const alias = labels[analysis.publicKey]?.replace(` (${analysis.publicKey})`, '');
    validators.push({
      publicKey: analysis.publicKey,
      path: analysis.path,
      minimalQuorums: analysis.minimalQuorums,
      criticalNodes: critical,
      ...(alias === undefined || alias === displayLabel(analysis.publicKey, labels)
        ? {}
        : { alias }),
      ...(organization === undefined ? {} : { organization }),
    });
  }

  // Critical status is only known after every validator's set has been solved.
  for (const node of nodes.values()) {
    if (
      node.kind === 'member' &&
      node.publicKey !== undefined &&
      criticalUnion.has(node.publicKey)
    ) {
      node.critical = true;
    }
  }

  return {
    nodes: [...nodes.values()],
    edges,
    validators,
    organizations: [...organizationSet].sort(),
    criticalNodes: [...criticalUnion].sort(),
  };
}

/** Resolves the document's quorum sets and builds the visual graph. */
export async function quorumGraphForDocument(
  doc: Record<string, unknown>,
  options: QuorumGraphOptions = {},
): Promise<QuorumGraph> {
  const analyses = await analyzeQuorumSets(doc, options.fetchImpl ?? fetch);
  return buildQuorumGraph(analyses, options, doc);
}

/** Alias used by callers that think of this as the graph builder. */
export const buildQuorumGraphForDocument = quorumGraphForDocument;

function escapeMermaid(text: string): string {
  return text.replace(/\\/g, '\\\\').replace(/"/g, '&quot;');
}

function classToken(value: string, prefix: string): string {
  const clean = value
    .toLowerCase()
    .replace(/[^a-z0-9_]+/g, '_')
    .replace(/^_+|_+$/g, '');
  return `${prefix}_${clean === '' ? 'other' : clean}`;
}

/** Renders the graph as a Mermaid `flowchart TD`. */
export function renderQuorumMermaid(graph: QuorumGraph): string {
  const lines: string[] = ['flowchart TD'];
  const orgClasses = new Map<string, string>();
  const usedClasses = new Set<string>();

  for (const node of graph.nodes) {
    lines.push(`  ${node.id}["${escapeMermaid(node.label)}"]`);
  }

  for (const edge of graph.edges) {
    if (edge.label === undefined) {
      lines.push(`  ${edge.from} --> ${edge.to}`);
    } else {
      lines.push(`  ${edge.from} -->|"${escapeMermaid(edge.label)}"| ${edge.to}`);
    }
  }

  for (const node of graph.nodes) {
    if (node.organization !== undefined) {
      const token = classToken(node.organization, 'org');
      orgClasses.set(node.organization, token);
      if (!usedClasses.has(token)) {
        usedClasses.add(token);
        const index = orgClasses.size - 1;
        lines.push(
          `  classDef ${token} fill:${ORG_PALETTE[index % ORG_PALETTE.length]},stroke:#546e7a,stroke-width:1px`,
        );
      }
      lines.push(`  class ${node.id} ${token}`);
    }
    if (node.critical) {
      if (!usedClasses.has('critical_node')) {
        usedClasses.add('critical_node');
        lines.push('  classDef critical_node fill:#ffebee,stroke:#c62828,stroke-width:3px');
      }
      lines.push(`  class ${node.id} critical_node`);
    }
  }

  const slices = graph.validators.flatMap((validator) =>
    validator.minimalQuorums.map((quorum) => `%% ${validator.publicKey}: ${quorum.join(' + ')}`),
  );
  if (slices.length > 0) lines.push(...slices);
  if (graph.criticalNodes.length > 0) {
    lines.push(`%% critical nodes: ${graph.criticalNodes.join(', ')}`);
  }
  return `${lines.join('\n')}\n`;
}

/** Alias: render a graph as Mermaid. */
export const renderMermaid = renderQuorumMermaid;
export const renderQuorumGraphMermaid = renderQuorumMermaid;

function asciiLabel(node: QuorumGraphNode): string {
  const org = node.organization === undefined ? '' : `[${node.organization}] `;
  const critical = node.critical ? ' *' : '';
  return `${org}${node.label}${critical}`;
}

/** Renders the graph as a terminal-friendly ASCII DAG. */
export function renderQuorumAscii(graph: QuorumGraph): string {
  const children = new Map<string, QuorumGraphEdge[]>();
  for (const edge of graph.edges) {
    const list = children.get(edge.from) ?? [];
    list.push(edge);
    children.set(edge.from, list);
  }
  const byId = new Map(graph.nodes.map((node) => [node.id, node]));
  const lines: string[] = [];

  const walk = (id: string, prefix: string, isLast: boolean, depth: number): void => {
    if (depth > 24) return;
    const node = byId.get(id);
    if (node === undefined) return;
    const connector = depth === 0 ? '' : isLast ? '└─ ' : '├─ ';
    const suffix = node.kind === 'quorum' ? ` (${node.threshold} of ${node.total})` : '';
    lines.push(`${prefix}${connector}${asciiLabel(node)}${suffix}`);
    const nextPrefix = depth === 0 ? '' : `${prefix}${isLast ? '   ' : '│  '}`;
    const outgoing = children.get(id) ?? [];
    outgoing.forEach((edge, index) => {
      walk(edge.to, nextPrefix, index === outgoing.length - 1, depth + 1);
    });
  };

  for (const validator of graph.validators) {
    const root = graph.nodes.find(
      (node) => node.kind === 'validator' && node.publicKey === validator.publicKey,
    );
    if (root === undefined) continue;
    walk(root.id, '', true, 0);
    lines.push('');
  }

  if (graph.validators.length > 0) {
    lines.push('Minimal quorum slices');
    for (const validator of graph.validators) {
      lines.push(`  ${validator.publicKey}`);
      if (validator.minimalQuorums.length === 0) {
        lines.push('    (not enumerable)');
        continue;
      }
      validator.minimalQuorums.forEach((quorum, index) => {
        lines.push(`    ${index + 1}. ${quorum.join(', ')}`);
      });
    }
    if (graph.criticalNodes.length > 0) {
      lines.push('', `Critical nodes: ${graph.criticalNodes.join(', ')}`);
    }
  }

  return `${lines.join('\n')}\n`;
}

export const renderAscii = renderQuorumAscii;
export const renderQuorumGraphAscii = renderQuorumAscii;

function escapeXml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

interface LayoutNode {
  node: QuorumGraphNode;
  x: number;
  y: number;
  width: number;
  height: number;
}

/** Renders a standalone, tooltip-enabled SVG of the quorum graph. */
export function renderQuorumSvg(graph: QuorumGraph): string {
  const byDepth = new Map<number, QuorumGraphNode[]>();
  for (const node of graph.nodes) {
    const depth = node.kind === 'validator' ? 0 : Math.max(1, node.depth);
    const list = byDepth.get(depth) ?? [];
    list.push(node);
    byDepth.set(depth, list);
  }

  const columnWidth = 280;
  const rowHeight = 74;
  const nodeHeight = 40;
  const layout = new Map<string, LayoutNode>();
  let maxRows = 1;
  for (const [depth, list] of [...byDepth.entries()].sort((a, b) => a[0] - b[0])) {
    maxRows = Math.max(maxRows, list.length);
    list.forEach((node, index) => {
      const width = Math.min(250, Math.max(120, node.label.length * 7 + 28));
      layout.set(node.id, {
        node,
        x: 32 + depth * columnWidth,
        y: 32 + index * rowHeight,
        width,
        height: nodeHeight,
      });
    });
  }

  const maxDepth = Math.max(0, ...[...byDepth.keys()]);
  const width = 32 + maxDepth * columnWidth + 280;
  const height = 32 + maxRows * rowHeight + 32;

  const orgColor = new Map<string, string>();
  for (const org of graph.organizations) {
    orgColor.set(org, ORG_PALETTE[orgColor.size % ORG_PALETTE.length] as string);
  }

  const parts: string[] = [
    `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" role="img" aria-label="Quorum graph">`,
    '  <defs>',
    '    <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">',
    '      <path d="M 0 0 L 10 5 L 0 10 z" fill="#607d8b" />',
    '    </marker>',
    '  </defs>',
    '  <style>text{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;fill:#263238} .edge{stroke:#90a4ae;stroke-width:1.4;fill:none}</style>',
    `  <rect x="0" y="0" width="${width}" height="${height}" fill="#ffffff" />`,
  ];

  for (const edge of graph.edges) {
    const from = layout.get(edge.from);
    const to = layout.get(edge.to);
    if (from === undefined || to === undefined) continue;
    const x1 = from.x + from.width;
    const y1 = from.y + from.height / 2;
    const x2 = to.x;
    const y2 = to.y + to.height / 2;
    const midX = (x1 + x2) / 2;
    parts.push(
      `  <path class="edge" d="M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}" marker-end="url(#arrow)" />`,
    );
    if (edge.label !== undefined) {
      parts.push(
        `  <text x="${midX}" y="${(y1 + y2) / 2 - 4}" text-anchor="middle" fill="#546e7a">${escapeXml(edge.label)}</text>`,
      );
    }
  }

  for (const entry of layout.values()) {
    const { node, x, y, width: boxWidth, height: boxHeight } = entry;
    const fill =
      node.organization === undefined ? '#f5f7f8' : (orgColor.get(node.organization) ?? '#f5f7f8');
    const stroke = node.critical ? '#c62828' : '#546e7a';
    const strokeWidth = node.critical ? 3 : 1;
    const title =
      `${node.kind}: ${node.label}` +
      (node.organization === undefined ? '' : `, organization ${node.organization}`) +
      (node.threshold === undefined ? '' : `, threshold ${node.threshold} of ${node.total}`) +
      (node.critical ? ', critical single point of failure' : '');
    parts.push(`  <g>`);
    parts.push(`    <title>${escapeXml(title)}</title>`);
    parts.push(
      `    <rect x="${x}" y="${y}" width="${boxWidth}" height="${boxHeight}" rx="8" ry="8" fill="${fill}" stroke="${stroke}" stroke-width="${strokeWidth}" />`,
    );
    parts.push(
      `    <text x="${x + boxWidth / 2}" y="${y + boxHeight / 2 + 4}" text-anchor="middle">${escapeXml(node.label)}</text>`,
    );
    parts.push('  </g>');
  }

  parts.push(
    `  <desc>${escapeXml(
      graph.validators
        .map(
          (validator) =>
            `${validator.publicKey}: ${validator.minimalQuorums
              .map((quorum) => quorum.join(' + '))
              .join(' | ')}`,
        )
        .join('; '),
    )}</desc>`,
  );
  parts.push('</svg>');
  return `${parts.join('\n')}\n`;
}

export const renderSvg = renderQuorumSvg;
export const renderQuorumGraphSvg = renderQuorumSvg;

/** Renders one graph in the requested format. */
export function renderQuorumGraph(graph: QuorumGraph, format: QuorumGraphFormat): string {
  switch (format) {
    case 'mermaid':
      return renderQuorumMermaid(graph);
    case 'svg':
      return renderQuorumSvg(graph);
    case 'ascii':
      return renderQuorumAscii(graph);
  }
}

/** Resolves and renders the document's quorum graph in one call. */
export async function generateQuorumGraph(
  doc: Record<string, unknown>,
  options: QuorumGraphOptions & { format?: QuorumGraphFormat } = {},
): Promise<string> {
  const graph = await quorumGraphForDocument(doc, options);
  return renderQuorumGraph(graph, options.format ?? 'ascii');
}
