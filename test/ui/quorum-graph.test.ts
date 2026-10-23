import { describe, expect, it, vi } from 'vitest';

import {
  buildQuorumGraph,
  generateQuorumGraph,
  isQuorumGraphFormat,
  minimalQuorumSlices,
  QUORUM_GRAPH_FORMATS,
  quorumGraphForDocument,
  renderQuorumAscii,
  renderQuorumGraph,
  renderQuorumMermaid,
  renderQuorumSvg,
} from '../../src/ui/quorum-graph.js';
import { analyzeQuorumSets } from '../../src/validators/split-brain-solver.js';

const A = 'GAOOOWJ2U7AITCNNUQ4LNRRTKOQGBYBSAXRXQHVUNOAQJYMZPM5QJ4EM';
const B = 'GAVLKMYOGHWXNBOQCH5XCGJPMHF7KWBAXRXQHVUNOAQJYMZPM5QB4CDD';
const C = 'GAYB4LTP7HXQDL5QHRVNAP3XPYHPXPGTRKUGNLTNXBKA6LG3ZGGCBSVJ';
const D = 'GDXVG5F6GRT2YIOJPM4ENUYHAXRXQHVUNOAQJYMZPM5QZZZZZ2AB4DDD';
const E = 'GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';
const F = 'GCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC';
const G = 'GDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD';

const doc = {
  VALIDATORS: [
    {
      PUBLIC_KEY: A,
      ALIAS: 'alpha',
      ORGANIZATION: 'Org One',
      QUORUM_SET: {
        threshold_percent: 50,
        inner: [
          { threshold_percent: 50, validators: [B, C, D] },
          { threshold_percent: 50, validators: [E, F, G] },
        ],
      },
    },
    {
      PUBLIC_KEY: B,
      HOST: 'validator.example.com:11625',
      QUORUM_SET: { threshold_percent: 100, validators: [A, C] },
    },
    {
      PUBLIC_KEY: C,
      ORGANIZATION: 'Org Two',
      QUORUM_SET: { threshold_percent: 100, validators: [A, B] },
    },
  ],
};

async function fixtureGraph() {
  const fetchImpl = vi.fn();
  const analyses = await analyzeQuorumSets(doc, fetchImpl as typeof fetch);
  return buildQuorumGraph(analyses, {}, doc);
}

describe('isQuorumGraphFormat', () => {
  it('accepts the three renderers', () => {
    expect(QUORUM_GRAPH_FORMATS).toEqual(['ascii', 'svg', 'mermaid']);
    for (const format of QUORUM_GRAPH_FORMATS) expect(isQuorumGraphFormat(format)).toBe(true);
    expect(isQuorumGraphFormat('dot')).toBe(false);
  });
});

describe('quorumGraphForDocument', () => {
  it('projects nested slices, members, and organisations into a graph', async () => {
    const graph = await quorumGraphForDocument(doc, {
      fetchImpl: vi.fn() as unknown as typeof fetch,
    });
    expect(graph.validators.map((validator) => validator.publicKey)).toEqual([A, B, C]);
    expect(graph.nodes.filter((node) => node.kind === 'validator')).toHaveLength(3);
    expect(graph.nodes.filter((node) => node.kind === 'quorum').length).toBeGreaterThanOrEqual(5);
    expect(graph.nodes.find((node) => node.publicKey === B)?.organization).toBe('example.com');
    expect(graph.nodes.find((node) => node.publicKey === C)?.organization).toBe('Org Two');
    expect(graph.organizations).toEqual(['Org One', 'Org Two', 'example.com']);
    expect(graph.edges.some((edge) => edge.label === '2' || edge.label === '1')).toBe(true);
  });

  it('marks members whose individual failure stalls a validator', async () => {
    const graph = await fixtureGraph();
    expect(graph.criticalNodes).toContain(A);
    expect(graph.criticalNodes).toContain(C);
    const critical = graph.nodes.filter((node) => node.critical);
    expect(critical.length).toBeGreaterThan(0);
    expect(critical.every((node) => node.kind === 'member')).toBe(true);
  });

  it('uses alias labels and explicit overrides', async () => {
    const graph = await fixtureGraph();
    expect(graph.nodes.find((node) => node.publicKey === A)?.label).toContain('alpha');
    const overridden = await generateQuorumGraph(doc, {
      format: 'mermaid',
      labels: { [B]: 'beta & co' },
      fetchImpl: vi.fn() as unknown as typeof fetch,
    });
    expect(overridden).toContain('beta & co');
  });

  it('exposes the same minimal slices as the solver', async () => {
    const analyses = await analyzeQuorumSets(doc, vi.fn() as unknown as typeof fetch);
    expect(minimalQuorumSlices(analyses)).toEqual(
      Object.fromEntries(analyses.map((analysis) => [analysis.publicKey, analysis.minimalQuorums])),
    );
  });
});

describe('renderQuorumMermaid', () => {
  it('generates a valid Mermaid flowchart for a complex quorum set', async () => {
    const graph = await fixtureGraph();
    const mermaid = renderQuorumMermaid(graph);

    expect(mermaid.startsWith('flowchart TD\n')).toBe(true);
    expect(mermaid).toContain('-->');
    expect(mermaid).toContain('classDef');
    expect(mermaid).toContain('critical_node');
    expect(mermaid).toMatch(/%% .*: .* \+ .*/);
    expect(
      mermaid
        .trim()
        .split('\n')
        .every((line) => !line.includes('undefined')),
    ).toBe(true);
  });

  it('escapes quotes in Mermaid labels', async () => {
    const graph = await fixtureGraph();
    const mermaid = renderQuorumGraph(graph, 'mermaid');
    expect(mermaid).toContain('flowchart TD');
    const quoted = renderQuorumMermaid(
      buildQuorumGraph(
        [
          {
            publicKey: A,
            path: 'VALIDATORS[0].QUORUM_SET',
            set: { threshold: 1, inner: [B] },
            minimalQuorums: [[B]],
          },
        ],
        { labels: { [B]: 'node "quoted"' } },
      ),
    );
    expect(quoted).toContain('&quot;');
    expect(quoted).not.toContain('node "quoted"');
  });
});

describe('renderQuorumSvg', () => {
  it('generates a standalone SVG with tooltips and critical styling', async () => {
    const graph = await fixtureGraph();
    const svg = renderQuorumSvg(graph);
    expect(svg.startsWith('<svg xmlns="http://www.w3.org/2000/svg"')).toBe(true);
    expect(svg).toContain('</svg>');
    expect(svg).toContain('<title>');
    expect(svg).toContain('critical single point of failure');
    expect(svg).toContain('stroke="#c62828"');
    expect(svg).toContain('<desc>');
    expect(svg).not.toContain('<script');
  });

  it('escapes XML metacharacters in labels', () => {
    const svg = renderQuorumSvg(
      buildQuorumGraph(
        [
          {
            publicKey: A,
            path: 'VALIDATORS[0].QUORUM_SET',
            set: { threshold: 1, inner: [B] },
            minimalQuorums: [[B]],
          },
        ],
        { labels: { [B]: '<script>alert(1)</script>' } },
      ),
    );
    expect(svg).toContain('&lt;script&gt;');
    expect(svg).not.toContain('<script>');
  });
});

describe('renderQuorumAscii', () => {
  it('renders a tree and lists the minimal slices and critical nodes', async () => {
    const graph = await fixtureGraph();
    const ascii = renderQuorumAscii(graph);
    expect(ascii).toContain('Org One');
    expect(ascii).toContain('alpha');
    expect(ascii).toMatch(/\(2 of 3\)/);
    expect(ascii).toContain('Minimal quorum slices');
    expect(ascii).toContain('Critical nodes:');
  });
});

describe('renderQuorumGraph', () => {
  it('dispatches to each renderer', async () => {
    const graph = await fixtureGraph();
    expect(renderQuorumGraph(graph, 'ascii')).toBe(renderQuorumAscii(graph));
    expect(renderQuorumGraph(graph, 'mermaid')).toBe(renderQuorumMermaid(graph));
    expect(renderQuorumGraph(graph, 'svg')).toBe(renderQuorumSvg(graph));
  });
});
