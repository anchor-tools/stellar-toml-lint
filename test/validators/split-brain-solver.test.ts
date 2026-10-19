import { describe, expect, it } from 'vitest';

import {
  analyzeQuorumSets,
  buildTrustGraph,
  checkSplitBrain,
  findBridgeNodes,
  findOrganizationChokePoints,
  flattenMembers,
  minimumNodeCut,
  CRITICAL_BRIDGE_NODE_RULE,
  PARTITION_VULNERABILITY_RULE,
  splitBrainRules,
} from '../../src/validators/split-brain-solver.js';

const V1 = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const V2 = 'GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';
const M1 = 'GCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC';
const M2 = 'GDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD';
const M3 = 'GEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE';
const M4 = 'GFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF';

function fetchText(body: string): typeof fetch {
  return (async () => new Response(body, { status: 200 })) as unknown as typeof fetch;
}

/** Every quorum slice is the whole set (threshold 100%), for exact intersections. */
const whole = (validators: string[]) => ({ threshold_percent: 100, validators });

describe('buildTrustGraph', () => {
  it('links each validator to every member it lists', () => {
    const analyses = [
      {
        publicKey: V1,
        path: 'VALIDATORS[0].QUORUM_SET',
        set: { threshold: 2, inner: [M1, M2] },
        minimalQuorums: [[M1, M2]],
      },
      {
        publicKey: V2,
        path: 'VALIDATORS[1].QUORUM_SET',
        set: { threshold: 2, inner: [M1, M3] },
        minimalQuorums: [[M1, M3]],
      },
    ];

    const graph = buildTrustGraph(analyses);

    expect(graph.nodes).toContain(V1);
    expect(graph.nodes).toContain(M3);
    expect([...(graph.edges.get(V1) ?? [])].sort()).toEqual([M1, M2].sort());
    expect([...(graph.edges.get(V2) ?? [])].sort()).toEqual([M1, M3].sort());
  });

  it('flattens nested inner sets to leaf members', () => {
    const members = flattenMembers({
      threshold: 2,
      inner: [M1, { threshold: 1, inner: [M2, { threshold: 1, inner: [M3] }] }],
    });

    expect(members).toEqual([M1, M2, M3]);
  });
});

describe('minimumNodeCut', () => {
  it('is the smallest cross-pair intersection size', () => {
    const analyses = [
      {
        publicKey: V1,
        path: 'p',
        set: { threshold: 2, inner: [M1, M2] },
        minimalQuorums: [[M1, M2]],
      },
      {
        publicKey: V2,
        path: 'p',
        set: { threshold: 2, inner: [M1, M2, M3] },
        minimalQuorums: [[M1, M2, M3]],
      },
    ];

    // Removing M1 and M2 leaves {M3} vs {} — two removals disconnect the quorums.
    expect(minimumNodeCut(analyses)).toBe(2);
  });

  it('is zero when two quorums are already disjoint', () => {
    const analyses = [
      { publicKey: V1, path: 'p', set: { threshold: 1, inner: [M1] }, minimalQuorums: [[M1]] },
      { publicKey: V2, path: 'p', set: { threshold: 1, inner: [M2] }, minimalQuorums: [[M2]] },
    ];

    expect(minimumNodeCut(analyses)).toBe(0);
  });

  it('needs at least two quorum sets', () => {
    expect(minimumNodeCut([])).toBeUndefined();
  });
});

describe('findBridgeNodes', () => {
  it('names the single shared member of two quorums', () => {
    const analyses = [
      {
        publicKey: V1,
        path: 'p',
        set: { threshold: 2, inner: [M1, M2] },
        minimalQuorums: [[M1, M2]],
      },
      {
        publicKey: V2,
        path: 'p',
        set: { threshold: 2, inner: [M1, M3] },
        minimalQuorums: [[M1, M3]],
      },
    ];

    expect(findBridgeNodes(analyses)).toEqual([{ key: M1, left: V1, right: V2 }]);
  });

  it('reports nothing when the intersection is wider than one member', () => {
    const analyses = [
      {
        publicKey: V1,
        path: 'p',
        set: { threshold: 2, inner: [M1, M2] },
        minimalQuorums: [[M1, M2]],
      },
      {
        publicKey: V2,
        path: 'p',
        set: { threshold: 2, inner: [M1, M2] },
        minimalQuorums: [[M1, M2]],
      },
    ];

    expect(findBridgeNodes(analyses)).toEqual([]);
  });
});

describe('findOrganizationChokePoints', () => {
  it('flags an organisation owning more than half a slice', () => {
    const analyses = [
      {
        publicKey: V1,
        path: 'VALIDATORS[0].QUORUM_SET',
        set: { threshold: 4, inner: [M1, M2, M3, M4] },
        minimalQuorums: [[M1, M2, M3, M4]],
      },
    ];
    const orgs: Record<string, string> = {
      [M1]: 'acme',
      [M2]: 'acme',
      [M3]: 'acme',
      [M4]: 'other',
    };

    const chokePoints = findOrganizationChokePoints(analyses, (key) => orgs[key]);

    expect(chokePoints).toHaveLength(1);
    expect(chokePoints[0]).toMatchObject({ organization: 'acme', controlled: 3, total: 4 });
  });

  it('stays silent when no organisation has a majority', () => {
    const analyses = [
      {
        publicKey: V1,
        path: 'p',
        set: { threshold: 3, inner: [M1, M2, M3] },
        minimalQuorums: [[M1, M2, M3]],
      },
    ];
    const orgs: Record<string, string> = { [M1]: 'acme', [M2]: 'beta', [M3]: 'gamma' };

    expect(findOrganizationChokePoints(analyses, (key) => orgs[key])).toEqual([]);
  });
});

describe('checkSplitBrain', () => {
  it('passes an intersecting quorum graph with no bridge', async () => {
    const doc = {
      VALIDATORS: [
        { PUBLIC_KEY: V1, QUORUM_SET: whole([M1, M2, M3]) },
        { PUBLIC_KEY: V2, QUORUM_SET: whole([M1, M2, M3]) },
      ],
    };

    expect(await checkSplitBrain(doc, fetchText(''))).toEqual([]);
  });

  it('reports a partition vulnerability and the bridge node for a one-member overlap', async () => {
    const doc = {
      VALIDATORS: [
        { PUBLIC_KEY: V1, QUORUM_SET: whole([M1, M2]) },
        { PUBLIC_KEY: V2, QUORUM_SET: whole([M1, M3]) },
      ],
    };

    const diagnostics = await checkSplitBrain(doc, fetchText(''));

    const vulnerability = diagnostics.find((d) => d.rule === PARTITION_VULNERABILITY_RULE);
    expect(vulnerability).toBeDefined();
    expect(vulnerability?.severity).toBe('error');

    const bridge = diagnostics.find((d) => d.rule === CRITICAL_BRIDGE_NODE_RULE);
    expect(bridge).toBeDefined();
    expect(bridge?.severity).toBe('warning');
    expect(bridge?.message).toContain(M1);
  });

  it('reports an organization choke point as a partition vulnerability', async () => {
    const doc = {
      VALIDATORS: [
        { PUBLIC_KEY: V1, QUORUM_SET: whole([M1, M2, M3, M4]) },
        { PUBLIC_KEY: V2, QUORUM_SET: whole([M1, M2, M3, M4]) },
      ],
    };

    const diagnostics = await checkSplitBrain(doc, fetchText(''), {
      organizations: { [M1]: 'acme', [M2]: 'acme', [M3]: 'acme', [M4]: 'other' },
    });

    const vulnerability = diagnostics.find(
      (d) => d.rule === PARTITION_VULNERABILITY_RULE && d.message.includes('acme'),
    );
    expect(vulnerability).toBeDefined();
    expect(vulnerability?.path).toBe('VALIDATORS[0].QUORUM_SET');
  });

  it('follows a CONFIG_URL stellar-core.cfg', async () => {
    const cfg = `[QUORUM_SET]\nTHRESHOLD_PERCENT = 100\nVALIDATORS = ["${M1}", "${M2}"]\n`;
    const cfgBridge = `[QUORUM_SET]\nTHRESHOLD_PERCENT = 100\nVALIDATORS = ["${M1}", "${M3}"]\n`;
    const fetchImpl = (async (input: Parameters<typeof fetch>[0]) =>
      new Response(String(input).includes('a.example') ? cfg : cfgBridge, {
        status: 200,
      })) as typeof fetch;

    const doc = {
      VALIDATORS: [
        { PUBLIC_KEY: V1, CONFIG_URL: 'https://a.example/stellar-core.cfg' },
        { PUBLIC_KEY: V2, CONFIG_URL: 'https://b.example/stellar-core.cfg' },
      ],
    };

    const diagnostics = await checkSplitBrain(doc, fetchImpl);
    expect(diagnostics.some((d) => d.rule === CRITICAL_BRIDGE_NODE_RULE)).toBe(true);
  });

  it('honours rule overrides', async () => {
    const doc = {
      VALIDATORS: [
        { PUBLIC_KEY: V1, QUORUM_SET: whole([M1, M2]) },
        { PUBLIC_KEY: V2, QUORUM_SET: whole([M1, M3]) },
      ],
    };

    const diagnostics = await checkSplitBrain(doc, fetchText(''), {
      rules: { [PARTITION_VULNERABILITY_RULE]: 'off' },
    });

    expect(diagnostics.every((d) => d.rule !== PARTITION_VULNERABILITY_RULE)).toBe(true);
    expect(diagnostics.some((d) => d.rule === CRITICAL_BRIDGE_NODE_RULE)).toBe(true);
  });

  it('stays silent with fewer than two resolvable quorum sets', async () => {
    const doc = {
      VALIDATORS: [{ PUBLIC_KEY: V1, QUORUM_SET: whole([M1, M2]) }, { PUBLIC_KEY: V2 }],
    };

    expect(await checkSplitBrain(doc, fetchText(''))).toEqual([]);
  });

  it('is registered for --list-rules', () => {
    expect(splitBrainRules.map((rule) => rule.id)).toEqual([
      PARTITION_VULNERABILITY_RULE,
      CRITICAL_BRIDGE_NODE_RULE,
    ]);
  });
});

describe('analyzeQuorumSets', () => {
  it('solves inline quorum sets', async () => {
    const doc = {
      VALIDATORS: [{ PUBLIC_KEY: V1, QUORUM_SET: whole([M1, M2]) }],
    };

    const analyses = await analyzeQuorumSets(doc, fetchText(''));

    expect(analyses).toHaveLength(1);
    expect(analyses[0]?.publicKey).toBe(V1);
    expect(analyses[0]?.minimalQuorums).toEqual([[M1, M2]]);
  });
});
