import { describe, expect, it } from 'vitest';
import {
  checkQuorumIntersection,
  failureResilience,
  findDisjointQuorumPair,
  minimalBlockingSets,
  minimalQuorums,
  normalizeQuorumSet,
  parseCoreCfgQuorumSet,
  QUORUM_INTERSECTION_FAILURE_RULE,
  FRAGILE_QUORUM_THRESHOLD_RULE,
} from '../src/validators/quorum-solver.js';

const A = 'GAOOOWJ2U7AITCNNUQ4LNRRTKOQGBYBSAXRXQHVUNOAQJYMZPM5QJ4EM';
const B = 'GAVLKMYOGHWXNBOQCH5XCGJPMHF7KWBAXRXQHVUNOAQJYMZPM5QB4CDD';
const C = 'GAYB4LTP7HXQDL5QHRVNAP3XPYHPXPGTRKUGNLTNXBKA6LG3ZGGCBSVJ';
const D = 'GDXVG5F6GRT2YIOJPM4ENUYHAXRXQHVUNOAQJYMZPM5QZZZZZ2AB4DDD';

function fetchJson(body: unknown): typeof fetch {
  return (async () =>
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })) as typeof fetch;
}

function fetchText(body: string): typeof fetch {
  return (async () => new Response(body, { status: 200 })) as unknown as typeof fetch;
}

function fetchReject(): typeof fetch {
  return (async () => {
    throw new Error('unreachable');
  }) as unknown as typeof fetch;
}

describe('normalizeQuorumSet', () => {
  it('rounds a threshold percentage up onto the slice count', () => {
    const set = normalizeQuorumSet({
      threshold_percent: 67,
      validators: [A, B, C],
    });
    // 67% of three slices is 2.01 — stellar-core rounds up to all three.
    expect(set).toEqual({ threshold: 3, inner: [A, B, C] });
    const majority = normalizeQuorumSet({
      threshold_percent: 50,
      validators: [A, B, C],
    });
    expect(majority?.threshold).toBe(2);
  });

  it('flattens nested inner sets', () => {
    const set = normalizeQuorumSet({
      threshold_percent: 67,
      validators: [A],
      inner: [{ threshold_percent: 67, validators: [B, C] }],
    });
    expect(set).toEqual({
      threshold: 2,
      inner: [A, { threshold: 2, inner: [B, C] }],
    });
  });

  it('rejects shapes it cannot interpret', () => {
    expect(normalizeQuorumSet('nope')).toBeUndefined();
    expect(normalizeQuorumSet({ threshold_percent: 0 })).toBeUndefined();
    expect(normalizeQuorumSet({ threshold_percent: 67 })).toBeUndefined();
  });
});

describe('minimalQuorums', () => {
  it('lists each exact-threshold combination of members', () => {
    const set = normalizeQuorumSet({ threshold_percent: 50, validators: [A, B, C] });
    if (set === undefined) throw new Error('fixture set did not parse');
    const { quorums, complete } = minimalQuorums(set);
    expect(complete).toBe(true);
    expect(quorums).toHaveLength(3);
    expect(quorums.map((quorum) => quorum.length).sort()).toEqual([2, 2, 2]);
  });

  it('unions nested slices and keeps only the minimal quorums', () => {
    // Either A alone agrees, or the nested 2-of-3 slice over {B, C, D} does.
    const set = normalizeQuorumSet({
      threshold_percent: 50,
      validators: [A],
      inner: [{ threshold_percent: 50, validators: [B, C, D] }],
    });
    if (set === undefined) throw new Error('fixture set did not parse');
    const { quorums } = minimalQuorums(set);
    const keys = quorums.map((quorum) => quorum.join(',')).sort();
    expect(keys).toEqual([A, [B, C].join(','), [B, D].join(','), [C, D].join(',')].sort());
  });
});

describe('findDisjointQuorumPair', () => {
  it('finds disjoint quorums across two validators', () => {
    const pair = findDisjointQuorumPair(
      { publicKey: A, quorums: [[A], [B]] },
      { publicKey: C, quorums: [[C], [D]] },
    );
    expect(pair).toEqual([[A], [C]]);
  });

  it('returns nothing when every quorum overlaps', () => {
    const pair = findDisjointQuorumPair(
      { publicKey: A, quorums: [[A, B]] },
      { publicKey: C, quorums: [[A, C]] },
    );
    expect(pair).toBeUndefined();
  });
});

describe('minimalBlockingSets and resilience', () => {
  it('single-critical-member sets have zero resilience', () => {
    const set = normalizeQuorumSet({ threshold_percent: 67, validators: [A] });
    if (set === undefined) throw new Error('fixture set did not parse');
    const { quorums, complete } = minimalQuorums(set);
    const blocking = minimalBlockingSets(set, quorums);
    expect(complete).toBe(true);
    expect(blocking.blockingSets).toEqual([[A]]);
    expect(failureResilience(blocking.blockingSets, blocking.complete)).toBe(0);
  });

  it('a 2-of-3 slice tolerates one failure', () => {
    const set = normalizeQuorumSet({ threshold_percent: 50, validators: [A, B, C] });
    if (set === undefined) throw new Error('fixture set did not parse');
    const { quorums } = minimalQuorums(set);
    const blocking = minimalBlockingSets(set, quorums);
    expect(failureResilience(blocking.blockingSets, blocking.complete)).toBe(1);
  });
});

describe('parseCoreCfgQuorumSet', () => {
  it('parses threshold, validators, and nested sections from stellar-core.cfg', () => {
    const cfg = `
UNIQUE_ID = "test"

[QUORUM_SET]
THRESHOLD_PERCENT = 67
VALIDATORS = ["$full1", "$full2", "GSELF..."]

[QUORUM_SET.full1]
THRESHOLD_PERCENT = 67
VALIDATORS = ["${A}", "${B}", "${C}"]

[QUORUM_SET.full2]
VALIDATORS = ["${D}"]
`;
    const set = parseCoreCfgQuorumSet(cfg);
    expect(set).toBeDefined();
    expect(set?.threshold).toBe(3);
    expect(set?.inner).toHaveLength(3);
  });

  it('returns undefined for configs with no quorum stanza', () => {
    expect(parseCoreCfgQuorumSet('NODE_HOME = "/var/lib"\n')).toBeUndefined();
  });
});

describe('checkQuorumIntersection', () => {
  it('passes a valid intersecting quorum graph', async () => {
    const doc = {
      VALIDATORS: [
        { PUBLIC_KEY: A, QUORUM_SET: { threshold_percent: 50, validators: [A, B, C] } },
        { PUBLIC_KEY: B, QUORUM_SET: { threshold_percent: 50, validators: [A, B, C] } },
        { PUBLIC_KEY: C, QUORUM_SET: { threshold_percent: 50, validators: [A, B, C] } },
      ],
    };
    expect(await checkQuorumIntersection(doc, fetchJson({}))).toEqual([]);
  });

  it('reports quorum-intersection-failure for a disjoint quorum graph', async () => {
    const doc = {
      VALIDATORS: [
        { PUBLIC_KEY: A, QUORUM_SET: { threshold_percent: 51, validators: [A, B, D] } },
        { PUBLIC_KEY: C, QUORUM_SET: { threshold_percent: 51, validators: [C, D, B] } },
      ],
    };
    const diagnostics = await checkQuorumIntersection(doc, fetchJson({}));
    const failure = diagnostics.find((d) => d.rule === QUORUM_INTERSECTION_FAILURE_RULE);
    expect(failure).toBeDefined();
    expect(failure?.severity).toBe('error');
    expect(failure?.path).toBe('VALIDATORS[0].QUORUM_SET');
  });

  it('warns about thresholds below the two-thirds safety margin', async () => {
    const doc = {
      VALIDATORS: [
        { PUBLIC_KEY: A, QUORUM_SET: { threshold_percent: 50, validators: [A, B, C, D] } },
        { PUBLIC_KEY: B, QUORUM_SET: { threshold_percent: 67, validators: [A, B, C, D] } },
        { PUBLIC_KEY: C, QUORUM_SET: { threshold_percent: 67, validators: [A, B, C, D] } },
        { PUBLIC_KEY: D, QUORUM_SET: { threshold_percent: 67, validators: [A, B, C, D] } },
      ],
    };
    const diagnostics = await checkQuorumIntersection(doc, fetchJson({}));
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      rule: FRAGILE_QUORUM_THRESHOLD_RULE,
      severity: 'warning',
      path: 'VALIDATORS[0].QUORUM_SET',
    });
  });

  it('follows CONFIG_URL to a linked stellar-core.cfg', async () => {
    const cfg = `
[QUORUM_SET]
THRESHOLD_PERCENT = 50
VALIDATORS = ["${A}", "${B}"]
`;
    const urls: string[] = [];
    const fetchImpl = (async (input: Parameters<typeof fetch>[0]) => {
      urls.push(String(input));
      return new Response(cfg, { status: 200 });
    }) as typeof fetch;
    const doc = {
      VALIDATORS: [
        { PUBLIC_KEY: A, CONFIG_URL: 'https://a.example/stellar-core.cfg' },
        { PUBLIC_KEY: B, CONFIG_URL: 'https://b.example/stellar-core.cfg' },
      ],
    };
    const diagnostics = await checkQuorumIntersection(doc, fetchImpl);
    expect(urls).toHaveLength(2);
    // 1-of-2 from both sides: {A} and {B} are disjoint quorums.
    expect(diagnostics.some((d) => d.rule === QUORUM_INTERSECTION_FAILURE_RULE)).toBe(true);
  });

  it('stays silent when configs are unreachable or undeclared', async () => {
    const doc = {
      VALIDATORS: [
        { PUBLIC_KEY: A, CONFIG_URL: 'https://a.example/stellar-core.cfg' },
        { PUBLIC_KEY: B },
      ],
    };
    expect(await checkQuorumIntersection(doc, fetchReject())).toEqual([]);
  });

  it('honours rule overrides', async () => {
    const doc = {
      VALIDATORS: [
        { PUBLIC_KEY: A, QUORUM_SET: { threshold_percent: 50, validators: [A, B] } },
        { PUBLIC_KEY: B, QUORUM_SET: { threshold_percent: 50, validators: [A, B] } },
      ],
    };
    const withOff = await checkQuorumIntersection(doc, fetchText(''), {
      rules: { [QUORUM_INTERSECTION_FAILURE_RULE]: 'off' },
    });
    // A 1-of-2 threshold is still fragile even with the error silenced.
    expect(withOff.every((d) => d.rule !== QUORUM_INTERSECTION_FAILURE_RULE)).toBe(true);
    expect(withOff.some((d) => d.rule === FRAGILE_QUORUM_THRESHOLD_RULE)).toBe(true);
  });
});
