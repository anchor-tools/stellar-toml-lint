import { describe, expect, it } from 'vitest';

import {
  analyseByzantineResilience,
  byzantineSimulatorRules,
  checkByzantineResilience,
  CATASTROPHIC_SINGLE_POINT_OF_FAILURE_RULE,
  estimateStallProbability,
  findCriticalNodes,
  LOW_BYZANTINE_FAULT_TOLERANCE_RULE,
  quorumSatisfied,
} from '../../src/validators/byzantine-simulator.js';
import { normalizeQuorumSet, type QuorumSet } from '../../src/validators/quorum-solver.js';

const A = 'GAOOOWJ2U7AITCNNUQ4LNRRTKOQGBYBSAXRXQHVUNOAQJYMZPM5QJ4EM';
const B = 'GAVLKMYOGHWXNBOQCH5XCGJPMHF7KWBAXRXQHVUNOAQJYMZPM5QB4CDD';
const C = 'GAYB4LTP7HXQDL5QHRVNAP3XPYHPXPGTRKUGNLTNXBKA6LG3ZGGCBSVJ';
const D = 'GDXVG5F6GRT2YIOJPM4ENUYHAXRXQHVUNOAQJYMZPM5QZZZZZ2AB4DDD';
const E = 'GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';
const F = 'GCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC';
const G = 'GDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD';
const H = 'GEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE';
const I = 'GFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF';
const J = 'GHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH';
const K = 'GIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII';
const L = 'GJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ';

function set(raw: Parameters<typeof normalizeQuorumSet>[0]): QuorumSet {
  const normalized = normalizeQuorumSet(raw);
  if (normalized === undefined) throw new Error('fixture quorum set did not parse');
  return normalized;
}

const simple = set({ threshold_percent: 50, validators: [A, B, C] });
const vulnerableRaw = { threshold_percent: 100, validators: [A, B] };
const vulnerable = set(vulnerableRaw);

/** Top level needs 2 of 3 groups; every group needs 3 of its 4 members. */
const robustRaw = {
  threshold_percent: 50,
  inner: [
    { threshold_percent: 75, validators: [A, B, C, D] },
    { threshold_percent: 75, validators: [E, F, G, H] },
    { threshold_percent: 75, validators: [I, J, K, L] },
  ],
};
const robust = set(robustRaw);

/** Top level needs 2 of 3 groups; every group needs all 3 members. */
const lowToleranceRaw = {
  threshold_percent: 50,
  inner: [
    { threshold_percent: 100, validators: [A, B, C] },
    { threshold_percent: 100, validators: [D, E, F] },
    { threshold_percent: 100, validators: [G, H, I] },
  ],
};

describe('quorumSatisfied', () => {
  it('requires a nested slice to meet its own threshold', () => {
    expect(quorumSatisfied(vulnerable, new Set([A, B]))).toBe(true);
    expect(quorumSatisfied(vulnerable, new Set([A]))).toBe(false);
  });
});

describe('estimateStallProbability', () => {
  it('is exact for a small member universe', () => {
    const one = estimateStallProbability(simple, { byzantineNodes: 1 });
    expect(one.method).toBe('exact');
    expect(one.probability).toBe(0);
    expect(one.samples).toBe(3);

    const two = estimateStallProbability(simple, { byzantineNodes: 2 });
    expect(two.method).toBe('exact');
    expect(two.probability).toBe(1);
    expect(two.alwaysStalls).toBe(true);
  });

  it('switches to a reproducible Monte Carlo sample above the cap', () => {
    const large = set({
      threshold_percent: 67,
      validators: [A, B, C, D, E, F, G, H, I],
    });
    const first = estimateStallProbability(large, {
      byzantineNodes: 4,
      maxExactCombinations: 10,
      iterations: 500,
      seed: 42,
    });
    const second = estimateStallProbability(large, {
      byzantineNodes: 4,
      maxExactCombinations: 10,
      iterations: 500,
      seed: 42,
    });
    expect(first.method).toBe('monte-carlo');
    expect(first.probability).toBe(second.probability);
    expect(first.probability).toBeGreaterThanOrEqual(0);
    expect(first.probability).toBeLessThanOrEqual(1);
  });
});

describe('analyseByzantineResilience', () => {
  it('reports the safety buffer, fault tolerance, and critical members', () => {
    const result = analyseByzantineResilience(simple);
    expect(result.totalNodes).toBe(3);
    expect(result.safetyBuffer).toBe(2);
    expect(result.faultTolerance).toBe(1);
    expect(result.criticalNodes).toEqual([]);
    expect(result.complete).toBe(true);
  });

  it('finds every member whose removal alone stalls a fragile set', () => {
    expect(findCriticalNodes(vulnerable).sort()).toEqual([A, B].sort());
    const result = analyseByzantineResilience(vulnerable);
    expect(result.faultTolerance).toBe(0);
    expect(result.stallProbability).toBe(1);
  });

  it('accepts a robust three-tier quorum', () => {
    const result = analyseByzantineResilience(robust);
    expect(result.totalNodes).toBe(12);
    expect(result.faultTolerance).toBeGreaterThanOrEqual(result.byzantineBudget);
    expect(result.criticalNodes).toEqual([]);
  });
});

describe('checkByzantineResilience', () => {
  it('passes a robust three-tier quorum', async () => {
    const doc = {
      VALIDATORS: [{ PUBLIC_KEY: A, QUORUM_SET: robustRaw }],
    };
    expect(await checkByzantineResilience(doc, fetch)).toEqual([]);
  });

  it('flags a quorum that one Byzantine node can stall', async () => {
    const doc = {
      VALIDATORS: [{ PUBLIC_KEY: A, QUORUM_SET: vulnerableRaw }],
    };
    const diagnostics = await checkByzantineResilience(doc, fetch);
    const catastrophic = diagnostics.find(
      (diagnostic) => diagnostic.rule === CATASTROPHIC_SINGLE_POINT_OF_FAILURE_RULE,
    );
    expect(catastrophic).toBeDefined();
    expect(catastrophic?.severity).toBe('error');
    expect(catastrophic?.message).toContain('single Byzantine node');
    expect(catastrophic?.path).toBe('VALIDATORS[0].QUORUM_SET');
  });

  it('warns when fault tolerance is below the BFT budget', async () => {
    const doc = {
      VALIDATORS: [{ PUBLIC_KEY: A, QUORUM_SET: lowToleranceRaw }],
    };
    const diagnostics = await checkByzantineResilience(doc, fetch);
    const low = diagnostics.find(
      (diagnostic) => diagnostic.rule === LOW_BYZANTINE_FAULT_TOLERANCE_RULE,
    );
    expect(low).toBeDefined();
    expect(low?.severity).toBe('warning');
    expect(low?.message).toContain('BFT budget');
  });

  it('honours --off', async () => {
    const doc = {
      VALIDATORS: [{ PUBLIC_KEY: A, QUORUM_SET: vulnerableRaw }],
    };
    const diagnostics = await checkByzantineResilience(doc, fetch, {
      rules: { [CATASTROPHIC_SINGLE_POINT_OF_FAILURE_RULE]: 'off' },
    });
    expect(
      diagnostics.every(
        (diagnostic) => diagnostic.rule !== CATASTROPHIC_SINGLE_POINT_OF_FAILURE_RULE,
      ),
    ).toBe(true);
  });

  it('is registered for --list-rules', () => {
    expect(byzantineSimulatorRules.map((rule) => rule.id)).toEqual([
      LOW_BYZANTINE_FAULT_TOLERANCE_RULE,
      CATASTROPHIC_SINGLE_POINT_OF_FAILURE_RULE,
    ]);
  });
});
