/**
 * Validator quorum set simulator and intersection validator — test suite
 * Issue #46: quorum-set-audit
 *
 * Tests the new `src/validators/quorum.ts` module which exposes:
 *   - simulateBft            pure BFT calculation for one quorum set
 *   - simulateQuorumBft      full document scan returning BftResult[]
 *   - auditQuorumSets        diagnostic emitter (fragile-quorum-set + intersection-failure)
 *   - formatQuorumSummaryTable  CLI table formatter
 *   - quorumAuditRules / quorumAuditRuleIds  rule registry
 *
 * Scenarios covered
 * ─────────────────
 * A. 3 nodes, threshold 2-of-3 (67%)  → BFT=1, intersection safe, no diagnostics
 * B. 3 nodes, threshold 3-of-3 (100%) → BFT=0 (fragile-quorum-set warning)
 * C. Disjoint 2-node cluster          → quorum-intersection-failure error
 * D. 4 nodes, 2 well-distributed orgs → intersection safe
 * E. CONFIG_URL resolution            → follows linked stellar-core.cfg
 * F. Network / graceful degradation   → silent on missing / unreachable configs
 * G. Rule overrides                   → --off / --warn / --error respected
 * H. formatQuorumSummaryTable         → correct table structure
 * I. Rule registry                    → correct ids and severities
 */

import { describe, expect, it } from 'vitest';
import {
  auditQuorumSets,
  simulateBft,
  simulateQuorumBft,
  formatQuorumSummaryTable,
  quorumAuditRules,
  quorumAuditRuleIds,
  FRAGILE_QUORUM_SET_RULE,
  QUORUM_INTERSECTION_FAILURE_RULE,
} from '../src/validators/quorum.js';
import { normalizeQuorumSet } from '../src/validators/quorum-solver.js';

// ─── Test fixtures ────────────────────────────────────────────────────────────

const A = 'GAOOOWJ2U7AITCNNUQ4LNRRTKOQGBYBSAXRXQHVUNOAQJYMZPM5QJ4EM';
const B = 'GAVLKMYOGHWXNBOQCH5XCGJPMHF7KWBAXRXQHVUNOAQJYMZPM5QB4CDD';
const C = 'GAYB4LTP7HXQDL5QHRVNAP3XPYHPXPGTRKUGNLTNXBKA6LG3ZGGCBSVJ';
const D = 'GDXVG5F6GRT2YIOJPM4ENUYHAXRXQHVUNOAQJYMZPM5QZZZZZ2AB4DDD';

/** Stub that serves a fixed JSON body — kept for future tests. */
function _fetchJson(body: unknown): typeof fetch {
  return (async () =>
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })) as typeof fetch;
}

/** Stub that always throws — used to prove no network call is made. */
function fetchReject(): typeof fetch {
  return (async () => {
    throw new Error('network must not be called');
  }) as unknown as typeof fetch;
}

/** Stub that serves a raw text body (for stellar-core.cfg). */
function fetchText(body: string): typeof fetch {
  return (async () => new Response(body, { status: 200 })) as unknown as typeof fetch;
}

/** Stub that returns HTTP 500. */
function fetchError(): typeof fetch {
  return (async () =>
    new Response('Internal Server Error', { status: 500 })) as unknown as typeof fetch;
}

// ─── A. 3-node 2-of-3 cluster — BFT=1, intersection safe ────────────────────

// threshold_percent: 50 on 3 nodes → ceil(0.5*3)=2 → 2-of-3 → BFT=1
describe('A — 3-node 2-of-3 cluster (threshold 50%)', () => {
  const doc = {
    VALIDATORS: [
      { PUBLIC_KEY: A, QUORUM_SET: { threshold_percent: 50, validators: [A, B, C] } },
      { PUBLIC_KEY: B, QUORUM_SET: { threshold_percent: 50, validators: [A, B, C] } },
      { PUBLIC_KEY: C, QUORUM_SET: { threshold_percent: 50, validators: [A, B, C] } },
    ],
  };

  it('emits zero diagnostics — cluster is safe', async () => {
    const diagnostics = await auditQuorumSets(doc, fetchReject());
    expect(diagnostics).toEqual([]);
  });

  it('computes BFT=1 for every validator', async () => {
    const results = await simulateQuorumBft(doc, fetchReject());
    expect(results).toHaveLength(3);
    for (const r of results) {
      expect(r.bft).toBe(1);
      expect(r.complete).toBe(true);
    }
  });

  it('BFT=1 means one failure can be tolerated without stalling consensus', async () => {
    const results = await simulateQuorumBft(doc, fetchReject());
    expect(results.every((r) => (r.bft ?? 0) >= 1)).toBe(true);
  });
});

// ─── B. 3-node 3-of-3 cluster — BFT=0 (fragile-quorum-set) ─────────────────

describe('B — 3-node 3-of-3 cluster (threshold 100%, BFT=0)', () => {
  const doc = {
    VALIDATORS: [
      { PUBLIC_KEY: A, QUORUM_SET: { threshold_percent: 100, validators: [A, B, C] } },
      { PUBLIC_KEY: B, QUORUM_SET: { threshold_percent: 100, validators: [A, B, C] } },
      { PUBLIC_KEY: C, QUORUM_SET: { threshold_percent: 100, validators: [A, B, C] } },
    ],
  };

  it('reports validators/fragile-quorum-set for every validator', async () => {
    const diagnostics = await auditQuorumSets(doc, fetchReject());
    const fragile = diagnostics.filter((d) => d.rule === FRAGILE_QUORUM_SET_RULE);
    // All three validators have zero BFT
    expect(fragile.length).toBeGreaterThanOrEqual(1);
    expect(fragile[0]?.severity).toBe('warning');
  });

  it('fragile finding path points at the QUORUM_SET', async () => {
    const diagnostics = await auditQuorumSets(doc, fetchReject());
    const fragile = diagnostics.find((d) => d.rule === FRAGILE_QUORUM_SET_RULE);
    expect(fragile?.path).toMatch(/^VALIDATORS\[\d+\]\.QUORUM_SET$/);
  });

  it('fragile finding includes the public key in the message', async () => {
    const diagnostics = await auditQuorumSets(doc, fetchReject());
    const fragile = diagnostics.find((d) => d.rule === FRAGILE_QUORUM_SET_RULE);
    expect(fragile?.message).toContain(A);
  });

  it('simulateBft returns BFT=0 for a 3-of-3 set', () => {
    const set = normalizeQuorumSet({ threshold_percent: 100, validators: [A, B, C] });
    if (set === undefined) throw new Error('fixture failed to parse');
    const result = simulateBft(A, 0, set);
    expect(result.bft).toBe(0);
    expect(result.complete).toBe(true);
  });

  it('does not also fire quorum-intersection-failure (all quorums share all nodes)', async () => {
    const diagnostics = await auditQuorumSets(doc, fetchReject());
    expect(diagnostics.every((d) => d.rule !== QUORUM_INTERSECTION_FAILURE_RULE)).toBe(true);
  });
});

// ─── C. Disjoint 2-node cluster — quorum-intersection-failure ───────────────

describe('C — disjoint 2-node split quorum (fork risk)', () => {
  // A only trusts {A, D}, C only trusts {C, D} — using majority 51%.
  // A's minimal quorums: {A,D}; C's minimal quorums: {C,D}
  // These ARE disjoint — no shared member.
  const doc = {
    VALIDATORS: [
      { PUBLIC_KEY: A, QUORUM_SET: { threshold_percent: 51, validators: [A, B, D] } },
      { PUBLIC_KEY: C, QUORUM_SET: { threshold_percent: 51, validators: [C, D, B] } },
    ],
  };

  it('reports validators/quorum-intersection-failure (error)', async () => {
    const diagnostics = await auditQuorumSets(doc, fetchReject());
    const failure = diagnostics.find((d) => d.rule === QUORUM_INTERSECTION_FAILURE_RULE);
    expect(failure).toBeDefined();
    expect(failure?.severity).toBe('error');
  });

  it('intersection-failure path points at VALIDATORS[0].QUORUM_SET', async () => {
    const diagnostics = await auditQuorumSets(doc, fetchReject());
    const failure = diagnostics.find((d) => d.rule === QUORUM_INTERSECTION_FAILURE_RULE);
    expect(failure?.path).toBe('VALIDATORS[0].QUORUM_SET');
  });

  it('message names both validators involved in the split', async () => {
    const diagnostics = await auditQuorumSets(doc, fetchReject());
    const failure = diagnostics.find((d) => d.rule === QUORUM_INTERSECTION_FAILURE_RULE);
    expect(failure?.message).toContain(A);
    expect(failure?.message).toContain(C);
  });

  it('includes a suggestion to fix the quorum set', async () => {
    const diagnostics = await auditQuorumSets(doc, fetchReject());
    const failure = diagnostics.find((d) => d.rule === QUORUM_INTERSECTION_FAILURE_RULE);
    expect(failure?.suggestion).toBeTruthy();
  });

  it('simulateQuorumBft returns two results with defined minimal quorums', async () => {
    const results = await simulateQuorumBft(doc, fetchReject());
    expect(results).toHaveLength(2);
    expect(results[0]?.minimalQuorums.length).toBeGreaterThan(0);
    expect(results[1]?.minimalQuorums.length).toBeGreaterThan(0);
  });
});

// ─── D. 4-node well-distributed cluster — intersection safe ─────────────────

describe('D — 4-node well-distributed cluster', () => {
  // All four validators declare the same 3-of-4 quorum set.
  const doc = {
    VALIDATORS: [
      { PUBLIC_KEY: A, QUORUM_SET: { threshold_percent: 67, validators: [A, B, C, D] } },
      { PUBLIC_KEY: B, QUORUM_SET: { threshold_percent: 67, validators: [A, B, C, D] } },
      { PUBLIC_KEY: C, QUORUM_SET: { threshold_percent: 67, validators: [A, B, C, D] } },
      { PUBLIC_KEY: D, QUORUM_SET: { threshold_percent: 67, validators: [A, B, C, D] } },
    ],
  };

  it('emits zero diagnostics', async () => {
    const diagnostics = await auditQuorumSets(doc, fetchReject());
    expect(diagnostics).toEqual([]);
  });

  it('BFT is at least 1 for all validators', async () => {
    const results = await simulateQuorumBft(doc, fetchReject());
    expect(results).toHaveLength(4);
    for (const r of results) {
      expect(r.bft).toBeGreaterThanOrEqual(1);
    }
  });
});

// ─── E. CONFIG_URL resolution ────────────────────────────────────────────────

describe('E — CONFIG_URL stellar-core.cfg resolution', () => {
  const safeCfg = `
[QUORUM_SET]
THRESHOLD_PERCENT = 50
VALIDATORS = ["${A}", "${B}", "${C}"]
`;

  it('loads the quorum set from the linked config and passes a safe cluster', async () => {
    const doc = {
      VALIDATORS: [
        { PUBLIC_KEY: A, CONFIG_URL: 'https://a.example/stellar-core.cfg' },
        { PUBLIC_KEY: B, CONFIG_URL: 'https://b.example/stellar-core.cfg' },
        { PUBLIC_KEY: C, CONFIG_URL: 'https://c.example/stellar-core.cfg' },
      ],
    };
    const diagnostics = await auditQuorumSets(doc, fetchText(safeCfg));
    expect(diagnostics).toEqual([]);
  });

  it('loads the quorum set from the linked config and detects a disjoint cluster', async () => {
    const splitCfgA = `
[QUORUM_SET]
THRESHOLD_PERCENT = 51
VALIDATORS = ["${A}", "${B}"]
`;
    const splitCfgC = `
[QUORUM_SET]
THRESHOLD_PERCENT = 51
VALIDATORS = ["${C}", "${D}"]
`;
    const urls: string[] = [];
    const fetchImpl = (async (input: Parameters<typeof fetch>[0]) => {
      const url = String(input);
      urls.push(url);
      const body = url.includes('/a.') ? splitCfgA : splitCfgC;
      return new Response(body, { status: 200 });
    }) as typeof fetch;

    const doc = {
      VALIDATORS: [
        { PUBLIC_KEY: A, CONFIG_URL: 'https://a.example/stellar-core.cfg' },
        { PUBLIC_KEY: C, CONFIG_URL: 'https://c.example/stellar-core.cfg' },
      ],
    };
    const diagnostics = await auditQuorumSets(doc, fetchImpl);
    expect(urls).toHaveLength(2);
    expect(diagnostics.some((d) => d.rule === QUORUM_INTERSECTION_FAILURE_RULE)).toBe(true);
  });
});

// ─── F. Graceful degradation ─────────────────────────────────────────────────

describe('F — graceful degradation (no diagnostics on missing data)', () => {
  it('returns empty when document has fewer than 2 validators', async () => {
    const doc = {
      VALIDATORS: [{ PUBLIC_KEY: A, QUORUM_SET: { threshold_percent: 67, validators: [A, B, C] } }],
    };
    expect(await auditQuorumSets(doc, fetchReject())).toEqual([]);
  });

  it('returns empty when no validator has a declared quorum set', async () => {
    const doc = {
      VALIDATORS: [{ PUBLIC_KEY: A }, { PUBLIC_KEY: B }],
    };
    expect(await auditQuorumSets(doc, fetchReject())).toEqual([]);
  });

  it('returns empty when VALIDATORS is absent', async () => {
    expect(await auditQuorumSets({}, fetchReject())).toEqual([]);
  });

  it('returns empty when CONFIG_URL fetch returns HTTP 500', async () => {
    const doc = {
      VALIDATORS: [
        { PUBLIC_KEY: A, CONFIG_URL: 'https://a.example/stellar-core.cfg' },
        { PUBLIC_KEY: B, CONFIG_URL: 'https://b.example/stellar-core.cfg' },
      ],
    };
    expect(await auditQuorumSets(doc, fetchError())).toEqual([]);
  });

  it('returns empty when CONFIG_URL fetch throws', async () => {
    const doc = {
      VALIDATORS: [
        { PUBLIC_KEY: A, CONFIG_URL: 'https://a.example/stellar-core.cfg' },
        { PUBLIC_KEY: B, CONFIG_URL: 'https://b.example/stellar-core.cfg' },
      ],
    };
    expect(await auditQuorumSets(doc, fetchReject())).toEqual([]);
  });

  it('skips validators without PUBLIC_KEY without throwing', async () => {
    const doc = {
      VALIDATORS: [
        { QUORUM_SET: { threshold_percent: 67, validators: [A, B, C] } }, // no PUBLIC_KEY
        { PUBLIC_KEY: B, QUORUM_SET: { threshold_percent: 67, validators: [A, B, C] } },
      ],
    };
    // Only 1 valid result — fewer than 2, so silent
    expect(await auditQuorumSets(doc, fetchReject())).toEqual([]);
  });

  it('simulateQuorumBft returns empty results for no quorum sets', async () => {
    const results = await simulateQuorumBft(
      { VALIDATORS: [{ PUBLIC_KEY: A }, { PUBLIC_KEY: B }] },
      fetchReject(),
    );
    expect(results).toEqual([]);
  });
});

// ─── G. Rule overrides ────────────────────────────────────────────────────────

describe('G — rule overrides (--off / --warn / --error)', () => {
  const fragileDoc = {
    VALIDATORS: [
      { PUBLIC_KEY: A, QUORUM_SET: { threshold_percent: 100, validators: [A, B, C] } },
      { PUBLIC_KEY: B, QUORUM_SET: { threshold_percent: 100, validators: [A, B, C] } },
      { PUBLIC_KEY: C, QUORUM_SET: { threshold_percent: 100, validators: [A, B, C] } },
    ],
  };

  it('--off fragile-quorum-set silences the warning', async () => {
    const diagnostics = await auditQuorumSets(fragileDoc, fetchReject(), {
      rules: { [FRAGILE_QUORUM_SET_RULE]: 'off' },
    });
    expect(diagnostics.filter((d) => d.rule === FRAGILE_QUORUM_SET_RULE)).toHaveLength(0);
  });

  it('--error fragile-quorum-set promotes the warning to error', async () => {
    const diagnostics = await auditQuorumSets(fragileDoc, fetchReject(), {
      rules: { [FRAGILE_QUORUM_SET_RULE]: 'error' },
    });
    const findings = diagnostics.filter((d) => d.rule === FRAGILE_QUORUM_SET_RULE);
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) expect(f.severity).toBe('error');
  });

  const disjointDoc = {
    VALIDATORS: [
      { PUBLIC_KEY: A, QUORUM_SET: { threshold_percent: 51, validators: [A, B, D] } },
      { PUBLIC_KEY: C, QUORUM_SET: { threshold_percent: 51, validators: [C, D, B] } },
    ],
  };

  it('--off quorum-intersection-failure silences the error', async () => {
    const diagnostics = await auditQuorumSets(disjointDoc, fetchReject(), {
      rules: { [QUORUM_INTERSECTION_FAILURE_RULE]: 'off' },
    });
    expect(diagnostics.filter((d) => d.rule === QUORUM_INTERSECTION_FAILURE_RULE)).toHaveLength(0);
  });

  it('--warn quorum-intersection-failure demotes the error to warning', async () => {
    const diagnostics = await auditQuorumSets(disjointDoc, fetchReject(), {
      rules: { [QUORUM_INTERSECTION_FAILURE_RULE]: 'warning' },
    });
    const findings = diagnostics.filter((d) => d.rule === QUORUM_INTERSECTION_FAILURE_RULE);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]?.severity).toBe('warning');
  });
});

// ─── H. formatQuorumSummaryTable ─────────────────────────────────────────────

describe('H — formatQuorumSummaryTable', () => {
  it('contains the validator count', async () => {
    const doc = {
      VALIDATORS: [
        { PUBLIC_KEY: A, QUORUM_SET: { threshold_percent: 67, validators: [A, B, C] } },
        { PUBLIC_KEY: B, QUORUM_SET: { threshold_percent: 67, validators: [A, B, C] } },
        { PUBLIC_KEY: C, QUORUM_SET: { threshold_percent: 67, validators: [A, B, C] } },
      ],
    };
    const results = await simulateQuorumBft(doc, fetchReject());
    const table = formatQuorumSummaryTable(results, true);
    expect(table).toContain('3 validators');
    expect(table).toContain('SAFE');
  });

  it('marks UNSAFE when intersection fails', async () => {
    const doc = {
      VALIDATORS: [
        { PUBLIC_KEY: A, QUORUM_SET: { threshold_percent: 51, validators: [A, B, D] } },
        { PUBLIC_KEY: C, QUORUM_SET: { threshold_percent: 51, validators: [C, D, B] } },
      ],
    };
    const results = await simulateQuorumBft(doc, fetchReject());
    const table = formatQuorumSummaryTable(results, false);
    expect(table).toContain('UNSAFE');
  });

  it('marks BFT=0 with a warning indicator', async () => {
    const doc = {
      VALIDATORS: [
        { PUBLIC_KEY: A, QUORUM_SET: { threshold_percent: 100, validators: [A, B, C] } },
        { PUBLIC_KEY: B, QUORUM_SET: { threshold_percent: 100, validators: [A, B, C] } },
        { PUBLIC_KEY: C, QUORUM_SET: { threshold_percent: 100, validators: [A, B, C] } },
      ],
    };
    const results = await simulateQuorumBft(doc, fetchReject());
    const table = formatQuorumSummaryTable(results, true);
    expect(table).toContain('0 ⚠');
  });

  it('returns a no-validators message for empty results', () => {
    const table = formatQuorumSummaryTable([], true);
    expect(table).toContain('no validators');
  });
});

// ─── I. simulateBft unit tests ───────────────────────────────────────────────

describe('I — simulateBft unit', () => {
  it('2-of-3 gives BFT=1', () => {
    // threshold_percent: 50 on 3 nodes → ceil(0.5*3)=2 → 2-of-3
    const set = normalizeQuorumSet({ threshold_percent: 50, validators: [A, B, C] });
    if (!set) throw new Error('fixture failed');
    const result = simulateBft(A, 0, set);
    expect(result.bft).toBe(1);
    expect(result.publicKey).toBe(A);
    expect(result.path).toBe('VALIDATORS[0].QUORUM_SET');
    expect(result.complete).toBe(true);
    expect(result.minimalQuorums.length).toBeGreaterThan(0);
  });

  it('1-of-1 gives BFT=0', () => {
    const set = normalizeQuorumSet({ threshold_percent: 100, validators: [A] });
    if (!set) throw new Error('fixture failed');
    const result = simulateBft(A, 2, set);
    expect(result.bft).toBe(0);
    expect(result.path).toBe('VALIDATORS[2].QUORUM_SET');
  });

  it('3-of-3 gives BFT=0 (no tolerance)', () => {
    const set = normalizeQuorumSet({ threshold_percent: 100, validators: [A, B, C] });
    if (!set) throw new Error('fixture failed');
    expect(simulateBft(A, 0, set).bft).toBe(0);
  });

  it('3-of-4 gives BFT=1', () => {
    const set = normalizeQuorumSet({ threshold_percent: 67, validators: [A, B, C, D] });
    if (!set) throw new Error('fixture failed');
    expect(simulateBft(A, 0, set).bft).toBe(1);
  });
});

// ─── J. Rule registry ────────────────────────────────────────────────────────

describe('J — rule registry', () => {
  it('quorumAuditRuleIds contains the fragile-quorum-set rule', () => {
    expect(quorumAuditRuleIds).toContain(FRAGILE_QUORUM_SET_RULE);
  });

  it('QUORUM_INTERSECTION_FAILURE_RULE is the correct id string', () => {
    expect(QUORUM_INTERSECTION_FAILURE_RULE).toBe('validators/quorum-intersection-failure');
  });

  it('quorumAuditRules has correct default severity for fragile-quorum-set', () => {
    const rule = quorumAuditRules.find((r) => r.id === FRAGILE_QUORUM_SET_RULE);
    expect(rule?.severity).toBe('warning');
  });

  it('every rule belongs to the validators category', () => {
    for (const rule of quorumAuditRules) {
      expect(rule.category).toBe('validators');
    }
  });

  it('FRAGILE_QUORUM_SET_RULE has the correct id string', () => {
    expect(FRAGILE_QUORUM_SET_RULE).toBe('validators/fragile-quorum-set');
  });
});

// ─── K. CLI integration — auditQuorumSets wired into --audit-quorum ──────────

describe('K — CLI integration wiring', () => {
  // These tests exercise the same functions the CLI calls so the integration
  // path is covered without spawning a child process.

  it('auditQuorumSets produces fragile-quorum-set when called with a zero-BFT doc', async () => {
    const doc = {
      VALIDATORS: [
        { PUBLIC_KEY: A, QUORUM_SET: { threshold_percent: 100, validators: [A, B, C] } },
        { PUBLIC_KEY: B, QUORUM_SET: { threshold_percent: 100, validators: [A, B, C] } },
        { PUBLIC_KEY: C, QUORUM_SET: { threshold_percent: 100, validators: [A, B, C] } },
      ],
    };
    const diagnostics = await auditQuorumSets(doc, fetchReject());
    expect(diagnostics.some((d) => d.rule === FRAGILE_QUORUM_SET_RULE)).toBe(true);
  });

  it('auditQuorumSets produces quorum-intersection-failure for a split-quorum doc', async () => {
    const doc = {
      VALIDATORS: [
        { PUBLIC_KEY: A, QUORUM_SET: { threshold_percent: 51, validators: [A, B, D] } },
        { PUBLIC_KEY: C, QUORUM_SET: { threshold_percent: 51, validators: [C, D, B] } },
      ],
    };
    const diagnostics = await auditQuorumSets(doc, fetchReject());
    expect(diagnostics.some((d) => d.rule === QUORUM_INTERSECTION_FAILURE_RULE)).toBe(true);
  });

  it('formatQuorumSummaryTable output contains the header and separator lines', async () => {
    const doc = {
      VALIDATORS: [
        { PUBLIC_KEY: A, QUORUM_SET: { threshold_percent: 50, validators: [A, B, C] } },
        { PUBLIC_KEY: B, QUORUM_SET: { threshold_percent: 50, validators: [A, B, C] } },
      ],
    };
    const results = await simulateQuorumBft(doc, fetchReject());
    const table = formatQuorumSummaryTable(results, true);

    // Header line with count
    expect(table).toContain('2 validators');
    // Separator line
    expect(table).toContain('─');
    // Intersection result
    expect(table).toContain('SAFE');
    // Each validator key appears (abbreviated form)
    expect(table).toContain('GAOO');
    expect(table).toContain('GAVL');
  });

  it('formatQuorumSummaryTable shows UNSAFE for a disjoint cluster', async () => {
    const doc = {
      VALIDATORS: [
        { PUBLIC_KEY: A, QUORUM_SET: { threshold_percent: 51, validators: [A, B, D] } },
        { PUBLIC_KEY: C, QUORUM_SET: { threshold_percent: 51, validators: [C, D, B] } },
      ],
    };
    const results = await simulateQuorumBft(doc, fetchReject());
    const intersectionSafe = !(await auditQuorumSets(doc, fetchReject())).some(
      (d) => d.rule === QUORUM_INTERSECTION_FAILURE_RULE,
    );
    const table = formatQuorumSummaryTable(results, intersectionSafe);
    expect(table).toContain('UNSAFE');
    expect(table).toContain('fork risk');
  });

  it('auditQuorumSets returns empty for a document with no VALIDATORS', async () => {
    expect(await auditQuorumSets({}, fetchReject())).toEqual([]);
  });

  it('simulateQuorumBft and auditQuorumSets are consistent — safe cluster has no diagnostics', async () => {
    const doc = {
      VALIDATORS: [
        { PUBLIC_KEY: A, QUORUM_SET: { threshold_percent: 50, validators: [A, B, C] } },
        { PUBLIC_KEY: B, QUORUM_SET: { threshold_percent: 50, validators: [A, B, C] } },
        { PUBLIC_KEY: C, QUORUM_SET: { threshold_percent: 50, validators: [A, B, C] } },
      ],
    };
    const bftResults = await simulateQuorumBft(doc, fetchReject());
    const diagnostics = await auditQuorumSets(doc, fetchReject());

    // Safe cluster: BFT=1 for all, no diagnostics
    expect(bftResults.every((r) => (r.bft ?? 0) >= 1)).toBe(true);
    expect(diagnostics).toEqual([]);

    // Table reflects the safe state
    const intersectionSafe = !diagnostics.some((d) => d.rule === QUORUM_INTERSECTION_FAILURE_RULE);
    const table = formatQuorumSummaryTable(bftResults, intersectionSafe);
    expect(table).toContain('SAFE');
  });
});
