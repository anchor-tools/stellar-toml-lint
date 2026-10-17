import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  DEFAULT_BUDGET_MS,
  DEFAULT_TOLERANCE,
  NOISE_FLOOR_MS,
  RULE_ALLOWANCES,
  SYNTHETIC_NODES,
  auditRegexes,
  judge,
  loadBaseline,
  syntheticDocument,
  writeBaseline,
  type Baseline,
  type Measurement,
  type RuleTiming,
} from '../../benchmarks/regression-harness.js';
import { lint } from '../../src/lint.js';
import { allRules } from '../../src/rules/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..', '..');

/** A timing with the boilerplate filled in. */
function timing(rule: string, meanMs: number, units = meanMs * 10): RuleTiming {
  return { rule, meanMs, units, rmeFraction: 0.01, samples: 200, diagnostics: 0 };
}

/** A measurement with a calibration of 0.1ms, so units are meanMs * 10. */
function measurement(timings: RuleTiming[]): Measurement {
  return { timings, calibrationMs: 0.1 };
}

/** A baseline recording the given rules at the given unit costs. */
function baselineOf(rules: Record<string, number>): Baseline {
  return {
    version: 2,
    recordedAt: '2026-01-01T00:00:00.000Z',
    node: 'v22.0.0',
    nodes: SYNTHETIC_NODES,
    calibrationMs: 0.1,
    rules: Object.fromEntries(
      Object.entries(rules).map(([rule, units]) => [rule, { units, rmeFraction: 0.01 }]),
    ),
  };
}

describe('the synthetic document', () => {
  const source = syntheticDocument(5);

  it('parses and lints, so the rules benchmark real work', () => {
    const result = lint(source);
    // A document that failed to parse would short-circuit `lint`, and every
    // rule would benchmark as instant while doing nothing.
    expect(result.parsed).toBeDefined();
    expect(result.diagnostics.some((d) => d.rule.startsWith('file/'))).toBe(false);
  });

  it('produces the requested number of each repeated table', () => {
    const result = lint(source);
    const doc = result.parsed as Record<string, unknown>;
    expect((doc.CURRENCIES as unknown[]).length).toBe(5);
    expect((doc.VALIDATORS as unknown[]).length).toBe(5);
    expect((doc.PRINCIPALS as unknown[]).length).toBe(5);
  });

  it('defaults to the 1,000 nodes the regression suite measures', () => {
    expect(SYNTHETIC_NODES).toBe(1_000);
  });

  it('gives the rules something to find rather than an empty document', () => {
    // If every rule reported nothing, the benchmark would be measuring early
    // returns. At least the shape-checking rules must have data to walk.
    const result = lint(syntheticDocument(20));
    expect(result.diagnostics.length).toBeGreaterThan(0);
  });

  it('scales with the node count', () => {
    expect(syntheticDocument(100).length).toBeGreaterThan(syntheticDocument(10).length * 5);
  });
});

describe('judge: latency budgets', () => {
  it('passes a rule inside the budget', () => {
    const verdicts = judge(measurement([timing('a/b', 0.1)]), undefined);
    expect(verdicts[0]?.overBudget).toBe(false);
    expect(verdicts[0]?.budgetMs).toBe(DEFAULT_BUDGET_MS);
  });

  it('fails a rule over the budget even with no baseline to compare against', () => {
    // The budget is what catches a rule that was slow from its first commit,
    // which a baseline comparison structurally cannot.
    const verdicts = judge(measurement([timing('a/b', 0.9)]), undefined);
    expect(verdicts[0]?.overBudget).toBe(true);
  });

  it('applies the documented allowance to a whole-document walker', () => {
    const rule = 'general/insecure-http-url';
    const allowance = RULE_ALLOWANCES[rule];
    expect(allowance).toBeDefined();

    const verdicts = judge(measurement([timing(rule, 0.9)]), undefined);
    expect(verdicts[0]?.overBudget).toBe(false);
    expect(verdicts[0]?.budgetMs).toBe(allowance?.budgetMs);

    const over = judge(measurement([timing(rule, (allowance?.budgetMs ?? 0) + 1)]), undefined);
    expect(over[0]?.overBudget).toBe(true);
  });

  it('honours a caller-supplied budget', () => {
    const verdicts = judge(measurement([timing('a/b', 0.3)]), undefined, 0.2);
    expect(verdicts[0]?.overBudget).toBe(true);
  });

  it('does not judge a rule that produced no samples', () => {
    const verdicts = judge(measurement([timing('a/b', Number.NaN, Number.NaN)]), undefined);
    expect(verdicts[0]?.overBudget).toBe(false);
    expect(verdicts[0]?.regressed).toBe(false);
  });
});

describe('judge: baseline comparison', () => {
  it('flags a rule that got materially slower', () => {
    // 1.0ms -> 2.0ms is a doubling, far past both the tolerance and the floor.
    const verdicts = judge(measurement([timing('a/b', 2.0)]), baselineOf({ 'a/b': 10 }));
    expect(verdicts[0]?.regressed).toBe(true);
    expect(verdicts[0]?.changeFraction).toBeCloseTo(1.0, 5);
  });

  it('accepts a rule that got faster', () => {
    const verdicts = judge(measurement([timing('a/b', 0.4)]), baselineOf({ 'a/b': 10 }));
    expect(verdicts[0]?.regressed).toBe(false);
    expect(verdicts[0]?.changeFraction).toBeLessThan(0);
  });

  it('accepts a rise inside the tolerance', () => {
    // +10% on a 1ms rule: real movement, under the 20% gate.
    const verdicts = judge(measurement([timing('a/b', 1.1)]), baselineOf({ 'a/b': 10 }));
    expect(verdicts[0]?.regressed).toBe(false);
  });

  it('ignores a large percentage rise that is tiny in absolute terms', () => {
    // 4µs -> 8µs doubles, and is scheduler noise rather than a code change.
    // Without the noise floor this gate would fail builds at random, because
    // most rules live in exactly this range.
    const verdicts = judge(measurement([timing('a/b', 0.008, 0.08)]), baselineOf({ 'a/b': 0.04 }));
    expect(verdicts[0]?.changeFraction).toBeCloseTo(1.0, 5);
    expect(verdicts[0]?.regressed).toBe(false);
  });

  it('flags the same proportional rise once it clears the noise floor', () => {
    const verdicts = judge(measurement([timing('a/b', 0.4)]), baselineOf({ 'a/b': 2 }));
    expect(verdicts[0]?.changeFraction).toBeCloseTo(1.0, 5);
    expect(verdicts[0]?.regressed).toBe(true);
  });

  it('widens the gate by the measurements’ own error bars', () => {
    // A baseline recorded on a noisy runner must not fail every later build.
    const noisy: Baseline = {
      ...baselineOf({ 'a/b': 10 }),
      rules: { 'a/b': { units: 10, rmeFraction: 0.3 } },
    };
    const verdicts = judge(
      { timings: [{ ...timing('a/b', 1.3), rmeFraction: 0.1 }], calibrationMs: 0.1 },
      noisy,
    );
    // +30% against a 20% gate widened by 0.3 + 0.1 of combined uncertainty.
    expect(verdicts[0]?.regressed).toBe(false);
  });

  it('gives a JIT-sensitive walker the looser documented tolerance', () => {
    const rule = 'sep7/invalid-uri-scheme';
    expect(RULE_ALLOWANCES[rule]?.tolerance).toBeGreaterThan(DEFAULT_TOLERANCE);

    // +30%, which these rules show between processes on an idle machine.
    const verdicts = judge(measurement([timing(rule, 1.3)]), baselineOf({ [rule]: 10 }));
    expect(verdicts[0]?.regressed).toBe(false);

    // A doubling still fails.
    const doubled = judge(measurement([timing(rule, 2.0)]), baselineOf({ [rule]: 10 }));
    expect(doubled[0]?.regressed).toBe(true);
  });

  it('marks a rule with no baseline as new rather than regressed', () => {
    const verdicts = judge(measurement([timing('new/rule', 0.1)]), baselineOf({ 'a/b': 10 }));
    expect(verdicts[0]?.isNew).toBe(true);
    expect(verdicts[0]?.regressed).toBe(false);
  });

  it('does not mark rules as new when there is no baseline at all', () => {
    const verdicts = judge(measurement([timing('a/b', 0.1)]), undefined);
    expect(verdicts[0]?.isNew).toBe(false);
  });

  it('compares in calibration units, so a slower machine does not look like a regression', () => {
    // Same work, machine twice as slow: every raw millisecond doubles while
    // the ratio to the calibration workload is unchanged.
    const slow: Measurement = {
      timings: [{ ...timing('a/b', 2.0), units: 10 }],
      calibrationMs: 0.2,
    };
    const verdicts = judge(slow, baselineOf({ 'a/b': 10 }));
    expect(verdicts[0]?.changeFraction).toBeCloseTo(0, 5);
    expect(verdicts[0]?.regressed).toBe(false);
  });
});

describe('baseline file', () => {
  it('round-trips through write and load', () => {
    const path = join(
      process.env.TMPDIR ?? '/tmp',
      `stellar-toml-lint-baseline-${process.pid}.json`,
    );
    const written = writeBaseline(measurement([timing('a/b', 0.25, 2.5)]), 10, path);

    expect(written.version).toBe(2);
    expect(written.nodes).toBe(10);
    expect(written.rules['a/b']?.units).toBeCloseTo(2.5, 4);

    const loaded = loadBaseline(path);
    expect(loaded?.rules['a/b']?.units).toBeCloseTo(2.5, 4);
  });

  it('returns undefined rather than throwing when there is no baseline', () => {
    expect(loadBaseline(join(root, 'does', 'not', 'exist.json'))).toBeUndefined();
  });

  it('rejects a baseline from an older schema instead of misreading it', async () => {
    const path = join(process.env.TMPDIR ?? '/tmp', `stellar-toml-lint-v1-${process.pid}.json`);
    const { writeFileSync } = await import('node:fs');
    writeFileSync(path, JSON.stringify({ version: 1, rules: {} }));
    expect(() => loadBaseline(path)).toThrow(/unsupported version 1/);
  });

  it('is committed, covers every rule, and records its calibration', () => {
    const baseline = loadBaseline();
    expect(baseline).toBeDefined();
    expect(baseline?.calibrationMs).toBeGreaterThan(0);
    expect(baseline?.nodes).toBe(SYNTHETIC_NODES);

    // Every rule present means the suite has nothing silently unmeasured.
    const missing = allRules
      .map((rule) => rule.id)
      .filter((id) => baseline?.rules[id] === undefined);
    expect(missing).toEqual([]);
  });
});

describe('regex backtracking audit', () => {
  it('finds no vulnerable or slow pattern in src/', () => {
    // The same guarantee as test/rules/redos.test.ts, reached the other way:
    // that test checks the *shape* of every pattern, this one also *times* the
    // ones that face a document's own values against adversarial input.
    expect(auditRegexes()).toEqual([]);
  });

  it('is fast enough to run on every invocation', () => {
    const start = performance.now();
    auditRegexes();
    expect(performance.now() - start).toBeLessThan(10_000);
  });
});

describe('the suite is wired into the project', () => {
  const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));

  it('exposes npm run bench:regression', () => {
    expect(pkg.scripts['bench:regression']).toContain('benchmarks/regression-suite.ts');
  });

  it('runs on a devDependency rather than an npx download', () => {
    // `npx tsx` would fetch a runner at CI time; vite-node is already here for
    // the corpus harness.
    expect(pkg.scripts['bench:regression']).toContain('vite-node');
    expect(pkg.devDependencies).toHaveProperty('tinybench');
  });

  it('has a CI workflow that gates pull requests', () => {
    const workflow = readFileSync(join(root, '.github', 'workflows', 'benchmarks.yml'), 'utf8');
    expect(workflow).toContain('pull_request');
    expect(workflow).toContain('bench:regression');
    // The PR comparison must be against a base measured on the same runner.
    expect(workflow).toContain('--update');
    expect(workflow).toContain('schedule');
  });

  it('documents the noise floor it relies on', () => {
    expect(NOISE_FLOOR_MS).toBeGreaterThan(0);
    expect(NOISE_FLOOR_MS).toBeLessThan(DEFAULT_BUDGET_MS);
  });

  it('gives every allowance a reason a reviewer can read', () => {
    for (const [rule, allowance] of Object.entries(RULE_ALLOWANCES)) {
      expect(allRules.some((r) => r.id === rule)).toBe(true);
      expect(allowance.reason.length).toBeGreaterThan(20);
      expect(allowance.budgetMs).toBeGreaterThan(DEFAULT_BUDGET_MS);
    }
  });
});
