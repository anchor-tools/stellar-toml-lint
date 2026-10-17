import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  REDOS_INVALID_RULE_ID,
  REDOS_RULE_ID,
  analyzeRegex,
  auditRegexSources,
  auditSourceRegexes,
  extractRegexLiterals,
  isRegexSafe,
  redosDetectorRules,
} from '../../src/rules/redos-detector.js';
import { allRules, ruleIds } from '../../src/rules/index.js';
import { lint } from '../../src/lint.js';
import {
  auditPolicyRegexes,
  collectRegexMatchers,
  evaluatePolicy,
  validatePolicy,
  type Policy,
} from '../../src/policy/engine.js';

const here = dirname(fileURLToPath(import.meta.url));
const srcDir = join(here, '..', '..', 'src');

/* ------------------------------------------------------------------ *
 * Detection
 * ------------------------------------------------------------------ */

describe('analyzeRegex on vulnerable patterns', () => {
  const EXPONENTIAL = [
    // The canonical example from the issue.
    '(a+)+$',
    '^(a+)+$',
    '(a*)*',
    '(\\d+)*',
    '([a-zA-Z]+)*$',
    // Alternation branches that can both claim the same character.
    '(a|a)*',
    '(a|ab)+',
    '(\\s|\\s\\s)+$',
    // A repeated group whose body can hand a character to the next iteration.
    '^(\\w+\\s?)*$',
    '(x+x+)+y',
    '^([a-z]+[a-z0-9]*)+!$',
  ];

  const POLYNOMIAL = [
    '\\s*\\s*$',
    '(\\s*\\s*)$',
    '.*.*=',
    '^[a-z]+[a-z0-9]+!',
    // Bounded outer repetition of an ambiguous body: O(n^10), not O(2^n).
    '(.*a){10}',
  ];

  it.each(EXPONENTIAL)('flags /%s/ as exponential', (pattern) => {
    const report = analyzeRegex(pattern);
    expect(report.safe).toBe(false);
    expect(report.worstComplexity).toBe('exponential');
    expect(report.findings.length).toBeGreaterThan(0);
  });

  it.each(POLYNOMIAL)('flags /%s/ as polynomial', (pattern) => {
    const report = analyzeRegex(pattern);
    expect(report.safe).toBe(false);
    expect(report.worstComplexity).toBe('polynomial');
  });

  it('points at the offending fragment rather than the whole pattern', () => {
    const report = analyzeRegex('^VERSION=(a+)+$');
    expect(report.findings[0]?.fragment).toBe('(a+)+');
    expect(report.findings[0]?.index).toBe(9);
  });

  it('names the structure and explains why it backtracks', () => {
    const finding = analyzeRegex('(a+)+$').findings[0];
    expect(finding?.kind).toBe('nested-quantifier');
    expect(finding?.detail).toContain('quantifier');
  });

  it('classifies an overlapping alternation separately from a nested quantifier', () => {
    expect(analyzeRegex('(a|ab)+').findings[0]?.kind).toBe('quantified-overlapping-alternation');
    expect(analyzeRegex('(a+)+').findings[0]?.kind).toBe('nested-quantifier');
    expect(analyzeRegex('\\s*\\s*$').findings[0]?.kind).toBe('adjacent-quantifiers');
  });

  it('ranks exponential findings ahead of polynomial ones', () => {
    // `(x+x+)+y` trips both; the exponential one is what has to be fixed.
    const report = analyzeRegex('(x+x+)+y');
    expect(report.findings.length).toBeGreaterThan(1);
    expect(report.findings[0]?.complexity).toBe('exponential');
    expect(report.worstComplexity).toBe('exponential');
  });

  it('supplies a witness string that actually triggers the blow-up', () => {
    const finding = analyzeRegex('^(a+)+$').findings[0];
    expect(finding?.witness.length).toBeGreaterThan(10);
    // The witness must make the overall match *fail* — a succeeding match
    // never backtracks, so a witness that matches would prove nothing.
    expect(new RegExp('^(a+)$').test(finding?.witness ?? '')).toBe(false);
  });
});

describe('analyzeRegex on safe patterns', () => {
  const SAFE = [
    // Shapes this linter's own rules use.
    '^G[A-Z2-7]{55}$',
    '^C[A-Z2-7]{55}$',
    '^https://[^/]+$',
    '^[A-Z0-9]{1,12}$',
    '^@?[A-Za-z0-9_]{1,15}$',
    '^[^\\s@]+@[^\\s@.]+(\\.[^\\s@.]+)+$',
    '^[a-z][a-z0-9]*(?:[_-][a-z0-9]+)*$',
    '^[+-]?(0|[1-9](_?[0-9])*)$',
    '\\d{4}-\\d{2}-\\d{2}',
    // Adjacent quantifiers over disjoint sets: the boundary is forced.
    'a+b+',
    '^[^@]+@[^@]+\\.[^@]+$',
    '(?:\\.[a-z0-9]+)*$',
    // Non-overlapping alternation under a quantifier.
    '(?:a|b)+',
    '^(TESTNET|PUBLIC)$',
    // A trailing quantifier pair with nothing after it cannot be forced to
    // backtrack, however much its character sets overlap.
    '\\d+[^\\s]*',
    '^\\s*#',
    'colou?r',
  ];

  it.each(SAFE)('accepts /%s/', (pattern) => {
    const report = analyzeRegex(pattern);
    expect(report.findings).toEqual([]);
    expect(report.safe).toBe(true);
    expect(report.worstComplexity).toBe('linear');
  });

  it('distinguishes a forced partition from an ambiguous one', () => {
    // Each iteration of `_?[0-9]` consumes exactly one digit, so the engine
    // has no choice to make. `\w+\s?` lets one iteration give a `\w` back.
    expect(isRegexSafe('(_?[0-9])*')).toBe(true);
    expect(isRegexSafe('(\\w+\\s?)*')).toBe(false);
  });

  it('does not treat a mandatory separator as backtrackable', () => {
    expect(isRegexSafe('(?:[_-][a-z0-9]+)*')).toBe(true);
    expect(isRegexSafe('(?:[a-z][a-z0-9]+)*')).toBe(false);
  });

  it('treats a bounded repetition of a fixed-width body as linear', () => {
    expect(isRegexSafe('[A-Z]{55}')).toBe(true);
    expect(isRegexSafe('(?:[A-Z]{2}){10}')).toBe(true);
  });
});

describe('analyzeRegex parsing', () => {
  it('reports a pattern that will not compile instead of guessing', () => {
    const report = analyzeRegex('(unclosed');
    expect(report.safe).toBe(false);
    expect(report.parseError).toBeDefined();
    expect(report.findings).toEqual([]);
  });

  it('rejects an invalid flag string', () => {
    expect(analyzeRegex('^a$', 'q').parseError).toBeDefined();
  });

  it('never throws, whatever it is handed', () => {
    for (const pattern of ['', '[', ')', '\\', '*', '(?<', '{2,1}', 'a{', '[z-a]', '(?#x)']) {
      expect(() => analyzeRegex(pattern)).not.toThrow();
    }
  });

  it('handles lookaround, named groups, and backreferences', () => {
    expect(isRegexSafe('(?=.*[a-z])(?!.*\\s)^\\S{8,64}$')).toBe(true);
    expect(isRegexSafe('(?<code>[A-Z]{1,12}):\\k<code>')).toBe(true);
    // Lookaround is zero-width but its contents are still analysed.
    expect(analyzeRegex('^(?=(a+)+$)\\w+$').safe).toBe(false);
  });

  it('does not claim to detect ambiguity driven through a lookahead capture', () => {
    // A documented limitation. `(?:(?=(a+))a)+` backtracks via the captured
    // group, which needs the engine's capture semantics modelled rather than
    // the pattern's shape. The detector treats lookaround as zero-width, so it
    // reports nothing here — a miss, not a false negative it hides: the
    // structural checks above still cover the shapes a hand-written matcher
    // realistically takes.
    expect(analyzeRegex('(?:(?=(a+))a)+$').safe).toBe(true);
  });

  it('reads every quantifier spelling', () => {
    expect(isRegexSafe('(a+)*')).toBe(false);
    expect(isRegexSafe('(a*)+')).toBe(false);
    expect(isRegexSafe('(a+){2,}')).toBe(false);
    expect(isRegexSafe('(a+){2}')).toBe(false);
    // One iteration cannot be ambiguous with itself.
    expect(isRegexSafe('(a+){1}')).toBe(true);
    expect(isRegexSafe('(a+)?')).toBe(true);
  });

  it('treats a lazy quantifier as no safer than a greedy one', () => {
    // Laziness changes which order the engine tries, not how many ways exist.
    expect(isRegexSafe('(a+?)+?$')).toBe(false);
  });
});

/* ------------------------------------------------------------------ *
 * Empirical confirmation
 * ------------------------------------------------------------------ */

describe('the detector agrees with the engine it is protecting', () => {
  /** Milliseconds `pattern` takes to refuse `input`. */
  function timeRefusal(pattern: string, input: string): number {
    const regex = new RegExp(pattern);
    const start = process.hrtime.bigint();
    regex.test(input);
    return Number(process.hrtime.bigint() - start) / 1e6;
  }

  it('flags a pattern that really does hang, and clears its rewrite', () => {
    // 24 `a`s then a `b`: 2^24 partitions to exhaust before refusing, which
    // is most of a second on a cold engine. Larger exponents make the point
    // better and cost seconds each, so this is the smallest input that puts
    // three orders of magnitude between the two patterns.
    const input = `${'a'.repeat(24)}b`;

    expect(analyzeRegex('^(a+)+$').safe).toBe(false);
    expect(timeRefusal('^(a+)+$', input)).toBeGreaterThan(50);

    // The rewrite the suggestion asks for, on the same input.
    expect(analyzeRegex('^a+$').safe).toBe(true);
    expect(timeRefusal('^a+$', input)).toBeLessThan(20);
  }, 30_000);

  it('clears the real matchers this linter applies to hostile values', () => {
    // A 50 KB value is well within what a `stellar.toml` can carry, and these
    // are the patterns a document's own strings reach.
    const hostile = 'a'.repeat(50_000);
    for (const pattern of ['^G[A-Z2-7]{55}$', '^https?://[^/]+/?$', '^[^\\s@]+@[^\\s@.]+$']) {
      expect(analyzeRegex(pattern).safe).toBe(true);
      expect(timeRefusal(pattern, hostile)).toBeLessThan(50);
    }
  });
});

/* ------------------------------------------------------------------ *
 * Diagnostics and the lint rule
 * ------------------------------------------------------------------ */

describe('auditRegexSources', () => {
  it('emits security/redos-vulnerable-regex at error for a dangerous matcher', () => {
    const [diagnostic] = auditRegexSources([
      { pattern: '(a+)+$', path: 'rules[0].match.regex', origin: 'policy "acme"' },
    ]);

    expect(diagnostic?.rule).toBe(REDOS_RULE_ID);
    expect(diagnostic?.severity).toBe('error');
    expect(diagnostic?.category).toBe('policy');
    expect(diagnostic?.path).toBe('rules[0].match.regex');
    expect(diagnostic?.message).toContain('policy "acme"');
    expect(diagnostic?.message).toContain('exponential');
    expect(diagnostic?.suggestion).toBeTruthy();
  });

  it('emits security/invalid-regex for a pattern that will not compile', () => {
    const [diagnostic] = auditRegexSources([{ pattern: '(unclosed' }]);
    expect(diagnostic?.rule).toBe(REDOS_INVALID_RULE_ID);
  });

  it('says nothing about safe matchers', () => {
    expect(auditRegexSources([{ pattern: '^[A-Z]{1,12}$' }, { pattern: 'a+b+' }])).toEqual([]);
  });

  it('honours a caller-chosen severity', () => {
    const [diagnostic] = auditRegexSources([{ pattern: '(a+)+$' }], 'warning');
    expect(diagnostic?.severity).toBe('warning');
  });
});

describe('the redos lint rules', () => {
  const MINIMAL = 'VERSION = "2.0.0"\n';

  it('are registered and listed like every other rule', () => {
    expect(ruleIds).toContain(REDOS_RULE_ID);
    expect(ruleIds).toContain(REDOS_INVALID_RULE_ID);
    expect(allRules.filter((rule) => rule.id === REDOS_RULE_ID)).toHaveLength(1);
    expect(redosDetectorRules.every((rule) => rule.category === 'policy')).toBe(true);
    expect(redosDetectorRules.every((rule) => rule.severity === 'error')).toBe(true);
    expect(redosDetectorRules.every((rule) => rule.description.length > 0)).toBe(true);
  });

  it('report a configured matcher through the ordinary diagnostic pipeline', () => {
    const result = lint(MINIMAL, {
      customRegexes: [{ pattern: '(a+)+$', path: 'rules[0].match.regex' }],
    });

    const finding = result.diagnostics.find((d) => d.rule === REDOS_RULE_ID);
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('error');
    expect(result.ok).toBe(false);
  });

  it('stay silent on a run that configures no matchers', () => {
    const result = lint(MINIMAL);
    expect(result.diagnostics.some((d) => d.rule === REDOS_RULE_ID)).toBe(false);
    expect(result.diagnostics.some((d) => d.rule === REDOS_INVALID_RULE_ID)).toBe(false);
  });

  it('stay silent when every configured matcher is safe', () => {
    const result = lint(MINIMAL, {
      customRegexes: [{ pattern: '^[A-Z]{1,12}$' }, { pattern: '^G[A-Z2-7]{55}$' }],
    });
    expect(result.diagnostics.some((d) => d.rule.startsWith('security/redos'))).toBe(false);
  });

  it('can be silenced per id, so an invalid pattern and a dangerous one differ', () => {
    const result = lint(MINIMAL, {
      customRegexes: [{ pattern: '(a+)+$' }, { pattern: '(unclosed' }],
      rules: { [REDOS_INVALID_RULE_ID]: 'off' },
    });

    expect(result.diagnostics.some((d) => d.rule === REDOS_RULE_ID)).toBe(true);
    expect(result.diagnostics.some((d) => d.rule === REDOS_INVALID_RULE_ID)).toBe(false);
  });
});

/* ------------------------------------------------------------------ *
 * Policy engine wiring
 * ------------------------------------------------------------------ */

describe('policy engine regex matchers', () => {
  function policyWith(regex: string): Policy {
    return {
      version: '1.0',
      name: 'acme-compliance',
      rules: [
        {
          id: 'org-name-shape',
          description: 'ORG_NAME must look like a registered company name',
          severity: 'error',
          match: { jsonPath: '$.DOCUMENTATION.ORG_NAME', regex },
          message: 'ORG_NAME does not match the required shape',
        },
      ],
    };
  }

  const doc = { DOCUMENTATION: { ORG_NAME: 'Acme Anchor Ltd' } };

  it('collects every matcher with the path that reaches it', () => {
    const policy: Policy = {
      version: '1.0',
      name: 'nested',
      rules: [
        {
          id: 'r0',
          description: 'd',
          severity: 'error',
          match: {
            allOf: [{ regex: '^a$' }, { not: { regex: '^b$' } }],
            anyOf: [{ regex: '^c$' }],
          },
          message: 'm',
        },
      ],
    };

    expect(collectRegexMatchers(policy).map((m) => m.path)).toEqual([
      'rules[0].match.allOf[0].regex',
      'rules[0].match.allOf[1].not.regex',
      'rules[0].match.anyOf[0].regex',
    ]);
    expect(collectRegexMatchers(policy)[0]?.origin).toBe('policy "nested"');
  });

  it('applies a safe matcher to the selected value', () => {
    const matched = evaluatePolicy(policyWith('^Acme'), doc, '');
    expect(matched.map((d) => d.rule)).toEqual(['org-name-shape']);

    const unmatched = evaluatePolicy(policyWith('^Globex'), doc, '');
    expect(unmatched).toEqual([]);
  });

  it('fails policy validation on a dangerous matcher', () => {
    const validation = validatePolicy(policyWith('(a+)+$'));
    expect(validation.valid).toBe(false);
    expect(validation.errors.join('\n')).toContain('rules[0].match.regex');
    expect(validation.errors.join('\n')).toContain('exponential');
  });

  it('accepts a policy whose matchers are all safe', () => {
    expect(validatePolicy(policyWith('^[A-Za-z0-9 .,-]{2,64}$')).valid).toBe(true);
  });

  it('refuses to evaluate a dangerous matcher and reports it in the rule’s place', () => {
    // Defence in depth: a programmatic caller that skipped validatePolicy must
    // still not get its thread frozen.
    const diagnostics = evaluatePolicy(policyWith('(a+)+$'), doc, '');

    expect(diagnostics.map((d) => d.rule)).toEqual([REDOS_RULE_ID]);
    expect(diagnostics[0]?.policyId).toBe('acme-compliance');
    expect(diagnostics.some((d) => d.rule === 'org-name-shape')).toBe(false);
  });

  it('keeps the other rules of a policy working when one matcher is refused', () => {
    const policy: Policy = {
      version: '1.0',
      name: 'mixed',
      rules: [
        {
          id: 'dangerous',
          description: 'd',
          severity: 'error',
          match: { jsonPath: '$.DOCUMENTATION.ORG_NAME', regex: '(a+)+$' },
          message: 'm',
        },
        {
          id: 'fine',
          description: 'd',
          severity: 'warning',
          match: { jsonPath: '$.DOCUMENTATION.ORG_NAME', regex: '^Acme' },
          message: 'm',
        },
      ],
    };

    const ids = evaluatePolicy(policy, doc, '').map((d) => d.rule);
    expect(ids).toContain(REDOS_RULE_ID);
    expect(ids).toContain('fine');
    expect(ids).not.toContain('dangerous');
  });

  it('audits a policy without evaluating it', () => {
    expect(auditPolicyRegexes(policyWith('^Acme'))).toEqual([]);
    expect(auditPolicyRegexes(policyWith('(a+)+$')).map((d) => d.rule)).toEqual([REDOS_RULE_ID]);
  });

  it('drops the global flag so a matcher answers the same for every node', () => {
    // `test` advances lastIndex with /g, which would make the second
    // CURRENCIES entry disagree with the first for no reason. The path uses
    // `.*.` rather than `[*]`: the engine's own JSONPath subset only expands a
    // wildcard that stands as its own segment.
    const policy: Policy = {
      version: '1.0',
      name: 'global-flag',
      rules: [
        {
          id: 'code-shape',
          description: 'd',
          severity: 'error',
          match: { jsonPath: '$.CURRENCIES.*.code', regex: '^[A-Z]+$', regexFlags: 'g' },
          message: 'm',
        },
      ],
    };

    const diagnostics = evaluatePolicy(
      policy,
      { CURRENCIES: [{ code: 'USD' }, { code: 'EUR' }] },
      '',
    );
    expect(diagnostics).toHaveLength(2);
  });

  it('matches nothing rather than throwing when the node is not a string', () => {
    const policy: Policy = {
      version: '1.0',
      name: 'non-string',
      rules: [
        {
          id: 'shape',
          description: 'd',
          severity: 'error',
          match: { jsonPath: '$.DOCUMENTATION', regex: '^Acme' },
          message: 'm',
        },
      ],
    };
    expect(evaluatePolicy(policy, doc, '')).toEqual([]);
  });
});

/* ------------------------------------------------------------------ *
 * Rule test harness
 * ------------------------------------------------------------------ */

describe('regex literal extraction', () => {
  it('finds literals and records their line', () => {
    const source = ['const a = /^[A-Z]+$/;', '', 'const b = /\\d{1,3}/gi;'].join('\n');
    expect(extractRegexLiterals(source)).toEqual([
      { pattern: '^[A-Z]+$', flags: '', line: 1 },
      { pattern: '\\d{1,3}', flags: 'gi', line: 3 },
    ]);
  });

  it('does not mistake division for a literal', () => {
    const source = 'const ratio = total / count / 2;\nconst pct = a / b;';
    expect(extractRegexLiterals(source)).toEqual([]);
  });

  it('ignores patterns written inside strings, templates, and comments', () => {
    const source = [
      "const s = '/(a+)+$/';",
      'const t = `/(a+)+$/`;',
      '// const c = /(a+)+$/;',
      '/* const d = /(a+)+$/; */',
    ].join('\n');
    expect(extractRegexLiterals(source)).toEqual([]);
  });

  it('reads a slash inside a character class as part of the pattern', () => {
    expect(extractRegexLiterals('const re = /^[/a-z]+$/;')).toEqual([
      { pattern: '^[/a-z]+$', flags: '', line: 1 },
    ]);
  });

  it('finds a literal after return and in a call argument', () => {
    const source = ['function f() {', '  return /^a+$/.test(x);', '}', 'g(/^b+$/, 1);'].join('\n');
    expect(extractRegexLiterals(source).map((l) => l.pattern)).toEqual(['^a+$', '^b+$']);
  });

  it('flags a vulnerable literal with the line it is on', () => {
    const source = ['const ok = /^a+$/;', 'const bad = /(a+)+$/;'].join('\n');
    const problems = auditSourceRegexes(source, 'example.ts');
    expect(problems).toHaveLength(1);
    expect(problems[0]?.line).toBe(2);
    expect(problems[0]?.finding.complexity).toBe('exponential');
  });
});

describe('every built-in rule regex is free of catastrophic backtracking', () => {
  /** Every `.ts` file under `src/`, recursively. */
  function sources(dir: string): string[] {
    return readdirSync(dir).flatMap((name) => {
      const path = join(dir, name);
      if (statSync(path).isDirectory()) return sources(path);
      return path.endsWith('.ts') ? [path] : [];
    });
  }

  const files = sources(srcDir);

  it('scans a meaningful number of literals, so a silent no-op cannot pass', () => {
    const total = files.reduce(
      (sum, file) => sum + extractRegexLiterals(readFileSync(file, 'utf8')).length,
      0,
    );
    expect(total).toBeGreaterThan(200);
  });

  it('finds no vulnerable pattern anywhere in src/', () => {
    // This is the harness half of issue #380: a URL or key matcher added to a
    // rule next year cannot introduce quadratic backtracking unnoticed, because
    // this test fails on the commit that adds it.
    const problems = files.flatMap((file) => {
      const label = relative(srcDir, file);
      return auditSourceRegexes(readFileSync(file, 'utf8'), label).map(
        (problem) =>
          `${label}:${problem.line} /${problem.finding.fragment}/ ` +
          `(${problem.finding.complexity}: ${problem.finding.kind})`,
      );
    });

    expect(problems).toEqual([]);
  });
});
