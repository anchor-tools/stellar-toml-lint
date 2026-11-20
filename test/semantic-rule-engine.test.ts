import { describe, expect, it } from 'vitest';
import { parse as parseToml } from 'smol-toml';

import {
  KNOWN_CATEGORIES,
  PluginRuleError,
  SemanticRuleEngine,
  assertSemanticRule,
  isCurrencyNode,
  ruleProblems,
} from '../src/engine/semanticRuleEngine.js';
import type {
  AstNode,
  AstVisitor,
  PluginContext,
  SemanticRule,
} from '../src/engine/semanticRuleEngine.js';
import { lint } from '../src/lint.js';
import { allRules } from '../src/rules/index.js';

/** A document shaped like a served `stellar.toml`, minus the noise. */
const doc = (): Record<string, unknown> => ({
  NETWORK_PASSPHRASE: 'Public Global Stellar Network ; September 2015',
  FUNCTIONS: ['TRANSFER'],
  UPDATED_AT: new Date('2026-01-01T00:00:00.000Z'),
  DOCUMENTATION: { ORG_URL: 'https://example.org' },
  CURRENCIES: [
    { code: 'USDC', issuer: 'GAHK7EEG', contract: 'CCW67TSZ', status: 'live' },
    { code: 'USD', issuer: 'GDHU6WRG' },
  ],
});

const source = 'NETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"\n';

/** One rule with the metadata every rule needs and the visitor a test cares about. */
function ruleWith(
  make: (ctx: PluginContext) => AstVisitor,
  meta: Partial<SemanticRule> = {},
): SemanticRule {
  return {
    id: 'acme/test',
    category: 'general',
    severity: 'warning',
    description: 'a rule the engine tests use',
    create: make,
    ...meta,
  };
}

/** A rule that reports `message` once, when it reaches the document root. */
const reporter = (message: string, meta: Partial<SemanticRule> = {}): SemanticRule =>
  ruleWith((ctx) => ({ visitDocument: () => ctx.report({ message }) }), meta);

/**
 * The eight hooks, each recording `<phase> <kind> <path>` as it fires, so an
 * ordering test reads off the array rather than off a mock's call list.
 */
function tracker(events: string[]): AstVisitor {
  const say =
    (phase: 'enter' | 'leave', kind: string) =>
    (node: AstNode): void => {
      events.push(`${phase} ${kind} ${node.path}`);
    };
  return {
    visitDocument: say('enter', 'document'),
    visitTable: say('enter', 'table'),
    visitCurrency: say('enter', 'currency'),
    visitKeyValue: say('enter', 'key-value'),
    leaveKeyValue: say('leave', 'key-value'),
    leaveCurrency: say('leave', 'currency'),
    leaveTable: say('leave', 'table'),
    leaveDocument: say('leave', 'document'),
  };
}

const run = (rules: Iterable<SemanticRule>, input = {}): ReturnType<SemanticRuleEngine['run']> =>
  new SemanticRuleEngine(rules).run({ doc: doc(), source, ...input });

describe('the traversal', () => {
  it('offers every node once and brackets each table around its keys', () => {
    const events: string[] = [];
    run([ruleWith(() => tracker(events))]);

    expect(events).toEqual([
      'enter document ',
      'enter key-value NETWORK_PASSPHRASE',
      'leave key-value NETWORK_PASSPHRASE',
      'enter key-value FUNCTIONS',
      'leave key-value FUNCTIONS',
      'enter key-value UPDATED_AT',
      'leave key-value UPDATED_AT',
      'enter table DOCUMENTATION',
      'enter key-value DOCUMENTATION.ORG_URL',
      'leave key-value DOCUMENTATION.ORG_URL',
      'leave table DOCUMENTATION',
      'enter table CURRENCIES[0]',
      'enter currency CURRENCIES[0]',
      'enter key-value CURRENCIES[0].code',
      'leave key-value CURRENCIES[0].code',
      'enter key-value CURRENCIES[0].issuer',
      'leave key-value CURRENCIES[0].issuer',
      'enter key-value CURRENCIES[0].contract',
      'leave key-value CURRENCIES[0].contract',
      'enter key-value CURRENCIES[0].status',
      'leave key-value CURRENCIES[0].status',
      'leave currency CURRENCIES[0]',
      'leave table CURRENCIES[0]',
      'enter table CURRENCIES[1]',
      'enter currency CURRENCIES[1]',
      'enter key-value CURRENCIES[1].code',
      'leave key-value CURRENCIES[1].code',
      'enter key-value CURRENCIES[1].issuer',
      'leave key-value CURRENCIES[1].issuer',
      'leave currency CURRENCIES[1]',
      'leave table CURRENCIES[1]',
      'leave document ',
    ]);
  });

  it('hands the same node object to the enter and the leave hook', () => {
    const seen: AstNode[] = [];
    run(
      [
        ruleWith(() => ({
          visitTable: (node) => void seen.push(node),
          leaveTable: (node) => void seen.push(node),
        })),
      ],
      { doc: { DOCUMENTATION: { ORG_URL: 'https://example.org' } }, source },
    );

    expect(seen).toHaveLength(2);
    expect(seen[0]).toBe(seen[1]);
  });

  it('shares one traversal between every rule', () => {
    // The hundred-and-first rule must not add a hundredth walk: both rules see
    // the same node before either sees the next one.
    const order: string[] = [];
    const mark = (id: string): SemanticRule =>
      ruleWith(
        () => ({
          visitDocument: () => order.push(`enter ${id}`),
          leaveDocument: () => order.push(`leave ${id}`),
        }),
        { id },
      );

    run([mark('acme/one'), mark('acme/two')], { doc: {}, source });

    expect(order).toEqual(['enter acme/one', 'enter acme/two', 'leave acme/one', 'leave acme/two']);
  });

  it('pairs each rule with its own currency hook instead of grouping by kind', () => {
    // The walk dispatches off a list per node kind, which is what makes a rule
    // that ignores tables cost nothing on one. A currency is both kinds at once,
    // so this pins the one thing that could quietly go wrong: every rule's table
    // hook has to fire immediately before its own currency hook, so findings come
    // out in load order rather than all the table findings first.
    const order: string[] = [];
    const mark = (id: string): SemanticRule =>
      ruleWith(
        () => ({
          visitTable: () => order.push(`enter table ${id}`),
          visitCurrency: () => order.push(`enter currency ${id}`),
          leaveCurrency: () => order.push(`leave currency ${id}`),
          leaveTable: () => order.push(`leave table ${id}`),
        }),
        { id },
      );

    run([mark('acme/one'), mark('acme/two')], { doc: { CURRENCIES: [{ code: 'USDC' }] }, source });

    expect(order).toEqual([
      'enter table acme/one',
      'enter currency acme/one',
      'enter table acme/two',
      'enter currency acme/two',
      'leave currency acme/one',
      'leave table acme/one',
      'leave currency acme/two',
      'leave table acme/two',
    ]);
  });

  it('visits each node once per rule, so the cost is rules × nodes and not walks', () => {
    // The benchmark's < 10 ms claim rests on this: a hundred rules share one walk,
    // so a hundred rules cost a hundred calls per node rather than a hundred
    // traversals of the document.
    const visits = (rules: SemanticRule[]): number => {
      let calls = 0;
      run(
        rules.map((rule) => ({
          ...rule,
          create: (ctx: PluginContext): AstVisitor => {
            const visitor = rule.create(ctx);
            return {
              ...visitor,
              visitKeyValue: (node): void => {
                calls += 1;
                visitor.visitKeyValue?.(node);
              },
            };
          },
        })),
      );
      return calls;
    };

    const keyCounter = (): AstVisitor => ({ visitKeyValue: () => {} });
    const one = visits([ruleWith(keyCounter)]);
    const hundred = visits(
      Array.from({ length: 100 }, (_unused, index) =>
        ruleWith(keyCounter, { id: `bench/rule-${index}` }),
      ),
    );

    expect(one).toBeGreaterThan(0);
    expect(hundred).toBe(one * 100);
  });

  it('gives a currency to the table hooks too, since it is an array-table entry', () => {
    const events: string[] = [];
    run([ruleWith(() => tracker(events))], {
      doc: { CURRENCIES: [{ code: 'USD' }] },
      source,
    });

    expect(events.filter((event) => !event.includes('key-value'))).toEqual([
      'enter document ',
      'enter table CURRENCIES[0]',
      'enter currency CURRENCIES[0]',
      'leave currency CURRENCIES[0]',
      'leave table CURRENCIES[0]',
      'leave document ',
    ]);
  });

  it('reads a currency identity off the node instead of off the values map', () => {
    let currency: AstNode | undefined;
    run([
      ruleWith(() => ({
        visitCurrency: (node) => {
          currency ??= node;
        },
      })),
    ]);

    expect(isCurrencyNode(currency!)).toBe(true);
    expect(currency).toMatchObject({
      kind: 'currency',
      path: 'CURRENCIES[0]',
      name: 'CURRENCIES',
      index: 0,
      code: 'USDC',
      issuer: 'GAHK7EEG',
      contract: 'CCW67TSZ',
      status: 'live',
    });
  });

  it('treats a list of strings as one value, not a table per element', () => {
    const seen: string[] = [];
    run(
      [
        ruleWith(() => ({
          visitKeyValue: (node) => seen.push(`value ${node.path}`),
          visitTable: (node) => seen.push(`table ${node.path}`),
        })),
      ],
      { doc: { ACCOUNTS: ['GABC', 'GDEF'], FUNCTIONS: [] }, source },
    );

    expect(seen).toEqual(['value ACCOUNTS', 'value FUNCTIONS']);
  });

  it('never walks a date as if it were a table', () => {
    // `smol-toml` returns a `Date` subclass for a date-time and `typeof` calls
    // that an object. Offered as a table it has no keys, so a rule written
    // against `UPDATED_AT` would pass on the file it was written to check.
    const seen: string[] = [];
    run(
      [
        ruleWith(() => ({
          visitKeyValue: (node) =>
            seen.push(`${node.path} is a Date: ${node.value instanceof Date}`),
          visitTable: (node) => seen.push(`${node.path} is a table`),
        })),
      ],
      { doc: parseToml('UPDATED_AT = 2026-01-01T00:00:00Z\n'), source },
    );

    expect(seen).toEqual(['UPDATED_AT is a Date: true']);
  });

  it('walks an inline table as a table and repeated tables by index', () => {
    const seen: string[] = [];
    run([ruleWith(() => ({ visitTable: (node) => seen.push(`${node.kind} ${node.path}`) }))], {
      doc: { FEES: { send: 1 }, VALIDATORS: [{ name: 'a' }, { name: 'b' }] },
      source,
    });

    expect(seen).toEqual(['table FEES', 'array-table VALIDATORS[0]', 'array-table VALIDATORS[1]']);
  });

  it('refuses to descend into a document that contains itself', () => {
    // Parsed TOML cannot do this; a caller building `doc` by hand can, and the
    // engine is public API. The cycle is cut at the table that reopens it, so the
    // rule keeps everything around it and the run still finishes.
    const cyclic: Record<string, unknown> = {
      NAME: 'x',
      DOCUMENTATION: { ORG_URL: 'https://e.org' },
    };
    cyclic.SELF = cyclic;
    const seen: string[] = [];

    expect(() =>
      run(
        [
          ruleWith(() => ({
            visitTable: (node) => seen.push(node.path),
            visitKeyValue: (node) => seen.push(node.path),
          })),
        ],
        { doc: cyclic, source },
      ),
    ).not.toThrow();
    expect(seen).toEqual(['NAME', 'DOCUMENTATION', 'DOCUMENTATION.ORG_URL']);
  });

  it('still visits two sibling tables that share one values object', () => {
    const shared = { code: 'USDC' };
    const seen: string[] = [];
    run([ruleWith(() => ({ visitCurrency: (node) => seen.push(node.path) }))], {
      doc: { CURRENCIES: [shared, shared] },
      source,
    });

    expect(seen).toEqual(['CURRENCIES[0]', 'CURRENCIES[1]']);
  });

  it('sees a key the built-in catalog has no rule for', () => {
    // Pluggability is the point: an anchor's own vocabulary has to reach a rule.
    const seen: unknown[] = [];
    run([ruleWith(() => ({ visitKeyValue: (node) => seen.push([node.path, node.value]) }))], {
      doc: { ACME_SETTLEMENT_WINDOW_HOURS: 4 },
      source,
    });

    expect(seen).toEqual([['ACME_SETTLEMENT_WINDOW_HOURS', 4]]);
  });
});

describe('findings', () => {
  it('stamps the rule id and category onto what the plugin reported', () => {
    const findings = run([
      ruleWith(
        (ctx) => ({
          visitCurrency: (node) =>
            ctx.report({ message: `${node.code} has no attestation`, path: node.path }),
        }),
        { id: 'acme/attestation', category: 'currencies', severity: 'error' },
      ),
    ]);

    expect(findings).toHaveLength(2);
    expect(findings[0]).toEqual({
      rule: 'acme/attestation',
      category: 'currencies',
      severity: 'error',
      message: 'USDC has no attestation',
      path: 'CURRENCIES[0]',
    });
  });

  it('uses the rule severity, then a per-finding severity, then the user override', () => {
    const both = ruleWith(
      (ctx) => ({
        visitDocument: () => ctx.report({ message: 'plain' }),
        leaveDocument: () => ctx.report({ message: 'asked for info', severity: 'info' }),
      }),
      { severity: 'error' },
    );

    expect(run([both], { doc: {}, source }).map((f) => f.severity)).toEqual(['error', 'info']);
    expect(
      run([both], { doc: {}, source, rules: { 'acme/test': 'warning' } }).map((f) => f.severity),
    ).toEqual(['warning', 'warning']);
  });

  it('never builds a visitor for a rule the user switched off', () => {
    let created = 0;
    const findings = run(
      [
        ruleWith(() => {
          created += 1;
          return {};
        }),
      ],
      { rules: { 'acme/test': 'off' } },
    );

    expect(created).toBe(0);
    expect(findings).toEqual([]);
  });

  it('refuses a finding with no message instead of filing an empty one', () => {
    const findings = run(
      [ruleWith((ctx) => ({ visitDocument: () => ctx.report({ message: '' }) }))],
      { doc: {}, source },
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      rule: 'internal/plugin-error',
      message: expect.stringContaining('non-empty message'),
    });
  });

  it('gives the plugin the run options, source and document', () => {
    let seen: PluginContext | undefined;
    run([ruleWith((ctx) => ((seen = ctx), {}))], {
      options: { domain: 'example.org', strict: true },
    });

    expect(seen).toBeDefined();
    expect(seen?.doc).toBe(seen?.ast.values);
    expect(seen?.source).toBe(source);
    expect(seen?.options).toMatchObject({ domain: 'example.org', strict: true });
    expect(seen?.ast).toMatchObject({ kind: 'document', path: '', name: '' });
    expect(seen?.locate('DOCUMENTATION.ORG_URL')).toBeUndefined();
  });

  it('locates a node through the index the caller supplies', () => {
    const positions: (string | undefined)[] = [];
    run(
      [
        ruleWith(() => ({
          visitTable: (node) => positions.push(node.position && `line ${node.position.line}`),
        })),
      ],
      {
        doc: { DOCUMENTATION: { ORG_URL: 'https://example.org' } },
        // The shape `SourceIndex.get` has, without importing it: the engine only
        // undertakes to pass the node's path through.
        locate: (path: string) => (path === 'DOCUMENTATION' ? { line: 12, column: 1 } : undefined),
      },
    );

    expect(positions).toEqual(['line 12']);
  });

  it('leaves the position off a node it cannot place', () => {
    const findings = run(
      [
        ruleWith(() => ({
          visitTable: (node) => {
            if (Object.hasOwn(node, 'position')) throw new Error('a position was invented');
          },
        })),
      ],
      { doc: { DOCUMENTATION: {} }, source },
    );

    expect(findings).toEqual([]);
  });
});

describe('fault isolation', () => {
  const boom = (): never => {
    throw new Error('cannot read properties of undefined');
  };

  it('keeps every other rule running when one throws', () => {
    const findings = run([
      ruleWith(() => ({ visitCurrency: boom }), { id: 'acme/boom' }),
      reporter('still here', { id: 'acme/fine' }),
    ]);

    expect(findings.map((f) => f.rule)).toEqual(['acme/fine', 'internal/plugin-error']);
    expect(findings[1]).toMatchObject({
      severity: 'warning',
      category: 'file',
      message: 'Plugin rule acme/boom failed on 2 nodes: cannot read properties of undefined',
      helpUri: 'https://github.com/anchor-tools/stellar-toml-lint/issues',
      suggestion: 'Report this to the plugin author; the rest of the run is unaffected.',
    });
  });

  it('collapses one rule failing on many nodes into a single finding', () => {
    // Two currencies and ten keys, reported once: a buggy plugin stays visible
    // without burying the file it broke on.
    const findings = run([ruleWith(() => ({ visitCurrency: boom, visitKeyValue: boom }))]);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.message).toBe(
      'Plugin rule acme/test failed on 12 nodes: cannot read properties of undefined',
    );
  });

  it('says "node" for a single failure', () => {
    const findings = run([
      ruleWith(() => ({
        visitDocument: () => {
          throw new Error('once only');
        },
      })),
    ]);

    expect(findings[0]?.message).toBe('Plugin rule acme/test failed on 1 node: once only');
  });

  it('reports a rule that throws something that is not an Error', () => {
    const findings = run([
      ruleWith(() => ({
        visitDocument: () => {
          throw 'policy file missing';
        },
      })),
    ]);

    expect(findings[0]?.message).toBe(
      'Plugin rule acme/test failed on 1 node: policy file missing',
    );
  });

  it('contains a rule that throws out of create', () => {
    const findings = run([
      ruleWith(() => {
        throw new TypeError('policy file missing');
      }),
      reporter('from the other rule', { id: 'acme/fine' }),
    ]);

    expect(findings.map((f) => f.rule)).toEqual(['acme/fine', 'internal/plugin-error']);
    expect(findings[1]?.message).toContain('policy file missing');
  });

  it('reports a visitor that is not an object instead of crashing', () => {
    const findings = run([
      ruleWith(() => undefined as unknown as AstVisitor, { id: 'acme/nothing' }),
      ruleWith(() => 7 as unknown as AstVisitor, { id: 'acme/a-number' }),
    ]);

    expect(findings).toHaveLength(2);
    for (const finding of findings) {
      expect(finding.message).toContain('create() must return a visitor object');
    }
  });

  it('keeps descending when a leave hook throws', () => {
    const seen: string[] = [];
    const findings = run(
      [
        ruleWith(() => ({
          leaveDocument: () => {
            throw new Error('left too late');
          },
          visitKeyValue: (node) => seen.push(node.path),
        })),
      ],
      { doc: { A: 1 }, source },
    );

    expect(seen).toEqual(['A']);
    expect(findings[0]?.message).toContain('left too late');
  });

  it('files what a rule reported before it threw', () => {
    const findings = run(
      [
        ruleWith((ctx) => ({
          visitDocument: () => {
            ctx.report({ message: 'one' });
            throw new Error('and then it threw');
          },
        })),
        reporter('two', { id: 'acme/two' }),
      ],
      { doc: {}, source },
    );

    expect(findings.map((f) => f.message)).toEqual([
      'one',
      'two',
      'Plugin rule acme/test failed on 1 node: and then it threw',
    ]);
  });
});

describe('registration', () => {
  it('lists the ids in the order their hooks run', () => {
    const engine = new SemanticRuleEngine([
      ruleWith(() => ({}), { id: 'acme/second' }),
      ruleWith(() => ({}), { id: 'acme/first' }),
    ]);

    expect(engine.ruleIds).toEqual(['acme/second', 'acme/first']);
    expect(engine.size).toBe(2);
  });

  it('runs nothing when it holds no rules', () => {
    expect(new SemanticRuleEngine().size).toBe(0);
    expect(new SemanticRuleEngine().run({ doc: doc(), source })).toEqual([]);
  });

  it('refuses a second rule with the same id', () => {
    const engine = new SemanticRuleEngine([ruleWith(() => ({}))]);

    expect(() => engine.addRule(ruleWith(() => ({})))).toThrow(/already uses this id/);
    expect(engine.size).toBe(1);
  });

  it('returns itself from addRule so rules chain', () => {
    const engine = new SemanticRuleEngine();

    expect(
      engine.addRule(ruleWith(() => ({}))).addRule(ruleWith(() => ({}), { id: 'b/c' })).size,
    ).toBe(2);
  });

  it('names a rule that has no id by the value it was handed', () => {
    expect(() => new SemanticRuleEngine().addRule('a string' as unknown as SemanticRule)).toThrow(
      'rule a string is not a usable rule',
    );
  });
});

describe('rule shape', () => {
  const good: SemanticRule = {
    id: 'acme/needs-attestation',
    category: 'currencies',
    severity: 'error',
    description: 'every asset names an attestation',
    create: () => ({}),
  };

  it('accepts a well-formed rule', () => {
    expect(ruleProblems(good)).toEqual([]);
    expect(assertSemanticRule(good, '--plugin acme.js')).toBe(good);
  });

  it('names what is wrong with each kind of bad rule', () => {
    const cases: [string, unknown, string][] = [
      ['a string', 'nope', 'a rule must be an object'],
      ['null', null, 'a rule must be an object'],
      ['no id', { ...good, id: undefined }, '`id` must be a string'],
      ['an id with no namespace', { ...good, id: 'attestation' }, 'must be "<namespace>/<name>"'],
      ['an id with capitals', { ...good, id: 'ACME/Test' }, 'must be "<namespace>/<name>"'],
      ['an unknown category', { ...good, category: 'finance' }, '`category` must be one of'],
      ['the wrong severity token', { ...good, severity: 'warn' }, '`severity` must be one of'],
      ['a blank description', { ...good, description: '  ' }, '`description` must be a non-empty'],
      ['no create', { ...good, create: undefined }, '`create` must be a function'],
      ['create is a value', { ...good, create: 42 }, '`create` must be a function'],
    ];

    for (const [what, candidate, expected] of cases) {
      expect(ruleProblems(candidate), what).toEqual([expect.stringContaining(expected)]);
    }
  });

  it('reports every problem at once so an author fixes the file in one pass', () => {
    const problems = ruleProblems({ id: 'oops', category: 'x', severity: 'y' });

    expect(problems).toHaveLength(5);
    expect(problems.join('\n')).toContain('got "oops"');
  });

  it('throws a PluginRuleError that says where the rule came from', () => {
    let error: unknown;
    try {
      assertSemanticRule({ id: 'oops' }, '--rules-dir rules');
    } catch (caught) {
      error = caught;
    }

    expect(error).toBeInstanceOf(PluginRuleError);
    const failure = error as PluginRuleError;
    expect(failure.origin).toBe('--rules-dir rules');
    expect(failure.name).toBe('PluginRuleError');
    expect(failure.problems.length).toBeGreaterThan(1);
    expect(failure.message).toContain('--rules-dir rules is not a usable rule:');
  });

  it('knows every category the built-in catalog files findings under', () => {
    // The union in `types.ts` is what the reporters group by, so a plugin that
    // picks a category outside it produces a finding no reporter can place.
    for (const rule of allRules) {
      expect(KNOWN_CATEGORIES, rule.id).toContain(rule.category);
    }
  });
});

describe('plugin rules through lint()', () => {
  const file = [
    'NETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"',
    '',
    '[[CURRENCIES]]',
    'code = "USDC"',
    'issuer = "GAHK7EEG"',
    '',
    '[[CURRENCIES]]',
    'code = "USD"',
    '',
  ].join('\n');

  const contractRule: SemanticRule = {
    id: 'acme/contract-or-issuer',
    category: 'currencies',
    severity: 'warning',
    description: 'an asset names an issuer or a Soroban contract',
    create: (ctx) => ({
      visitCurrency: (node) => {
        if (node.issuer === undefined && node.contract === undefined) {
          ctx.report({
            message: `${node.code} has neither issuer nor contract`,
            path: node.path,
            position: node.position,
          });
        }
      },
    }),
  };

  const finding = (rules: SemanticRule[], overrides = {}): ReturnType<typeof lint> =>
    lint(file, { semanticRules: rules, rules: overrides });

  it('runs a plugin over the parsed file without disturbing the catalog', () => {
    const without = lint(file);
    const withPlugin = finding([contractRule]);

    expect(withPlugin.diagnostics.length).toBe(without.diagnostics.length + 1);
    expect(withPlugin.diagnostics.filter((d) => d.rule === 'acme/contract-or-issuer')).toEqual([
      {
        rule: 'acme/contract-or-issuer',
        severity: 'warning',
        category: 'currencies',
        message: 'USD has neither issuer nor contract',
        path: 'CURRENCIES[1]',
        position: { line: 7, column: 1 },
      },
    ]);
  });

  it('points at the second currency header, not the first', () => {
    // If `SourceIndex` handed back its fallback for `CURRENCIES[1]` the finding
    // would sit on the block above the one it is about.
    const positions = finding([contractRule]).diagnostics.map((d) => d.position?.line);

    expect(positions).toContain(7);
    expect(positions.filter((line) => line === 3)).toHaveLength(
      lint(file).diagnostics.filter((d) => d.position?.line === 3).length,
    );
  });

  it('honours --off, --error and --warn for a plugin id', () => {
    const id = 'acme/contract-or-issuer';
    const off = finding([contractRule], { [id]: 'off' });

    expect(off.diagnostics.some((d) => d.rule === id)).toBe(false);
    expect(finding([contractRule], { [id]: 'error' }).counts.error).toBe(
      lint(file).counts.error + 1,
    );
    expect(finding([contractRule], { [id]: 'warning' }).counts.warning).toBe(
      lint(file).counts.warning + 1,
    );
  });

  it('turns a plugin warning into a failure under --strict', () => {
    const [onlyPlugin] = [
      lint('VERSION = "1.0.0"\n', { semanticRules: [reporter('a plugin spoke up')] }),
    ];

    expect(onlyPlugin?.counts.warning).toBe(lint('VERSION = "1.0.0"\n').counts.warning + 1);
    expect(
      lint('VERSION = "1.0.0"\n', { semanticRules: [reporter('a plugin spoke up')], strict: true })
        .ok,
    ).toBe(false);
  });

  it('leaves a run without plugins exactly as it was', () => {
    expect(lint(file)).toEqual(lint(file, { semanticRules: [] }));
  });

  it('files a plugin crash as a warning beside a built-in crash', () => {
    const result = finding([
      ruleWith(() => ({
        visitKeyValue: () => {
          throw new Error('plugin fell over');
        },
      })),
    ]);

    expect(result.diagnostics.some((d) => d.rule === 'internal/rule-error')).toBe(
      lint(file).diagnostics.some((d) => d.rule === 'internal/rule-error'),
    );
    expect(result.diagnostics.some((d) => d.rule === 'internal/plugin-error')).toBe(true);
  });
});
