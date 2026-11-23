/**
 * The Monaco language bundle: grammar, markers, completions, registration and
 * the worker validator.
 *
 * `monaco-editor` is not a dependency of this package and is not loaded here.
 * The tokenizer assertions therefore run the same algorithm Monaco runs —
 * states, `include`, push/pop, patterns matched implicitly at the caret — over
 * the rule data this bundle publishes, which is the part that can actually be
 * wrong. Behaviour that is Monaco's own (token postfixes, theming) is asserted
 * only as far as this bundle hands it the right numbers.
 */
import { describe, expect, it, vi } from 'vitest';

import { toMonacoMarkers as toPackageMonacoMarkers } from '../packages/monaco/src/index.js';
import {
  createWorkerValidator,
  languageConfiguration,
  monacoLanguageBundle,
  monarchDefinition,
  register,
  toMonacoCompletions,
  toMonacoMarkers,
} from '../src/editor/monacoBundle.js';
import type {
  LintValidator,
  MonarchDefinition,
  MonarchRule,
  MonacoCompletionList,
  MonacoLanguageConfiguration,
  MonacoLanguageRegistration,
  MonacoLanguages,
  MonacoLike,
  MonacoMarker,
  MonacoModel,
  MonacoRegistration,
  WorkerLike,
} from '../src/editor/monacoBundle.js';
import type { Diagnostic, LintResult } from '../src/types.js';

// ── fixtures ─────────────────────────────────────────────────────────────────

/** Base32 has no `0`, `I`, `L` or `U`; the grammar checks shape, not checksum. */
const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function strkey(prefix: 'G' | 'M' | 'C', total: number): string {
  let out = prefix;
  for (let index = 1; index < total; index++) out += BASE32[index % BASE32.length];
  return out;
}

const ACCOUNT = strkey('G', 56);
const SECOND_ACCOUNT = `${strkey('G', 55)}A`;
const CONTRACT = strkey('C', 56);
const MULTIPLEXED = strkey('M', 69);

const SAMPLE = [
  '# SEP-1 stellar.toml',
  'NETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"',
  'TRANSFER_SERVER = "https://example.com/sep6"',
  `ACCOUNTS = [\n  "${ACCOUNT}",\n  "${SECOND_ACCOUNT}"\n]`,
  `SIGNING_KEY = "${ACCOUNT}"`,
  '',
  '[DOCUMENTATION]',
  'ORG_NAME = "Acme Anchoring"',
  'BOGUS_FIELD = 1',
  '',
  '[[CURRENCIES]]',
  'code = "USD"',
  'status = "live"',
  `issuer = "${ACCOUNT}"`,
  '',
  '[[VALIDATORS]]',
  'ALIAS = "acme-1"',
  `PUBLIC_KEY = "${SECOND_ACCOUNT}"`,
  'HISTORY = "http://history.example.com"',
].join('\n');

const DIAGNOSTICS: Diagnostic[] = [
  {
    rule: 'general/trailing-slash-in-endpoint',
    severity: 'error',
    category: 'general',
    message: 'TRANSFER_SERVER must not end with a slash',
    path: 'TRANSFER_SERVER',
    position: { line: 3, column: 20 },
  },
  {
    rule: 'currencies/status-invalid',
    severity: 'warning',
    category: 'currencies',
    message: 'status is not a SEP-1 value',
    path: 'CURRENCIES[0].status',
    position: { line: 13, column: 12 },
  },
  {
    rule: 'documentation/recommended-missing',
    severity: 'info',
    category: 'documentation',
    message: 'ORG_SUPPORT_EMAIL is recommended',
    path: 'DOCUMENTATION.ORG_SUPPORT_EMAIL',
  },
];

const RESULT: LintResult = {
  diagnostics: DIAGNOSTICS,
  ok: false,
  counts: { error: 1, warning: 1, info: 1 },
};

// ── a miniature Monarch tokenizer ────────────────────────────────────────────

interface MonarchToken {
  token: string;
  text: string;
}

interface MonarchLineResult {
  tokens: MonarchToken[];
  stack: string[];
}

interface RuleParts {
  pattern: string;
  action: string;
  next: string | undefined;
}

function ruleParts(rule: MonarchRule): RuleParts {
  if ('include' in rule) throw new Error(`${rule.include} is expanded before matching`);
  const parts = rule as readonly string[];
  return { pattern: parts[0] ?? '', action: parts[1] ?? '', next: parts[2] };
}

/** `{ include: '@name' }` splices the referenced state in, as Monarch does. */
function rulesFor(state: string, seen: ReadonlySet<string> = new Set()): readonly MonarchRule[] {
  const rules = monarchDefinition.tokenizer[state] ?? [];
  const out: MonarchRule[] = [];
  for (const rule of rules) {
    if ('include' in rule) {
      const name = rule.include.replace(/^@/, '');
      if (seen.has(name)) continue;
      out.push(...rulesFor(name, new Set([...seen, name])));
    } else {
      out.push(rule);
    }
  }
  return out;
}

function matchAt(pattern: string, line: string, index: number): string | null {
  // Monarch compiles pattern sources into sticky expressions: a rule only ever
  // matches at the caret, never later in the line.
  const expression = new RegExp(pattern, 'y');
  expression.lastIndex = index;
  return expression.exec(line)?.[0] ?? null;
}

function tokenizeLine(line: string, stack: readonly string[] = ['root']): MonarchLineResult {
  const states = [...stack];
  const tokens: MonarchToken[] = [];
  let index = 0;
  let steps = 0;

  while (index < line.length) {
    if (++steps > 5000) throw new Error(`Monarch tokenizer looped on ${JSON.stringify(line)}`);
    const current = states[states.length - 1] ?? 'root';
    let advanced = false;

    for (const rule of rulesFor(current)) {
      const { pattern, action, next } = ruleParts(rule);
      const text = matchAt(pattern, line, index);
      if (text === null || text === '') continue;
      tokens.push({ token: action, text });
      index += text.length;
      if (next === '@pop') states.pop();
      else if (next !== undefined && next !== '@push') states.push(next.replace(/^@/, ''));
      advanced = true;
      break;
    }

    if (!advanced) {
      tokens.push({ token: monarchDefinition.defaultToken, text: line[index] ?? '' });
      index += 1;
    }
  }

  return { tokens, stack: states };
}

function tokenizeDocument(content: string): MonarchLineResult[] {
  const results: MonarchLineResult[] = [];
  let stack: string[] = ['root'];
  for (const line of content.split('\n')) {
    const result = tokenizeLine(line, stack);
    stack = result.stack;
    results.push(result);
  }
  return results;
}

/** The styled tokens of one line, unstyled spacing dropped. */
function styled(line: string, stack: readonly string[] = ['root']): MonarchToken[] {
  return tokenizeLine(line, stack).tokens.filter(({ token }) => token !== '');
}

/** Token names for one line. */
function tokens(line: string): string[] {
  return styled(line).map(({ token }) => token);
}

/** The text each token covers, as `[token, text]` pairs. */
function runs(line: string): [string, string][] {
  return styled(line).map(({ token, text }) => [token, text]);
}

/** The named tokens of one line of a document, in the state it is reached in. */
function named(result: MonarchLineResult | undefined): string[] {
  return (result?.tokens ?? []).filter(({ token }) => token !== '').map(({ token }) => token);
}

// ── a miniature Monaco ───────────────────────────────────────────────────────

interface MonacoStub {
  monaco: MonacoLike;
  model: MonacoModel;
  registered: MonacoLanguageRegistration[];
  monarchs: MonarchDefinition[];
  configurations: MonacoLanguageConfiguration[];
  markerCalls: { owner: string; markers: MonacoMarker[] }[];
  completionSelectors: (string | string[])[];
  provideCompletions(model: MonacoModel, lineNumber: number, column: number): MonacoCompletionList;
  disposablesDisposed: number;
  change(): void;
}

function createMonacoStub(): MonacoStub {
  // The methods below close over `stub`, which does not exist yet: they only
  // ever run once the code under test calls them, by which time it does.
  const disposable = {
    dispose: () => {
      stub.disposablesDisposed += 1;
    },
  };

  const languages: MonacoLanguages = {
    register: (language) => {
      stub.registered.push(language);
      return disposable;
    },
    setMonarchTokensProvider: (_id, monarch) => {
      stub.monarchs.push(monarch);
      return disposable;
    },
    setLanguageConfiguration: (_id, configuration) => {
      stub.configurations.push(configuration);
      return disposable;
    },
    registerCompletionProvider: (selector, provider) => {
      stub.completionSelectors.push(selector);
      stub.provideCompletions = (model, lineNumber, column) =>
        provider.provideCompletionItems(model, { lineNumber, column });
      return disposable;
    },
    // Real Monaco numbers them from 0; these are distinct so a mix-up shows.
    CompletionItemKind: { Property: 90, Keyword: 91, Enum: 92, Value: 93, Snippet: 94 },
  };

  const stub: MonacoStub = {
    monaco: {
      editor: {
        setModelMarkers: (_model, owner, markers) => {
          stub.markerCalls.push({ owner, markers });
        },
      },
      languages,
      MarkerSeverity: { Error: 8, Warning: 4, Info: 2, Hint: 1 },
    },
    model: {
      getValue: () => SAMPLE,
      getWordUntilPosition: (position) => wordUntil(SAMPLE, position.lineNumber, position.column),
      onDidChangeContent: (listener) => {
        stub.change = () => listener({});
        return disposable;
      },
    },
    registered: [],
    monarchs: [],
    configurations: [],
    markerCalls: [],
    completionSelectors: [],
    provideCompletions: () => {
      throw new Error('no completion provider was registered');
    },
    disposablesDisposed: 0,
    change: () => undefined,
  };

  return stub;
}

/** Monaco's `getWordUntilPosition`: the word run immediately before the caret. */
function wordUntil(
  content: string,
  lineNumber: number,
  column: number,
): { word: string; startColumn: number; endColumn: number } {
  const line = (content.split('\n')[lineNumber - 1] ?? '').slice(0, column - 1);
  const word = /[A-Za-z0-9_.-]*$/.exec(line)?.[0] ?? '';
  return { word, startColumn: column - word.length, endColumn: column };
}

// ── markers ──────────────────────────────────────────────────────────────────

describe('Monaco markers', () => {
  it('agrees with packages/monaco on every diagnostic', () => {
    expect(toMonacoMarkers(RESULT)).toEqual(toPackageMonacoMarkers(RESULT));
    expect(toMonacoMarkers(DIAGNOSTICS)).toEqual(toPackageMonacoMarkers(DIAGNOSTICS));
  });

  it('maps severity, code, source and 1-based ranges', () => {
    const [error, warning, absent] = toMonacoMarkers(RESULT);
    expect(error).toEqual({
      severity: 8,
      message: 'TRANSFER_SERVER must not end with a slash',
      source: 'stellar-toml-lint',
      code: 'general/trailing-slash-in-endpoint',
      startLineNumber: 3,
      startColumn: 20,
      endLineNumber: 3,
      endColumn: 21,
    });
    expect(warning).toMatchObject({ severity: 4, startLineNumber: 13, startColumn: 12 });
    expect(absent).toMatchObject({ severity: 2, startLineNumber: 1, startColumn: 1, endColumn: 2 });
  });

  it('takes severities from the Monaco instance and the owner from options', () => {
    const markers = toMonacoMarkers(
      RESULT,
      { MarkerSeverity: { Error: 1, Warning: 2, Info: 3, Hint: 4 } },
      'anchor-tools',
    );
    expect(markers.map((marker) => marker.severity)).toEqual([1, 2, 3]);
    expect(markers.every((marker) => marker.source === 'anchor-tools')).toBe(true);
  });

  it('accepts a bare diagnostic list as well as a lint result', () => {
    expect(toMonacoMarkers(DIAGNOSTICS)).toHaveLength(3);
    expect(toMonacoMarkers([])).toEqual([]);
  });
});

// ── grammar ──────────────────────────────────────────────────────────────────

describe('Monarch grammar', () => {
  const stateNames = Object.keys(monarchDefinition.tokenizer);
  const everyRule = (): MonarchRule[] => stateNames.flatMap((state) => [...rulesFor(state)]);

  it('compiles every pattern source into a regex that consumes characters', () => {
    const corpus = [SAMPLE, 'x', '= ""', '[A]', `["${ACCOUNT}"]`, '###', "''' '"];
    for (const { pattern } of everyRule().map(ruleParts)) {
      expect(() => new RegExp(pattern)).not.toThrow();
      for (const text of corpus) {
        for (let index = 0; index <= text.length; index++) {
          const matched = matchAt(pattern, text, index);
          expect(matched === null || matched.length > 0).toBe(true);
        }
      }
    }
  });

  it('only references tokenizer states that exist', () => {
    const names = new Set(stateNames);
    for (const state of stateNames) {
      for (const rule of monarchDefinition.tokenizer[state] ?? []) {
        const target = 'include' in rule ? rule.include : ruleParts(rule).next;
        if (target === undefined || target.startsWith('@pop')) continue;
        expect(names.has(target.replace(/^@/, ''))).toBe(true);
      }
    }
  });

  it('is posted with the language id so themes can target it', () => {
    expect(monarchDefinition.tokenPostfix).toBe('.stellar-toml');
    expect(monarchDefinition.defaultToken).toBe('');
    expect(monarchDefinition.ignoreCase).toBe(false);
  });

  it('colours comments, SEP-1 tables and endpoint keys', () => {
    expect(tokens(SAMPLE.split('\n')[0] ?? '')).toEqual(['comment']);
    expect(tokens('[DOCUMENTATION]')).toEqual(['keyword.table.sep']);
    expect(tokens('[[CURRENCIES]]')).toEqual(['keyword.table.sep']);
    expect(tokens('[SERVERS]')).toEqual(['keyword.table.sep']);
    expect(tokens('[MY_TEAM]')).toEqual(['keyword.table']);
    expect(tokens('[[my-team]]')).toEqual(['keyword.table.array']);
    expect(runs('TRANSFER_SERVER = "https://example.com/sep6"')).toEqual([
      ['constant.language.endpoint', 'TRANSFER_SERVER'],
      ['operator', '='],
      ['string.quote', '"'],
      ['string', 'https://example.com/sep6'],
      ['string.quote', '"'],
    ]);
  });

  it('separates catalogued keys from free-form ones', () => {
    expect(tokens('ORG_NAME = "x"')).toContain('identifier.key.sep');
    expect(runs('BOGUS_FIELD = 1')).toEqual([
      ['identifier.key', 'BOGUS_FIELD'],
      ['operator', '='],
      ['number', '1'],
    ]);
  });

  it('recognises Stellar primitives inside quoted values', () => {
    expect(runs(`SIGNING_KEY = "${ACCOUNT}"`)).toEqual([
      ['identifier.key.sep', 'SIGNING_KEY'],
      ['operator', '='],
      ['string.quote', '"'],
      ['string.stellar.account-id', ACCOUNT],
      ['string.quote', '"'],
    ]);
    expect(runs(`WEB_AUTH_CONTRACT_ID = "${CONTRACT}"`)).toContainEqual([
      'string.stellar.contract-id',
      CONTRACT,
    ]);
    expect(runs(`muxed = "${MULTIPLEXED}"`)).toContainEqual([
      'string.stellar.muxed-account-id',
      MULTIPLEXED,
    ]);
    expect(runs('code = "USD"')).toContainEqual(['string.stellar.asset-code', 'USD']);
  });

  it('does not mistake an array of strkeys for a table header', () => {
    const arrayLine = SAMPLE.split('\n').find((line) => line.startsWith('ACCOUNTS = [')) ?? '';
    expect(tokens(arrayLine)).toEqual(['identifier.key.sep', 'operator', 'delimiter.bracket']);

    expect(runs(`  "${ACCOUNT}",`)).toEqual([
      ['string.quote', '"'],
      ['string.stellar.account-id', ACCOUNT],
      ['string.quote', '"'],
      ['delimiter.comma', ','],
    ]);
    expect(tokens(']')).toEqual(['delimiter.bracket']);
  });

  it('keeps multi-line strings across lines and returns to the root state', () => {
    const document = ['KEY = """', 'not a [[TABLE]] or KEY = value', '"""', 'VERSION = 1'].join(
      '\n',
    );
    const [opening, body, closing] = tokenizeDocument(document);
    expect(opening?.stack).toEqual(['root', 'multilineBasic']);
    expect(named(opening)).toEqual(['identifier.key', 'operator', 'string.quote']);
    expect(named(body)).toEqual(['string']);
    expect(closing?.stack).toEqual(['root']);
    expect(named(closing)).toEqual(['string.quote']);
    expect(tokens("KEY = '''")).toEqual(['identifier.key', 'operator', 'string.quote']);
  });

  it('treats escapes and apostrophes as string content', () => {
    expect(runs('MY_TEXT = "a\\tb"')).toEqual([
      ['identifier.key', 'MY_TEXT'],
      ['operator', '='],
      ['string.quote', '"'],
      ['string', 'a'],
      ['string.escape', '\\t'],
      ['string', 'b'],
      ['string.quote', '"'],
    ]);
    expect(runs('MY_TEXT = "O\'Brien"')).toEqual([
      ['identifier.key', 'MY_TEXT'],
      ['operator', '='],
      ['string.quote', '"'],
      ['string', "O'Brien"],
      ['string.quote', '"'],
    ]);
    expect(runs("MY_TEXT = 'a literal value'")).toEqual([
      ['identifier.key', 'MY_TEXT'],
      ['operator', '='],
      ['string.quote', "'"],
      ['string', 'a literal value'],
      ['string.quote', "'"],
    ]);
  });

  it('leaves nothing but spacing unstyled in the sample document', () => {
    const unstyled = tokenizeDocument(SAMPLE)
      .flatMap((result) => result.tokens)
      .filter(({ token }) => token === '')
      .map(({ text }) => text)
      .join('');
    expect(unstyled.trim()).toBe('');
  });

  it('covers the scalar forms TOML allows in a value', () => {
    expect(tokens('flag = true')).toContain('constant.language.boolean');
    expect(tokens('at = 2024-01-02T03:04:05Z')).toContain('constant.datetime');
    expect(tokens('time = 03:04:05')).toContain('constant.datetime');
    expect(tokens('limit = inf')).toContain('constant.language.number');
    expect(tokens('mask = 0x1F')).toContain('number');
    expect(tokens('count = -12_000.5e3')).toContain('number');
  });
});

// ── language configuration ───────────────────────────────────────────────────

describe('Monaco language configuration', () => {
  it('describes TOML commenting, brackets and quoting', () => {
    expect(languageConfiguration.comments).toEqual({ lineComment: '#' });
    expect(languageConfiguration.brackets).toEqual([
      ['[', ']'],
      ['{', '}'],
      ['(', ')'],
    ]);
    expect(languageConfiguration.surroundingPairs?.map((pair) => pair.open)).toEqual([
      '[',
      '"',
      "'",
    ]);
  });

  it('never auto-closes brackets inside a comment or a string', () => {
    const bracket = languageConfiguration.autoClosingPairs?.find((pair) => pair.open === '[');
    expect(bracket?.notIn).toEqual(['string', 'comment']);
    const quote = languageConfiguration.autoClosingPairs?.find((pair) => pair.open === "'");
    expect(quote?.notIn).toContain('string');
  });

  it('keeps a whole SEP-1 key as one word', () => {
    expect(languageConfiguration.wordPattern?.flags).not.toContain('g');
    expect(languageConfiguration.wordPattern?.source).toBe('[A-Za-z0-9_.-]+');
    expect(languageConfiguration.wordPattern?.test('TRANSFER_SERVER_SEP0024')).toBe(true);
  });
});

// ── completions ──────────────────────────────────────────────────────────────

describe('Monaco completions', () => {
  const bundle = monacoLanguageBundle();

  it('suggests the section keys SEP-1 defines, minus the ones already written', () => {
    const labels = bundle
      .completions({ content: '[DOCUMENTATION]\nORG_NAME = "Acme"\n', lineNumber: 3, column: 1 })
      .map((suggestion) => suggestion.label);
    expect(labels).toContain('ORG_URL');
    expect(labels).not.toContain('ORG_NAME');
  });

  it('suggests table headers after an opening bracket, array or single', () => {
    expect(
      bundle
        .completions({ content: '[[', lineNumber: 1, column: 3 })
        .map((suggestion) => suggestion.insertText),
    ).toEqual(['[[PRINCIPALS]]', '[[CURRENCIES]]', '[[VALIDATORS]]']);

    expect(
      bundle
        .completions({ content: '[', lineNumber: 1, column: 2 })
        .map((suggestion) => suggestion.insertText),
    ).toEqual(['[DOCUMENTATION]', '[SERVERS]']);
  });

  it('suggests enumerated values only where SEP-1 enumerates them', () => {
    const status = bundle.completions({
      content: '[[CURRENCIES]]\nstatus = ',
      lineNumber: 2,
      column: 14,
    });
    expect(status.map((suggestion) => suggestion.insertText)).toEqual([
      'live',
      'dead',
      'test',
      'private',
    ]);
    expect(status.every((suggestion) => suggestion.context === 'value')).toBe(true);

    expect(
      bundle.completions({ content: '[[CURRENCIES]]\nname = ', lineNumber: 2, column: 12 }),
    ).toEqual([]);
  });

  it('carries the documentation the language server hovers', () => {
    const [suggestion] = bundle.completions({
      content: '[[CURRENCIES]]\nstatus = ',
      lineNumber: 2,
      column: 14,
    });
    expect(suggestion?.detail).toContain('string');
    expect(suggestion?.documentation).toContain('`[[CURRENCIES]].status`');
    expect(suggestion?.documentation).toContain('**Permitted values:**');
    expect(suggestion?.helpUri).toContain('stellar/stellar-protocol');
  });

  it('maps suggestions to Monaco items, taking kinds from Monaco when present', () => {
    const list = toMonacoCompletions(
      bundle.completions({ content: '[[CURRENCIES]]\nstatus = ', lineNumber: 2, column: 14 }),
      { CompletionItemKind: { Enum: 92 } },
      { getValue: () => '[[CURRENCIES]]\nstatus = ' },
      { lineNumber: 2, column: 14 },
    );
    expect(list.suggestions.map((item) => item.kind)).toEqual([92, 92, 92, 92]);
    expect(list.suggestions[0]).toMatchObject({
      label: 'live',
      insertText: 'live',
      filterText: 'live',
      documentation: { value: expect.stringContaining('[[CURRENCIES]].status') },
    });
  });

  it('falls back to the documented CompletionItemKind numbers', () => {
    const list = toMonacoCompletions(
      bundle.completions({ content: '[[', lineNumber: 1, column: 3 }),
      undefined,
      { getValue: () => '[[' },
      { lineNumber: 1, column: 3 },
    );
    expect(list.suggestions.map((item) => item.kind)).toEqual([13, 13, 13]);
  });

  it('replaces the word the caret is inside, as Monaco reports it', () => {
    const model: MonacoModel = {
      getValue: () => 'ORG_N',
      getWordUntilPosition: () => ({ word: 'ORG_N', startColumn: 1, endColumn: 6 }),
    };
    const list = toMonacoCompletions(
      [{ label: 'ORG_NAME', insertText: 'ORG_NAME', context: 'key' }],
      undefined,
      model,
      { lineNumber: 1, column: 6 },
    );
    expect(list.suggestions[0]?.range).toEqual({
      startLineNumber: 1,
      startColumn: 1,
      endLineNumber: 1,
      endColumn: 6,
    });
  });

  it('replaces typed brackets when the model has no word until position', () => {
    const list = toMonacoCompletions(
      [{ label: '[[CURRENCIES]]', insertText: '[[CURRENCIES]]', context: 'table' }],
      undefined,
      { getValue: () => '[[' },
      { lineNumber: 1, column: 3 },
    );
    expect(list.suggestions[0]?.range).toMatchObject({ startColumn: 1, endColumn: 3 });
  });
});

// ── register ─────────────────────────────────────────────────────────────────

describe('register', () => {
  it('attaches the grammar, configuration and provider to the language id', () => {
    const stub = createMonacoStub();
    const registration: MonacoRegistration = register(stub.monaco);

    expect(stub.registered).toEqual([
      {
        id: 'stellar-toml',
        extensions: ['.toml'],
        aliases: ['Stellar TOML', 'stellar-toml'],
        filenames: ['stellar.toml'],
      },
    ]);
    expect(stub.monarchs).toEqual([monarchDefinition]);
    expect(stub.configurations).toEqual([languageConfiguration]);
    expect(stub.completionSelectors).toEqual(['stellar-toml']);

    registration.dispose();
    expect(stub.disposablesDisposed).toBe(4);
  });

  it('honours a custom language id, owner and replacement grammar', () => {
    const stub = createMonacoStub();
    const monarch: MonarchDefinition = {
      tokenPostfix: '.sep1',
      defaultToken: '',
      ignoreCase: true,
      tokenizer: { root: [['#.*', 'comment']] },
    };
    const registration = register(stub.monaco, {
      languageId: 'sep1',
      owner: 'anchor',
      monarch,
    });

    expect(stub.registered[0]?.id).toBe('sep1');
    expect(stub.monarchs).toEqual([monarch]);

    registration.publish(stub.model, DIAGNOSTICS);
    expect(stub.markerCalls.at(-1)?.owner).toBe('anchor');
    registration.dispose();
  });

  it('answers completions through the registered provider', () => {
    const stub = createMonacoStub();
    register(stub.monaco).dispose();
    const list = stub.provideCompletions({ getValue: () => '[[CURRENCIES]]\nstatus = ' }, 2, 14);
    expect(list.suggestions.map((item) => item.label)).toEqual(['live', 'dead', 'test', 'private']);
    expect(list.suggestions[0]?.kind).toBe(92);
  });

  it('publishes markers for a lint result through the bundle', () => {
    const stub = createMonacoStub();
    const registration = register(stub.monaco, { owner: 'anchor-tools' });
    const markers = registration.publish(stub.model, RESULT);

    expect(markers).toHaveLength(3);
    expect(stub.markerCalls).toEqual([{ owner: 'anchor-tools', markers }]);
    registration.dispose();
  });

  it('needs a validator before it can lint by itself', async () => {
    const stub = createMonacoStub();
    const registration = register(stub.monaco);
    await expect(registration.validate(stub.model)).rejects.toThrow(/validator/);
    registration.dispose();
  });

  it('runs the injected validator and publishes what it returns', async () => {
    const stub = createMonacoStub();
    const seen: { content: string; options: Record<string, unknown> }[] = [];
    const validator: LintValidator = (content, options) => {
      seen.push({ content, options });
      return RESULT;
    };
    const registration = register(stub.monaco, { validator, lintOptions: { strict: true } });

    const markers = await registration.validate(stub.model);
    expect(seen).toEqual([{ content: SAMPLE, options: { strict: true } }]);
    expect(stub.markerCalls.at(-1)?.markers).toEqual(markers);
    expect(markers).toEqual(toMonacoMarkers(RESULT));
    registration.dispose();
  });

  it('revalidates on edit, once per quiet period', async () => {
    vi.useFakeTimers();
    try {
      const stub = createMonacoStub();
      let runs = 0;
      const registration = register(stub.monaco, {
        validator: () => {
          runs += 1;
          return RESULT;
        },
        debounceMs: 100,
      });
      const observed = registration.observe(stub.model);

      stub.change();
      stub.change();
      stub.change();
      expect(runs).toBe(0);

      await vi.advanceTimersByTimeAsync(100);
      expect(runs).toBe(1);
      expect(stub.markerCalls).toHaveLength(1);

      observed.dispose();
      expect(stub.markerCalls.at(-1)).toEqual({ owner: 'stellar-toml-lint', markers: [] });
      registration.dispose();
    } finally {
      vi.useRealTimers();
    }
  });

  it('validates immediately when the debounce is off', async () => {
    const stub = createMonacoStub();
    const registration = register(stub.monaco, { validator: () => RESULT, debounceMs: 0 });
    registration.observe(stub.model);

    stub.change();
    await Promise.resolve();
    expect(stub.markerCalls).toHaveLength(1);
    registration.dispose();
  });

  it('clears only its own markers', () => {
    const stub = createMonacoStub();
    const registration = register(stub.monaco);
    registration.publish(stub.model, RESULT);
    registration.clear(stub.model);
    expect(stub.markerCalls.map((call) => call.markers.length)).toEqual([3, 0]);
    expect(stub.markerCalls.every((call) => call.owner === 'stellar-toml-lint')).toBe(true);
    registration.dispose();
  });
});

// ── worker validator ─────────────────────────────────────────────────────────

class FakeWorker implements WorkerLike {
  onmessage: ((event: { data: unknown }) => void) | null = null;
  readonly requests: Record<string, unknown>[] = [];

  postMessage(message: unknown): void {
    this.requests.push(message as Record<string, unknown>);
  }
}

class EventWorker implements WorkerLike {
  readonly requests: Record<string, unknown>[] = [];
  private listener: ((event: { data: unknown }) => void) | undefined;

  postMessage(message: unknown): void {
    this.requests.push(message as Record<string, unknown>);
  }

  addEventListener(_type: 'message', listener: (event: { data: unknown }) => void): void {
    this.listener = listener;
  }

  emit(data: unknown): void {
    this.listener?.({ data });
  }
}

describe('createWorkerValidator', () => {
  it('speaks the shipped worker protocol and resolves its result', async () => {
    const worker = new FakeWorker();
    const validate = createWorkerValidator(worker, { lintOptions: { offline: true } });

    const pending = validate('content', { strict: true });
    expect(worker.requests[0]).toEqual({
      type: 'lint',
      content: 'content',
      options: { offline: true, strict: true },
      id: 1,
    });

    worker.onmessage?.({ data: { type: 'result', id: 1, result: RESULT } });
    await expect(pending).resolves.toBe(RESULT);
  });

  it('pairs overlapping requests by id, whichever order they land in', async () => {
    const worker = new FakeWorker();
    const validate = createWorkerValidator(worker);
    const first = validate('a', {});
    const second = validate('b', {});
    expect(worker.requests.map((request) => request.id)).toEqual([1, 2]);

    const later: LintResult = { ...RESULT, ok: true };
    worker.onmessage?.({ data: { type: 'result', id: 2, result: later } });
    await expect(second).resolves.toBe(later);
    worker.onmessage?.({ data: { type: 'result', id: 1, result: RESULT } });
    await expect(first).resolves.toBe(RESULT);
  });

  it('rejects on a worker error and reports it', async () => {
    const worker = new FakeWorker();
    const errors: Error[] = [];
    const validate = createWorkerValidator(worker, { onError: (error) => errors.push(error) });

    const pending = validate('a', {});
    worker.onmessage?.({ data: { type: 'error', id: 1, message: 'parse failed' } });

    await expect(pending).rejects.toThrow('parse failed');
    expect(errors.map((error) => error.message)).toEqual(['parse failed']);
  });

  it('ignores messages for unknown or missing request ids', async () => {
    const worker = new FakeWorker();
    const validate = createWorkerValidator(worker);
    const pending = validate('a', {});

    worker.onmessage?.({ data: null });
    worker.onmessage?.({ data: { type: 'result', result: RESULT } });
    worker.onmessage?.({ data: { type: 'result', id: 99, result: RESULT } });
    worker.onmessage?.({ data: { type: 'result', id: 1, result: DIAGNOSTICS } });

    await expect(pending).resolves.toEqual(DIAGNOSTICS);
  });

  it('subscribes with addEventListener when the worker has no onmessage', async () => {
    const worker = new EventWorker();
    const validate = createWorkerValidator(worker);
    const pending = validate('a', {});

    worker.emit({ type: 'result', id: 1, result: RESULT });
    await expect(pending).resolves.toBe(RESULT);
    expect(worker.requests[0]).toMatchObject({ type: 'lint', id: 1 });
  });

  it('drives a real lint result end to end through register', async () => {
    const worker = new FakeWorker();
    const stub = createMonacoStub();
    const registration = register(stub.monaco, {
      validator: createWorkerValidator(worker),
      debounceMs: 0,
    });

    const pending = registration.validate(stub.model);
    worker.onmessage?.({ data: { type: 'result', id: 1, result: RESULT } });

    expect(await pending).toHaveLength(3);
    expect(stub.markerCalls.at(-1)?.markers).toEqual(toMonacoMarkers(RESULT));
    registration.dispose();
  });
});

// ── bundle metadata ──────────────────────────────────────────────────────────

describe('monacoLanguageBundle', () => {
  it('describes the language the way the TextMate grammar does', () => {
    const bundle = monacoLanguageBundle();
    expect(bundle).toMatchObject({
      id: 'stellar-toml',
      name: 'Stellar TOML (SEP-1)',
      owner: 'stellar-toml-lint',
    });
    expect(bundle.aliases).toContain('stellar-toml');
    expect(bundle.extensions).toEqual(['.toml']);
    expect(bundle.filenames).toEqual(['stellar.toml']);
    expect(bundle.monarch).toBe(monarchDefinition);
    expect(bundle.languageConfiguration).toBe(languageConfiguration);
  });

  it('takes its language id and owner from options', () => {
    const bundle = monacoLanguageBundle({ languageId: 'sep1-toml', owner: 'acme' });
    const stub = createMonacoStub();
    expect(bundle.id).toBe('sep1-toml');
    expect(bundle.markers(DIAGNOSTICS)[0]?.source).toBe('acme');
    expect(bundle.publish(stub.monaco, { getValue: () => '' }, DIAGNOSTICS)).toHaveLength(3);
    expect(stub.markerCalls.at(-1)?.owner).toBe('acme');
    expect(
      bundle.completionProvider.provideCompletionItems(stub.model, {
        lineNumber: 8,
        column: 1,
      }).suggestions.length,
    ).toBeGreaterThan(0);
  });
});
