/**
 * The CodeMirror 6 adapter: the `StreamParser` tokenizer and the diagnostic and
 * completion mappers.
 *
 * CodeMirror is not a dependency of this package and is not loaded here, so the
 * assertions run against a `StringStream` re-implementation that follows the
 * documented contract — patterns matched at the caret, `start` reset per token,
 * `match(string)` compared exactly. The most important property a stream parser
 * can break is asserted by the driver itself: every `token()` call must consume
 * at least one character, because CodeMirror loops until the stream is done.
 */
import { describe, expect, it } from 'vitest';

import {
  blankLine,
  completionsFor,
  copyState,
  startState,
  stellarTomlStreamParser,
  toCodeMirrorCompletions,
  toCodeMirrorDiagnostics,
  token,
  toCodeMirrorDiagnostics as diagnosticsFor,
} from '../src/editor/codeMirror.js';
import type {
  CodeMirrorCompletion,
  CodeMirrorDiagnostic,
  CodeMirrorStream,
  CodeMirrorStreamParser,
  StellarTomlStreamState,
} from '../src/editor/codeMirror.js';
import parserDefault from '../src/editor/codeMirror.js';
import { KNOWN_DOCUMENTATION_FIELDS } from '../src/spec.js';
import type { Diagnostic, LintResult } from '../src/types.js';

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function strkey(prefix: 'G' | 'C', total: number): string {
  let out = prefix;
  for (let index = 1; index < total; index++) out += BASE32[index % BASE32.length];
  return out;
}

const ACCOUNT = strkey('G', 56);
const CONTRACT = strkey('C', 56);

// ── a miniature CodeMirror stream ────────────────────────────────────────────

class StringStream implements CodeMirrorStream {
  pos = 0;
  start = 0;

  constructor(private readonly line: string) {}

  peek(): string | undefined {
    return this.line[this.pos];
  }

  next(): string | undefined {
    if (this.pos >= this.line.length) return undefined;
    return this.line[this.pos++];
  }

  match(pattern: string | RegExp, consume = true): string | null {
    if (typeof pattern === 'string') {
      if (!this.line.startsWith(pattern, this.pos)) return null;
      if (consume) this.pos += pattern.length;
      return pattern;
    }
    const matched = this.line.slice(this.pos).match(pattern);
    if (matched === null || matched.index !== 0) return null;
    if (consume) this.pos += matched[0].length;
    return matched[0];
  }

  eatSpace(): boolean {
    const before = this.pos;
    while (/[ \t]/.test(this.line[this.pos] ?? '')) this.pos++;
    return this.pos > before;
  }

  skipToEnd(): void {
    this.pos = this.line.length;
  }

  sol(): boolean {
    return this.pos === 0;
  }

  current(): string {
    return this.line.slice(this.start, this.pos);
  }

  get done(): boolean {
    return this.pos >= this.line.length;
  }
}

interface CmToken {
  token: string | null;
  text: string;
}

/** Drives `token()` the way `StreamLanguage` does, and insists it progresses. */
function tokenizeLine(line: string, state: StellarTomlStreamState): CmToken[] {
  const stream = new StringStream(line);
  const tokens: CmToken[] = [];

  while (!stream.done) {
    const before = stream.pos;
    stream.start = before;
    const type = token(stream, state);
    if (stream.pos <= before) {
      throw new Error(`token() did not advance at column ${before + 1} of ${JSON.stringify(line)}`);
    }
    tokens.push({ token: type, text: line.slice(before, stream.pos) });
  }

  return tokens;
}

/** Token types for one line, with the untitled whitespace runs dropped. */
function types(line: string, state = startState()): (string | null)[] {
  return tokenizeLine(line, state).map((entry) => entry.token);
}

function styled(line: string, state = startState()): string[] {
  return types(line, state).filter((type): type is string => type !== null);
}

/** The `[token, text]` pairs of a whole document, sharing one parser state. */
function documentRuns(content: string): { token: string | null; text: string }[] {
  const state = startState();
  return content.split('\n').flatMap((line) => tokenizeLine(line, state));
}

// ── the parser contract ──────────────────────────────────────────────────────

describe('CodeMirror stream parser', () => {
  it('exposes the StreamParser surface StreamLanguage.define expects', () => {
    const parsed: CodeMirrorStreamParser = stellarTomlStreamParser;
    expect(Object.keys(parsed).sort()).toEqual(['blankLine', 'copyState', 'startState', 'token']);
    expect(parsed.startState).toBe(startState);
    expect(parsed.copyState).toBe(copyState);
    expect(parsed.blankLine).toBe(blankLine);
    expect(parsed.token).toBe(token);
    expect(parserDefault).toBe(stellarTomlStreamParser);
  });

  it('starts at the document root, outside any string', () => {
    expect(startState()).toEqual({ multiline: null, section: '', inValue: false });
  });

  it('copies state so CodeMirror can branch, without sharing it', () => {
    const state = startState();
    tokenizeLine('[[CURRENCIES]]', state);
    const copy = copyState(state);
    expect(copy).toEqual(state);
    expect(copy).not.toBe(state);

    tokenizeLine('desc = """', state);
    expect(state.multiline).toBe('"');
    expect(copy.multiline).toBeNull();
  });

  it('closes an unterminated multi-line string at a blank line', () => {
    const state = startState();
    tokenizeLine('note = """', state);
    expect(state.multiline).toBe('"');

    blankLine(state);
    expect(state.multiline).toBeNull();
    expect(state.inValue).toBe(false);
  });
});

// ── tokens ───────────────────────────────────────────────────────────────────

describe('CodeMirror tokens', () => {
  it('styles comments and nothing else on the line', () => {
    expect(styled('# SEP-1 stellar.toml')).toEqual(['comment']);
    expect(styled('VERSION = "2.0.0" # trailing note')).toEqual([
      'propertyName.sep',
      'operator',
      'string',
      'comment',
    ]);
  });

  it('styles table headers and remembers the section', () => {
    const state = startState();
    expect(styled('[[CURRENCIES]]', state)).toEqual(['keyword.sep']);
    expect(state.section).toBe('CURRENCIES');

    expect(styled('[DOCUMENTATION]', state)).toEqual(['keyword.sep']);
    expect(styled('[SERVERS]', state)).toEqual(['keyword.sep']);

    const custom = startState();
    expect(styled('[MY_TEAM]', custom)).toEqual(['keyword']);
    expect(custom.section).toBe('MY_TEAM');

    expect(styled('[[my-team]]', custom)).toEqual(['keyword']);
  });

  it('separates endpoint keys, catalogued keys and free-form keys', () => {
    expect(styled('TRANSFER_SERVER = "https://example.com/sep6"')).toEqual([
      'propertyName.endpoint',
      'operator',
      'string',
    ]);

    const documentation = startState();
    documentation.section = 'DOCUMENTATION';
    expect(styled('ORG_NAME = "Acme"', documentation)).toEqual([
      'propertyName.sep',
      'operator',
      'string',
    ]);
    expect(styled('BOGUS_FIELD = 1', documentation)).toEqual([
      'propertyName',
      'operator',
      'number',
    ]);
  });

  it('colours a key by the section it is actually in', () => {
    const validators = startState();
    validators.section = 'VALIDATORS';
    expect(styled('ALIAS = "acme-1"', validators)[0]).toBe('propertyName.sep');

    const documentation = startState();
    documentation.section = 'DOCUMENTATION';
    expect(styled('ALIAS = "unused"', documentation)[0]).toBe('propertyName');
  });

  it('follows the section across a document', () => {
    const state = startState();
    tokenizeLine('[DOCUMENTATION]', state);
    tokenizeLine('ORG_NAME = "Acme"', state);
    tokenizeLine('[[CURRENCIES]]', state);
    expect(styled('code = "USD"', state)[0]).toBe('propertyName.sep');
    expect(styled('ORG_URL = "https://acme.example"', state)[0]).toBe('propertyName');
  });

  it('styles every TOML scalar a stellar.toml can hold', () => {
    expect(styled('is_unlimited = true')).toEqual(['propertyName', 'operator', 'bool']);
    expect(styled('at = 2024-01-02T03:04:05Z')).toEqual(['propertyName', 'operator', 'date']);
    expect(styled('day = 2024-01-02')).toEqual(['propertyName', 'operator', 'date']);
    expect(styled('clock = 03:04:05')).toEqual(['propertyName', 'operator', 'date']);
    expect(styled('mask = 0x1F')).toEqual(['propertyName', 'operator', 'number']);
    expect(styled('limit = -inf')).toEqual(['propertyName', 'operator', 'number']);
    expect(styled('count = -12_000.5e3')).toEqual(['propertyName', 'operator', 'number']);
    expect(styled('name = "Acme Anchoring"')).toEqual(['propertyName', 'operator', 'string']);
    expect(styled("note = 'a literal value'")).toEqual(['propertyName', 'operator', 'string']);
  });

  it('styles Stellar primitives in quoted values', () => {
    expect(styled(`SIGNING_KEY = "${ACCOUNT}"`)).toEqual([
      'propertyName.sep',
      'operator',
      'string.stellar',
    ]);
    expect(styled(`WEB_AUTH_CONTRACT_ID = "${CONTRACT}"`)).toContain('string.stellar');
    expect(styled('code = "USD"')).toContain('string.stellar');
    expect(styled('url = "https://acme.example/sep24"')).toEqual([
      'propertyName',
      'operator',
      'string',
    ]);
  });

  it('styles arrays of strkeys, on one line and wrapped', () => {
    expect(styled(`ACCOUNTS = ["${ACCOUNT}", "${ACCOUNT}"]`)).toEqual([
      'propertyName.sep',
      'operator',
      'punctuation',
      'string.stellar',
      'punctuation',
      'string.stellar',
      'punctuation',
    ]);

    const state = startState();
    tokenizeLine('WEB_AUTH_CONTRACT_ID = [', state);
    expect(styled(`  "${CONTRACT}",`, state)).toEqual(['string.stellar', 'punctuation']);
    expect(styled(`  "${CONTRACT}"`, state)).toEqual(['string.stellar']);
    expect(styled(']', state)).toEqual(['punctuation']);
  });

  it('keeps a multi-line string styled across its lines', () => {
    const document = [
      'redemption_instructions = """',
      'Send from your bank.',
      `Issuer: ${ACCOUNT}`,
      '"""',
      'VERSION = "2.0.0"',
    ].join('\n');

    const state = startState();
    const results = document.split('\n').map((line) => ({
      line,
      tokens: tokenizeLine(line, state),
      multiline: state.multiline,
    }));

    expect(results[0]?.tokens.map((entry) => entry.token)).toEqual([
      // No `[[CURRENCIES]]` header precedes it, so the root section is in
      // effect and `redemption_instructions` is not one of its keys.
      'propertyName',
      null,
      'operator',
      null,
      'string.multiline',
    ]);
    expect(results[0]?.multiline).toBe('"');
    expect(results[1]?.tokens.every((entry) => entry.token === 'string.multiline')).toBe(true);
    // Prose is one run: a strkey mid-sentence is text, and Monarch's value
    // rules are anchored the same way, so the two bundles agree.
    expect(results[2]?.tokens.map((entry) => entry.token)).toEqual(['string.multiline']);
    expect(results[3]?.multiline).toBeNull();
    expect(results[4]?.tokens.map((entry) => entry.token)).toEqual([
      'propertyName.sep',
      null,
      'operator',
      null,
      'string',
    ]);
  });

  it('styles a strkey that starts a multi-line body line', () => {
    const state = startState();
    tokenizeLine('destination_accounts = """', state);
    expect(styled(`${ACCOUNT}`, state)).toEqual(['string.stellar']);
    expect(styled(`${ACCOUNT} and ${ACCOUNT}`, state)).toEqual([
      'string.stellar',
      // The rest is one prose run, so the second key is text: a stream parser
      // cannot see ahead for the next primitive without a lookahead it does
      // not have.
      'string.multiline',
    ]);
  });

  it('styles escapes inside a multi-line basic string', () => {
    const state = startState();
    tokenizeLine('desc = """', state);
    const runs = tokenizeLine('a \\u00e9 line', state);
    expect(runs.map((entry) => entry.token)).toEqual([
      'string.multiline',
      'string.escape',
      'string.multiline',
    ]);
    expect(runs.map((entry) => entry.text)).toEqual(['a ', '\\u00e9', ' line']);
  });

  it('closes a multi-line literal string on its own delimiter', () => {
    const state = startState();
    tokenizeLine("desc = '''", state);
    expect(state.multiline).toBe("'");
    expect(styled("it's still text", state)).toEqual(['string.multiline']);
    tokenizeLine("'''", state);
    expect(state.multiline).toBeNull();
  });

  it('advances on every token, whatever the line holds', () => {
    const corpus = [
      '',
      '#',
      '=',
      ']',
      '[',
      ',,',
      'x',
      'x =',
      '= = =',
      '"""',
      "'''",
      '"unclosed',
      "'unclosed",
      '[[',
      '[[]]',
      '[[CURRENCIES]',
      '"key" = 1',
      'a.b.c = 1',
      '   ',
      '\t-1',
      '@@',
      'https://acme.example',
    ];
    for (const line of corpus) {
      expect(() => tokenizeLine(line, startState())).not.toThrow();
      for (const continuation of corpus) {
        expect(() => tokenizeLine(continuation, startState())).not.toThrow();
      }
    }
  });

  it('leaves nothing but spacing unstyled in a real document', () => {
    const document = [
      '# SEP-1 stellar.toml',
      'NETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"',
      'TRANSFER_SERVER = "https://acme.example/sep6"',
      `ACCOUNTS = [\n  "${ACCOUNT}",\n  "${ACCOUNT}"\n]`,
      '',
      '[DOCUMENTATION]',
      'ORG_NAME = "Acme Anchoring"',
      'ORG_URL = "https://acme.example"',
      '',
      '[[CURRENCIES]]',
      'code = "USD"',
      'status = "live"',
      `issuer = "${ACCOUNT}"`,
      'display_decimals = 2',
      'collateral_addresses = ["' + CONTRACT + '"]',
    ].join('\n');

    const unstyled = documentRuns(document)
      .filter((entry) => entry.token === null)
      .map((entry) => entry.text)
      .join('');
    expect(unstyled.trim()).toBe('');
  });
});

// ── diagnostics ──────────────────────────────────────────────────────────────

const LINTED = [
  'VERSION = "2.0.0"',
  'TRANSFER_SERVER = "https://acme.example/sep6/"',
  '[[CURRENCIES]]',
  'status = "live"',
].join('\n');

const FINDINGS: Diagnostic[] = [
  {
    rule: 'general/trailing-slash-in-endpoint',
    severity: 'error',
    category: 'general',
    message: 'TRANSFER_SERVER must not end with a slash',
    position: { line: 2, column: 1 },
  },
  {
    rule: 'currencies/status-invalid',
    severity: 'warning',
    category: 'currencies',
    message: 'status is not a SEP-1 value',
    position: { line: 4, column: 1 },
  },
  {
    rule: 'documentation/recommended-missing',
    severity: 'info',
    category: 'documentation',
    message: 'ORG_SUPPORT_EMAIL is recommended',
  },
];

const RESULT: LintResult = {
  diagnostics: FINDINGS,
  ok: false,
  counts: { error: 1, warning: 1, info: 1 },
};

describe('CodeMirror diagnostics', () => {
  it('converts line and column into document offsets over the whole token', () => {
    const [error, warning, absent] = toCodeMirrorDiagnostics(RESULT, LINTED) as [
      CodeMirrorDiagnostic,
      CodeMirrorDiagnostic,
      CodeMirrorDiagnostic,
    ];

    expect(LINTED.slice(error.from, error.to)).toBe('TRANSFER_SERVER');
    expect(LINTED.slice(warning.from, warning.to)).toBe('status');
    expect(error).toEqual({
      from: 18,
      to: 33,
      severity: 'error',
      message: 'TRANSFER_SERVER must not end with a slash',
      source: 'stellar-toml-lint',
      code: 'general/trailing-slash-in-endpoint',
    });
    expect(absent).toMatchObject({
      from: 0,
      severity: 'info',
      code: 'documentation/recommended-missing',
    });
    expect(LINTED.slice(absent.from, absent.to)).toBe('VERSION');
  });

  it('accepts a bare diagnostic list too', () => {
    expect(toCodeMirrorDiagnostics(FINDINGS, LINTED)).toHaveLength(3);
    expect(toCodeMirrorDiagnostics([], LINTED)).toEqual([]);
  });

  it('keeps the three core severities, which are the three CodeMirror has', () => {
    expect(
      toCodeMirrorDiagnostics(FINDINGS, LINTED).map((diagnostic) => diagnostic.severity),
    ).toEqual(['error', 'warning', 'info']);
  });

  it('never lets a marker run past the end of the document', () => {
    const past = [{ ...FINDINGS[0], position: { line: 4, column: 99 } }] as Diagnostic[];
    const [diagnostic] = toCodeMirrorDiagnostics(past, LINTED);
    // Offsets are 0-based and measure between characters, so the last
    // position the document can address is its length.
    expect(diagnostic?.from).toBe(LINTED.length);
    expect(diagnostic?.to).toBe(LINTED.length);
  });

  it('is the same finding the Monaco bundle reports', () => {
    const [cm] = diagnosticsFor(FINDINGS, LINTED);
    const line = LINTED.slice(0, cm?.from).split('\n').length;
    const column = (cm?.from ?? 0) - (LINTED.lastIndexOf('\n', cm?.from ?? 0) + 1) + 1;
    expect({ line, column }).toEqual({ line: 2, column: 1 });
    expect(cm?.code).toBe(FINDINGS[0]?.rule);
  });
});

// ── completions ──────────────────────────────────────────────────────────────

describe('CodeMirror completions', () => {
  it('labels each completion with the type CodeMirror renders', () => {
    const options = completionsFor('[[CURRENCIES]]\nstatus = ', 2, 14);
    expect(options.map((option) => option.label)).toEqual(['live', 'dead', 'test', 'private']);
    expect(options.every((option) => option.type === 'enum')).toBe(true);
    expect(options[0]?.info).toContain('[[CURRENCIES]].status');
    expect(options[0]?.detail).toContain('string');
  });

  it('suggests section keys as properties, minus those already written', () => {
    const options = completionsFor('[DOCUMENTATION]\nORG_NAME = "Acme"\n', 3, 1);
    expect(options.every((option) => option.type === 'property')).toBe(true);
    expect(options.map((option) => option.label)).toEqual(
      [...KNOWN_DOCUMENTATION_FIELDS].filter((field) => field !== 'ORG_NAME'),
    );
  });

  it('suggests headers as keywords after a bracket', () => {
    expect(completionsFor('[[', 1, 3).map((option) => option.type)).toEqual([
      'keyword',
      'keyword',
      'keyword',
    ]);
    expect(completionsFor('[', 1, 2).map((option) => option.label)).toEqual([
      '[DOCUMENTATION]',
      '[SERVERS]',
    ]);
  });

  it('maps a suggestion list directly, for a page with its own source', () => {
    const mapped: CodeMirrorCompletion[] = toCodeMirrorCompletions([
      { label: 'ORG_URL', insertText: 'ORG_URL', context: 'key', detail: 'required' },
    ]);
    expect(mapped).toEqual([
      { label: 'ORG_URL', type: 'property', detail: 'required', info: undefined },
    ]);
  });

  it('returns nothing where there is nothing to suggest', () => {
    expect(completionsFor('[[CURRENCIES]]\nname = ', 2, 12)).toEqual([]);
    expect(completionsFor('', 1, 1).length).toBeGreaterThan(0);
  });
});
