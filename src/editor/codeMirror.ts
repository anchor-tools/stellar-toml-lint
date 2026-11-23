/**
 * CodeMirror 6 integration for `stellar.toml`.
 *
 * Two pieces, both plain data and functions: a `StreamParser`-shaped tokenizer
 * for `StreamLanguage.define`, and mappers from this package's diagnostics and
 * completions to the shapes `@codemirror/lint` and `@codemirror/autocomplete`
 * read. `StreamLanguage.define({ token, startState })` is a one-line call a
 * page makes itself — this module deliberately does not wrap it, because
 * wrapping would mean depending on `@codemirror/language`, and a language
 * bundle that pulls its own CodeMirror into a project that already has one is
 * how you end up with two editors. The structural types below are the whole
 * contract, so the page passes the returned objects straight through:
 *
 * ```ts
 * import { StreamLanguage } from '@codemirror/language';
 * import { linter, lintGutter } from '@codemirror/lint';
 * import { lintBrowser } from 'stellar-toml-lint/browser';
 * import { stellarTomlStreamParser, toCodeMirrorDiagnostics } from 'stellar-toml-lint/editor/codemirror';
 *
 * const language = StreamLanguage.define(stellarTomlStreamParser);
 * const check = linter(async (view) => {
 *   const content = view.state.doc.toString();
 *   return toCodeMirrorDiagnostics(await lintBrowser(content), content);
 * });
 * ```
 *
 * Token names are `@lezer/highlight` tag names where one exists (`keyword`,
 * `propertyName`, `string`, `number`, `bool`, `date`, `comment`, `operator`,
 * `punctuation`) so the default highlighter styles them with no
 * configuration, and dotted sub-tokens (`propertyName.sep`,
 * `string.stellar`, `string.multiline`, `keyword.sep`) for the Stellar-specific
 * cases a page will want its own colours for. An unrecognised name falls back
 * to the default face, which is why nothing here has to know which CM version
 * is loading it.
 *
 * Like the Monaco bundle, this file contains no linter core: findings arrive as
 * diagnostics from wherever the page ran them.
 */
import {
  ASSIGNED_KEY_PATTERN,
  ENDPOINT_KEY_PATTERN,
  SEP_ARRAY_HEADER_PATTERN,
  SEP_TABLE_HEADER_PATTERN,
  STRKEY_PATTERNS,
  completeStellarToml,
  headerSectionOf,
  keysOfSection,
  rangeOfDiagnostic,
} from './language.js';
import type { CompletionContext, CompletionSuggestion, DiagnosticSource } from './language.js';
import type { Diagnostic } from '../types.js';

/** The part of CodeMirror's `StringStream` this tokenizer uses. */
export interface CodeMirrorStream {
  readonly pos: number;
  readonly start: number;
  peek(): string | undefined;
  next(): string | undefined;
  match(pattern: string | RegExp, consume?: boolean): string | null;
  eatSpace(): boolean;
  skipToEnd(): void;
  sol(): boolean;
  current(): string;
}

export interface StellarTomlStreamState {
  /** Delimiter of the open multi-line string, or `null` when not inside one. */
  multiline: '"' | "'" | null;
  /** Table currently in effect, so keys are coloured per section. */
  section: string;
  /** True once the line's `=` has been consumed. */
  inValue: boolean;
}

/** The `StreamParser<State>` shape `StreamLanguage.define` expects. */
export interface CodeMirrorStreamParser {
  startState(): StellarTomlStreamState;
  copyState(state: StellarTomlStreamState): StellarTomlStreamState;
  blankLine?(state: StellarTomlStreamState): void;
  token(stream: CodeMirrorStream, state: StellarTomlStreamState): string | null;
}

/** CodeMirror's `Diagnostic`, as `@codemirror/lint` consumes it. */
export interface CodeMirrorDiagnostic {
  from: number;
  to: number;
  severity: 'error' | 'warning' | 'info';
  message: string;
  source?: string;
  /** The rule id, so a page can filter findings or offer a code action. */
  code?: string;
}

/** CodeMirror's `Completion`, as `@codemirror/autocomplete` consumes it. */
export interface CodeMirrorCompletion {
  label: string;
  type: string;
  detail?: string;
  info?: string;
}

const OWNER = 'stellar-toml-lint';

function anchored(pattern: string): RegExp {
  return new RegExp(`^(?:${pattern})`);
}

/** A quoted value holding exactly one Stellar primitive, quotes included. */
function quotedPrimitive(quote: string): RegExp {
  const strkey = [
    STRKEY_PATTERNS.accountId,
    STRKEY_PATTERNS.contractId,
    STRKEY_PATTERNS.muxedAccountId,
    STRKEY_PATTERNS.assetCode,
  ].join('|');
  return anchored(`${quote}(?:${strkey})${quote}`);
}

const HEADER_ARRAY_RE = anchored('\\[\\[\\s*[A-Za-z0-9_.-]+\\s*\\]\\]');
const HEADER_TABLE_RE = anchored('\\[\\s*[A-Za-z0-9_.-]+\\s*\\]');
/** Both header forms of a SEP-1 table, so `[[CURRENCIES]]` reads as SEP-1 too. */
const SEP_HEADER_RE = anchored(`${SEP_ARRAY_HEADER_PATTERN}|${SEP_TABLE_HEADER_PATTERN}`);
const KEY_RE = anchored(ASSIGNED_KEY_PATTERN);
const ENDPOINT_RE = anchored(ENDPOINT_KEY_PATTERN);
const BOOLEAN_RE = anchored('\\b(?:true|false)\\b');
const DATETIME_RE = anchored(
  '\\d{4}-\\d{2}-\\d{2}(?:[Tt ][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.\\d+)?(?:[Zz]|[+-][0-9]{2}:[0-9]{2})?)?',
);
const TIME_RE = anchored('[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.\\d+)?');
const SPECIAL_NUMBER_RE = anchored('[+-]?(?:inf|nan)');
const RADIX_NUMBER_RE = anchored('0x[0-9A-Fa-f_]+|0o[0-9_]+|0b[01_]+');
const NUMBER_RE = anchored('[+-]?[0-9][0-9_]*(?:\\.[0-9_]+)?(?:[eE][+-]?[0-9_]+)?');
const BASIC_PRIMITIVE_RE = quotedPrimitive('"');
const LITERAL_PRIMITIVE_RE = quotedPrimitive("'");
const ESCAPE_RE = anchored('\\\\(?:u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|.)');
const MULTILINE_PRIMITIVE_RE = anchored(
  `(?:${STRKEY_PATTERNS.accountId}|${STRKEY_PATTERNS.contractId}|${STRKEY_PATTERNS.muxedAccountId})` +
    '(?=$|[\'"\\s])',
);

export function startState(): StellarTomlStreamState {
  return { multiline: null, section: '', inValue: false };
}

export function copyState(state: StellarTomlStreamState): StellarTomlStreamState {
  return { multiline: state.multiline, section: state.section, inValue: state.inValue };
}

/**
 * An unterminated multi-line string closes at a blank line, the way TOML closes
 * it at end of file; leaving it open tints the rest of the document.
 */
export function blankLine(state: StellarTomlStreamState): void {
  state.multiline = null;
  state.inValue = false;
}

/**
 * One token, advancing `stream` as CodeMirror expects. Every path consumes at
 * least one character once whitespace has been skipped, because a stream parser
 * that does not progress is an infinite loop in the editor, not a test failure.
 */
export function token(stream: CodeMirrorStream, state: StellarTomlStreamState): string | null {
  if (stream.sol() && state.multiline === null) state.inValue = false;
  if (state.multiline !== null) return multilineToken(stream, state);
  if (stream.eatSpace()) return null;

  const next = stream.peek();
  if (next === '#') {
    stream.skipToEnd();
    return 'comment';
  }
  if (!state.inValue) return keyToken(stream, state);
  if (next === '[' || next === ']' || next === ',') {
    stream.next();
    return 'punctuation';
  }
  return valueToken(stream, state);
}

/** Headers, keys, and the `=` that opens a value. */
function keyToken(stream: CodeMirrorStream, state: StellarTomlStreamState): string | null {
  const next = stream.peek();

  if (next === '[') {
    const header = stream.match(HEADER_ARRAY_RE) ?? stream.match(HEADER_TABLE_RE);
    if (header !== null) {
      const section = headerSectionOf(header);
      if (section !== undefined) state.section = section;
      return SEP_HEADER_RE.test(header) ? 'keyword.sep' : 'keyword';
    }
  }

  if (stream.match(ENDPOINT_RE) !== null) return 'propertyName.endpoint';

  const key = stream.match(KEY_RE);
  if (key !== null) return isCatalogKey(key, state.section) ? 'propertyName.sep' : 'propertyName';

  if (stream.match('=')) {
    state.inValue = true;
    return 'operator';
  }

  // A wrapped array puts its items — and its brackets — on lines of their own,
  // where `inValue` was reset at the line start. Values are still values, so
  // they are tokenised as such rather than skipped a character at a time. This
  // is also what the Monaco grammar does, which has no notion of a column.
  if (next === '"' || next === "'") return valueToken(stream, state);
  if (next === '[' || next === ']' || next === ',') {
    stream.next();
    return 'punctuation';
  }

  stream.next();
  return null;
}

/** True when a written key is one the catalog says this section accepts. */
function isCatalogKey(key: string, section: string): boolean {
  const segment = (key.split('.').pop() ?? key).replace(/^["']|["']$/g, '');
  return keysOfSection(section).some((candidate) => candidate === segment);
}

/** Everything to the right of an `=`. */
function valueToken(stream: CodeMirrorStream, state: StellarTomlStreamState): string | null {
  if (stream.match('"""')) {
    state.multiline = '"';
    return 'string.multiline';
  }
  if (stream.match("'''")) {
    state.multiline = "'";
    return 'string.multiline';
  }
  if (stream.match(BASIC_PRIMITIVE_RE) !== null || stream.match(LITERAL_PRIMITIVE_RE) !== null) {
    return 'string.stellar';
  }
  if (stream.match('"') !== null) {
    stream.match(/(?:[^"\\\n]|\\.)*"?/);
    return 'string';
  }
  if (stream.match("'") !== null) {
    stream.match(/[^'\n]*'?/);
    return 'string';
  }
  if (stream.match(BOOLEAN_RE) !== null) return 'bool';
  if (stream.match(DATETIME_RE) !== null || stream.match(TIME_RE) !== null) return 'date';
  if (stream.match(SPECIAL_NUMBER_RE) !== null) return 'number';
  if (stream.match(RADIX_NUMBER_RE) !== null || stream.match(NUMBER_RE) !== null) return 'number';

  stream.next();
  return null;
}

/**
 * The body of a `"""` or `'''` string, across as many lines as it spans.
 *
 * Single-line strings are consumed whole instead, because CodeMirror gives a
 * stream parser no way back into a finished line and `string.escape` inside a
 * one-line TOML value is not worth carrying a state for every quote character.
 */
function multilineToken(stream: CodeMirrorStream, state: StellarTomlStreamState): string | null {
  const closer = state.multiline === '"' ? '"""' : "'''";
  if (stream.match(closer)) {
    state.multiline = null;
    state.inValue = false;
    return 'string.multiline';
  }
  if (state.multiline === '"' && stream.match(ESCAPE_RE) !== null) return 'string.escape';
  if (stream.match(MULTILINE_PRIMITIVE_RE) !== null) return 'string.stellar';

  const inBasic = state.multiline === '"';
  // A body run absorbs runs of one or two quotes — an apostrophe in prose, a
  // `""` inside text — so a sentence is one token, not five. Three quotes is
  // the closer, and the trailing `[^"']+)` requirement means a `"""` can never
  // be swallowed: the repetition stops before it and the next call sees it.
  const body = inBasic ? /[^"'\\]+(?:['"]{1,2}[^"'\\]+)*/ : /[^']+(?:'{1,2}[^']+)*/;
  if (stream.match(body) !== null) return 'string.multiline';
  if (stream.match(inBasic ? /"{1,2}/ : /'{1,2}/) !== null) return 'string.multiline';

  stream.next();
  return 'string.multiline';
}

export const stellarTomlStreamParser: CodeMirrorStreamParser = {
  startState,
  copyState,
  blankLine,
  token,
};

/**
 * Diagnostics to `@codemirror/lint` markers.
 *
 * CodeMirror wants document offsets rather than line/column, and a squiggle
 * over the whole token is what makes one actionable, so the range is measured
 * at the position instead of guessed. `severity` passes through untouched: the
 * core's three levels are already CodeMirror's three.
 */
export function toCodeMirrorDiagnostics(
  input: DiagnosticSource,
  content: string,
): CodeMirrorDiagnostic[] {
  const diagnostics: readonly Diagnostic[] = 'diagnostics' in input ? input.diagnostics : input;

  return diagnostics.map((diagnostic) => {
    const { from, to } = rangeOfDiagnostic(diagnostic, content);
    return {
      from,
      to: Math.min(to, Math.max(content.length, from)),
      severity: diagnostic.severity,
      message: diagnostic.message,
      source: OWNER,
      code: diagnostic.rule,
    };
  });
}

const CM_KIND: Readonly<Record<CompletionContext, string>> = {
  key: 'property',
  table: 'keyword',
  value: 'enum',
};

/** SEP-1 completions in the shape `@codemirror/autocomplete` reads. */
export function toCodeMirrorCompletions(
  suggestions: readonly CompletionSuggestion[],
): CodeMirrorCompletion[] {
  return suggestions.map((suggestion) => ({
    label: suggestion.label,
    type: CM_KIND[suggestion.context],
    detail: suggestion.detail,
    info: suggestion.documentation,
  }));
}

/**
 * Completions for a 1-based line and column, as CodeMirror counts them with
 * `doc.lineAt(offset)`. Pass it to `autocompletion({ override: [...] })` inside
 * a source that returns `{ from, options }`.
 */
export function completionsFor(
  content: string,
  lineNumber: number,
  column: number,
): CodeMirrorCompletion[] {
  return toCodeMirrorCompletions(completeStellarToml({ content, lineNumber, column }));
}

export type { CompletionContext, CompletionSuggestion, DiagnosticSource } from './language.js';

export default stellarTomlStreamParser;
