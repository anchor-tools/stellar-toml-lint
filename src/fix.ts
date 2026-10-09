/**
 * Mechanical fix engine — turns diagnostics that carry a {@link Fix} into
 * precise text edits.
 *
 * Shared by `--fix` (#9) and LSP code actions (#42): both need the same
 * "where is the value, and what replaces it?" answer. Edits are reported as
 * source offsets so callers can map them into LSP ranges, line/column pairs,
 * or a rewritten string without a second pass over the document.
 */
import { SourceIndex } from './source-index.js';
import type { Diagnostic, Position } from './types.js';

/** A replacement of `[start, end)` in the source with `text`. */
export interface OffsetTextEdit {
  start: number;
  end: number;
  text: string;
}

/** One non-overlapping rewrite against the original source. */
export interface TextEdit {
  /** Absolute offset of the first character replaced. */
  start: number;
  /** Absolute offset just past the last character replaced. */
  end: number;
  /** The text written in place of `source.slice(start, end)`. */
  text: string;
  /** Dotted value path the edit fixes, e.g. `NETWORK_PASSPHRASE`. */
  path: string;
  /** Rule id that produced the fix. */
  rule: string;
  /** The value as it was read from the source, for reporting. */
  old: string;
  /** The value written over it, for reporting. */
  replacement: string;
}

export interface FixResult {
  /** The source with every edit applied. */
  source: string;
  /** The edits applied, sorted by start offset. */
  edits: TextEdit[];
}

/** Non-overlapping edits ready to apply, in ascending offset order. */
export function computeFixEdits(source: string, diagnostics: Diagnostic[]): OffsetTextEdit[] {
  const index = new SourceIndex(source);
  const edits: OffsetTextEdit[] = [];

  for (const diagnostic of diagnostics) {
    if (!diagnostic.fix || !diagnostic.path) continue;
    const span = offsetValueSpan(source, diagnostic.path, index);
    if (!span) continue;
    if (source.slice(span.start, span.end) === diagnostic.fix.value) continue;
    edits.push({ start: span.start, end: span.end, text: diagnostic.fix.value });
  }

  return dedupeOverlaps(edits);
}

/** Applies {@link computeFixEdits} and returns the corrected source. */
export function applyFixes(source: string, diagnostics: Diagnostic[]): string {
  let result = source;
  for (const edit of computeFixEdits(source, diagnostics).reverse()) {
    result = result.slice(0, edit.start) + edit.text + result.slice(edit.end);
  }
  return result;
}

/**
 * Rewrites the offending spans the diagnostics point at, leaving every other
 * byte untouched.
 *
 * Diagnostics without a `fix`, without a resolvable span, or whose value
 * already matches the fix (stale diagnostics) contribute nothing.
 */
export function fix(source: string, diagnostics: Diagnostic[]): FixResult {
  const index = new SourceIndex(source);
  const lineStarts = lineStartOffsets(source);
  const edits: TextEdit[] = [];

  for (const diagnostic of diagnostics) {
    const replacement = diagnostic.fix?.value;
    const path = diagnostic.path;
    if (replacement === undefined || path === undefined) continue;

    // SourceIndex already resolved this path once for the diagnostic's
    // position; resolving again keeps the two consistent.
    const at = index.get(path);
    if (!at) continue;

    const span = valueSpan(source, lineStarts, at, path);
    if (!span) continue;

    // A stale diagnostic whose value is already correct must not produce a
    // pointless rewrite (it is also what makes a second --fix run a no-op).
    if (span.value === replacement) continue;

    edits.push({
      start: span.start,
      end: span.end,
      text: encodeValue(span.quote, replacement),
      path,
      rule: diagnostic.rule,
      old: span.value,
      replacement,
    });
  }

  const nonOverlapping = sortNonOverlapping(edits);

  let next = source;
  for (const edit of [...nonOverlapping].reverse()) {
    next = next.slice(0, edit.start) + edit.text + next.slice(edit.end);
  }
  return { source: next, edits: nonOverlapping };
}

/**
 * Locates the value content for a dotted path.
 *
 * Returns offsets *inside* any surrounding quotes, so a fix never rewrites
 * the quoting style of a hand-written `stellar.toml`.
 */
function offsetValueSpan(
  source: string,
  path: string,
  index: SourceIndex,
): { start: number; end: number } | undefined {
  const position = index.get(path);
  if (!position) return undefined;

  const lineStart = offsetOfLine(source, position.line);
  if (lineStart < 0) return undefined;

  const lineEnd = lineStart + lineLength(source, lineStart);
  const eq = source.indexOf('=', lineStart);
  if (eq < 0 || eq > lineEnd) return undefined;

  let i = eq + 1;
  while (i < lineEnd && (source[i] === ' ' || source[i] === '\t')) i++;
  if (i >= lineEnd) return undefined;

  const quote = source[i];
  if (quote === '"' || quote === "'") {
    const open = i;
    const closed = findClosingQuote(source, open, quote);
    if (closed < 0) return undefined;
    return { start: open + 1, end: closed };
  }

  let end = lineEnd;
  const comment = findBareComment(source, i, lineEnd);
  if (comment >= 0) end = comment;
  while (end > i && (source[end - 1] === ' ' || source[end - 1] === '\t')) end--;
  if (end <= i) return undefined;
  return { start: i, end };
}

/**
 * Resolves the raw span of the value for `path`, as it appears on `position`'s
 * line, together with its decoded value and the quoting style it was written in.
 *
 * Returns `undefined` whenever the span cannot be pinned down exactly — a
 * multiline string, a header rather than a key, an inline table — because a
 * wrong edit is worse than no edit.
 */
function valueSpan(
  source: string,
  lineStarts: number[],
  position: Position,
  path: string,
): { start: number; end: number; value: string; quote: string | undefined } | undefined {
  const lineStart = lineStarts[position.line - 1];
  if (lineStart === undefined) return undefined;
  const lineEnd = lineStarts[position.line] ?? source.length;

  const keyIndex = lineStart + (position.column - 1);
  const eq = source.indexOf('=', keyIndex);
  if (eq === -1 || eq >= lineEnd) return undefined;

  // SourceIndex falls back to the containing table when a path was not indexed
  // (inline tables, arrays). Guard against mistaking a table header for the
  // key by requiring the key to actually appear before the `=`.
  const key = path.split('.').pop() ?? '';
  if (key !== '' && source.slice(keyIndex, eq).indexOf(key) === -1) return undefined;

  let valueStart = eq + 1;
  while (valueStart < lineEnd && isSpace(source[valueStart] ?? '')) valueStart++;
  if (valueStart >= lineEnd) return undefined;

  const ch = source[valueStart];
  if (ch === '"') {
    if (source.startsWith('"""', valueStart)) {
      const close = source.indexOf('"""', valueStart + 3);
      if (close === -1 || close > lineEnd) return undefined;
      const content = source.slice(valueStart + 3, close);
      return { start: valueStart, end: close + 3, value: decodeBasic(content), quote: '"""' };
    }
    const end = basicEnd(source, valueStart + 1, lineEnd);
    if (end === undefined) return undefined;
    return {
      start: valueStart,
      end,
      value: decodeBasic(source.slice(valueStart + 1, end - 1)),
      quote: '"',
    };
  }

  if (ch === "'") {
    if (source.startsWith("'''", valueStart)) {
      const close = source.indexOf("'''", valueStart + 3);
      if (close === -1 || close > lineEnd) return undefined;
      return {
        start: valueStart,
        end: close + 3,
        value: source.slice(valueStart + 3, close),
        quote: "'''",
      };
    }
    const end = source.indexOf("'", valueStart + 1);
    if (end === -1 || end >= lineEnd) return undefined;
    return {
      start: valueStart,
      end: end + 1,
      value: source.slice(valueStart + 1, end),
      quote: "'",
    };
  }

  // Bare value. Inline tables and arrays are never safely rewritable here, and
  // a `#` terminates the value whether a comment follows or not.
  if (ch === '{' || ch === '[') return undefined;
  let valueEnd = valueStart;
  while (valueEnd < lineEnd && !isSpace(source[valueEnd] ?? '') && source[valueEnd] !== '#') {
    valueEnd++;
  }
  return {
    start: valueStart,
    end: valueEnd,
    value: source.slice(valueStart, valueEnd),
    quote: undefined,
  };
}

/** Index just past the closing quote of a basic string, or `undefined`. */
function basicEnd(source: string, from: number, limit: number): number | undefined {
  for (let i = from; i < limit; i++) {
    const ch = source[i] ?? '';
    if (ch === '\\') {
      i++; // Skip whatever is escaped.
      continue;
    }
    if (ch === '"') return i + 1;
  }
  return undefined;
}

/** Unescapes the TOML basic-string escapes smol-toml would have accepted. */
function decodeBasic(content: string): string {
  return content.replace(/\\(u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|.)/g, (_match, esc: string) => {
    switch (esc) {
      case 'b':
        return '\b';
      case 't':
        return '\t';
      case 'n':
        return '\n';
      case 'f':
        return '\f';
      case 'r':
        return '\r';
      case '"':
        return '"';
      case '\\':
        return '\\';
      default:
        if (/^u[0-9A-Fa-f]{4}$/.test(esc)) return String.fromCharCode(parseInt(esc.slice(1), 16));
        if (/^U[0-9A-Fa-f]{8}$/.test(esc)) {
          const code = parseInt(esc.slice(1), 16);
          return code <= 0x10ffff ? String.fromCodePoint(code) : '\uFFFD';
        }
        return _match; // Unknown escape; TOML rejects it, keep the bytes honest.
    }
  });
}

/** Quotes a value for TOML, preserving a safe single-quoted literal style. */
function encodeValue(quote: string | undefined, value: string): string {
  if (quote === "'" && !value.includes("'")) return `'${value}'`;
  return encodeBasic(value);
}

/** Writes a basic (double-quoted) TOML string, escaping control characters. */
function encodeBasic(value: string): string {
  let out = '"';
  for (const ch of value) {
    switch (ch) {
      case '"':
        out += '\\"';
        break;
      case '\\':
        out += '\\\\';
        break;
      case '\b':
        out += '\\b';
        break;
      case '\t':
        out += '\\t';
        break;
      case '\n':
        out += '\\n';
        break;
      case '\f':
        out += '\\f';
        break;
      case '\r':
        out += '\\r';
        break;
      default:
        out +=
          ch < ' ' || ch === '\x7f' ? `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}` : ch;
    }
  }
  return `${out}"`;
}

/**
 * Sorts edits by position and drops any edit that overlaps one already
 * accepted, so two rules pointing at the same span cannot double-apply.
 */
function sortNonOverlapping(edits: TextEdit[]): TextEdit[] {
  const sorted = [...edits].sort((a, b) => a.start - b.start || a.end - b.end);
  const accepted: TextEdit[] = [];
  for (const edit of sorted) {
    const last = accepted[accepted.length - 1];
    if (last !== undefined && edit.start < last.end) continue;
    accepted.push(edit);
  }
  return accepted;
}

function lineStartOffsets(source: string): number[] {
  const starts = [0];
  for (let i = 0; i < source.length; i++) {
    if (source[i] === '\n') starts.push(i + 1);
  }
  return starts;
}

function isSpace(ch: string): boolean {
  return ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n' || ch === '\f';
}

function findClosingQuote(source: string, open: number, quote: string): number {
  for (let i = open + 1; i < source.length; i++) {
    const ch = source[i];
    if (quote === '"' && ch === '\\') {
      i++;
      continue;
    }
    if (ch === quote) return i;
    if (ch === '\n') return -1;
  }
  return -1;
}

function findBareComment(source: string, from: number, to: number): number {
  for (let i = from; i < to; i++) if (source[i] === '#') return i;
  return -1;
}

function offsetOfLine(source: string, line: number): number {
  if (line < 1) return -1;
  let current = 1;
  let offset = 0;
  while (current < line) {
    const nl = source.indexOf('\n', offset);
    if (nl < 0) return -1;
    offset = nl + 1;
    current++;
  }
  return offset;
}

function lineLength(source: string, lineStart: number): number {
  const nl = source.indexOf('\n', lineStart);
  return (nl < 0 ? source.length : nl) - lineStart;
}

/**
 * Drops edits that overlap an earlier one (first diagnostic wins).
 * Two rules rewriting the same value is a bug in the rules, not something
 * to apply twice and hope.
 */
function dedupeOverlaps(edits: OffsetTextEdit[]): OffsetTextEdit[] {
  const sorted = [...edits].sort((a, b) => a.start - b.start || a.end - b.end);
  const kept: OffsetTextEdit[] = [];
  let lastEnd = -1;
  for (const edit of sorted) {
    if (edit.start < lastEnd) continue;
    kept.push(edit);
    lastEnd = edit.end;
  }
  return kept;
}
