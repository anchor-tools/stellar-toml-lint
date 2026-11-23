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
import type { Diagnostic } from './types.js';

/** A replacement of `[start, end)` in the source with `text`. */
export interface OffsetTextEdit {
  start: number;
  end: number;
  text: string;
}

/** Non-overlapping edits ready to apply, in ascending offset order. */
export function computeFixEdits(source: string, diagnostics: Diagnostic[]): OffsetTextEdit[] {
  const index = new SourceIndex(source);
  const edits: OffsetTextEdit[] = [];

  for (const diagnostic of diagnostics) {
    if (!diagnostic.fix || !diagnostic.path) continue;
    const span = valueSpan(source, diagnostic.path, index);
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
 * Locates the value content for a dotted path.
 *
 * Returns offsets *inside* any surrounding quotes, so a fix never rewrites
 * the quoting style of a hand-written `stellar.toml`.
 */
function valueSpan(
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
