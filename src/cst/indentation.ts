/**
 * Indentation normalizer and style audit for `stellar.toml` (#303).
 *
 * Two halves that share one scan of the source:
 *
 * 1. **Detection & normalization** — {@link detectIndentation} reads the
 *    leading whitespace of every structural line and reports how the file is
 *    indented (two spaces, four spaces, tabs, or a mix of spaces and tabs);
 *    {@link normalizeIndentation} rewrites tab/space units into a single
 *    requested style while leaving string contents and comments untouched.
 *
 * 2. **Audit** — {@link auditIndentation} reports the two style findings the
 *    `style/*` rules surface: a file that mixes tabs and spaces for the same
 *    job (`style/mixed-indentation`), and a nested table header or key-value
 *    whose indentation does not line up with its siblings
 *    (`style/misaligned-table-key`).
 *
 * Indentation only ever appears as *trivia* in the CST — it is never part of a
 * value or a key — so the scan works from the raw source line by line (the same
 * substrate `format-file.ts` uses) while {@link normalizeIndentation} consults
 * the CST to know which lines are structural. A line inside a `"""` block or a
 * multi-line array is content, not structure, and is copied through verbatim.
 *
 * The rewrite is deliberately conservative: it changes only the whitespace that
 * introduces a structural line, never the bytes between tokens, so a file that
 * already uses the requested style round-trips byte-for-byte.
 */
import { parseCst } from './parser.js';
import type { CstDocument, CstValue } from './parser.js';
import type { Position, Severity } from '../types.js';

/** The indentation style a file is written in. */
export type IndentStyle = '2' | '4' | 'tabs';

/** All values `--format-style` accepts, in help/autocomplete order. */
export const INDENT_STYLES: readonly IndentStyle[] = ['2', '4', 'tabs'];

/** True when `value` is a style {@link normalizeIndentation} understands. */
export function isIndentStyle(value: string): value is IndentStyle {
  return (INDENT_STYLES as readonly string[]).includes(value);
}

/** The whitespace unit a style writes for one level of nesting. */
export function indentUnit(style: IndentStyle): string {
  return style === 'tabs' ? '\t' : ' '.repeat(Number(style));
}

/** What a single scan found about a file's indentation. */
export interface IndentationReport {
  /** The style the structural lines agree on, or `'mixed'` when they do not. */
  style: IndentStyle | 'mixed';
  /** The unit that occurred most often, used when no style is requested. */
  dominant: IndentStyle;
  /** True when both tabs and spaces introduce structural lines. */
  mixed: boolean;
  /** Number of structural lines indented with a leading tab. */
  tabLines: number;
  /** Number of structural lines indented with leading spaces. */
  spaceLines: number;
  /** A sample position for each finding, keyed by rule id. */
  findings: IndentationFinding[];
}

/** One audit finding, ready to become a diagnostic. */
export interface IndentationFinding {
  rule: 'style/mixed-indentation' | 'style/misaligned-table-key';
  severity: Severity;
  message: string;
  suggestion: string;
  position: Position;
  /** The indentation as written, for `--fix`-style rewrites (not emitted). */
  indent: string;
}

/**
 * Scans `source` and reports how it is indented, without changing anything.
 *
 * @param source TOML text, with or without a trailing newline.
 * @param document Optional already-parsed CST to avoid a second parse.
 */
export function detectIndentation(source: string, document?: CstDocument): IndentationReport {
  const structural = structuralLines(source, document ?? parseCst(source));
  let tabLines = 0;
  let spaceLines = 0;

  for (const line of structural) {
    if (line.indent.length === 0) continue;
    if (line.indent.startsWith('\t')) tabLines++;
    else spaceLines++;
  }

  const dominant: IndentStyle =
    tabLines > 0 && spaceLines > 0
      ? tabLines >= spaceLines
        ? 'tabs'
        : '2'
      : tabLines > 0
        ? 'tabs'
        : spaceLines > 0
          ? '2'
          : '2';

  const mixed = tabLines > 0 && spaceLines > 0;
  const style: IndentStyle | 'mixed' = mixed ? 'mixed' : tabLines > 0 ? 'tabs' : '2';

  return {
    style,
    dominant,
    mixed,
    tabLines,
    spaceLines,
    findings: auditIndentation(source, document),
  };
}

/**
 * Reports the style findings in `source`.
 *
 * @param source   TOML text.
 * @param document Optional already-parsed CST.
 */
export function auditIndentation(source: string, document?: CstDocument): IndentationFinding[] {
  const cst = document ?? parseCst(source);
  const structural = structuralLines(source, cst);
  const findings: IndentationFinding[] = [];

  const mixedLine = structural.find((line) => line.mixedUnit);
  if (mixedLine) {
    findings.push({
      rule: 'style/mixed-indentation',
      severity: 'warning',
      message: `Line ${mixedLine.line} mixes tabs and spaces in its indentation`,
      suggestion: 'Pick one indentation style for the whole file, e.g. --format-style 2.',
      position: { line: mixedLine.line, column: 1 },
      indent: mixedLine.indent,
    });
  } else if (
    structural.some((line) => line.indent.startsWith('\t')) &&
    structural.some((line) => line.indent.startsWith(' ') && line.indent.length > 0)
  ) {
    const first = structural.find((l) => l.indent.startsWith('\t'))!;
    findings.push({
      rule: 'style/mixed-indentation',
      severity: 'warning',
      message: 'The file indents some lines with tabs and others with spaces',
      suggestion: 'Normalize indentation with --format-style 2 (or 4, or tabs).',
      position: { line: first.line, column: 1 },
      indent: first.indent,
    });
  }

  // A misaligned line is only meaningful inside a nested context: a top-level
  // key or header is never indented, so there is nothing for it to line up with.
  const expected = new Map<string, { column: number; line: number }>();
  for (const line of structural) {
    if (line.indent.length === 0) {
      expected.delete(line.context);
      continue;
    }
    const sibling = expected.get(line.context);
    if (sibling === undefined) {
      expected.set(line.context, { column: line.indent.length, line: line.line });
      continue;
    }
    if (sibling.column !== line.indent.length) {
      findings.push({
        rule: 'style/misaligned-table-key',
        severity: 'warning',
        message: `Line ${line.line} is indented ${line.indent.length} columns; its siblings use ${sibling.column}`,
        suggestion: `Align it with line ${sibling.line}, or run --format-style to normalize the block.`,
        position: { line: line.line, column: 1 },
        indent: line.indent,
      });
    }
  }

  return findings;
}

/**
 * Rewrites a file's indentation into `style`, preserving everything else.
 *
 * Only the whitespace that introduces a structural line is changed; string
 * contents, comments, and the relative nesting of each level survive. Returns
 * `{ output, changed }`; `changed` is `false` when the file already matches, so
 * a caller can leave it on disk untouched.
 *
 * @param source TOML text.
 * @param style  Target style; defaults to {@link detectIndentation}'s dominant.
 */
export function normalizeIndentation(
  source: string,
  style?: IndentStyle,
): { output: string; changed: boolean } {
  const document = parseCst(source);
  const report = detectIndentation(source, document);
  const target = style ?? report.dominant;
  const unit = indentUnit(target);

  const lines = splitLines(source);
  const structural = structuralLines(source, document);
  const indentByLine = new Map(structural.map((line) => [line.line, line]));

  // Lines that share a sibling context (a table's keys, an array's members)
  // must end up at the *same* depth, so a group is normalized to one level
  // whenever any of its members is indented. This keeps a multi-line array
  // aligned instead of letting a stray extra space become a phantom level.
  const groupIndented = new Set<string>();
  for (const line of structural) {
    if (line.indent.length > 0) groupIndented.add(line.context);
  }

  let changed = false;
  const rewritten = lines.map((text, index) => {
    const line = indentByLine.get(index + 1);
    if (!line || line.indent.length === 0) return text;
    const rest = text.slice(line.indent.length);
    const replacement = groupIndented.has(line.context) ? unit : '';
    if (replacement === line.indent) return text;
    changed = true;
    return replacement + rest;
  });

  // `splitLines` drops the empty line a trailing newline produces, so put the
  // terminal newline back. Without this a clean file would lose its final \n
  // and never round-trip byte-for-byte.
  const output = rewritten.join('\n') + (source.endsWith('\n') ? '\n' : '');

  return { output, changed };
}

/** One structural line: its leading whitespace and sibling context. */
interface StructuralLine {
  /** 1-based line number. */
  line: number;
  /** Leading whitespace, tabs and spaces exactly as written. */
  indent: string;
  /** Key grouping siblings the line should align with. */
  context: string;
  /** True when a single run contains both a tab and a space. */
  mixedUnit: boolean;
}

/**
 * Finds every line whose leading whitespace is *structural* — a key-value, a
 * table header, or a member of a multi-line array — rather than the contents of
 * a string. Blank lines, comment-only lines, and the interior of `"""`/`'''`
 * blocks are skipped.
 */
function structuralLines(source: string, document: CstDocument): StructuralLine[] {
  const content = contentLines(document);
  const out: StructuralLine[] = [];

  // Walk the source with an index rather than splitting it first: on a large
  // file the split allocates one string per line, and only a structural line's
  // indentation is ever needed.
  let start = 0;
  let lineNo = 1;
  while (start <= source.length) {
    let end = source.indexOf('\n', start);
    if (end < 0) end = source.length;

    let cursor = start;
    let sawSpace = false;
    let sawTab = false;
    while (cursor < end) {
      const char = source.charCodeAt(cursor);
      if (char === 32) sawSpace = true;
      else if (char === 9) sawTab = true;
      else break;
      cursor++;
    }

    if (cursor < end && source.charCodeAt(cursor) !== 35 && content.inStructure.has(lineNo)) {
      out.push({
        line: lineNo,
        indent: source.slice(start, cursor),
        context: content.contextByLine.get(lineNo) ?? '',
        mixedUnit: sawSpace && sawTab,
      });
    }

    if (end === source.length) break;
    start = end + 1;
    lineNo++;
  }

  return out;
}

/** Per-line structural metadata derived from the CST. */
interface ContentLineInfo {
  /** Lines that hold a value token (key-value, header, or array member). */
  inStructure: Set<number>;
  /** Enclosing table/array path of each structural line, for sibling grouping. */
  contextByLine: Map<number, string>;
}

/**
 * Walks the parsed document and records, for every line, whether it carries a
 * token (as opposed to being inside a multi-line string) and what sibling
 * context it belongs to. The CST already resolved multi-line strings for us.
 */
function contentLines(document: CstDocument): ContentLineInfo {
  const source = document.source;
  const inStructure = new Set<number>();
  const contextByLine = new Map<number, string>();

  // Entries and their tokens arrive in source order, so a cursor that walks the
  // newlines once is enough to map every offset to a line. Rescanning the whole
  // source per token made the audit quadratic — a 100 KB file took over a
  // second — and even a precomputed binary search cost more than this walk.
  let cursorOffset = 0;
  let cursorLine = 1;
  let starts: number[] | undefined;
  const lineAt = (offset: number): number => {
    if (offset < cursorOffset) {
      // Never expected, but a mis-ordered token must not silently land on the
      // wrong line: fall back to an exact search built once, on demand.
      starts ??= lineStarts(source);
      return lineOfOffset(starts, offset);
    }
    while (cursorOffset < offset && cursorOffset < source.length) {
      if (source.charCodeAt(cursorOffset) === 10) cursorLine++;
      cursorOffset++;
    }
    return cursorLine;
  };

  const touch = (offset: number, context: string): void => {
    const line = lineAt(offset);
    // First writer wins so an outer token is not overwritten by a nested one.
    if (!contextByLine.has(line)) {
      inStructure.add(line);
      contextByLine.set(line, context);
    }
  };

  // Key-values align with the table they live in, so the context is the most
  // recent header (`[[CURRENCIES]]`), not the key's own path — otherwise every
  // key would be an island and nothing would ever be "misaligned".
  let table = '';
  let memberContext = '[]';
  for (const entry of document.entries) {
    if (entry.kind === 'key-value') {
      if (entry.key) touch(entry.key.start, table);
      if (entry.value) collectValueLines(entry.value, memberContext, touch);
    } else {
      const name = entry.key?.path ?? '';
      table = `${entry.kind === 'array-table' ? '[[' : '['}${name}]]`;
      memberContext = `${table}[]`;
      touch(entry.start, table);
    }
  }

  return { inStructure, contextByLine };
}

/**
 * Records the lines a value token occupies. Arrays and inline tables report
 * every element as a sibling (`context[]`), so multi-line array members align
 * with one another.
 */
function collectValueLines(
  value: CstValue,
  context: string,
  touch: (offset: number, context: string) => void,
): void {
  if (value.kind === 'array') {
    for (const item of value.items) {
      touch(item.value.start, context);
      collectValueLines(item.value, context, touch);
    }
    return;
  }
  if (value.kind === 'inline-table') {
    for (const entry of value.entries) {
      if (entry.value) {
        touch(entry.value.start, context);
        collectValueLines(entry.value, context, touch);
      }
    }
  }
}

/** Splits on `\n`, dropping a single trailing empty line from a final newline. */
function splitLines(source: string): string[] {
  const lines = source.split('\n');
  if (lines.length > 1 && lines[lines.length - 1] === '') lines.pop();
  return lines;
}

/** Offsets at which each line begins; `starts[0]` is always 0. */
function lineStarts(source: string): number[] {
  const starts = [0];
  for (let i = 0; i < source.length; i++) {
    if (source[i] === '\n') starts.push(i + 1);
  }
  return starts;
}

/**
 * 1-based line for a source offset, counting `\n` only (matches the lexer).
 * Binary-searches {@link lineStarts} so a document with many keys stays linear.
 */
function lineOfOffset(starts: readonly number[], offset: number): number {
  let low = 0;
  let high = starts.length - 1;
  while (low < high) {
    const mid = (low + high + 1) >> 1;
    if (starts[mid]! <= offset) low = mid;
    else high = mid - 1;
  }
  return low + 1;
}
