/**
 * Side-by-side terminal diff renderer for `--diff --diff-style side-by-side`.
 *
 * A severity list tells a compliance officer *what* changed; it does not show
 * them the file. This renderer lines the two versions up in synchronized
 * split columns — line numbers, `-`/`+` markers, and word-level highlighting
 * inside changed lines — and folds long runs of unchanged lines to a single
 * `... N unchanged lines ...` marker so the changed regions stay on one
 * screen.
 *
 * The line alignment is a patience-style LCS: common prefix and suffix are
 * consumed first, then lines that occur exactly once on both sides anchor the
 * middle (a longest-increasing-subsequence pass), and only anchor-less gaps
 * fall back to a bounded dynamic-programming LCS. That keeps a 5,000-line
 * file cheap: real edits trim to a tiny middle, and repeated lines such as
 * blank separators never blow the DP limit.
 *
 * Colour is optional end to end: pass `color: false`, or let the default
 * honour the `NO_COLOR` environment variable, and the output contains no
 * escape sequences at all.
 */
import process from 'node:process';

/** A run of text marked as present on one side of a changed line. */
export interface Segment {
  text: string;
  changed: boolean;
}

/** One aligned row: both sides for context, one side for pure add/remove. */
interface TextCell {
  /** 1-based line number in its own file. */
  num: number;
  text: string;
  /** Word-level segments when computed; falls back to whole-line marking. */
  segments?: Segment[];
}

interface Row {
  kind: 'equal' | 'change';
  left?: TextCell;
  right?: TextCell;
}

interface FoldRow {
  kind: 'fold';
  count: number;
}

type DisplayRow = Row | FoldRow;

/** How the split view is rendered. */
export interface SplitDiffOptions {
  /** Label for the left column (the base file). */
  base?: string;
  /** Label for the right column (the target file). */
  target?: string;
  /** Coloured output; defaults to honouring `NO_COLOR`. */
  color?: boolean;
  /** Terminal width in columns; detected when omitted. */
  width?: number;
  /** Unchanged lines kept on each side of a fold (default 3). */
  context?: number;
}

/** ANSI helpers. Built from `String.fromCharCode` so lint stays regex-clean. */
const ESC = String.fromCharCode(27);
const RED = `${ESC}[31m`;
const GREEN = `${ESC}[32m`;
const DIM = `${ESC}[2m`;
const RESET = `${ESC}[0m`;

/** Cells of the fallback LCS table before it gives up and replaces wholesale. */
const LCS_CELL_LIMIT = 1_000_000;

/** Word-level LCS cells before a line falls back to whole-line marking. */
const WORD_LIMIT = 250_000;

type LineOp =
  | { kind: 'equal'; a: number; b: number }
  | { kind: 'delete'; a: number }
  | { kind: 'insert'; b: number };

/**
 * Terminal width to render for: stdout's TTY width, then `$COLUMNS`, then 80.
 *
 * Clamped to a range a split view can actually use — narrower than 40 makes
 * two columns unreadable, wider than 240 makes them a mile apart.
 */
export function detectTerminalWidth(): number {
  const fromTty = process.stdout.columns;
  const fromEnv = Number.parseInt(process.env.COLUMNS ?? '', 10);
  let width = 80;
  if (typeof fromTty === 'number' && fromTty > 0) {
    width = fromTty;
  } else if (Number.isFinite(fromEnv) && fromEnv > 0) {
    width = fromEnv;
  }
  return Math.min(Math.max(width, 40), 240);
}

/** True unless `NO_COLOR` is present and non-empty (no-color.org). */
function colorByDefault(): boolean {
  const noColor = process.env.NO_COLOR;
  return noColor === undefined || noColor === '';
}

/**
 * Renders `baseSource` and `targetSource` as synchronized split columns.
 *
 * The output is a complete block: `---`/`+++` header, the folded columnar
 * body, and an additions/deletions summary line, ending in a newline.
 */
export function renderSplitDiff(
  baseSource: string,
  targetSource: string,
  options: SplitDiffOptions = {},
): string {
  const color = options.color ?? colorByDefault();
  const width = Math.min(Math.max(options.width ?? detectTerminalWidth(), 40), 240);
  const context = Math.max(0, options.context ?? 3);

  const aLines = splitLines(baseSource);
  const bLines = splitLines(targetSource);
  const ops = computeLineOps(aLines, bLines);
  const rows = foldRows(buildRows(aLines, bLines, ops), context);

  const lines: string[] = [];
  lines.push(`${color ? RED : ''}---${color ? RESET : ''} ${options.base ?? 'a'}`);
  lines.push(`${color ? GREEN : ''}+++${color ? RESET : ''} ${options.target ?? 'b'}`);
  lines.push(...renderRows(rows, aLines.length, bLines.length, width, color));
  lines.push('');
  lines.push(summarize(rows, color));
  return `${lines.join('\n')}\n`;
}

/** Splits text into lines, normalizing CRLF and dropping the final empty line. */
function splitLines(text: string): string[] {
  const lines = text.split('\n').map((line) => (line.endsWith('\r') ? line.slice(0, -1) : line));
  if (lines.length > 0 && lines[lines.length - 1] === '') lines.pop();
  return lines;
}

// ---------------------------------------------------------------------------
// Line alignment
// ---------------------------------------------------------------------------

/** Aligns two line arrays into equal/delete/insert ops. */
function computeLineOps(a: string[], b: string[]): LineOp[] {
  const ops: LineOp[] = [];
  collectOps(a, b, 0, a.length, 0, b.length, ops);
  return ops;
}

/** Recursively aligns `a[a0..a1)` against `b[b0..b1)` into `ops`. */
function collectOps(
  a: string[],
  b: string[],
  a0: number,
  a1: number,
  b0: number,
  b1: number,
  ops: LineOp[],
): void {
  while (a0 < a1 && b0 < b1 && a[a0] === b[b0]) {
    ops.push({ kind: 'equal', a: a0, b: b0 });
    a0++;
    b0++;
  }

  const suffix: LineOp[] = [];
  while (a0 < a1 && b0 < b1 && a[a1 - 1] === b[b1 - 1]) {
    a1--;
    b1--;
    suffix.push({ kind: 'equal', a: a1, b: b1 });
  }
  suffix.reverse();

  if (a0 >= a1 || b0 >= b1) {
    for (let i = a0; i < a1; i++) ops.push({ kind: 'delete', a: i });
    for (let j = b0; j < b1; j++) ops.push({ kind: 'insert', b: j });
    ops.push(...suffix);
    return;
  }

  const anchors = findAnchors(a, b, a0, a1, b0, b1);
  if (anchors.length > 0) {
    let pa = a0;
    let pb = b0;
    for (const [ai, bi] of anchors) {
      collectOps(a, b, pa, ai, pb, bi, ops);
      ops.push({ kind: 'equal', a: ai, b: bi });
      pa = ai + 1;
      pb = bi + 1;
    }
    collectOps(a, b, pa, a1, pb, b1, ops);
    ops.push(...suffix);
    return;
  }

  if ((a1 - a0) * (b1 - b0) <= LCS_CELL_LIMIT) {
    ops.push(...lcsOps(a, b, a0, a1, b0, b1));
  } else {
    for (let i = a0; i < a1; i++) ops.push({ kind: 'delete', a: i });
    for (let j = b0; j < b1; j++) ops.push({ kind: 'insert', b: j });
  }
  ops.push(...suffix);
}

/**
 * Lines that occur exactly once in both ranges, paired and ordered.
 *
 * Unique lines are the trustworthy anchors of a patience diff: a blank line
 * or a repeated `}` matches in many places, but a unique key line matches in
 * exactly one.
 */
function findAnchors(
  a: string[],
  b: string[],
  a0: number,
  a1: number,
  b0: number,
  b1: number,
): Array<[number, number]> {
  const aCounts = new Map<string, number>();
  const aIndex = new Map<string, number>();
  for (let i = a0; i < a1; i++) {
    const line = a[i] ?? '';
    aCounts.set(line, (aCounts.get(line) ?? 0) + 1);
    aIndex.set(line, i);
  }

  const bCounts = new Map<string, number>();
  const bIndex = new Map<string, number>();
  for (let j = b0; j < b1; j++) {
    const line = b[j] ?? '';
    bCounts.set(line, (bCounts.get(line) ?? 0) + 1);
    bIndex.set(line, j);
  }

  const pairs: Array<{ a: number; b: number }> = [];
  for (const [line, ai] of aIndex) {
    if ((aCounts.get(line) ?? 0) !== 1) continue;
    if ((bCounts.get(line) ?? 0) !== 1) continue;
    const bi = bIndex.get(line);
    if (bi === undefined) continue;
    pairs.push({ a: ai, b: bi });
  }
  pairs.sort((x, y) => x.a - y.a);
  return longestIncreasing(pairs);
}

/** Longest strictly increasing subsequence on `b`, as `[a, b]` anchor pairs. */
function longestIncreasing(pairs: Array<{ a: number; b: number }>): Array<[number, number]> {
  if (pairs.length === 0) return [];

  const prev: number[] = [];
  const tails: number[] = [];
  for (let i = 0; i < pairs.length; i++) {
    const value = pairs[i]?.b ?? -1;
    let low = 0;
    let high = tails.length;
    while (low < high) {
      const mid = (low + high) >> 1;
      if ((pairs[tails[mid]]?.b ?? -1) < value) low = mid + 1;
      else high = mid;
    }
    prev[i] = low > 0 ? (tails[low - 1] ?? -1) : -1;
    if (low === tails.length) tails.push(i);
    else tails[low] = i;
  }

  const out: Array<[number, number]> = [];
  let cursor = tails.length > 0 ? (tails[tails.length - 1] ?? -1) : -1;
  while (cursor >= 0) {
    const pair = pairs[cursor];
    if (pair !== undefined) out.push([pair.a, pair.b]);
    cursor = prev[cursor] ?? -1;
  }
  out.reverse();
  return out;
}

/** Bounded dynamic-programming LCS over `a[a0..a1)` and `b[b0..b1)`. */
function lcsOps(
  a: string[],
  b: string[],
  a0: number,
  a1: number,
  b0: number,
  b1: number,
): LineOp[] {
  const n = a1 - a0;
  const m = b1 - b0;
  const width = m + 1;
  const dp = new Int32Array((n + 1) * width);

  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      const here = i * width + j;
      if (a[a0 + i] === b[b0 + j]) {
        dp[here] = (dp[(i + 1) * width + j + 1] ?? 0) + 1;
      } else {
        dp[here] = Math.max(dp[(i + 1) * width + j] ?? 0, dp[i * width + j + 1] ?? 0);
      }
    }
  }

  const ops: LineOp[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[a0 + i] === b[b0 + j]) {
      ops.push({ kind: 'equal', a: a0 + i, b: b0 + j });
      i++;
      j++;
    } else if ((dp[(i + 1) * width + j] ?? 0) >= (dp[i * width + j + 1] ?? 0)) {
      ops.push({ kind: 'delete', a: a0 + i });
      i++;
    } else {
      ops.push({ kind: 'insert', b: b0 + j });
      j++;
    }
  }
  while (i < n) {
    ops.push({ kind: 'delete', a: a0 + i });
    i++;
  }
  while (j < m) {
    ops.push({ kind: 'insert', b: b0 + j });
    j++;
  }
  return ops;
}

// ---------------------------------------------------------------------------
// Rows, word-level highlighting, folding
// ---------------------------------------------------------------------------

/** Pairs delete/insert runs into aligned rows, adding word-level segments. */
function buildRows(aLines: string[], bLines: string[], ops: LineOp[]): Row[] {
  const rows: Row[] = [];
  let i = 0;

  while (i < ops.length) {
    const op = ops[i];
    if (op === undefined) break;

    if (op.kind === 'equal') {
      rows.push({
        kind: 'equal',
        left: { num: op.a + 1, text: aLines[op.a] ?? '' },
        right: { num: op.b + 1, text: bLines[op.b] ?? '' },
      });
      i++;
      continue;
    }

    const deletions: number[] = [];
    const insertions: number[] = [];
    while (i < ops.length) {
      const next = ops[i];
      if (next?.kind === 'delete') deletions.push(next.a);
      else if (next?.kind === 'insert') insertions.push(next.b);
      else break;
      i++;
    }

    const depth = Math.max(deletions.length, insertions.length);
    for (let k = 0; k < depth; k++) {
      const aIndex = deletions[k];
      const bIndex = insertions[k];
      const left: TextCell | undefined =
        aIndex === undefined ? undefined : { num: aIndex + 1, text: aLines[aIndex] ?? '' };
      const right: TextCell | undefined =
        bIndex === undefined ? undefined : { num: bIndex + 1, text: bLines[bIndex] ?? '' };

      if (left !== undefined && right !== undefined) {
        const words = wordDiff(left.text, right.text);
        if (words !== undefined) {
          left.segments = words.left;
          right.segments = words.right;
        }
      }
      rows.push({ kind: 'change', left, right });
    }
  }

  return rows;
}

/**
 * Word-level diff of one changed line pair.
 *
 * Returns `undefined` when the line is too wordy for the DP to be worth it,
 * in which case the caller marks the whole line instead.
 */
function wordDiff(
  before: string,
  after: string,
): { left: Segment[]; right: Segment[] } | undefined {
  const a = before.match(/\S+|\s+/g) ?? [];
  const b = after.match(/\S+|\s+/g) ?? [];
  if (a.length * b.length > WORD_LIMIT) return undefined;

  const ops = lcsOps(a, b, 0, a.length, 0, b.length);
  const left: Segment[] = [];
  const right: Segment[] = [];
  for (const op of ops) {
    if (op.kind === 'equal') {
      const text = a[op.a] ?? '';
      left.push({ text, changed: false });
      right.push({ text: b[op.b] ?? '', changed: false });
    } else if (op.kind === 'delete') {
      left.push({ text: a[op.a] ?? '', changed: true });
    } else {
      right.push({ text: b[op.b] ?? '', changed: true });
    }
  }
  return { left: mergeSegments(left), right: mergeSegments(right) };
}

/** Collapses adjacent segments that share a changed flag. */
function mergeSegments(segments: Segment[]): Segment[] {
  const out: Segment[] = [];
  for (const segment of segments) {
    const last = out[out.length - 1];
    if (last !== undefined && last.changed === segment.changed) last.text += segment.text;
    else out.push({ ...segment });
  }
  return out;
}

/**
 * Replaces long equal runs with a single fold marker, keeping `context`
 * unchanged lines on each side so the change stays anchored to its location.
 */
function foldRows(rows: Row[], context: number): DisplayRow[] {
  const out: DisplayRow[] = [];
  let i = 0;

  while (i < rows.length) {
    if (rows[i]?.kind !== 'equal') {
      const row = rows[i];
      if (row !== undefined) out.push(row);
      i++;
      continue;
    }

    let end = i;
    while (end < rows.length && rows[end]?.kind === 'equal') end++;
    const runLength = end - i;

    if (runLength > 2 * context + 2) {
      for (let k = i; k < i + context; k++) {
        const row = rows[k];
        if (row !== undefined) out.push(row);
      }
      out.push({ kind: 'fold', count: runLength - 2 * context });
      for (let k = end - context; k < end; k++) {
        const row = rows[k];
        if (row !== undefined) out.push(row);
      }
    } else {
      for (let k = i; k < end; k++) {
        const row = rows[k];
        if (row !== undefined) out.push(row);
      }
    }
    i = end;
  }

  return out;
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/** Lays out folded rows as split columns, wrapping content to the width. */
function renderRows(
  rows: DisplayRow[],
  aLength: number,
  bLength: number,
  width: number,
  color: boolean,
): string[] {
  const numWidth = String(Math.max(aLength, bLength, 1)).length;
  const gutter = numWidth + 2;
  const contentWidth = Math.max(8, Math.floor((width - 2 * gutter - 3) / 2));
  const out: string[] = [];

  for (const row of rows) {
    if (row.kind === 'fold') {
      const text = `... ${row.count} unchanged lines ...`;
      out.push(color ? `${DIM}${text}${RESET}` : text);
      continue;
    }

    const leftChunks =
      row.left === undefined ? [] : wrapSegments(segmentsOf(row.left, row.kind), contentWidth);
    const rightChunks =
      row.right === undefined ? [] : wrapSegments(segmentsOf(row.right, row.kind), contentWidth);
    const depth = Math.max(1, leftChunks.length, rightChunks.length);

    for (let s = 0; s < depth; s++) {
      const leftLine = renderSide(
        row.left,
        leftChunks[s],
        s,
        'left',
        row.kind,
        numWidth,
        contentWidth,
        color,
      );
      const rightLine = renderSide(
        row.right,
        rightChunks[s],
        s,
        'right',
        row.kind,
        numWidth,
        contentWidth,
        color,
      );
      out.push(`${leftLine} | ${rightLine}`);
    }
  }

  return out;
}

/** Cell content as segments: word-level when present, whole-line otherwise. */
function segmentsOf(cell: TextCell, kind: 'equal' | 'change'): Segment[] {
  if (cell.segments !== undefined) return cell.segments;
  return [{ text: cell.text, changed: kind === 'change' }];
}

/** One column of one wrapped sub-line: number, marker, content, padding. */
function renderSide(
  cell: TextCell | undefined,
  chunk: Segment[] | undefined,
  subLine: number,
  side: 'left' | 'right',
  kind: 'equal' | 'change',
  numWidth: number,
  contentWidth: number,
  color: boolean,
): string {
  let number = ' '.repeat(numWidth);
  if (subLine === 0 && cell !== undefined) {
    number = String(cell.num).padStart(numWidth);
  }
  const paintedNumber = color && number.trim() !== '' ? `${DIM}${number}${RESET}` : number;

  const present = cell !== undefined && chunk !== undefined && subLine === 0 ? cell : undefined;
  const marker = present === undefined || kind !== 'change' ? ' ' : side === 'left' ? '-' : '+';
  let paintedMarker = marker;
  if (color && marker !== ' ') paintedMarker = `${side === 'left' ? RED : GREEN}${marker}${RESET}`;

  const text = chunk === undefined ? '' : paintSegments(chunk, side, color);
  const visible = chunk === undefined ? 0 : chunkWidth(chunk);
  const padding = ' '.repeat(Math.max(0, contentWidth - visible));

  return `${paintedNumber} ${paintedMarker}${text}${padding}`;
}

/** Visible width of a segment run (segments carry no escapes themselves). */
function chunkWidth(chunk: Segment[]): number {
  let width = 0;
  for (const segment of chunk) width += segment.text.length;
  return width;
}

/** Joins segments, colouring only the changed ones. */
function paintSegments(chunk: Segment[], side: 'left' | 'right', color: boolean): string {
  if (!color) return chunk.map((segment) => segment.text).join('');
  const tint = side === 'left' ? RED : GREEN;
  return chunk
    .map((segment) => (segment.changed ? `${tint}${segment.text}${RESET}` : segment.text))
    .join('');
}

/** Wraps segments into lines of at most `width` visible characters. */
function wrapSegments(segments: Segment[], width: number): Segment[][] {
  const lines: Segment[][] = [];
  let current: Segment[] = [];
  let used = 0;

  for (const segment of segments) {
    let text = segment.text;
    while (text.length > 0) {
      if (used >= width) {
        lines.push(current);
        current = [];
        used = 0;
      }
      const room = width - used;
      if (text.length <= room) {
        if (text.length > 0) current.push({ text, changed: segment.changed });
        used += text.length;
        text = '';
      } else {
        current.push({ text: text.slice(0, room), changed: segment.changed });
        text = text.slice(room);
        lines.push(current);
        current = [];
        used = 0;
      }
    }
  }

  if (current.length > 0 || lines.length === 0) lines.push(current);
  return lines;
}

/** Footer counts: `N insertions(+), M deletions(-), K unchanged`. */
function summarize(rows: DisplayRow[], color: boolean): string {
  let added = 0;
  let removed = 0;
  let unchanged = 0;
  for (const row of rows) {
    if (row.kind === 'fold') {
      unchanged += row.count;
      continue;
    }
    if (row.kind === 'equal') unchanged++;
    else {
      if (row.right !== undefined) added++;
      if (row.left !== undefined) removed++;
    }
  }

  const plus = `${added} insertions(+)`;
  const minus = `${removed} deletions(-)`;
  const tail = `${unchanged} unchanged`;
  if (!color) return `${plus}, ${minus}, ${tail}`;
  return `${GREEN}${plus}${RESET}, ${RED}${minus}${RESET}, ${tail}`;
}
