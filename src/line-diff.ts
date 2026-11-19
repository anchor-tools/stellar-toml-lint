/**
 * Line-level unified diff, used by codemods that want to show their work
 * instead of silently rewriting a file.
 *
 * Deliberately dumb about TOML: the callers change the *order* of lines rather
 * than their content, and a text diff is what a reviewer reads for that. It is
 * kept out of `src/cst/` so any future fixer can preview with the same output
 * as `git diff`.
 */

export type DiffOp = 'context' | 'added' | 'removed';

export interface DiffLine {
  op: DiffOp;
  text: string;
  /** 1-based line in the original file; 0 for a pure addition. */
  oldLine: number;
  /** 1-based line in the new file; 0 for a pure removal. */
  newLine: number;
}

export interface UnifiedDiffOptions {
  /** Context lines kept around each change. Defaults to 3, like git. */
  context?: number;
  /** Wrap `+`/`-` lines in ANSI green/red. */
  color?: boolean;
}

/** A change with no position yet: the middle of the file, before numbering. */
type BareOp = { op: DiffOp; text: string };

const MAX_LCS_CELLS = 4_000_000;

/** Split into diffable lines. A trailing newline does not become an empty line. */
export function toLines(text: string): string[] {
  const lines = text.split('\n');
  if (lines.at(-1) === '') lines.pop();
  return lines;
}

/**
 * Diff two texts line by line.
 *
 * The common prefix and suffix are trimmed first, then an LCS runs over what is
 * left, so reordering a few keys in a large file costs about as much as
 * comparing the few.
 */
export function diffLines(before: string, after: string): DiffLine[] {
  if (before === after) return [];
  const oldLines = toLines(before);
  const newLines = toLines(after);

  let head = 0;
  while (
    head < oldLines.length &&
    head < newLines.length &&
    at(oldLines, head) === at(newLines, head)
  ) {
    head++;
  }

  let tail = 0;
  while (
    tail < oldLines.length - head &&
    tail < newLines.length - head &&
    at(oldLines, oldLines.length - 1 - tail) === at(newLines, newLines.length - 1 - tail)
  ) {
    tail++;
  }

  const oldMiddle = oldLines.slice(head, oldLines.length - tail);
  const newMiddle = newLines.slice(head, newLines.length - tail);

  const lines: DiffLine[] = [];
  let oldLine = 1;
  let newLine = 1;
  const push = (op: DiffOp, text: string) => {
    if (op === 'context') lines.push({ op, text, oldLine: oldLine++, newLine: newLine++ });
    else if (op === 'removed') lines.push({ op, text, oldLine: oldLine++, newLine: 0 });
    else lines.push({ op, text, oldLine: 0, newLine: newLine++ });
  };

  for (let i = 0; i < head; i++) push('context', at(oldLines, i));
  for (const op of middleOps(oldMiddle, newMiddle)) push(op.op, op.text);
  for (let i = oldLines.length - tail; i < oldLines.length; i++) push('context', at(oldLines, i));
  return lines;
}

/** The changed region as context/added/removed ops, without line numbers. */
function middleOps(oldMiddle: string[], newMiddle: string[]): BareOp[] {
  if (oldMiddle.length === 0) return newMiddle.map((text): BareOp => ({ op: 'added', text }));
  if (newMiddle.length === 0) return oldMiddle.map((text): BareOp => ({ op: 'removed', text }));

  // Past a few million cells the table stops being worth its memory, and a
  // replace-all diff of a region this large is honest enough to read.
  if (oldMiddle.length * newMiddle.length > MAX_LCS_CELLS) {
    return [
      ...oldMiddle.map((text): BareOp => ({ op: 'removed', text })),
      ...newMiddle.map((text): BareOp => ({ op: 'added', text })),
    ];
  }

  const rows = oldMiddle.length + 1;
  const columns = newMiddle.length + 1;
  const table = new Uint32Array(rows * columns);
  const cell = (row: number, column: number) => table[row * columns + column] ?? 0;

  for (let old = rows - 2; old >= 0; old--) {
    for (let next = columns - 2; next >= 0; next--) {
      const matched =
        at(oldMiddle, old) === at(newMiddle, next)
          ? cell(old + 1, next + 1) + 1
          : Math.max(cell(old + 1, next), cell(old, next + 1));
      table[old * columns + next] = matched;
    }
  }

  const ops: BareOp[] = [];
  let old = 0;
  let next = 0;
  while (old < oldMiddle.length && next < newMiddle.length) {
    if (at(oldMiddle, old) === at(newMiddle, next)) {
      ops.push({ op: 'context', text: at(oldMiddle, old) });
      old++;
      next++;
    } else if (cell(old + 1, next) >= cell(old, next + 1)) {
      ops.push({ op: 'removed', text: at(oldMiddle, old) });
      old++;
    } else {
      ops.push({ op: 'added', text: at(newMiddle, next) });
      next++;
    }
  }
  while (old < oldMiddle.length) ops.push({ op: 'removed', text: at(oldMiddle, old++) });
  while (next < newMiddle.length) ops.push({ op: 'added', text: at(newMiddle, next++) });
  return ops;
}

/**
 * Render `before` → `after` as a unified diff for `path`, or `''` when the two
 * are identical. The header lines match git so the output pipes into a pager or
 * a GitHub suggestion block unchanged.
 */
export function formatUnifiedDiff(
  path: string,
  before: string,
  after: string,
  options: UnifiedDiffOptions = {},
): string {
  const context = options.context ?? 3;
  const lines = diffLines(before, after);
  if (lines.length === 0) return '';

  const color = options.color ?? false;
  const red = (text: string) => (color ? `\x1b[31m${text}\x1b[39m` : text);
  const green = (text: string) => (color ? `\x1b[32m${text}\x1b[39m` : text);
  const cyan = (text: string) => (color ? `\x1b[36m${text}\x1b[39m` : text);
  const bold = (text: string) => (color ? `\x1b[1m${text}\x1b[22m` : text);

  const out: string[] = [bold(`--- ${label('a', path)}`), bold(`+++ ${label('b', path)}`)];

  for (const hunk of groupIntoHunks(lines, context)) {
    const oldStart = hunk.find((line) => line.oldLine > 0)?.oldLine ?? 1;
    const newStart = hunk.find((line) => line.newLine > 0)?.newLine ?? 1;
    const oldCount = hunk.filter((line) => line.op !== 'added').length;
    const newCount = hunk.filter((line) => line.op !== 'removed').length;
    out.push(cyan(`@@ -${oldStart},${oldCount} +${newStart},${newCount} @@`));
    for (const line of hunk) {
      if (line.op === 'context') out.push(` ${line.text}`);
      else if (line.op === 'added') out.push(green(`+${line.text}`));
      else out.push(red(`-${line.text}`));
    }
  }

  return `${out.join('\n')}\n`;
}

/** Split the diff into runs of changes separated by at most `context` lines. */
function groupIntoHunks(lines: DiffLine[], context: number): DiffLine[][] {
  const changed: number[] = [];
  lines.forEach((line, index) => {
    if (line.op !== 'context') changed.push(index);
  });
  if (changed.length === 0) return [];

  const first = changed[0] ?? 0;
  let start = Math.max(0, first - context);
  let end = Math.min(lines.length, first + context + 1);
  const hunks: DiffLine[][] = [];

  for (const index of changed.slice(1)) {
    if (index - context > end) {
      hunks.push(lines.slice(start, end));
      start = Math.max(0, index - context);
    }
    end = Math.min(lines.length, index + context + 1);
  }
  hunks.push(lines.slice(start, end));
  return hunks;
}

function at(lines: string[], index: number): string {
  return lines[index] ?? '';
}

/**
 * Git prefixes diff targets with `a/` and `b/` because its paths are relative to
 * the repository root. A standalone linter is handed whatever the user typed,
 * and `a//etc/stellar.toml` is not a path anyone can paste back into a shell.
 */
function label(side: 'a' | 'b', path: string): string {
  // An absolute path is already pasteable, so prefixing `a/`/`b/` would only
  // mangle it (`a//tmp/...`). Windows drive letters and UNC shares count too,
  // even when the diff is rendered on a POSIX host (e.g. CI diffing a path
  // supplied by a Windows caller).
  const absolute = path.startsWith('/') || /^[A-Za-z]:[\\/]/.test(path) || path.startsWith('\\\\');
  return absolute ? path : `${side}/${path}`;
}
