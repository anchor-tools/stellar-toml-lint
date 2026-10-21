/**
 * Lossless Concrete Syntax Tree rewrite engine.
 *
 * The CST parser already keeps every byte of the source — trivia tokens carry
 * exact spans for whitespace, newlines, and comments — so a rewrite only has
 * to decide *which spans to replace* and leave the rest untouched. That is
 * what this module does: {@link LosslessRewriter} records offset-based edits
 * against the original source, and {@link LosslessRewriter.serialize} applies
 * them in one pass, reparses the result, and verifies that no comment was
 * dropped.
 *
 * Comment retention is a hard guarantee, not a hope. Autofix (`--fix`) and
 * programmatic mutations run through this engine (or through the same
 * offset-edit discipline), and every serialization compares the input comment
 * count with the output comment count. A mismatch emits the
 * `cst/comment-loss-detected` error, so a formatter bug surfaces as a lint
 * failure instead of as silently deleted developer documentation.
 */
import type { Diagnostic } from '../types.js';
import { parseCst } from './parser.js';
import type { CstDocument, CstEntry, CstKeyValueEntry } from './parser.js';
import { collectComments, evaluateDocument } from './visitor.js';

/** Rule id emitted when a rewrite drops a comment the source contained. */
export const COMMENT_LOSS_RULE = 'cst/comment-loss-detected';

/** One offset-based replacement against the original source. */
export interface RewriteEdit {
  /** Inclusive start offset in the original source. */
  start: number;
  /** Exclusive end offset in the original source. */
  end: number;
  /** Text written in place of `[start, end)`. */
  text: string;
}

/** What a serialized rewrite produced. */
export interface RewriteResult {
  /** The rewritten source. Byte-identical to the input when no edit was made. */
  source: string;
  /** Reparse of {@link source}; its comments are what retention was checked against. */
  document: CstDocument;
  /** The edits that were applied, in application order. */
  edits: RewriteEdit[];
  /** `cst/comment-loss-detected` when a comment was dropped; empty otherwise. */
  diagnostics: Diagnostic[];
}

/** An entry located by its fully qualified dotted path. */
interface LocatedEntry {
  entry: CstEntry;
  index: number;
  /** Fully qualified path, e.g. `CURRENCIES[0].code`. */
  path: string;
}

/**
 * Rewrites a `stellar.toml` while preserving every byte outside the edited
 * spans — comments, quoting styles, indentation, and blank lines all survive.
 *
 * Mutations are addressed by the same dotted paths the linter's diagnostics
 * use (`DOCUMENTATION.ORG_NAME`, `CURRENCIES[0].code`), so a fix proposed for
 * a diagnostic can be applied without a second path scheme. Mutations that
 * would overlap an earlier mutation are refused (the method returns `false`)
 * rather than silently corrupting the file.
 */
export class LosslessRewriter {
  readonly source: string;
  readonly document: CstDocument;
  private readonly edits: RewriteEdit[] = [];

  constructor(source: string) {
    this.source = source;
    this.document = parseCst(source);
  }

  /**
   * Replaces the value at `path` with `value`, written as raw TOML.
   *
   * `value` must be a complete TOML value as it should appear in the file —
   * `'"USD"'`, `'2'`, `'true'` — because the rewriter preserves the original
   * quoting style only when it is not asked to change the text. Everything
   * outside the value's own span (the key, `=`, surrounding whitespace, and
   * any comment on the line) is untouched.
   */
  replaceNode(path: string, value: string): boolean {
    const located = this.find(path);
    if (located === undefined || located.entry.kind !== 'key-value') return false;
    const entry: CstKeyValueEntry = located.entry;
    if (entry.value === null) return false;
    return this.edit(entry.value.start, entry.value.end, value);
  }

  /**
   * Deletes the key-value entry at `path`, keeping its comments.
   *
   * Only the entry's own tokens are removed (`[entry.start, entry.end)`).
   * Leading comments above the entry and a trailing comment on the entry's
   * line both fall outside that span and therefore remain in the file — a
   * decommissioned key loses its assignment, not the documentation beside it.
   */
  deleteNode(path: string): boolean {
    const located = this.find(path);
    if (located === undefined || located.entry.kind !== 'key-value') return false;
    return this.edit(located.entry.start, located.entry.end, '');
  }

  /**
   * Inserts `text` as a new line immediately after the entry at `path`.
   *
   * `text` should be one or more complete TOML lines without a trailing
   * newline. The insertion lands after the existing entry's trailing trivia
   * (its same-line comment and line break), so the new line starts clean and
   * the original line keeps its comment. Inserting after the last entry of a
   * table is the supported way to add a key to that table.
   */
  insertAfter(path: string, text: string): boolean {
    const located = this.find(path);
    if (located === undefined) return false;
    const insertAt = this.endOfEntryLine(located.entry);
    const prefix = insertAt > 0 && this.source.charCodeAt(insertAt - 1) === 0x0a ? '' : '\n';
    return this.edit(insertAt, insertAt, `${prefix}${text}\n`);
  }

  /**
   * Applies the recorded edits and verifies comment retention.
   *
   * The rewritten source is reparsed; if the output holds fewer comments than
   * the input, a `cst/comment-loss-detected` error is returned alongside the
   * output so the caller can refuse to write it. The result document is the
   * reparse of the output, ready for further mutation or evaluation.
   */
  serialize(): RewriteResult {
    const source = applyEdits(this.source, this.edits);
    const document = parseCst(source);
    const diagnostics: Diagnostic[] = [];

    const before = collectComments(this.document).length;
    const after = collectComments(document).length;
    if (after < before) {
      diagnostics.push({
        rule: COMMENT_LOSS_RULE,
        severity: 'error',
        category: 'file',
        message: `Rewrite dropped ${before - after} of ${before} comments from the file`,
        suggestion:
          'The rewrite engine refused to lose comments by design — this indicates a bug. ' +
          'Report it with the original file and the attempted rewrite attached.',
      });
    }

    return { source, document, edits: [...this.edits], diagnostics };
  }

  /**
   * Records an edit, refusing one that overlaps an edit already recorded.
   *
   * Overlap means the two spans share a byte: a replacement would silently
   * clobber the other edit's text when the edits are applied. An insertion
   * (a zero-width span) is refused only when it lands strictly inside another
   * edit — inserting at a boundary is harmless and used by `insertAfter`.
   */
  private edit(start: number, end: number, text: string): boolean {
    if (start > end) return false;
    for (const existing of this.edits) {
      if (start === end) {
        if (start > existing.start && start < existing.end) return false;
      } else if (start < existing.end && end > existing.start) {
        return false;
      }
    }
    this.edits.push({ start, end, text });
    return true;
  }

  /** Offset just past the entry's trailing trivia (end of its line). */
  private endOfEntryLine(entry: CstEntry): number {
    let end = entry.end;
    for (const trivia of entry.trailing) {
      if (trivia.end > end) end = trivia.end;
    }
    return end;
  }

  /** Locates the entry at a fully qualified dotted path. */
  private find(path: string): LocatedEntry | undefined {
    return findEntry(this.document, path);
  }
}

/**
 * Rewrites `source` through `mutate` and returns the serialized result.
 *
 * Convenience wrapper for the common one-shot case: parse, let the callback
 * apply whichever primitives it needs, serialize, and check comment retention.
 */
export function rewrite(
  source: string,
  mutate: (rewriter: LosslessRewriter) => void,
): RewriteResult {
  const rewriter = new LosslessRewriter(source);
  mutate(rewriter);
  return rewriter.serialize();
}

/** Number of `#` comment tokens the source contains. */
export function countComments(source: string): number {
  return collectComments(parseCst(source)).length;
}

/**
 * Checks that going from `before` to `after` kept every comment.
 *
 * Returns the `cst/comment-loss-detected` diagnostic when comments were
 * dropped, otherwise `undefined`. Exported so callers that rewrite text
 * outside {@link LosslessRewriter} — autofix, the canonical formatter — can
 * apply the same guarantee the engine applies to its own output.
 */
export function detectCommentLoss(before: string, after: string): Diagnostic | undefined {
  const input = countComments(before);
  const output = countComments(after);
  if (output >= input) return undefined;
  return {
    rule: COMMENT_LOSS_RULE,
    severity: 'error',
    category: 'file',
    message: `Rewrite dropped ${input - output} of ${input} comments from the file`,
    suggestion:
      'The rewrite engine refused to lose comments by design — this indicates a bug. ' +
      'Report it with the original file and the attempted rewrite attached.',
  };
}

/**
 * Evaluates a rewritten document, so a caller can confirm the edit produced
 * the intended data before writing it to disk.
 */
export function evaluateRewritten(result: RewriteResult): Record<string, unknown> {
  return evaluateDocument(result.document).value;
}

/** Applies edits to `source`; edits are applied last-first so offsets hold. */
function applyEdits(source: string, edits: RewriteEdit[]): string {
  if (edits.length === 0) return source;
  const ordered = [...edits].sort((a, b) => b.start - a.start || b.end - a.end);
  let out = source;
  for (const { start, end, text } of ordered) {
    out = out.slice(0, start) + text + out.slice(end);
  }
  return out;
}

/**
 * Finds the entry at a fully qualified dotted path.
 *
 * Mirrors the prefix walk `SourceIndex` uses: table headers open a scope,
 * `[[ARRAY]]` headers open `NAME[index]` scopes, and key-value entries inside
 * a scope are addressed as `SCOPE.KEY`. A bare top-level key matches itself.
 */
function findEntry(document: CstDocument, path: string): LocatedEntry | undefined {
  let prefix = '';
  const arrayCounts = new Map<string, number>();

  for (const [index, entry] of document.entries.entries()) {
    if (entry.kind === 'table' || entry.kind === 'array-table') {
      if (entry.key === null) continue;
      const name = entry.key.path;
      if (entry.kind === 'array-table') {
        const next = arrayCounts.get(name) ?? 0;
        arrayCounts.set(name, next + 1);
        prefix = `${name}[${next}]`;
      } else {
        prefix = name;
      }
      if (prefix === path) return { entry, index, path: prefix };
      continue;
    }

    if (entry.key === null) continue;
    const full = prefix === '' ? entry.key.path : `${prefix}.${entry.key.path}`;
    if (full === path) return { entry, index, path: full };
  }

  return undefined;
}
