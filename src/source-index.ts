import type { Position } from './types.js';

/** What kind of token an index entry describes. */
export type SourceEntryKind = 'key' | 'table' | 'array';

/**
 * One token in the source: its path, where it starts, and how long it is.
 *
 * The length is what lets a hover distinguish "the cursor is on `ORG_NAME`"
 * from "the cursor is on the space after it", which a start position alone
 * cannot say.
 */
export interface SourceEntry {
  /** Dotted path, e.g. `DOCUMENTATION.ORG_URL` or `CURRENCIES[0].code`. */
  path: string;
  /** 1-based line. */
  line: number;
  /** 1-based column of the token's first character. */
  column: number;
  /** Length of the token as written: the key, or the whole `[header]`. */
  length: number;
  kind: SourceEntryKind;
}

/**
 * Maps dotted value paths (`DOCUMENTATION.ORG_URL`, `CURRENCIES[1].code`) to
 * source positions.
 *
 * TOML parsers hand back plain objects with no provenance, so to point at the
 * offending line we re-scan the source and build an index. This is a
 * line-oriented scanner rather than a full parser: it tracks the current table
 * context from `[table]` / `[[array]]` headers and records the first occurrence
 * of each bare key within that context.
 *
 * Known limits, all of which degrade to "no position" rather than a wrong one:
 * inline tables (`a = { b = 1 }`) are indexed by their outer key only, and
 * multi-line array values are indexed at the line where the key appears. Both
 * are rare in real `stellar.toml` files, and a diagnostic without a position is
 * still correct — just less precise.
 */
export class SourceIndex {
  private readonly positions = new Map<string, Position>();
  private readonly entries: SourceEntry[] = [];

  constructor(source: string) {
    this.build(source);
  }

  /** Position of `path`, falling back to the nearest indexed ancestor. */
  get(path: string): Position | undefined {
    const direct = this.positions.get(path);
    if (direct) return direct;

    // Fall back to the containing table so the diagnostic still lands in the
    // right neighbourhood, e.g. `CURRENCIES[2].issuer` -> `CURRENCIES[2]`.
    let cursor = path;
    while (cursor.length > 0) {
      const cut = Math.max(cursor.lastIndexOf('.'), cursor.lastIndexOf('['));
      if (cut <= 0) break;
      cursor = cursor.slice(0, cut);
      const hit = this.positions.get(cursor);
      if (hit) return hit;
    }
    return undefined;
  }

  /**
   * The token under an editor cursor, or `undefined` for whitespace, a
   * comment, or a position past the end of the line.
   *
   * `line` and `character` are zero-based, as they arrive over LSP.
   */
  entryAt(line: number, character: number): SourceEntry | undefined {
    for (const entry of this.entries) {
      if (entry.line !== line + 1) continue;
      const start = entry.column - 1;
      if (character >= start && character < start + entry.length) return entry;
    }
    return undefined;
  }

  private build(source: string): void {
    const lines = source.split(/\r?\n/);
    // Current dotted prefix, e.g. `DOCUMENTATION` or `CURRENCIES[0]`.
    let prefix = '';
    // Next index to use for each array-of-tables name.
    const arrayCounts = new Map<string, number>();

    for (let i = 0; i < lines.length; i++) {
      const raw = lines[i] ?? '';
      const line = stripComment(raw);
      const trimmed = line.trim();
      if (trimmed === '') continue;

      const arrayHeader = /^\[\[\s*([^\]]+?)\s*\]\]$/.exec(trimmed);
      if (arrayHeader) {
        const name = unquotePath(arrayHeader[1] ?? '');
        const next = arrayCounts.get(name) ?? 0;
        arrayCounts.set(name, next + 1);
        prefix = `${name}[${next}]`;
        const column = raw.indexOf('[') + 1;
        this.positions.set(prefix, { line: i + 1, column });
        this.entries.push({
          path: prefix,
          line: i + 1,
          column,
          length: trimmed.length,
          kind: 'array',
        });
        continue;
      }

      const tableHeader = /^\[\s*([^\]]+?)\s*\]$/.exec(trimmed);
      if (tableHeader) {
        prefix = unquotePath(tableHeader[1] ?? '');
        const column = raw.indexOf('[') + 1;
        this.positions.set(prefix, { line: i + 1, column });
        this.entries.push({
          path: prefix,
          line: i + 1,
          column,
          length: trimmed.length,
          kind: 'table',
        });
        continue;
      }

      const keyValue = /^([A-Za-z0-9_\-."']+?)\s*=/.exec(trimmed);
      if (keyValue) {
        const key = unquotePath(keyValue[1] ?? '');
        const path = prefix === '' ? key : `${prefix}.${key}`;
        const column = Math.max(raw.indexOf(keyValue[1] ?? '') + 1, 1);
        if (!this.positions.has(path)) {
          this.positions.set(path, { line: i + 1, column });
        }
        this.entries.push({
          path,
          line: i + 1,
          column,
          length: (keyValue[1] ?? '').length,
          kind: 'key',
        });
      }
    }
  }
}

/**
 * Removes a trailing `#` comment, respecting quoted strings so that a `#`
 * inside a value (e.g. a URL fragment) is not mistaken for a comment.
 */
function stripComment(line: string): string {
  let inSingle = false;
  let inDouble = false;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '\\' && inDouble) {
      i++; // Skip the escaped character.
      continue;
    }
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === '"' && !inSingle) inDouble = !inDouble;
    else if (ch === '#' && !inSingle && !inDouble) return line.slice(0, i);
  }
  return line;
}

/** Strips quotes from each dot-separated segment of a TOML key path. */
function unquotePath(path: string): string {
  return path
    .split('.')
    .map((segment) => {
      const s = segment.trim();
      const quoted =
        (s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"));
      return quoted && s.length >= 2 ? s.slice(1, -1) : s;
    })
    .join('.');
}
