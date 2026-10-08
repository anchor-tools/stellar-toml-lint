import { SourcePositions } from './cst/lexer.js';
import { parseCst } from './cst/parser.js';
import type { CstDocument } from './cst/parser.js';
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
 * Positions now come straight from the {@link CstDocument} the linter already
 * parsed rather than a second line-oriented scan, so a quoted key containing a
 * dot, a multi-line array value, and an inline table all resolve correctly
 * instead of degrading to "no position". Pass a tree when you have one; when
 * you do not, this parses the source itself (recoverably, so a malformed file
 * still indexes the statements that did parse).
 *
 * `get` falls back to the nearest indexed ancestor, so a diagnostic about a
 * missing key still lands in the right table.
 */
export class SourceIndex {
  private readonly positions = new Map<string, Position>();
  private readonly entries: SourceEntry[] = [];

  constructor(source: string, document?: CstDocument) {
    this.build(document ?? parseCst(source));
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

  private build(document: CstDocument): void {
    const positions = new SourcePositions(document.source);
    // Current dotted prefix, e.g. `DOCUMENTATION` or `CURRENCIES[0]`.
    let prefix = '';
    // Next index to use for each array-of-tables name.
    const arrayCounts = new Map<string, number>();

    for (const entry of document.entries) {
      if (entry.key === null) continue;

      if (entry.kind === 'key-value') {
        const path = prefix === '' ? entry.key.path : `${prefix}.${entry.key.path}`;
        const position = positions.at(entry.key.start);
        if (!this.positions.has(path)) {
          this.positions.set(path, { line: position.line, column: position.column });
        }
        this.entries.push({
          path,
          line: position.line,
          column: position.column,
          length: entry.key.end - entry.key.start,
          kind: 'key',
        });
        continue;
      }

      const name = entry.key.path;
      if (entry.kind === 'array-table') {
        const next = arrayCounts.get(name) ?? 0;
        arrayCounts.set(name, next + 1);
        prefix = `${name}[${next}]`;
      } else {
        prefix = name;
      }

      const position = positions.at(entry.open.start);
      const end = entry.close?.end ?? entry.end;
      this.positions.set(prefix, { line: position.line, column: position.column });
      this.entries.push({
        path: prefix,
        line: position.line,
        column: position.column,
        length: end - entry.open.start,
        kind: entry.kind === 'array-table' ? 'array' : 'table',
      });
    }
  }
}
