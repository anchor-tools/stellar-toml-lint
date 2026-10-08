/**
 * `textDocument/hover` — SEP-1 field documentation under the cursor.
 *
 * The mapping is deliberately two stages: the line scanner in
 * {@link SourceIndex} answers "which token sits under this position", and
 * {@link fieldDoc} answers "what does SEP-1 say about that token". Keeping the
 * two apart means the hover handler never parses TOML itself and never guesses
 * at positions — and it gives the same answer on a key, on a table header, and
 * on nothing at all.
 */
import { SourceIndex } from '../source-index.js';
import type { SourceEntry } from '../source-index.js';
import { ANCHOR_TITLES, fieldDoc, qualifiedFieldName, specUrl } from '../spec.js';
import type { FieldDoc } from '../spec.js';

/** Zero-based, as positions arrive over LSP. */
export interface HoverPosition {
  line: number;
  character: number;
}

export interface HoverRange {
  start: HoverPosition;
  end: HoverPosition;
}

export interface Hover {
  contents: { kind: 'markdown'; value: string };
  /** The token the tooltip was computed for, so the editor can highlight it. */
  range: HoverRange;
}

/**
 * Builds the hover tooltip for `position`, or `null` when the cursor is on
 * whitespace, a comment, an unknown key, or past the end of the document.
 */
export function getHoverInfo(doc: string, position: HoverPosition): Hover | null {
  const entry = new SourceIndex(doc).entryAt(position.line, position.character);
  if (entry === undefined) return null;

  const { section, name, qualified } = locate(entry);
  const field = fieldDoc(section, name);
  if (field === undefined) return null;

  const start = { line: entry.line - 1, character: entry.column - 1 };
  const end = { line: start.line, character: start.character + entry.length };

  return {
    contents: { kind: 'markdown', value: render(field, qualified) },
    range: { start, end },
  };
}

/**
 * Splits an indexed path into the SEP-1 section, the field's own name, and the
 * name to put in the tooltip's heading.
 *
 * `CURRENCIES[0].status` is a field of the `[[CURRENCIES]]` list, while the
 * bare `CURRENCIES[0]` (or `DOCUMENTATION`) is the table header itself — which
 * documents the section rather than a field inside it, so it is written out
 * with its brackets.
 */
function locate(entry: SourceEntry): { section: string; name: string; qualified: string } {
  if (entry.kind !== 'key') {
    const name = entry.path.replace(/\[\d+\]$/, '');
    return { section: '', name, qualified: entry.kind === 'array' ? `[[${name}]]` : `[${name}]` };
  }

  const path = entry.path.replace(/\[\d+\]/g, '');
  const dot = path.indexOf('.');
  if (dot < 0) return { section: '', name: path, qualified: path };
  const section = path.slice(0, dot);
  const name = path.slice(dot + 1);
  return { section, name, qualified: qualifiedFieldName(section, name) };
}

/** Renders the Markdown document the editor shows. */
function render(field: FieldDoc, qualified: string): string {
  const parts = [`\`${qualified}\``, `*${field.type}*`, field.description];

  if (field.values !== undefined && field.values.length > 0) {
    const values = field.values.map((value) => `\`${value}\``).join(', ');
    parts.push(`**Permitted values:** ${values}`);
  }

  const title = ANCHOR_TITLES[field.anchor] ?? 'SEP-1';
  parts.push(`[SEP-1 — ${title}](${specUrl(field.anchor)})`);
  return parts.join('\n\n');
}
