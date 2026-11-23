/**
 * The language model both editor adapters share.
 *
 * Monaco's Monarch rules and CodeMirror's stream parser are two different
 * shapes over the same three facts: what a Stellar primitive looks like, which
 * tables SEP-1 defines, and which keys belong to each. Reading them from one
 * place means a strkey coloured by one editor is coloured by the other, and —
 * the reason the field lists come from `src/spec.ts` rather than being restated
 * here — that an editor can never suggest a field the linter does not know.
 *
 * Positions are 1-based line/column throughout, because that is what Monaco and
 * this package's own `Diagnostic` agree on. CodeMirror works in document
 * offsets, so the conversion lives here once rather than in each adapter.
 */
import {
  ANCHOR_TITLES,
  ARRAY_SECTIONS,
  FIELD_DOCS,
  HTTPS_ENDPOINT_FIELDS,
  KNOWN_CURRENCY_FIELDS,
  KNOWN_DOCUMENTATION_FIELDS,
  KNOWN_GLOBAL_FIELDS,
  KNOWN_PRINCIPAL_FIELDS,
  KNOWN_SERVER_FIELDS,
  KNOWN_VALIDATOR_FIELDS,
  fieldDoc,
  qualifiedFieldName,
  specUrl,
} from '../spec.js';
import type { FieldDoc } from '../spec.js';
import type { Diagnostic, LintResult } from '../types.js';

export const LANGUAGE_ID = 'stellar-toml';
export const LANGUAGE_NAME = 'Stellar TOML (SEP-1)';
export const LANGUAGE_ALIASES: readonly string[] = ['Stellar TOML', 'stellar-toml'];
export const FILE_EXTENSIONS: readonly string[] = ['.toml'];
export const FILENAMES: readonly string[] = ['stellar.toml'];

/**
 * Shape-only Stellar primitives, as regex sources: Monarch takes strings, and
 * the CodeMirror parser builds anchored expressions from the same text.
 *
 * The alphabet is base32 (`A-Z2-7`, so no `0`, `I`, `L` or `U`) and the lengths
 * match `syntaxes/stellar-toml.tmLanguage.json` — 56 characters for an account
 * or contract ID, 69 for a muxed one. They are deliberately *shape* checks: the
 * CRC16 checksum is verified by `src/predicates.ts` through
 * `@stellar/stellar-base`, and no syntax-highlighting bundle should pay ~146KB
 * gzip for that. A lookalike key is coloured here and reported as invalid by
 * the linter, which is the right division of labour.
 */
export const STRKEY_PATTERNS = {
  accountId: 'G[A-Z2-7]{55}',
  muxedAccountId: 'M[A-Z2-7]{68}',
  contractId: 'C[A-Z2-7]{55}',
  /**
   * Uppercase, and tighter than the linter's 1–12 characters: at 1–2, every
   * short value (`"us"`, `"no"`) would read as an asset code, and allowing
   * lowercase makes any ordinary 3–12-character string (`"Acme"`) one too.
   * SEP-1 writes asset codes in uppercase, as does the tree-sitter grammar.
   */
  assetCode: '[A-Z0-9]{3,12}',
} as const;

/** A section name the way SEP-1 writes it: `[[VALIDATORS]]`, `[DOCUMENTATION]`. */
export function tableHeaderOf(section: string): string {
  return ARRAY_SECTIONS.has(section) ? `[[${section}]]` : `[${section}]`;
}

/** Sections with their own field tables, so the grammar can colour their names. */
export const TABLE_SECTIONS: readonly string[] = [
  ...new Set(FIELD_DOCS.map((doc) => doc.section).filter((section) => section !== '')),
  'SERVERS',
];

const DOCUMENTED_TABLES = new Set(
  TABLE_SECTIONS.filter((section) =>
    FIELD_DOCS.some((doc) => doc.section === '' && doc.name === section),
  ),
);

/** Keys valid at the document root: global fields that are not tables. */
export const GLOBAL_KEYS: readonly string[] = [...KNOWN_GLOBAL_FIELDS].filter(
  (field) => !DOCUMENTED_TABLES.has(field),
);

/**
 * Which keys each section accepts.
 *
 * `SERVERS` is the one entry SEP-1 does not define: it reuses the
 * `KNOWN_SERVER_FIELDS` catalog the schema generator reads, and is named here
 * because no `FIELD_DOCS` entry would otherwise reveal the table exists.
 */
const KEY_CATALOG: Readonly<Record<string, readonly string[]>> = {
  '': GLOBAL_KEYS,
  DOCUMENTATION: [...KNOWN_DOCUMENTATION_FIELDS],
  PRINCIPALS: [...KNOWN_PRINCIPAL_FIELDS],
  CURRENCIES: [...KNOWN_CURRENCY_FIELDS],
  VALIDATORS: [...KNOWN_VALIDATOR_FIELDS],
  SERVERS: [...KNOWN_SERVER_FIELDS],
};

/** Keys a section accepts, in catalog order. Unknown sections accept none. */
export function keysOfSection(section: string): readonly string[] {
  return KEY_CATALOG[section] ?? [];
}

/** Every key across all sections, longest first so an alternation prefers it. */
export const ALL_KNOWN_KEYS: readonly string[] = [
  ...new Set(Object.values(KEY_CATALOG).flat()),
].sort((a, b) => b.length - a.length);

function alternation(values: readonly string[]): string {
  return values.map(escapeForPattern).join('|');
}

function escapeForPattern(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

const KEY_NAME = '[A-Za-z0-9_-]+';
const KEY_SEGMENT = `(?:${KEY_NAME}|"(?:[^"\\\\\\n]|\\\\.)*"|'[^'\\n]*')`;

/** A bare, quoted or dotted key. */
export const KEY_PATTERN = `${KEY_SEGMENT}(?:\\.${KEY_SEGMENT})*`;

/** A key followed by the `=` it assigns. */
export const ASSIGNED_KEY_PATTERN = `${KEY_PATTERN}(?=[ \\t]*=)`;

/** An endpoint field, coloured apart from other keys. */
export const ENDPOINT_KEY_PATTERN = `(?:${alternation(HTTPS_ENDPOINT_FIELDS)})(?=[ \\t]*=)`;

/** A key SEP-1 defines somewhere in the document. */
export const KNOWN_KEY_PATTERN = `(?:${alternation(ALL_KNOWN_KEYS)})(?=[ \\t]*=)`;

/**
 * `[section]`, with the SEP-1 names recognised separately.
 *
 * A header's content has to start like a key and cannot contain a quote, which
 * is what stops `["GAX..."]` — an array of strkeys, the most common line in a
 * real `stellar.toml` — from reading as a table header to a line-based
 * tokenizer that has no notion of the current column.
 */
const HEADER_BODY = '[A-Za-z_.][^\\]\\n"\']*';
export const TABLE_NAMES_PATTERN = `(?:${alternation(TABLE_SECTIONS)})`;
export const SEP_ARRAY_HEADER_PATTERN = `\\[\\[\\s*${TABLE_NAMES_PATTERN}\\s*\\]\\]`;
export const SEP_TABLE_HEADER_PATTERN = `\\[\\s*${TABLE_NAMES_PATTERN}\\s*\\]`;
export const ARRAY_HEADER_PATTERN = `\\[\\[${HEADER_BODY}\\]\\]`;
export const TABLE_HEADER_PATTERN = `\\[${HEADER_BODY}\\]`;

/**
 * Index of the `=` that opens a value on `line`, or `-1` when the line has none.
 *
 * A `#` or `=` inside a quoted value must not decide this, so the scan skips
 * over the body of a quoted string when it meets an opening quote. It walks the
 * line rather than masking it with a regex: the CodeQL polynomial-regex rule
 * flags a `"(?:[^"\\]|\\.)*"` scan on file input, and a single pass is both
 * linear-time and shorter than explaining why a linear-time regex is safe.
 */
export function valueStartOf(line: string): number {
  let equals = -1;
  let comment = -1;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"' || c === "'") {
      const quote = c;
      i++;
      while (i < line.length && line[i] !== quote && line[i] !== '\n') {
        // A backslash escapes the next character only inside a basic string,
        // so a literal backslash does not need its own case here: the loop
        // consumes it as `\\` and the following character as the escapee,
        // which is what TOML specifies for `'literal'` too.
        if (quote === '"' && line[i] === '\\') i++;
        i++;
      }
      continue;
    }
    if (equals < 0 && c === '=') equals = i;
    else if (comment < 0 && c === '#') comment = i;
  }
  if (equals < 0) return -1;
  if (comment >= 0 && comment < equals) return -1;
  return equals;
}

/** The table header in effect on `lineText`, or `undefined` for a non-header. */
export function headerSectionOf(lineText: string): string | undefined {
  const trimmed = lineText.trim();
  // `(.+)` greedy with a manual trim, rather than `\s*(.+?)\s*` — the lazy body
  // inside two whitespace runs lets the engine split a run of spaces any way it
  // likes, which is what a scanner reading an untrusted file should not do.
  const array = /^\[\[(.+)\]\]$/.exec(trimmed);
  const table = /^\[(.+)\]$/.exec(trimmed);
  const raw = (array?.[1] ?? table?.[1])?.trim();
  if (raw === undefined || raw === '') return undefined;
  return (raw.split('.')[0] ?? raw).replace(/^["']|["']$/g, '');
}

/**
 * The section a cursor on `lineNumber` (1-based, that line included) sits in;
 * `''` is the document root.
 */
export function sectionAt(content: string, lineNumber: number): string {
  const lines = content.split('\n');
  let section = '';
  for (let index = 0; index < Math.min(lineNumber, lines.length); index++) {
    const header = headerSectionOf(lines[index] ?? '');
    if (header !== undefined) section = header;
  }
  return section;
}

/** Keys already written in a single table, so suggestions skip duplicates. */
export function definedKeysInSection(content: string, section: string): Set<string> {
  const defined = new Set<string>();
  let current = '';

  for (const line of content.split('\n')) {
    const header = headerSectionOf(line);
    if (header !== undefined) {
      current = header;
      continue;
    }
    if (current !== section) continue;

    const equals = valueStartOf(line);
    if (equals < 0) continue;
    const key = line.slice(0, equals).trim();
    if (key !== '') defined.add(key.replace(/^["']|["']$/g, ''));
  }

  return defined;
}

/** A lint result, or a bare diagnostic list from any transport. */
export type DiagnosticSource = LintResult | readonly Diagnostic[];

/** Which part of the document a cursor is completing. */
export type CompletionContext = 'key' | 'table' | 'value';

/** One editor-agnostic completion; adapters map it to Monaco or CodeMirror. */
export interface CompletionSuggestion {
  label: string;
  insertText: string;
  context: CompletionContext;
  /** SEP-1's "Requirements" column, e.g. `string`, `optional string`. */
  detail?: string;
  /** The same Markdown the language server's hover shows for this field. */
  documentation?: string;
  helpUri?: string;
}

export interface CompletionQuery {
  content: string;
  /** 1-based. */
  lineNumber: number;
  /** 1-based. */
  column: number;
}

/**
 * SEP-1 completions for one cursor position.
 *
 * Three shapes, decided in this order: a cursor past the `=` gets the values
 * SEP-1 enumerates for that key (`[[CURRENCIES]].status` → `live`), a cursor
 * after `[` or `[[` gets the table headers, and anywhere else on a line gets
 * that section's keys. Every candidate comes from `src/spec.ts`, so a
 * suggestion and a rule can never disagree.
 */
export function completeStellarToml(query: CompletionQuery): CompletionSuggestion[] {
  const line = query.content.split('\n')[query.lineNumber - 1] ?? '';
  const before = line.slice(0, query.column - 1);

  const equals = valueStartOf(before);
  if (equals >= 0) return valueSuggestions(query, before, equals);
  if (/^\s*\[{1,2}\s*[A-Za-z0-9_]*$/.test(before)) return tableSuggestions(before);
  return keySuggestions(query);
}

function valueSuggestions(
  query: CompletionQuery,
  before: string,
  equals: number,
): CompletionSuggestion[] {
  const section = sectionAt(query.content, query.lineNumber);
  const key = before
    .slice(0, equals)
    .trim()
    .replace(/^["']|["']$/g, '');
  const doc = fieldDoc(section, key);
  if (doc === undefined) return [];

  return (doc.values ?? []).map((value) => ({
    label: value,
    insertText: value,
    context: 'value' as const,
    detail: doc.type,
    documentation: renderDoc(qualifiedFieldName(section, key), doc),
    helpUri: specUrl(doc.anchor),
  }));
}

function tableSuggestions(before: string): CompletionSuggestion[] {
  const array = /^\s*\[\[/.test(before);

  return TABLE_SECTIONS.filter((section) => array === ARRAY_SECTIONS.has(section)).map(
    (section) => {
      const header = tableHeaderOf(section);
      const doc = FIELD_DOCS.find((entry) => entry.section === '' && entry.name === section);
      return {
        label: header,
        insertText: header,
        context: 'table' as const,
        detail: doc?.type,
        documentation: doc === undefined ? undefined : renderDoc(header, doc),
        helpUri: doc === undefined ? undefined : specUrl(doc.anchor),
      };
    },
  );
}

function keySuggestions(query: CompletionQuery): CompletionSuggestion[] {
  const section = sectionAt(query.content, query.lineNumber);
  // Array-of-tables sections repeat their keys entry by entry, so only a
  // single table has anything useful to deduplicate.
  const defined = ARRAY_SECTIONS.has(section)
    ? new Set<string>()
    : definedKeysInSection(query.content, section);

  return keysOfSection(section)
    .filter((key) => !defined.has(key))
    .map((key) => {
      const doc = fieldDoc(section, key);
      return {
        label: key,
        insertText: key,
        context: 'key' as const,
        detail: doc?.type,
        documentation:
          doc === undefined ? undefined : renderDoc(qualifiedFieldName(section, key), doc),
        helpUri: doc === undefined ? undefined : specUrl(doc.anchor),
      };
    });
}

/**
 * The tooltip Markdown for one field, in the same shape `src/lsp/hover.ts`
 * renders, so a completion and a hover never describe a field differently.
 */
export function fieldDocumentation(section: string, name: string): string | undefined {
  const doc = fieldDoc(section, name);
  if (doc === undefined) return undefined;
  return renderDoc(qualifiedFieldName(section, name), doc);
}

function renderDoc(qualified: string, doc: FieldDoc): string {
  const parts = [`\`${qualified}\``, `*${doc.type}*`, doc.description];
  const values = doc.values ?? [];
  if (values.length > 0) {
    parts.push(`**Permitted values:** ${values.map((value) => `\`${value}\``).join(', ')}`);
  }
  parts.push(`[SEP-1 — ${ANCHOR_TITLES[doc.anchor] ?? 'SEP-1'}](${specUrl(doc.anchor)})`);
  return parts.join('\n\n');
}

/**
 * The document offsets a diagnostic covers.
 *
 * A marker over `TRANSFER_SERVER` is actionable and one over a single character
 * is not, so the run of key characters at the position is measured rather than
 * assumed. A diagnostic with no position lands on line 1, as it does in the
 * Monaco package and over LSP. A position past the last line — which a stale
 * diagnostic can carry after a deletion — lands at the end of the document,
 * because an offset past the text is not a range anything can read.
 */
export function rangeOfDiagnostic(
  diagnostic: Diagnostic,
  content: string,
): { from: number; to: number } {
  const lines = content.split('\n');
  const lineIndex = (diagnostic.position?.line ?? 1) - 1;
  let from = 0;
  for (let index = 0; index < lineIndex && index < lines.length; index++) {
    from += (lines[index]?.length ?? 0) + 1;
  }
  from += Math.max((diagnostic.position?.column ?? 1) - 1, 0);
  from = Math.min(from, content.length);

  const run = /^[A-Za-z0-9_.-]+/.exec(content.slice(from))?.[0];
  return { from, to: from + Math.max(run?.length ?? 0, 1) };
}
