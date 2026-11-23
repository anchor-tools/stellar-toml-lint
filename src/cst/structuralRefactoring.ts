/**
 * CST-guided structural refactoring for large stellar.toml files.
 *
 * Duplicated `[[CURRENCIES]]` entries are easy to create in multi-team anchors
 * and dangerous to merge by hand: comments get lost and conflicting metadata
 * quietly disappears. This module works on the lossless CST from
 * {@link ./parser.js}, so comments and formatting survive a merge, and it
 * validates the refactored tree before handing it back.
 *
 * No remote calls and no writes happen here — the CLI decides what to do with
 * the generated text and diff.
 */
import {
  parseCst,
  printCst,
  type CstDocument,
  type CstKeyValueEntry,
  type CstTableEntry,
} from './parser.js';

export interface FieldConflict {
  field: string;
  kept: string;
  discarded: string;
  /** 1-based source line of the discarded value. */
  line: number;
}

export interface AssetDuplicateGroup {
  code: string;
  issuer: string;
  /** 1-based source lines of the merged declarations. */
  lines: number[];
  conflicts: FieldConflict[];
  commentsRetained: number;
}

export interface RefactorValidation {
  ok: boolean;
  errors: string[];
  originalCurrencies: number;
  refactoredCurrencies: number;
  /** Fields intentionally discarded because they conflicted. */
  discardedFields: string[];
}

export interface RefactorResult {
  original: string;
  source: string;
  groups: AssetDuplicateGroup[];
  duplicateCount: number;
  diff: string;
  validation: RefactorValidation;
}

export interface SplitOptions {
  /** Soft limit for each emitted file. Default 64 KiB. */
  maxBytes?: number;
  /** Prefix for generated filenames. Default `stellar`. */
  baseName?: string;
}

export interface PartialFile {
  name: string;
  source: string;
}

export interface SplitResult {
  files: PartialFile[];
  validation: RefactorValidation;
}

interface FieldInfo {
  name: string;
  normalized: string;
  entry: CstKeyValueEntry;
}

interface TableBlock {
  index: number;
  header: CstTableEntry;
  /** Start of this table's own leading trivia (comments included). */
  leadingStart: number;
  start: number;
  end: number;
  text: string;
}

interface CurrencyEntry {
  block: TableBlock;
  code: string;
  issuer: string;
  fields: Map<string, FieldInfo>;
  headerComments: string;
}

function isTableEntry(entry: { kind: string }): entry is CstTableEntry {
  return entry.kind === 'table' || entry.kind === 'array-table';
}

function lineAt(source: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset; i++) if (source[i] === '\n') line++;
  return line;
}

function blocksOf(document: CstDocument): TableBlock[] {
  const tables = document.entries.filter(isTableEntry);
  return tables.map((header, index) => {
    const next = tables[index + 1];
    const leadingStart = next?.leading[0]?.start ?? next?.start ?? document.end;
    const end = Math.max(leadingStart, header.end);
    return {
      index: document.entries.indexOf(header),
      header,
      leadingStart: header.leading[0]?.start ?? header.start,
      start: header.start,
      end,
      text: document.source.slice(header.start, end),
    };
  });
}

function normalizedValue(field: CstKeyValueEntry): string {
  const value = field.value;
  if (value === null) return '';
  return value.kind === 'string' ? value.value : 'raw' in value ? value.raw : '';
}

function fieldsOf(
  document: CstDocument,
  block: TableBlock,
  nextIndex: number,
): Map<string, FieldInfo> {
  const fields = new Map<string, FieldInfo>();
  for (let index = block.index + 1; index < nextIndex; index++) {
    const entry = document.entries[index];
    if (entry === undefined || entry.kind !== 'key-value' || entry.key === null) continue;
    const name = entry.key.path;
    fields.set(name, { name, normalized: normalizedValue(entry), entry });
  }
  return fields;
}

function currencyEntries(document: CstDocument, blocks: TableBlock[]): CurrencyEntry[] {
  const entries: CurrencyEntry[] = [];
  for (const [index, block] of blocks.entries()) {
    if (block.header.kind !== 'array-table' || block.header.key?.path !== 'CURRENCIES') continue;
    const nextIndex = blocks[index + 1]?.index ?? document.entries.length;
    const fields = fieldsOf(document, block, nextIndex);
    const code = fields.get('code')?.normalized;
    const issuer = fields.get('issuer')?.normalized;
    if (code === undefined || issuer === undefined || code === '' || issuer === '') continue;
    entries.push({
      block,
      code,
      issuer,
      fields,
      headerComments: block.header.leadingComments.map((comment) => `${comment.text}\n`).join(''),
    });
  }
  return entries;
}

function fieldText(source: string, field: FieldInfo): string {
  return `${source.slice(field.entry.start, field.entry.end)}\n`;
}

/** All comments attached to a field, in source order. */
function fieldComments(field: FieldInfo): string[] {
  const comments = field.entry.leadingComments.map((comment) => comment.text);
  if (field.entry.trailingComment !== undefined) {
    comments.push(`# ${field.entry.trailingComment.text.replace(/^#\s*/, '')}`);
  }
  return comments;
}

function quote(value: string): string {
  return JSON.stringify(value);
}

/**
 * Merges duplicate `[[CURRENCIES]]` tables while retaining every comment.
 * Conflicting fields keep the canonical value and are recorded in
 * {@link AssetDuplicateGroup.conflicts} and as `# refactor:` comments.
 */
export function deduplicateAssets(source: string): RefactorResult {
  const document = parseCst(source);
  const blocks = blocksOf(document);
  const currencies = currencyEntries(document, blocks);
  const groups: AssetDuplicateGroup[] = [];
  const replacements = new Map<number, string>();
  const discardedFields: string[] = [];
  const byKey = new Map<string, CurrencyEntry[]>();

  for (const entry of currencies) {
    const key = `${entry.code}\u0000${entry.issuer}`;
    const group = byKey.get(key) ?? [];
    group.push(entry);
    byKey.set(key, group);
  }

  for (const group of byKey.values()) {
    if (group.length < 2) continue;
    const canonical = group[0];
    if (canonical === undefined) continue;
    const duplicates = group.slice(1);
    const conflicts: FieldConflict[] = [];
    const commentLines: string[] = [];
    const appended: string[] = [];
    let commentsRetained = 0;

    for (const duplicate of duplicates) {
      const duplicateLine = lineAt(source, duplicate.block.start);
      if (duplicate.headerComments.trim() !== '') {
        commentLines.push(...duplicate.headerComments.trimEnd().split('\n'));
        commentsRetained += duplicate.headerComments.trimEnd().split('\n').length;
      }
      for (const field of duplicate.fields.values()) {
        if (field.name === 'code' || field.name === 'issuer') continue;
        const existing = canonical.fields.get(field.name);
        const ownComments = fieldComments(field);
        commentsRetained += ownComments.length;
        if (existing === undefined) {
          appended.push(
            `${ownComments.join('\n')}${ownComments.length > 0 ? '\n' : ''}${fieldText(source, field)}`,
          );
          continue;
        }
        if (existing.normalized === field.normalized) {
          commentLines.push(...ownComments);
          continue;
        }
        conflicts.push({
          field: field.name,
          kept: existing.normalized,
          discarded: field.normalized,
          line: duplicateLine,
        });
        discardedFields.push(
          `${canonical.code}\u0000${canonical.issuer}\u0000${field.name}\u0000${field.normalized}`,
        );
        commentLines.push(...ownComments);
        commentLines.push(
          `# refactor: conflict for ${field.name} at line ${duplicateLine}: kept ${quote(existing.normalized)}, discarded ${quote(field.normalized)}`,
        );
      }
      replacements.set(duplicate.block.start, '');
    }

    let merged = source.slice(canonical.block.start, canonical.block.end);
    if (!merged.endsWith('\n')) merged += '\n';
    if (commentLines.length > 0) merged += `${commentLines.join('\n')}\n`;
    merged += appended.join('');
    replacements.set(canonical.block.start, merged);

    groups.push({
      code: canonical.code,
      issuer: canonical.issuer,
      lines: group.map((entry) => lineAt(source, entry.block.start)),
      conflicts,
      commentsRetained,
    });
  }

  let refactored = '';
  let cursor = 0;
  for (const block of blocks) {
    refactored += source.slice(cursor, block.leadingStart);
    const replacement = replacements.get(block.start);
    if (replacement === undefined) {
      refactored += source.slice(block.leadingStart, block.end);
    } else {
      // A duplicate loses its whole leading trivia with the table; its
      // comments were moved into the canonical block above.
      refactored +=
        replacement === '' ? '' : source.slice(block.leadingStart, block.start) + replacement;
    }
    cursor = block.end;
  }
  refactored += source.slice(cursor);

  const validation = validateMerge(source, refactored, groups, discardedFields);
  return {
    original: source,
    source: refactored,
    groups,
    duplicateCount: groups.reduce((sum, group) => sum + group.lines.length - 1, 0),
    diff: diffText(source, refactored),
    validation,
  };
}

function currencyCounts(source: string): Map<string, number> {
  const document = parseCst(source);
  const blocks = blocksOf(document);
  const counts = new Map<string, number>();
  for (const entry of currencyEntries(document, blocks)) {
    const key = `${entry.code}\u0000${entry.issuer}`;
    const countKey = `CURRENCIES:${key}`;
    counts.set(countKey, (counts.get(countKey) ?? 0) + 1);
    for (const field of entry.fields.values()) {
      if (field.name === 'code' || field.name === 'issuer') continue;
      const fieldKey = `FIELD:${key}\u0000${field.name}\u0000${field.normalized}`;
      counts.set(fieldKey, (counts.get(fieldKey) ?? 0) + 1);
    }
  }
  return counts;
}

function validateMerge(
  originalSource: string,
  refactoredSource: string,
  groups: AssetDuplicateGroup[],
  discardedFields: string[],
): RefactorValidation {
  const errors: string[] = [];
  const originalDoc = parseCst(originalSource);
  const refactoredDoc = parseCst(refactoredSource);
  for (const error of refactoredDoc.errors) {
    errors.push(`line ${error.line}: ${error.message}`);
  }
  const original = currencyCounts(originalSource);
  const refactored = currencyCounts(refactoredSource);
  const discarded = new Set(discardedFields.map((field) => `FIELD:${field}`));

  for (const [key, count] of original) {
    if (key.startsWith('CURRENCIES:')) continue;
    if (discarded.has(key)) continue;
    if ((refactored.get(key) ?? 0) < count) {
      errors.push(`value lost during refactoring: ${key.replaceAll('\u0000', ' ')}`);
    }
  }

  const originalKeys = new Set([...original.keys()].filter((key) => key.startsWith('CURRENCIES:')));
  const refactoredKeys = new Set(
    [...refactored.keys()].filter((key) => key.startsWith('CURRENCIES:')),
  );
  for (const key of originalKeys) {
    if (!refactoredKeys.has(key)) errors.push(`currency ${key.split('\u0000')[1]} was removed`);
  }

  // Round-tripping the tree must reproduce the text we produced.
  if (printCst(refactoredDoc) !== refactoredSource) {
    errors.push('refactored source does not round-trip through the CST');
  }

  const originalCount = originalDoc.entries.filter(
    (entry) => isTableEntry(entry) && entry.key?.path === 'CURRENCIES',
  ).length;
  const refactoredCount = refactoredDoc.entries.filter(
    (entry) => isTableEntry(entry) && entry.key?.path === 'CURRENCIES',
  ).length;
  const expected = originalCount - groups.reduce((sum, group) => sum + group.lines.length - 1, 0);
  if (refactoredCount !== expected) {
    errors.push(`expected ${expected} CURRENCIES tables, found ${refactoredCount}`);
  }

  return {
    ok: errors.length === 0,
    errors,
    originalCurrencies: originalCount,
    refactoredCurrencies: refactoredCount,
    discardedFields,
  };
}

/** Splits a file into modular partials, grouped by table. */
export function splitLargeFile(source: string, options: SplitOptions = {}): SplitResult {
  const maxBytes = options.maxBytes ?? 64 * 1024;
  const baseName = options.baseName ?? 'stellar';
  const document = parseCst(source);
  const blocks = blocksOf(document);
  const headerEnd = blocks[0]?.leadingStart ?? source.length;
  const preamble = source.slice(0, headerEnd);
  const buckets = new Map<string, string[]>();

  const nameFor = (path: string): string => {
    const map: Record<string, string> = {
      CURRENCIES: 'currencies',
      VALIDATORS: 'validators',
      PRINCIPALS: 'principals',
      SERVERS: 'servers',
      DOCUMENTATION: 'documentation',
    };
    return map[path] ?? 'base';
  };

  const push = (bucket: string, text: string): void => {
    const list = buckets.get(bucket) ?? [];
    list.push(text);
    buckets.set(bucket, list);
  };

  if (preamble.trim() !== '') push('base', preamble);
  for (const block of blocks) {
    const bucket = nameFor(block.header.key?.path ?? 'base');
    push(bucket, source.slice(block.leadingStart, block.end));
  }

  const files: PartialFile[] = [];
  for (const [bucket, pieces] of buckets) {
    let chunk = '';
    let part = 1;
    for (const piece of pieces) {
      if (chunk !== '' && Buffer.byteLength(chunk + piece, 'utf8') > maxBytes) {
        files.push({
          name: `${baseName}.${bucket}${part > 1 ? `-${part}` : ''}.toml`,
          source: chunk,
        });
        chunk = '';
        part++;
      }
      chunk += piece;
    }
    if (chunk.trim() !== '') {
      files.push({
        name: `${baseName}.${bucket}${part > 1 ? `-${part}` : ''}.toml`,
        source: chunk,
      });
    }
  }

  const combined = files.map((file) => file.source).join('\n');
  const originalCounts = currencyCounts(source);
  const splitCounts = currencyCounts(combined);
  const errors: string[] = [];
  for (const error of parseCst(combined).errors) errors.push(`split parse error: ${error.message}`);
  for (const [key, count] of originalCounts) {
    if ((splitCounts.get(key) ?? 0) !== count) {
      errors.push(`split lost ${key.replaceAll('\u0000', ' ')}`);
    }
  }

  return {
    files,
    validation: {
      ok: errors.length === 0,
      errors,
      originalCurrencies: originalCounts.size,
      refactoredCurrencies: splitCounts.size,
      discardedFields: [],
    },
  };
}

/** LCS-based unified diff for terminal review. */
export function diffText(original: string, revised: string): string {
  const before = original.split('\n');
  const after = revised.split('\n');
  const rows: number[][] = Array.from({ length: before.length + 1 }, () =>
    Array<number>(after.length + 1).fill(0),
  );
  for (let i = before.length - 1; i >= 0; i--) {
    for (let j = after.length - 1; j >= 0; j--) {
      rows[i]![j] =
        before[i] === after[j]
          ? (rows[i + 1]![j + 1] ?? 0) + 1
          : Math.max(rows[i + 1]![j] ?? 0, rows[i]![j + 1] ?? 0);
    }
  }

  type Change = { kind: ' ' | '-' | '+'; text: string; oldLine: number; newLine: number };
  const changes: Change[] = [];
  let i = 0;
  let j = 0;
  while (i < before.length || j < after.length) {
    if (i < before.length && j < after.length && before[i] === after[j]) {
      changes.push({ kind: ' ', text: before[i] ?? '', oldLine: i + 1, newLine: j + 1 });
      i++;
      j++;
    } else if (
      j < after.length &&
      (i >= before.length || (rows[i]![j + 1] ?? 0) >= (rows[i + 1]![j] ?? 0))
    ) {
      changes.push({ kind: '+', text: after[j] ?? '', oldLine: i + 1, newLine: j + 1 });
      j++;
    } else {
      changes.push({ kind: '-', text: before[i] ?? '', oldLine: i + 1, newLine: j + 1 });
      i++;
    }
  }

  const changed = changes.filter((change) => change.kind !== ' ');
  if (changed.length === 0) return '--- original\n+++ refactored\n(no changes)\n';

  const lines = ['--- original', '+++ refactored'];
  let hunk: Change[] = [];
  const flush = (): void => {
    if (hunk.length === 0) return;
    const first = hunk[0]!;
    const last = hunk[hunk.length - 1]!;
    lines.push(
      `@@ -${first.oldLine},${last.oldLine - first.oldLine + 1} +${first.newLine},${last.newLine - first.newLine + 1} @@`,
    );
    for (const change of hunk) lines.push(`${change.kind}${change.text}`);
    hunk = [];
  };

  for (const [index, change] of changes.entries()) {
    const distance =
      changes[index - 1] === undefined ? 0 : change.oldLine - (changes[index - 1]?.oldLine ?? 0);
    if (hunk.length > 0 && distance > 7) flush();
    if (change.kind !== ' ') hunk.push(change);
    else if (hunk.length > 0) hunk.push(change);
  }
  flush();
  return `${lines.join('\n')}\n`;
}

/** Text summary printed by the CLI before the diff. */
export function renderRefactorSummary(result: RefactorResult): string {
  const lines = [
    `Duplicate asset groups: ${result.groups.length}`,
    `Duplicates removed: ${result.duplicateCount}`,
    `Comments retained: ${result.groups.reduce((sum, group) => sum + group.commentsRetained, 0)}`,
    `Validation: ${result.validation.ok ? 'passed (zero data loss)' : `FAILED (${result.validation.errors.join('; ')})`}`,
  ];
  for (const group of result.groups) {
    lines.push(
      `  ${group.code} / ${group.issuer} merged from lines ${group.lines.join(', ')}` +
        (group.conflicts.length > 0
          ? ` — ${group.conflicts.length} conflict(s): ${group.conflicts.map((conflict) => conflict.field).join(', ')}`
          : ''),
    );
  }
  return `${lines.join('\n')}\n`;
}

/** Facade used by the CLI and embedders. */
export class StructuralRefactoringEngine {
  private readonly source: string;

  constructor(source: string) {
    this.source = source;
  }

  deduplicateAssets(): RefactorResult {
    return deduplicateAssets(this.source);
  }

  split(options: SplitOptions = {}): SplitResult {
    return splitLargeFile(this.source, options);
  }

  diff(refactored: string): string {
    return diffText(this.source, refactored);
  }
}
