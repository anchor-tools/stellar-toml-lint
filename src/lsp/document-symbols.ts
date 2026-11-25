/**
 * `textDocument/documentSymbol` — the outline and breadcrumb tree for a
 * `stellar.toml`.
 *
 * Editors build their Outline view from this response. A flat list of keys is
 * technically valid but useless once a file has twenty `[[CURRENCIES]]`
 * entries, so this provider mirrors the document's structure: namespace nodes
 * for tables, array nodes for `[[CURRENCIES]]` / `[[VALIDATORS]]` entries, and
 * field nodes for the keys inside them. A value written as an inline table or a
 * list of them expands the same way, because an anchor's `TYPES` and
 * `collateral_addresses` are where the interesting detail lives.
 *
 * Positions come from the same lossless CST the linter already parsed, so a
 * symbol's range covers the statement as written, including quoted keys and
 * multi-line values.
 */
import { SourcePositions } from '../cst/lexer.js';
import { parseCst } from '../cst/parser.js';
import type {
  CstDocument,
  CstEntry,
  CstKeyValueEntry,
  CstKey,
  CstTableEntry,
  CstValue,
} from '../cst/parser.js';
import type { LspPosition, LspRange } from './code-actions.js';

/** SymbolKind values from the LSP specification. */
export const DocumentSymbolKind = {
  Namespace: 3,
  Field: 8,
  /** A `[[CURRENCIES]]` entry: one named asset a client conforms to. */
  Interface: 11,
  Array: 18,
  /** An inline table, which has no header of its own to name. */
  Object: 19,
} as const;

export interface LspDocumentSymbol {
  name: string;
  detail?: string;
  kind: number;
  range: LspRange;
  selectionRange: LspRange;
  children?: LspDocumentSymbol[];
}

/** Internal form while ranges are still offsets into the source. */
interface DraftSymbol {
  name: string;
  detail?: string;
  kind: number;
  start: number;
  headerEnd: number;
  selectionStart: number;
  selectionEnd: number;
  children: DraftSymbol[];
}

/**
 * Builds the hierarchical outline for `source`.
 *
 * The optional `document` lets a caller that already parsed the file (the LSP
 * server keeps CSTs for diagnostics) avoid parsing it a second time.
 */
export function getDocumentSymbols(
  source: string,
  document: CstDocument = parseCst(source),
): LspDocumentSymbol[] {
  const builder = new SymbolBuilder(source);
  builder.add(document.entries);
  return builder.finish();
}

/** Alias kept for callers that prefer a verb-first name. */
export const buildDocumentSymbols = getDocumentSymbols;

/** Alias matching the protocol method's noun. */
export const documentSymbolsFor = getDocumentSymbols;

class SymbolBuilder {
  private readonly positions: SourcePositions;
  private readonly roots: DraftSymbol[] = [];
  private readonly namespaces = new Map<string, DraftSymbol>();
  private readonly arrayCounts = new Map<string, number>();

  constructor(private readonly source: string) {
    this.positions = new SourcePositions(source);
  }

  add(entries: CstEntry[]): void {
    let current: DraftSymbol | undefined;
    let insideArrayEntry = false;

    for (const entry of entries) {
      if (entry.kind === 'key-value') {
        const field = this.pairOf(entry.key, entry.value, entry.start, entry.end);
        if (field === undefined) continue;
        (current?.children ?? this.roots).push(field);
        if (current !== undefined && insideArrayEntry) this.labelArrayFrom(current, entry);
        continue;
      }

      insideArrayEntry = entry.kind === 'array-table';
      current = insideArrayEntry ? this.arrayOf(entry) : this.tableOf(entry);
    }

    // Every table node spans its header plus the statements that follow it.
    // Walk bottom-up so a parent's end includes a nested table's children.
    const extend = (symbol: DraftSymbol): number => {
      let end = symbol.headerEnd;
      for (const child of symbol.children) end = Math.max(end, extend(child));
      symbol.headerEnd = end;
      return end;
    };
    for (const root of this.roots) extend(root);
  }

  finish(): LspDocumentSymbol[] {
    return this.roots.map((root) => this.render(root));
  }

  /**
   * A symbol for one `key = value`, whether it was written at the top level,
   * inside a table, or inside an inline table. `start` and `end` are whatever
   * encloses the pair: the statement for a document key, the entry itself for
   * an inline one, which has no span of its own.
   */
  private pairOf(
    key: CstKey | null,
    value: CstValue | null,
    start: number,
    end: number,
  ): DraftSymbol | undefined {
    if (key === null) return undefined;
    const name = key.path;
    if (name === '') return undefined;

    return {
      name,
      kind: valueKind(value),
      start,
      headerEnd: end,
      selectionStart: key.start,
      selectionEnd: key.end,
      children: this.childrenOf(value),
    };
  }

  /**
   * The symbols a value expands to. Only a value with members has any: an
   * `ACCOUNTS = ["GA…", "GB…"]` list gains nothing from two more nodes, while a
   * `TYPES = [{…}, {…}]` list is unreadable without them — so array elements
   * become symbols exactly when they are tables or arrays themselves.
   */
  private childrenOf(value: CstValue | null): DraftSymbol[] {
    if (value === null) return [];

    if (value.kind === 'inline-table') {
      const children: DraftSymbol[] = [];
      for (const item of value.entries) {
        const child = this.pairOf(
          item.key,
          item.value,
          item.key?.start ?? value.start,
          item.value?.end ?? item.key?.end ?? value.end,
        );
        if (child !== undefined) children.push(child);
      }
      return children;
    }

    if (value.kind === 'array') {
      const children: DraftSymbol[] = [];
      value.items.forEach((item, index) => {
        const child = this.elementOf(item.value, index);
        if (child !== undefined) children.push(child);
      });
      return children;
    }

    return [];
  }

  /**
   * One structured element of an array, numbered because an element has no key
   * to name it. The index is the element's position in the source, so a skipped
   * scalar in a mixed list does not renumber what follows it.
   */
  private elementOf(value: CstValue, index: number): DraftSymbol | undefined {
    if (value.kind !== 'inline-table' && value.kind !== 'array') return undefined;

    return {
      name: `[${index}]`,
      kind: value.kind === 'inline-table' ? DocumentSymbolKind.Object : DocumentSymbolKind.Array,
      start: value.start,
      headerEnd: value.end,
      selectionStart: value.start,
      selectionEnd: value.end,
      children: this.childrenOf(value),
    };
  }

  private tableOf(entry: CstTableEntry): DraftSymbol {
    const path = entry.key?.path ?? '';
    const name = lastName(path);
    const headerEnd = entry.close?.end ?? entry.end;
    const parent = this.parentFor(path, entry.start);

    let symbol = this.namespaces.get(path);
    if (symbol === undefined) {
      symbol = {
        name: name === '' ? '[table]' : name,
        kind: DocumentSymbolKind.Namespace,
        start: entry.start,
        headerEnd,
        selectionStart: entry.open.start,
        selectionEnd: headerEnd,
        children: [],
      };
      this.namespaces.set(path, symbol);
      (parent?.children ?? this.roots).push(symbol);
    } else {
      // Re-opening a table is invalid TOML but common while a file is being
      // edited. Extend the existing outline node instead of duplicating it.
      symbol.headerEnd = Math.max(symbol.headerEnd, headerEnd);
    }
    return symbol;
  }

  private arrayOf(entry: CstTableEntry): DraftSymbol {
    const path = entry.key?.path ?? '';
    const base = lastName(path);
    const index = this.arrayCounts.get(path) ?? 0;
    this.arrayCounts.set(path, index + 1);

    const headerEnd = entry.close?.end ?? entry.end;
    const parent = this.parentFor(path, entry.start);
    const symbol: DraftSymbol = {
      name: arrayLabel(base, index),
      // A currency entry is a named asset a client has to conform to, which is
      // what `Interface` means here; a row of any other array table is a row.
      kind: base === 'CURRENCIES' ? DocumentSymbolKind.Interface : DocumentSymbolKind.Array,
      start: entry.start,
      headerEnd,
      selectionStart: entry.open.start,
      selectionEnd: headerEnd,
      children: [],
    };
    (parent?.children ?? this.roots).push(symbol);
    return symbol;
  }

  /**
   * Returns the namespace that should contain `path`, creating namespaces for
   * dotted table headers whose parent table has not been declared yet.
   */
  private parentFor(path: string, start: number): DraftSymbol | undefined {
    const dot = path.lastIndexOf('.');
    if (dot <= 0) return undefined;
    return this.ensureNamespace(path.slice(0, dot), start);
  }

  private ensureNamespace(path: string, start: number): DraftSymbol {
    const existing = this.namespaces.get(path);
    if (existing !== undefined) return existing;

    const dot = path.lastIndexOf('.');
    const parent = dot > 0 ? this.ensureNamespace(path.slice(0, dot), start) : undefined;
    // A child table's range starts at its own header; `extend` grows the
    // synthetic parent to cover it once all entries are known.
    const synthetic: DraftSymbol = {
      name: lastName(path),
      kind: DocumentSymbolKind.Namespace,
      start,
      headerEnd: start,
      selectionStart: start,
      selectionEnd: start,
      children: [],
    };
    this.namespaces.set(path, synthetic);
    (parent?.children ?? this.roots).push(synthetic);
    return synthetic;
  }

  private labelArrayFrom(symbol: DraftSymbol, entry: CstKeyValueEntry): void {
    if (entry.key === null) return;
    const value = scalarValue(entry);
    if (value === undefined) return;

    const field = entry.key.path;
    const [, label = ''] = symbol.name.split(/:\s*/, 2);
    const placeholder = /^\d+$/.test(label);

    if (symbol.name.startsWith('Currency:') && field === 'code' && value !== '') {
      symbol.name = `Currency: ${value}`;
    } else if (symbol.name.startsWith('Validator:') && value !== '') {
      if (field === 'ALIAS' || (field === 'HOST' && placeholder)) {
        symbol.name = `Validator: ${value}`;
      }
    } else if (symbol.name.startsWith('Principal:') && value !== '') {
      if (field === 'name' || (field === 'email' && placeholder)) {
        symbol.name = `Principal: ${value}`;
      }
    }
  }

  private render(symbol: DraftSymbol): LspDocumentSymbol {
    const rendered: LspDocumentSymbol = {
      name: symbol.name,
      kind: symbol.kind,
      range: {
        start: this.position(symbol.start),
        end: this.position(symbol.headerEnd),
      },
      selectionRange: {
        start: this.position(symbol.selectionStart),
        end: this.position(symbol.selectionEnd),
      },
    };
    if (symbol.detail !== undefined) rendered.detail = symbol.detail;
    if (symbol.children.length > 0) rendered.children = symbol.children.map((c) => this.render(c));
    return rendered;
  }

  private position(offset: number): LspPosition {
    const position = this.positions.at(Math.min(offset, this.source.length));
    return { line: position.line - 1, character: position.column - 1 };
  }
}

/** Last dot-separated segment of a table path. */
function lastName(path: string): string {
  const dot = path.lastIndexOf('.');
  return dot < 0 ? path : path.slice(dot + 1);
}

/** The outline kind of a value, which decides whether it has anything to expand. */
function valueKind(value: CstValue | null): number {
  if (value?.kind === 'inline-table') return DocumentSymbolKind.Object;
  if (value?.kind === 'array') return DocumentSymbolKind.Array;
  return DocumentSymbolKind.Field;
}

/**
 * Outline label for an array-of-tables entry.
 *
 * An anonymous `[[CURRENCIES]]` is far less useful than `Currency: USDC`, and
 * a validator is usually recognised by its alias or host, so those lead with
 * the value the reader is looking for.
 */
function arrayLabel(base: string, index: number): string {
  switch (base) {
    case 'CURRENCIES':
      return `Currency: ${index}`;
    case 'VALIDATORS':
      return `Validator: ${index}`;
    case 'PRINCIPALS':
      return `Principal: ${index}`;
    case 'SERVERS':
      return `Server: ${index}`;
    default:
      return `${base}[${index}]`;
  }
}

/** A scalar as written, for labels built from a field's value. */
function scalarValue(entry: CstKeyValueEntry): string | undefined {
  const value = entry.value;
  if (value === null || value === undefined) return undefined;
  switch (value.kind) {
    case 'string':
      return value.value;
    case 'integer':
    case 'float':
    case 'datetime':
      return value.raw;
    case 'boolean':
      return String(value.value);
    default:
      return undefined;
  }
}
