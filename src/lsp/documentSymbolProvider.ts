/**
 * Language Server Protocol (LSP) document symbol and outline provider.
 *
 * Implements hierarchical DocumentSymbol generation conforming to LSP specification 3.17.
 * Provides outline navigation, breadcrumbs, and quick symbol search for stellar.toml.
 */
import { SourcePositions } from '../cst/lexer.js';
import { parseCst } from '../cst/parser.js';
import type { CstDocument, CstInlineTableValue, CstArrayValue } from '../cst/parser.js';
import type { LspPosition, LspRange } from './code-actions.js';

/**
 * SymbolKind enumeration conforming to LSP specification 3.17.
 */
export const SymbolKind = {
  File: 1,
  Module: 2,
  Namespace: 3,
  Package: 4,
  Class: 5,
  Method: 6,
  Property: 7,
  Field: 8,
  Constructor: 9,
  Enum: 10,
  Interface: 11,
  Function: 12,
  Variable: 13,
  Constant: 14,
  String: 15,
  Number: 16,
  Boolean: 17,
  Array: 18,
  Object: 19,
  Key: 20,
  Null: 21,
  EnumMember: 22,
  Struct: 23,
  Event: 24,
  Operator: 25,
  TypeParameter: 26,
} as const;

export type SymbolKindValue = (typeof SymbolKind)[keyof typeof SymbolKind];

export interface DocumentSymbol {
  name: string;
  detail?: string;
  kind: number;
  tags?: number[];
  deprecated?: boolean;
  range: LspRange;
  selectionRange: LspRange;
  children?: DocumentSymbol[];
}

interface DraftSymbol {
  name: string;
  detail?: string;
  kind: number;
  start: number;
  headerEnd: number;
  selectionStart: number;
  selectionEnd: number;
  children: DraftSymbol[];
  fieldsMap?: Map<string, string>;
}

export class LspDocumentSymbolProvider {
  /**
   * Generates a hierarchical outline of DocumentSymbols for a given source or CST.
   */
  public provideDocumentSymbols(sourceOrDoc: string | CstDocument): DocumentSymbol[] {
    const doc = typeof sourceOrDoc === 'string' ? parseCst(sourceOrDoc) : sourceOrDoc;
    const source = doc.source;
    const positions = new SourcePositions(source);

    const roots: DraftSymbol[] = [];
    const tableSymbols = new Map<string, DraftSymbol>();
    const arrayCounts = new Map<string, number>();

    let currentTable: DraftSymbol | undefined = undefined;

    for (const entry of doc.entries) {
      if (entry.kind === 'table' || entry.kind === 'array-table') {
        const rawPath = entry.key?.path?.trim() ?? '';
        const isAnonymous = rawPath === '';
        const tableName = isAnonymous ? '[anonymous]' : rawPath;
        const upperTable = tableName.toUpperCase();
        const keySegment = entry.key?.segments[0];

        const selectionStart = keySegment ? keySegment.start : entry.start;
        const selectionEnd = keySegment ? keySegment.end : entry.end;

        if (entry.kind === 'array-table') {
          const index = arrayCounts.get(upperTable) ?? 0;
          arrayCounts.set(upperTable, index + 1);

          let kind: number = SymbolKind.Class;
          let detail: string | undefined = `[${index}]`;

          if (upperTable === 'CURRENCIES') {
            kind = SymbolKind.Interface;
            detail = `Asset [${index}]`;
          } else if (upperTable === 'VALIDATORS') {
            kind = SymbolKind.Class;
            detail = `Node [${index}]`;
          } else if (upperTable === 'PRINCIPALS') {
            kind = SymbolKind.Class;
            detail = `Contact [${index}]`;
          }

          const symbol: DraftSymbol = {
            name: `[[${tableName}]]`,
            detail,
            kind,
            start: entry.start,
            headerEnd: entry.end,
            selectionStart,
            selectionEnd,
            children: [],
            fieldsMap: new Map(),
          };

          // Hierarchical nesting for dotted array tables
          const dot = rawPath.lastIndexOf('.');
          if (dot > 0) {
            const parentPath = rawPath.slice(0, dot).toUpperCase();
            const parent = tableSymbols.get(parentPath);
            if (parent) {
              parent.children.push(symbol);
            } else {
              roots.push(symbol);
            }
          } else {
            roots.push(symbol);
          }

          currentTable = symbol;
        } else {
          // Standard table [TABLE]
          const isNamespace =
            upperTable === 'DOCUMENTATION' ||
            upperTable.startsWith('DOCUMENTATION.') ||
            upperTable === 'FEED' ||
            upperTable === 'METRICS';
          const kind = isAnonymous
            ? SymbolKind.Class
            : isNamespace
              ? SymbolKind.Namespace
              : SymbolKind.Class;

          const symbol: DraftSymbol = {
            name: isAnonymous ? '[anonymous]' : `[${tableName}]`,
            detail: isNamespace
              ? 'SEP Section'
              : isAnonymous
                ? 'Anonymous Table'
                : 'Configuration Table',
            kind,
            start: entry.start,
            headerEnd: entry.end,
            selectionStart,
            selectionEnd,
            children: [],
            fieldsMap: new Map(),
          };

          // Dotted table hierarchy (e.g. [DOCUMENTATION.SUPPORT] under [DOCUMENTATION])
          const dot = rawPath.lastIndexOf('.');
          if (dot > 0) {
            const parentPath = rawPath.slice(0, dot).toUpperCase();
            const parent = tableSymbols.get(parentPath);
            if (parent) {
              parent.children.push(symbol);
            } else {
              roots.push(symbol);
            }
          } else {
            roots.push(symbol);
          }

          tableSymbols.set(upperTable, symbol);
          currentTable = symbol;
        }
      } else if (entry.kind === 'key-value') {
        const key = entry.key;
        if (!key) continue;

        const keyName = key.path;
        const rawValue = entry.value ? source.slice(entry.value.start, entry.value.end) : undefined;
        const cleanValue = entry.value?.kind === 'string' ? entry.value.value : rawValue;

        // Check if value is an inline table or an array of inline tables
        if (entry.value?.kind === 'inline-table') {
          const inlineSym = this.convertInlineTable(
            entry.value,
            keyName,
            key.start,
            key.end,
            source,
          );
          if (currentTable) {
            currentTable.children.push(inlineSym);
          } else {
            roots.push(inlineSym);
          }
          continue;
        } else if (entry.value?.kind === 'array') {
          const inlineArraySym = this.convertInlineArray(
            entry.value,
            keyName,
            key.start,
            key.end,
            source,
          );
          if (inlineArraySym) {
            if (currentTable) {
              currentTable.children.push(inlineArraySym);
            } else {
              roots.push(inlineArraySym);
            }
            continue;
          }
        }

        let kind: number = SymbolKind.Field;
        if (entry.value?.kind === 'string') kind = SymbolKind.String;
        else if (entry.value?.kind === 'integer' || entry.value?.kind === 'float')
          kind = SymbolKind.Number;
        else if (entry.value?.kind === 'boolean') kind = SymbolKind.Boolean;
        else if (entry.value?.kind === 'array') kind = SymbolKind.Array;

        const fieldSymbol: DraftSymbol = {
          name: keyName,
          detail: cleanValue !== undefined ? String(cleanValue) : undefined,
          kind,
          start: entry.start,
          headerEnd: entry.end,
          selectionStart: key.start,
          selectionEnd: key.end,
          children: [],
        };

        if (currentTable) {
          currentTable.children.push(fieldSymbol);
          if (cleanValue !== undefined) {
            currentTable.fieldsMap?.set(keyName.toLowerCase(), String(cleanValue));

            // Refine parent currency symbol: label with asset code and set Interface kind
            if (currentTable.kind === SymbolKind.Interface && keyName.toLowerCase() === 'code') {
              currentTable.name = String(cleanValue);
              currentTable.detail = `Currency: ${cleanValue}`;
            } else if (
              currentTable.kind === SymbolKind.Class &&
              (keyName === 'ALIAS' || keyName === 'name')
            ) {
              currentTable.detail = String(cleanValue);
            }
          }
        } else {
          roots.push(fieldSymbol);
        }
      }
    }

    // Extend range of tables to enclose their children
    const extendSymbolEnd = (sym: DraftSymbol): number => {
      let maxEnd = sym.headerEnd;
      for (const child of sym.children) {
        maxEnd = Math.max(maxEnd, extendSymbolEnd(child));
      }
      return maxEnd;
    };

    const convertPosition = (offset: number): LspPosition => {
      const p = positions.at(offset);
      return { line: p.line - 1, character: p.column - 1 };
    };

    const convertSymbol = (draft: DraftSymbol): DocumentSymbol => {
      const fullEnd = extendSymbolEnd(draft);
      return {
        name: draft.name,
        detail: draft.detail,
        kind: draft.kind,
        range: {
          start: convertPosition(draft.start),
          end: convertPosition(fullEnd),
        },
        selectionRange: {
          start: convertPosition(draft.selectionStart),
          end: convertPosition(draft.selectionEnd),
        },
        children: draft.children.length > 0 ? draft.children.map(convertSymbol) : undefined,
      };
    };

    return roots.map(convertSymbol);
  }

  private convertInlineTable(
    table: CstInlineTableValue,
    name: string,
    keyStart: number,
    keyEnd: number,
    source: string,
  ): DraftSymbol {
    const children: DraftSymbol[] = [];
    let assetCode: string | undefined;

    for (const item of table.entries) {
      if (!item.key) continue;
      const kName = item.key.path;
      const rawVal = item.value ? source.slice(item.value.start, item.value.end) : undefined;
      const cleanVal = item.value?.kind === 'string' ? item.value.value : rawVal;

      if (kName.toLowerCase() === 'code' && cleanVal) {
        assetCode = String(cleanVal);
      }

      let kind: number = SymbolKind.Field;
      if (item.value?.kind === 'string') kind = SymbolKind.String;
      else if (item.value?.kind === 'integer' || item.value?.kind === 'float')
        kind = SymbolKind.Number;
      else if (item.value?.kind === 'boolean') kind = SymbolKind.Boolean;

      children.push({
        name: kName,
        detail: cleanVal !== undefined ? String(cleanVal) : undefined,
        kind,
        start: item.key.start,
        headerEnd: item.value?.end ?? item.key.end,
        selectionStart: item.key.start,
        selectionEnd: item.key.end,
        children: [],
      });
    }

    const isCurrency = name.toUpperCase() === 'CURRENCIES' || assetCode !== undefined;
    return {
      name: assetCode ?? name,
      detail: isCurrency ? (assetCode ? `Currency: ${assetCode}` : 'Currency') : 'Inline Table',
      kind: isCurrency ? SymbolKind.Interface : SymbolKind.Object,
      start: keyStart,
      headerEnd: table.end,
      selectionStart: keyStart,
      selectionEnd: keyEnd,
      children,
    };
  }

  private convertInlineArray(
    arr: CstArrayValue,
    name: string,
    keyStart: number,
    keyEnd: number,
    source: string,
  ): DraftSymbol | undefined {
    const isCurrency = name.toUpperCase() === 'CURRENCIES';
    const inlineItems = arr.items.filter((item) => item.value.kind === 'inline-table');
    if (inlineItems.length === 0) return undefined;

    const children: DraftSymbol[] = [];
    let idx = 0;
    for (const item of inlineItems) {
      const tableVal = item.value as CstInlineTableValue;
      const childSym = this.convertInlineTable(
        tableVal,
        `${name}[${idx}]`,
        tableVal.start,
        tableVal.start + 1,
        source,
      );
      if (isCurrency && childSym.kind !== SymbolKind.Interface) {
        childSym.kind = SymbolKind.Interface;
      }
      children.push(childSym);
      idx++;
    }

    return {
      name,
      detail: isCurrency ? 'Currency Collection' : 'Inline Table Array',
      kind: SymbolKind.Array,
      start: keyStart,
      headerEnd: arr.end,
      selectionStart: keyStart,
      selectionEnd: keyEnd,
      children,
    };
  }
}
