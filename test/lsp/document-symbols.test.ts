import { describe, expect, it } from 'vitest';

import {
  DocumentSymbolKind,
  getDocumentSymbols,
} from '../../src/lsp/document-symbols.js';
import type { LspDocumentSymbol } from '../../src/lsp/document-symbols.js';

const DOC = [
  'VERSION = "2.7.0"',
  'SIGNING_KEY = "GAC2CQ7JBSRCCNZRCSJNZK5SMH4R4N5XQVQZQZQZQZQZQZQZQZQZQZQ"',
  '',
  '[DOCUMENTATION]',
  'ORG_NAME = "Example Anchor"',
  'ORG_URL = "https://example.com"',
  '',
  '[DOCUMENTATION.SUPPORT]',
  'EMAIL = "support@example.com"',
  '',
  '[[CURRENCIES]]',
  'code = "USDC"',
  'issuer = "GAC2CQ7JBSRCCNZRCSJNZK5SMH4R4N5XQVQZQZQZQZQZQZQZQZQZQZ"',
  'status = "live"',
  '',
  '[[CURRENCIES]]',
  'code = "EURC"',
  'status = "test"',
  '',
  '[[VALIDATORS]]',
  'ALIAS = "example-us-node"',
  'HOST = "stellar-core.example.com:11625"',
  '',
].join('\n');

function find(symbols: LspDocumentSymbol[], name: string): LspDocumentSymbol | undefined {
  for (const symbol of symbols) {
    if (symbol.name === name) return symbol;
    const nested = find(symbol.children ?? [], name);
    if (nested !== undefined) return nested;
  }
  return undefined;
}

describe('getDocumentSymbols', () => {
  it('returns top-level keys as fields', () => {
    const symbols = getDocumentSymbols(DOC);
    const version = find(symbols, 'VERSION');

    expect(version?.kind).toBe(DocumentSymbolKind.Field);
    expect(version?.range.start).toEqual({ line: 0, character: 0 });
  });

  it('builds namespaces for tables and nests child tables', () => {
    const documentation = find(getDocumentSymbols(DOC), 'DOCUMENTATION');
    const support = find(documentation?.children ?? [], 'SUPPORT');

    expect(documentation?.kind).toBe(DocumentSymbolKind.Namespace);
    expect(support?.kind).toBe(DocumentSymbolKind.Namespace);
    expect(support?.children?.map((child) => child.name)).toEqual(['EMAIL']);
  });

  it('labels each currency array entry with its code', () => {
    const symbols = getDocumentSymbols(DOC);
    const currency = find(symbols, 'Currency: USDC');

    expect(currency?.kind).toBe(DocumentSymbolKind.Array);
    expect(currency?.children?.map((child) => child.name)).toEqual([
      'code',
      'issuer',
      'status',
    ]);
    expect(find(symbols, 'Currency: EURC')?.kind).toBe(DocumentSymbolKind.Array);
  });

  it('labels validators with their alias and falls back to the host', () => {
    const symbols = getDocumentSymbols(DOC);
    expect(find(symbols, 'Validator: example-us-node')?.kind).toBe(
      DocumentSymbolKind.Array,
    );

    const hostOnly = getDocumentSymbols(
      ['[[VALIDATORS]]', 'HOST = "validator.example.com:11625"', ''].join('\n'),
    );
    expect(find(hostOnly, 'Validator: validator.example.com:11625')).toBeDefined();
  });

  it('gives the table range its body while the selection stays on the header', () => {
    const symbols = getDocumentSymbols(DOC);
    const documentation = find(symbols, 'DOCUMENTATION');

    expect(documentation?.selectionRange).toEqual({
      start: { line: 3, character: 0 },
      end: { line: 3, character: 15 },
    });
    expect(documentation?.range.start).toEqual({ line: 3, character: 0 });
    expect(documentation?.range.end.line).toBeGreaterThan(3);
    expect(documentation?.children?.map((child) => child.name)).toEqual([
      'ORG_NAME',
      'ORG_URL',
      'SUPPORT',
    ]);
  });

  it('handles empty and key-only documents', () => {
    expect(getDocumentSymbols('')).toEqual([]);
    expect(getDocumentSymbols('ACCOUNTS = ["G..."]\n').map((symbol) => symbol.name)).toEqual([
      'ACCOUNTS',
    ]);
  });
});
