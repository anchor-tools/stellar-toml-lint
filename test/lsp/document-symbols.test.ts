import { readFileSync } from 'node:fs';
import { PassThrough } from 'node:stream';

import { describe, expect, it } from 'vitest';

import { DocumentSymbolKind, getDocumentSymbols } from '../../src/lsp/document-symbols.js';
import type { LspDocumentSymbol } from '../../src/lsp/document-symbols.js';
import { runLspServer } from '../../src/lsp/server.js';
import type { LspPosition, LspRange } from '../../src/lsp/code-actions.js';

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

function offsetOf(source: string, position: LspPosition): number {
  const lines = source.split('\n');
  let offset = 0;
  for (let line = 0; line < position.line; line++) offset += (lines[line] ?? '').length + 1;
  return offset + position.character;
}

/** The text a range covers — the plainest way to say a node *is* that table. */
function textOf(source: string, range: LspRange | undefined): string {
  if (range === undefined) return '';
  return source.slice(offsetOf(source, range.start), offsetOf(source, range.end));
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

  it('labels each currency entry with its code and calls it an interface', () => {
    const symbols = getDocumentSymbols(DOC);
    const currency = find(symbols, 'Currency: USDC');

    expect(currency?.kind).toBe(DocumentSymbolKind.Interface);
    expect(currency?.children?.map((child) => child.name)).toEqual(['code', 'issuer', 'status']);
    expect(find(symbols, 'Currency: EURC')?.kind).toBe(DocumentSymbolKind.Interface);
  });

  it('labels validators with their alias and falls back to the host', () => {
    const symbols = getDocumentSymbols(DOC);
    expect(find(symbols, 'Validator: example-us-node')?.kind).toBe(DocumentSymbolKind.Array);

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

  it('outlines half-written statements instead of failing them', () => {
    // A client asks for the outline on every keystroke, so a value with no key
    // or an empty key has to cost a node rather than the whole response.
    expect(getDocumentSymbols('= 5\n')).toEqual([]);
    expect(getDocumentSymbols('"" = 1\n')).toEqual([]);

    // A key the anchor has not given a value yet is still a key it means to
    // fill in, so it keeps its place in the outline.
    const symbols = getDocumentSymbols('bar = { A = 1, B, C = 2 }\n');

    expect(find(symbols, 'bar')?.children?.map((child) => child.name)).toEqual(['A', 'B', 'C']);
    expect(find(symbols, 'bar')?.children?.[1]?.kind).toBe(DocumentSymbolKind.Field);
  });

  it('labels every array table the SEP-1 catalogue names', () => {
    const symbols = getDocumentSymbols(
      [
        '[[PRINCIPALS]]',
        'name = "Jane Doe"',
        'email = "jane@example.com"',
        '',
        '[[SERVERS]]',
        'host = "horizon.example.com"',
        '',
        '[[THRESHOLDS]]',
        'low_threshold = 1',
        'medium_threshold = 2',
        '',
      ].join('\n'),
    );

    expect(symbols.map((symbol) => symbol.name)).toEqual([
      'Principal: Jane Doe',
      'Server: 0',
      'THRESHOLDS[0]',
    ]);
  });

  it('grows one node when an anchor re-opens a table mid-edit', () => {
    const symbols = getDocumentSymbols('[A]\nx = 1\n\n[A]\ny = 2\n');
    const table = find(symbols, 'A');

    expect(symbols).toHaveLength(1);
    expect(table?.children?.map((child) => child.name)).toEqual(['x', 'y']);
    expect(table?.range.end.line).toBe(4);
  });

  it('reads a currency label from a scalar and ignores the ones around it', () => {
    const symbols = getDocumentSymbols(
      [
        '[[CURRENCIES]]',
        'code = "USDC"',
        'collateral_addresses = ["GAC2CQ7JBSRCCNZRCSJNZK5SMH4R4N5XQVQZQZQZQ"]',
        'issued = 2024-05-17T07:32:00Z',
        'precision = 7',
        'live = true',
        '',
      ].join('\n'),
    );
    const currency = find(symbols, 'Currency: USDC');

    expect(currency?.children?.map((child) => child.name)).toEqual([
      'code',
      'collateral_addresses',
      'issued',
      'precision',
      'live',
    ]);
  });
});

/**
 * An outline is only useful if a value written on one line expands the same way
 * a header does: `TYPES`, `collateral_accounts` and an inline `SUPPORT` table
 * are where an anchor actually puts its detail.
 */
describe('getDocumentSymbols over inline values', () => {
  const INLINE = [
    'VERSION = "2.7.0"',
    'ACCOUNTS = ["GAAA", "GBBB"]',
    'TYPES = [{asset = "iso4217:USD", price = "https://x.example/1", status = "test"},',
    '         {asset = "domestic:check", price = "https://x.example/2"}]',
    '',
    '[DOCUMENTATION]',
    'SUPPORT = { EMAIL = "support@example.com", PHONE = "+15551234567" }',
    '',
  ].join('\n');

  it('expands an inline table into the fields it declares', () => {
    const symbols = getDocumentSymbols(INLINE);
    const support = find(symbols, 'SUPPORT');
    const email = find(symbols, 'EMAIL');

    expect(support?.kind).toBe(DocumentSymbolKind.Object);
    expect(support?.children?.map((child) => child.name)).toEqual(['EMAIL', 'PHONE']);
    // The table's own range is the statement; a member's is the pair inside it.
    expect(textOf(INLINE, support?.range)).toBe(
      'SUPPORT = { EMAIL = "support@example.com", PHONE = "+15551234567" }',
    );
    expect(textOf(INLINE, email?.range)).toBe('EMAIL = "support@example.com"');
    expect(textOf(INLINE, email?.selectionRange)).toBe('EMAIL');
  });

  it('gives every entry of an inline table array its own node', () => {
    const types = find(getDocumentSymbols(INLINE), 'TYPES');

    expect(types?.kind).toBe(DocumentSymbolKind.Array);
    expect(types?.children?.map((child) => [child.name, child.kind])).toEqual([
      ['[0]', DocumentSymbolKind.Object],
      ['[1]', DocumentSymbolKind.Object],
    ]);
    expect(types?.children?.[0]?.children?.map((child) => child.name)).toEqual([
      'asset',
      'price',
      'status',
    ]);
  });

  it('numbers array elements by where they are, not by which ones expanded', () => {
    const symbols = getDocumentSymbols('MIX = ["a", {k = 1}, "b", {j = 2}]\n');

    expect(find(symbols, 'MIX')?.children?.map((child) => child.name)).toEqual(['[1]', '[3]']);
  });

  it('calls a scalar list an array without inventing children for it', () => {
    const accounts = find(getDocumentSymbols(INLINE), 'ACCOUNTS');

    expect(accounts?.kind).toBe(DocumentSymbolKind.Array);
    expect(accounts?.children).toBeUndefined();
  });

  it('nests a table declared by a dotted header under its parents', () => {
    const symbols = getDocumentSymbols('[A.B.C]\nX = 1\n');
    const a = find(symbols, 'A');

    expect(a?.kind).toBe(DocumentSymbolKind.Namespace);
    expect(find(symbols, 'X')).toBeDefined();
    expect(a?.children?.[0]?.children?.[0]?.name).toBe('C');
  });

  it('outlines a header the parser could not name as an anonymous table', () => {
    const symbols = getDocumentSymbols('[]\nX = 1\n');

    expect(symbols[0]?.name).toBe('[table]');
    expect(symbols[0]?.kind).toBe(DocumentSymbolKind.Namespace);
    expect(symbols[0]?.children?.map((child) => child.name)).toEqual(['X']);
  });
});

/**
 * LSP 3.17 makes two structural promises about a `DocumentSymbol`: the
 * selection range is inside the range, and a child is inside its parent. An
 * editor that receives a tree breaking either one positions the cursor outside
 * the thing it just highlighted, so the promises get checked rather than noted.
 */
describe('getDocumentSymbols ranges', () => {
  const isAfter = (a: LspPosition, b: LspPosition): boolean =>
    a.line > b.line || (a.line === b.line && a.character >= b.character);

  function assertContained(symbols: LspDocumentSymbol[], parent?: LspDocumentSymbol): void {
    for (const symbol of symbols) {
      const message = parent === undefined ? symbol.name : `${parent.name} > ${symbol.name}`;
      expect(isAfter(symbol.selectionRange.end, symbol.selectionRange.start), message).toBe(true);
      expect(isAfter(symbol.range.end, symbol.selectionRange.end), message).toBe(true);
      if (parent !== undefined) {
        expect(isAfter(symbol.range.start, parent.range.start), `${message} starts early`).toBe(
          true,
        );
        expect(isAfter(parent.range.end, symbol.range.end), `${message} escapes`).toBe(true);
      }
      assertContained(symbol.children ?? [], symbol);
    }
  }

  it('keeps every selection inside its range across a full anchor file', () => {
    const source = readFileSync('test/fixtures/valid.toml', 'utf8');
    const symbols = getDocumentSymbols(source);

    expect(symbols.length).toBeGreaterThan(0);
    assertContained(symbols);
  });

  it('keeps the invariant through mixed and nested arrays', () => {
    assertContained(
      getDocumentSymbols(
        [
          'MIX = ["a", {k = [1, {deep = 2}]}, [[3]]]',
          'TYPES = [{asset = "iso4217:USD"}]',
          '[DOCUMENTATION]',
          'SUPPORT = { EMAIL = "a@example.com" }',
          '',
        ].join('\n'),
      ),
    );
  });
});

/**
 * The outline only reaches an editor through the server, so the wire gets
 * checked too: the capability is advertised on `initialize` and
 * `textDocument/documentSymbol` answers with the same tree.
 */
describe('textDocument/documentSymbol over the wire', () => {
  function frame(message: unknown): string {
    const body = JSON.stringify(message);
    return `Content-Length: ${Buffer.byteLength(body, 'utf8')}\r\n\r\n${body}`;
  }

  /**
   * One session: `initialize`, then `didOpen` unless `text` is null (so a
   * request for a document the server never saw can be answered too), then
   * `textDocument/documentSymbol`.
   */
  async function session(text: string | null): Promise<{
    documentSymbolProvider: unknown;
    symbols: LspDocumentSymbol[];
  }> {
    const input = new PassThrough();
    const output = new PassThrough();
    const chunks: Buffer[] = [];
    output.on('data', (chunk: Buffer) => chunks.push(chunk));

    const server = runLspServer(input, output);
    const uri = 'file:///stellar.toml';
    input.write(frame({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }));
    if (text !== null) {
      input.write(
        frame({
          jsonrpc: '2.0',
          method: 'textDocument/didOpen',
          params: { textDocument: { uri, version: 1, text } },
        }),
      );
    }
    input.write(
      frame({
        jsonrpc: '2.0',
        id: 2,
        method: 'textDocument/documentSymbol',
        params: { textDocument: { uri } },
      }),
    );

    const replies = await new Promise<Record<number, unknown>>((resolve) => {
      const check = (): void => {
        const got: Record<number, unknown> = {};
        for (const part of Buffer.concat(chunks)
          .toString('utf8')
          .split(/Content-Length: \d+\r\n\r\n/)) {
          if (!part) continue;
          const message = JSON.parse(part) as { id?: number; result?: unknown };
          if (message.id === 1 || message.id === 2) got[message.id] = message.result;
        }
        if (got[1] !== undefined && got[2] !== undefined) resolve(got);
        else setTimeout(check, 5);
      };
      check();
    });

    input.write(frame({ jsonrpc: '2.0', method: 'exit' }));
    input.end();
    await server;

    const initialized = replies[1] as { capabilities: { documentSymbolProvider?: unknown } };
    return {
      documentSymbolProvider: initialized.capabilities.documentSymbolProvider,
      symbols: replies[2] as LspDocumentSymbol[],
    };
  }

  it('advertises the provider and answers with the symbol tree', async () => {
    const { documentSymbolProvider, symbols } = await session(
      [
        '[[CURRENCIES]]',
        'code = "USDC"',
        'issuer = "GAC2CQ7JBSRCCNZRCSJNZK5SMH4R4N5XQVQZQZQZQ"',
      ].join('\n'),
    );

    expect(documentSymbolProvider).toBe(true);
    const currency = find(symbols, 'Currency: USDC');
    expect(currency?.kind).toBe(DocumentSymbolKind.Interface);
    expect(currency?.children?.map((child) => child.name)).toEqual(['code', 'issuer']);
    expect(currency?.range.start).toEqual({ line: 0, character: 0 });
  });

  it('answers with an empty outline for a document the server never saw', async () => {
    expect((await session(null)).symbols).toEqual([]);
  });
});
