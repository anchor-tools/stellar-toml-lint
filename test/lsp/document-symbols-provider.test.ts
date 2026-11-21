import { describe, expect, it } from 'vitest';
import { LspDocumentSymbolProvider, SymbolKind } from '../../src/lsp/documentSymbolProvider.js';
import type { DocumentSymbol } from '../../src/lsp/documentSymbolProvider.js';
import { parseCst } from '../../src/cst/parser.js';

const SAMPLE_TOML = `
VERSION = "2.7.0"
NETWORK_PASSPHRASE = "Test SDF Network ; September 2015"

[DOCUMENTATION]
ORG_NAME = "Example Anchor Foundation"
ORG_URL = "https://example.com"

[DOCUMENTATION.SUPPORT]
EMAIL = "support@example.com"

[[CURRENCIES]]
code = "USDC"
issuer = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"
status = "live"
display_decimals = 2

[[CURRENCIES]]
code = "EURC"
issuer = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"
status = "test"

[[VALIDATORS]]
ALIAS = "stellar-node-1"
HOST = "node1.stellar.org:11625"
`;

function findSymbol(
  symbols: DocumentSymbol[],
  predicate: (s: DocumentSymbol) => boolean,
): DocumentSymbol | undefined {
  for (const s of symbols) {
    if (predicate(s)) return s;
    if (s.children) {
      const found = findSymbol(s.children, predicate);
      if (found) return found;
    }
  }
  return undefined;
}

describe('LspDocumentSymbolProvider', () => {
  const provider = new LspDocumentSymbolProvider();

  it('generates hierarchical symbols conforming to LSP 3.17', () => {
    const symbols = provider.provideDocumentSymbols(SAMPLE_TOML);
    expect(symbols.length).toBeGreaterThan(0);

    const version = symbols.find((s) => s.name === 'VERSION');
    expect(version).toBeDefined();
    expect(version?.kind).toBe(SymbolKind.String);
    expect(version?.range).toBeDefined();
    expect(version?.selectionRange).toBeDefined();
  });

  it('maps TOML tables to Namespace and Class kinds with dotted hierarchy', () => {
    const symbols = provider.provideDocumentSymbols(SAMPLE_TOML);

    const docSection = symbols.find((s) => s.name === '[DOCUMENTATION]');
    expect(docSection).toBeDefined();
    expect(docSection?.kind).toBe(SymbolKind.Namespace);

    // Support section nested under DOCUMENTATION
    const supportSection = docSection?.children?.find((s) => s.name === '[DOCUMENTATION.SUPPORT]');
    expect(supportSection).toBeDefined();
    expect(supportSection?.kind).toBe(SymbolKind.Namespace);

    const email = supportSection?.children?.find((s) => s.name === 'EMAIL');
    expect(email).toBeDefined();
    expect(email?.detail).toBe('support@example.com');
  });

  it('maps currency entries to SymbolKind.Interface labeled with asset code', () => {
    const symbols = provider.provideDocumentSymbols(SAMPLE_TOML);

    const usdc = findSymbol(symbols, (s) => s.name === 'USDC');
    expect(usdc).toBeDefined();
    expect(usdc?.kind).toBe(SymbolKind.Interface);
    expect(usdc?.detail).toContain('Currency: USDC');

    // Child symbols for code, issuer, status, etc.
    const issuer = usdc?.children?.find((s) => s.name === 'issuer');
    expect(issuer).toBeDefined();
    expect(issuer?.detail).toBe('GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5');

    const eurc = findSymbol(symbols, (s) => s.name === 'EURC');
    expect(eurc).toBeDefined();
    expect(eurc?.kind).toBe(SymbolKind.Interface);
  });

  it('maps validator tables to SymbolKind.Class', () => {
    const symbols = provider.provideDocumentSymbols(SAMPLE_TOML);

    const validator = findSymbol(symbols, (s) => s.name === '[[VALIDATORS]]');
    expect(validator).toBeDefined();
    expect(validator?.kind).toBe(SymbolKind.Class);
    expect(validator?.detail).toBe('stellar-node-1');

    const host = validator?.children?.find((s) => s.name === 'HOST');
    expect(host).toBeDefined();
    expect(host?.detail).toBe('node1.stellar.org:11625');
  });

  it('provides accurate range and selectionRange coordinates', () => {
    const symbols = provider.provideDocumentSymbols(SAMPLE_TOML);
    const docSection = symbols.find((s) => s.name === '[DOCUMENTATION]');
    expect(docSection).toBeDefined();

    // selectionRange must encompass header
    expect(docSection!.selectionRange.start.line).toBe(4);
    // range must enclose body and children
    expect(docSection!.range.start.line).toBe(4);
    expect(docSection!.range.end.line).toBeGreaterThanOrEqual(docSection!.selectionRange.end.line);
  });

  it('handles anonymous tables without errors', () => {
    const anonToml = `
[]
key1 = "value1"
`;
    const symbols = provider.provideDocumentSymbols(anonToml);
    expect(symbols.length).toBe(1);
    expect(symbols[0]!.name).toBe('[anonymous]');
    expect(symbols[0]!.kind).toBe(SymbolKind.Class);
    expect(symbols[0]!.children?.[0]?.name).toBe('key1');
  });

  it('handles inline table arrays and inline tables', () => {
    const inlineToml = `
CURRENCIES = [
  { code = "XLM", issuer = "native", status = "live" },
  { code = "AQUA", issuer = "GBNZILSTVQZ4R7IKQDGHYGY2Q2GLNO2467PMCWWMRF7PPKBDWFVSDVII" }
]

SETTINGS = { theme = "dark", refresh_interval = 60 }
`;
    const symbols = provider.provideDocumentSymbols(inlineToml);

    const currencies = symbols.find((s) => s.name === 'CURRENCIES');
    expect(currencies).toBeDefined();
    expect(currencies?.kind).toBe(SymbolKind.Array);
    expect(currencies?.children?.length).toBe(2);

    const xlm = currencies?.children?.[0];
    expect(xlm?.name).toBe('XLM');
    expect(xlm?.kind).toBe(SymbolKind.Interface);
    expect(xlm?.children?.find((c) => c.name === 'issuer')?.detail).toBe('native');

    const aqua = currencies?.children?.[1];
    expect(aqua?.name).toBe('AQUA');
    expect(aqua?.kind).toBe(SymbolKind.Interface);

    const settings = symbols.find((s) => s.name === 'SETTINGS');
    expect(settings).toBeDefined();
    expect(settings?.kind).toBe(SymbolKind.Object);
    expect(settings?.children?.find((c) => c.name === 'theme')?.detail).toBe('dark');
  });

  it('accepts pre-parsed CST documents', () => {
    const cst = parseCst(SAMPLE_TOML);
    const symbols = provider.provideDocumentSymbols(cst);
    expect(symbols.length).toBeGreaterThan(0);
    expect(symbols.find((s) => s.name === 'VERSION')).toBeDefined();
  });
});
