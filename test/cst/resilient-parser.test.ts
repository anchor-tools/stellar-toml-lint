import { describe, expect, it } from 'vitest';
import { ResilientIncrementalParser } from '../../src/cst/resilientParser.js';

describe('ResilientIncrementalParser', () => {
  const parser = new ResilientIncrementalParser();

  it('recovers from unclosed quotes and continues parsing succeeding tables', () => {
    const malformed = `
VERSION = "2.7.0"
ORG_NAME = "Half typed unclosed string
NETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"

[DOCUMENTATION]
ORG_URL = "https://example.com"
`;

    const result = parser.parse(malformed);
    expect(result.document).toBeDefined();
    expect(result.isRecovered).toBe(true);
    expect(result.diagnostics.length).toBeGreaterThan(0);

    // Preceding and succeeding nodes are still captured in CST
    const hasVersion = result.document.entries.some(
      (e) => e.kind === 'key-value' && e.key?.path === 'VERSION',
    );
    const hasDocTable = result.document.entries.some(
      (e) => e.kind === 'table' && e.key?.path === 'DOCUMENTATION',
    );

    expect(hasVersion).toBe(true);
    expect(hasDocTable).toBe(true);
  });

  it('recovers from dangling equal signs without crashing', () => {
    const malformed = `
VERSION = "2.7.0"
DANGLING_KEY =
SIGNING_KEY = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"
`;

    const result = parser.parse(malformed);
    expect(result.document).toBeDefined();
    expect(result.diagnostics.length).toBeGreaterThan(0);

    const hasSigning = result.document.entries.some(
      (e) => e.kind === 'key-value' && e.key?.path === 'SIGNING_KEY',
    );
    expect(hasSigning).toBe(true);
  });

  it('recovers from unclosed table header brackets', () => {
    const malformed = `
[DOCUMENTATION
ORG_NAME = "My Anchor"

[[CURRENCIES]]
code = "USDC"
`;

    const result = parser.parse(malformed);
    expect(result.document).toBeDefined();
    expect(result.diagnostics.length).toBeGreaterThan(0);

    const hasCurrency = result.document.entries.some(
      (e) => e.kind === 'array-table' && e.key?.path === 'CURRENCIES',
    );
    expect(hasCurrency).toBe(true);
  });

  it('supports incremental re-parsing of edited ranges', () => {
    const initialSource = `
VERSION = "2.7.0"
SIGNING_KEY = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"

[DOCUMENTATION]
ORG_NAME = "Original Name"
ORG_URL = "https://example.com"
`;
    parser.parse(initialSource);

    const updatedSource = initialSource.replace('Original Name', 'Updated Anchor Name');
    const editOffset = initialSource.indexOf('Original Name');

    const result = parser.parseIncremental(updatedSource, {
      start: editOffset,
      oldLength: 'Original Name'.length,
      newLength: 'Updated Anchor Name'.length,
    });

    expect(result.document).toBeDefined();
    expect(result.reparsedRange).toBeDefined();
  });

  it('benchmarks parsing speed on 5,000+ line documents to be sub-millisecond per line and responsive', () => {
    const lines: string[] = ['VERSION = "2.7.0"', 'NETWORK_PASSPHRASE = "Public"'];

    for (let i = 0; i < 2000; i++) {
      lines.push('[[CURRENCIES]]');
      lines.push(`code = "TOKEN${i}"`);
      lines.push('issuer = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"');
      lines.push('status = "live"');
      lines.push('');
    }

    const largeToml = lines.join('\n');
    expect(largeToml.split('\n').length).toBeGreaterThan(5000);

    const start = performance.now();
    const result = parser.parse(largeToml);
    const durationMs = performance.now() - start;

    expect(result.document).toBeDefined();
    expect(result.document.entries.length).toBeGreaterThan(1000);
    // Sub-millisecond per line requirement (< 1ms per line on 5,000+ line documents)
    const perLineMs = durationMs / lines.length;
    expect(perLineMs).toBeLessThan(1.0);
    expect(durationMs).toBeLessThan(500);
  });
});
