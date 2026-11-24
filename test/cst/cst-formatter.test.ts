import { describe, expect, it } from 'vitest';
import { LosslessCstFormatter } from '../../src/cst/cstFormatter.js';
import { parseCst } from '../../src/cst/parser.js';

const SAMPLE_TOML = `# Top-level file header comment
VERSION = "2.7.0"
# Network comment
NETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"

[DOCUMENTATION]
# Org details
ORG_NAME = "Example Foundation"
ORG_URL = "https://example.com"

[[CURRENCIES]]
code = "USDC"
issuer = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"
status = "live"
display_decimals = 2
`;

describe('LosslessCstFormatter', () => {
  const formatter = new LosslessCstFormatter();

  it('preserves byte-for-byte formatting and comments on unmutated documents (idempotent)', () => {
    const formatted = formatter.format(SAMPLE_TOML);
    expect(formatted).toBe(SAMPLE_TOML);

    // Idempotency: f(f(x)) = f(x)
    const secondPass = formatter.format(formatted);
    expect(secondPass).toBe(formatted);
  });

  it('updates top-level signing key preserving surrounding comments', () => {
    const doc = parseCst(SAMPLE_TOML);
    formatter.updateSigningKey(doc, 'GDI45678901234567890123456789012345678901234567890123456');

    const serialized = formatter.serialize(doc);
    expect(serialized).toContain('GDI45678901234567890123456789012345678901234567890123456');
    expect(serialized).toContain('# Top-level file header comment');
    expect(serialized).toContain('# Org details');
  });

  it('adds a currency table programmatically with proper indentation', () => {
    const doc = parseCst(SAMPLE_TOML);
    formatter.addCurrencyTable(doc, {
      code: 'EURC',
      issuer: 'GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5',
      status: 'test',
      display_decimals: 2,
    });

    const serialized = formatter.serialize(doc);
    expect(serialized).toContain('code = "EURC"');
    expect(serialized).toContain('status = "test"');
    expect(serialized).toContain('code = "USDC"');
  });

  it('removes keys programmatically', () => {
    const doc = parseCst(SAMPLE_TOML);
    const removed = formatter.removeKey(doc, 'ORG_URL', 'DOCUMENTATION');
    expect(removed).toBe(true);

    const serialized = formatter.serialize(doc);
    expect(serialized).not.toContain('ORG_URL');
    expect(serialized).toContain('ORG_NAME = "Example Foundation"');
  });

  it('reorders sections according to provided list', () => {
    const doc = parseCst(SAMPLE_TOML);
    formatter.reorderSections(doc, ['CURRENCIES', 'DOCUMENTATION']);

    const serialized = formatter.serialize(doc);
    const currenciesPos = serialized.indexOf('[[CURRENCIES]]');
    const docPos = serialized.indexOf('[DOCUMENTATION]');
    expect(currenciesPos).toBeLessThan(docPos);
  });
});
