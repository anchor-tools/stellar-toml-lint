import { describe, expect, it } from 'vitest';
import { lint } from '../src/lint.js';

const VALID_64_BYTE_BASE64 = Buffer.alloc(64, 42).toString('base64');
const INVALID_32_BYTE_BASE64 = Buffer.alloc(32, 42).toString('base64');
const INVALID_16_BYTE_BASE64 = Buffer.alloc(16, 42).toString('base64');
const MALFORMED_BASE64_CHARS = '%%%not-valid-base64%%%!';
const MALFORMED_BASE64_PADDING = 'AAAA='; // bad padding length

function tomlWithSignatures(signatures: string[]): string {
  const sigList = signatures.map((s) => `"${s}"`).join(', ');
  return [
    'VERSION="2.0.0"',
    'NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"',
    '[[CURRENCIES]]',
    'code="USDC"',
    'issuer="GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"',
    'is_unlimited=true',
    `collateral_address_signatures=[${sigList}]`,
  ].join('\n');
}

describe('collateral-sig-format rules', () => {
  it('passes a valid 64-byte base64 signature cleanly', () => {
    const source = tomlWithSignatures([VALID_64_BYTE_BASE64]);
    const result = lint(source);
    const diagnostics = result.diagnostics.filter((d) =>
      d.rule.startsWith('currencies/invalid-signature'),
    );
    expect(diagnostics).toHaveLength(0);
  });

  it('asserts currencies/invalid-signature-encoding on non-base64 characters', () => {
    const source = tomlWithSignatures([MALFORMED_BASE64_CHARS]);
    const result = lint(source);
    const diagnostic = result.diagnostics.find(
      (d) => d.rule === 'currencies/invalid-signature-encoding',
    );
    expect(diagnostic).toBeDefined();
    expect(diagnostic?.severity).toBe('error');
    expect(diagnostic?.category).toBe('currencies');
    expect(diagnostic?.path).toBe('CURRENCIES[0].collateral_address_signatures');
    expect(diagnostic?.message).toContain('CURRENCIES[0].collateral_address_signatures[0]');
    expect(diagnostic?.message).toContain('not a valid base64');
  });

  it('asserts currencies/invalid-signature-encoding on malformed base64 padding', () => {
    const source = tomlWithSignatures([MALFORMED_BASE64_PADDING]);
    const result = lint(source);
    const diagnostic = result.diagnostics.find(
      (d) => d.rule === 'currencies/invalid-signature-encoding',
    );
    expect(diagnostic).toBeDefined();
    expect(diagnostic?.severity).toBe('error');
  });

  it('asserts currencies/invalid-signature-length on a 32-byte signature', () => {
    const source = tomlWithSignatures([INVALID_32_BYTE_BASE64]);
    const result = lint(source);
    const diagnostic = result.diagnostics.find(
      (d) => d.rule === 'currencies/invalid-signature-length',
    );
    expect(diagnostic).toBeDefined();
    expect(diagnostic?.severity).toBe('error');
    expect(diagnostic?.category).toBe('currencies');
    expect(diagnostic?.path).toBe('CURRENCIES[0].collateral_address_signatures');
    expect(diagnostic?.message).toContain('CURRENCIES[0].collateral_address_signatures[0]');
    expect(diagnostic?.message).toContain('decodes to 32 bytes');
  });

  it('asserts currencies/invalid-signature-length on a 16-byte signature', () => {
    const source = tomlWithSignatures([INVALID_16_BYTE_BASE64]);
    const result = lint(source);
    const diagnostic = result.diagnostics.find(
      (d) => d.rule === 'currencies/invalid-signature-length',
    );
    expect(diagnostic).toBeDefined();
    expect(diagnostic?.message).toContain('decodes to 16 bytes');
  });

  it('reports errors for each invalid signature in a multi-signature array', () => {
    const source = tomlWithSignatures([
      VALID_64_BYTE_BASE64,
      INVALID_32_BYTE_BASE64,
      MALFORMED_BASE64_CHARS,
    ]);
    const result = lint(source);
    const encodingDiagnostics = result.diagnostics.filter(
      (d) => d.rule === 'currencies/invalid-signature-encoding',
    );
    const lengthDiagnostics = result.diagnostics.filter(
      (d) => d.rule === 'currencies/invalid-signature-length',
    );

    expect(encodingDiagnostics).toHaveLength(1);
    expect(encodingDiagnostics[0]?.message).toContain(
      'CURRENCIES[0].collateral_address_signatures[2]',
    );

    expect(lengthDiagnostics).toHaveLength(1);
    expect(lengthDiagnostics[0]?.message).toContain(
      'CURRENCIES[0].collateral_address_signatures[1]',
    );
  });

  it('can be disabled with rule overrides', () => {
    const source = tomlWithSignatures([INVALID_32_BYTE_BASE64, MALFORMED_BASE64_CHARS]);
    const result = lint(source, {
      rules: {
        'currencies/invalid-signature-encoding': 'off',
        'currencies/invalid-signature-length': 'off',
      },
    });
    const diagnostics = result.diagnostics.filter((d) =>
      d.rule.startsWith('currencies/invalid-signature'),
    );
    expect(diagnostics).toHaveLength(0);
  });
});
