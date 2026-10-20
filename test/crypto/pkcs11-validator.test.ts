import { describe, expect, it } from 'vitest';
import {
  INSECURE_EMBEDDED_PKCS11_PIN_RULE,
  MALFORMED_PKCS11_URI_RULE,
  checkPkcs11Pointers,
  isValidPkcs11Uri,
  parsePkcs11Uri,
  validatePkcs11Uri,
} from '../../src/crypto/pkcs11-validator.js';
import { lint } from '../../src/lint.js';

describe('PKCS#11 URI validator', () => {
  it('accepts a compliant RFC 7512 URI', () => {
    const uri = 'pkcs11:token=stellar;object=signing-key;type=private';
    expect(parsePkcs11Uri(uri).ok).toBe(true);
    expect(isValidPkcs11Uri(uri)).toBe(true);
    expect(validatePkcs11Uri(uri)).toEqual([]);
  });

  it('accepts percent-encoded values', () => {
    const uri = 'pkcs11:token=Stellar%20HSM;object=signing-key;id=%01%02%03';
    expect(parsePkcs11Uri(uri).ok).toBe(true);
    expect(validatePkcs11Uri(uri)).toEqual([]);
  });

  it('flags an embedded plaintext PIN', () => {
    const diagnostics = validatePkcs11Uri(
      'pkcs11:token=stellar;object=signing-key?pin-value=123456',
    );
    expect(diagnostics.map((diagnostic) => diagnostic.rule)).toContain(
      INSECURE_EMBEDDED_PKCS11_PIN_RULE,
    );
    expect(diagnostics[0]?.severity).toBe('error');
  });

  it('flags a PIN embedded on the path as well as in the query', () => {
    const diagnostics = validatePkcs11Uri('pkcs11:token=stellar;object=signing-key;pin-value=9999');
    expect(diagnostics.map((diagnostic) => diagnostic.rule)).toContain(
      INSECURE_EMBEDDED_PKCS11_PIN_RULE,
    );
  });

  it('accepts pin-source instead of an embedded PIN', () => {
    expect(
      validatePkcs11Uri(
        'pkcs11:token=stellar;object=signing-key?pin-source=file:/run/secrets/hsm-pin',
      ),
    ).toEqual([]);
  });

  it('rejects malformed and incomplete URIs', () => {
    for (const uri of [
      'https://example.com/key',
      'pkcs11:token',
      'pkcs11:token=stellar;unknown=value',
      'pkcs11:token=%zz',
      'pkcs11:',
    ]) {
      expect(validatePkcs11Uri(uri).map((diagnostic) => diagnostic.rule)).toContain(
        MALFORMED_PKCS11_URI_RULE,
      );
    }
  });

  it('walks a document and reports the dotted path', () => {
    const diagnostics = checkPkcs11Pointers({
      SIGNING_KEY: 'pkcs11:token=stellar;object=signing-key?pin-value=123456',
    });
    expect(diagnostics[0]?.path).toBe('SIGNING_KEY');
  });

  it('allows a compliant PKCS#11 SIGNING_KEY through the general rule', () => {
    const result = lint(
      ['VERSION="2.0.0"', 'SIGNING_KEY="pkcs11:token=stellar;object=signing-key"'].join('\n'),
    );
    expect(result.diagnostics.filter((d) => d.rule === MALFORMED_PKCS11_URI_RULE)).toEqual([]);
    expect(result.diagnostics.filter((d) => d.rule === 'general/signing-keys')).toEqual([]);
  });

  it('reports insecure PINs through lint', () => {
    const result = lint(
      [
        'VERSION="2.0.0"',
        'SIGNING_KEY="pkcs11:token=stellar;object=signing-key?pin-value=123456"',
      ].join('\n'),
    );
    expect(
      result.diagnostics.filter((d) => d.rule === INSECURE_EMBEDDED_PKCS11_PIN_RULE),
    ).not.toHaveLength(0);
  });
});
