import { Keypair } from '@stellar/stellar-base';
import { describe, expect, it } from 'vitest';
import {
  analyzeVanityAddress,
  auditVanityAddresses,
  SUSPICIOUS_VANITY_ADDRESS_RULE,
} from '../../src/crypto/vanity-auditor.js';

const SUSPICIOUS = 'GSTELLARABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQ';

describe('vanity address entropy auditor', () => {
  it('passes a standard random Stellar public key', () => {
    const key = Keypair.random().publicKey();
    expect(analyzeVanityAddress(key).suspicious).toBe(false);
    expect(auditVanityAddresses({ SIGNING_KEY: key })).toEqual([]);
  });

  it('flags a suspicious 10-character vanity key', () => {
    const diagnostics = auditVanityAddresses({ SIGNING_KEY: SUSPICIOUS });

    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: SUSPICIOUS_VANITY_ADDRESS_RULE,
        severity: 'warning',
        path: 'SIGNING_KEY',
      }),
    );
    expect(diagnostics[0]?.helpUri).toContain('profanity');
  });

  it('inspects issuer accounts as well as SIGNING_KEY', () => {
    const diagnostics = auditVanityAddresses({
      CURRENCIES: [{ code: 'USD', issuer: SUSPICIOUS }],
    });

    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: SUSPICIOUS_VANITY_ADDRESS_RULE,
        path: 'CURRENCIES[0].issuer',
      }),
    );
  });

  it('flags degenerate repeated prefixes', () => {
    expect(analyzeVanityAddress(`G${'A'.repeat(55)}`).suspicious).toBe(true);
  });

  it('can be switched off by rule id', () => {
    const diagnostics = auditVanityAddresses(
      { SIGNING_KEY: SUSPICIOUS },
      { rules: { [SUSPICIOUS_VANITY_ADDRESS_RULE]: 'off' } },
    );

    expect(diagnostics).toEqual([]);
  });
});
