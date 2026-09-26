import { describe, expect, it } from 'vitest';
import { Keypair } from '@stellar/stellar-base';
import {
  parseSep7Uri,
  validateSep7Uri,
  signSep7Uri,
  verifySep7Signature,
  checkSep7Uris,
  INVALID_SIGNATURE_RULE,
  INVALID_URI_SCHEME_RULE,
  UNSUPPORTED_REPLACEMENT_FIELD_RULE,
} from '../../src/protocols/sep7.js';

describe('SEP-7 URI parser and verifier', () => {
  const keypair = Keypair.random();
  const signingKey = keypair.publicKey();
  const secretKey = keypair.secret();
  const destination = Keypair.random().publicKey();

  it('parses a basic web+stellar:pay URI', () => {
    const uri = `web+stellar:pay?destination=${destination}&amount=100.50&asset_code=USDC`;
    const parsed = parseSep7Uri(uri);
    expect(parsed).not.toBeNull();
    expect(parsed?.operation).toBe('pay');
    expect(parsed?.params.destination).toBe(destination);
    expect(parsed?.params.amount).toBe('100.50');
    expect(parsed?.params.asset_code).toBe('USDC');
  });

  it('validates a correctly signed SEP-7 URI cleanly', () => {
    const rawUri = `web+stellar:pay?destination=${destination}&amount=25&asset_code=native`;
    const signedUri = signSep7Uri(rawUri, secretKey);

    expect(verifySep7Signature(signedUri, signingKey)).toBe(true);

    const diagnostics = validateSep7Uri(signedUri, { signingKey });
    expect(diagnostics).toEqual([]);
  });

  it('asserts sep7/invalid-signature for a forged or invalid signature', () => {
    const rawUri = `web+stellar:pay?destination=${destination}&amount=25&asset_code=native`;
    const otherKeypair = Keypair.random();
    const forgedUri = signSep7Uri(rawUri, otherKeypair.secret());

    expect(verifySep7Signature(forgedUri, signingKey)).toBe(false);

    const diagnostics = validateSep7Uri(forgedUri, { signingKey });
    expect(diagnostics.some((d) => d.rule === INVALID_SIGNATURE_RULE)).toBe(true);
    expect(diagnostics[0]?.severity).toBe('error');
  });

  it('asserts sep7/invalid-uri-scheme for unsupported operation', () => {
    const uri = 'web+stellar:invalid_op?param=1';
    const diagnostics = validateSep7Uri(uri);
    expect(diagnostics.some((d) => d.rule === INVALID_URI_SCHEME_RULE)).toBe(true);
  });

  it('asserts sep7/invalid-uri-scheme for invalid destination account or asset code', () => {
    const uri = 'web+stellar:pay?destination=invalidAccount&asset_code=WAYTOOLONGASSETCODE123';
    const diagnostics = validateSep7Uri(uri);
    expect(
      diagnostics.filter((d) => d.rule === INVALID_URI_SCHEME_RULE).length,
    ).toBeGreaterThanOrEqual(2);
  });

  it('asserts sep7/invalid-uri-scheme for missing xdr in tx operation', () => {
    const uri = 'web+stellar:tx?callback=url:https://anchor.com/callback';
    const diagnostics = validateSep7Uri(uri);
    expect(diagnostics.some((d) => d.rule === INVALID_URI_SCHEME_RULE)).toBe(true);
  });

  it('asserts sep7/unsupported-replacement-field for invalid replacement parameters', () => {
    const uri = `web+stellar:pay?destination=${destination}&replace=invalid_field:varName,amount:amt`;
    const diagnostics = validateSep7Uri(uri);
    expect(diagnostics.some((d) => d.rule === UNSUPPORTED_REPLACEMENT_FIELD_RULE)).toBe(true);
    expect(diagnostics[0]?.severity).toBe('warning');
  });

  it('extracts and validates SEP-7 URIs within stellar.toml doc structure', () => {
    const validRaw = `web+stellar:pay?destination=${destination}&amount=10`;
    const validSigned = signSep7Uri(validRaw, secretKey);

    const doc = {
      SIGNING_KEY: signingKey,
      DOCUMENTATION: {
        ORG_DESCRIPTION: `Pay us with SEP-7: ${validSigned}`,
      },
      CURRENCIES: [
        {
          code: 'USD',
          desc: `Deposit link: web+stellar:pay?destination=bad_dest`,
        },
      ],
    };

    const diagnostics = checkSep7Uris(doc);
    expect(diagnostics.some((d) => d.rule === INVALID_URI_SCHEME_RULE)).toBe(true);
    expect(diagnostics.filter((d) => d.rule === INVALID_SIGNATURE_RULE)).toHaveLength(0);
  });
});
