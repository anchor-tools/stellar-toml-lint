import { describe, expect, it } from 'vitest';
import { Keypair } from '@stellar/stellar-base';
import {
  ED25519_GROUP_ORDER,
  MALLEABLE_SIGNATURE_RULE,
  auditEd25519Signature,
  checkSignatureMalleability,
  isCanonicalEd25519Signature,
  isMalleableEd25519Signature,
} from '../../src/crypto/malleability-auditor.js';
import { lint } from '../../src/lint.js';

const MESSAGE = 'Reserve attestation for USDC, 2026-10-20';
const keypair = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 9));

function signatureWithNonCanonicalS(): string {
  const signature = Uint8Array.from(keypair.sign(Buffer.from(MESSAGE, 'utf8')));
  let s = 0n;
  for (let index = 63; index >= 32; index--) {
    s = (s << 8n) | BigInt(signature[index] as number);
  }
  const malleated = s + ED25519_GROUP_ORDER;
  // Write the little-endian S scalar back into the last 32 bytes.
  let value = malleated;
  for (let index = 32; index < 64; index++) {
    signature[index] = Number(value & 0xffn);
    value >>= 8n;
  }
  return Buffer.from(signature).toString('base64');
}

const toml = (signature: string): string =>
  [
    'VERSION="2.0.0"',
    '[[CURRENCIES]]',
    'code="USDC"',
    'issuer="GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"',
    'is_unlimited=true',
    `collateral_address_signatures=["${signature}"]`,
  ].join('\n');

describe('Ed25519 malleability auditor', () => {
  it('accepts a canonical signature', () => {
    const signature = keypair.sign(Buffer.from(MESSAGE, 'utf8')).toString('base64');
    expect(isCanonicalEd25519Signature(signature)).toBe(true);
    expect(auditEd25519Signature(signature)).toMatchObject({ canonical: true, malleable: false });
    expect(checkSignatureMalleability({})).toEqual([]);
  });

  it('detects a non-canonical S scalar', () => {
    const signature = signatureWithNonCanonicalS();
    expect(isCanonicalEd25519Signature(signature)).toBe(false);
    expect(isMalleableEd25519Signature(signature)).toBe(true);
  });

  it('asserts crypto/malleable-signature-detected through collaterals', () => {
    const result = lint(toml(signatureWithNonCanonicalS()));
    const finding = result.diagnostics.find((d) => d.rule === MALLEABLE_SIGNATURE_RULE);
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('error');
    expect(finding?.path).toBe('CURRENCIES[0].collateral_address_signatures[0]');
  });

  it('passes canonical collateral signatures through lint', () => {
    const signature = keypair.sign(Buffer.from(MESSAGE, 'utf8')).toString('base64');
    const result = lint(toml(signature));
    expect(result.diagnostics.filter((d) => d.rule === MALLEABLE_SIGNATURE_RULE)).toEqual([]);
  });

  it('can be disabled with a rule override', () => {
    const result = lint(toml(signatureWithNonCanonicalS()), {
      rules: { [MALLEABLE_SIGNATURE_RULE]: 'off' },
    });
    expect(result.diagnostics.filter((d) => d.rule === MALLEABLE_SIGNATURE_RULE)).toEqual([]);
  });
});
