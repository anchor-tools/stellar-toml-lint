import { createSign, generateKeyPairSync } from 'node:crypto';
import { Keypair } from '@stellar/stellar-base';
import { describe, expect, it } from 'vitest';
import {
  auditJwtCrypto,
  INSECURE_JWT_ALGORITHM_RULE,
  JWT_SIGNATURE_VERIFICATION_FAILED_RULE,
  type JwtJwk,
} from '../../src/security/jwt-crypto-auditor.js';

function base64Url(value: string | Buffer): string {
  return Buffer.from(value).toString('base64url');
}

function jwt(header: object, payload: object, signature: string | Buffer): string {
  return `${base64Url(JSON.stringify(header))}.${base64Url(JSON.stringify(payload))}.${base64Url(signature)}`;
}

function edDsaToken(server: Keypair): string {
  const signingInput = `${base64Url(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' }))}.${base64Url(
    JSON.stringify({ iss: 'anchor.example.com', sub: 'GCLIENT', iat: 1, exp: 2 }),
  )}`;
  return `${signingInput}.${server.sign(Buffer.from(signingInput)).toString('base64url')}`;
}

describe('SEP-10 JWT crypto auditor', () => {
  it('accepts a token with a valid EdDSA signature from SIGNING_KEY', async () => {
    const server = Keypair.random();
    const diagnostics = await auditJwtCrypto(edDsaToken(server), {
      signingKey: server.publicKey(),
    });

    expect(diagnostics).toEqual([]);
  });

  it('flags HS256 as security/insecure-jwt-algorithm', async () => {
    const token = jwt({ alg: 'HS256', typ: 'JWT' }, { iss: 'anchor.example.com' }, 'signature');
    const diagnostics = await auditJwtCrypto(token, { signingKey: Keypair.random().publicKey() });

    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: INSECURE_JWT_ALGORITHM_RULE,
        severity: 'error',
      }),
    );
  });

  it('flags the none algorithm as insecure', async () => {
    const token = jwt({ alg: 'none', typ: 'JWT' }, { iss: 'anchor.example.com' }, '');
    const diagnostics = await auditJwtCrypto(token);

    expect(diagnostics.map((d) => d.rule)).toContain(INSECURE_JWT_ALGORITHM_RULE);
  });

  it('flags a tampered EdDSA signature as verification failure', async () => {
    const server = Keypair.random();
    const valid = edDsaToken(server);
    const parts = valid.split('.');
    const signature = Buffer.from(parts[2] ?? '', 'base64url');
    signature[0] = (signature[0] ?? 0) ^ 0xff;
    const tampered = `${parts[0]}.${parts[1]}.${signature.toString('base64url')}`;

    const diagnostics = await auditJwtCrypto(tampered, { signingKey: server.publicKey() });

    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: JWT_SIGNATURE_VERIFICATION_FAILED_RULE,
        severity: 'error',
      }),
    );
  });

  it('verifies an RS256 token against a published JWKS key', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = publicKey.export({ format: 'jwk' }) as JwtJwk;
    const signingInput = `${base64Url(
      JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: 'anchor-key' }),
    )}.${base64Url(JSON.stringify({ iss: 'anchor.example.com' }))}`;
    const signature = createSign('RSA-SHA256').update(signingInput).sign(privateKey);
    const token = `${signingInput}.${signature.toString('base64url')}`;

    const diagnostics = await auditJwtCrypto(token, {
      jwks: [{ ...jwk, kid: 'anchor-key' }],
    });

    expect(diagnostics).toEqual([]);
  });
});
