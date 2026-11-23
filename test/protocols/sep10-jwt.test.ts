import { StrKey } from '@stellar/stellar-base';
import { describe, expect, it } from 'vitest';
import {
  DEFAULT_MAX_JWT_LIFETIME_SECONDS,
  SEP10_ALLOWED_ALGORITHMS,
  Sep10JwtAuditor,
  auditSep10Jwt,
  decodeJwt,
  isValidSep10Subject,
  sep10JwtRuleIds,
  sep10JwtRules,
} from '../../src/protocols/sep10JwtAuditor.js';

const ANCHOR = 'quotes.example.com';
const ACCOUNT = 'GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY';
const CLIENT_SIGNER = 'GB7Q4A7GBQX4Y6DDAZW6G4Q2BZQZ6VQZ6VQZ6VQZ6VQZ6VQZ6VQZ6VQZ';
const NOW = new Date('2026-06-01T00:00:00Z');
const NOW_SECONDS = Math.floor(NOW.getTime() / 1000);

const DOC = { WEB_AUTH_ENDPOINT: 'https://quotes.example.com/auth' };

function base64url(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function token(
  payload: Record<string, unknown> = {},
  header: Record<string, unknown> = { alg: 'EdDSA', typ: 'JWT' },
): string {
  return `${base64url(header)}.${base64url(payload)}.signature`;
}

function validPayload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    iss: ANCHOR,
    sub: ACCOUNT,
    iat: NOW_SECONDS - 60,
    exp: NOW_SECONDS + 3600,
    ...overrides,
  };
}

function audit(tokens: string[], options: Record<string, unknown> = {}) {
  return auditSep10Jwt(DOC, fetch, { tokens, now: NOW, ...options });
}

describe('SEP-10 JWT helpers', () => {
  it('registers the JWT rule ids', () => {
    expect(sep10JwtRuleIds).toEqual([
      'sep10/malformed-jwt',
      'sep10/unsafe-jwt-algorithm',
      'sep10/missing-jwt-claim',
      'sep10/jwt-issuer-mismatch',
      'sep10/expired-jwt',
      'sep10/invalid-jwt-subject',
      'sep10/excessive-jwt-lifetime',
      'sep10/unbound-client-domain',
      'sep10/jwt-unverifiable',
    ]);
    expect(sep10JwtRules.map((rule) => rule.severity)).toContain('warning');
  });

  it('decodes a compact JWS and rejects malformed tokens', () => {
    const decoded = decodeJwt(token(validPayload()));
    expect(decoded?.payload.iss).toBe(ANCHOR);
    expect(decoded?.header.alg).toBe('EdDSA');
    expect(decodeJwt('a.b')).toBeUndefined();
    expect(decodeJwt('a.b.c')).toBeUndefined();
    expect(decodeJwt(`${base64url({})}.${base64url({})}.sig`)).toBeDefined();
  });

  it('accepts classic and muxed subjects only', () => {
    const muxed = StrKey.encodeMed25519PublicKey(Buffer.alloc(40));
    expect(isValidSep10Subject(ACCOUNT)).toBe(true);
    expect(isValidSep10Subject(muxed)).toBe(true);
    expect(isValidSep10Subject('not-an-account')).toBe(false);
    expect(SEP10_ALLOWED_ALGORITHMS).toEqual(['EdDSA', 'Ed25519', 'ES256', 'RS256']);
    expect(DEFAULT_MAX_JWT_LIFETIME_SECONDS).toBe(86_400);
  });
});

describe('Sep10JwtAuditor', () => {
  it('passes a well-formed token', async () => {
    const result = await audit([token(validPayload())], { expectedDomain: ANCHOR });
    expect(result.diagnostics).toEqual([]);
    expect(result.tokens).toHaveLength(1);
  });

  it('reports a malformed token', async () => {
    const result = await audit(['not-a-jwt']);
    expect(result.diagnostics.map((d) => d.rule)).toEqual(['sep10/malformed-jwt']);
    expect(result.tokens).toEqual([]);
  });

  it('rejects alg: none and other unapproved algorithms', async () => {
    const none = await audit([token(validPayload(), { alg: 'none' })], { expectedDomain: ANCHOR });
    expect(none.diagnostics.map((d) => d.rule)).toContain('sep10/unsafe-jwt-algorithm');

    const hs = await audit([token(validPayload(), { alg: 'HS256' })], { expectedDomain: ANCHOR });
    expect(hs.diagnostics.map((d) => d.rule)).toContain('sep10/unsafe-jwt-algorithm');
  });

  it('reports every missing required claim', async () => {
    const result = await audit([token({})], { expectedDomain: ANCHOR });
    const missing = result.diagnostics.filter((d) => d.rule === 'sep10/missing-jwt-claim');
    expect(missing).toHaveLength(4);
    expect(missing.map((d) => d.message).join(' ')).toContain('iss');
  });

  it('reports an expired token and an excessive lifetime separately', async () => {
    const expired = await audit(
      [token(validPayload({ iat: NOW_SECONDS - 7200, exp: NOW_SECONDS - 60 }))],
      { expectedDomain: ANCHOR },
    );
    expect(expired.diagnostics.map((d) => d.rule)).toContain('sep10/expired-jwt');

    const long = await audit(
      [token(validPayload({ iat: NOW_SECONDS - 60, exp: NOW_SECONDS + 48 * 3600 }))],
      { expectedDomain: ANCHOR },
    );
    expect(long.diagnostics.map((d) => d.rule)).toEqual(['sep10/excessive-jwt-lifetime']);
    expect(long.diagnostics[0]?.message).toContain('48h');
  });

  it('reports exp before iat and a future iat', async () => {
    const inverted = await audit([token(validPayload({ exp: NOW_SECONDS - 3600 }))], {
      expectedDomain: ANCHOR,
      rules: { 'sep10/expired-jwt': 'off' },
    });
    expect(inverted.diagnostics.map((d) => d.rule)).toContain('sep10/malformed-jwt');

    const future = await audit([token(validPayload({ iat: NOW_SECONDS + 3600 }))], {
      expectedDomain: ANCHOR,
    });
    expect(future.diagnostics.map((d) => d.rule)).toContain('sep10/malformed-jwt');
  });

  it('reports issuer mismatch and an invalid subject', async () => {
    const result = await audit([token(validPayload({ iss: 'evil.example.com', sub: 'garbage' }))], {
      expectedDomain: ANCHOR,
    });
    expect(result.diagnostics.map((d) => d.rule)).toContain('sep10/jwt-issuer-mismatch');
    expect(result.diagnostics.map((d) => d.rule)).toContain('sep10/invalid-jwt-subject');
  });

  it('derives the expected issuer from WEB_AUTH_ENDPOINT', async () => {
    const result = await audit([token(validPayload({ iss: 'other.example.com' }))]);
    expect(result.diagnostics.map((d) => d.rule)).toEqual(['sep10/jwt-issuer-mismatch']);
  });

  it('rejects a client_domain that is not a bare DNS name', async () => {
    const result = await audit(
      [token(validPayload({ client_domain: 'https://wallet.example.com/path' }))],
      { expectedDomain: ANCHOR },
    );
    expect(result.diagnostics.map((d) => d.rule)).toEqual(['sep10/unbound-client-domain']);
  });

  it('binds client_domain to the signer in the client stellar.toml', async () => {
    const fetched: string[] = [];
    const fetchImpl = (async (input: string | URL | Request) => {
      fetched.push(String(input));
      if (String(input).includes('wallet.example.com')) {
        return new Response(`SIGNING_KEY = "${CLIENT_SIGNER}"`, { status: 200 });
      }
      return new Response('ACCOUNTS = ["GOTHER"]', { status: 200 });
    }) as unknown as typeof fetch;

    const bound = await new Sep10JwtAuditor(fetchImpl, {
      tokens: [token(validPayload({ client_domain: 'wallet.example.com' }))],
      expectedDomain: ANCHOR,
      clientSigner: CLIENT_SIGNER,
      now: NOW,
    }).verify(DOC);
    expect(bound.diagnostics).toEqual([]);
    expect(fetched[0]).toBe('https://wallet.example.com/.well-known/stellar.toml');

    const unbound = await new Sep10JwtAuditor(
      (async () =>
        new Response('SIGNING_KEY = "GSOMEONEELSE"', { status: 200 })) as unknown as typeof fetch,
      {
        tokens: [token(validPayload({ client_domain: 'wallet.example.com' }))],
        expectedDomain: ANCHOR,
        clientSigner: CLIENT_SIGNER,
        now: NOW,
      },
    ).verify(DOC);
    expect(unbound.diagnostics.map((d) => d.rule)).toEqual(['sep10/unbound-client-domain']);

    const down = await new Sep10JwtAuditor(
      (async () => {
        throw new Error('offline');
      }) as unknown as typeof fetch,
      {
        tokens: [token(validPayload({ client_domain: 'wallet.example.com' }))],
        expectedDomain: ANCHOR,
        clientSigner: CLIENT_SIGNER,
        now: NOW,
      },
    ).verify(DOC);
    expect(down.diagnostics.map((d) => d.rule)).toEqual(['sep10/jwt-unverifiable']);
  });

  it('skips client-domain fetching without a signer or when disabled', async () => {
    let fetched = 0;
    const fetchImpl = (async () => {
      fetched++;
      return new Response('', { status: 200 });
    }) as unknown as typeof fetch;
    const result = await auditSep10Jwt(DOC, fetchImpl, {
      tokens: [token(validPayload({ client_domain: 'wallet.example.com' }))],
      expectedDomain: ANCHOR,
      now: NOW,
    });
    expect(result.diagnostics).toEqual([]);
    expect(fetched).toBe(0);
  });

  it('reports when no token is supplied', async () => {
    const result = await audit([]);
    expect(result.diagnostics.map((d) => d.rule)).toEqual(['sep10/jwt-unverifiable']);
    expect(result.summary).toContain('No tokens');
  });

  it('honours severity overrides', async () => {
    const result = await audit([token(validPayload({ iss: 'evil.example.com' }))], {
      expectedDomain: ANCHOR,
      rules: { 'sep10/jwt-issuer-mismatch': 'off' },
    });
    expect(result.diagnostics).toEqual([]);
  });
});
