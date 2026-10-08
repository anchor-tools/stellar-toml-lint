import { describe, expect, it } from 'vitest';
import {
  checkTokenBinding,
  JWT_DOMAIN_MISMATCH_RULE,
  JWT_REJECTED_RULE,
} from '../../src/security/token-binding.js';

function createMockJwt(payload: Record<string, unknown>): string {
  const header = btoa(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' }))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  const body = btoa(JSON.stringify(payload))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  const signature = 'mock_signature';
  return `${header}.${body}.${signature}`;
}

describe('checkTokenBinding', () => {
  const domain = 'example.com';
  const webAuthEndpoint = 'https://auth.example.com/auth';
  const transferServer = 'https://transfer.example.com/sep24';
  const kycServer = 'https://kyc.example.com/sep12';
  const directPaymentServer = 'https://direct.example.com/sep31';

  const baseDoc = {
    WEB_AUTH_ENDPOINT: webAuthEndpoint,
    TRANSFER_SERVER_SEP0024: transferServer,
    KYC_SERVER: kycServer,
    DIRECT_PAYMENT_SERVER: directPaymentServer,
    DOCUMENTATION: {
      ORG_URL: 'https://example.com',
    },
  };

  it('passes cleanly when all endpoints accept the token and domain matches', async () => {
    const validJwt = createMockJwt({
      iss: 'https://example.com/auth',
      sub: 'GAHK7EEG2WWHVKDNT4CEQFZGKF2LGDSBRTC4TQBXXK2ZBDUFLYWWDZDT',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    });

    const fetchImpl = (async (url: string | URL | Request, init?: RequestInit) => {
      const urlStr = String(url);
      if (urlStr.includes('/auth')) {
        return new Response(JSON.stringify({ token: validJwt }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      // Downstream endpoints receiving token
      if (init?.headers && (init.headers as Record<string, string>).Authorization) {
        return new Response(JSON.stringify({ ok: true }), { status: 200 });
      }
      return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
    }) as unknown as typeof fetch;

    const diagnostics = await checkTokenBinding(baseDoc, fetchImpl, { domain });
    expect(diagnostics).toEqual([]);
  });

  it('asserts security/jwt-rejected-by-transfer-server when transfer server rejects token', async () => {
    const validJwt = createMockJwt({
      iss: 'https://example.com/auth',
      sub: 'GAHK7EEG2WWHVKDNT4CEQFZGKF2LGDSBRTC4TQBXXK2ZBDUFLYWWDZDT',
    });

    const fetchImpl = (async (url: string | URL | Request) => {
      const urlStr = String(url);
      if (urlStr.includes('/auth')) {
        return new Response(JSON.stringify({ token: validJwt }), { status: 200 });
      }
      if (urlStr.includes('/sep24')) {
        return new Response(JSON.stringify({ error: 'Invalid auth token' }), { status: 401 });
      }
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    }) as unknown as typeof fetch;

    const diagnostics = await checkTokenBinding(baseDoc, fetchImpl, { domain });
    expect(diagnostics.some((d) => d.rule === JWT_REJECTED_RULE)).toBe(true);
    expect(diagnostics[0]?.severity).toBe('error');
    expect(diagnostics[0]?.path).toBe('TRANSFER_SERVER_SEP0024');
  });

  it('asserts security/jwt-domain-mismatch when iss claim points to different domain', async () => {
    const mismatchedJwt = createMockJwt({
      iss: 'https://evil-anchor.com/auth',
      sub: 'GAHK7EEG2WWHVKDNT4CEQFZGKF2LGDSBRTC4TQBXXK2ZBDUFLYWWDZDT',
    });

    const fetchImpl = (async (url: string | URL | Request) => {
      const urlStr = String(url);
      if (urlStr.includes('/auth')) {
        return new Response(JSON.stringify({ token: mismatchedJwt }), { status: 200 });
      }
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    }) as unknown as typeof fetch;

    const diagnostics = await checkTokenBinding(baseDoc, fetchImpl, { domain });
    expect(diagnostics.some((d) => d.rule === JWT_DOMAIN_MISMATCH_RULE)).toBe(true);
    expect(diagnostics[0]?.severity).toBe('error');
  });

  it('returns empty diagnostics when WEB_AUTH_ENDPOINT is not declared', async () => {
    const docWithoutAuth = {
      TRANSFER_SERVER_SEP0024: transferServer,
    };
    const diagnostics = await checkTokenBinding(docWithoutAuth);
    expect(diagnostics).toEqual([]);
  });
});
