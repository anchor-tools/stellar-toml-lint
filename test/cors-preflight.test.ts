import { strict as assert } from 'node:assert';
import { describe, it } from 'vitest';
import { checkCorsPreflight } from '../src/network/cors-preflight.js';

const endpoints = {
  WEB_AUTH_ENDPOINT: 'https://anchor.example/auth',
  TRANSFER_SERVER: 'https://anchor.example/transfer',
  KYC_SERVER: 'https://anchor.example/kyc',
  ANCHOR_QUOTE_SERVER: 'https://anchor.example/quote',
};

function response(headers: Record<string, string> = {}): Response {
  return new Response(null, {
    status: 204,
    headers,
  });
}

describe('cors-preflight', () => {
  it('checks every declared service endpoint with OPTIONS', async () => {
    const requests: Array<{ url: string; method?: string }> = [];
    const fetchStub = async (url: string | URL, init?: RequestInit) => {
      requests.push({ url: url.toString(), method: init?.method });
      return response({
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      });
    };

    const diagnostics = await checkCorsPreflight(endpoints, fetchStub as typeof fetch);

    assert.equal(diagnostics.length, 0);
    assert.deepEqual(
      requests,
      Object.values(endpoints).map((url) => ({ url, method: 'OPTIONS' })),
    );
  });

  it('accepts the requesting origin and reports missing allow headers', async () => {
    const fetchStub = async () =>
      response({
        'Access-Control-Allow-Origin': 'https://stellar-toml-lint.invalid',
        'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      });

    const diagnostics = await checkCorsPreflight(
      { WEB_AUTH_ENDPOINT: endpoints.WEB_AUTH_ENDPOINT },
      fetchStub as typeof fetch,
    );

    assert.equal(diagnostics.length, 1);
    assert.equal(diagnostics[0]?.rule, 'network/missing-allow-headers');
    assert.equal(diagnostics[0]?.severity, 'warning');
  });

  it('reports invalid pre-flight responses and transport failures', async () => {
    let calls = 0;
    const fetchStub = async () => {
      calls++;
      if (calls === 1) {
        return response({
          'Access-Control-Allow-Origin': 'https://wrong.example',
          'Access-Control-Allow-Methods': 'GET',
        });
      }
      throw new Error('offline');
    };

    const diagnostics = await checkCorsPreflight(
      {
        WEB_AUTH_ENDPOINT: endpoints.WEB_AUTH_ENDPOINT,
        TRANSFER_SERVER: endpoints.TRANSFER_SERVER,
      },
      fetchStub as typeof fetch,
    );

    assert.equal(diagnostics.length, 3);
    assert.equal(diagnostics[0]?.rule, 'network/cors-preflight-failed');
    assert.equal(diagnostics[1]?.rule, 'network/missing-allow-headers');
    assert.equal(diagnostics[2]?.rule, 'network/cors-preflight-failed');
  });
});
