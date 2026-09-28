import { describe, expect, it } from 'vitest';
import {
  checkRateLimitResilience,
  computeBackoffDelayMs,
  NETWORK_MISSING_RATE_LIMIT_HEADERS,
  NETWORK_UNSTANDARDIZED_RATE_LIMIT_RESPONSE,
} from '../src/network/rate-limit-tester.js';

const STANDARD_HEADERS = {
  'X-RateLimit-Limit': '100',
  'X-RateLimit-Remaining': '99',
  'X-RateLimit-Reset': '1700000000',
};

function jsonResponse(
  body: unknown,
  init: { status?: number; headers?: Record<string, string> } = {},
): Response {
  return new Response(JSON.stringify(body), {
    status: init.status ?? 200,
    headers: { 'content-type': 'application/json', ...(init.headers ?? {}) },
  });
}

describe('rate limit tester', () => {
  it('passes when Horizon returns standard rate-limit headers', async () => {
    const fetchImpl = (async () => jsonResponse({}, { headers: STANDARD_HEADERS })) as typeof fetch;

    const diagnostics = await checkRateLimitResilience({
      horizonUrl: 'https://horizon.example',
      fetchImpl,
    });

    expect(diagnostics).toEqual([]);
  });

  it('warns when rate-limit headers are missing', async () => {
    const fetchImpl = (async () => jsonResponse({})) as typeof fetch;

    const diagnostics = await checkRateLimitResilience({
      horizonUrl: 'https://horizon.example',
      fetchImpl,
    });

    expect(diagnostics.map((d) => d.rule)).toContain(NETWORK_MISSING_RATE_LIMIT_HEADERS);
  });

  it('errors when a 429 lacks RFC 7807 problem details', async () => {
    const fetchImpl = (async () =>
      jsonResponse({ error: 'slow down' }, { status: 429, headers: STANDARD_HEADERS })) as typeof fetch;

    const diagnostics = await checkRateLimitResilience({
      horizonUrl: 'https://horizon.example',
      fetchImpl,
    });

    expect(diagnostics.map((d) => d.rule)).toContain(
      NETWORK_UNSTANDARDIZED_RATE_LIMIT_RESPONSE,
    );
  });

  it('accepts a 429 that returns problem details', async () => {
    const fetchImpl = (async () =>
      jsonResponse(
        { type: 'about:blank', title: 'Too Many Requests', status: 429 },
        { status: 429, headers: { ...STANDARD_HEADERS, 'content-type': 'application/problem+json' } },
      )) as typeof fetch;

    const diagnostics = await checkRateLimitResilience({
      horizonUrl: 'https://horizon.example',
      fetchImpl,
    });

    expect(diagnostics).toEqual([]);
  });

  it('degrades to silence when Horizon is unreachable', async () => {
    const fetchImpl = (async () => {
      throw new Error('ECONNREFUSED');
    }) as unknown as typeof fetch;

    expect(
      await checkRateLimitResilience({ horizonUrl: 'https://horizon.example', fetchImpl }),
    ).toEqual([]);
  });

  it('computes capped exponential backoff delays', () => {
    expect(computeBackoffDelayMs(1)).toBe(1000);
    expect(computeBackoffDelayMs(3)).toBe(4000);
    expect(computeBackoffDelayMs(10)).toBe(60000);
  });
});
