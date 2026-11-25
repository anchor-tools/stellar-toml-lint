import { describe, expect, it } from 'vitest';
import { RateLimitHeaderVerifier } from '../../src/telemetry/rateLimitHeaderVerifier.js';

describe('RateLimitHeaderVerifier', () => {
  const verifier = new RateLimitHeaderVerifier();

  it('validates compliant IETF RateLimit headers', () => {
    const headers = {
      'ratelimit-limit': '100',
      'ratelimit-remaining': '95',
      'ratelimit-reset': '60',
    };

    const result = verifier.verifyHeaders(headers, 200);
    expect(result.ok).toBe(true);
    expect(result.standard).toBe('ietf');
    expect(result.limit).toBe(100);
    expect(result.remaining).toBe(95);
    expect(result.reset).toBe(60);
    expect(result.findings.length).toBe(0);
  });

  it('detects legacy X-RateLimit headers and reports info finding', () => {
    const headers = {
      'x-ratelimit-limit': '50',
      'x-ratelimit-remaining': '10',
      'x-ratelimit-reset': '30',
    };

    const result = verifier.verifyHeaders(headers, 200);
    expect(result.standard).toBe('legacy');
    expect(result.limit).toBe(50);
    expect(result.findings.some((f) => f.rule === 'ratelimit/legacy-headers-used')).toBe(true);
  });

  it('validates RFC 6585 Retry-After delta-seconds on HTTP 429', () => {
    const headers = {
      'ratelimit-limit': '100',
      'ratelimit-remaining': '0',
      'ratelimit-reset': '120',
      'retry-after': '120',
    };

    const result = verifier.verifyHeaders(headers, 429);
    expect(result.ok).toBe(true);
    expect(result.retryAfterSeconds).toBe(120);
    expect(result.findings.some((f) => f.rule === 'ratelimit/missing-retry-after')).toBe(false);
  });

  it('validates RFC 7231 HTTP-date in Retry-After on HTTP 429', () => {
    const futureDate = new Date(Date.now() + 60000).toUTCString();
    const headers = {
      'ratelimit-limit': '100',
      'ratelimit-remaining': '0',
      'retry-after': futureDate,
    };

    const result = verifier.verifyHeaders(headers, 429);
    expect(result.ok).toBe(true);
    expect(result.retryAfterDate).toBeDefined();
    expect(result.retryAfterSeconds).toBeGreaterThan(0);
  });

  it('flags missing Retry-After header under status 429', () => {
    const headers = {
      'ratelimit-limit': '100',
      'ratelimit-remaining': '0',
    };

    const result = verifier.verifyHeaders(headers, 429);
    expect(result.ok).toBe(false);
    expect(result.findings.some((f) => f.rule === 'ratelimit/missing-retry-after')).toBe(true);
  });

  it('flags inconsistent headers (remaining > limit, negative reset)', () => {
    const headers = {
      'ratelimit-limit': '100',
      'ratelimit-remaining': '150',
      'ratelimit-reset': '-10',
    };

    const result = verifier.verifyHeaders(headers, 200);
    expect(result.ok).toBe(false);
    expect(result.findings.some((f) => f.rule === 'ratelimit/inconsistent-remaining')).toBe(true);
    expect(result.findings.some((f) => f.rule === 'ratelimit/inconsistent-reset')).toBe(true);
  });

  it('renders human-readable and JSON reports', () => {
    const headers = {
      'ratelimit-limit': '100',
      'ratelimit-remaining': '80',
    };
    const result = verifier.verifyHeaders(headers, 200, 'https://example.com/api');

    const textReport = verifier.renderReport(result, 'text');
    expect(textReport).toContain('Rate Limit Compliance Report');
    expect(textReport).toContain('Limit:       100');

    const jsonReport = verifier.renderReport(result, 'json');
    const parsed = JSON.parse(jsonReport);
    expect(parsed.limit).toBe(100);
  });

  it('simulates structured bursts with mock fetch', async () => {
    let callCount = 0;
    const mockFetch = async () => {
      callCount++;
      return {
        status: callCount >= 2 ? 429 : 200,
        headers: new Headers({
          'ratelimit-limit': '2',
          'ratelimit-remaining': callCount >= 2 ? '0' : '1',
          'ratelimit-reset': '60',
          ...(callCount >= 2 ? { 'retry-after': '60' } : {}),
        }),
      } as unknown as Response;
    };

    const result = await verifier.verifyEndpoint('https://api.example.com/endpoint', {
      burstCount: 3,
      fetchImpl: mockFetch as any,
    });

    expect(callCount).toBe(2);
    expect(result.statusCode).toBe(429);
    expect(result.ok).toBe(true);
  });
});
