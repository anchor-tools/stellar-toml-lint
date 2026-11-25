import { describe, expect, it } from 'vitest';
import {
  IpSpoofingVulnerabilityDetector,
  SPOOF_HEADERS,
  auditIpSpoofing,
  findReflectedHeaders,
  ipSpoofingRuleIds,
  proxyHopCount,
  rateLimitRemaining,
} from '../../src/protocols/ipSpoofingDetector.js';

const DOC = { TRANSFER_SERVER_SEP0024: 'https://api.example.com/sep24' };

type Handler = (headers: Headers) => {
  status?: number;
  body?: string;
  headers?: Record<string, string>;
};

/** A mock server; records every request it receives. */
function server(handler: Handler, log: { url: string; headers: Headers }[] = []): typeof fetch {
  return (async (url: string, init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    log.push({ url, headers });
    const out = handler(headers);
    return new Response(out.body ?? '{}', { status: out.status ?? 200, headers: out.headers });
  }) as unknown as typeof fetch;
}

/** A rate limiter keyed on the connecting address only (a secure proxy setup). */
function secureLimiter(): typeof fetch {
  let remaining = 60;
  return server(() => ({ headers: { 'X-RateLimit-Remaining': String(--remaining) } }));
}

/** A rate limiter keyed on whatever X-Forwarded-For says. */
function vulnerableLimiter(): typeof fetch {
  const buckets = new Map<string, number>();
  return server((h) => {
    const key = h.get('x-forwarded-for') ?? 'socket';
    const left = (buckets.get(key) ?? 60) - 1;
    buckets.set(key, left);
    return { headers: { 'X-RateLimit-Remaining': String(left) } };
  });
}

const rules = (r: { diagnostics: { rule: string }[] }): string[] =>
  r.diagnostics.map((d) => d.rule).sort();

describe('IpSpoofingVulnerabilityDetector', () => {
  it('registers rule ids', () => {
    expect(ipSpoofingRuleIds).toContain('ipspoof/rate-limit-bypass');
  });

  it('reads rate-limit and Via headers', () => {
    expect(rateLimitRemaining(new Headers({ 'X-RateLimit-Remaining': '7' }))).toBe(7);
    expect(rateLimitRemaining(new Headers({ 'RateLimit-Remaining': '3' }))).toBe(3);
    expect(rateLimitRemaining(new Headers({ RateLimit: '"default";r=12;t=30' }))).toBe(12);
    expect(rateLimitRemaining(new Headers({ 'X-RateLimit-Remaining': 'lots' }))).toBeUndefined();
    expect(rateLimitRemaining(new Headers())).toBeUndefined();
    expect(proxyHopCount(new Headers({ Via: '1.1 cf, 1.1 nginx, 1.1 envoy' }))).toBe(3);
    expect(proxyHopCount(new Headers())).toBe(0);
  });

  it('does nothing without the probe option', async () => {
    const log: { url: string; headers: Headers }[] = [];
    const r = await auditIpSpoofing(
      DOC,
      server(() => ({}), log),
    );
    expect(r.diagnostics).toEqual([]);
    expect(log).toEqual([]);
  });

  it('passes a backend that ignores spoofed headers, using three requests per endpoint', async () => {
    const log: { url: string; headers: Headers }[] = [];
    let remaining = 60;
    const fetchImpl = server(
      () => ({ headers: { 'X-RateLimit-Remaining': String(--remaining) } }),
      log,
    );
    const r = await auditIpSpoofing(DOC, fetchImpl, { probe: true });
    expect(r.diagnostics).toEqual([]);
    expect(log.map((l) => l.url)).toEqual(Array(3).fill('https://api.example.com/sep24/info'));
    expect(log[2]?.headers.get('x-real-ip')).toBe(SPOOF_HEADERS['X-Real-IP']);
    expect(r.endpoints[0]).toMatchObject({ rateLimitBypass: false, reflectedHeaders: [] });
    expect((await auditIpSpoofing(DOC, secureLimiter(), { probe: true })).diagnostics).toEqual([]);
  });

  it('detects a rate limiter keyed on X-Forwarded-For', async () => {
    const r = await auditIpSpoofing(DOC, vulnerableLimiter(), { probe: true });
    expect(rules(r)).toEqual(['ipspoof/rate-limit-bypass']);
    expect(r.diagnostics[0]?.severity).toBe('error');
    expect(r.diagnostics[0]?.suggestion).toContain('set_real_ip_from');
    expect(r.diagnostics[0]?.suggestion).toContain('Cloudflare');
  });

  it('detects a 429 that disappears when headers are spoofed', async () => {
    const fetchImpl = server((h) => ({ status: h.has('x-real-ip') ? 200 : 429 }));
    const r = await auditIpSpoofing(DOC, fetchImpl, { probe: true });
    expect(rules(r)).toEqual(['ipspoof/rate-limit-bypass']);
  });

  it('detects reflected client IP headers and an unstripped forwarded chain', async () => {
    const fetchImpl = server((h) => ({
      body: JSON.stringify({ client_ip: h.get('x-forwarded-for') ?? '10.0.0.1' }),
    }));
    const r = await auditIpSpoofing(DOC, fetchImpl, { probe: true });
    expect(rules(r)).toEqual(['ipspoof/forwarded-chain-not-stripped', 'ipspoof/header-reflected']);
    expect(r.endpoints[0]?.reflectedHeaders).toEqual(['X-Forwarded-For']);
  });

  it('finds addresses reflected in response headers', () => {
    const headers = new Headers({ 'X-Client-IP': SPOOF_HEADERS['CF-Connecting-IP'] as string });
    expect(findReflectedHeaders({ text: '', headers })).toEqual(['CF-Connecting-IP']);
  });

  it('reports long proxy chains', async () => {
    const fetchImpl = server(() => ({ headers: { Via: '1.1 a, 1.1 b, 1.1 c, 1.1 d' } }));
    const r = await new IpSpoofingVulnerabilityDetector(fetchImpl, { probe: true }).detect(DOC);
    expect(rules(r)).toEqual(['ipspoof/excess-proxy-hops']);
    const relaxed = await auditIpSpoofing(DOC, fetchImpl, { probe: true, maxProxyHops: 4 });
    expect(relaxed.diagnostics).toEqual([]);
  });

  it('skips non-https endpoints and survives unreachable ones', async () => {
    const failing = (async () => {
      throw new Error('ECONNRESET');
    }) as unknown as typeof fetch;
    const r = await auditIpSpoofing(
      { ...DOC, WEB_AUTH_ENDPOINT: 'http://insecure.example.com/auth', KYC_SERVER: 42 },
      failing,
      { probe: true },
    );
    expect(rules(r)).toEqual(['ipspoof/endpoint-unreachable']);
    expect(r.endpoints).toEqual([]);
  });

  it('honours rule overrides', async () => {
    const r = await auditIpSpoofing(DOC, vulnerableLimiter(), {
      probe: true,
      rules: { 'ipspoof/rate-limit-bypass': 'off' },
    });
    expect(r.diagnostics).toEqual([]);
  });
});
