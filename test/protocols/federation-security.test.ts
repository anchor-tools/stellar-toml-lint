import { describe, expect, it } from 'vitest';
import {
  ERROR_LEAK_PATTERNS,
  FederationSecurityTester,
  INJECTION_PROBES,
  auditFederationSecurity,
  federationSecurityRuleIds,
  findLeakedDetail,
  renderFederationSecurityReport,
} from '../../src/protocols/federationSecurityTester.js';

const SERVER = 'https://anchor.example.com/federation';

const doc = { FEDERATION_SERVER: SERVER };

/** A server that validates q and returns a clean SEP-2 400 for anything odd. */
const compliantFetch = (async (input: string | URL | Request) => {
  const url = new URL(String(input));
  const q = url.searchParams.get('q') ?? '';
  if (q === 'test*example.com') {
    return new Response(JSON.stringify({ stellar_address: q, account_id: 'G' }), { status: 200 });
  }
  return new Response(JSON.stringify({ detail: 'Invalid federation query' }), {
    status: 400,
    headers: { 'content-type': 'application/json' },
  });
}) as unknown as typeof fetch;

/** A server that leaks its database error as a 500. */
const leakingFetch = (async () =>
  new Response('Postgres error: SQLSTATE 42601 syntax error at or near "\'"', {
    status: 500,
  })) as unknown as typeof fetch;

describe('injection probes', () => {
  it('are non-destructive and cover the required characters', () => {
    const payloads = INJECTION_PROBES.join('\n');
    expect(payloads).toContain("'");
    expect(payloads).toContain(';');
    expect(payloads).toContain('\u0000');
    expect(/\p{L}/u.test(payloads)).toBe(true);
    expect(payloads).not.toMatch(/\b(?:DROP|DELETE|TRUNCATE|INSERT|UPDATE)\b/i);
  });

  it('detects database errors, ORM names, and stack traces', () => {
    expect(findLeakedDetail('SQLSTATE 42601')).toBe('SQLSTATE');
    expect(findLeakedDetail('at handler (/srv/app/node_modules/pg/lib/client.js:10:2)')).toContain(
      'stack trace',
    );
    expect(findLeakedDetail('{"detail":"Invalid federation query"}')).toBeUndefined();
    expect(ERROR_LEAK_PATTERNS.length).toBeGreaterThan(5);
  });
});

describe('FederationSecurityTester', () => {
  it('registers rule ids', () => {
    expect(federationSecurityRuleIds).toEqual([
      'federation/missing-server',
      'federation/non-4xx-error',
      'federation/invalid-error-json',
      'federation/error-detail-leak',
      'federation/server-error',
    ]);
  });

  it('passes a compliant server', async () => {
    const tester = new FederationSecurityTester(compliantFetch, { rateLimitMs: 0 });
    const report = await tester.audit(doc);
    expect(report.ok).toBe(true);
    expect(report.probes).toHaveLength(3 + INJECTION_PROBES.length);
    expect(renderFederationSecurityReport(report)).toContain('clean');
  });

  it('flags a server that leaks SQL errors on injection probes', async () => {
    const tester = new FederationSecurityTester(leakingFetch, { rateLimitMs: 0 });
    const report = await tester.audit(doc);
    expect(report.ok).toBe(false);
    const codes = report.findings.map((finding) => finding.code);
    expect(codes).toContain('federation/error-detail-leak');
    expect(codes).toContain('federation/server-error');
  });

  it('fails when FEDERATION_SERVER is absent or not https', async () => {
    const tester = new FederationSecurityTester(compliantFetch, { rateLimitMs: 0 });
    const missing = await tester.audit({});
    expect(missing.findings[0]?.code).toBe('federation/missing-server');
    const insecure = await tester.audit({ FEDERATION_SERVER: 'http://example.com/f' });
    expect(insecure.findings[0]?.code).toBe('federation/missing-server');
  });

  it('warns when an injection probe is accepted with 2xx or returns non-JSON', async () => {
    const oddFetch = (async (input: string | URL | Request) => {
      const q = new URL(String(input)).searchParams.get('q') ?? '';
      if (q.includes("'")) {
        return new Response('<html>Not found</html>', { status: 404 });
      }
      return new Response('{}', { status: 200 });
    }) as unknown as typeof fetch;
    const tester = new FederationSecurityTester(oddFetch, { rateLimitMs: 0 });
    const report = await tester.audit(doc);
    const codes = report.findings.map((finding) => finding.code);
    expect(codes).toContain('federation/invalid-error-json');
  });

  it('produces lint diagnostics for --audit-federation-security', async () => {
    const { diagnostics, report } = await auditFederationSecurity(doc, leakingFetch, {
      rateLimitMs: 0,
    });
    expect(report.ok).toBe(false);
    expect(diagnostics.length).toBe(report.findings.length);
    expect(diagnostics[0]?.category).toBe('network');
    expect(diagnostics[0]?.path).toBe('FEDERATION_SERVER');
  });
});
