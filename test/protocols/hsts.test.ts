import { describe, expect, it } from 'vitest';
import {
  HstsSecurityVerifier,
  auditHsts,
  collectHosts,
  hstsRuleIds,
  parseHsts,
  renderHstsBadges,
} from '../../src/security/hstsVerifier.js';

const DOC = {
  ORG_URL: 'https://example.com',
  TRANSFER_SERVER_SEP0024: 'https://api.example.com/sep24',
  DOCUMENTATION: { ORG_URL: 'https://example.com' },
};

const headers = (byHost: Record<string, string | undefined>): typeof fetch =>
  (async (url: string) => {
    const host = new URL(url).hostname;
    const value = byHost[host];
    return new Response(null, {
      headers: value === undefined ? {} : { 'strict-transport-security': value },
    });
  }) as unknown as typeof fetch;

const FULL = 'max-age=63072000; includeSubDomains; preload';

describe('parseHsts', () => {
  it('parses a full policy, quoted values and case-insensitive names', () => {
    expect(parseHsts('Max-Age="31536000"; IncludeSubDomains; Preload')).toEqual({
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    });
  });

  it('rejects malformed headers', () => {
    expect(parseHsts('includeSubDomains')).toEqual({ error: 'max-age directive is required' });
    expect(parseHsts('max-age=abc')).toMatchObject({ error: expect.stringContaining('integer') });
    expect(parseHsts('max-age=-5')).toHaveProperty('error');
    expect(parseHsts('max-age=1; max-age=2')).toMatchObject({
      error: expect.stringContaining('duplicate'),
    });
    expect(parseHsts('max-age')).toHaveProperty('error');
  });
});

describe('HstsSecurityVerifier', () => {
  it('registers rule ids', () => {
    expect(hstsRuleIds).toContain('hsts/short-max-age');
  });

  it('collects the apex and declared subdomains once', () => {
    expect(collectHosts(DOC, 'example.com')).toEqual(['example.com', 'api.example.com']);
  });

  it('passes fully compliant hosts with preload-ready badges', async () => {
    const r = await auditHsts(
      DOC,
      headers({ 'example.com': FULL, 'api.example.com': 'max-age=31536000' }),
      {
        domain: 'example.com',
      },
    );
    expect(r.diagnostics).toEqual([]);
    expect(r.hosts.map((h) => h.badge)).toEqual(['PRELOAD-READY', 'COMPLIANT']);
    expect(renderHstsBadges(r)).toContain('[PRELOAD-READY] example.com (apex)');
  });

  it('flags missing headers', async () => {
    const r = await auditHsts(DOC, headers({}), { domain: 'example.com' });
    expect(r.diagnostics.map((d) => d.rule)).toEqual([
      'hsts/missing-header',
      'hsts/missing-header',
    ]);
    expect(r.hosts[0]?.badge).toBe('FAIL');
  });

  it('flags short-lived max-age', async () => {
    const r = await auditHsts(
      { ORG_URL: 'https://example.com' },
      headers({ 'example.com': 'max-age=300; includeSubDomains; preload' }),
    );
    expect(r.diagnostics.map((d) => d.rule)).toEqual(['hsts/short-max-age']);
  });

  it('requires includeSubDomains and preload on the apex only', async () => {
    const r = await auditHsts(
      DOC,
      headers({ 'example.com': 'max-age=31536000', 'api.example.com': 'max-age=31536000' }),
      {
        domain: 'example.com',
      },
    );
    expect(r.diagnostics.map((d) => d.rule)).toEqual([
      'hsts/missing-include-subdomains',
      'hsts/missing-preload',
    ]);
    expect(r.hosts[0]?.badge).toBe('PARTIAL');
  });

  it('reports non-standard header formats as errors', async () => {
    const r = await auditHsts(
      { ORG_URL: 'https://example.com' },
      headers({ 'example.com': 'max-age=soon' }),
    );
    expect(r.diagnostics[0]?.rule).toBe('hsts/invalid-header');
    expect(r.diagnostics[0]?.severity).toBe('error');
  });

  it('does not reject on unreachable hosts and honours overrides', async () => {
    const failing = (async () => {
      throw new Error('ECONNREFUSED');
    }) as unknown as typeof fetch;
    const r = await new HstsSecurityVerifier(failing, {
      rules: { 'hsts/unreachable': 'off' },
    }).verify({
      ORG_URL: 'https://example.com',
    });
    expect(r.diagnostics).toEqual([]);
    expect(r.hosts[0]?.badge).toBe('UNREACHABLE');
    const on = await auditHsts({ ORG_URL: 'https://example.com' }, failing);
    expect(on.diagnostics[0]?.rule).toBe('hsts/unreachable');
  });

  it('is silent with nothing to check', async () => {
    const r = await auditHsts({}, headers({}));
    expect(r.hosts).toEqual([]);
    expect(renderHstsBadges(r)).toBe('');
  });
});
