import { describe, expect, it } from 'vitest';
import {
  DirectorySyncVerifier,
  diffAnchor,
  extractPublishedAnchor,
  mapPool,
  normalizeAsset,
  normalizeDomain,
  normalizeServiceKey,
  normalizeUrl,
  parseDirectoryFeed,
  renderDirectorySyncReport,
} from '../src/protocols/directorySyncVerifier.js';

const TOML = `
SIGNING_KEY = "GAAAA"
CURRENCIES = [{ code = "USD", issuer = "GISSUER" }]
TRANSFER_SERVER = "https://anchor.example/sep24"
ANCHOR_QUOTE_SERVER = "https://anchor.example/sep38"
`;

const feedEntry = {
  domain: 'anchor.example',
  name: 'Example Anchor',
  signingKey: 'GAAAA',
  assets: ['usd:GISSUER'],
  serviceUrls: {
    transferServer: 'https://anchor.example/sep24/',
    ANCHOR_QUOTE_SERVER: 'https://anchor.example/sep38',
  },
};

const fetchImpl = (async (input: string | URL | Request) => {
  const url = String(input);
  if (url.includes('dead.example')) throw new Error('connection refused');
  if (url.includes('gone.example')) return new Response('missing', { status: 404 });
  if (url.includes('broken.example')) {
    return new Response('this is = not valid toml [', {
      headers: { 'content-type': 'text/plain' },
    });
  }
  return new Response(TOML, { headers: { 'content-type': 'text/plain' } });
}) as unknown as typeof fetch;

describe('directory feed parsing', () => {
  it('normalizes domains, assets, service keys, and URLs', () => {
    expect(normalizeDomain('https://Anchor.Example/path?q=1')).toBe('anchor.example');
    expect(normalizeDomain('not a domain')).toBeUndefined();
    expect(normalizeAsset('usd:GISSUER')).toBe('USD:GISSUER');
    expect(normalizeAsset({ code: 'eur', issuer: 'GISSUER' })).toBe('EUR:GISSUER');
    expect(normalizeServiceKey('transfer_server')).toBe('TRANSFER_SERVER');
    expect(normalizeServiceKey('transferServer')).toBe('TRANSFER_SERVER');
    expect(normalizeUrl('https://Anchor.Example/sep24/')).toBe('https://anchor.example/sep24');
  });

  it('accepts an object feed with camelCase and snake_case fields', () => {
    const parsed = parseDirectoryFeed({
      anchors: [
        {
          home_domain: 'anchor.example',
          organization: 'Example',
          currencies: [{ code: 'usd', issuer: 'GISSUER' }],
          signing_key: 'GAAAA',
          services: { transferServer: 'https://anchor.example/sep24' },
          valid_until: '2027-01-01T00:00:00Z',
        },
        { name: 'no domain here' },
        { domain: 'anchor.example' },
      ],
    });

    expect(parsed.anchors).toHaveLength(1);
    expect(parsed.anchors[0]).toMatchObject({
      domain: 'anchor.example',
      name: 'Example',
      assets: ['USD:GISSUER'],
      signingKey: 'GAAAA',
      serviceUrls: { TRANSFER_SERVER: 'https://anchor.example/sep24' },
      expiresAt: '2027-01-01T00:00:00Z',
    });
    expect(parsed.problems).toHaveLength(2);
  });

  it('rejects feeds without an entries array', () => {
    expect(parseDirectoryFeed({ wrong: true }).problems[0]).toContain('must be a JSON array');
    expect(parseDirectoryFeed(null).anchors).toEqual([]);
  });

  it('extracts published signing keys, assets, and service URLs', () => {
    const published = extractPublishedAnchor({
      SIGNING_KEY: 'GAAAA',
      CURRENCIES: [{ code: 'usd', issuer: 'GISSUER' }],
      TRANSFER_SERVER: 'https://anchor.example/sep24',
    });
    expect(published).toEqual({
      signingKey: 'GAAAA',
      assets: ['USD:GISSUER'],
      serviceUrls: { TRANSFER_SERVER: 'https://anchor.example/sep24' },
    });
  });
});

describe('diffAnchor', () => {
  it('returns no drift for a matching record', () => {
    const published = extractPublishedAnchor({
      SIGNING_KEY: 'GAAAA',
      CURRENCIES: [{ code: 'USD', issuer: 'GISSUER' }],
      TRANSFER_SERVER: 'https://anchor.example/sep24',
      ANCHOR_QUOTE_SERVER: 'https://anchor.example/sep38',
    });
    expect(diffAnchor(parseDirectoryFeed({ anchors: [feedEntry] }).anchors[0]!, published)).toEqual(
      [],
    );
  });

  it('reports every changed field', () => {
    const published = extractPublishedAnchor({
      SIGNING_KEY: 'GNEW',
      CURRENCIES: [{ code: 'EUR', issuer: 'GISSUER' }],
      TRANSFER_SERVER: 'https://anchor.example/v2',
    });
    const drift = diffAnchor(parseDirectoryFeed({ anchors: [feedEntry] }).anchors[0]!, published);
    expect(drift.map((field) => field.field).sort()).toEqual([
      'ANCHOR_QUOTE_SERVER',
      'CURRENCIES',
      'SIGNING_KEY',
      'TRANSFER_SERVER',
    ]);
  });
});

describe('DirectorySyncVerifier', () => {
  it('marks a matching anchor in sync', async () => {
    const parsed = parseDirectoryFeed({ anchors: [feedEntry] });
    const report = await new DirectorySyncVerifier({ fetchImpl }).verify(parsed.anchors, 'feed');
    expect(report.ok).toBe(true);
    expect(report.inSync).toBe(1);
    expect(report.results[0]?.status).toBe('in-sync');
    expect(report.findings).toEqual([]);
    expect(renderDirectorySyncReport(report)).toContain('1 in sync');
  });

  it('reports drift with the changed fields', async () => {
    const drifted = {
      ...feedEntry,
      signingKey: 'GOLD',
      assets: ['EUR:GISSUER'],
      serviceUrls: { transferServer: 'https://old.example/sep24' },
    };
    const parsed = parseDirectoryFeed({ anchors: [drifted] });
    const report = await new DirectorySyncVerifier({ fetchImpl }).verify(parsed.anchors);
    expect(report.ok).toBe(false);
    expect(report.drifted).toBe(1);
    expect(report.results[0]?.status).toBe('drift');
    expect(report.findings[0]).toMatchObject({
      code: 'directory/out-of-sync',
      severity: 'error',
      domain: 'anchor.example',
    });
    expect(report.findings[0]?.fields?.sort()).toEqual([
      'CURRENCIES',
      'SIGNING_KEY',
      'TRANSFER_SERVER',
    ]);
    const rendered = renderDirectorySyncReport(report);
    expect(rendered).toContain('SIGNING_KEY');
    expect(rendered).toContain('fail');
  });

  it('flags expired listings as a warning, not an error', async () => {
    const expired = { ...feedEntry, expiresAt: '2020-01-01T00:00:00Z' };
    const parsed = parseDirectoryFeed({ anchors: [expired] });
    const report = await new DirectorySyncVerifier({
      fetchImpl,
      now: new Date('2026-01-01T00:00:00Z'),
    }).verify(parsed.anchors);
    expect(report.ok).toBe(true);
    expect(report.expired).toBe(1);
    expect(report.results[0]?.status).toBe('expired');
    expect(report.findings[0]?.code).toBe('directory/expired-anchor');
  });

  it('separates unresolvable domains from invalid TOML', async () => {
    const parsed = parseDirectoryFeed({
      anchors: [
        { domain: 'dead.example' },
        { domain: 'gone.example' },
        { domain: 'broken.example' },
      ],
    });
    const report = await new DirectorySyncVerifier({ fetchImpl }).verify(parsed.anchors);
    expect(report.ok).toBe(false);
    expect(report.results.map((result) => result.status)).toEqual([
      'unresolvable',
      'unresolvable',
      'invalid-toml',
    ]);
    expect(report.findings.map((finding) => finding.code)).toEqual([
      'directory/unresolvable-domain',
      'directory/unresolvable-domain',
      'directory/invalid-stellar-toml',
    ]);
  });

  it('times out a hanging domain instead of blocking the batch', async () => {
    const hanging = (() => new Promise<Response>(() => {})) as unknown as typeof fetch;
    const parsed = parseDirectoryFeed({ anchors: [{ domain: 'slow.example' }] });
    const report = await new DirectorySyncVerifier({ fetchImpl: hanging, timeoutMs: 20 }).verify(
      parsed.anchors,
    );
    expect(report.results[0]?.status).toBe('unresolvable');
    expect(report.results[0]?.error).toContain('timed out');
  });

  it('warns when the feed has no usable anchors', async () => {
    const report = await new DirectorySyncVerifier({ fetchImpl }).verify([]);
    expect(report.ok).toBe(true);
    expect(report.findings[0]?.code).toBe('directory/no-anchors');
  });

  it('respects the concurrency limit', async () => {
    let active = 0;
    let peak = 0;
    const results = await mapPool([1, 2, 3, 4, 5], 2, async (value) => {
      active++;
      peak = Math.max(peak, active);
      await new Promise((resolve) => setTimeout(resolve, 5));
      active--;
      return value * 2;
    });
    expect(results).toEqual([2, 4, 6, 8, 10]);
    expect(peak).toBeLessThanOrEqual(2);
  });
});
