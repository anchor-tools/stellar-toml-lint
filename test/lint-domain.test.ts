import { describe, expect, it } from 'vitest';
import { lintDomain } from '../src/lint.js';

const GOOD_TOML = [
  'VERSION="2.7.0"',
  'NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"',
  '',
  '[DOCUMENTATION]',
  'ORG_NAME="Example"',
  'ORG_URL="https://example.com"',
  'ORG_DESCRIPTION="Example"',
  'ORG_LOGO="https://example.com/logo.png"',
  'ORG_OFFICIAL_EMAIL="ops@example.com"',
].join('\n');

interface StubOptions {
  headers?: Record<string, string>;
  status?: number;
  body?: string;
}

/**
 * A fetch stub that records the request, so tests can assert on what the linter
 * sent as well as what it did with the response.
 */
function stubFetch(options: StubOptions = {}) {
  const calls: { url: string; headers: Record<string, string> }[] = [];

  const impl = (async (url: string | URL, init?: RequestInit) => {
    calls.push({
      url: String(url),
      headers: (init?.headers ?? {}) as Record<string, string>,
    });
    return new Response(options.body ?? GOOD_TOML, {
      status: options.status ?? 200,
      headers: {
        'content-type': 'text/plain',
        ...(options.headers ?? { 'access-control-allow-origin': '*' }),
      },
    });
  }) as unknown as typeof fetch;

  return { impl, calls };
}

const ruleIds = (result: { diagnostics: { rule: string }[] }): string[] =>
  result.diagnostics.map((d) => d.rule);

describe('lintDomain', () => {
  it('requests the well-known path over https', async () => {
    const { impl, calls } = stubFetch();
    await lintDomain('example.com', {}, impl);
    expect(calls[0]?.url).toBe('https://example.com/.well-known/stellar.toml');
  });

  it('normalises a domain given with a scheme or path', async () => {
    const { impl, calls } = stubFetch();
    await lintDomain('https://example.com/some/path', {}, impl);
    expect(calls[0]?.url).toBe('https://example.com/.well-known/stellar.toml');
  });

  it('sends an Origin header so CORS is evaluated as a browser would', async () => {
    // Regression: many hosts only emit Access-Control-Allow-Origin when the
    // request carries Origin. Probing without it reported a CORS failure
    // against correctly-configured anchors.
    const { impl, calls } = stubFetch();
    await lintDomain('example.com', {}, impl);
    expect(calls[0]?.headers.Origin).toBeTruthy();
  });

  it('accepts a wildcard CORS header', async () => {
    const { impl } = stubFetch({ headers: { 'access-control-allow-origin': '*' } });
    const result = await lintDomain('example.com', {}, impl);
    expect(ruleIds(result)).not.toContain('network/cors');
  });

  it('rejects a missing CORS header', async () => {
    const { impl } = stubFetch({ headers: {} });
    const result = await lintDomain('example.com', {}, impl);
    expect(ruleIds(result)).toContain('network/cors');
  });

  it('rejects a non-wildcard CORS header', async () => {
    const { impl } = stubFetch({
      headers: { 'access-control-allow-origin': 'https://example.com' },
    });
    const result = await lintDomain('example.com', {}, impl);
    const cors = result.diagnostics.find((d) => d.rule === 'network/cors');
    expect(cors?.message).toContain('requires');
  });

  it('warns when the content type is not text/plain', async () => {
    const { impl } = stubFetch({
      headers: { 'access-control-allow-origin': '*', 'content-type': 'application/octet-stream' },
    });
    const result = await lintDomain('example.com', {}, impl);
    expect(ruleIds(result)).toContain('network/content-type');
  });

  it('reports an HTTP error and stops', async () => {
    const { impl } = stubFetch({ status: 404 });
    const result = await lintDomain('example.com', {}, impl);
    expect(ruleIds(result)).toEqual(['network/unreachable']);
    expect(result.ok).toBe(false);
  });

  it('reports a transport failure without throwing', async () => {
    const failing = (async () => {
      throw new Error('getaddrinfo ENOTFOUND');
    }) as unknown as typeof fetch;

    const result = await lintDomain('nope.invalid', {}, failing);
    expect(ruleIds(result)).toEqual(['network/unreachable']);
    expect(result.diagnostics[0]?.message).toContain('ENOTFOUND');
  });

  it('infers the domain so ORG_URL is checked against the serving host', async () => {
    const { impl } = stubFetch();
    const result = await lintDomain('different-domain.org', {}, impl);
    expect(ruleIds(result)).toContain('documentation/org-url-matches-domain');
  });

  it('still lints the file contents it fetched', async () => {
    const { impl } = stubFetch({ body: 'VERSION="two"\n' });
    const result = await lintDomain('example.com', {}, impl);
    expect(ruleIds(result)).toContain('general/version');
  });
});
