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
 * sent as well as what it did with the response. Pass a single set of options
 * to answer every URL the same way, or a pathname→options map to answer the
 * well-known and root paths differently.
 */
function stubFetch(options: StubOptions | Record<string, StubOptions> = {}) {
  const calls: { url: string; headers: Record<string, string> }[] = [];
  const routes = isRouteMap(options) ? options : undefined;
  const fallback: StubOptions = isRouteMap(options) ? { status: 404 } : options;

  const impl = (async (url: string | URL, init?: RequestInit) => {
    calls.push({
      url: String(url),
      headers: (init?.headers ?? {}) as Record<string, string>,
    });
    const pathname = new URL(String(url)).pathname;
    const matched = routes?.[pathname] ?? fallback;
    return new Response(matched.body ?? GOOD_TOML, {
      status: matched.status ?? 200,
      headers: {
        'content-type': 'text/plain',
        ...(matched.headers ?? { 'access-control-allow-origin': '*' }),
      },
    });
  }) as unknown as typeof fetch;

  return { impl, calls };
}

function isRouteMap(
  options: StubOptions | Record<string, StubOptions>,
): options is Record<string, StubOptions> {
  return (
    options.status === undefined &&
    options.body === undefined &&
    options.headers === undefined &&
    Object.keys(options).length > 0
  );
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

  it('points at the root when only /.well-known/stellar.toml is missing', async () => {
    const { impl, calls } = stubFetch({
      '/.well-known/stellar.toml': { status: 404 },
      '/stellar.toml': { status: 200 },
    });
    const result = await lintDomain('example.com', {}, impl);

    expect(ruleIds(result)).toContain('network/wrong-path');
    expect(result.diagnostics.find((d) => d.rule === 'network/wrong-path')?.message).toContain(
      'https://example.com/stellar.toml',
    );
    expect(result.ok).toBe(false);

    // Exactly one extra request, and only for the root path.
    expect(calls).toHaveLength(2);
    expect(calls[1]?.url).toBe('https://example.com/stellar.toml');
  });

  it('keeps network/unreachable alone when the root probe also fails', async () => {
    const { impl, calls } = stubFetch({
      '/.well-known/stellar.toml': { status: 404 },
      '/stellar.toml': { status: 404 },
    });
    const result = await lintDomain('example.com', {}, impl);

    expect(ruleIds(result)).toEqual(['network/unreachable']);
    expect(calls).toHaveLength(2);
  });

  it('does not probe the root for a non-404 failure', async () => {
    const { impl, calls } = stubFetch({ status: 500 });
    const result = await lintDomain('example.com', {}, impl);

    expect(ruleIds(result)).toEqual(['network/unreachable']);
    expect(calls).toHaveLength(1);
  });

  it('survives a transport failure on the root probe', async () => {
    const calls: string[] = [];
    const impl = (async (url: string | URL) => {
      calls.push(String(url));
      if (String(url).endsWith('/stellar.toml') && !String(url).includes('.well-known')) {
        throw new Error('socket hang up');
      }
      return new Response('nope', { status: 404 });
    }) as unknown as typeof fetch;

    const result = await lintDomain('example.com', {}, impl);
    expect(ruleIds(result)).toEqual(['network/unreachable']);
    expect(calls).toHaveLength(2);
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

  describe('followTomlPointers', () => {
    it('fetches and lints valid toml pointers', async () => {
      const mainToml = ['[[CURRENCIES]]', 'toml="https://example.com/asset.toml"'].join('\n');
      const assetToml = ['[[CURRENCIES]]', 'code="FOO"', 'issuer="invalid-account"'].join('\n');

      const impl = (async (url: string | URL) => {
        if (String(url).endsWith('stellar.toml')) {
          return new Response(mainToml, {
            status: 200,
            headers: { 'content-type': 'text/plain', 'access-control-allow-origin': '*' },
          });
        } else {
          return new Response(assetToml, {
            status: 200,
            headers: { 'content-type': 'text/plain', 'access-control-allow-origin': '*' },
          });
        }
      }) as unknown as typeof fetch;

      const result = await lintDomain('example.com', { followLinks: true }, impl);

      expect(ruleIds(result)).toContain('currencies/issuer-or-contract');
      const err = result.diagnostics.find((d) => d.rule === 'currencies/issuer-or-contract');
      expect(err?.message).toContain('[https://example.com/asset.toml]');
    });

    it('gracefully handles missing toml pointers as warnings', async () => {
      const mainToml = ['[[CURRENCIES]]', 'toml="https://example.com/broken.toml"'].join('\n');

      const impl = (async (url: string | URL) => {
        if (String(url).endsWith('stellar.toml')) {
          return new Response(mainToml, {
            status: 200,
            headers: { 'content-type': 'text/plain', 'access-control-allow-origin': '*' },
          });
        } else {
          return new Response('Not found', { status: 404 });
        }
      }) as unknown as typeof fetch;

      const result = await lintDomain('example.com', { followLinks: true }, impl);

      expect(ruleIds(result)).toContain('network/toml-pointer-fetch');
      const warn = result.diagnostics.find((d) => d.rule === 'network/toml-pointer-fetch');
      expect(warn?.severity).toBe('warning');
      expect(warn?.message).toContain('HTTP 404');
    });
  });
});

describe('lintDomain ORG_URL probe', () => {
  interface Outcome {
    status?: number;
    headers?: Record<string, string>;
    body?: string;
  }

  /**
   * A stub that serves GOOD_TOML for the well-known path and defers to
   * `handler` for everything else (i.e. the ORG_URL probe), recording calls.
   */
  function routingFetch(handler: (url: string, method: string) => Outcome | 'fail') {
    const calls: { url: string; method: string }[] = [];
    const impl = (async (url: string | URL, init?: RequestInit) => {
      const target = String(url);
      const method = init?.method ?? 'GET';
      calls.push({ url: target, method });
      if (target.endsWith('/.well-known/stellar.toml')) {
        return new Response(GOOD_TOML, {
          status: 200,
          headers: { 'content-type': 'text/plain', 'access-control-allow-origin': '*' },
        });
      }
      const outcome = handler(target, method);
      if (outcome === 'fail') throw new Error('getaddrinfo ENOTFOUND');
      return new Response(outcome.body ?? '', {
        status: outcome.status ?? 200,
        headers: outcome.headers ?? {},
      });
    }) as unknown as typeof fetch;
    return { impl, calls };
  }

  it('probes ORG_URL over HTTPS when --domain is used', async () => {
    const { impl, calls } = routingFetch(() => ({ status: 200 }));
    await lintDomain('example.com', {}, impl);
    const probe = calls.find((c) => c.url === 'https://example.com');
    expect(probe).toBeDefined();
    expect(probe?.method).toBe('HEAD');
  });

  it('does not emit org-url-unreachable when ORG_URL is healthy', async () => {
    const { impl } = routingFetch(() => ({ status: 200 }));
    const result = await lintDomain('example.com', {}, impl);
    expect(ruleIds(result)).not.toContain('network/org-url-unreachable');
  });

  it('emits network/org-url-unreachable when ORG_URL fails DNS or TLS', async () => {
    const { impl } = routingFetch((url) =>
      url === 'https://example.com' ? 'fail' : { status: 200 },
    );
    const result = await lintDomain('example.com', {}, impl);
    const diag = result.diagnostics.find((d) => d.rule === 'network/org-url-unreachable');
    expect(diag).toBeDefined();
    expect(diag?.severity).toBe('error');
    expect(diag?.message).toContain('ENOTFOUND');
  });

  it('emits network/org-url-unreachable when ORG_URL returns an HTTP error', async () => {
    const { impl } = routingFetch(() => ({ status: 503 }));
    const result = await lintDomain('example.com', {}, impl);
    const diag = result.diagnostics.find((d) => d.rule === 'network/org-url-unreachable');
    expect(diag?.message).toContain('503');
  });

  it('falls back to GET when the server rejects HEAD', async () => {
    const { impl, calls } = routingFetch((_url, method) =>
      method === 'HEAD' ? { status: 405 } : { status: 200 },
    );
    const result = await lintDomain('example.com', {}, impl);
    const orgCalls = calls.filter((c) => c.url === 'https://example.com');
    expect(orgCalls[0]?.method).toBe('HEAD');
    expect(orgCalls[1]?.method).toBe('GET');
    expect(ruleIds(result)).not.toContain('network/org-url-unreachable');
  });

  it('skips the probe when the rule is switched off', async () => {
    const { impl, calls } = routingFetch(() => ({ status: 200 }));
    await lintDomain('example.com', { rules: { 'network/org-url-unreachable': 'off' } }, impl);
    expect(calls.find((c) => c.url === 'https://example.com')).toBeUndefined();
  });

  it('offline lint() never probes the network', async () => {
    let probed = false;
    const impl = (async () => {
      probed = true;
      return new Response('VERSION="2.7.0"', { status: 200 });
    }) as unknown as typeof fetch;
    const { lint } = await import('../src/lint.js');
    lint(GOOD_TOML);
    expect(probed).toBe(false);
    void impl;
  });
});
