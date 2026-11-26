import { describe, expect, it } from 'vitest';
import {
  MIN_HSTS_MAX_AGE_SECONDS,
  Sep24WebviewSecurityValidator,
  auditSep24WebviewSecurity,
  collectResourceUrls,
  frameAncestorsAreWildcard,
  parseCsp,
  renderSep24SecurityReport,
  scriptsWithoutSri,
  sep24SecurityRuleIds,
  sep24SecurityRules,
} from '../src/protocols/sep24Security.js';

const TOKEN = 'header.payload.signature';

const HARDENED_HEADERS: Record<string, string> = {
  'content-security-policy':
    "default-src 'self'; script-src https://cdn.anchor.test; frame-ancestors https://wallet.test",
  'x-frame-options': 'DENY',
  'strict-transport-security': `max-age=${MIN_HSTS_MAX_AGE_SECONDS}; includeSubDomains`,
  'referrer-policy': 'strict-origin-when-cross-origin',
};

const HARDENED_HTML =
  '<html><head><script src="https://cdn.anchor.test/app.js" integrity="sha384-abc" crossorigin="anonymous"></script></head><body></body></html>';

interface ServerOptions {
  headers?: Record<string, string>;
  html?: string;
  interactiveStatus?: number;
  missingUrl?: boolean;
  throwOnPage?: boolean;
}

function mockServer(options: ServerOptions = {}) {
  const calls: string[] = [];
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input));
    calls.push(`${init?.method ?? 'GET'} ${url.pathname}`);
    if (/\/transactions\/(deposit|withdraw)\/interactive$/.test(url.pathname)) {
      if (options.interactiveStatus !== undefined && options.interactiveStatus >= 400) {
        return new Response('no', { status: options.interactiveStatus });
      }
      return Response.json(
        options.missingUrl === true
          ? { id: '1' }
          : { url: 'https://anchor.test/interactive/abc?session=example', id: '1' },
      );
    }
    if (url.pathname === '/interactive/abc') {
      if (options.throwOnPage === true) throw new Error('page unreachable');
      return new Response(options.html ?? '<html></html>', {
        status: 200,
        headers: options.headers ?? {},
      });
    }
    return new Response('not found', { status: 404 });
  }) as unknown as typeof fetch;
  return { fetchImpl, calls };
}

const DOC = { TRANSFER_SERVER_SEP0024: 'https://anchor.test/sep24' };

describe('CSP helpers', () => {
  it('parses directives case-insensitively', () => {
    const csp = parseCsp("DEFAULT-SRC 'self'; frame-ancestors https://a.test https://b.test");
    expect(csp.get('default-src')).toEqual(["'self'"]);
    expect(csp.get('frame-ancestors')).toEqual(['https://a.test', 'https://b.test']);
  });

  it('detects wildcard frame-ancestors forms', () => {
    expect(frameAncestorsAreWildcard(['*'])).toBe(true);
    expect(frameAncestorsAreWildcard(['https:'])).toBe(true);
    expect(frameAncestorsAreWildcard(['https://wallet.test'])).toBe(false);
  });

  it('collects plain-HTTP and script resources', () => {
    const html =
      '<script src="https://cdn.test/a.js"></script><link href="http://cdn.test/b.css"><form action="//cdn.test/post">';
    const result = collectResourceUrls(html);
    expect(result.scripts).toEqual(['https://cdn.test/a.js']);
    expect(result.insecure).toEqual(['http://cdn.test/b.css', '//cdn.test/post']);
  });

  it('finds third-party scripts without integrity', () => {
    const html =
      '<script src="https://a.test/a.js" integrity="sha384-x"></script>' +
      '<script src="https://b.test/b.js"></script>' +
      '<script src="/local.js"></script>';
    expect(scriptsWithoutSri(html)).toEqual(['https://b.test/b.js']);
  });

  it('registers unique rule ids', () => {
    expect(new Set(sep24SecurityRuleIds).size).toBe(sep24SecurityRuleIds.length);
    expect(sep24SecurityRules).toHaveLength(sep24SecurityRuleIds.length);
  });
});

describe('Sep24WebviewSecurityValidator', () => {
  it('passes a hardened webview', async () => {
    const { fetchImpl, calls } = mockServer({
      headers: HARDENED_HEADERS,
      html: HARDENED_HTML,
    });
    const result = await new Sep24WebviewSecurityValidator(fetchImpl, { token: TOKEN }).audit(DOC);

    expect(result.diagnostics).toEqual([]);
    expect(result.report.ok).toBe(true);
    expect(result.report.interactiveUrl).toBe('https://anchor.test/interactive/abc');
    expect(JSON.stringify(result.report)).not.toContain('session=example');
    expect(result.report.headers.frameAncestors).toEqual(['https://wallet.test']);
    expect(calls).toEqual(['POST /sep24/transactions/deposit/interactive', 'GET /interactive/abc']);
    expect(renderSep24SecurityReport(result.report)).toContain('PASS');
  });

  it('flags every missing security header', async () => {
    const { fetchImpl } = mockServer();
    const result = await new Sep24WebviewSecurityValidator(fetchImpl, { token: TOKEN }).audit(DOC);
    const codes = result.diagnostics.map((d) => d.rule);
    expect(codes).toContain('sep24/webview-missing-csp');
    expect(codes).toContain('sep24/webview-missing-frame-ancestors');
    expect(codes).toContain('sep24/webview-missing-hsts');
    expect(codes).toContain('sep24/webview-missing-referrer-policy');
    expect(result.report.ok).toBe(false);
  });

  it('flags a wildcard frame-ancestors policy', async () => {
    const { fetchImpl } = mockServer({
      headers: { ...HARDENED_HEADERS, 'content-security-policy': 'frame-ancestors *' },
    });
    const result = await new Sep24WebviewSecurityValidator(fetchImpl, { token: TOKEN }).audit(DOC);
    expect(result.diagnostics.map((d) => d.rule)).toContain(
      'sep24/webview-wildcard-frame-ancestors',
    );
  });

  it('flags a deprecated X-Frame-Options value', async () => {
    const { fetchImpl } = mockServer({
      headers: { ...HARDENED_HEADERS, 'x-frame-options': 'ALLOW-FROM https://wallet.test' },
    });
    const result = await new Sep24WebviewSecurityValidator(fetchImpl, { token: TOKEN }).audit(DOC);
    expect(result.diagnostics.map((d) => d.rule)).toContain('sep24/webview-weak-frame-options');
  });

  it('flags a short HSTS max-age', async () => {
    const { fetchImpl } = mockServer({
      headers: { ...HARDENED_HEADERS, 'strict-transport-security': 'max-age=300' },
    });
    const result = await new Sep24WebviewSecurityValidator(fetchImpl, { token: TOKEN }).audit(DOC);
    expect(result.diagnostics.map((d) => d.rule)).toContain('sep24/webview-weak-hsts');
  });

  it('flags HSTS without max-age', async () => {
    const { fetchImpl } = mockServer({
      headers: { ...HARDENED_HEADERS, 'strict-transport-security': 'includeSubDomains' },
    });
    const result = await new Sep24WebviewSecurityValidator(fetchImpl, { token: TOKEN }).audit(DOC);
    expect(result.diagnostics.map((d) => d.rule)).toContain('sep24/webview-weak-hsts');
  });

  it('flags a referrer policy that leaks the session URL', async () => {
    const { fetchImpl } = mockServer({
      headers: { ...HARDENED_HEADERS, 'referrer-policy': 'unsafe-url' },
    });
    const result = await new Sep24WebviewSecurityValidator(fetchImpl, { token: TOKEN }).audit(DOC);
    expect(result.diagnostics.map((d) => d.rule)).toContain('sep24/webview-weak-referrer-policy');
  });

  it('flags mixed content and scripts without SRI', async () => {
    const html =
      '<script src="http://cdn.test/a.js"></script>' +
      '<script src="https://cdn.test/b.js"></script>' +
      '<img src="http://images.test/logo.png">';
    const { fetchImpl } = mockServer({ headers: HARDENED_HEADERS, html });
    const result = await new Sep24WebviewSecurityValidator(fetchImpl, { token: TOKEN }).audit(DOC);

    expect(result.diagnostics.map((d) => d.rule)).toContain('sep24/webview-mixed-content');
    expect(result.diagnostics.map((d) => d.rule)).toContain('sep24/webview-script-without-sri');
    expect(result.report.mixedContent).toHaveLength(2);
  });

  it('starts a withdrawal session when asked', async () => {
    const { fetchImpl, calls } = mockServer({
      headers: HARDENED_HEADERS,
      html: HARDENED_HTML,
    });
    const result = await new Sep24WebviewSecurityValidator(fetchImpl, {
      token: TOKEN,
      withdraw: true,
      assetCode: 'EURC',
    }).audit(DOC);
    expect(calls[0]).toBe('POST /sep24/transactions/withdraw/interactive');
    expect(result.report.ok).toBe(true);
  });

  it('reports missing transfer server and token as unverifiable', async () => {
    const { fetchImpl } = mockServer();
    const noServer = await auditSep24WebviewSecurity({}, fetchImpl, { token: TOKEN });
    expect(noServer.diagnostics.map((d) => d.rule)).toEqual(['sep24/webview-unverifiable']);

    const noToken = await auditSep24WebviewSecurity(DOC, fetchImpl, {});
    expect(noToken.diagnostics.map((d) => d.rule)).toEqual(['sep24/webview-unverifiable']);
  });

  it('does not transmit the token to an HTTP transfer server', async () => {
    const { fetchImpl, calls } = mockServer();
    const result = await new Sep24WebviewSecurityValidator(fetchImpl, { token: TOKEN }).audit({
      TRANSFER_SERVER_SEP0024: 'http://anchor.test/sep24',
    });
    expect(result.diagnostics[0]?.message).toContain('must use HTTPS');
    expect(calls).toEqual([]);
  });

  it('reports a failed interactive session request', async () => {
    const { fetchImpl } = mockServer({ interactiveStatus: 500 });
    const result = await new Sep24WebviewSecurityValidator(fetchImpl, { token: TOKEN }).audit(DOC);
    expect(result.diagnostics[0]?.message).toContain('HTTP 500');
    expect(result.report.ok).toBe(false);
  });

  it('reports a response with no interactive url', async () => {
    const { fetchImpl } = mockServer({ missingUrl: true });
    const result = await new Sep24WebviewSecurityValidator(fetchImpl, { token: TOKEN }).audit(DOC);
    expect(result.diagnostics[0]?.message).toContain('no `url`');
  });

  it('reports an unreachable interactive page', async () => {
    const { fetchImpl } = mockServer({ throwOnPage: true });
    const result = await new Sep24WebviewSecurityValidator(fetchImpl, { token: TOKEN }).audit(DOC);
    expect(result.diagnostics.map((d) => d.rule)).toContain('sep24/webview-unverifiable');
    expect(result.report.ok).toBe(false);
  });

  it('honours severity overrides', async () => {
    const { fetchImpl } = mockServer();
    const result = await new Sep24WebviewSecurityValidator(fetchImpl, {
      token: TOKEN,
      rules: {
        'sep24/webview-missing-csp': 'off',
        'sep24/webview-missing-frame-ancestors': 'off',
        'sep24/webview-missing-hsts': 'off',
        'sep24/webview-missing-referrer-policy': 'off',
      },
    }).audit(DOC);
    expect(result.diagnostics).toEqual([]);
  });
});
