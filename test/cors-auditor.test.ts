import { describe, expect, it } from 'vitest';
import {
  CorsSecurityAuditor,
  REQUESTING_ORIGIN,
  UNLISTED_ORIGIN,
  auditCors,
  corsSecurityRuleIds,
  corsTargets,
  renderCorsReport,
} from '../src/security/corsAuditor.js';

const DOC = {
  DOCUMENTATION: { ORG_URL: 'https://anchor.example.com' },
  WEB_AUTH_ENDPOINT: 'https://auth.anchor.example.com/auth',
  KYC_SERVER: 'https://api.anchor.example.com/kyc',
  ANCHOR_QUOTE_SERVER: 'https://api.anchor.example.com/sep38/info',
  TRANSFER_SERVER_SEP0024: 'https://api.anchor.example.com/sep24',
};

/** Public reads are the toml file itself and the SEP-38 info endpoint. */
function isPublicPath(url: URL): boolean {
  return url.pathname === '/.well-known/stellar.toml' || url.pathname.endsWith('/info');
}

function responseTo(origin: string | null, options: RequestInit, methods = 'GET, POST, OPTIONS') {
  const headers: Record<string, string> = {};
  if (origin !== null) headers['access-control-allow-origin'] = origin;
  if (options.method === 'OPTIONS') headers['access-control-allow-methods'] = methods;
  return new Response('{}', { status: 200, headers });
}

/** A server that whitelists the wallet origin and reserves `*` for public reads. */
const compliantFetch = (async (input: string | URL | Request, options?: RequestInit) => {
  const url = new URL(String(input));
  const origin = new Headers(options?.headers).get('origin');
  if (isPublicPath(url)) return responseTo('*', options ?? {});
  return responseTo(origin === REQUESTING_ORIGIN ? REQUESTING_ORIGIN : null, options ?? {});
}) as unknown as typeof fetch;

/** Wildcard on everything, credentials on everything — the OWASP mistake. */
const wildcardCredentialsFetch = (async () =>
  new Response('{}', {
    status: 200,
    headers: {
      'access-control-allow-origin': '*',
      'access-control-allow-credentials': 'true',
      'access-control-allow-methods': 'GET, POST, OPTIONS',
    },
  })) as unknown as typeof fetch;

/** Echoes any Origin back, which means no whitelist exists. */
const echoingFetch = (async (_input: string | URL | Request, options?: RequestInit) => {
  const origin = new Headers(options?.headers).get('origin');
  return new Response('{}', {
    status: 200,
    headers: {
      ...(origin === null ? {} : { 'access-control-allow-origin': origin }),
      'access-control-allow-credentials': 'true',
      'access-control-allow-methods': 'GET, POST, OPTIONS',
    },
  });
}) as unknown as typeof fetch;

describe('corsTargets', () => {
  it('splits the declared endpoints into public and credentialed roles', () => {
    const targets = corsTargets(DOC);
    expect(targets.map((target) => target.role)).toEqual([
      'public',
      'public',
      'authenticated',
      'authenticated',
      'interactive',
    ]);
    expect(targets.map((target) => target.field)).toEqual([
      'DOCUMENTATION.ORG_URL',
      'ANCHOR_QUOTE_SERVER',
      'WEB_AUTH_ENDPOINT',
      'KYC_SERVER',
      'TRANSFER_SERVER_SEP0024',
    ]);
  });

  it('derives the toml origin from a declared endpoint when ORG_URL is absent', () => {
    const targets = corsTargets({ WEB_AUTH_ENDPOINT: 'https://auth.example.com/auth' });
    expect(targets[0]?.url).toBe('https://auth.example.com/.well-known/stellar.toml');
  });

  it('prefers --domain over the document for the toml probe', () => {
    const targets = corsTargets(DOC, { domain: 'wallet.example.org' });
    expect(targets[0]?.url).toBe('https://wallet.example.org/.well-known/stellar.toml');
  });

  it('covers a regulated asset approval server as an interactive endpoint', () => {
    const targets = corsTargets({
      CURRENCIES: [{ approval_server: 'https://kyc.example/approve' }],
    });
    expect(targets.some((target) => target.field.includes('approval_server'))).toBe(true);
  });
});

describe('CorsSecurityAuditor', () => {
  it('registers the CORS rule ids', () => {
    expect(corsSecurityRuleIds).toEqual([
      'cors/public-endpoint-missing-wildcard',
      'cors/wildcard-origin-with-credentials',
      'cors/unlisted-origin-echoed',
      'cors/preflight-not-allowed',
      'cors/endpoint-unreachable',
    ]);
  });

  it('sends a pre-flight, a wallet request and an unlisted-origin request per endpoint', async () => {
    const report = await new CorsSecurityAuditor(compliantFetch, {}).audit(DOC);
    expect(report.observations).toHaveLength(15);
    expect([...new Set(report.observations.map((entry) => entry.probe))].sort()).toEqual([
      'actual',
      'preflight',
      'unlisted-origin',
    ]);
    expect(report.findings).toEqual([]);
    expect(report.ok).toBe(true);
  });

  it('accepts a whitelisted origin with credentials and does not flag it', async () => {
    const { diagnostics } = await auditCors(DOC, compliantFetch);
    expect(diagnostics).toEqual([]);
  });

  it('reports wildcard origins paired with credentials on credentialed endpoints only', async () => {
    const { diagnostics, report } = await auditCors(DOC, wildcardCredentialsFetch);
    expect(report.origin).toBe('https://anchor.example.com');
    const codes = diagnostics.map((diagnostic) => diagnostic.rule);
    expect(codes).toEqual(Array.from({ length: 3 }, () => 'cors/wildcard-origin-with-credentials'));
    expect(diagnostics.every((diagnostic) => diagnostic.severity === 'error')).toBe(true);
    expect(diagnostics.map((diagnostic) => diagnostic.path)).toEqual([
      'WEB_AUTH_ENDPOINT',
      'KYC_SERVER',
      'TRANSFER_SERVER_SEP0024',
    ]);
  });

  it('flags an origin echoed without a whitelist', async () => {
    const { diagnostics } = await auditCors(DOC, echoingFetch);
    const echoed = diagnostics.filter(
      (diagnostic) => diagnostic.rule === 'cors/unlisted-origin-echoed',
    );
    expect(echoed).toHaveLength(3);
    expect(echoed[0]?.message).toContain(UNLISTED_ORIGIN);
    // The same server answers the public reads with an echoed origin instead of `*`.
    expect(diagnostics.map((diagnostic) => diagnostic.rule)).toContain(
      'cors/public-endpoint-missing-wildcard',
    );
  });

  it('warns when a pre-flight is refused', async () => {
    const noPreflightFetch = (async (input: string | URL | Request, options?: RequestInit) => {
      const url = new URL(String(input));
      if (options?.method === 'OPTIONS') return new Response('', { status: 405 });
      return responseTo(isPublicPath(url) ? '*' : REQUESTING_ORIGIN, options ?? {});
    }) as unknown as typeof fetch;
    const report = await new CorsSecurityAuditor(noPreflightFetch, {}).audit(DOC);
    expect(report.findings.map((finding) => finding.code)).toEqual(
      Array.from({ length: 5 }, () => 'cors/preflight-not-allowed'),
    );
    expect(report.ok).toBe(true);
  });

  it('degrades an unreachable endpoint to one warning per target', async () => {
    const failingFetch = (async () => {
      throw new Error('ECONNREFUSED');
    }) as unknown as typeof fetch;
    const { diagnostics, report } = await auditCors(DOC, failingFetch);
    expect(diagnostics).toHaveLength(5);
    expect(diagnostics.every((diagnostic) => diagnostic.rule === 'cors/endpoint-unreachable')).toBe(
      true,
    );
    expect(diagnostics[0]?.category).toBe('network');
    expect(report.observations.every((entry) => entry.error !== undefined)).toBe(true);
  });

  it('honours --off and --error overrides on each rule', async () => {
    const off = await auditCors(DOC, wildcardCredentialsFetch, {
      rules: { 'cors/wildcard-origin-with-credentials': 'off' },
    });
    expect(off.diagnostics).toEqual([]);

    const raised = await auditCors(DOC, compliantFetch, {
      rules: { 'cors/public-endpoint-missing-wildcard': 'error' },
    });
    expect(raised.diagnostics).toEqual([]);
  });

  it('renders the policy of every probe plus each fix', async () => {
    const { report } = await auditCors(DOC, wildcardCredentialsFetch);
    const rendered = renderCorsReport(report);
    expect(rendered).toContain('CORS policy audit: issues found');
    expect(rendered).toContain('served from: https://anchor.example.com');
    expect(rendered).toContain('probes: 15');
    expect(rendered).toContain('cors/wildcard-origin-with-credentials');
    expect(rendered).toContain('fix:');
  });
});
