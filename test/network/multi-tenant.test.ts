import { describe, expect, it } from 'vitest';
import {
  auditMultiTenantRouting,
  multiTenantRules,
  INVALID_HOST_ROUTING_RULE,
  TENANT_CROSS_CONTAMINATION_RULE,
} from '../../src/network/multi-tenant.js';

const ACME_TOML = `VERSION = "2.7.0"
SIGNING_KEY = "GACMEACMEACMEACMEACMEACMEACMEACMEACMEACMEACMEACMEACMEAC"

[DOCUMENTATION]
ORG_NAME = "Acme Anchor"
ORG_URL = "https://anchor.example.com"
`;

const GLOBEX_TOML = `VERSION = "2.7.0"
SIGNING_KEY = "GGLOBEXGLOBEXGLOBEXGLOBEXGLOBEXGLOBEXGLOBEXGLOBEXGLOBEXG"

[DOCUMENTATION]
ORG_NAME = "Globex Anchor"
ORG_URL = "https://globex.example.com"
`;

const DOC = {
  VERSION: '2.7.0',
  SIGNING_KEY: 'GACMEACMEACMEACMEACMEACMEACMEACMEACMEACMEACMEACMEACMEAC',
  DOCUMENTATION: { ORG_NAME: 'Acme Anchor', ORG_URL: 'https://anchor.example.com' },
};

function requestedHost(init?: RequestInit): string {
  const headers = new Headers(init?.headers);
  return (headers.get('x-forwarded-host') ?? headers.get('host') ?? '').toLowerCase();
}

/** Routes `/.well-known/stellar.toml` by the forwarded host header. */
function tenantFetch(
  documents: Record<string, string>,
  options: { accessControlAllowOrigin?: string } = {},
): typeof fetch {
  return (async (input: unknown, init?: RequestInit) => {
    const url = new URL(String(input));
    const host = requestedHost(init);
    const body = documents[host];

    if (body === undefined) {
      return new Response('not found', { status: 404 });
    }

    return new Response(body, {
      status: 200,
      headers: {
        'content-type': 'application/toml',
        'access-control-allow-origin': options.accessControlAllowOrigin ?? `https://${url.host}`,
      },
    });
  }) as unknown as typeof fetch;
}

describe('auditMultiTenantRouting', () => {
  it('passes isolated tenants that honour the host header', async () => {
    const diagnostics = await auditMultiTenantRouting(
      DOC,
      tenantFetch({
        'anchor.example.com': ACME_TOML,
        'globex.example.com': GLOBEX_TOML,
      }),
      { tenantHosts: ['globex.example.com'] },
    );

    expect(diagnostics).toEqual([]);
  });

  it('asserts network/tenant-cross-contamination when a sibling host is served this tenant', async () => {
    const diagnostics = await auditMultiTenantRouting(
      DOC,
      tenantFetch({
        'anchor.example.com': ACME_TOML,
        'globex.example.com': GLOBEX_TOML,
      }),
      { tenantHosts: ['globex.example.com'] },
    );

    expect(diagnostics.filter((d) => d.rule === TENANT_CROSS_CONTAMINATION_RULE)).toEqual([]);

    const leaky = await auditMultiTenantRouting(
      DOC,
      tenantFetch({
        'anchor.example.com': ACME_TOML,
        'globex.example.com': ACME_TOML,
      }),
      { tenantHosts: ['globex.example.com'] },
    );

    const hit = leaky.find((d) => d.rule === TENANT_CROSS_CONTAMINATION_RULE);
    expect(hit?.severity).toBe('error');
    expect(hit?.message).toContain('globex.example.com');
  });

  it('asserts network/tenant-cross-contamination when the primary file carries sibling data', async () => {
    const contaminatedToml = `VERSION = "2.7.0"
SIGNING_KEY = "GGLOBEXGLOBEXGLOBEXGLOBEXGLOBEXGLOBEXGLOBEXGLOBEXGLOBEXG"

[DOCUMENTATION]
ORG_NAME = "Acme Anchor"
ORG_URL = "https://anchor.example.com"
`;

    const diagnostics = await auditMultiTenantRouting(
      DOC,
      tenantFetch({
        'anchor.example.com': contaminatedToml,
        'globex.example.com': GLOBEX_TOML,
      }),
      { tenantHosts: ['globex.example.com'] },
    );

    const hit = diagnostics.find((d) => d.rule === TENANT_CROSS_CONTAMINATION_RULE);
    expect(hit?.severity).toBe('error');
    expect(hit?.message).toContain('globex.example.com');
  });

  it('asserts network/invalid-host-routing when an unknown host is served the primary file', async () => {
    const ignoresHost = (async (_input: unknown, init?: RequestInit) => {
      const host = requestedHost(init);
      return new Response(host === 'globex.example.com' ? GLOBEX_TOML : ACME_TOML, {
        status: 200,
        headers: { 'content-type': 'application/toml' },
      });
    }) as unknown as typeof fetch;

    const diagnostics = await auditMultiTenantRouting(DOC, ignoresHost, {
      tenantHosts: ['globex.example.com'],
    });
    const hit = diagnostics.find((d) => d.rule === INVALID_HOST_ROUTING_RULE);
    expect(hit?.severity).toBe('warning');
    expect(hit?.message).toContain('stellar-toml-lint.invalid');
  });

  it('asserts network/invalid-host-routing when CORS does not reflect the tenant', async () => {
    const diagnostics = await auditMultiTenantRouting(
      DOC,
      tenantFetch(
        { 'anchor.example.com': ACME_TOML },
        { accessControlAllowOrigin: 'https://sibling.example.com' },
      ),
      {},
    );

    const hit = diagnostics.find((d) => d.rule === INVALID_HOST_ROUTING_RULE);
    expect(hit?.severity).toBe('warning');
    expect(hit?.message).toContain('Access-Control-Allow-Origin');
  });

  it('accepts a wildcard CORS origin and a reflecting one', async () => {
    const wildcard = await auditMultiTenantRouting(
      DOC,
      tenantFetch({ 'anchor.example.com': ACME_TOML }, { accessControlAllowOrigin: '*' }),
      {},
    );
    expect(wildcard).toEqual([]);

    const reflecting = await auditMultiTenantRouting(
      DOC,
      tenantFetch(
        { 'anchor.example.com': ACME_TOML },
        { accessControlAllowOrigin: 'https://anchor.example.com' },
      ),
      {},
    );
    expect(reflecting).toEqual([]);
  });

  it('stays silent without a domain and without ORG_URL', async () => {
    const diagnostics = await auditMultiTenantRouting(
      { VERSION: '2.7.0' },
      tenantFetch({ 'anchor.example.com': ACME_TOML }),
    );

    expect(diagnostics).toEqual([]);
  });

  it('stays silent when the transport fails', async () => {
    const failing = (async () => {
      throw new Error('dns failure');
    }) as unknown as typeof fetch;

    const diagnostics = await auditMultiTenantRouting(DOC, failing, {});
    expect(diagnostics).toEqual([]);
  });

  it('uses an explicit domain over the one in ORG_URL', async () => {
    const seen: string[] = [];
    const recording = (async (_input: unknown, init?: RequestInit) => {
      const host = requestedHost(init);
      seen.push(host);
      if (host === 'stellar-toml-lint.invalid') {
        return new Response('not found', { status: 404 });
      }
      return new Response(ACME_TOML, {
        status: 200,
        headers: {
          'content-type': 'application/toml',
          'access-control-allow-origin': 'https://other.example.com',
        },
      });
    }) as unknown as typeof fetch;

    const diagnostics = await auditMultiTenantRouting(DOC, recording, {
      domain: 'other.example.com',
      tenantHosts: ['sibling.example.com'],
    });

    expect(seen[0]).toBe('other.example.com');
    // The wildcard probe also passes the unknown host to the transport.
    expect(seen).toContain('stellar-toml-lint.invalid');
    // The CORS header reflects the explicit domain, so no warning is raised.
    expect(diagnostics.filter((d) => d.rule === INVALID_HOST_ROUTING_RULE)).toEqual([]);
  });

  it('honours a rule override that turns the warning off', async () => {
    const ignoresHost = (async () =>
      new Response(ACME_TOML, {
        status: 200,
        headers: { 'content-type': 'application/toml' },
      })) as unknown as typeof fetch;

    const diagnostics = await auditMultiTenantRouting(DOC, ignoresHost, {
      rules: { [INVALID_HOST_ROUTING_RULE]: 'off' },
      tenantHosts: ['globex.example.com'],
    });

    expect(diagnostics.filter((d) => d.rule === INVALID_HOST_ROUTING_RULE)).toEqual([]);
  });
});

describe('multiTenantRules', () => {
  it('registers both diagnostics', () => {
    const byId = new Map(multiTenantRules.map((rule) => [rule.id, rule]));
    expect([...byId.keys()]).toEqual([TENANT_CROSS_CONTAMINATION_RULE, INVALID_HOST_ROUTING_RULE]);
    expect(byId.get(TENANT_CROSS_CONTAMINATION_RULE)?.severity).toBe('error');
    expect(byId.get(INVALID_HOST_ROUTING_RULE)?.severity).toBe('warning');
  });
});
