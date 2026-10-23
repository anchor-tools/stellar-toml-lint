import { describe, expect, it, vi } from 'vitest';
import {
  checkSubdomainTakeover,
  SECURITY_DANGLING_CNAME_TAKEOVER_RISK,
} from '../../src/security/subdomain-takeover.js';

function response(body: string): Response {
  return new Response(body, { status: 404 });
}

describe('subdomain takeover auditor', () => {
  it('reports an unclaimed GitHub Pages alias', async () => {
    const diagnostics = await checkSubdomainTakeover(
      { DOCUMENTATION: { ORG_URL: 'https://docs.anchor.example' } },
      {
        resolveCname: async () => ['samjay8.github.io'],
        fetchImpl: (async () => response("There isn't a GitHub Pages site here.")) as typeof fetch,
      },
    );

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      rule: SECURITY_DANGLING_CNAME_TAKEOVER_RISK,
      severity: 'error',
      path: 'DOCUMENTATION.ORG_URL',
    });
  });

  it('does not report a claimed provider endpoint without its unclaimed signature', async () => {
    const fetchImpl = vi.fn(async () => response('Welcome to our documentation')) as typeof fetch;
    const diagnostics = await checkSubdomainTakeover(
      { TRANSFER_SERVER: 'https://api.anchor.example' },
      { resolveCname: async () => ['claimed.herokuapp.com'], fetchImpl },
    );

    expect(diagnostics).toEqual([]);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it('does not perform DNS lookups when its rule is disabled', async () => {
    const resolveCname = vi.fn();
    await expect(
      checkSubdomainTakeover(
        { TRANSFER_SERVER: 'https://api.anchor.example' },
        {
          resolveCname,
          rules: { [SECURITY_DANGLING_CNAME_TAKEOVER_RISK]: 'off' },
        },
      ),
    ).resolves.toEqual([]);
    expect(resolveCname).not.toHaveBeenCalled();
  });
});
