import { describe, expect, it } from 'vitest';
import {
  checkDnsIntegrity,
  type DnsResolver,
  SECURITY_DNS_RESOLVER_DIVERGENCE,
  SECURITY_DNSSEC_NOT_ENABLED,
} from '../src/security/dns-integrity.js';

const RESOLVERS: readonly DnsResolver[] = [
  { name: 'one', server: '1.1.1.1', endpoint: 'https://one.example/dns-query' },
  { name: 'two', server: '8.8.8.8', endpoint: 'https://two.example/dns-query' },
  { name: 'three', server: '9.9.9.9', endpoint: 'https://three.example/dns-query' },
];

const DOC = {
  DOCUMENTATION: { ORG_URL: 'https://anchor.example.com' },
};

function response(addresses: string[], ad = true, type = 'A'): Response {
  return new Response(
    JSON.stringify({
      AD: ad,
      Answer: addresses.map((address) => ({ type: type === 'AAAA' ? 28 : 1, data: address })),
    }),
    { headers: { 'content-type': 'application/json' } },
  );
}

describe('DNS integrity', () => {
  it('passes when resolver answers agree and DNSSEC is authenticated', async () => {
    const calls: string[] = [];
    const fetchImpl = (async (input: Parameters<typeof fetch>[0]) => {
      const url = new URL(String(input));
      calls.push(url.toString());
      return response(['192.0.2.1'], true, url.searchParams.get('type') ?? 'A');
    }) as typeof fetch;
    const diagnostics = await checkDnsIntegrity(DOC, fetchImpl, { resolvers: RESOLVERS });
    expect(diagnostics).toEqual([]);
    expect(calls).toHaveLength(6);
  });

  it('reports divergent A records', async () => {
    const fetchImpl = (async (input: Parameters<typeof fetch>[0]) => {
      const url = new URL(String(input));
      return response(
        url.hostname === 'two.example' ? ['192.0.2.2'] : ['192.0.2.1'],
        true,
        url.searchParams.get('type') ?? 'A',
      );
    }) as typeof fetch;
    const diagnostics = await checkDnsIntegrity(DOC, fetchImpl, { resolvers: RESOLVERS });
    expect(diagnostics[0]?.rule).toBe(SECURITY_DNS_RESOLVER_DIVERGENCE);
  });

  it('warns when the authenticated-data flag is false', async () => {
    const fetchImpl = (async () => response(['192.0.2.1'], false)) as typeof fetch;
    const diagnostics = await checkDnsIntegrity(DOC, fetchImpl, { resolvers: RESOLVERS });
    expect(diagnostics[0]).toMatchObject({
      rule: SECURITY_DNSSEC_NOT_ENABLED,
      severity: 'warning',
    });
  });

  it('does not query without a domain', async () => {
    let calls = 0;
    const fetchImpl = (async () => {
      calls++;
      return response(['192.0.2.1']);
    }) as typeof fetch;
    expect(await checkDnsIntegrity({}, fetchImpl)).toEqual([]);
    expect(calls).toBe(0);
  });
});
