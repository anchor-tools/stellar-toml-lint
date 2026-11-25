import { describe, expect, it } from 'vitest';
import {
  FederationSrvRecordVerifier,
  federationSrvRuleIds,
  isValidSrvTarget,
  verifyFederationSrv,
  type SrvRecord,
} from '../../src/protocols/federationSrvVerifier.js';

const rec = (name: string, port = 443, priority = 10, weight = 5): SrvRecord => ({
  name,
  port,
  priority,
  weight,
});
const resolverOf = (records: SrvRecord[]) => async () => records;
const DOC = { FEDERATION_SERVER: 'https://fed.example.com/federation' };
const fed = (body: unknown, status = 200): typeof fetch =>
  (async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    })) as unknown as typeof fetch;

describe('FederationSrvRecordVerifier', () => {
  it('registers rule ids', () => {
    expect(federationSrvRuleIds).toContain('federationsrv/conflicts-with-toml');
  });

  it('validates SRV targets', () => {
    expect(isValidSrvTarget('fed.example.com.')).toBe(true);
    expect(isValidSrvTarget('.')).toBe(false);
    expect(isValidSrvTarget('10.0.0.1')).toBe(false);
    expect(isValidSrvTarget('bad_host.example.com')).toBe(false);
  });

  it('is silent for a valid, matching record', async () => {
    const r = await verifyFederationSrv(DOC, fed({ account_id: 'G' }), {
      domain: 'example.com',
      resolver: resolverOf([rec('fed.example.com.')]),
      probe: true,
    });
    expect(r.diagnostics).toEqual([]);
  });

  it('is silent when DNS has no SRV record', async () => {
    const r = await verifyFederationSrv(DOC, fetch, {
      domain: 'example.com',
      resolver: async () => {
        throw new Error('ENODATA');
      },
    });
    expect(r).toEqual({ diagnostics: [], records: [] });
  });

  it('reports broken targets, ports and priority/weight', async () => {
    const r = await verifyFederationSrv({}, fetch, {
      domain: 'example.com',
      resolver: resolverOf([
        rec('.'),
        rec('a.example.com', 70000),
        rec('b.example.com', 8443, 70000, 1),
        rec('c.example.com', 443, 1, 0),
        rec('d.example.com', 443, 1, 0),
      ]),
    });
    const rules = r.diagnostics.map((d) => d.rule);
    expect(rules).toEqual(
      expect.arrayContaining([
        'federationsrv/invalid-target',
        'federationsrv/invalid-port',
        'federationsrv/invalid-priority-weight',
        'federationsrv/non-default-port',
      ]),
    );
    expect(
      r.diagnostics.filter((d) => d.rule === 'federationsrv/invalid-priority-weight'),
    ).toHaveLength(2);
  });

  it('warns when the SRV host conflicts with FEDERATION_SERVER', async () => {
    const r = await verifyFederationSrv(DOC, fetch, {
      domain: 'example.com',
      resolver: resolverOf([rec('other.example.net.')]),
    });
    expect(r.diagnostics.map((d) => d.rule)).toEqual(['federationsrv/conflicts-with-toml']);
  });

  it('flags targets that do not host SEP-2 or are down', async () => {
    const html = (async () => new Response('<html>', { status: 200 })) as unknown as typeof fetch;
    const notFed = await verifyFederationSrv(DOC, html, {
      domain: 'example.com',
      resolver: resolverOf([rec('fed.example.com')]),
      probe: true,
    });
    expect(notFed.diagnostics[0]?.rule).toBe('federationsrv/not-a-federation-server');
    const down = await verifyFederationSrv(DOC, fed({}, 503), {
      domain: 'example.com',
      resolver: resolverOf([rec('fed.example.com')]),
      probe: true,
    });
    expect(down.diagnostics[0]?.rule).toBe('federationsrv/unreachable-target');
  });

  it('times out on hanging targets instead of stalling', async () => {
    const hang = ((_u: string, init?: RequestInit) =>
      new Promise((_res, rej) => {
        init?.signal?.addEventListener('abort', () => rej(new Error('aborted')));
      })) as unknown as typeof fetch;
    const r = await new FederationSrvRecordVerifier(hang, {
      domain: 'example.com',
      resolver: resolverOf([rec('fed.example.com')]),
      probe: true,
      timeoutMs: 20,
    }).verify(DOC);
    expect(r.diagnostics[0]?.rule).toBe('federationsrv/unreachable-target');
    expect(r.diagnostics[0]?.message).toContain('aborted');
  });

  it('honours severity overrides', async () => {
    const r = await verifyFederationSrv(DOC, fetch, {
      domain: 'example.com',
      rules: { 'federationsrv/conflicts-with-toml': 'off' },
      resolver: resolverOf([rec('other.example.net.')]),
    });
    expect(r.diagnostics).toEqual([]);
  });
});
