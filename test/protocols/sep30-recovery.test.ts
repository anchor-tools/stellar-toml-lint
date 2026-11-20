import { describe, expect, it } from 'vitest';
import {
  Sep30RecoveryVerifier,
  auditSep30Recovery,
  findUnsupportedAuthMethods,
  sep30RuleIds,
} from '../../src/protocols/sep30Verifier.js';

const K1 = 'GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY';
const K2 = 'GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7';

const GOOD = { RECOVERY_SERVER: 'https://recovery.example.com', RECOVERY_SIGNING_KEYS: [K1, K2] };

const respond = (status: number, body: unknown = { error: 'unauthorized' }): typeof fetch =>
  (async () => new Response(JSON.stringify(body), { status })) as unknown as typeof fetch;

describe('Sep30RecoveryVerifier', () => {
  it('registers rule ids', () => {
    expect(sep30RuleIds).toContain('sep30/unauthenticated-recovery');
  });

  it('is silent when no recovery server is declared', async () => {
    const r = await auditSep30Recovery({});
    expect(r.diagnostics).toEqual([]);
  });

  it('passes a compliant two-signer server that demands authentication', async () => {
    const r = await auditSep30Recovery(GOOD, respond(401), { probe: true });
    expect(r.diagnostics).toEqual([]);
    expect(r.endpoints).toEqual({ POST: 401, GET: 401, PUT: 401 });
  });

  it('flags a bad URL and bad keys', async () => {
    const r = await auditSep30Recovery({
      RECOVERY_SERVER: 'http://recovery.example.com',
      RECOVERY_SIGNING_KEYS: ['nope', K1],
    });
    expect(r.diagnostics.map((d) => d.rule).sort()).toEqual([
      'sep30/insufficient-recovery-quorum',
      'sep30/invalid-recovery-server',
      'sep30/invalid-signing-key',
    ]);
  });

  it('counts duplicate keys as one signer', async () => {
    const r = await auditSep30Recovery({ ...GOOD, RECOVERY_SIGNING_KEYS: [K1, K1] });
    expect(r.diagnostics.map((d) => d.rule)).toEqual(['sep30/insufficient-recovery-quorum']);
  });

  it('accepts a single RECOVERY_SIGNING_KEY but warns about the quorum', async () => {
    const r = await auditSep30Recovery({
      RECOVERY_SERVER: GOOD.RECOVERY_SERVER,
      RECOVERY_SIGNING_KEY: K1,
    });
    expect(r.diagnostics[0]?.rule).toBe('sep30/insufficient-recovery-quorum');
  });

  it('errors when the server answers without authentication', async () => {
    const r = await auditSep30Recovery(GOOD, respond(200, { identities: [] }), { probe: true });
    const unauth = r.diagnostics.filter((d) => d.rule === 'sep30/unauthenticated-recovery');
    expect(unauth).toHaveLength(3);
    expect(unauth[0]?.severity).toBe('error');
  });

  it('flags missing routes but tolerates GET 404 for an unknown address', async () => {
    const fetchImpl = (async (_u: string, init?: RequestInit) =>
      new Response('{}', {
        status: init?.method === 'GET' ? 404 : 405,
      })) as unknown as typeof fetch;
    const r = await auditSep30Recovery(GOOD, fetchImpl, { probe: true });
    expect(r.diagnostics.map((d) => d.message)).toEqual([
      expect.stringContaining('POST'),
      expect.stringContaining('PUT'),
    ]);
  });

  it('does not reject on unreachable servers (timeout resilience)', async () => {
    const failing = (async () => {
      throw new Error('ECONNREFUSED');
    }) as unknown as typeof fetch;
    const r = await new Sep30RecoveryVerifier(failing, { probe: true }).verify(GOOD);
    expect(r.diagnostics.every((d) => d.rule === 'sep30/endpoint-unavailable')).toBe(true);
    expect(r.endpoints).toEqual({ POST: 0, GET: 0, PUT: 0 });
  });

  it('does not probe without the probe option', async () => {
    let calls = 0;
    const counting = (async () => {
      calls++;
      return new Response('{}');
    }) as unknown as typeof fetch;
    await auditSep30Recovery(GOOD, counting);
    expect(calls).toBe(0);
  });

  it('validates auth method types', () => {
    const body = {
      identities: [
        { role: 'owner', auth_methods: [{ type: 'email', value: 'a@b.c' }, { type: 'webauthn' }] },
        { role: 'sender', auth_methods: [{ type: 'carrier_pigeon' }, {}] },
      ],
    };
    expect(findUnsupportedAuthMethods(body)).toEqual(['carrier_pigeon', 'undefined']);
    expect(findUnsupportedAuthMethods('x')).toEqual([]);
  });

  it('reports unsupported auth methods from probe responses and honours overrides', async () => {
    const body = { identities: [{ auth_methods: [{ type: 'fax' }] }] };
    const r = await auditSep30Recovery(GOOD, respond(401, body), {
      probe: true,
      rules: { 'sep30/unsupported-auth-method': 'off' },
    });
    expect(r.diagnostics).toEqual([]);
    const on = await auditSep30Recovery(GOOD, respond(401, body), { probe: true });
    expect(on.diagnostics.some((d) => d.rule === 'sep30/unsupported-auth-method')).toBe(true);
  });
});
