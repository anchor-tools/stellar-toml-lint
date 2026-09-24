import { describe, expect, it } from 'vitest';
import { checkHorizon, horizonRules } from '../src/rules/horizon-check.js';

const HORIZON_URL = 'https://horizon.example.com';

/** Mirrors the shape of a real `GET /` response from Horizon. */
function validRoot(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    horizon_version: '28.0.1-a70eb47f',
    core_version: 'stellar-core 29.0.0 (4eb8333)',
    network_passphrase: 'Public Global Stellar Network ; September 2015',
    current_protocol_version: 28,
    supported_protocol_version: 28,
    core_supported_protocol_version: 29,
    ...overrides,
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function fetchReturning(body: unknown, status = 200): typeof fetch {
  return (async () => jsonResponse(body, status)) as unknown as typeof fetch;
}

const DOC = { HORIZON_URL };

describe('checkHorizon', () => {
  it('passes when Horizon returns a valid root document', async () => {
    const diagnostics = await checkHorizon(DOC, fetchReturning(validRoot()));
    expect(diagnostics).toEqual([]);
  });

  it('passes when the network protocol is within what core supports', async () => {
    const diagnostics = await checkHorizon(
      DOC,
      fetchReturning(
        validRoot({ current_protocol_version: 29, core_supported_protocol_version: 29 }),
      ),
    );
    expect(diagnostics).toEqual([]);
  });

  it('reports network/horizon-unreachable on HTTP 502', async () => {
    const diagnostics = await checkHorizon(DOC, fetchReturning('Bad Gateway', 502));

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      rule: 'network/horizon-unreachable',
      severity: 'error',
      category: 'network',
      path: 'HORIZON_URL',
    });
    expect(diagnostics[0]?.message).toContain('HTTP 502');
  });

  it('reports network/horizon-unreachable when fetch rejects', async () => {
    const fetchImpl = (async () => {
      throw new Error('connect ECONNREFUSED');
    }) as unknown as typeof fetch;

    const diagnostics = await checkHorizon(DOC, fetchImpl);
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.rule).toBe('network/horizon-unreachable');
    expect(diagnostics[0]?.message).toContain('ECONNREFUSED');
  });

  it('reports network/horizon-unreachable when the body is not JSON', async () => {
    const fetchImpl = (async () =>
      new Response('<html>502 Bad Gateway</html>', {
        status: 200,
        headers: { 'content-type': 'text/html' },
      })) as unknown as typeof fetch;

    const diagnostics = await checkHorizon(DOC, fetchImpl);
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.rule).toBe('network/horizon-unreachable');
    expect(diagnostics[0]?.message).toContain('valid JSON');
  });

  it('reports network/horizon-unreachable when the JSON is not a Horizon root', async () => {
    const diagnostics = await checkHorizon(DOC, fetchReturning({ hello: 'world' }));

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.rule).toBe('network/horizon-unreachable');
    expect(diagnostics[0]?.message).toContain('Horizon root');
  });

  it('warns when core does not support the current protocol version', async () => {
    const diagnostics = await checkHorizon(
      DOC,
      fetchReturning(
        validRoot({ current_protocol_version: 29, core_supported_protocol_version: 28 }),
      ),
    );

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      rule: 'network/horizon-protocol-outdated',
      severity: 'warning',
      category: 'network',
      path: 'HORIZON_URL',
    });
    expect(diagnostics[0]?.message).toContain('current protocol 29');
    expect(diagnostics[0]?.message).toContain('only supports 28');
  });

  it('stays silent without HORIZON_URL', async () => {
    let calls = 0;
    const fetchImpl = (async () => {
      calls++;
      return jsonResponse(validRoot());
    }) as unknown as typeof fetch;

    const diagnostics = await checkHorizon({}, fetchImpl);
    expect(diagnostics).toEqual([]);
    expect(calls).toBe(0);
  });

  it('stays silent when HORIZON_URL is not a parseable URL', async () => {
    let calls = 0;
    const fetchImpl = (async () => {
      calls++;
      return jsonResponse(validRoot());
    }) as unknown as typeof fetch;

    const diagnostics = await checkHorizon({ HORIZON_URL: 'not a url' }, fetchImpl);
    expect(diagnostics).toEqual([]);
    expect(calls).toBe(0);
  });

  it('honours --off for network/horizon-unreachable', async () => {
    const diagnostics = await checkHorizon(DOC, fetchReturning('nope', 502), {
      rules: { 'network/horizon-unreachable': 'off' },
    });
    expect(diagnostics).toEqual([]);
  });

  it('honours --warn downgrades for network/horizon-unreachable', async () => {
    const diagnostics = await checkHorizon(DOC, fetchReturning('nope', 502), {
      rules: { 'network/horizon-unreachable': 'warning' },
    });
    expect(diagnostics[0]?.severity).toBe('warning');
  });
});

describe('horizonRules', () => {
  it('registers both rule ids with the severities the audit emits', () => {
    expect(horizonRules.map((r) => ({ id: r.id, severity: r.severity }))).toEqual([
      { id: 'network/horizon-unreachable', severity: 'error' },
      { id: 'network/horizon-protocol-outdated', severity: 'warning' },
    ]);
  });
});
