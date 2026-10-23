import { describe, expect, it, vi } from 'vitest';
import {
  simulateTrustlineFreezing,
  UNDISCLOSED_FREEZING_RULE,
} from '../../src/security/trustline-simulator.js';

const ISSUER = 'GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS';
const HORIZON = 'https://horizon.example.com';

function response(body: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function horizon(flags: Record<string, unknown>, status = 200): typeof fetch {
  return vi.fn(async () => response({ flags }, status)) as unknown as typeof fetch;
}

function doc(entry: Record<string, unknown>): Record<string, unknown> {
  return {
    HORIZON_URL: HORIZON,
    CURRENCIES: [{ code: 'USD', issuer: ISSUER, ...entry }],
  };
}

describe('trustline authorization freeze simulator', () => {
  it('passes a revocable asset that discloses freezing under regulated = true', async () => {
    const diagnostics = await simulateTrustlineFreezing(
      doc({
        regulated: true,
        desc: 'Holders may be frozen or have authorization revoked for sanctions compliance.',
      }),
      horizon({ auth_required: true, auth_revocable: true }),
    );

    expect(diagnostics).toEqual([]);
  });

  it('flags an undisclosed freeze capability on Horizon', async () => {
    const diagnostics = await simulateTrustlineFreezing(
      doc({ regulated: true, desc: 'A dollar stablecoin' }),
      horizon({ auth_required: true, auth_revocable: true }),
    );

    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: UNDISCLOSED_FREEZING_RULE,
        severity: 'error',
        path: 'CURRENCIES[0].issuer',
      }),
    );
  });

  it('flags a revocable asset that is not marked regulated', async () => {
    const diagnostics = await simulateTrustlineFreezing(
      doc({ desc: 'Balances can be frozen at any time' }),
      horizon({ auth_required: true, auth_revocable: true }),
    );

    expect(diagnostics.map((d) => d.rule)).toContain(UNDISCLOSED_FREEZING_RULE);
  });

  it('passes when the issuer cannot revoke authorization', async () => {
    const diagnostics = await simulateTrustlineFreezing(
      doc({ regulated: false }),
      horizon({ auth_required: false, auth_revocable: false }),
    );

    expect(diagnostics).toEqual([]);
  });

  it('stays silent when Horizon cannot be reached', async () => {
    const fetchImpl = vi.fn(async () => response({}, 503)) as unknown as typeof fetch;
    const diagnostics = await simulateTrustlineFreezing(
      doc({ regulated: true, desc: 'Regulated stablecoin' }),
      fetchImpl,
    );

    expect(diagnostics).toEqual([]);
  });
});
