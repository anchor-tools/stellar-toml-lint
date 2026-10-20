import { describe, expect, it } from 'vitest';
import {
  checkCrossSepFees,
  crossSepFeeRules,
  normalizeFeeSchedule,
} from '../../src/rules/cross-sep-fee-auditor.js';

const ISSUER = 'GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY';
const SEP6 = 'https://api.example.com/sep6';
const SEP24 = 'https://api.example.com/sep24';
const SEP38 = 'https://api.example.com/sep38';

interface FeeFields {
  fee_fixed?: number;
  fee_percent?: number;
  fee_minimum?: number;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function infoBody(deposit: FeeFields = {}, withdraw: FeeFields = {}): Record<string, unknown> {
  return {
    deposit: { USD: { enabled: true, ...deposit } },
    withdraw: { USD: { enabled: true, ...withdraw } },
  };
}

function fetchServer(routes: {
  sep6?: () => Response | Promise<Response>;
  sep24?: () => Response | Promise<Response>;
  prices?: () => Response | Promise<Response>;
}): typeof fetch {
  return (async (input: string | URL | Request) => {
    const url = String(input);
    if (url.startsWith(`${SEP6}/info`)) {
      return routes.sep6 ? routes.sep6() : jsonResponse(infoBody({ fee_fixed: 5, fee_percent: 1 }));
    }
    if (url.startsWith(`${SEP24}/info`)) {
      return routes.sep24
        ? routes.sep24()
        : jsonResponse(infoBody({ fee_fixed: 5, fee_percent: 1 }));
    }
    if (url.startsWith(`${SEP38}/prices`)) {
      return routes.prices
        ? routes.prices()
        : jsonResponse({ buy_assets: [{ asset: `stellar:USD:${ISSUER}`, price: '1.00' }] });
    }
    throw new Error(`unexpected request to ${url}`);
  }) as unknown as typeof fetch;
}

function doc(currency: Record<string, unknown>): Record<string, unknown> {
  return {
    TRANSFER_SERVER: SEP6,
    TRANSFER_SERVER_SEP0024: SEP24,
    ANCHOR_QUOTE_SERVER: SEP38,
    CURRENCIES: [{ code: 'USD', issuer: ISSUER, ...currency }],
  };
}

describe('checkCrossSepFees', () => {
  it('passes when every endpoint publishes the same fixed and percentage fees', async () => {
    const diagnostics = await checkCrossSepFees(
      doc({ fee_fixed: 5, fee_percent: 1 }),
      fetchServer({}),
    );
    expect(diagnostics).toEqual([]);
  });

  it('reports fees/contradictory-fee-schedules when fixed fees conflict', async () => {
    const diagnostics = await checkCrossSepFees(
      doc({ fee_fixed: 5 }),
      fetchServer({ sep24: () => jsonResponse(infoBody({ fee_fixed: 7 })) }),
    );

    const contradictions = diagnostics.filter(
      (entry) => entry.rule === 'fees/contradictory-fee-schedules',
    );
    expect(contradictions).toHaveLength(1);
    expect(contradictions[0]).toMatchObject({
      severity: 'error',
      category: 'fees',
      path: 'CURRENCIES[0].fee_fixed',
    });
    expect(contradictions[0]?.message).toContain('stellar.toml');
    expect(contradictions[0]?.message).toContain('SEP-24 /info (deposit)');
    expect(contradictions[0]?.message).toContain('7');
  });

  it('flags a 1% TOML fee raised to 3% by SEP-24', async () => {
    const diagnostics = await checkCrossSepFees(
      doc({ fee_percent: 1 }),
      fetchServer({ sep24: () => jsonResponse(infoBody({ fee_percent: 3 })) }),
    );

    expect(diagnostics.some((entry) => entry.rule === 'fees/contradictory-fee-schedules')).toBe(
      true,
    );
    const undisclosed = diagnostics.find(
      (entry) => entry.rule === 'fees/undisclosed-percentage-fee',
    );
    expect(undisclosed).toMatchObject({
      severity: 'warning',
      category: 'fees',
      path: 'CURRENCIES[0].fee_percent',
    });
    expect(undisclosed?.message).toContain('3%');
    expect(undisclosed?.message).toContain('1%');
  });

  it('reports when SEP-6 and SEP-24 disagree even without a TOML fee', async () => {
    const diagnostics = await checkCrossSepFees(
      doc({}),
      fetchServer({
        sep6: () => jsonResponse(infoBody({ fee_fixed: 2 })),
        sep24: () => jsonResponse(infoBody({ fee_fixed: 4 })),
      }),
    );

    const contradictions = diagnostics.filter(
      (entry) => entry.rule === 'fees/contradictory-fee-schedules',
    );
    expect(contradictions).toHaveLength(1);
    expect(contradictions[0]?.message).toContain('SEP-6 /info (deposit)');
    expect(contradictions[0]?.message).toContain('SEP-24 /info (deposit)');
  });

  it('does not compare deposit fees against withdrawal fees', async () => {
    const diagnostics = await checkCrossSepFees(
      doc({}),
      fetchServer({
        sep6: () => jsonResponse(infoBody({ fee_fixed: 2 }, { fee_fixed: 9 })),
        sep24: () => jsonResponse(infoBody({ fee_fixed: 2 }, { fee_fixed: 9 })),
      }),
    );

    expect(diagnostics).toEqual([]);
  });

  it('does not warn when the endpoint percentage fee is below the TOML declaration', async () => {
    const diagnostics = await checkCrossSepFees(
      doc({ fee_percent: 3 }),
      fetchServer({
        sep6: () => jsonResponse(infoBody({ fee_percent: 1 })),
        sep24: () => jsonResponse(infoBody({ fee_percent: 1 })),
      }),
    );

    expect(diagnostics.some((entry) => entry.rule === 'fees/undisclosed-percentage-fee')).toBe(
      false,
    );
  });

  it('includes explicit fee fields from SEP-38 /prices', async () => {
    const diagnostics = await checkCrossSepFees(
      doc({ fee_fixed: 5 }),
      fetchServer({
        prices: () =>
          jsonResponse({
            buy_assets: [{ asset: `stellar:USD:${ISSUER}`, price: '1.00', fee_fixed: 8 }],
          }),
      }),
    );

    expect(
      diagnostics.some(
        (entry) =>
          entry.rule === 'fees/contradictory-fee-schedules' &&
          entry.path === 'CURRENCIES[0].fee_fixed',
      ),
    ).toBe(true);
    expect(diagnostics[0]?.message).toContain('SEP-38 /prices');
  });

  it('asks SEP-38 about the native asset as stellar:XLM', async () => {
    let requested = '';
    const fetchImpl = (async (input: string | URL | Request) => {
      const url = String(input);
      if (url.includes('/prices')) {
        requested = decodeURIComponent(url);
        return jsonResponse({ buy_assets: [] });
      }
      return jsonResponse(infoBody());
    }) as unknown as typeof fetch;

    await checkCrossSepFees(
      {
        ANCHOR_QUOTE_SERVER: SEP38,
        CURRENCIES: [{ code: 'native' }],
      },
      fetchImpl,
    );
    expect(requested).toContain('sell_asset=stellar:XLM');
  });

  it('stays silent without transfer or quote servers', async () => {
    let calls = 0;
    const fetchImpl = (async () => {
      calls++;
      return jsonResponse(infoBody());
    }) as unknown as typeof fetch;

    const diagnostics = await checkCrossSepFees(
      { CURRENCIES: [{ code: 'USD', issuer: ISSUER, fee_fixed: 1 }] },
      fetchImpl,
    );
    expect(diagnostics).toEqual([]);
    expect(calls).toBe(0);
  });

  it('honours --off for fees/contradictory-fee-schedules', async () => {
    const diagnostics = await checkCrossSepFees(
      doc({ fee_fixed: 5 }),
      fetchServer({ sep24: () => jsonResponse(infoBody({ fee_fixed: 7 })) }),
      { rules: { 'fees/contradictory-fee-schedules': 'off' } },
    );
    expect(diagnostics).toEqual([]);
  });

  it('honours --warn downgrades for fees/contradictory-fee-schedules', async () => {
    const diagnostics = await checkCrossSepFees(
      doc({ fee_fixed: 5 }),
      fetchServer({ sep24: () => jsonResponse(infoBody({ fee_fixed: 7 })) }),
      { rules: { 'fees/contradictory-fee-schedules': 'warning' } },
    );
    expect(diagnostics[0]?.severity).toBe('warning');
  });
});

describe('normalizeFeeSchedule', () => {
  it('reads fixed, percentage, minimum, and tiered fee structures', () => {
    expect(
      normalizeFeeSchedule({
        fee_fixed: 1,
        fee_percent: '2',
        fee_minimum: 0.5,
        fee_tiers: [
          { min_amount: 0, max_amount: 10, fee_fixed: 1 },
          { min_amount: 10, fee_percent: 0.5 },
        ],
      }),
    ).toEqual({
      fixed: 1,
      percent: 2,
      minimum: 0.5,
      tiers: [
        { minAmount: 0, maxAmount: 10, fixed: 1 },
        { minAmount: 10, percent: 0.5 },
      ],
    });
  });

  it('returns undefined when no fee field is present', () => {
    expect(normalizeFeeSchedule({ enabled: true })).toBeUndefined();
  });
});

describe('crossSepFeeRules', () => {
  it('registers both fee audit rule ids', () => {
    expect(crossSepFeeRules.map((rule) => ({ id: rule.id, severity: rule.severity }))).toEqual([
      { id: 'fees/contradictory-fee-schedules', severity: 'error' },
      { id: 'fees/undisclosed-percentage-fee', severity: 'warning' },
    ]);
  });
});
