import { describe, expect, it } from 'vitest';
import {
  verifySep6FeeCurve,
  sep6FeeVerifierRules,
  DEFAULT_FEE_SAMPLE_AMOUNTS,
  FEE_EXCEEDS_DECLARED_BOUNDS_RULE,
  NON_MONOTONIC_FEE_CURVE_RULE,
} from '../../src/protocols/sep6-fee-verifier.js';

const TRANSFER_SERVER = 'https://transfer.example.com/sep6';

interface Routes {
  info?: Record<string, unknown>;
  fee: (amount: number, operation: string, assetCode: string) => number | undefined;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function fetchServer(routes: Routes): typeof fetch {
  return (async (input: unknown) => {
    const url = new URL(String(input));

    if (url.pathname.endsWith('/info')) {
      return jsonResponse(
        routes.info ?? {
          deposit: { USD: { fee_minimum: 0.5, fee_maximum: 1000 } },
          withdraw: {},
        },
      );
    }

    if (url.pathname.endsWith('/fee')) {
      const amount = Number(url.searchParams.get('amount'));
      const operation = url.searchParams.get('operation') ?? 'deposit';
      const assetCode = url.searchParams.get('asset_code') ?? 'USD';
      const fee = routes.fee(amount, operation, assetCode);
      return fee === undefined
        ? jsonResponse({ error: 'unsupported' }, 400)
        : jsonResponse({ fee });
    }

    return jsonResponse({ error: 'not found' }, 404);
  }) as unknown as typeof fetch;
}

const DOC = { TRANSFER_SERVER, CURRENCIES: [{ code: 'USD' }] };

describe('verifySep6FeeCurve', () => {
  it('passes a monotonic, in-bounds fee curve', async () => {
    const diagnostics = await verifySep6FeeCurve(
      DOC,
      fetchServer({ fee: (amount) => Math.max(0.5, amount * 0.005) }),
    );

    expect(diagnostics).toEqual([]);
  });

  it('asserts sep6/non-monotonic-fee-curve when the fee drops as the amount rises', async () => {
    const diagnostics = await verifySep6FeeCurve(
      DOC,
      fetchServer({
        info: { deposit: { USD: {} }, withdraw: {} },
        fee: (amount) => (amount <= 1_000 ? amount * 0.01 : 1),
      }),
    );

    const hit = diagnostics.find((d) => d.rule === NON_MONOTONIC_FEE_CURVE_RULE);
    expect(hit?.severity).toBe('error');
    expect(hit?.message).toContain('dropped');
    expect(hit?.message).toContain('2500');
  });

  it('asserts sep6/fee-exceeds-declared-bounds above fee_maximum', async () => {
    const diagnostics = await verifySep6FeeCurve(
      DOC,
      fetchServer({
        info: { deposit: { USD: { fee_maximum: 0.1 } }, withdraw: {} },
        fee: () => 0.5,
      }),
    );

    const hit = diagnostics.find((d) => d.rule === FEE_EXCEEDS_DECLARED_BOUNDS_RULE);
    expect(hit?.severity).toBe('error');
    expect(hit?.message).toContain('outside the');
  });

  it('asserts sep6/fee-exceeds-declared-bounds below fee_minimum', async () => {
    const diagnostics = await verifySep6FeeCurve(
      DOC,
      fetchServer({
        info: { deposit: { USD: { fee_minimum: 1 } }, withdraw: {} },
        fee: () => 0.5,
      }),
    );

    const hit = diagnostics.find((d) => d.rule === FEE_EXCEEDS_DECLARED_BOUNDS_RULE);
    expect(hit?.message).toContain('at least 1');
  });

  it('asserts sep6/fee-exceeds-declared-bounds for a non-positive fee', async () => {
    const diagnostics = await verifySep6FeeCurve(
      DOC,
      fetchServer({
        info: { deposit: { USD: {} }, withdraw: {} },
        fee: () => 0,
      }),
    );

    const hit = diagnostics.find((d) => d.rule === FEE_EXCEEDS_DECLARED_BOUNDS_RULE);
    expect(hit?.message).toContain('not positive');
  });

  it('asserts sep6/fee-exceeds-declared-bounds when the fee exceeds the amount', async () => {
    const diagnostics = await verifySep6FeeCurve(
      DOC,
      fetchServer({
        info: { deposit: { USD: {} }, withdraw: {} },
        fee: () => 5_000,
      }),
    );

    const hit = diagnostics.find((d) => d.rule === FEE_EXCEEDS_DECLARED_BOUNDS_RULE);
    expect(hit?.message).toContain('larger than the transaction amount');
  });

  it('samples amounts in ascending order', async () => {
    const sampled: number[] = [];
    const diagnostics = await verifySep6FeeCurve(
      DOC,
      fetchServer({
        fee: (amount) => {
          sampled.push(amount);
          return Math.max(0.5, amount * 0.005);
        },
      }),
      { amounts: [1, 10, 100] },
    );

    expect(sampled).toEqual([1, 10, 100]);
    expect(diagnostics).toEqual([]);
  });

  it('covers withdraw assets as well as deposit assets', async () => {
    const diagnostics = await verifySep6FeeCurve(
      DOC,
      fetchServer({
        info: { deposit: {}, withdraw: { EUR: { fee_maximum: 0.1 } } },
        fee: (_amount, _operation, assetCode) => (assetCode === 'EUR' ? 0.5 : undefined),
      }),
    );

    expect(
      diagnostics.some(
        (d) => d.rule === FEE_EXCEEDS_DECLARED_BOUNDS_RULE && d.message.includes('withdraw'),
      ),
    ).toBe(true);
  });

  it('stays silent without a TRANSFER_SERVER', async () => {
    const diagnostics = await verifySep6FeeCurve({ CURRENCIES: [] }, fetchServer({ fee: () => 1 }));
    expect(diagnostics).toEqual([]);
  });

  it('stays silent when /info is unreachable', async () => {
    const failing = (async () => {
      throw new Error('connection refused');
    }) as unknown as typeof fetch;

    const diagnostics = await verifySep6FeeCurve(DOC, failing);
    expect(diagnostics).toEqual([]);
  });

  it('honours a rule override that turns the curve check off', async () => {
    const diagnostics = await verifySep6FeeCurve(
      DOC,
      fetchServer({
        info: { deposit: { USD: {} }, withdraw: {} },
        fee: (amount) => (amount <= 1_000 ? amount * 0.01 : 1),
      }),
      { rules: { [NON_MONOTONIC_FEE_CURVE_RULE]: 'off' } },
    );

    expect(diagnostics.filter((d) => d.rule === NON_MONOTONIC_FEE_CURVE_RULE)).toEqual([]);
  });
});

describe('sep6FeeVerifierRules', () => {
  it('registers both diagnostics', () => {
    const byId = new Map(sep6FeeVerifierRules.map((rule) => [rule.id, rule]));
    expect([...byId.keys()]).toEqual([
      NON_MONOTONIC_FEE_CURVE_RULE,
      FEE_EXCEEDS_DECLARED_BOUNDS_RULE,
    ]);
    expect(byId.get(NON_MONOTONIC_FEE_CURVE_RULE)?.severity).toBe('error');
    expect(byId.get(FEE_EXCEEDS_DECLARED_BOUNDS_RULE)?.severity).toBe('error');
  });

  it('samples 1 through 100,000 units', () => {
    expect(DEFAULT_FEE_SAMPLE_AMOUNTS[0]).toBe(1);
    expect(DEFAULT_FEE_SAMPLE_AMOUNTS.at(-1)).toBe(100_000);
    expect([...DEFAULT_FEE_SAMPLE_AMOUNTS].sort((a, b) => a - b)).toEqual([
      ...DEFAULT_FEE_SAMPLE_AMOUNTS,
    ]);
  });
});
