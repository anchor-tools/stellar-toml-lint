import { describe, expect, it } from 'vitest';
import {
  DEFAULT_MAX_QUOTE_DURATION_SECONDS,
  Sep38CircuitBreakerVerifier,
  applyShock,
  isVolatilePair,
  percentDelta,
  pickPair,
  priceFromPricesBody,
  quoteDurationSeconds,
  sep38CircuitBreakerRuleIds,
  sep38CircuitBreakerRules,
  verifySep38Volatility,
} from '../../src/protocols/sep38CircuitBreaker.js';

const ISSUER = 'GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY';
const SELL = `stellar:USDC:${ISSUER}`;
const BUY = `stellar:EURC:${ISSUER}`;

const DOC = { ANCHOR_QUOTE_SERVER: 'https://quotes.example.com/' };

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

/**
 * Quote server driven by per-call price arrays. Each round asks `/prices` then
 * `/quote`, so index `i` of the arrays is one sampling interval.
 */
function anchorServer(options: {
  prices?: number[];
  quotePrices?: number[];
  durationSeconds?: number | null | ((index: number) => number | undefined);
  quoteStatus?: number;
  assets?: unknown[];
  calls?: { prices: number; quote: number };
}): typeof fetch {
  let quoteIndex = 0;
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input));
    if (url.pathname === '/info') {
      return jsonResponse({
        assets: options.assets ?? [{ asset: SELL }, { asset: BUY }],
      });
    }
    const index = quoteIndex;
    if (url.pathname === '/prices') {
      if (options.calls) options.calls.prices++;
      const price = options.prices?.[index] ?? 100;
      return jsonResponse({ buy_assets: [{ asset: BUY, price: String(price), decimals: 7 }] });
    }
    if (url.pathname === '/quote') {
      if (options.calls) options.calls.quote++;
      if (options.quoteStatus !== undefined && options.quoteStatus !== 200) {
        return jsonResponse({ error: 'nope' }, options.quoteStatus);
      }
      quoteIndex++;
      const price = options.quotePrices?.[index] ?? 100;
      const body: Record<string, unknown> = {
        id: `q-${index}`,
        price: String(price),
        sell_asset: SELL,
        buy_asset: BUY,
        sell_amount: '100.00',
        buy_amount: String(price * 100),
      };
      const duration =
        options.durationSeconds === undefined
          ? 30
          : options.durationSeconds === null
            ? undefined
            : typeof options.durationSeconds === 'number'
              ? options.durationSeconds
              : options.durationSeconds(index);
      if (duration !== undefined) {
        body.expires_at = new Date(Date.now() + duration * 1000).toISOString();
      }
      return jsonResponse(body);
    }
    throw new Error(`unexpected request to ${url}`);
  }) as unknown as typeof fetch;
}

function verify(
  fetchImpl: typeof fetch,
  options: Parameters<typeof verifySep38Volatility>[2] = {},
) {
  return verifySep38Volatility(DOC, fetchImpl, { intervalMs: 0, ...options });
}

/** Quote prices for the default steady / shock-up / shock-down schedule. */
const FOLLOW_MARKET = [100, 100, 105, 105, 95, 95];
const STALE_MARKET = [100, 100, 100, 100, 100, 100];

describe('Sep38CircuitBreakerVerifier helpers', () => {
  it('registers the circuit-breaker rule ids', () => {
    expect(sep38CircuitBreakerRuleIds).toEqual([
      'sep38/quote-window-too-long',
      'sep38/quote-window-unbounded',
      'sep38/quote-window-too-short',
      'sep38/no-volatility-protection',
      'sep38/stale-price-feed',
      'sep38/volatility-unverifiable',
    ]);
    expect(sep38CircuitBreakerRules.map((rule) => [rule.id, rule.severity])).toEqual([
      ['sep38/quote-window-too-long', 'error'],
      ['sep38/quote-window-unbounded', 'warning'],
      ['sep38/quote-window-too-short', 'warning'],
      ['sep38/no-volatility-protection', 'warning'],
      ['sep38/stale-price-feed', 'warning'],
      ['sep38/volatility-unverifiable', 'info'],
    ]);
  });

  it('classifies volatile pairs and computes price deltas', () => {
    expect(isVolatilePair(SELL, BUY)).toBe(true);
    expect(isVolatilePair('iso4217:USD', 'iso4217:EUR')).toBe(false);
    expect(isVolatilePair('iso4217:USD', BUY)).toBe(false);
    expect(percentDelta(105, 100)).toBeCloseTo(5);
    expect(percentDelta(95, 100)).toBeCloseTo(5);
    expect(percentDelta(100, 0)).toBe(Number.POSITIVE_INFINITY);
    expect(applyShock(100, -5)).toBeCloseTo(95);
    expect(quoteDurationSeconds(61_000, 1_000)).toBe(60);
    expect(DEFAULT_MAX_QUOTE_DURATION_SECONDS).toBe(60);
  });

  it('reads the matching price from GET /prices', () => {
    expect(priceFromPricesBody({ buy_assets: [{ asset: BUY, price: '1.25' }] }, BUY)).toBe(1.25);
    expect(priceFromPricesBody({ buy_assets: [{ asset: 'x', price: '2' }] }, BUY)).toBeUndefined();
    expect(priceFromPricesBody({}, BUY)).toBeUndefined();
  });

  it('prefers a volatile pair when choosing what to probe', () => {
    expect(pickPair([{ asset: 'iso4217:USD' }, { asset: SELL }, { asset: BUY }])).toEqual({
      sell: SELL,
      buy: BUY,
      volatile: true,
    });
    expect(pickPair([{ asset: 'iso4217:USD' }, { asset: 'iso4217:EUR' }])).toEqual({
      sell: 'iso4217:USD',
      buy: 'iso4217:EUR',
      volatile: false,
    });
    expect(pickPair([{ asset: SELL }])).toBeUndefined();
  });
});

describe('Sep38CircuitBreakerVerifier', () => {
  it('passes a steady market with a bounded quote window', async () => {
    const calls = { prices: 0, quote: 0 };
    const result = await verify(
      anchorServer({
        prices: FOLLOW_MARKET,
        quotePrices: FOLLOW_MARKET,
        durationSeconds: 30,
        calls,
      }),
    );
    expect(result.diagnostics).toEqual([]);
    expect(result.samples).toHaveLength(6);
    expect(calls).toEqual({ prices: 6, quote: 6 });
    expect(result.samples.map((s) => s.phase)).toEqual([
      'steady',
      'steady',
      'shock-up',
      'shock-up',
      'shock-down',
      'shock-down',
    ]);
    expect(result.samples.every((s) => (s.quoteLatencyMs ?? -1) >= 0)).toBe(true);
    expect(result.summary).toContain('volatile pair');
  });

  it('passes a responsive anchor that re-prices through both shocks', async () => {
    const result = await verify(
      anchorServer({
        prices: FOLLOW_MARKET,
        quotePrices: FOLLOW_MARKET,
        durationSeconds: 60,
      }),
    );
    expect(result.diagnostics).toEqual([]);
  });

  it('warns when the quote keeps a stale price through a shock', async () => {
    const result = await verify(
      anchorServer({
        prices: FOLLOW_MARKET,
        quotePrices: STALE_MARKET,
        durationSeconds: 30,
      }),
    );
    expect(result.diagnostics.map((d) => d.rule)).toEqual(['sep38/no-volatility-protection']);
    expect(result.diagnostics[0]).toMatchObject({ severity: 'warning', category: 'network' });
    expect(result.diagnostics[0]?.message).toMatch(/shock-(up|down)/);
    expect(result.diagnostics[0]?.message).toContain('stale');
  });

  it('warns when /prices itself stops tracking the market', async () => {
    const result = await verify(
      anchorServer({
        prices: STALE_MARKET,
        quotePrices: FOLLOW_MARKET,
        durationSeconds: 30,
      }),
    );
    expect(result.diagnostics.map((d) => d.rule)).toEqual(['sep38/stale-price-feed']);
    expect(result.diagnostics[0]?.message).toContain('simulated SDEX price');
  });

  it('flags quotes longer than the 60s volatility buffer in a crypto pair', async () => {
    const result = await verify(
      anchorServer({ prices: FOLLOW_MARKET, quotePrices: FOLLOW_MARKET, durationSeconds: 90 }),
    );
    expect(result.diagnostics.map((d) => d.rule)).toEqual(['sep38/quote-window-too-long']);
    expect(result.diagnostics[0]?.severity).toBe('error');
    expect(result.diagnostics[0]?.message).toContain('90.0s');
    expect(result.diagnostics[0]?.message).toContain('60s');
  });

  it('does not flag a quote that expires exactly at the buffer boundary', async () => {
    const result = await verify(
      anchorServer({ prices: FOLLOW_MARKET, quotePrices: FOLLOW_MARKET, durationSeconds: 60 }),
    );
    expect(result.diagnostics).toEqual([]);
  });

  it('warns about an unbounded quote advertised without expires_at', async () => {
    const result = await verify(
      anchorServer({
        prices: FOLLOW_MARKET,
        quotePrices: FOLLOW_MARKET,
        durationSeconds: null,
      }),
    );
    expect(result.diagnostics.map((d) => d.rule)).toEqual(['sep38/quote-window-unbounded']);
    expect(result.diagnostics[0]?.severity).toBe('warning');
    expect(result.diagnostics[0]?.message).toContain('6 of 6');
  });

  it('treats a far-future expiry as unbounded rather than merely too long', async () => {
    const result = await verify(
      anchorServer({
        prices: FOLLOW_MARKET,
        quotePrices: FOLLOW_MARKET,
        durationSeconds: 400 * 24 * 60 * 60,
      }),
    );
    expect(result.diagnostics.map((d) => d.rule)).toEqual(['sep38/quote-window-unbounded']);
  });

  it('warns about micro-duration quotes a wallet cannot use', async () => {
    const result = await verify(
      anchorServer({ prices: FOLLOW_MARKET, quotePrices: FOLLOW_MARKET, durationSeconds: 2 }),
    );
    expect(result.diagnostics.map((d) => d.rule)).toEqual(['sep38/quote-window-too-short']);
    expect(result.diagnostics[0]?.message).toContain('2.0s');
  });

  it('reports a single combined finding set for all violations', async () => {
    const result = await verify(
      anchorServer({
        prices: STALE_MARKET,
        quotePrices: STALE_MARKET,
        durationSeconds: (index) => (index % 2 === 0 ? 120 : undefined),
      }),
    );
    expect(new Set(result.diagnostics.map((d) => d.rule))).toEqual(
      new Set([
        'sep38/quote-window-too-long',
        'sep38/quote-window-unbounded',
        'sep38/no-volatility-protection',
        'sep38/stale-price-feed',
      ]),
    );
    expect(result.diagnostics).toHaveLength(4);
  });

  it('stays silent without a usable ANCHOR_QUOTE_SERVER', async () => {
    let called = 0;
    const counting = (async () => {
      called++;
      return jsonResponse({});
    }) as unknown as typeof fetch;
    const result = await verifySep38Volatility(
      { ANCHOR_QUOTE_SERVER: 'http://insecure' },
      counting,
    );
    expect(result.diagnostics).toEqual([]);
    expect(result.samples).toEqual([]);
    expect(called).toBe(0);
  });

  it('reports when the anchor advertises no pair to exercise', async () => {
    const result = await verify(anchorServer({ assets: [{ asset: SELL }] }));
    expect(result.diagnostics.map((d) => d.rule)).toEqual(['sep38/volatility-unverifiable']);
    expect(result.diagnostics[0]?.severity).toBe('info');
  });

  it('reports when no quote can be booked', async () => {
    const result = await verify(anchorServer({ quoteStatus: 500 }));
    expect(result.diagnostics.map((d) => d.rule)).toEqual(['sep38/volatility-unverifiable']);
    expect(result.summary).toContain('No quote could be booked');
  });

  it('honours severity overrides and rule ids', async () => {
    const result = await verify(
      anchorServer({ prices: FOLLOW_MARKET, quotePrices: FOLLOW_MARKET, durationSeconds: 90 }),
      { rules: { 'sep38/quote-window-too-long': 'off' } },
    );
    expect(result.diagnostics).toEqual([]);
  });

  it('raises a warning to an error when configured', async () => {
    const result = await verify(
      anchorServer({ prices: STALE_MARKET, quotePrices: FOLLOW_MARKET, durationSeconds: 30 }),
      { rules: { 'sep38/stale-price-feed': 'error' } },
    );
    expect(result.diagnostics).toHaveLength(1);
    expect(result.diagnostics[0]).toMatchObject({
      rule: 'sep38/stale-price-feed',
      severity: 'error',
    });
  });

  it('exposes the verifier class with injected timing', async () => {
    let monotonic = 0;
    let wall = Date.now();
    const result = await new Sep38CircuitBreakerVerifier(
      anchorServer({ prices: FOLLOW_MARKET, quotePrices: FOLLOW_MARKET, durationSeconds: 30 }),
      {
        intervalMs: 0,
        clock: {
          wallNow: () => wall,
          monotonicNow: () => {
            const now = monotonic;
            monotonic += 2;
            wall += 2;
            return now;
          },
        },
      },
    ).verify(DOC);
    expect(result.diagnostics).toEqual([]);
    expect(result.samples[0]?.quoteLatencyMs).toBeGreaterThan(0);
  });
});
