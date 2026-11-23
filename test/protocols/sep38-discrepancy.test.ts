import { describe, expect, it } from 'vitest';
import {
  DEFAULT_MAX_QUOTE_LIFETIME_SECONDS,
  systemWallClock,
  DEFAULT_QUOTE_TIERS,
  DEFAULT_SPREAD_TOLERANCE_BPS,
  RATE_SCALE,
  Sep38QuoteDiscrepancyAuditor,
  advertisedFeeBps,
  auditSep38QuoteDiscrepancies,
  feeBps,
  formatScaledDecimal,
  indicativePriceFrom,
  parseScaledDecimal,
  quoteFeeTotal,
  rateSpreadBps,
  sep38DiscrepancyRuleIds,
  sep38DiscrepancyRules,
  systemSleep,
} from '../../src/protocols/sep38Discrepancy.js';

const ISSUER = 'GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY';
const SELL = `stellar:USDC:${ISSUER}`;
const BUY = `stellar:EURC:${ISSUER}`;
const TRANSFER = 'https://anchor.example.com/sep6';

const DOC = {
  ANCHOR_QUOTE_SERVER: 'https://quotes.example.com/',
  TRANSFER_SERVER: TRANSFER,
};

const FIXED_NOW = Date.parse('2026-01-01T00:00:00.000Z');
const FIXED_CLOCK = { wallNow: () => FIXED_NOW };

function isRecordBody(body: unknown): Record<string, unknown> | undefined {
  if (typeof body !== 'string') return undefined;
  try {
    const parsed: unknown = JSON.parse(body);
    return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
}

function isString(value: unknown): value is string {
  return typeof value === 'string';
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function rawResponse(body: string): Response {
  return new Response(body, {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

interface QuotePlan {
  buyAmount?: string;
  feeTotal?: string;
  fees?: { amount: string }[];
  expiresInSeconds?: number | null;
  useExpireAfter?: boolean;
  id?: string;
  sellAmount?: string;
  raw?: Record<string, unknown>;
  status?: number;
}

interface ServerOptions {
  assets?: unknown[];
  infoRaw?: string;
  pricesRaw?: string;
  quoteRaw?: string;
  price?: (sellAmount: string) => string | number | undefined;
  pricesStatus?: number;
  pricesThrows?: boolean;
  quote?: (sellAmount: string) => QuotePlan;
  quoteStatus?: number;
  quoteThrows?: boolean;
  quoteBody?: unknown;
  infoStatus?: number;
  infoThrows?: boolean;
  deposit?: (url: URL, init: RequestInit | undefined) => Response | Promise<Response>;
  onRequest?: (url: URL, init: RequestInit | undefined) => void;
}

/** A quote server whose answers can vary by the `sell_amount` asked for. */
function anchorServer(options: ServerOptions = {}): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input));
    options.onRequest?.(url, init);

    if (url.pathname === '/info') {
      if (options.infoThrows) throw new Error('offline');
      if (options.infoRaw !== undefined) return rawResponse(options.infoRaw);
      if (options.infoStatus !== undefined) return jsonResponse({}, options.infoStatus);
      return jsonResponse({
        assets: options.assets ?? [{ asset: SELL }, { asset: BUY }],
      });
    }

    if (url.pathname === '/prices') {
      if (options.pricesThrows) throw new Error('offline');
      if (options.pricesRaw !== undefined) return rawResponse(options.pricesRaw);
      if (options.pricesStatus !== undefined) return jsonResponse({}, options.pricesStatus);
      const sellAmount = url.searchParams.get('sell_amount') ?? '';
      const price = options.price?.(sellAmount) ?? '1';
      return jsonResponse({ buy_assets: [{ asset: BUY, price: String(price), decimals: 7 }] });
    }

    if (url.pathname === '/quote') {
      if (options.quoteThrows) throw new Error('offline');
      if (options.quoteRaw !== undefined) return rawResponse(options.quoteRaw);
      if (options.quoteStatus !== undefined) return jsonResponse({}, options.quoteStatus);
      if (options.quoteBody !== undefined) return jsonResponse(options.quoteBody);
      const request = isRecordBody(init?.body) ?? {};
      const sellAmount = isString(request.sell_amount) ? request.sell_amount : '100';
      const plan = options.quote?.(sellAmount) ?? {};
      if ((plan.status ?? 200) !== 200) return jsonResponse({}, plan.status);
      if (plan.raw !== undefined) return jsonResponse(plan.raw);
      const body: Record<string, unknown> = {
        id: plan.id ?? `quote-${sellAmount}`,
        price: '1',
        sell_asset: SELL,
        buy_asset: BUY,
        sell_amount: plan.sellAmount ?? sellAmount,
        buy_amount: plan.buyAmount ?? sellAmount,
      };
      if (plan.feeTotal !== undefined) body.fee = { total: plan.feeTotal, asset: BUY };
      if (plan.fees !== undefined) body.fees = plan.fees;
      if (plan.expiresInSeconds !== null) {
        const expires = new Date(FIXED_NOW + (plan.expiresInSeconds ?? 30) * 1000).toISOString();
        body[plan.useExpireAfter === true ? 'expire_after' : 'expires_at'] = expires;
      }
      return jsonResponse(body);
    }

    if (url.pathname.endsWith('/deposit')) {
      return options.deposit?.(url, init) ?? jsonResponse({}, 200);
    }

    throw new Error(`unexpected request to ${url}`);
  }) as unknown as typeof fetch;
}

/** A clock tests can move, plus a sleep that moves it without waiting. */
function fakeClock(start = FIXED_NOW): {
  clock: { wallNow: () => number };
  sleep: (ms: number) => Promise<unknown>;
  advance: (ms: number) => void;
} {
  let now = start;
  return {
    clock: { wallNow: () => now },
    sleep: async (ms: number) => {
      now += ms;
    },
    advance: (ms: number) => {
      now += ms;
    },
  };
}

function audit(
  fetchImpl: typeof fetch,
  options: Parameters<typeof auditSep38QuoteDiscrepancies>[2] = {},
) {
  return auditSep38QuoteDiscrepancies(DOC, fetchImpl, {
    clock: FIXED_CLOCK,
    probeExpiredExecution: false,
    ...options,
  });
}

describe('sep38 discrepancy helpers', () => {
  it('registers rule ids with their severities', async () => {
    expect(sep38DiscrepancyRuleIds).toEqual([
      'sep38/spread-exceeds-tolerance',
      'sep38/fee-exceeds-disclosure',
      'sep38/quote-expiry-missing',
      'sep38/firm-quote-expired',
      'sep38/quote-lifetime-exceeds-limit',
      'sep38/expired-quote-accepted',
      'sep38/quote-audit-unverifiable',
    ]);
    expect(sep38DiscrepancyRules.map((rule) => [rule.id, rule.severity])).toEqual([
      ['sep38/spread-exceeds-tolerance', 'error'],
      ['sep38/fee-exceeds-disclosure', 'error'],
      ['sep38/quote-expiry-missing', 'error'],
      ['sep38/firm-quote-expired', 'error'],
      ['sep38/quote-lifetime-exceeds-limit', 'warning'],
      ['sep38/expired-quote-accepted', 'error'],
      ['sep38/quote-audit-unverifiable', 'info'],
    ]);
    expect(DEFAULT_SPREAD_TOLERANCE_BPS).toBe(50n);
    expect(DEFAULT_MAX_QUOTE_LIFETIME_SECONDS).toBe(300);
    expect(RATE_SCALE).toBe(12);
    expect(DEFAULT_QUOTE_TIERS.map((tier) => tier.label)).toEqual(['small', 'medium', 'large']);
    expect(systemWallClock.wallNow()).toBeGreaterThan(0);
    await expect(systemSleep(0)).resolves.toBeUndefined();
    for (const rule of sep38DiscrepancyRules) {
      expect(() => rule.run({} as never)).not.toThrow();
    }
  });

  it('parses decimals exactly into scaled integers', () => {
    expect(parseScaledDecimal('1', 7)).toBe(10_000_000n);
    expect(parseScaledDecimal('1.0000001', 7)).toBe(10_000_001n);
    expect(parseScaledDecimal('0.5', 2)).toBe(50n);
    expect(parseScaledDecimal('0.123456789012345', 12)).toBe(123_456_789_012n);
    expect(parseScaledDecimal(1.25, 2)).toBe(125n);
    expect(parseScaledDecimal(Number.NaN)).toBeUndefined();
    expect(parseScaledDecimal('-1')).toBeUndefined();
    expect(parseScaledDecimal('1e-7')).toBeUndefined();
    expect(parseScaledDecimal(undefined)).toBeUndefined();
    expect(parseScaledDecimal(null)).toBeUndefined();
  });

  it('formats scaled integers without floating point', () => {
    expect(formatScaledDecimal(10_000_000n, 7)).toBe('1');
    expect(formatScaledDecimal(10_000_001n, 7)).toBe('1.0000001');
    expect(formatScaledDecimal(50n, 2)).toBe('0.5');
    expect(formatScaledDecimal(-150n, 2)).toBe('-1.5');
    expect(formatScaledDecimal(123_400n, 6)).toBe('0.1234');
  });

  it('measures the indicative-to-firm spread in basis points exactly', () => {
    // 100 buy for 100 sell at 1.0: no spread.
    expect(rateSpreadBps('100', '100', '1')).toBe(0n);
    // 95 buy for 100 sell at 1.0: 5%.
    expect(rateSpreadBps('95', '100', '1')).toBe(500n);
    // Half a percent.
    expect(rateSpreadBps('99.5', '100', '1')).toBe(50n);
    // Firm above the indicative rate, same magnitude.
    expect(rateSpreadBps('105', '100', '1')).toBe(500n);
    // A fractional indicative price.
    expect(rateSpreadBps('250', '100', '2.5')).toBe(0n);
    expect(rateSpreadBps('250', '100', '2.5')).toBe(0n);
    // No floating-point drift on values that are awkward in binary.
    expect(rateSpreadBps('0.1', '0.1', '1')).toBe(0n);
    expect(rateSpreadBps('100', '0', '1')).toBeUndefined();
    expect(rateSpreadBps('100', '100', '0')).toBeUndefined();
    expect(rateSpreadBps('x', '100', '1')).toBeUndefined();
  });

  it('measures quoted fees in basis points', () => {
    expect(feeBps('1', '100')).toBe(100n);
    expect(feeBps('0.5', '10')).toBe(500n);
    expect(feeBps('0', '100')).toBe(0n);
    expect(feeBps('1', '0')).toBeUndefined();
    expect(feeBps('x', '100')).toBeUndefined();
  });

  it('reads advertised fee disclosures from documentation and currencies', () => {
    expect(advertisedFeeBps({})).toBeUndefined();
    expect(
      advertisedFeeBps({ DOCUMENTATION: { ORG_DESCRIPTION: 'We charge 1% fees on trades' } }),
    ).toBe(100n);
    expect(
      advertisedFeeBps({
        CURRENCIES: [{ code: 'USDC', issuer: ISSUER, desc: '0.25% fees' }],
      }),
    ).toBe(25n);
    expect(
      advertisedFeeBps({
        DOCUMENTATION: { ORG_DESCRIPTION: 'Discounted spreads available' },
      }),
    ).toBeUndefined();
    // A quantified claim that carries no bound is ignored, not treated as zero.
    expect(
      advertisedFeeBps({
        DOCUMENTATION: { ORG_DESCRIPTION: 'Cash-back rewards available' },
      }),
    ).toBeUndefined();
    expect(
      advertisedFeeBps({
        DOCUMENTATION: { ORG_DESCRIPTION: '2% commission' },
      }),
    ).toBe(200n);
    expect(
      advertisedFeeBps({
        DOCUMENTATION: { ORG_DESCRIPTION: '0.5% fees and 2% commission' },
      }),
    ).toBe(50n);
    expect(
      advertisedFeeBps({
        CURRENCIES: [
          { code: 'USDC', issuer: ISSUER, desc: '0.25% fees' },
          { code: 'EURC', issuer: ISSUER, desc: '1% fees' },
          { code: 'BRL', issuer: ISSUER, desc: '0.1% fees' },
        ],
      }),
    ).toBe(100n);
  });

  it('extracts the matching indicative price and quote fee', () => {
    expect(indicativePriceFrom({ buy_assets: [{ asset: BUY, price: '1.25' }] }, BUY)).toBe('1.25');
    expect(indicativePriceFrom({ buy_assets: [{ asset: BUY, price: 1.25 }] }, BUY)).toBe('1.25');
    expect(indicativePriceFrom({ buy_assets: [{ asset: 'x', price: '1' }] }, BUY)).toBeUndefined();
    expect(indicativePriceFrom({ buy_assets: [{ asset: BUY, price: null }] }, BUY)).toBeUndefined();
    expect(indicativePriceFrom({}, BUY)).toBeUndefined();
    expect(indicativePriceFrom(null, BUY)).toBeUndefined();

    expect(quoteFeeTotal({ fee: { total: '1.5' } })).toBe('1.5');
    expect(quoteFeeTotal({ fee: { total: 1.5 } })).toBe('1.5');
    expect(quoteFeeTotal({ fee: { total: Number.NaN } })).toBeUndefined();
    expect(quoteFeeTotal({ fees: [{ amount: '0.4' }, { amount: '0.1' }] })).toBe('0.5');
    expect(quoteFeeTotal({ fees: [{ amount: 'bad' }, { amount: '0.1' }] })).toBe('0.1');
    expect(quoteFeeTotal({})).toBeUndefined();
  });
});

describe('Sep38QuoteDiscrepancyAuditor', () => {
  it('falls back to the system clock when none is injected', async () => {
    const result = await audit(anchorServer(), { clock: undefined });
    // The server stamps quotes against FIXED_NOW, so they read as expired now;
    // what matters here is that the default clock path is exercised.
    expect(result.observations).toHaveLength(3);
    expect(result.diagnostics.every((d) => d.rule === 'sep38/firm-quote-expired')).toBe(true);
  });

  it('prices small, medium and large tiers with no findings for a consistent anchor', async () => {
    const requested: string[] = [];
    const result = await audit(
      anchorServer({
        onRequest: (url) => requested.push(url.pathname),
      }),
    );

    expect(result.diagnostics).toEqual([]);
    expect(result.observations).toHaveLength(3);
    expect(result.observations.map((o) => o.tier)).toEqual(DEFAULT_QUOTE_TIERS.map((t) => t.label));
    expect(result.observations.every((o) => o.spreadBps === 0n)).toBe(true);
    expect(result.observations[0]?.firmRate).toBe('1');
    expect(result.observations[0]?.expiresAt).toBe(new Date(FIXED_NOW + 30_000).toISOString());
    expect(result.summary).toContain('worst spread 0 bps');
    expect(requested.filter((p) => p === '/prices')).toHaveLength(3);
    expect(requested.filter((p) => p === '/quote')).toHaveLength(3);
  });

  it('tracks the worst spread when tiers widen at different rates', async () => {
    const result = await audit(
      anchorServer({
        quote: (amount) => {
          const n = Number(amount);
          const factor = n >= 100000 ? 0.9 : n >= 1000 ? 0.95 : 0.99;
          return { buyAmount: String(n * factor) };
        },
      }),
    );
    const messages = result.diagnostics.map((d) => d.message);
    expect(messages).toHaveLength(3);
    expect(messages[2]).toContain('1000 bps');
    expect(result.summary).toContain('1000 bps');
  });

  it('flags a firm spread that exceeds the configured tolerance', async () => {
    const result = await audit(
      anchorServer({
        quote: (amount) => ({ buyAmount: String(Number(amount) * 0.95) }),
      }),
    );
    const spreads = result.diagnostics.filter((d) => d.rule === 'sep38/spread-exceeds-tolerance');
    expect(spreads).toHaveLength(3);
    expect(spreads[0]).toMatchObject({ severity: 'error', category: 'network' });
    expect(spreads[0]?.message).toContain('500 bps');
    expect(spreads[0]?.message).toContain('50 bps');
    expect(result.summary).toContain('500 bps');
  });

  it('accepts a spread inside a larger configured tolerance', async () => {
    const result = await audit(
      anchorServer({ quote: (amount) => ({ buyAmount: String(Number(amount) * 0.95) }) }),
      { toleranceBps: 500n },
    );
    expect(result.diagnostics).toEqual([]);
  });

  it('allows a spread covered by the fee disclosed in stellar.toml', async () => {
    const doc = {
      ...DOC,
      DOCUMENTATION: { ORG_DESCRIPTION: '1% fees on every trade' },
    };
    // 120 bps spread < 50 bps tolerance + 100 bps disclosed fee.
    const result = await auditSep38QuoteDiscrepancies(
      doc,
      anchorServer({ quote: (amount) => ({ buyAmount: String(Number(amount) * 0.988) }) }),
      { clock: FIXED_CLOCK, probeExpiredExecution: false },
    );
    expect(result.diagnostics).toEqual([]);
  });

  it('flags a spread beyond both tolerance and disclosed fee', async () => {
    const doc = {
      ...DOC,
      DOCUMENTATION: { ORG_DESCRIPTION: '1% fees on every trade' },
    };
    // 300 bps spread > 150 bps allowance.
    const result = await auditSep38QuoteDiscrepancies(
      doc,
      anchorServer({ quote: (amount) => ({ buyAmount: String(Number(amount) * 0.97) }) }),
      { clock: FIXED_CLOCK, probeExpiredExecution: false },
    );
    expect(result.diagnostics.map((d) => d.rule)).toEqual(
      new Array(3).fill('sep38/spread-exceeds-tolerance'),
    );
    expect(result.diagnostics[0]?.message).toContain('150 bps');
  });

  it('flags a firm fee above the fee the file discloses', async () => {
    const doc = {
      ...DOC,
      DOCUMENTATION: { ORG_DESCRIPTION: '1% fees on every trade' },
    };
    const result = await auditSep38QuoteDiscrepancies(
      doc,
      anchorServer({ quote: () => ({ feeTotal: '0.5' }) }),
      { clock: FIXED_CLOCK, probeExpiredExecution: false },
    );
    // 0.5 on the small 10-unit tier is 500 bps; the larger tiers dilute it.
    const fees = result.diagnostics.filter((d) => d.rule === 'sep38/fee-exceeds-disclosure');
    expect(fees).toHaveLength(1);
    expect(fees[0]?.severity).toBe('error');
    expect(fees[0]?.message).toContain('500 bps');
    expect(fees[0]?.message).toContain('100 bps');
  });

  it('accepts a fee inside the disclosure plus tolerance', async () => {
    const doc = {
      ...DOC,
      DOCUMENTATION: { ORG_DESCRIPTION: '1% fees on every trade' },
    };
    const result = await auditSep38QuoteDiscrepancies(
      doc,
      anchorServer({ quote: () => ({ feeTotal: '0.1' }) }),
      { clock: FIXED_CLOCK, probeExpiredExecution: false },
    );
    expect(result.diagnostics).toEqual([]);
  });

  it('does not compare fees when the file discloses none', async () => {
    const result = await audit(anchorServer({ quote: () => ({ feeTotal: '9' }) }));
    expect(result.diagnostics).toEqual([]);
  });

  it('flags a quote with no expiry', async () => {
    const result = await audit(anchorServer({ quote: () => ({ expiresInSeconds: null }) }));
    expect(result.diagnostics.map((d) => d.rule)).toEqual(
      new Array(3).fill('sep38/quote-expiry-missing'),
    );
    expect(result.diagnostics[0]?.severity).toBe('error');
  });

  it('flags an unparseable expiry', async () => {
    const result = await audit(
      anchorServer({
        quote: () => ({
          raw: { id: 'q', sell_amount: '10', buy_amount: '10', expires_at: 'tomorrow' },
        }),
      }),
    );
    expect(result.diagnostics.map((d) => d.rule)).toEqual(
      new Array(3).fill('sep38/quote-expiry-missing'),
    );
    expect(result.diagnostics[0]?.message).toContain('tomorrow');
  });

  it('flags a quote issued already expired', async () => {
    const { clock } = fakeClock();
    const result = await audit(anchorServer({ quote: () => ({ expiresInSeconds: -5 }) }), {
      clock,
    });
    expect(result.diagnostics.map((d) => d.rule)).toEqual(
      new Array(3).fill('sep38/firm-quote-expired'),
    );
    expect(result.diagnostics[0]?.message).toContain('already expired');
  });

  it('warns about a quote window longer than the configured limit', async () => {
    const result = await audit(anchorServer({ quote: () => ({ expiresInSeconds: 400 }) }));
    expect(result.diagnostics.map((d) => d.rule)).toEqual(
      new Array(3).fill('sep38/quote-lifetime-exceeds-limit'),
    );
    expect(result.diagnostics[0]?.severity).toBe('warning');
    expect(result.diagnostics[0]?.message).toContain('400.0s');
  });

  it('accepts expire_after as an expiry alias', async () => {
    const result = await audit(
      anchorServer({ quote: () => ({ expiresInSeconds: 30, useExpireAfter: true }) }),
    );
    expect(result.diagnostics).toEqual([]);
    expect(result.observations[0]?.expiresAt).toBe(new Date(FIXED_NOW + 30_000).toISOString());
  });

  it('honours severity overrides and does not report disabled rules', async () => {
    const result = await audit(
      anchorServer({ quote: (amount) => ({ buyAmount: String(Number(amount) * 0.95) }) }),
      { rules: { 'sep38/spread-exceeds-tolerance': 'off' } },
    );
    expect(result.diagnostics).toEqual([]);
  });

  it('raises the lifetime warning to an error when configured', async () => {
    const result = await audit(anchorServer({ quote: () => ({ expiresInSeconds: 400 }) }), {
      rules: { 'sep38/quote-lifetime-exceeds-limit': 'error' },
    });
    expect(result.diagnostics[0]?.severity).toBe('error');
  });

  it('uses exact integer math where floats would hide a spread', async () => {
    // 0.1 + 0.2 style inputs: the firm rate is 0.30000000000000004 in floats,
    // but as exact decimals this is a clean 3:1 rate.
    const result = await audit(
      anchorServer({
        price: () => '0.3',
        quote: () => ({ buyAmount: '0.3', sellAmount: '1' }),
      }),
    );
    expect(result.observations[0]?.spreadBps).toBe(0n);
  });

  it('falls back to the requested sell amount when the quote omits one', async () => {
    const result = await audit(
      anchorServer({
        quote: (amount) => ({
          raw: {
            id: 'q',
            buy_amount: amount,
            expires_at: new Date(FIXED_NOW + 30_000).toISOString(),
          },
        }),
      }),
    );
    expect(result.observations[0]?.sellAmount).toBe('10');
    expect(result.observations[0]?.spreadBps).toBe(0n);
  });

  it('skips the spread when the quote omits buy_amount', async () => {
    const result = await audit(
      anchorServer({
        quote: () => ({
          raw: { id: 'q', expires_at: new Date(FIXED_NOW + 30_000).toISOString() },
        }),
      }),
    );
    expect(result.observations.every((o) => o.spreadBps === undefined)).toBe(true);
    expect(result.summary).toContain('worst spread unmeasured');
    expect(result.diagnostics).toEqual([]);
  });

  it('resolves a pair from explicit options without asking /info', async () => {
    const paths: string[] = [];
    const result = await audit(anchorServer({ onRequest: (url) => paths.push(url.pathname) }), {
      sellAsset: SELL,
      buyAsset: BUY,
    });
    expect(result.diagnostics).toEqual([]);
    expect(paths).not.toContain('/info');
    expect(paths).toContain('/prices');
  });

  it('stays silent without a usable quote server', async () => {
    let called = 0;
    const counting = (async () => {
      called++;
      return jsonResponse({});
    }) as unknown as typeof fetch;
    const result = await auditSep38QuoteDiscrepancies(
      { ANCHOR_QUOTE_SERVER: 'http://insecure' },
      counting,
    );
    expect(result).toEqual({
      diagnostics: [],
      observations: [],
      summary: 'No usable ANCHOR_QUOTE_SERVER to probe.',
    });
    expect(called).toBe(0);
  });

  it('reports when the anchor advertises no pair', async () => {
    const result = await audit(anchorServer({ assets: [{ asset: SELL }] }));
    expect(result.diagnostics.map((d) => d.rule)).toEqual(['sep38/quote-audit-unverifiable']);
    expect(result.diagnostics[0]?.severity).toBe('info');
    expect(result.summary).toBe('No quotable pair advertised.');
  });

  it('reports an unreachable /info as unverifiable', async () => {
    const result = await audit(anchorServer({ infoThrows: true }));
    expect(result.diagnostics.map((d) => d.rule)).toEqual(['sep38/quote-audit-unverifiable']);
  });

  it('reports a non-200 /info as unverifiable', async () => {
    const result = await audit(anchorServer({ infoStatus: 503 }));
    expect(result.diagnostics.map((d) => d.rule)).toEqual(['sep38/quote-audit-unverifiable']);
  });

  it('reports when neither endpoint answers for any tier', async () => {
    const result = await audit(anchorServer({ pricesStatus: 500, quoteStatus: 500 }));
    expect(result.diagnostics.map((d) => d.rule)).toEqual(['sep38/quote-audit-unverifiable']);
    expect(result.observations).toHaveLength(3);
    expect(result.summary).toContain('No quote could be priced');
  });

  it('keeps expiry findings even when the indicative price is unavailable', async () => {
    const result = await audit(
      anchorServer({
        pricesStatus: 500,
        quote: () => ({ expiresInSeconds: null }),
      }),
    );
    expect(result.diagnostics.map((d) => d.rule)).toEqual(
      new Array(3).fill('sep38/quote-expiry-missing'),
    );
  });

  it('tolerates a quote request that throws', async () => {
    const result = await audit(anchorServer({ quoteThrows: true }));
    expect(result.diagnostics).toEqual([]);
    expect(result.observations.every((o) => o.indicativePrice === '1')).toBe(true);
    expect(result.observations.every((o) => o.expiresAt === undefined)).toBe(true);
  });

  it('tolerates invalid JSON from every endpoint', async () => {
    const result = await audit(
      anchorServer({ infoRaw: '<html>', pricesRaw: '<html>', quoteRaw: '<html>' }),
    );
    expect(result.diagnostics.map((d) => d.rule)).toEqual(['sep38/quote-audit-unverifiable']);
  });

  it('tolerates invalid JSON from /prices and /quote once the pair is known', async () => {
    const result = await audit(anchorServer({ pricesRaw: '<html>', quoteRaw: '<html>' }));
    expect(result.diagnostics.map((d) => d.rule)).toEqual(['sep38/quote-audit-unverifiable']);
  });

  it('tolerates request failures and non-JSON bodies', async () => {
    const result = await audit(
      anchorServer({
        pricesThrows: true,
        quoteBody: 'not-an-object',
      }),
    );
    expect(result.diagnostics.map((d) => d.rule)).toEqual(['sep38/quote-audit-unverifiable']);
  });

  it('skips non-object fee entries', async () => {
    const result = await audit(
      anchorServer({
        quote: () => ({
          raw: {
            id: 'q',
            buy_amount: '100',
            sell_amount: '100',
            fees: [null, { amount: '0.25' }],
            expires_at: new Date(FIXED_NOW + 30_000).toISOString(),
          },
        }),
      }),
    );
    expect(result.observations[0]?.declaredFeeBps).toBe(25n);
  });

  it('handles a quote without an id', async () => {
    const result = await audit(
      anchorServer({
        quote: () => ({
          raw: {
            buy_amount: '10',
            sell_amount: '10',
            expires_at: new Date(FIXED_NOW + 30_000).toISOString(),
          },
        }),
      }),
    );
    expect(result.observations.every((o) => o.quoteId === undefined)).toBe(true);
    expect(result.diagnostics).toEqual([]);
  });

  it('reads fees from a fees array and ignores malformed entries', async () => {
    const result = await audit(
      anchorServer({
        quote: () => ({
          raw: {
            id: 'q',
            buy_amount: '100',
            sell_amount: '100',
            fees: [{ amount: '0.1' }, { amount: 'nope' }],
            expires_at: new Date(FIXED_NOW + 30_000).toISOString(),
          },
        }),
      }),
    );
    expect(result.observations[0]?.declaredFeeBps).toBe(10n);
    expect(result.diagnostics).toEqual([]);
  });
});

describe('Sep38QuoteDiscrepancyAuditor expired-quote probe', () => {
  it('reports an expired quote the transfer server still accepts', async () => {
    const { clock, sleep } = fakeClock();
    let depositUrl: URL | undefined;
    const result = await auditSep38QuoteDiscrepancies(
      DOC,
      anchorServer({
        quote: () => ({ expiresInSeconds: 1 }),
        deposit: (url) => {
          depositUrl = url;
          return jsonResponse({ id: 'deposit' }, 200);
        },
      }),
      { clock, sleep, maxExpiryWaitMs: 5000 },
    );

    expect(result.diagnostics.map((d) => d.rule)).toEqual(['sep38/expired-quote-accepted']);
    expect(result.diagnostics[0]?.severity).toBe('error');
    expect(result.diagnostics[0]?.message).toContain('quote-10');
    expect(depositUrl?.searchParams.get('quote_id')).toBe('quote-10');
    expect(depositUrl?.searchParams.get('asset_code')).toBe('USDC');
    expect(depositUrl?.searchParams.get('account')).toBe(
      'GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY',
    );
  });

  it('passes when the transfer server rejects the expired quote', async () => {
    const { clock, sleep } = fakeClock();
    const result = await auditSep38QuoteDiscrepancies(
      DOC,
      anchorServer({
        quote: () => ({ expiresInSeconds: 1 }),
        deposit: () => jsonResponse({ error: 'quote expired' }, 400),
      }),
      { clock, sleep, maxExpiryWaitMs: 5000 },
    );
    expect(result.diagnostics).toEqual([]);
  });

  it('is silent when the transfer server cannot be reached', async () => {
    const { clock, sleep } = fakeClock();
    const result = await auditSep38QuoteDiscrepancies(
      DOC,
      anchorServer({
        quote: () => ({ expiresInSeconds: 1 }),
        deposit: () => {
          throw new Error('offline');
        },
      }),
      { clock, sleep, maxExpiryWaitMs: 5000 },
    );
    expect(result.diagnostics).toEqual([]);
  });

  it('skips the probe when no quote has a future expiry', async () => {
    const { clock, sleep } = fakeClock();
    let deposits = 0;
    const result = await auditSep38QuoteDiscrepancies(
      DOC,
      anchorServer({
        quote: () => ({ expiresInSeconds: -5 }),
        deposit: () => {
          deposits++;
          return jsonResponse({}, 200);
        },
      }),
      { clock, sleep, maxExpiryWaitMs: 5000 },
    );
    expect(result.diagnostics.map((d) => d.rule)).toEqual(
      new Array(3).fill('sep38/firm-quote-expired'),
    );
    expect(deposits).toBe(0);
  });

  it('skips the probe for a non-HTTPS transfer server', async () => {
    const { clock, sleep } = fakeClock();
    let deposits = 0;
    const result = await auditSep38QuoteDiscrepancies(
      { ...DOC, TRANSFER_SERVER: 'http://anchor.example.com/sep6' },
      anchorServer({
        quote: () => ({ expiresInSeconds: 1 }),
        deposit: () => {
          deposits++;
          return jsonResponse({}, 200);
        },
      }),
      { clock, sleep, maxExpiryWaitMs: 5000 },
    );
    expect(result.diagnostics).toEqual([]);
    expect(deposits).toBe(0);
  });

  it('derives the asset code even from a non-standard asset id', async () => {
    const { clock, sleep } = fakeClock();
    let assetCode: string | null = null;
    const result = await auditSep38QuoteDiscrepancies(
      DOC,
      anchorServer({
        quote: () => ({ expiresInSeconds: 1 }),
        deposit: (url) => {
          assetCode = url.searchParams.get('asset_code');
          return jsonResponse({}, 200);
        },
      }),
      {
        clock,
        sleep,
        maxExpiryWaitMs: 5000,
        sellAsset: 'USDC',
        buyAsset: 'EURC',
      },
    );
    expect(result.diagnostics.map((d) => d.rule)).toEqual(['sep38/expired-quote-accepted']);
    expect(assetCode).toBe('');
  });

  it('skips the probe when the quote outlives the wait budget', async () => {
    const { clock, sleep } = fakeClock();
    let deposits = 0;
    const result = await auditSep38QuoteDiscrepancies(
      DOC,
      anchorServer({
        quote: () => ({ expiresInSeconds: 60 }),
        deposit: () => {
          deposits++;
          return jsonResponse({}, 200);
        },
      }),
      { clock, sleep, maxExpiryWaitMs: 2000 },
    );
    expect(result.diagnostics).toEqual([]);
    expect(deposits).toBe(0);
  });

  it('skips the probe without a transfer server', async () => {
    const { clock, sleep } = fakeClock();
    let deposits = 0;
    const result = await auditSep38QuoteDiscrepancies(
      { ANCHOR_QUOTE_SERVER: DOC.ANCHOR_QUOTE_SERVER },
      anchorServer({
        quote: () => ({ expiresInSeconds: 1 }),
        deposit: () => {
          deposits++;
          return jsonResponse({}, 200);
        },
      }),
      { clock, sleep, maxExpiryWaitMs: 5000 },
    );
    expect(result.diagnostics).toEqual([]);
    expect(deposits).toBe(0);
  });

  it('sends a SEP-10 token when one is configured', async () => {
    const { clock, sleep } = fakeClock();
    let authorization: string | undefined;
    const result = await auditSep38QuoteDiscrepancies(
      DOC,
      anchorServer({
        quote: () => ({ expiresInSeconds: 1 }),
        deposit: (_url, init) => {
          authorization = (init?.headers as Record<string, string> | undefined)?.authorization;
          return jsonResponse({}, 403);
        },
      }),
      { clock, sleep, maxExpiryWaitMs: 5000, token: 'jwt-token' },
    );
    expect(result.diagnostics).toEqual([]);
    expect(authorization).toBe('Bearer jwt-token');
  });

  it('probes by default and can be disabled', async () => {
    const { clock, sleep } = fakeClock();
    let deposits = 0;
    const fetchImpl = anchorServer({
      quote: () => ({ expiresInSeconds: 1 }),
      deposit: () => {
        deposits++;
        return jsonResponse({}, 200);
      },
    });

    const probed = await auditSep38QuoteDiscrepancies(DOC, fetchImpl, {
      clock,
      sleep,
      maxExpiryWaitMs: 5000,
    });
    expect(probed.diagnostics.map((d) => d.rule)).toEqual(['sep38/expired-quote-accepted']);
    expect(deposits).toBe(1);

    const second = fakeClock();
    const disabled = await auditSep38QuoteDiscrepancies(DOC, fetchImpl, {
      clock: second.clock,
      sleep: second.sleep,
      maxExpiryWaitMs: 5000,
      probeExpiredExecution: false,
    });
    expect(disabled.diagnostics).toEqual([]);
    expect(deposits).toBe(1);
  });

  it('exposes the auditor class with injected transport and clock', async () => {
    const { clock, sleep } = fakeClock();
    const result = await new Sep38QuoteDiscrepancyAuditor(anchorServer(), {
      clock,
      sleep,
      probeExpiredExecution: false,
      quoteServer: DOC.ANCHOR_QUOTE_SERVER,
      transferServer: TRANSFER,
    }).audit(DOC);
    expect(result.diagnostics).toEqual([]);
    expect(result.observations).toHaveLength(3);
  });
});
