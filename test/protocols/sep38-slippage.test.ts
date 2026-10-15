import { describe, it, expect } from 'vitest';
import {
  analyzeSep38Slippage,
  INVERTED_BID_ASK_SPREAD_RULE,
  EXCESSIVE_SLIPPAGE_DETECTED_RULE,
  NON_MONOTONIC_PRICE_CURVE_RULE,
} from '../../src/protocols/sep38-slippage-analyzer.js';

const ANCHOR_QUOTE_SERVER = 'https://api.example.com/sep38';
const ISSUER_A = 'GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY';
const ISSUER_B = 'GAHK7EEG2WWHVKDNT4CEQFZGKF2LGDSBRTC4TQBXXK2ZBDUFLYWWDZDT';

const USDX = `stellar:USDX:${ISSUER_A}`;
const EURX = `stellar:EURX:${ISSUER_B}`;
const DECLARED = [USDX, EURX];

const DOC = {
  ANCHOR_QUOTE_SERVER,
  CURRENCIES: [
    { code: 'USDX', issuer: ISSUER_A },
    { code: 'EURX', issuer: ISSUER_B },
  ],
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function priceList(quotes: Record<string, string>): Response {
  return jsonResponse({
    buy_assets: Object.entries(quotes).map(([asset, price]) => ({ asset, price, decimals: 2 })),
  });
}

interface Routes {
  prices?: (sellAsset: string, sellAmount: string) => Response;
  quote?: (payload: Record<string, unknown>) => Response;
}

function fetchServer(routes: Routes): typeof fetch {
  return (async (input: unknown, init?: RequestInit) => {
    const url = new URL(String(input));

    if (url.pathname.endsWith('/prices')) {
      const sellAsset = url.searchParams.get('sell_asset') ?? '';
      const sellAmount = url.searchParams.get('sell_amount') ?? '1';
      return (routes.prices ?? (() => priceList({})))(sellAsset, sellAmount);
    }

    if (url.pathname.endsWith('/quote')) {
      const payload =
        typeof init?.body === 'string' ? (JSON.parse(init.body) as Record<string, unknown>) : {};
      return (routes.quote ?? (() => jsonResponse({ price: '1.00' })))(payload);
    }

    throw new Error(`unexpected request to ${url}`);
  }) as unknown as typeof fetch;
}

describe('SEP-38 Slippage Analyzer', () => {
  it('passes with monotonic pricing curve within slippage limits', async () => {
    const diagnostics = await analyzeSep38Slippage(DOC, fetchServer({
      prices: (sellAsset, sellAmount) => {
        const amount = Number(sellAmount);
        // Forward direction: normal slippage (price decreases with amount)
        // Reverse direction: different base price to avoid inverted spread
        if (sellAsset === USDX) {
          const basePrice = 0.9; // 1 USDX = 0.9 EURX
          const slippage = amount * 0.0000001; // 0.00001% per unit
          const price = basePrice - slippage;
          return priceList({ [EURX]: price.toFixed(4) });
        } else {
          const basePrice = 1.1112; // 1 EURX = 1.1112 USDX (inverse of 0.9 with spread)
          const slippage = amount * 0.0000001;
          const price = basePrice - slippage;
          return priceList({ [USDX]: price.toFixed(4) });
        }
      },
    }));

    const inverted = diagnostics.filter((d) => d.rule === INVERTED_BID_ASK_SPREAD_RULE);
    const excessive = diagnostics.filter((d) => d.rule === EXCESSIVE_SLIPPAGE_DETECTED_RULE);
    const nonMonotonic = diagnostics.filter((d) => d.rule === NON_MONOTONIC_PRICE_CURVE_RULE);

    expect(inverted).toHaveLength(0);
    expect(excessive).toHaveLength(0);
    expect(nonMonotonic).toHaveLength(0);
  });

  it('detects inverted bid-ask spread', async () => {
    const diagnostics = await analyzeSep38Slippage(DOC, fetchServer({
      prices: (sellAsset) =>
        sellAsset === USDX ? priceList({ [EURX]: '0.5' }) : priceList({ [USDX]: '0.5' }),
    }));

    const inverted = diagnostics.filter((d) => d.rule === INVERTED_BID_ASK_SPREAD_RULE);
    expect(inverted).toHaveLength(1);
    expect(inverted[0]?.severity).toBe('error');
    expect(inverted[0]?.message).toContain('inverted bid-ask spread');
  });

  it('detects excessive slippage', async () => {
    const diagnostics = await analyzeSep38Slippage(DOC, fetchServer({
      prices: (sellAsset, sellAmount) => {
        const amount = Number(sellAmount);
        // Excessive slippage: price drops 20% at 1000 units
        const basePrice = 1.0;
        const slippage = amount * 0.0002; // 0.02% per unit -> 20% at 1000
        const price = Math.max(0.01, basePrice - slippage);
        return sellAsset === USDX
          ? priceList({ [EURX]: price.toFixed(4) })
          : priceList({ [USDX]: price.toFixed(4) });
      },
    }));

    const excessive = diagnostics.filter((d) => d.rule === EXCESSIVE_SLIPPAGE_DETECTED_RULE);
    expect(excessive.length).toBeGreaterThan(0);
  });

  it('detects non-monotonic price curve', async () => {
    const diagnostics = await analyzeSep38Slippage(DOC, fetchServer({
      prices: (sellAsset, sellAmount) => {
        const amount = Number(sellAmount);
        // Non-monotonic: price improves at larger size
        let price = 1.0;
        if (amount === 10) price = 1.0;
        else if (amount === 100) price = 0.95;
        else if (amount === 1000) price = 0.98; // Improves - bad!
        else if (amount === 10000) price = 0.9;
        else if (amount === 100000) price = 0.85;

        return sellAsset === USDX
          ? priceList({ [EURX]: price.toFixed(4) })
          : priceList({ [USDX]: price.toFixed(4) });
      },
    }));

    const nonMonotonic = diagnostics.filter((d) => d.rule === NON_MONOTONIC_PRICE_CURVE_RULE);
    expect(nonMonotonic.length).toBeGreaterThan(0);
  });

  it('stays silent when no ANCHOR_QUOTE_SERVER', async () => {
    const doc = { CURRENCIES: DOC.CURRENCIES };
    const diagnostics = await analyzeSep38Slippage(doc, fetchServer({}));
    expect(diagnostics).toEqual([]);
  });

  it('stays silent when ANCHOR_QUOTE_SERVER is not a URL', async () => {
    const doc = { ANCHOR_QUOTE_SERVER: 'not a url', CURRENCIES: DOC.CURRENCIES };
    const diagnostics = await analyzeSep38Slippage(doc, fetchServer({}));
    expect(diagnostics).toEqual([]);
  });

  it('respects rule severity overrides', async () => {
    const diagnostics = await analyzeSep38Slippage(DOC, fetchServer({
      prices: (sellAsset) =>
        sellAsset === USDX ? priceList({ [EURX]: '0.5' }) : priceList({ [USDX]: '0.5' }),
    }), {
      rules: { [INVERTED_BID_ASK_SPREAD_RULE]: 'off' },
    });

    const inverted = diagnostics.filter((d) => d.rule === INVERTED_BID_ASK_SPREAD_RULE);
    expect(inverted).toHaveLength(0);
  });

  it('uses custom order sizes and slippage limits', async () => {
    const diagnostics = await analyzeSep38Slippage(DOC, fetchServer({
      prices: (sellAsset, sellAmount) => {
        const amount = Number(sellAmount);
        // Small slippage
        const price = 1.0 - amount * 0.000001;
        return sellAsset === USDX
          ? priceList({ [EURX]: price.toFixed(4) })
          : priceList({ [USDX]: price.toFixed(4) });
      },
    }), {
      orderSizes: [1, 10, 100],
      maxSlippagePercent: 1,
    });

    const excessive = diagnostics.filter((d) => d.rule === EXCESSIVE_SLIPPAGE_DETECTED_RULE);
    expect(excessive).toHaveLength(0);
  });
});