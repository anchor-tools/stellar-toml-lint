import { describe, expect, it } from 'vitest';
import { checkSep38, sep38Rules } from '../src/rules/sep38-endpoints.js';

const ANCHOR_QUOTE_SERVER = 'https://api.example.com/sep38';
const ISSUER = 'GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY';

const DOC = {
  ANCHOR_QUOTE_SERVER,
  CURRENCIES: [{ code: 'USDX', issuer: ISSUER }],
};

/** Mirrors the shape of a real `GET /prices` response from SEP-38. */
function validPrices(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    buy_assets: [
      {
        asset: 'iso4217:USD',
        price: '1.00',
        decimals: 2,
      },
    ],
    ...overrides,
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

/**
 * Routes each request by path so `/prices` and `/quote` can answer
 * differently inside one audit, mirroring a real mock server.
 */
function fetchServer(routes: {
  prices?: () => Response | Promise<Response>;
  quote?: () => Response | Promise<Response>;
}): typeof fetch {
  return (async (input: string | URL | Request) => {
    const url = String(input);
    if (url.includes('/prices')) {
      if (routes.prices) return routes.prices();
      return jsonResponse(validPrices());
    }
    if (url.includes('/quote')) {
      if (routes.quote) return routes.quote();
      return jsonResponse({ id: 'q-1', price: '1.00' }, 404);
    }
    throw new Error(`unexpected request to ${url}`);
  }) as unknown as typeof fetch;
}

describe('checkSep38', () => {
  it('passes when /prices returns 200 with a buy_assets array of price objects', async () => {
    const diagnostics = await checkSep38(DOC, fetchServer({}));
    expect(diagnostics).toEqual([]);
  });

  it('requests /prices with the sell_asset declared in the file', async () => {
    let requested = '';
    const fetchImpl = (async (input: string | URL | Request) => {
      const url = String(input);
      if (url.includes('/prices')) requested = url;
      return jsonResponse(validPrices());
    }) as unknown as typeof fetch;

    await checkSep38(DOC, fetchImpl);
    expect(requested).toContain('/prices?sell_asset=');
    expect(decodeURIComponent(requested)).toContain(`stellar:USDX:${ISSUER}`);
  });

  it('reports sep38/prices-endpoint-error on HTTP 500', async () => {
    const diagnostics = await checkSep38(
      DOC,
      fetchServer({ prices: () => jsonResponse({ error: 'boom' }, 500) }),
    );

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      rule: 'sep38/prices-endpoint-error',
      severity: 'error',
      category: 'network',
      path: 'ANCHOR_QUOTE_SERVER',
    });
    expect(diagnostics[0]?.message).toContain('HTTP 500');
  });

  it('reports sep38/prices-endpoint-error when fetch rejects', async () => {
    const fetchImpl = (async () => {
      throw new Error('connect ECONNREFUSED');
    }) as unknown as typeof fetch;

    const diagnostics = await checkSep38(DOC, fetchImpl);
    // Both /prices and /quote fail against a dead server.
    const prices = diagnostics.find((d) => d.rule === 'sep38/prices-endpoint-error');
    expect(diagnostics).toHaveLength(2);
    expect(prices?.message).toContain('ECONNREFUSED');
    expect(prices?.severity).toBe('error');
  });

  it('reports sep38/malformed-price-response when the body is not JSON', async () => {
    const diagnostics = await checkSep38(
      DOC,
      fetchServer({
        prices: () =>
          new Response('<html>oops</html>', {
            status: 200,
            headers: { 'content-type': 'text/html' },
          }),
      }),
    );

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.rule).toBe('sep38/malformed-price-response');
    expect(diagnostics[0]?.message).toContain('valid JSON');
  });

  it('reports sep38/malformed-price-response when buy_assets is missing', async () => {
    const diagnostics = await checkSep38(
      DOC,
      fetchServer({ prices: () => jsonResponse({ prices: [] }) }),
    );

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.rule).toBe('sep38/malformed-price-response');
    expect(diagnostics[0]?.message).toContain('buy_assets');
  });

  it('reports sep38/malformed-price-response when buy_assets is not an array', async () => {
    const diagnostics = await checkSep38(
      DOC,
      fetchServer({ prices: () => jsonResponse({ buy_assets: 'nope' }) }),
    );

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.rule).toBe('sep38/malformed-price-response');
  });

  it('reports sep38/malformed-price-response when a price object lacks asset/price', async () => {
    const diagnostics = await checkSep38(
      DOC,
      fetchServer({
        prices: () => jsonResponse({ buy_assets: [{ asset: 'iso4217:USD' }] }),
      }),
    );

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.rule).toBe('sep38/malformed-price-response');
    expect(diagnostics[0]?.message).toContain('price');
  });

  it('reports sep38/malformed-price-response when the body is not an object', async () => {
    const diagnostics = await checkSep38(
      DOC,
      fetchServer({ prices: () => jsonResponse(['not', 'an', 'object']) }),
    );

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.rule).toBe('sep38/malformed-price-response');
  });

  it('reports sep38/quote-endpoint-error when /quote answers 500', async () => {
    const diagnostics = await checkSep38(
      DOC,
      fetchServer({ quote: () => jsonResponse({ error: 'boom' }, 500) }),
    );

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      rule: 'sep38/quote-endpoint-error',
      severity: 'error',
      category: 'network',
      path: 'ANCHOR_QUOTE_SERVER',
    });
  });

  it('reports sep38/malformed-quote-response when /quote answers 200 with non-JSON', async () => {
    const fetchImpl = (async (input: string | URL | Request) => {
      const url = String(input);
      if (url.includes('/prices')) return jsonResponse(validPrices());
      return new Response('<html>portal</html>', {
        status: 200,
        headers: { 'content-type': 'text/html' },
      });
    }) as unknown as typeof fetch;

    const diagnostics = await checkSep38(DOC, fetchImpl);
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.rule).toBe('sep38/malformed-quote-response');
  });

  it('stays quiet when /quote answers 404 without auth or a quote id', async () => {
    const diagnostics = await checkSep38(
      DOC,
      fetchServer({ quote: () => jsonResponse({ error: 'not found' }, 404) }),
    );
    expect(diagnostics).toEqual([]);
  });

  it('stays silent without ANCHOR_QUOTE_SERVER', async () => {
    let calls = 0;
    const fetchImpl = (async () => {
      calls++;
      return jsonResponse(validPrices());
    }) as unknown as typeof fetch;

    const diagnostics = await checkSep38({ CURRENCIES: DOC.CURRENCIES }, fetchImpl);
    expect(diagnostics).toEqual([]);
    expect(calls).toBe(0);
  });

  it('stays silent when ANCHOR_QUOTE_SERVER is not a parseable URL', async () => {
    let calls = 0;
    const fetchImpl = (async () => {
      calls++;
      return jsonResponse(validPrices());
    }) as unknown as typeof fetch;

    const diagnostics = await checkSep38({ ...DOC, ANCHOR_QUOTE_SERVER: 'not a url' }, fetchImpl);
    expect(diagnostics).toEqual([]);
    expect(calls).toBe(0);
  });

  it('skips /prices when no classic asset is declared to sell', async () => {
    let priceCalls = 0;
    const fetchImpl = (async (input: string | URL | Request) => {
      if (String(input).includes('/prices')) priceCalls++;
      return jsonResponse({ id: 'q-1' }, 404);
    }) as unknown as typeof fetch;

    const diagnostics = await checkSep38(
      { ANCHOR_QUOTE_SERVER, CURRENCIES: [{ code: 'EXPL', contract: 'CAAAA' }] },
      fetchImpl,
    );
    expect(diagnostics).toEqual([]);
    expect(priceCalls).toBe(0);
  });

  it('queries the native asset as stellar:XLM for a native entry', async () => {
    let requested = '';
    const fetchImpl = (async (input: string | URL | Request) => {
      const url = String(input);
      if (url.includes('/prices')) requested = decodeURIComponent(url);
      return jsonResponse(validPrices());
    }) as unknown as typeof fetch;

    await checkSep38({ ANCHOR_QUOTE_SERVER, CURRENCIES: [{ code: 'native' }] }, fetchImpl);
    expect(requested).toContain('sell_asset=stellar:XLM');
  });

  it('honours --off for sep38/prices-endpoint-error', async () => {
    const diagnostics = await checkSep38(
      DOC,
      fetchServer({ prices: () => jsonResponse({}, 500) }),
      { rules: { 'sep38/prices-endpoint-error': 'off' } },
    );
    expect(diagnostics).toEqual([]);
  });

  it('honours --warn downgrades for sep38/prices-endpoint-error', async () => {
    const diagnostics = await checkSep38(
      DOC,
      fetchServer({ prices: () => jsonResponse({}, 500) }),
      { rules: { 'sep38/prices-endpoint-error': 'warning' } },
    );
    expect(diagnostics[0]?.severity).toBe('warning');
  });
});

describe('sep38Rules', () => {
  it('registers both required rule ids with error severity', () => {
    expect(sep38Rules.map((r) => ({ id: r.id, severity: r.severity }))).toEqual([
      { id: 'sep38/prices-endpoint-error', severity: 'error' },
      { id: 'sep38/malformed-price-response', severity: 'error' },
      { id: 'sep38/quote-endpoint-error', severity: 'error' },
      { id: 'sep38/malformed-quote-response', severity: 'error' },
    ]);
  });
});
