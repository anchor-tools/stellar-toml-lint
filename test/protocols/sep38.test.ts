import { describe, expect, it } from 'vitest';
import {
  verifySep38,
  sep38QuoteRules,
  ABNORMAL_EXCHANGE_RATE_SPREAD_RULE,
  INFO_SCHEMA_INVALID_RULE,
  INVALID_QUOTE_EXPIRATION_RULE,
  MAX_QUOTE_SPREAD_PERCENT,
  PRICES_MISSING_DECLARED_ASSET_RULE,
} from '../../src/protocols/sep38.js';

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

const FUTURE = new Date(Date.now() + 60 * 60 * 1000).toISOString();
const PAST = new Date(Date.now() - 60 * 60 * 1000).toISOString();

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

/** The conforming server: every declared counterpart quoted at par. */
function defaultPrices(sellAsset: string): Response {
  const quotes: Record<string, string> = {};
  for (const asset of DECLARED) {
    if (asset !== sellAsset) quotes[asset] = '1.00';
  }
  return priceList(quotes);
}

function validInfo(): Response {
  return jsonResponse({
    assets: [{ asset: USDX }, { asset: EURX, country_codes: ['DE', 'US-NY'] }],
  });
}

function validQuote(): Response {
  return jsonResponse(
    { id: 'quote-1', expires_at: FUTURE, price: '1.00', sell_asset: USDX, buy_asset: EURX },
    201,
  );
}

interface Routes {
  info?: () => Response;
  prices?: (sellAsset: string) => Response;
  quote?: (payload: Record<string, unknown>) => Response;
}

/** A path-routed fetch stub standing in for the anchor's quote server. */
function fetchServer(routes: Routes): typeof fetch {
  return (async (input: unknown, init?: RequestInit) => {
    const url = new URL(String(input));

    if (url.pathname.endsWith('/info')) {
      return (routes.info ?? validInfo)();
    }

    if (url.pathname.endsWith('/prices')) {
      const sellAsset = url.searchParams.get('sell_asset') ?? '';
      return (routes.prices ?? defaultPrices)(sellAsset);
    }

    if (url.pathname.endsWith('/quote')) {
      const payload =
        typeof init?.body === 'string' ? (JSON.parse(init.body) as Record<string, unknown>) : {};
      return (routes.quote ?? validQuote)(payload);
    }

    throw new Error(`unexpected request to ${url}`);
  }) as unknown as typeof fetch;
}

describe('SEP-38 anchor quotes and RFQ pricing engine simulator', () => {
  it('passes cleanly when the mock server returns valid quotes', async () => {
    const diagnostics = await verifySep38(DOC, fetchServer({}));

    expect(diagnostics).toEqual([]);
  });

  it('stays silent when the file declares no usable ANCHOR_QUOTE_SERVER', async () => {
    expect(await verifySep38({ CURRENCIES: DOC.CURRENCIES }, fetchServer({}))).toEqual([]);
    expect(await verifySep38({ ANCHOR_QUOTE_SERVER: 'not a url' }, fetchServer({}))).toEqual([]);
  });

  it('asserts sep38/invalid-quote-expiration when the server returns expired quotes', async () => {
    const diagnostics = await verifySep38(
      DOC,
      fetchServer({
        quote: () =>
          jsonResponse({ id: 'quote-1', expires_at: PAST, price: '1.00', sell_asset: USDX }, 201),
      }),
    );

    const expirations = diagnostics.filter((d) => d.rule === INVALID_QUOTE_EXPIRATION_RULE);
    // One per quote kind: the wallet asks for a firm and an indicative quote.
    expect(expirations).toHaveLength(2);
    expect(expirations.map((d) => d.severity)).toEqual(['error', 'error']);
    expect(expirations[0]?.message).toContain('already in the past');
    expect(expirations[0]?.message).toContain('firm');
    expect(expirations[1]?.message).toContain('indicative');
  });

  it('asserts sep38/invalid-quote-expiration when the quote never expires', async () => {
    const diagnostics = await verifySep38(
      DOC,
      fetchServer({
        quote: () => jsonResponse({ id: 'quote-1', price: '1.00' }, 201),
      }),
    );

    const expirations = diagnostics.filter((d) => d.rule === INVALID_QUOTE_EXPIRATION_RULE);
    expect(expirations).toHaveLength(2);
    expect(expirations[0]?.message).toContain('without an `expires_at`');
  });

  it('asserts sep38/abnormal-exchange-rate-spread on inverted reverse rates', async () => {
    const diagnostics = await verifySep38(
      DOC,
      fetchServer({
        prices: (sellAsset) =>
          sellAsset === USDX ? priceList({ [EURX]: '2.00' }) : priceList({ [USDX]: '0.40' }),
      }),
    );

    const spreads = diagnostics.filter((d) => d.rule === ABNORMAL_EXCHANGE_RATE_SPREAD_RULE);
    expect(spreads).toHaveLength(1);
    expect(spreads[0]?.severity).toBe('warning');
    expect(spreads[0]?.message).toContain('20.0%');
    expect(spreads[0]?.message).toContain(`${MAX_QUOTE_SPREAD_PERCENT}%`);
  });

  it('asserts sep38/abnormal-exchange-rate-spread on a zero rate', async () => {
    const diagnostics = await verifySep38(
      DOC,
      fetchServer({
        prices: (sellAsset) =>
          sellAsset === USDX ? priceList({ [EURX]: '0' }) : priceList({ [USDX]: '1.00' }),
      }),
    );

    const spreads = diagnostics.filter((d) => d.rule === ABNORMAL_EXCHANGE_RATE_SPREAD_RULE);
    expect(spreads).toHaveLength(1);
    expect(spreads[0]?.severity).toBe('warning');
    expect(spreads[0]?.message).toContain('not a positive number');
  });

  it('asserts sep38/prices-missing-declared-asset when a declared pair is not priced', async () => {
    const diagnostics = await verifySep38(
      DOC,
      fetchServer({
        prices: (sellAsset) => (sellAsset === USDX ? priceList({}) : priceList({ [USDX]: '1.00' })),
      }),
    );

    const missing = diagnostics.filter((d) => d.rule === PRICES_MISSING_DECLARED_ASSET_RULE);
    expect(missing).toHaveLength(1);
    expect(missing[0]?.severity).toBe('error');
    expect(missing[0]?.message).toContain(EURX);
    expect(missing[0]?.path).toBe('CURRENCIES');
  });

  it('prices the iso4217 leg a fiat-anchored currency declares', async () => {
    const anchored = {
      ANCHOR_QUOTE_SERVER,
      CURRENCIES: [
        { code: 'USDX', issuer: ISSUER_A, anchor_asset_type: 'fiat', anchor_asset: 'USD' },
      ],
    };
    const fiat = 'iso4217:USD';

    const covered = await verifySep38(
      anchored,
      fetchServer({
        prices: (sellAsset) =>
          sellAsset === USDX ? priceList({ [fiat]: '1.00' }) : priceList({ [USDX]: '1.00' }),
      }),
    );
    expect(covered).toEqual([]);

    const unpriced = await verifySep38(
      anchored,
      fetchServer({
        prices: () => priceList({ [fiat]: '1.00' }),
      }),
    );
    expect(unpriced.map((d) => d.rule)).toEqual([PRICES_MISSING_DECLARED_ASSET_RULE]);
  });

  it('asserts sep38/info-schema-invalid on a country code no registry would issue', async () => {
    const diagnostics = await verifySep38(
      DOC,
      fetchServer({
        info: () => jsonResponse({ assets: [{ asset: EURX, country_codes: ['DEU', '1'] }] }),
      }),
    );

    const info = diagnostics.filter((d) => d.rule === INFO_SCHEMA_INVALID_RULE);
    expect(info).toHaveLength(1);
    expect(info[0]?.severity).toBe('error');
    expect(info[0]?.message).toContain('"DEU"');
  });

  it('asserts sep38/info-schema-invalid when /info has no assets array', async () => {
    const diagnostics = await verifySep38(DOC, fetchServer({ info: () => jsonResponse({}) }));

    const info = diagnostics.filter((d) => d.rule === INFO_SCHEMA_INVALID_RULE);
    expect(info).toHaveLength(1);
    expect(info[0]?.message).toContain('`assets` array');
  });

  it('asks POST /quote for both quote kinds with the country from /info', async () => {
    const payloads: Record<string, unknown>[] = [];

    await verifySep38(
      DOC,
      fetchServer({
        quote: (payload) => {
          payloads.push(payload);
          return validQuote();
        },
      }),
    );

    expect(payloads.map((payload) => payload.type)).toEqual(['firm', 'indicative']);
    for (const payload of payloads) {
      expect(payload.sell_asset).toBe(USDX);
      expect(payload.buy_asset).toBe(EURX);
      // EURX quotes to Germany; USDX declares no country_codes of its own.
      expect(payload.country_code).toBe('DE');
    }
  });

  it('treats the 403 of an auth-required server as silence, not a finding', async () => {
    const diagnostics = await verifySep38(
      DOC,
      fetchServer({
        quote: () => jsonResponse({ error: 'SEP-10 authentication required' }, 403),
      }),
    );

    expect(diagnostics).toEqual([]);
  });

  it('honours severity overrides on its rules', async () => {
    const brokenPrices = fetchServer({
      prices: (sellAsset) => (sellAsset === USDX ? priceList({}) : priceList({ [USDX]: '1.00' })),
    });

    const silenced = await verifySep38(DOC, brokenPrices, {
      rules: { [PRICES_MISSING_DECLARED_ASSET_RULE]: 'off' },
    });
    expect(silenced.filter((d) => d.rule === PRICES_MISSING_DECLARED_ASSET_RULE)).toEqual([]);

    const raised = await verifySep38(DOC, brokenPrices, {
      rules: { [PRICES_MISSING_DECLARED_ASSET_RULE]: 'warning' },
    });
    expect(raised[0]?.severity).toBe('warning');
  });
});

describe('sep38QuoteRules', () => {
  it('registers the ids and severities the engine emits', () => {
    const byId = new Map(sep38QuoteRules.map((rule) => [rule.id, rule]));

    expect([...byId.keys()].sort()).toEqual(
      [
        ABNORMAL_EXCHANGE_RATE_SPREAD_RULE,
        INFO_SCHEMA_INVALID_RULE,
        INVALID_QUOTE_EXPIRATION_RULE,
        PRICES_MISSING_DECLARED_ASSET_RULE,
      ].sort(),
    );
    expect(byId.get(PRICES_MISSING_DECLARED_ASSET_RULE)?.severity).toBe('error');
    expect(byId.get(ABNORMAL_EXCHANGE_RATE_SPREAD_RULE)?.severity).toBe('warning');
    expect(byId.get(INVALID_QUOTE_EXPIRATION_RULE)?.severity).toBe('error');
    expect(byId.get(INFO_SCHEMA_INVALID_RULE)?.severity).toBe('error');
    for (const rule of sep38QuoteRules) expect(rule.category).toBe('network');
  });
});
