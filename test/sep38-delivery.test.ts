import { describe, expect, it } from 'vitest';
import {
  DELIVERY_METHOD_NAME_PATTERN,
  Sep38DeliveryMethodVerifier,
  countDeliveryFeeItems,
  isValidFee,
  renderSep38DeliveryReport,
  sep38DeliveryRuleIds,
  sep38DeliveryRules,
  validateDeliveryMethods,
  verifySep38DeliveryMethods,
} from '../src/protocols/sep38Delivery.js';

const USDC = 'stellar:USDC:GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H';
const EURC = 'stellar:EURC:GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H';
const DOC = { ANCHOR_QUOTE_SERVER: 'https://quotes.test' };

const INFO = {
  assets: [
    {
      asset: USDC,
      sell_delivery_methods: [{ name: 'bank_transfer', description: 'Local bank transfer' }],
    },
    {
      asset: EURC,
      buy_delivery_methods: [{ name: 'cash_pickup', description: 'Cash pickup at an agent' }],
    },
  ],
};

interface ServerOptions {
  info?: unknown;
  infoStatus?: number;
  quoteFee?: unknown;
  quoteStatus?: number;
  throwOnQuote?: boolean;
}

function mockServer(options: ServerOptions = {}) {
  const calls: string[] = [];
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input));
    calls.push(`${init?.method ?? 'GET'} ${url.pathname}`);
    if (url.pathname === '/info') {
      const status = options.infoStatus ?? 200;
      if (status >= 400) return new Response('no', { status });
      return Response.json(options.info ?? INFO);
    }
    if (url.pathname === '/quote') {
      if (options.throwOnQuote === true) throw new Error('quote down');
      const status = options.quoteStatus ?? 200;
      if (status >= 400) return Response.json({ error: 'unsupported' }, { status });
      return Response.json({
        id: 'quote-1',
        expires_at: '2030-01-01T00:00:00Z',
        price: '1.00',
        sell_amount: '1.00',
        buy_amount: '1.00',
        fee: options.quoteFee ?? {
          total: '0.10',
          asset: USDC,
          details: [
            { name: 'delivery_fee', description: 'Bank transfer delivery', amount: '0.10' },
          ],
        },
      });
    }
    return new Response('not found', { status: 404 });
  }) as unknown as typeof fetch;
  return { fetchImpl, calls };
}

const audit = (server: ServerOptions, options: Record<string, unknown> = {}) =>
  new Sep38DeliveryMethodVerifier(mockServer(server).fetchImpl, options).audit(DOC);

describe('delivery method schema', () => {
  it('exposes a lowercase identifier pattern', () => {
    expect(DELIVERY_METHOD_NAME_PATTERN.test('bank_transfer')).toBe(true);
    expect(DELIVERY_METHOD_NAME_PATTERN.test('Bank Transfer')).toBe(false);
  });

  it('returns nothing for an absent field', () => {
    expect(validateDeliveryMethods(undefined, 'sell')).toEqual({ methods: [], issues: [] });
  });

  it('rejects a non-array declaration', () => {
    const { issues } = validateDeliveryMethods('bank', 'sell');
    expect(issues[0]?.message).toContain('not an array');
  });

  it('requires an object, a valid name and a description', () => {
    const { methods, issues } = validateDeliveryMethods(
      [null, {}, { name: 'Bank Transfer' }, { name: 'bank_transfer' }],
      'buy',
      USDC,
    );
    expect(methods.map((method) => method.name)).toEqual(['Bank Transfer', 'bank_transfer']);
    const messages = issues.map((issue) => issue.message);
    expect(messages).toContain('buy_delivery_methods[0] is not an object');
    expect(messages).toContain('buy_delivery_methods[1].name is missing');
    expect(messages.some((message) => message.includes('not a lowercase identifier'))).toBe(true);
    expect(messages.some((message) => message.includes('has no description'))).toBe(true);
    expect(issues[0]?.asset).toBe(USDC);
  });

  it('rejects duplicates and keeps the first declaration', () => {
    const { methods, issues } = validateDeliveryMethods(
      [
        { name: 'bank_transfer', description: 'First' },
        { name: 'bank_transfer', description: 'Second' },
      ],
      'sell',
    );
    expect(methods).toEqual([{ name: 'bank_transfer', description: 'First' }]);
    expect(issues.map((issue) => issue.code)).toEqual(['sep38/delivery-method-duplicate']);
  });
});

describe('fee breakdown helpers', () => {
  it('counts delivery entries by name or description', () => {
    expect(
      countDeliveryFeeItems(
        {
          details: [
            { name: 'delivery_fee', amount: '1' },
            { name: 'platform', description: 'Delivery handling', amount: '1' },
            { name: 'bank_transfer', amount: '1' },
            { name: 'spread', amount: '1' },
          ],
        },
        'bank_transfer',
      ),
    ).toEqual({ details: 4, delivery: 3 });
    expect(countDeliveryFeeItems({}, 'x')).toEqual({ details: 0, delivery: 0 });
  });

  it('validates a SEP-38 fee object', () => {
    expect(isValidFee({ total: '1.00', asset: USDC })).toBe(true);
    expect(isValidFee({ total: 'x', asset: USDC })).toBe(false);
    expect(isValidFee({ total: '1.00' })).toBe(false);
    expect(isValidFee(undefined)).toBe(false);
  });

  it('registers unique rule ids', () => {
    expect(new Set(sep38DeliveryRuleIds).size).toBe(sep38DeliveryRuleIds.length);
    expect(sep38DeliveryRules).toHaveLength(sep38DeliveryRuleIds.length);
  });
});

describe('Sep38DeliveryMethodVerifier', () => {
  it('passes when every method is documented and its fee itemised', async () => {
    const { fetchImpl, calls } = mockServer();
    const result = await new Sep38DeliveryMethodVerifier(fetchImpl).audit(DOC);

    expect(result.diagnostics).toEqual([]);
    expect(result.report.ok).toBe(true);
    expect(result.report.assets).toBe(2);
    expect(result.report.methods).toBe(2);
    expect(result.report.probes).toHaveLength(2);
    expect(result.report.probes.every((probe) => probe.transparent)).toBe(true);
    expect(calls).toEqual(['GET /info', 'POST /quote', 'POST /quote']);
    expect(renderSep38DeliveryReport(result.report)).toContain('PASS');
  });

  it('flags missing descriptions and invalid names', async () => {
    const result = await audit({
      info: {
        assets: [
          {
            asset: USDC,
            sell_delivery_methods: [{ name: 'BANK' }, { name: 'mobile_money', description: '' }],
          },
        ],
      },
    });
    expect(result.diagnostics.map((d) => d.rule)).toContain('sep38/delivery-method-invalid');
    expect(result.report.ok).toBe(false);
  });

  it('flags a missing transfer server', async () => {
    const { fetchImpl } = mockServer();
    const result = await verifySep38DeliveryMethods({}, fetchImpl);
    expect(result.diagnostics[0]?.rule).toBe('sep38/delivery-unverifiable');
  });

  it('reports a failed or malformed info response', async () => {
    const failed = await audit({ infoStatus: 500 });
    expect(failed.diagnostics[0]?.message).toContain('HTTP 500');

    const malformed = await audit({ info: 'nope' });
    expect(malformed.diagnostics[0]?.rule).toBe('sep38/delivery-unverifiable');

    const empty = await audit({ info: { assets: [] } });
    expect(empty.diagnostics[0]?.message).toContain('no assets');
  });

  it('reports an unreachable info endpoint', async () => {
    const fetchImpl = (async () => {
      throw new Error('ECONNREFUSED');
    }) as unknown as typeof fetch;
    const result = await verifySep38DeliveryMethods(DOC, fetchImpl);
    expect(result.diagnostics[0]?.rule).toBe('sep38/delivery-unverifiable');
  });

  it('flags a quote that does not itemise the delivery fee', async () => {
    const result = await audit({
      quoteFee: { total: '0.10', asset: USDC, details: [{ name: 'spread', amount: '0.10' }] },
    });
    expect(result.diagnostics.map((d) => d.rule)).toContain('sep38/delivery-fee-breakdown-missing');
  });

  it('flags a quote with no fee details at all', async () => {
    const result = await audit({ quoteFee: { total: '0.10', asset: USDC } });
    expect(result.diagnostics.map((d) => d.rule)).toContain('sep38/delivery-fee-breakdown-missing');
  });

  it('warns when the quote server rejects a delivery-method quote', async () => {
    const result = await audit({ quoteStatus: 400 });
    expect(result.diagnostics.map((d) => d.rule)).toContain('sep38/delivery-fee-missing');
    expect(result.diagnostics[0]?.severity).toBe('warning');
    expect(result.report.ok).toBe(false);
  });

  it('warns when the quote request fails at the transport layer', async () => {
    const result = await audit({ throwOnQuote: true });
    expect(result.diagnostics.map((d) => d.rule)).toContain('sep38/delivery-fee-missing');
    expect(result.report.probes[0]?.status).toBeUndefined();
  });

  it('skips quote booking when asked', async () => {
    const result = await audit({}, { checkQuotes: false });
    expect(result.report.probes).toEqual([]);
    expect(result.diagnostics).toEqual([]);
    expect(result.report.ok).toBe(true);
  });

  it('honours severity overrides', async () => {
    const result = await audit(
      { quoteFee: { total: '0.10', asset: USDC } },
      { rules: { 'sep38/delivery-fee-breakdown-missing': 'off' } },
    );
    expect(result.diagnostics).toEqual([]);
  });
});
