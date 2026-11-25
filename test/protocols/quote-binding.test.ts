import { describe, expect, it } from 'vitest';
import {
  auditQuoteBinding,
  quoteBindingRuleIds,
  quoteBindingRules,
} from '../../src/protocols/quote-binding-auditor.js';

const ANCHOR_QUOTE_SERVER = 'https://quote.example.com/sep38';
const TRANSFER_SERVER = 'https://transfer.example.com/sep6';
const ISSUER = 'GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY';

/** Expiry far enough out that the audit window never closes mid-test. */
const QUOTE_EXPIRY = '2031-01-01T00:00:00.000Z';

const DOC = {
  ANCHOR_QUOTE_SERVER,
  TRANSFER_SERVER,
  CURRENCIES: [{ code: 'USDX', issuer: ISSUER }],
};

/** A SEP-38 firm quote: one unit of fee, priced at 1.20. */
function quoteBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'q-1',
    price: '1.20',
    sell_amount: '100.00',
    buy_amount: '120.00',
    total: '120.00',
    fees: [{ amount: '1.00', type: 'sell' }],
    expire_after: QUOTE_EXPIRY,
    ...overrides,
  };
}

/** A SEP-6 deposit that honours that quote exactly. */
function depositBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'd-1',
    price: '1.20',
    total_fee: '1.00',
    expires_at: QUOTE_EXPIRY,
    ...overrides,
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

/** Routes `POST /quote` and `GET /deposit` so each step can diverge on its own. */
function anchorServer(
  routes: { quote?: () => Response; deposit?: () => Response } = {},
): typeof fetch {
  return (async (input: string | URL | Request) => {
    const url = String(input);
    if (url.includes('/quote')) {
      if (routes.quote) return routes.quote();
      return jsonResponse(quoteBody());
    }
    if (url.includes('/deposit')) {
      if (routes.deposit) return routes.deposit();
      return jsonResponse(depositBody());
    }
    throw new Error(`unexpected request to ${url}`);
  }) as unknown as typeof fetch;
}

function audit(
  doc: Record<string, unknown>,
  routes: { quote?: () => Response; deposit?: () => Response } = {},
) {
  return auditQuoteBinding(doc, anchorServer(routes));
}

describe('auditQuoteBinding', () => {
  it('registers both required rule ids', () => {
    expect(quoteBindingRuleIds).toEqual([
      'quotes/mismatched-quote-fee',
      'quotes/quote-binding-unsupported',
    ]);
  });

  it('registers the divergence as an error and the unsupported binding as a warning', () => {
    expect(quoteBindingRules.map((rule) => ({ id: rule.id, severity: rule.severity }))).toEqual([
      { id: 'quotes/mismatched-quote-fee', severity: 'error' },
      { id: 'quotes/quote-binding-unsupported', severity: 'warning' },
    ]);
  });

  it('passes when the deposit honours the quote and its fee breakdown', async () => {
    expect(await audit(DOC)).toEqual([]);
  });

  it('binds the booked quote_id into the SEP-6 deposit request', async () => {
    const requested: string[] = [];
    await auditQuoteBinding(DOC, (async (input: string | URL | Request) => {
      const url = String(input);
      requested.push(url);
      return anchorServer()(input);
    }) as unknown as typeof fetch);

    const deposit = requested.find((url) => url.includes('/deposit'));
    expect(deposit).toBeDefined();
    const params = new URLSearchParams(new URL(deposit ?? '').search);
    expect(params.get('quote_id')).toBe('q-1');
    expect(params.get('asset_code')).toBe('USDX');
  });

  it('reports quotes/mismatched-quote-fee when total_fee diverges from the quoted fees', async () => {
    const diagnostics = await audit(DOC, {
      deposit: () => jsonResponse(depositBody({ total_fee: '2.50' })),
    });

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.rule).toBe('quotes/mismatched-quote-fee');
    expect(diagnostics[0]?.severity).toBe('error');
    expect(diagnostics[0]?.message).toContain('2.5');
    expect(diagnostics[0]?.message).toContain('1');
  });

  it('reports quotes/mismatched-quote-fee when the deposit re-prices the trade', async () => {
    const diagnostics = await audit(DOC, {
      deposit: () => jsonResponse(depositBody({ price: '1.31' })),
    });

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.rule).toBe('quotes/mismatched-quote-fee');
    expect(diagnostics[0]?.message).toContain('1.31');
  });

  it('reports quotes/mismatched-quote-fee when execution expires before the quoted expiry', async () => {
    const diagnostics = await audit(DOC, {
      deposit: () => jsonResponse(depositBody({ expires_at: '2030-01-01T00:00:00.000Z' })),
    });

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.rule).toBe('quotes/mismatched-quote-fee');
    expect(diagnostics[0]?.message).toContain('earlier than the quoted');
  });

  it('reports quotes/quote-binding-unsupported when /deposit rejects the quote_id', async () => {
    const diagnostics = await audit(DOC, {
      deposit: () => jsonResponse({ error: 'quote_id is not supported' }, 400),
    });

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.rule).toBe('quotes/quote-binding-unsupported');
    expect(diagnostics[0]?.severity).toBe('warning');
  });

  it('stays silent when /deposit fails for a reason unrelated to the quote', async () => {
    const diagnostics = await audit(DOC, {
      deposit: () => jsonResponse({ error: 'asset not supported' }, 400),
    });

    expect(diagnostics).toEqual([]);
  });

  it('stays silent when the quote cannot be booked', async () => {
    expect(await audit(DOC, { quote: () => jsonResponse({ error: 'boom' }, 500) })).toEqual([]);
  });

  it('stays silent when a file declares only one of the two servers', async () => {
    expect(
      await auditQuoteBinding(
        { TRANSFER_SERVER, CURRENCIES: [{ code: 'USDX', issuer: ISSUER }] },
        anchorServer(),
      ),
    ).toEqual([]);
    expect(
      await auditQuoteBinding(
        { ANCHOR_QUOTE_SERVER, CURRENCIES: [{ code: 'USDX', issuer: ISSUER }] },
        anchorServer(),
      ),
    ).toEqual([]);
  });

  it('stays silent when the file declares no classic asset to sell', async () => {
    const contractOnly = {
      ANCHOR_QUOTE_SERVER,
      TRANSFER_SERVER,
      CURRENCIES: [
        { code: 'USDX', contract: 'CAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY' },
      ],
    };

    expect(await audit(contractOnly)).toEqual([]);
  });

  it('stays silent when an endpoint cannot be reached', async () => {
    const unreachable = (async () => {
      throw new Error('ECONNREFUSED');
    }) as unknown as typeof fetch;

    expect(await auditQuoteBinding(DOC, unreachable)).toEqual([]);
  });

  it('honours rule overrides', async () => {
    const diagnostics = await auditQuoteBinding(
      DOC,
      anchorServer({ deposit: () => jsonResponse(depositBody({ total_fee: '9.00' })) }),
      { rules: { 'quotes/mismatched-quote-fee': 'off' } },
    );

    expect(diagnostics).toEqual([]);
  });

  it('sums every declared fee line before comparing totals', async () => {
    const diagnostics = await audit(DOC, {
      quote: () =>
        jsonResponse(
          quoteBody({
            fees: [
              { amount: '0.50', type: 'sell' },
              { amount: '0.50', type: 'send' },
            ],
          }),
        ),
      deposit: () => jsonResponse(depositBody({ total_fee: '0.50' })),
    });

    expect(diagnostics[0]?.rule).toBe('quotes/mismatched-quote-fee');
    expect(diagnostics[0]?.message).toContain('0.5');
  });
});
