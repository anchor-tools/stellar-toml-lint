import { describe, expect, it } from 'vitest';
import {
  verifySep24,
  sep24Rules,
  INFO_ENDPOINT_UNREACHABLE_RULE,
  CURRENCY_NOT_SUPPORTED_IN_INFO_RULE,
  INVALID_FEE_SCHEMA_RULE,
  INTERACTIVE_URL_INSECURE_RULE,
} from '../../src/protocols/sep24.js';

const TRANSFER_SERVER_SEP0024 = 'https://api.example.com/sep24';
const ISSUER_A = 'GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY';
const ISSUER_B = 'GAHK7EEG2WWHVKDNT4CEQFZGKF2LGDSBRTC4TQBXXK2ZBDUFLYWWDZDT';

const DOC = {
  TRANSFER_SERVER_SEP0024,
  CURRENCIES: [
    { code: 'USDX', issuer: ISSUER_A, is_asset_anchored: true },
    { code: 'EURX', issuer: ISSUER_B, is_asset_anchored: true },
  ],
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function validInfo(): Response {
  return jsonResponse({
    deposit: {
      USDX: { enabled: true, min_amount: 1, max_amount: 1_000_000, fee_fixed: 1, fee_percent: 0.5 },
      EURX: { enabled: true, min_amount: 1, max_amount: 1_000_000, fee_fixed: 1, fee_percent: 0.5 },
    },
    withdraw: {
      USDX: { enabled: true, min_amount: 1, max_amount: 1_000_000, fee_fixed: 1, fee_percent: 0.5 },
      EURX: { enabled: true, min_amount: 1, max_amount: 1_000_000, fee_fixed: 1, fee_percent: 0.5 },
    },
    fee: { enabled: true },
    features: { account_creation: true, claimable_balances: true },
  });
}

function validInteractive(): Response {
  return jsonResponse(
    { id: 'itxn_sep24_001', url: 'https://sep24.example.com/deposit/itxn_sep24_001' },
    201,
  );
}

interface Routes {
  info?: () => Response;
  interactive?: () => Response;
}

/** A path-routed fetch stub standing in for the anchor's SEP-24 transfer server. */
function fetchServer(routes: Routes): typeof fetch {
  return (async (input: unknown, init?: RequestInit) => {
    const url = new URL(String(input));
    void init;

    if (url.pathname.endsWith('/info')) {
      return (routes.info ?? validInfo)();
    }

    if (url.pathname.includes('/transactions/deposit/interactive')) {
      return (routes.interactive ?? validInteractive)();
    }

    throw new Error(`unexpected request to ${url}`);
  }) as unknown as typeof fetch;
}

describe('SEP-24 hosted deposit and withdrawal flow validator', () => {
  it('passes cleanly when the mock server returns valid info and an HTTPS interactive url', async () => {
    const diagnostics = await verifySep24(DOC, fetchServer({}));

    expect(diagnostics).toEqual([]);
  });

  it('stays silent when the file declares no usable transfer server', async () => {
    expect(await verifySep24({ CURRENCIES: DOC.CURRENCIES }, fetchServer({}))).toEqual([]);
    expect(await verifySep24({ TRANSFER_SERVER_SEP0024: 'not a url' }, fetchServer({}))).toEqual(
      [],
    );
  });

  it('falls back to TRANSFER_SERVER when TRANSFER_SERVER_SEP0024 is absent', async () => {
    const diagnostics = await verifySep24(
      {
        TRANSFER_SERVER: 'https://api.example.com/sep6',
        CURRENCIES: DOC.CURRENCIES,
      },
      fetchServer({}),
    );

    expect(diagnostics).toEqual([]);
  });

  it('asserts sep24/currency-not-supported-in-info when an anchored currency is missing from /info', async () => {
    const diagnostics = await verifySep24(
      DOC,
      fetchServer({
        info: () =>
          jsonResponse({
            deposit: { USDX: { enabled: true, min_amount: 1, max_amount: 1000 } },
            withdraw: { USDX: { enabled: true, min_amount: 1, max_amount: 1000 } },
            fee: { enabled: true },
          }),
      }),
    );

    const missing = diagnostics.filter((d) => d.rule === CURRENCY_NOT_SUPPORTED_IN_INFO_RULE);
    expect(missing).toHaveLength(1);
    expect(missing[0]?.severity).toBe('warning');
    expect(missing[0]?.message).toContain('EURX');
    expect(missing[0]?.path).toBe('CURRENCIES');
  });

  it('asserts sep24/invalid-fee-schema when a fee field is non-numeric', async () => {
    const diagnostics = await verifySep24(
      DOC,
      fetchServer({
        info: () =>
          jsonResponse({
            deposit: {
              USDX: { enabled: true, min_amount: 1, max_amount: 1000, fee: { fixed: 'abc' } },
              EURX: { enabled: true, min_amount: 1, max_amount: 1000 },
            },
            withdraw: {
              USDX: { enabled: true, min_amount: 1, max_amount: 1000 },
              EURX: { enabled: true, min_amount: 1, max_amount: 1000 },
            },
            fee: { enabled: true },
          }),
      }),
    );

    const invalid = diagnostics.filter((d) => d.rule === INVALID_FEE_SCHEMA_RULE);
    expect(invalid).toHaveLength(1);
    expect(invalid[0]?.severity).toBe('error');
    expect(invalid[0]?.message).toContain('fee.fixed');
    expect(invalid[0]?.message).toContain('"abc"');
  });

  it('asserts sep24/interactive-url-insecure when the interactive url is not HTTPS', async () => {
    const diagnostics = await verifySep24(
      DOC,
      fetchServer({
        interactive: () =>
          jsonResponse({ id: 'itxn_sep24_001', url: 'http://sep24.example.com/deposit/itxn' }, 201),
      }),
    );

    const insecure = diagnostics.filter((d) => d.rule === INTERACTIVE_URL_INSECURE_RULE);
    expect(insecure).toHaveLength(1);
    expect(insecure[0]?.severity).toBe('error');
    expect(insecure[0]?.message).toContain('http://');
  });

  it('asserts sep24/info-endpoint-unreachable as a warning when /info throws', async () => {
    const diagnostics = await verifySep24(
      DOC,
      fetchServer({
        info: () => {
          throw new Error('ECONNREFUSED');
        },
      }),
    );

    const unreachable = diagnostics.filter((d) => d.rule === INFO_ENDPOINT_UNREACHABLE_RULE);
    expect(unreachable).toHaveLength(1);
    expect(unreachable[0]?.severity).toBe('warning');
    expect(unreachable[0]?.message).toContain('Could not reach');
  });

  it('asserts sep24/info-endpoint-unreachable as a warning when /info returns 500', async () => {
    const diagnostics = await verifySep24(
      DOC,
      fetchServer({
        info: () => jsonResponse({ error: 'internal' }, 500),
      }),
    );

    const unreachable = diagnostics.filter((d) => d.rule === INFO_ENDPOINT_UNREACHABLE_RULE);
    expect(unreachable).toHaveLength(1);
    expect(unreachable[0]?.severity).toBe('warning');
    expect(unreachable[0]?.message).toContain('HTTP 500');
  });

  it('honours --off by silencing a rule', async () => {
    const brokenFees = fetchServer({
      info: () =>
        jsonResponse({
          deposit: {
            USDX: { enabled: true, min_amount: 1, max_amount: 1000, fee_fixed: 'nope' },
            EURX: { enabled: true, min_amount: 1, max_amount: 1000 },
          },
          withdraw: {
            USDX: { enabled: true, min_amount: 1, max_amount: 1000 },
            EURX: { enabled: true, min_amount: 1, max_amount: 1000 },
          },
          fee: { enabled: true },
        }),
    });

    const silenced = await verifySep24(DOC, brokenFees, {
      rules: { [INVALID_FEE_SCHEMA_RULE]: 'off' },
    });
    expect(silenced.filter((d) => d.rule === INVALID_FEE_SCHEMA_RULE)).toEqual([]);

    const raised = await verifySep24(DOC, brokenFees, {
      rules: { [INVALID_FEE_SCHEMA_RULE]: 'warning' },
    });
    expect(raised.find((d) => d.rule === INVALID_FEE_SCHEMA_RULE)?.severity).toBe('warning');
  });
});

describe('sep24Rules', () => {
  it('registers the ids and severities the engine emits', () => {
    const byId = new Map(sep24Rules.map((rule) => [rule.id, rule]));

    expect([...byId.keys()].sort()).toEqual(
      [
        INFO_ENDPOINT_UNREACHABLE_RULE,
        CURRENCY_NOT_SUPPORTED_IN_INFO_RULE,
        INVALID_FEE_SCHEMA_RULE,
        INTERACTIVE_URL_INSECURE_RULE,
      ].sort(),
    );
    expect(byId.get(INFO_ENDPOINT_UNREACHABLE_RULE)?.severity).toBe('error');
    expect(byId.get(CURRENCY_NOT_SUPPORTED_IN_INFO_RULE)?.severity).toBe('warning');
    expect(byId.get(INVALID_FEE_SCHEMA_RULE)?.severity).toBe('error');
    expect(byId.get(INTERACTIVE_URL_INSECURE_RULE)?.severity).toBe('error');
    for (const rule of sep24Rules) expect(rule.category).toBe('network');
  });
});
