import { describe, expect, it } from 'vitest';
import {
  verifySep6Integration,
  DEPOSIT_PARAMETER_MISMATCH_RULE,
  FEE_CALCULATION_MISMATCH_RULE,
  INVALID_TRANSACTION_STATUS_RULE,
} from '../../src/protocols/sep6.js';

describe('SEP-6 programmatic integration tester', () => {
  const transferServer = 'https://api.example.com/sep6';
  const doc = {
    TRANSFER_SERVER: transferServer,
  };

  const validInfo = {
    deposit: {
      USDC: {
        enabled: true,
        fee_fixed: 5,
        fee_percent: 1,
        min_amount: 1,
        max_amount: 1000,
      },
    },
    withdraw: {
      USDC: {
        enabled: true,
        fee_fixed: 5,
        fee_percent: 1,
        types: {
          bank_account: {},
        },
      },
    },
  };

  it('passes cleanly when mock server adheres to SEP-6 specs', async () => {
    const fetchImpl = (async (url: string | URL | Request) => {
      const urlStr = String(url);
      if (urlStr.endsWith('/info')) {
        return new Response(JSON.stringify(validInfo), { status: 200 });
      }
      if (urlStr.includes('/deposit')) {
        return new Response(
          JSON.stringify({
            how: 'Send bank transfer to Account #12345',
            id: 'tx_deposit_001',
            eta: 3600,
          }),
          { status: 200 },
        );
      }
      if (urlStr.includes('/withdraw')) {
        return new Response(
          JSON.stringify({
            account_id: 'GAHK7EEG2WWHVKDNT4CEQFZGKF2LGDSBRTC4TQBXXK2ZBDUFLYWWDZDT',
            memo_type: 'id',
            memo: '123456',
            id: 'tx_withdraw_001',
          }),
          { status: 200 },
        );
      }
      if (urlStr.includes('/fee')) {
        // 5 fixed + (100 * 1%) = 6
        return new Response(JSON.stringify({ fee: 6 }), { status: 200 });
      }
      if (urlStr.includes('/transaction')) {
        return new Response(
          JSON.stringify({
            transaction: {
              id: 'tx_deposit_001',
              status: 'completed',
              amount_in: '100',
              amount_out: '94',
            },
          }),
          { status: 200 },
        );
      }
      return new Response(JSON.stringify({ error: 'Not found' }), { status: 404 });
    }) as unknown as typeof fetch;

    const diagnostics = await verifySep6Integration(doc, fetchImpl);
    expect(diagnostics).toEqual([]);
  });

  it('asserts sep6/fee-calculation-mismatch when server fails fee calculations', async () => {
    const fetchImpl = (async (url: string | URL | Request) => {
      const urlStr = String(url);
      if (urlStr.endsWith('/info')) {
        return new Response(JSON.stringify(validInfo), { status: 200 });
      }
      if (urlStr.includes('/deposit')) {
        return new Response(JSON.stringify({ how: 'Wire', id: '1' }), { status: 200 });
      }
      if (urlStr.includes('/withdraw')) {
        return new Response(JSON.stringify({ account_id: 'G...', id: '1' }), { status: 200 });
      }
      if (urlStr.includes('/fee')) {
        // Expected fee is 6, but server returns 15
        return new Response(JSON.stringify({ fee: 15 }), { status: 200 });
      }
      if (urlStr.includes('/transaction')) {
        return new Response(JSON.stringify({ transaction: { status: 'completed' } }), {
          status: 200,
        });
      }
      return new Response(JSON.stringify({}), { status: 200 });
    }) as unknown as typeof fetch;

    const diagnostics = await verifySep6Integration(doc, fetchImpl);
    expect(diagnostics.some((d) => d.rule === FEE_CALCULATION_MISMATCH_RULE)).toBe(true);
    expect(diagnostics[0]?.severity).toBe('warning');
  });

  it('asserts sep6/invalid-transaction-status when unknown status is returned', async () => {
    const fetchImpl = (async (url: string | URL | Request) => {
      const urlStr = String(url);
      if (urlStr.endsWith('/info')) {
        return new Response(JSON.stringify(validInfo), { status: 200 });
      }
      if (urlStr.includes('/fee')) {
        return new Response(JSON.stringify({ fee: 6 }), { status: 200 });
      }
      if (urlStr.includes('/transaction')) {
        return new Response(
          JSON.stringify({ transaction: { status: 'invalid_unrecognized_status' } }),
          {
            status: 200,
          },
        );
      }
      return new Response(JSON.stringify({ how: 'ok', id: '1' }), { status: 200 });
    }) as unknown as typeof fetch;

    const diagnostics = await verifySep6Integration(doc, fetchImpl);
    expect(diagnostics.some((d) => d.rule === INVALID_TRANSACTION_STATUS_RULE)).toBe(true);
    expect(diagnostics[0]?.severity).toBe('error');
  });

  it('asserts sep6/deposit-parameter-mismatch when deposit parameter validation fails', async () => {
    const fetchImpl = (async (url: string | URL | Request) => {
      const urlStr = String(url);
      if (urlStr.endsWith('/info')) {
        return new Response(JSON.stringify(validInfo), { status: 200 });
      }
      if (urlStr.includes('/deposit')) {
        return new Response(JSON.stringify({ error: 'asset_code is required' }), { status: 400 });
      }
      return new Response(JSON.stringify({}), { status: 200 });
    }) as unknown as typeof fetch;

    const diagnostics = await verifySep6Integration(doc, fetchImpl);
    expect(diagnostics.some((d) => d.rule === DEPOSIT_PARAMETER_MISMATCH_RULE)).toBe(true);
    expect(diagnostics[0]?.severity).toBe('error');
  });
});
