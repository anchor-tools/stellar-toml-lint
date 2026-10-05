import { describe, expect, it } from 'vitest';
import {
  verifySep31,
  ASSET_UNSUPPORTED_RULE,
  INFO_SCHEMA_INVALID_RULE,
  MISSING_KYC_REQUIREMENTS_RULE,
} from '../../src/protocols/sep31.js';

describe('SEP-31 cross-border direct payment auditor', () => {
  const directPaymentServer = 'https://api.example.com/sep31';
  const doc = {
    DIRECT_PAYMENT_SERVER: directPaymentServer,
    CURRENCIES: [
      {
        code: 'USD',
        issuer: 'GAHK7EEG2WWHVKDNT4CEQFZGKF2LGDSBRTC4TQBXXK2ZBDUFLYWWDZDT',
      },
    ],
  };

  const validInfo = {
    receive: {
      USD: {
        enabled: true,
        fee_fixed: 5,
        fee_percent: 1,
        min_amount: 1,
        max_amount: 10000,
        sender_sep12_type: 'sep31-sender',
        receiver_sep12_type: 'sep31-receiver',
        fields: {
          transaction: {
            routing_number: { description: 'routing number' },
            account_number: { description: 'bank account number' },
          },
        },
      },
    },
  };

  it('passes cleanly when mock server adheres to SEP-31 specs', async () => {
    const fetchImpl = (async (url: string | URL | Request) => {
      const urlStr = String(url);
      if (urlStr.endsWith('/info')) {
        return new Response(JSON.stringify(validInfo), { status: 200 });
      }
      if (urlStr.endsWith('/transactions')) {
        return new Response(
          JSON.stringify({
            id: 'tx_31_001',
            status: 'pending_sender',
          }),
          { status: 201 },
        );
      }
      return new Response(JSON.stringify({ error: 'Not found' }), { status: 404 });
    }) as unknown as typeof fetch;

    const diagnostics = await verifySep31(doc, fetchImpl);
    expect(diagnostics).toEqual([]);
  });

  it('asserts sep31/asset-unsupported when declared currency is missing from /info', async () => {
    const fetchImpl = (async (url: string | URL | Request) => {
      const urlStr = String(url);
      if (urlStr.endsWith('/info')) {
        return new Response(
          JSON.stringify({
            receive: {
              EUR: {
                enabled: true,
                sender_sep12_type: 'sep31-sender',
                receiver_sep12_type: 'sep31-receiver',
              },
            },
          }),
          { status: 200 },
        );
      }
      return new Response(JSON.stringify({}), { status: 200 });
    }) as unknown as typeof fetch;

    const diagnostics = await verifySep31(doc, fetchImpl);
    expect(diagnostics.some((d) => d.rule === ASSET_UNSUPPORTED_RULE)).toBe(true);
    expect(diagnostics[0]?.severity).toBe('warning');
  });

  it('asserts sep31/info-schema-invalid when /info response is missing receive mapping', async () => {
    const fetchImpl = (async (url: string | URL | Request) => {
      const urlStr = String(url);
      if (urlStr.endsWith('/info')) {
        return new Response(JSON.stringify({ unsupported_key: {} }), { status: 200 });
      }
      return new Response(JSON.stringify({}), { status: 200 });
    }) as unknown as typeof fetch;

    const diagnostics = await verifySep31(doc, fetchImpl);
    expect(diagnostics.some((d) => d.rule === INFO_SCHEMA_INVALID_RULE)).toBe(true);
    expect(diagnostics[0]?.severity).toBe('error');
  });

  it('asserts sep31/missing-kyc-requirements when KYC types are missing', async () => {
    const fetchImpl = (async (url: string | URL | Request) => {
      const urlStr = String(url);
      if (urlStr.endsWith('/info')) {
        return new Response(
          JSON.stringify({
            receive: {
              USD: {
                enabled: true,
              },
            },
          }),
          { status: 200 },
        );
      }
      return new Response(JSON.stringify({}), { status: 200 });
    }) as unknown as typeof fetch;

    const diagnostics = await verifySep31(doc, fetchImpl);
    expect(diagnostics.some((d) => d.rule === MISSING_KYC_REQUIREMENTS_RULE)).toBe(true);
    expect(diagnostics[0]?.severity).toBe('error');
  });
});
