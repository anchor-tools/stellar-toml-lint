import { StrKey } from '@stellar/stellar-base';
import { describe, expect, it } from 'vitest';
import {
  Sep24RefundAuditor,
  auditSep24Refunds,
  matchHorizonPayment,
  parseRefundRecord,
  renderSep24RefundReport,
  sep24RefundRuleIds,
  sep24RefundRules,
} from '../src/protocols/sep24RefundAuditor.js';

const BUYER = StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 1));
const OTHER = StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 2));
const ISSUER = StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 3));
const HASH = 'a'.repeat(64);
const TOKEN = 'header.payload.signature';
const DOC = { TRANSFER_SERVER_SEP0024: 'https://anchor.test/sep24' };

function deposit(refunds: unknown = undefined) {
  return {
    id: 'tx-1',
    status: 'error',
    from: BUYER,
    asset_code: 'USDC',
    deposit_memo: '12345',
    deposit_memo_type: 'text',
    ...(refunds === undefined
      ? {}
      : {
          refunds:
            refunds === 'default'
              ? {
                  amount_refunded: '10.00',
                  amount_fee: '0.50',
                  payments: [{ id: HASH, id_type: 'stellar', amount: '9.50', fee: '0.50' }],
                }
              : refunds,
        }),
  };
}

interface ServerOptions {
  transaction?: unknown;
  transactionStatus?: number;
  horizonTx?: unknown;
  horizonStatus?: number;
  payments?: unknown;
  paymentsStatus?: number;
}

function mockServer(options: ServerOptions = {}) {
  const calls: string[] = [];
  const fetchImpl = (async (input: string | URL | Request) => {
    const url = new URL(String(input));
    calls.push(url.pathname + url.search);
    if (url.pathname === '/sep24/transaction') {
      const status = options.transactionStatus ?? 200;
      if (status >= 400) return new Response('no', { status });
      return Response.json(options.transaction ?? { transaction: deposit('default') });
    }
    if (url.pathname === `/transactions/${HASH}`) {
      const status = options.horizonStatus ?? 200;
      if (status >= 400) return new Response('missing', { status });
      return Response.json(
        options.horizonTx ?? { hash: HASH, successful: true, memo: '12345', memo_type: 'text' },
      );
    }
    if (url.pathname === `/transactions/${HASH}/payments`) {
      const status = options.paymentsStatus ?? 200;
      if (status >= 400) return new Response('missing', { status });
      return Response.json(
        options.payments ?? {
          _embedded: {
            records: [
              {
                type: 'payment',
                to: BUYER,
                asset_code: 'USDC',
                asset_issuer: ISSUER,
                amount: '9.50',
              },
            ],
          },
        },
      );
    }
    return new Response('not found', { status: 404 });
  }) as unknown as typeof fetch;
  return { fetchImpl, calls };
}

const audit = (server: ServerOptions, options: Record<string, unknown> = {}) =>
  new Sep24RefundAuditor(mockServer(server).fetchImpl, {
    transactionId: 'tx-1',
    token: TOKEN,
    horizonUrl: 'https://horizon.test',
    ...options,
  }).audit(DOC);

describe('parseRefundRecord', () => {
  it('accepts a complete refund record', () => {
    const { record, issues } = parseRefundRecord({
      amount_refunded: '10.00',
      amount_fee: '0.50',
      payments: [{ id: HASH, id_type: 'stellar', amount: '9.50', fee: '0.50' }],
    });
    expect(issues).toEqual([]);
    expect(record?.payments).toEqual([
      { id: HASH, idType: 'stellar', amount: '9.50', fee: '0.50' },
    ]);
  });

  it('reports a missing or non-object refunds field', () => {
    expect(parseRefundRecord(undefined).issues[0]?.code).toBe('sep24/refund-schema-invalid');
    expect(parseRefundRecord([]).issues[0]?.code).toBe('sep24/refund-schema-invalid');
  });

  it('reports missing and malformed amounts, payments and ids', () => {
    const { issues } = parseRefundRecord({
      amount_refunded: 'ten',
      payments: [null, { amount: '1.00' }, { id: HASH, amount: 'x' }],
    });
    const messages = issues.map((issue) => issue.message);
    expect(messages).toContain('refunds.amount_fee is missing');
    expect(messages).toContain('refunds.amount_refunded is not a decimal amount');
    expect(messages).toContain('refunds.payments[0] is not an object');
    expect(messages).toContain('refunds.payments[1].id is missing');
    expect(messages).toContain('refunds.payments[2].amount is not a decimal amount');
  });

  it('flags an empty payments array and non-array payments', () => {
    expect(parseRefundRecord({ payments: [] }).issues.map((issue) => issue.code)).toContain(
      'sep24/refund-missing-payment',
    );
    expect(parseRefundRecord({ payments: 'nope' }).issues.map((issue) => issue.code)).toContain(
      'sep24/refund-schema-invalid',
    );
  });

  it('flags a fee larger than the refunded amount', () => {
    const { issues } = parseRefundRecord({
      amount_refunded: '1.00',
      amount_fee: '2.00',
      payments: [{ id: HASH }],
    });
    expect(issues.map((issue) => issue.code)).toContain('sep24/refund-fee-exceeds-amount');
  });
});

describe('matchHorizonPayment', () => {
  it('matches destination, asset and memo', () => {
    const match = matchHorizonPayment(
      { to: BUYER, asset_code: 'USDC', memo: '12345' },
      { sender: BUYER, assetCode: 'usdc', memo: '12345' },
    );
    expect(match.matched).toBe(true);
  });

  it('treats native payments as XLM', () => {
    const match = matchHorizonPayment(
      { to: OTHER, asset_type: 'native' },
      { sender: OTHER, assetCode: 'XLM' },
    );
    expect(match.assetCode).toBe('XLM');
    expect(match.matched).toBe(true);
  });

  it('rejects a different destination, asset or memo', () => {
    expect(matchHorizonPayment({ to: OTHER }, { sender: BUYER }).matched).toBe(false);
    expect(
      matchHorizonPayment({ to: BUYER, asset_code: 'EURC' }, { sender: BUYER, assetCode: 'USDC' })
        .matched,
    ).toBe(false);
    expect(
      matchHorizonPayment({ to: BUYER, memo: '999' }, { sender: BUYER, memo: '12345' }).matched,
    ).toBe(false);
  });

  it('registers unique rule ids', () => {
    expect(new Set(sep24RefundRuleIds).size).toBe(sep24RefundRuleIds.length);
    expect(sep24RefundRules).toHaveLength(sep24RefundRuleIds.length);
  });
});

describe('Sep24RefundAuditor', () => {
  it('passes a refund that matches the original deposit on-chain', async () => {
    const result = await audit({});
    expect(result.diagnostics).toEqual([]);
    expect(result.report.ok).toBe(true);
    expect(result.report.payments[0]).toMatchObject({
      id: HASH,
      found: true,
      successful: true,
      destination: BUYER,
      matched: true,
    });
    expect(renderSep24RefundReport(result.report)).toContain('PASS');
  });

  it('accepts an unwrapped transaction body', async () => {
    const result = await audit({ transaction: deposit('default') });
    expect(result.report.ok).toBe(true);
  });

  it('flags schema problems in the refunds object', async () => {
    const result = await audit({
      transaction: { transaction: deposit({ amount_refunded: 'ten', payments: [] }) },
    });
    const codes = result.diagnostics.map((d) => d.rule);
    expect(codes).toContain('sep24/refund-schema-invalid');
    expect(codes).toContain('sep24/refund-missing-payment');
  });

  it('flags a refund transaction that Horizon does not know', async () => {
    const result = await audit({ horizonStatus: 404 });
    expect(result.diagnostics.map((d) => d.rule)).toContain('sep24/refund-transaction-not-found');
  });

  it('flags a failed refund transaction', async () => {
    const result = await audit({
      horizonTx: { hash: HASH, successful: false, memo: '12345' },
    });
    expect(result.diagnostics.map((d) => d.rule)).toContain('sep24/refund-transaction-failed');
  });

  it('flags a refund paid to the wrong account', async () => {
    const result = await audit({
      payments: { _embedded: { records: [{ type: 'payment', to: OTHER }] } },
    });
    expect(result.diagnostics.map((d) => d.rule)).toContain('sep24/refund-destination-mismatch');
  });

  it('flags a refund paid in the wrong asset', async () => {
    const result = await audit({
      payments: {
        _embedded: { records: [{ type: 'payment', to: BUYER, asset_code: 'EURC' }] },
      },
    });
    expect(result.diagnostics.map((d) => d.rule)).toContain('sep24/refund-asset-mismatch');
  });

  it('flags a refund memo that does not match the deposit memo', async () => {
    const result = await audit({
      horizonTx: { hash: HASH, successful: true, memo: '999', memo_type: 'text' },
    });
    expect(result.diagnostics.map((d) => d.rule)).toContain('sep24/refund-memo-mismatch');
  });

  it('flags a refund with no matching payment record', async () => {
    const result = await audit({
      payments: { _embedded: { records: [{ type: 'payment', to: OTHER }] } },
    });
    expect(result.report.payments[0]?.matched).toBe(false);
    expect(result.report.ok).toBe(false);
  });

  it('tolerates a payments endpoint that fails', async () => {
    const result = await audit({ paymentsStatus: 404 });
    expect(result.report.payments[0]?.found).toBe(true);
    expect(result.report.payments[0]?.matched).toBe(false);
    expect(result.report.ok).toBe(false);
  });

  it('reports missing configuration as unverifiable', async () => {
    const { fetchImpl } = mockServer();
    const noDomain = await auditSep24Refunds({}, fetchImpl, {
      transactionId: 'tx-1',
      token: TOKEN,
    });
    expect(noDomain.diagnostics[0]?.rule).toBe('sep24/refund-unverifiable');

    const noId = await auditSep24Refunds(DOC, fetchImpl, { token: TOKEN });
    expect(noId.diagnostics[0]?.rule).toBe('sep24/refund-unverifiable');

    const noToken = await auditSep24Refunds(DOC, fetchImpl, { transactionId: 'tx-1' });
    expect(noToken.diagnostics[0]?.rule).toBe('sep24/refund-unverifiable');
  });

  it('reports a failed transaction lookup', async () => {
    const result = await audit({ transactionStatus: 500 });
    expect(result.diagnostics[0]?.message).toContain('HTTP 500');
  });

  it('reports a non-object transaction body', async () => {
    const result = await audit({ transaction: { transaction: 'nope' } });
    expect(result.diagnostics[0]?.rule).toBe('sep24/refund-unverifiable');
  });

  it('reports a network error as unverifiable', async () => {
    const fetchImpl = (async () => {
      throw new Error('ECONNREFUSED');
    }) as unknown as typeof fetch;
    const result = await auditSep24Refunds(DOC, fetchImpl, {
      transactionId: 'tx-1',
      token: TOKEN,
    });
    expect(result.diagnostics[0]?.rule).toBe('sep24/refund-unverifiable');
  });

  it('reports a network error while checking Horizon as not found', async () => {
    let call = 0;
    const fetchImpl = (async () => {
      call += 1;
      if (call === 1) return Response.json({ transaction: deposit('default') });
      throw new Error('horizon down');
    }) as unknown as typeof fetch;
    const result = await auditSep24Refunds(DOC, fetchImpl, {
      transactionId: 'tx-1',
      token: TOKEN,
      horizonUrl: 'https://horizon.test',
    });
    expect(result.report.payments[0]?.found).toBe(false);
    expect(result.diagnostics.map((d) => d.rule)).toContain('sep24/refund-transaction-not-found');
  });

  it('honours severity overrides', async () => {
    const result = await audit(
      { horizonStatus: 404 },
      { rules: { 'sep24/refund-transaction-not-found': 'off' } },
    );
    expect(result.diagnostics).toEqual([]);
  });
});
