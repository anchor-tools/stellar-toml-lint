import { describe, expect, it } from 'vitest';
import {
  ClawbackAuditTrailGenerator,
  findClawbackAssets,
  fromStroops,
  hasAuditReference,
  parseAsset,
  renderClawbackJson,
  renderClawbackMarkdown,
  toStroops,
} from '../../src/protocols/clawbackAuditGenerator.js';

const ISSUER = 'GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY';
const HASH = 'a'.repeat(64);
const H = 'https://horizon.test';

const OPS = [
  { id: '1', type: 'payment', transaction_hash: 'tx0' },
  {
    id: '2',
    type: 'clawback',
    asset_code: 'USDX',
    from: 'GFROM',
    amount: '10.0000001',
    created_at: '2025-01-01T00:00:00Z',
    transaction_hash: 'tx1',
  },
  {
    id: '3',
    type: 'clawback',
    asset_code: 'OTHER',
    from: 'GFROM',
    amount: '99.0000000',
    created_at: '2025-01-02T00:00:00Z',
    transaction_hash: 'tx1',
  },
  {
    id: '4',
    type: 'clawback_claimable_balance',
    balance_id: '00ab',
    created_at: '2025-01-03T00:00:00Z',
    transaction_hash: 'tx2',
  },
  {
    id: '5',
    type: 'clawback',
    asset_code: 'USDX',
    from: 'GFROM2',
    amount: '0.0000001',
    created_at: '2025-01-04T00:00:00Z',
    transaction_hash: 'tx3',
  },
];

const TXS: Record<string, unknown> = {
  tx1: { memo_type: 'text', memo: `LEGAL:court-order-${HASH}` },
  tx2: { memo_type: 'none' },
  tx3: { memo_type: 'text', memo: 'oops' },
};

function horizon(ops: unknown[]): typeof fetch {
  return (async (url: string) => {
    if (url.includes('/transactions/')) {
      const body = TXS[url.split('/').pop() as string];
      return new Response(JSON.stringify(body ?? { memo_type: 'none' }), { status: 200 });
    }
    // Second page is empty, which ends pagination.
    const page = url.includes('cursor=2') ? [] : ops;
    return new Response(
      JSON.stringify({
        _embedded: { records: page },
        _links: { next: { href: `${H}/accounts/${ISSUER}/operations?cursor=2` } },
      }),
      { status: 200 },
    );
  }) as unknown as typeof fetch;
}

describe('clawback audit trail', () => {
  it('keeps exact stroop precision', () => {
    expect(toStroops('10.0000001')).toBe(100000001n);
    expect(fromStroops(100000001n)).toBe('10.0000001');
    expect(fromStroops(0n)).toBe('0.0000000');
    expect(toStroops('1')).toBe(10000000n);
  });

  it('parses assets and finds clawback-enabled currencies', () => {
    expect(parseAsset(`USDX:${ISSUER}`)).toEqual({ code: 'USDX', issuer: ISSUER });
    expect(() => parseAsset('USDX')).toThrow();
    expect(
      findClawbackAssets({
        CURRENCIES: [
          { code: 'A', issuer: ISSUER, clawback_enabled: true },
          { code: 'B', issuer: ISSUER, flags: { clawback_enabled: true } },
          { code: 'C', issuer: ISSUER },
          'junk',
        ],
      }).map((a) => a.code),
    ).toEqual(['A', 'B']);
    expect(findClawbackAssets({})).toEqual([]);
  });

  it('recognises audit references', () => {
    expect(hasAuditReference('text', 'https://court.example/order/1')).toBe(true);
    expect(hasAuditReference('text', `x ${HASH}`)).toBe(true);
    expect(hasAuditReference('text', 'CASE-42')).toBe(true);
    expect(hasAuditReference('hash', 'abc=')).toBe(true);
    expect(hasAuditReference('text', 'oops')).toBe(false);
    expect(hasAuditReference('none', undefined)).toBe(false);
  });

  it('generates a report with totals, memos and unreferenced counts', async () => {
    const report = await new ClawbackAuditTrailGenerator(horizon(OPS), H).generate({
      code: 'USDX',
      issuer: ISSUER,
    });
    expect(report.totalClawbacks).toBe(3);
    expect(report.totalAmount).toBe('10.0000002');
    expect(report.totalAmountStroops).toBe('100000002');
    expect(report.unreferenced).toBe(2);
    expect(report.records.map((r) => r.hasAuditReference)).toEqual([true, false, false]);
    expect(report.records[1]).toMatchObject({ type: 'clawback_claimable_balance', amount: null });

    const md = renderClawbackMarkdown(report);
    expect(md).toContain('| 2025-01-01T00:00:00Z | clawback | GFROM | 10.0000001 |');
    expect(md).toContain('MISSING');
    expect(JSON.parse(renderClawbackJson(report)).totalClawbacks).toBe(3);
  });

  it('handles assets with zero clawback events', async () => {
    const report = await new ClawbackAuditTrailGenerator(horizon([OPS[0]]), H).generate({
      code: 'USDX',
      issuer: ISSUER,
    });
    expect(report).toMatchObject({ totalClawbacks: 0, totalAmount: '0.0000000', unreferenced: 0 });
    expect(renderClawbackMarkdown(report)).toContain('No clawback operations were found');
  });

  it('surfaces Horizon errors', async () => {
    const failing = (async () => new Response('', { status: 500 })) as unknown as typeof fetch;
    await expect(
      new ClawbackAuditTrailGenerator(failing, H).generate({ code: 'USDX', issuer: ISSUER }),
    ).rejects.toThrow(/HTTP 500/);
  });
});
