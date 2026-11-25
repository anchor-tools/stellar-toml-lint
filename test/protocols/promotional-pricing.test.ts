import { describe, expect, it } from 'vitest';
import {
  collectPromoClaims,
  formatPercent,
  parsePromoClaim,
  promotionalPricingRuleIds,
  verifyPromotions,
} from '../../src/protocols/promotionalPricingVerifier.js';

const ISSUER = 'GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY';
const doc = (desc: string) => ({
  ANCHOR_QUOTE_SERVER: 'https://quotes.example.com/',
  CURRENCIES: [{ code: 'USDC', issuer: ISSUER, desc }],
});
const NOW = new Date('2026-06-01T00:00:00Z');

/** Quote server charging `feeRate` of the sell amount. */
const quotes = (feeFor: (amount: string) => string): typeof fetch =>
  (async (url: string) => {
    const u = new URL(url);
    if (u.pathname === '/info') {
      return Response.json({
        assets: [{ asset: `stellar:USDC:${ISSUER}` }, { asset: 'iso4217:USD' }],
      });
    }
    const amount = u.searchParams.get('sell_amount') ?? '0';
    return Response.json({ fee: { total: feeFor(amount), asset: 'iso4217:USD' } });
  }) as unknown as typeof fetch;

describe('PromotionalPricingVerifier', () => {
  it('registers rule ids', () => {
    expect(promotionalPricingRuleIds).toEqual([
      'promotions/fee-mismatch',
      'promotions/expired-claim',
      'promotions/unverifiable-claim',
    ]);
  });

  it('parses claims', () => {
    expect(parsePromoClaim('p', '0% fee on all transfers')?.feePercent).toBe(0n);
    expect(parsePromoClaim('p', 'Zero-fee corridor until 2026-12-31')).toMatchObject({
      feePercent: 0n,
      expires: '2026-12-31',
    });
    expect(parsePromoClaim('p', 'Only 1.5% fee')?.feePercent).toBe(15000n);
    expect(parsePromoClaim('p', 'Discounted spread this month')?.feePercent).toBeUndefined();
    expect(parsePromoClaim('p', 'A regular dollar token')).toBeUndefined();
    expect(formatPercent(15000n)).toBe('1.5%');
    expect(formatPercent(0n)).toBe('0%');
  });

  it('collects claims from documentation and currencies', () => {
    const claims = collectPromoClaims({
      DOCUMENTATION: { ORG_DESCRIPTION: 'No fees for everyone', ORG_NAME: 'Acme' },
      CURRENCIES: [{ code: 'A', issuer: ISSUER, desc: '0% fee' }, 'junk'],
    });
    expect(claims.map((c) => c.path)).toEqual([
      'DOCUMENTATION.ORG_DESCRIPTION',
      'CURRENCIES[0].desc',
    ]);
    expect(claims[1]?.asset).toBe(`A:${ISSUER}`);
  });

  it('passes when quotes match the claim', async () => {
    const r = await verifyPromotions(
      doc('0% fee'),
      quotes(() => '0.0000000'),
      {
        checkQuotes: true,
        now: NOW,
      },
    );
    expect(r.diagnostics).toEqual([]);
  });

  it('flags a deceptive zero-fee claim using exact arithmetic', async () => {
    const r = await verifyPromotions(
      doc('Zero fee remittances'),
      quotes((a) => (Number(a) * 0.02).toFixed(7)),
      {
        checkQuotes: true,
        now: NOW,
      },
    );
    expect(r.diagnostics).toHaveLength(1);
    expect(r.diagnostics[0]).toMatchObject({ rule: 'promotions/fee-mismatch', severity: 'error' });
    expect(r.diagnostics[0]?.message).toContain('0% fee');
    expect(r.diagnostics[0]?.message).toContain('charges 2%');
  });

  it('accepts a stated percentage fee that is honoured', async () => {
    const r = await verifyPromotions(
      doc('Just 1% fee'),
      quotes((a) => (Number(a) / 100).toFixed(7)),
      {
        checkQuotes: true,
        now: NOW,
      },
    );
    expect(r.diagnostics).toEqual([]);
  });

  it('flags expired promotions even without network', async () => {
    const r = await verifyPromotions(doc('0% fee until 2026-01-31'), fetch, { now: NOW });
    expect(r.diagnostics.map((d) => d.rule)).toEqual(['promotions/expired-claim']);
  });

  it('does not query quotes without checkQuotes', async () => {
    let calls = 0;
    const counting = (async () => {
      calls++;
      return Response.json({});
    }) as unknown as typeof fetch;
    await verifyPromotions(doc('0% fee'), counting, { now: NOW });
    expect(calls).toBe(0);
  });

  it('reports unverifiable claims', async () => {
    const noServer = await verifyPromotions(
      { CURRENCIES: [{ code: 'A', issuer: ISSUER, desc: '0% fee' }] },
      fetch,
      {
        checkQuotes: true,
        now: NOW,
      },
    );
    expect(noServer.diagnostics[0]?.rule).toBe('promotions/unverifiable-claim');
    const noFee = await verifyPromotions(
      doc('0% fee'),
      (async (url: string) =>
        new URL(url).pathname === '/info'
          ? Response.json({ assets: [{ asset: 'a' }, { asset: 'b' }] })
          : new Response('{}', { status: 400 })) as unknown as typeof fetch,
      { checkQuotes: true, now: NOW },
    );
    expect(noFee.diagnostics[0]?.rule).toBe('promotions/unverifiable-claim');
    const down = await verifyPromotions(
      doc('0% fee'),
      (async () => {
        throw new Error('boom');
      }) as unknown as typeof fetch,
      { checkQuotes: true, now: NOW },
    );
    expect(down.diagnostics[0]?.message).toContain('boom');
    const noPair = await verifyPromotions(
      doc('0% fee'),
      (async () => Response.json({ assets: [] })) as unknown as typeof fetch,
      {
        checkQuotes: true,
        now: NOW,
      },
    );
    expect(noPair.diagnostics[0]?.rule).toBe('promotions/unverifiable-claim');
  });

  it('honours severity overrides', async () => {
    const r = await verifyPromotions(doc('0% fee until 2026-01-31'), fetch, {
      now: NOW,
      rules: { 'promotions/expired-claim': 'off' },
    });
    expect(r.diagnostics).toEqual([]);
  });
});
