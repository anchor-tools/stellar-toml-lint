import { describe, expect, it } from 'vitest';
import {
  ChainlinkPorVerifier,
  chainlinkPorRuleIds,
  collectPorFeeds,
  decodeLatestRoundData,
  verifyPorFeeds,
} from '../../src/bridges/chainlinkPorVerifier.js';
import { hexToBytes } from '../../src/bridges/evmCrypto.js';

const ISSUER = 'GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY';
const FEED = '0x1111111111111111111111111111111111111111';
const NOW = Date.UTC(2026, 10, 19, 12, 0, 0);
const NOW_S = BigInt(NOW / 1000);
const RPC = 'https://rpc.example.com';
const HORIZON = 'https://horizon.example.com';

const doc = (feed: Record<string, unknown> = {}): Record<string, unknown> => ({
  HORIZON_URL: HORIZON,
  CURRENCIES: [{ code: 'USDX', issuer: ISSUER }],
  DOCUMENTATION: {
    PROOF_OF_RESERVES: {
      CHAINLINK_FEEDS: [{ asset: 'USDX', chain: 'ethereum', aggregator: FEED, rpc: RPC, ...feed }],
    },
  },
});

const word = (v: bigint): string => (v < 0n ? (1n << 256n) + v : v).toString(16).padStart(64, '0');

interface Round {
  roundId?: bigint;
  answer: bigint;
  updatedAt: bigint;
  answeredInRound?: bigint;
}

/** Mock aggregator (8 decimals) plus a Horizon /assets endpoint. */
function chain(round: Round, supply = '1000000.0000000', status = 200): typeof fetch {
  return (async (url: string, init?: RequestInit) => {
    if (url.startsWith(HORIZON)) {
      return new Response(JSON.stringify({ _embedded: { records: [{ amount: supply }] } }));
    }
    if (status !== 200) return new Response('{}', { status });
    const { params, id } = JSON.parse(String(init?.body));
    const data: string = params[0].data;
    const roundId = round.roundId ?? 5n;
    const result =
      data === '0x313ce567'
        ? `0x${word(8n)}`
        : `0x${[roundId, round.answer, round.updatedAt, round.updatedAt, round.answeredInRound ?? roundId].map(word).join('')}`;
    return new Response(JSON.stringify({ jsonrpc: '2.0', id, result }));
  }) as unknown as typeof fetch;
}

const rules = (r: { diagnostics: { rule: string }[] }): string[] =>
  r.diagnostics.map((d) => d.rule);
const probe = { probe: true, now: NOW, retryDelayMs: 0 };

describe('ChainlinkPorVerifier', () => {
  it('registers rule ids', () => {
    expect(chainlinkPorRuleIds).toContain('por/stale-feed');
    expect(chainlinkPorRuleIds).toContain('por/undercollateralized');
  });

  it('is silent without feed declarations', async () => {
    expect((await verifyPorFeeds({})).diagnostics).toEqual([]);
  });

  it('collects feeds from DOCUMENTATION and CURRENCIES', () => {
    const feeds = collectPorFeeds({
      ...doc(),
      CURRENCIES: [{ code: 'USDX', issuer: ISSUER, chainlink_por: { aggregator: FEED } }],
    });
    expect(feeds.map((f) => f.path)).toEqual([
      'DOCUMENTATION.PROOF_OF_RESERVES.CHAINLINK_FEEDS[0]',
      'CURRENCIES[0].chainlink_por',
    ]);
    expect(feeds[1]?.asset).toBe(`USDX:${ISSUER}`);
  });

  it('validates declarations offline without touching the network', async () => {
    let calls = 0;
    const counting = (async () => {
      calls++;
      return new Response('{}');
    }) as unknown as typeof fetch;
    const r = await verifyPorFeeds(doc({ aggregator: '0x123', heartbeat: 90000 }), counting);
    expect(rules(r)).toEqual(['por/invalid-feed']);
    const r2 = await verifyPorFeeds(doc({ heartbeat: 172800 }), counting);
    expect(r2.diagnostics[0]?.message).toContain('exceeds');
    const r3 = await verifyPorFeeds(doc({ chain: 'nowhere', rpc: undefined }), counting);
    expect(rules(r3)).toEqual(['por/invalid-feed']);
    const r4 = await verifyPorFeeds(doc({ asset: 'NOPE' }), counting);
    expect(r4.diagnostics[0]?.message).toContain('Stellar asset');
    expect(calls).toBe(0);
  });

  it('passes a fresh, fully collateralized feed and reports the ratio', async () => {
    // 1,025,000 USD of reserves (8 decimals) against 1,000,000 issued.
    const r = await verifyPorFeeds(
      doc(),
      chain({ answer: 102_500_000_000_000n, updatedAt: NOW_S - 600n }),
      probe,
    );
    expect(rules(r)).toEqual(['por/collateralization']);
    expect(r.diagnostics[0]?.severity).toBe('info');
    expect(r.feeds[0]).toMatchObject({
      reserve: '1025000',
      supply: '1000000',
      collateralRatio: '102.5%',
      ageSeconds: 600,
    });
  });

  it('flags a stale feed beyond its heartbeat', async () => {
    const r = await verifyPorFeeds(
      doc({ heartbeat: 3600 }),
      chain({ answer: 100_000_000_000_000n, updatedAt: NOW_S - 7200n }),
      probe,
    );
    expect(rules(r)).toContain('por/stale-feed');
    expect(r.diagnostics.find((d) => d.rule === 'por/stale-feed')?.message).toContain('7200s');
  });

  it('flags timestamps in the future and incomplete rounds', async () => {
    const r = await verifyPorFeeds(
      doc(),
      chain({
        answer: 100_000_000_000_000n,
        updatedAt: NOW_S + 3600n,
        roundId: 9n,
        answeredInRound: 8n,
      }),
      probe,
    );
    expect(rules(r)).toEqual(expect.arrayContaining(['por/incomplete-round', 'por/stale-feed']));
  });

  it('errors when the reserve does not cover the Stellar supply', async () => {
    const r = await verifyPorFeeds(
      doc(),
      chain({ answer: 90_000_000_000_000n, updatedAt: NOW_S }),
      probe,
    );
    const under = r.diagnostics.find((d) => d.rule === 'por/undercollateralized');
    expect(under?.severity).toBe('error');
    expect(under?.message).toContain('90%');
  });

  it('compares with exact integer math at the boundary', async () => {
    const exact = await verifyPorFeeds(
      doc(),
      chain({ answer: 100_000_000_000_000n, updatedAt: NOW_S }, '1000000.0000001'),
      probe,
    );
    expect(rules(exact)).toContain('por/undercollateralized');
  });

  it('rejects non-positive answers', async () => {
    const r = await verifyPorFeeds(doc(), chain({ answer: -1n, updatedAt: NOW_S }), probe);
    expect(rules(r)).toEqual(['por/invalid-answer']);
  });

  it('uses provided supplies instead of Horizon', async () => {
    const r = await new ChainlinkPorVerifier(
      chain({ answer: 100_000_000_000n, updatedAt: NOW_S }, 'unused'),
      { ...probe, supplies: { USDX: '2000' } },
    ).verify(doc());
    expect(r.feeds[0]?.collateralRatio).toBe('50%');
  });

  it('degrades to warnings on RPC errors and rate limits', async () => {
    const limited = await verifyPorFeeds(
      doc(),
      chain({ answer: 1n, updatedAt: NOW_S }, '1', 429),
      probe,
    );
    expect(rules(limited)).toEqual(['por/rpc-unavailable']);
    expect(limited.diagnostics[0]?.message).toContain('rate limited');
    const down = (async () => {
      throw new Error('ECONNREFUSED');
    }) as unknown as typeof fetch;
    const r = await verifyPorFeeds(doc(), down, probe);
    expect(r.diagnostics[0]?.severity).toBe('warning');
  });

  it('retries once after a rate limit', async () => {
    let calls = 0;
    const inner = chain({ answer: 100_000_000_000_000n, updatedAt: NOW_S });
    const flaky = (async (url: string, init?: RequestInit) => {
      if (!url.startsWith(HORIZON) && calls++ === 0) return new Response('{}', { status: 429 });
      return inner(url, init);
    }) as unknown as typeof fetch;
    const r = await verifyPorFeeds(doc(), flaky, probe);
    expect(rules(r)).toEqual(['por/collateralization']);
  });

  it('warns when the Stellar supply cannot be read', async () => {
    const r = await verifyPorFeeds(
      doc(),
      chain({ answer: 100_000_000_000_000n, updatedAt: NOW_S }, 'garbage'),
      probe,
    );
    expect(rules(r)).toEqual(['por/supply-unavailable']);
  });

  it('decodes latestRoundData and rejects short payloads', () => {
    const data = hexToBytes([1n, -5n, 2n, 3n, 1n].map(word).join('')) as Uint8Array;
    expect(decodeLatestRoundData(data)).toMatchObject({ roundId: 1n, answer: -5n, updatedAt: 3n });
    expect(decodeLatestRoundData(new Uint8Array(64))).toBeUndefined();
  });

  it('honours rule overrides', async () => {
    const r = await verifyPorFeeds(
      doc(),
      chain({ answer: 102_500_000_000_000n, updatedAt: NOW_S }),
      { ...probe, rules: { 'por/collateralization': 'off' } },
    );
    expect(r.diagnostics).toEqual([]);
  });
});
