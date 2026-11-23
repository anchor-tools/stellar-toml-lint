import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  BridgeSettlementLatencyBenchmark,
  benchmarkBridgeLatency,
  blockToMillis,
  bridgeLatencyRuleIds,
  percentile,
  renderLatencyReport,
  toUtcMillis,
} from '../../src/bridges/latencyBenchmark.js';
import {
  accountToBytes32,
  auditBridgeReplays,
  bridgeReplayRuleIds,
  normalizeBytes32,
  parseLockEvent,
} from '../../src/bridges/eventReplayDetector.js';
import {
  verifyBankAttestations,
  bankAttestationRuleIds,
  collectAttestations,
  parsePdfDate,
  readPdfMetadata,
} from '../../src/bridges/bankAttestationVerifier.js';
import {
  auditBurnRedemptions,
  classifyBurn,
  proofOfBurnRuleIds,
  renderBurnReport,
} from '../../src/bridges/proofOfBurnValidator.js';

const K1 = 'GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY';
const K2 = 'GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7';
const rules = (d: { rule: string }[]): string[] => d.map((x) => x.rule).sort();

describe('latency benchmark', () => {
  const NOW = Date.parse('2026-11-19T12:00:00Z');
  const pair = (id: string, start: string, end: string) => ({
    id,
    origin: { chain: 'ethereum', timestamp: start },
    destination: { chain: 'stellar', timestamp: end },
  });

  it('normalises timestamps to UTC and rejects zone-less ones', () => {
    expect(toUtcMillis('2026-11-19T12:00:00+01:00')).toBe(Date.parse('2026-11-19T11:00:00Z'));
    expect(toUtcMillis(1_700_000_000)).toBe(1_700_000_000_000);
    expect(toUtcMillis('1700000000000')).toBe(1_700_000_000_000);
    expect(toUtcMillis('2026-11-19T12:00:00')).toBeUndefined();
    expect(toUtcMillis('soon')).toBeUndefined();
    expect(toUtcMillis(-5)).toBeUndefined();
  });

  it('computes mean, stddev and p99', () => {
    const r = benchmarkBridgeLatency(
      {
        receipts: [
          pair('a', '2026-11-19T10:00:00Z', '2026-11-19T10:01:00Z'),
          pair('b', '2026-11-19T10:00:00Z', '2026-11-19T10:03:00Z'),
        ],
      },
      { now: NOW },
    );
    const c = r.corridors[0]!;
    expect(c.corridor).toBe('ethereum-stellar');
    expect(c.meanSeconds).toBe(120);
    expect(c.stdDevSeconds).toBe(60);
    expect(c.p99Seconds).toBe(180);
    expect(c.rating).toBe('meets-sla');
    expect(r.diagnostics).toEqual([]);
    expect(renderLatencyReport(r.corridors)).toContain('ethereum-stellar: MEETS-SLA');
  });

  it('flags degraded and congested corridors', () => {
    const slow = (secs: number) =>
      pair(
        'x',
        '2026-11-19T10:00:00Z',
        new Date(Date.parse('2026-11-19T10:00:00Z') + secs * 1000).toISOString(),
      );
    const degraded = benchmarkBridgeLatency({ receipts: [slow(1200)] }, { now: NOW });
    expect(rules(degraded.diagnostics)).toEqual(['bridgelatency/sla-breach']);
    const congested = benchmarkBridgeLatency({ receipts: [slow(5000)] }, { now: NOW });
    expect(rules(congested.diagnostics)).toEqual(['bridgelatency/congested-corridor']);
    expect(congested.corridors[0]!.rating).toBe('congested');
  });

  it('flags stalled transfers but not fresh pending ones', () => {
    const r = benchmarkBridgeLatency(
      {
        receipts: [
          { id: 'old', origin: { chain: 'polygon', timestamp: '2026-11-19T08:00:00Z' } },
          { id: 'new', origin: { chain: 'polygon', timestamp: '2026-11-19T11:50:00Z' } },
        ],
      },
      { now: NOW },
    );
    expect(rules(r.diagnostics)).toEqual(['bridgelatency/stalled-transfer']);
    expect(r.corridors[0]).toMatchObject({ pending: 2, stalled: 1, rating: 'stalled' });
  });

  it('interpolates block numbers using per-chain checkpoints', () => {
    const cps = [
      { block: 100, time: 1_000_000 },
      { block: 200, time: 1_200_000 },
    ];
    expect(blockToMillis(150, cps)).toBe(1_100_000);
    expect(blockToMillis(100, cps)).toBe(1_000_000);
    expect(blockToMillis(300, cps)).toBe(1_400_000);
    expect(blockToMillis(150, [cps[0]!])).toBeUndefined();
    const r = benchmarkBridgeLatency(
      {
        blockCheckpoints: {
          ethereum: [
            { block: 100, timestamp: 1_700_000_000 },
            { block: 200, timestamp: 1_700_001_200 },
          ],
        },
        receipts: [
          {
            origin: { chain: 'ethereum', blockNumber: 150 },
            destination: { chain: 'stellar', timestamp: 1_700_000_900 },
          },
        ],
      },
      { now: NOW },
    );
    expect(r.corridors[0]!.meanSeconds).toBe(300);
  });

  it('filters by corridor and handles malformed input', () => {
    const evidence = {
      receipts: [
        pair('a', '2026-11-19T10:00:00Z', '2026-11-19T10:01:00Z'),
        {
          origin: { chain: 'solana', timestamp: 1_700_000_000 },
          destination: { chain: 'stellar', timestamp: 1_700_000_030 },
        },
      ],
    };
    const only = new BridgeSettlementLatencyBenchmark({ corridor: 'solana-stellar', now: NOW }).run(
      evidence,
    );
    expect(only.corridors.map((c) => c.corridor)).toEqual(['solana-stellar']);
    expect(rules(benchmarkBridgeLatency('nope').diagnostics)).toEqual([
      'bridgelatency/invalid-receipt',
    ]);
    const bad = benchmarkBridgeLatency(
      {
        receipts: [
          42,
          { origin: { chain: 'eth' } },
          pair('neg', '2026-11-19T10:05:00Z', '2026-11-19T10:00:00Z'),
        ],
      },
      { now: NOW },
    );
    expect(rules(bad.diagnostics)).toEqual([
      'bridgelatency/invalid-receipt',
      'bridgelatency/invalid-receipt',
      'bridgelatency/negative-latency',
    ]);
    expect(
      benchmarkBridgeLatency(evidence, { now: NOW, rules: { 'bridgelatency/sla-breach': 'off' } })
        .diagnostics,
    ).toEqual([]);
    expect(percentile([], 99)).toBe(0);
    expect(bridgeLatencyRuleIds).toContain('bridgelatency/stalled-transfer');
  });
});

describe('event replay detector', () => {
  const tx = (n: number): string => `0x${n.toString(16).padStart(64, '0')}`;
  const lock = (n: number, extra: Record<string, unknown> = {}) => ({
    txHash: tx(n),
    logIndex: 0,
    blockNumber: 100,
    amount: '1000000000000000000',
    recipient: accountToBytes32(K1),
    ...extra,
  });
  const mint = (n: number, extra: Record<string, unknown> = {}) => ({
    stellarTxHash: 'ab'.repeat(32),
    sourceTxHash: tx(n),
    sourceLogIndex: 0,
    amount: '1.0000000',
    recipient: K1,
    ...extra,
  });
  const base = { headBlock: 200 };

  it('accepts a one-to-one mapping', () => {
    const r = auditBridgeReplays({
      ...base,
      lockEvents: [lock(1), lock(2)],
      stellarMints: [mint(1), mint(2)],
    });
    expect(r.diagnostics).toEqual([]);
    expect(r.matched).toHaveLength(2);
  });

  it('flags duplicate mints of one lock', () => {
    const r = auditBridgeReplays({
      ...base,
      lockEvents: [lock(1)],
      stellarMints: [mint(1), mint(1)],
    });
    expect(rules(r.diagnostics)).toEqual(['bridgereplay/duplicate-mint']);
    expect(r.matched).toEqual([]);
  });

  it('flags unrecorded locks, orphan mints and missing replay ids', () => {
    const r = auditBridgeReplays({
      ...base,
      lockEvents: [lock(1)],
      stellarMints: [mint(9), { stellarTxHash: 'cd'.repeat(32), amount: '1' }],
    });
    expect(rules(r.diagnostics)).toEqual([
      'bridgereplay/missing-replay-id',
      'bridgereplay/orphan-mint',
      'bridgereplay/unrecorded-lock',
    ]);
  });

  it('handles reorgs: removed logs, shallow depth and re-reported logs', () => {
    const removed = auditBridgeReplays({
      ...base,
      lockEvents: [lock(1, { removed: true })],
      stellarMints: [mint(1)],
    });
    expect(rules(removed.diagnostics)).toEqual(['bridgereplay/reorged-event-minted']);
    const shallow = auditBridgeReplays({
      headBlock: 105,
      lockEvents: [lock(1)],
      stellarMints: [mint(1)],
    });
    expect(rules(shallow.diagnostics)).toEqual(['bridgereplay/premature-mint']);
    const pending = auditBridgeReplays({ headBlock: 105, lockEvents: [lock(1)], stellarMints: [] });
    expect(pending.diagnostics).toEqual([]);
    const reincluded = auditBridgeReplays({
      ...base,
      lockEvents: [lock(1, { removed: true }), lock(1)],
      stellarMints: [mint(1)],
    });
    expect(reincluded.diagnostics).toEqual([]);
  });

  it('checks amount and recipient', () => {
    const r = auditBridgeReplays({
      ...base,
      lockEvents: [lock(1)],
      stellarMints: [mint(1, { amount: '2.0000000', recipient: K2 })],
    });
    expect(rules(r.diagnostics)).toEqual([
      'bridgereplay/amount-mismatch',
      'bridgereplay/recipient-mismatch',
    ]);
  });

  it('requires strict 32-byte hex and parses raw eth_getLogs entries', () => {
    expect(normalizeBytes32('0x' + 'AB'.repeat(32))).toBe('0x' + 'ab'.repeat(32));
    expect(normalizeBytes32('0x' + 'ab'.repeat(31))).toBeUndefined();
    expect(normalizeBytes32('ab'.repeat(32))).toBeUndefined();
    const raw = parseLockEvent({
      transactionHash: tx(7),
      logIndex: '0x2',
      topics: ['0x' + '11'.repeat(32), tx(1), accountToBytes32(K1)],
      data: `0x${5n.toString(16).padStart(64, '0')}`,
    });
    expect(raw).toMatchObject({ logIndex: 2, amount: 5n, id: `${tx(7)}:2` });
    expect(parseLockEvent({ txHash: '0x12', logIndex: 0 })).toMatch(/32-byte/);
    expect(parseLockEvent(null)).toBe('not an object');
    expect(accountToBytes32('nope')).toBeUndefined();
  });

  it('rejects malformed evidence', () => {
    expect(rules(auditBridgeReplays([]).diagnostics)).toEqual(['bridgereplay/invalid-event']);
    const r = auditBridgeReplays({ lockEvents: [{ txHash: 1 }, lock(1, { logIndex: -1 })] });
    expect(rules(r.diagnostics)).toEqual([
      'bridgereplay/invalid-event',
      'bridgereplay/invalid-event',
    ]);
    expect(bridgeReplayRuleIds).toContain('bridgereplay/duplicate-mint');
  });
});

describe('bank attestation verifier', () => {
  const NOW = Date.parse('2026-11-19T00:00:00Z');
  const pdf = (date: string, extra = '/Author (Smith & Co CPAs)'): Uint8Array =>
    new TextEncoder().encode(
      `%PDF-1.7\n1 0 obj\n<< /CreationDate (${date}) ${extra} >>\nendobj\ntrailer\n%%EOF\n`,
    );
  const sha = (b: Uint8Array): string => createHash('sha256').update(b).digest('hex');
  const serve = (bytes: Uint8Array, status = 200): typeof fetch =>
    (async () =>
      new Response(bytes as unknown as ArrayBuffer, { status })) as unknown as typeof fetch;
  const toml = (hash: string, extra: Record<string, unknown> = {}) => ({
    DOCUMENTATION: {
      ATTESTATIONS: [{ url: 'https://a.example.com/q3.pdf', sha256: hash, ...extra }],
    },
  });

  it('verifies a fresh document with a matching checksum', async () => {
    const bytes = pdf('D:20261101000000Z');
    const r = await verifyBankAttestations(toml(sha(bytes)), serve(bytes), {
      download: true,
      now: NOW,
    });
    expect(r.diagnostics).toEqual([]);
    expect(r.attestations[0]!.verified).toBe(true);
  });

  it('flags expired documents', async () => {
    const bytes = pdf("D:20260101000000+01'00'");
    const r = await verifyBankAttestations(toml(sha(bytes)), serve(bytes), {
      download: true,
      now: NOW,
    });
    expect(rules(r.diagnostics)).toEqual(['attestation/expired']);
    expect(r.attestations[0]!.verified).toBe(false);
  });

  it('flags a checksum mismatch', async () => {
    const bytes = pdf('D:20261101000000Z');
    const r = await verifyBankAttestations(toml('0'.repeat(64)), serve(bytes), {
      download: true,
      now: NOW,
    });
    expect(rules(r.diagnostics)).toEqual(['attestation/checksum-mismatch']);
  });

  it('reports corrupted PDFs and download failures without throwing', async () => {
    const junk = new TextEncoder().encode('%PDF-1.7 truncated');
    const r = await verifyBankAttestations(toml(sha(junk)), serve(junk), {
      download: true,
      now: NOW,
    });
    expect(rules(r.diagnostics)).toEqual(['attestation/corrupted-document']);
    const down = await verifyBankAttestations(toml('0'.repeat(64)), serve(junk, 404), {
      download: true,
      now: NOW,
    });
    expect(rules(down.diagnostics)).toEqual(['attestation/unreachable']);
    const boom = (async () => {
      throw new Error('certificate has expired');
    }) as unknown as typeof fetch;
    const failed = await verifyBankAttestations(toml('0'.repeat(64)), boom, {
      download: true,
      now: NOW,
    });
    expect(failed.diagnostics[0]!.message).toContain('certificate has expired');
  });

  it('checks declarations offline', async () => {
    const r = await verifyBankAttestations(
      {
        DOCUMENTATION: {
          ATTESTATIONS: [
            { url: 'http://a.example.com/q.pdf', sha256: 'x' },
            { url: 'https://a.example.com/q.pdf' },
            {
              url: 'https://a.example.com/q.pdf',
              sha256: 'zz',
              date: '2026-01-01',
              reserve_balance: '90',
              issued_supply: '100',
            },
          ],
        },
      },
      serve(new Uint8Array()),
      { now: NOW },
    );
    expect(rules(r.diagnostics)).toEqual([
      'attestation/expired',
      'attestation/invalid-field',
      'attestation/invalid-url',
      'attestation/missing-checksum',
      'attestation/under-reserved',
    ]);
  });

  it('reads SEP-1 attestation_of_reserve and exposes parsers', () => {
    const entries = collectAttestations({
      CURRENCIES: [{ code: 'USD', attestation_of_reserve: 'https://a.example.com/r.pdf' }, 'bad'],
    });
    expect(entries).toHaveLength(1);
    expect(parsePdfDate('D:20261101120000Z')).toBe(Date.parse('2026-11-01T12:00:00Z'));
    expect(parsePdfDate('garbage')).toBeUndefined();
    expect(readPdfMetadata(new Uint8Array([1, 2, 3]))).toBeUndefined();
    expect(readPdfMetadata(pdf('D:20261101000000Z'))?.author).toBe('Smith & Co CPAs');
    expect(bankAttestationRuleIds).toContain('attestation/expired');
  });
});

describe('proof of burn validator', () => {
  const ASSET = `WUSD:${K1}`;
  const doc = {
    CURRENCIES: [
      { code: 'WUSD', issuer: K1, is_asset_anchored: true, redemption_instructions: 'burn first' },
    ],
  };
  const red = (op: Record<string, unknown>, extra: Record<string, unknown> = {}) => ({
    id: 'r1',
    asset: ASSET,
    amount: '10.0000000',
    operation: op,
    ...extra,
  });

  it('accepts payments back to the issuer and to locked accounts', () => {
    const r = auditBurnRedemptions(doc, {
      accounts: { [K2]: { masterWeight: 0, activeSigners: 0 } },
      redemptions: [
        red({ type: 'payment', destination: K1 }),
        red({ type: 'payment', destination: K2 }),
      ],
    });
    expect(r.diagnostics).toEqual([]);
    expect(r.redemptions.map((x) => x.kind)).toEqual(['issuer-payment', 'locked-account']);
    expect(renderBurnReport(r)).toContain('r1: BURNED (issuer-payment)');
  });

  it('accepts SAC burn host function calls', () => {
    const c = 'CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE';
    const r = auditBurnRedemptions(
      {},
      {
        redemptions: [
          { asset: c, amount: '5', operation: { type: 'invoke_host_function', function: 'burn' } },
        ],
      },
    );
    expect(r.diagnostics).toEqual([]);
    expect(r.redemptions[0]!.kind).toBe('sac-burn');
  });

  it('flags pseudo-burns to hot wallets and non-burn host calls', () => {
    const r = auditBurnRedemptions(doc, {
      accounts: { [K2]: { masterWeight: 1, activeSigners: 0 } },
      redemptions: [
        red({ type: 'payment', destination: K2 }),
        red({ type: 'invoke_host_function', function: 'transfer' }),
        red({ type: 'path_payment' }),
      ],
    });
    expect(rules(r.diagnostics)).toEqual([
      'burn/pseudo-burn',
      'burn/pseudo-burn',
      'burn/pseudo-burn',
    ]);
    expect(r.diagnostics[0]!.message).toContain('supply stays in circulation');
    expect(renderBurnReport(r)).toContain('NOT BURNED');
  });

  it('requires supply to drop by exactly the redeemed amount', () => {
    const ok = auditBurnRedemptions(doc, {
      redemptions: [
        red({ type: 'payment', destination: K1 }, { supplyBefore: '100', supplyAfter: '90' }),
      ],
    });
    expect(ok.diagnostics).toEqual([]);
    const bad = auditBurnRedemptions(doc, {
      redemptions: [
        red({ type: 'payment', destination: K1 }, { supplyBefore: '100', supplyAfter: '95' }),
      ],
    });
    expect(rules(bad.diagnostics)).toEqual(['burn/supply-mismatch']);
  });

  it('handles malformed and undeclared input', () => {
    expect(rules(auditBurnRedemptions({}, null).diagnostics)).toEqual(['burn/invalid-redemption']);
    const r = auditBurnRedemptions(doc, {
      redemptions: [
        { asset: 'x', amount: '1' },
        red({ type: 'payment', destination: K1 }, { amount: '0' }),
        { ...red({ type: 'payment', destination: K1 }), asset: `OTHER:${K1}` },
      ],
    });
    expect(rules(r.diagnostics)).toEqual([
      'burn/invalid-redemption',
      'burn/invalid-redemption',
      'burn/undeclared-asset',
    ]);
    const anchored = auditBurnRedemptions(
      { CURRENCIES: [{ code: 'WUSD', issuer: K1, is_asset_anchored: true }] },
      { redemptions: [] },
    );
    expect(rules(anchored.diagnostics)).toEqual(['burn/missing-withdraw-endpoint']);
    expect(
      classifyBurn({ asset: ASSET, operation: { type: 'payment', destination: 'bad' } }, {}),
    ).toBe('none');
    expect(proofOfBurnRuleIds).toContain('burn/pseudo-burn');
  });
});
