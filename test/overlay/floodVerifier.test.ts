import { describe, expect, it } from 'vitest';
import { execFile } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import {
  Account,
  Asset,
  Keypair,
  Networks,
  Operation,
  TransactionBuilder,
  xdr,
} from '@stellar/stellar-base';
import {
  DEFAULT_QUEUE_SIZE_MULTIPLIER,
  FLOOD_DONT_HAVE_MISMATCH,
  FLOOD_DUPLICATE_OVERHEAD,
  FLOOD_MALFORMED_FRAME,
  FLOOD_METRICS_UNAVAILABLE,
  FLOOD_PREMATURE_DROP,
  FLOOD_PRIORITY_INVERSION,
  FLOOD_QUEUE_PRESSURE,
  FLOOD_QUEUE_SATURATED,
  FLOOD_STALE_PENDING,
  FLOOD_TXSET_UNAVAILABLE,
  FloodPropagationVerifier,
  MAX_SIMULATED_SUBMISSIONS,
  TransactionQueueModel,
  analyzeExchanges,
  analyzeSubmissions,
  buildBurst,
  compareFeeRate,
  defaultBurstProfile,
  floodPropagationRuleIds,
  floodPropagationRules,
  parseBurstProfile,
  parseCoreInfo,
  parseCoreMetrics,
  renderFloodPolicyReport,
  simulateBurst,
  tierForFeeRate,
  type OverlayExchange,
  type QueuedTransaction,
  type SubmissionEvent,
} from '../../src/overlay/floodVerifier.js';
import { allRules } from '../../src/rules/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(here, '..', 'fixtures', 'overlay', 'flood');
const fixture = (name: string): unknown =>
  JSON.parse(readFileSync(join(FIXTURES, name), 'utf8')) as unknown;

/** The observed log fixture, converted the way the CLI does it. */
function observedLog(): SubmissionEvent[] {
  return (fixture('submissions-observed.json') as Record<string, unknown>[]).map((raw) => {
    const tx = raw.tx as Record<string, unknown>;
    return {
      ...(raw as unknown as SubmissionEvent),
      tx: { ...(tx as unknown as QueuedTransaction), fee: BigInt(tx.fee as string) },
    };
  });
}

const tx = (id: string, fee: number, operations = 1, account = id): QueuedTransaction => ({
  id,
  account,
  operations,
  fee: BigInt(fee),
});

function envelope(feePerOp: number, ops = 1): xdr.TransactionEnvelope {
  const kp = Keypair.random();
  let builder = new TransactionBuilder(new Account(kp.publicKey(), '1'), {
    fee: String(feePerOp),
    networkPassphrase: Networks.PUBLIC,
  });
  for (let i = 0; i < ops; i++) {
    builder = builder.addOperation(
      Operation.payment({ destination: kp.publicKey(), asset: Asset.native(), amount: '1' }),
    );
  }
  const built = builder.setTimeout(0).build();
  built.sign(kp);
  return built.toEnvelope();
}

describe('fee rates and the queue model', () => {
  it('compares fee per operation exactly', () => {
    expect(compareFeeRate(tx('a', 100), tx('b', 200, 2))).toBe(0);
    expect(compareFeeRate(tx('a', 99), tx('b', 200, 2))).toBe(-1);
    expect(compareFeeRate(tx('a', 301, 3), tx('b', 100))).toBe(1);
  });

  it('admits until full, then evicts only cheaper transactions', () => {
    const model = new TransactionQueueModel(3);
    expect(model.submit(tx('a', 100)).status).toBe('accepted');
    expect(model.submit(tx('b', 300)).status).toBe('accepted');
    expect(model.submit(tx('c', 200)).occupancyOps).toBe(3);

    const bump = model.submit(tx('d', 250));
    expect(bump).toMatchObject({ status: 'accepted', evicted: ['a'], occupancyOps: 3 });
    expect(model.has('a')).toBe(false);

    const twoOps = model.submit(tx('e', 1000, 2));
    expect(twoOps.evicted).toEqual(['c', 'd']);
    expect(model.size).toBe(2);

    const cheap = model.submit(tx('f', 100));
    expect(cheap).toMatchObject({ status: 'rejected', reason: 'insufficient-fee', evicted: [] });
    expect(model.occupancyOps).toBe(3);
  });

  it('rejects malformed, oversized and duplicate submissions', () => {
    const model = new TransactionQueueModel(2);
    expect(model.submit(tx('a', 100, 0)).reason).toBe('malformed');
    expect(model.submit({ ...tx('b', 100), fee: -1n }).reason).toBe('malformed');
    expect(model.submit(tx('c', 100, 3)).reason).toBe('too-large');
    model.submit(tx('d', 100));
    expect(model.submit(tx('d', 100, 1, 'other')).reason).toBe('malformed');
    expect(() => new TransactionQueueModel(0)).toThrow(RangeError);
    expect(() => new TransactionQueueModel(1.5)).toThrow(RangeError);
  });

  it('keeps one pending transaction per account unless replaced by a 10x fee', () => {
    const model = new TransactionQueueModel(2);
    model.submit(tx('a1', 100, 1, 'alice'));
    model.submit(tx('b1', 100, 1, 'bob'));
    expect(model.submit(tx('a2', 999, 1, 'alice')).reason).toBe('account-pending');
    const replaced = model.submit(tx('a3', 1000, 1, 'alice'));
    expect(replaced).toMatchObject({ status: 'accepted', replaced: 'a1', evicted: [] });
    expect(model.has('a1')).toBe(false);
    expect(model.occupancyOps).toBe(2);
  });
});

describe('bursts', () => {
  it('builds a reproducible, interleaved burst', () => {
    const profile = parseBurstProfile('low=3, medium=2,high=1,priority=1');
    const first = buildBurst(profile, 100, 7);
    expect(first.map((t) => t.id)).toEqual(buildBurst(profile, 100, 7).map((t) => t.id));
    expect(first.map((t) => t.id)).not.toEqual(buildBurst(profile, 100, 8).map((t) => t.id));
    expect(first.find((t) => t.tier === 'priority')?.fee).toBe(10000n);
    expect(first).toHaveLength(7);
  });

  it('defaults to 150% of capacity and bounds the burst size', () => {
    const profile = defaultBurstProfile(200);
    expect(profile.low + profile.medium + profile.high + profile.priority).toBe(300);
    expect(defaultBurstProfile(1).priority).toBe(1);
    expect(() =>
      buildBurst({ low: MAX_SIMULATED_SUBMISSIONS + 1, medium: 0, high: 0, priority: 0 }),
    ).toThrow(RangeError);
  });

  it('rejects malformed burst profiles', () => {
    expect(() => parseBurstProfile('cheap=1')).toThrow('expected tier=count');
    expect(() => parseBurstProfile('low')).toThrow('expected tier=count');
    expect(() => parseBurstProfile('low=-1')).toThrow('non-negative integer');
    expect(() => parseBurstProfile('low=1.5')).toThrow('non-negative integer');
  });

  it('saturates fairly: only the cheapest tier is rejected or evicted', () => {
    const capacity = 100;
    const events = simulateBurst(
      new TransactionQueueModel(capacity),
      buildBurst(defaultBurstProfile(capacity)),
    );
    const analysis = analyzeSubmissions(events, capacity);
    expect(analysis.violations).toEqual([]);
    expect(analysis.saturatedAt).toBeDefined();
    expect(analysis.firstEvictionAt).toBeDefined();
    expect(analysis.peakOccupancyRatio).toBe(1);
    expect(analysis.entryFeePerOp).toBe(101);
    expect(analysis.byTier.priority).toMatchObject({ rejected: 0, evicted: 0 });
    expect(analysis.byTier.high).toMatchObject({ rejected: 0, evicted: 0 });
    expect(analysis.byTier.low?.rejected).toBeGreaterThan(0);
  });
});

describe('analyzeSubmissions on observed logs', () => {
  it('flags priority inversions and premature drops of rejected and evicted frames', () => {
    const analysis = analyzeSubmissions(observedLog(), 4);
    const rules = analysis.violations.map((v) => `${v.rule}:${v.txId}`);
    expect(rules).toEqual([
      `${FLOOD_PRIORITY_INVERSION}:b`,
      `${FLOOD_PRIORITY_INVERSION}:e`,
      `${FLOOD_PREMATURE_DROP}:e`,
    ]);
    expect(analysis.evictions).toBe(1);
    expect(analysis.rejectedByReason).toEqual({ 'insufficient-fee': 2 });
    expect(analysis.byTier.low).toMatchObject({ submitted: 3, retained: 1 });
    expect(analysis.saturatedAt).toBe(6);
  });

  it('does not treat replacements or ledger inclusions as drops', () => {
    const events: SubmissionEvent[] = [
      { tx: tx('a1', 100, 1, 'alice'), status: 'accepted', evicted: [], occupancyOps: 1 },
      { tx: tx('cheap', 50), status: 'accepted', evicted: [], occupancyOps: 2 },
      {
        tx: tx('a2', 1000, 1, 'alice'),
        status: 'accepted',
        evicted: ['ghost'],
        replaced: 'a1',
        occupancyOps: 2,
      },
      {
        tx: tx('late', 10),
        status: 'rejected',
        reason: 'account-pending',
        evicted: [],
        removed: ['cheap'],
        occupancyOps: 1,
      },
      { tx: tx('x', 10), status: 'rejected', evicted: [], occupancyOps: 1 },
    ];
    const analysis = analyzeSubmissions(events, 2);
    expect(analysis.violations).toEqual([]);
    expect(analysis.evictions).toBe(0);
    expect(analysis.byTier.untiered).toMatchObject({ submitted: 5, accepted: 3, rejected: 2 });
    expect(analysis.rejectedByReason).toEqual({ 'account-pending': 1, 'insufficient-fee': 1 });
    expect(analysis.entryFeePerOp).toBe(1001);
  });
});

describe('stellar-core metrics and info', () => {
  it('reads propagation counters from /metrics', () => {
    expect(parseCoreMetrics(fixture('metrics.json'))).toEqual({
      floodUnique: 1200,
      floodDuplicate: 3600,
      dontHaveReceived: 12,
      getTxSetReceived: 40,
      transactionsReceived: 1500,
      bannedTransactions: 7,
      pendingAge: [120, 30, 4, 2],
    });
  });

  it('accepts flat documents and other counter shapes', () => {
    expect(
      parseCoreMetrics({
        'overlay.flood.unique_recv': 5,
        'overlay.flood.duplicate_recv': { value: 2 },
        'overlay.recv.get-txset': { sum: 3 },
        'overlay.recv.dont-have': { other: 1 },
        'herder.pending-txs.age0': 'n/a',
      }),
    ).toEqual({ floodUnique: 5, floodDuplicate: 2, getTxSetReceived: 3, pendingAge: [] });
    expect(parseCoreMetrics(null)).toEqual({ pendingAge: [] });
    expect(parseCoreMetrics({ metrics: { 'overlay.flood.unique_recv': null } })).toEqual({
      pendingAge: [],
    });
  });

  it('reads the queue size inputs from /info', () => {
    expect(parseCoreInfo(fixture('info.json'))).toEqual({ maxTxSetOps: 100, baseFee: 100 });
    expect(parseCoreInfo({ ledger: { maxTxSetSize: 50 } })).toEqual({ maxTxSetOps: 50 });
    expect(parseCoreInfo({ ledger: { maxTxSetSize: 0, baseFee: -1 } })).toEqual({});
    expect(parseCoreInfo({ info: 'oops' })).toEqual({});
    expect(parseCoreInfo(undefined)).toEqual({});
  });
});

describe('transaction set exchanges', () => {
  it('decodes GET_TX_SET answers, DONT_HAVE misses and malformed frames', () => {
    const analysis = analyzeExchanges(
      fixture('exchanges.json') as OverlayExchange[],
      Networks.PUBLIC,
    );
    expect(analysis).toMatchObject({
      getTxSetRequests: 3,
      answered: 1,
      dontHave: 2,
      mismatched: 1,
      malformed: 1,
    });
    expect(analysis.transactions.map((t) => t.tier)).toEqual([
      'low',
      'medium',
      'high',
      'priority',
      'low',
    ]);
    expect(analysis.transactions[1]).toMatchObject({ operations: 2, fee: 400n });
  });

  it('handles generalized sets, flooded responses, fee bumps and unrelated frames', () => {
    const hash = Buffer.alloc(32, 1);
    const inner = TransactionBuilder.fromXDR(envelope(100), Networks.PUBLIC);
    const feeSource = Keypair.random();
    const bump = TransactionBuilder.buildFeeBumpTransaction(
      feeSource,
      '5000',
      inner as Parameters<typeof TransactionBuilder.buildFeeBumpTransaction>[2],
      Networks.PUBLIC,
    );
    bump.sign(feeSource);
    const component = xdr.TxSetComponent.txsetCompTxsMaybeDiscountedFee(
      new xdr.TxSetComponentTxsMaybeDiscountedFee({ baseFee: null, txes: [envelope(1000)] }),
    );
    // Int-switched unions are constructed as `new Union(switch, value)`.
    const Phase = xdr.TransactionPhase as unknown as new (arm: number, value: unknown) => unknown;
    const GeneralizedSet = xdr.GeneralizedTransactionSet as unknown as new (
      arm: number,
      value: unknown,
    ) => xdr.GeneralizedTransactionSet;
    const generalized = xdr.StellarMessage.generalizedTxSet(
      new GeneralizedSet(
        1,
        new xdr.TransactionSetV1({
          previousLedgerHash: hash,
          phases: [new Phase(0, [component]) as xdr.TransactionPhase],
        }),
      ),
    );
    const exchanges: OverlayExchange[] = [
      {
        request: xdr.StellarMessage.getTxSet(hash).toXDR('base64'),
        response: generalized.toXDR('base64'),
      },
      {
        request: xdr.StellarMessage.getTxSet(hash).toXDR('base64'),
        response: xdr.StellarMessage.transaction(bump.toEnvelope()).toXDR('base64'),
      },
      {
        request: xdr.StellarMessage.getTxSet(hash).toXDR('base64'),
        response: xdr.StellarMessage.getTxSet(hash).toXDR('base64'),
      },
      { request: xdr.StellarMessage.getTxSet(hash).toXDR('base64') },
      { request: 'not xdr' },
    ];
    const analysis = analyzeExchanges(exchanges, Networks.PUBLIC);
    expect(analysis).toMatchObject({ getTxSetRequests: 4, answered: 1, malformed: 1 });
    expect(analysis.transactions[0]).toMatchObject({ tier: 'high', fee: 1000n });
    expect(analysis.transactions[1]).toMatchObject({
      account: feeSource.publicKey(),
      operations: 2,
      fee: 10000n,
      tier: 'high',
    });

    // An envelope for another network still decodes; a corrupt one does not.
    const corrupt: OverlayExchange[] = [
      {
        request: xdr.StellarMessage.transaction(envelope(100)).toXDR('base64'),
      },
    ];
    expect(
      analyzeExchanges(corrupt, 'Test SDF Network ; September 2015').transactions,
    ).toHaveLength(1);
  });

  it('assigns fee tiers relative to the base fee', () => {
    expect(tierForFeeRate(100)).toBe('low');
    expect(tierForFeeRate(250)).toBe('medium');
    expect(tierForFeeRate(1000)).toBe('high');
    expect(tierForFeeRate(10000)).toBe('priority');
    expect(tierForFeeRate(500, 50)).toBe('high');
  });
});

describe('FloodPropagationVerifier', () => {
  it('reports saturation thresholds without metrics', () => {
    const report = new FloodPropagationVerifier().verify();
    expect(report.capacityOps).toBe(1000 * DEFAULT_QUEUE_SIZE_MULTIPLIER);
    expect(report.thresholds).toEqual({ pressureOps: 1600, saturationOps: 2000 });
    expect(report.diagnostics.map((d) => d.rule)).toEqual([
      FLOOD_QUEUE_SATURATED,
      FLOOD_METRICS_UNAVAILABLE,
    ]);
    expect(report.ok).toBe(true);
    expect(report.healthScore).toBe(100);
    expect(report.grade).toBe('healthy');
  });

  it('combines metrics, exchanges and observed submissions', () => {
    const report = new FloodPropagationVerifier({ capacityOps: 4 }).verify({
      metrics: fixture('metrics.json'),
      info: fixture('info.json'),
      exchanges: fixture('exchanges.json') as OverlayExchange[],
      observed: observedLog(),
    });
    const rules = report.diagnostics.map((d) => d.rule);
    for (const rule of [
      FLOOD_QUEUE_SATURATED,
      FLOOD_PRIORITY_INVERSION,
      FLOOD_PREMATURE_DROP,
      FLOOD_DUPLICATE_OVERHEAD,
      FLOOD_STALE_PENDING,
      FLOOD_TXSET_UNAVAILABLE,
      FLOOD_DONT_HAVE_MISMATCH,
      FLOOD_MALFORMED_FRAME,
    ]) {
      expect(rules).toContain(rule);
    }
    expect(report.ok).toBe(false);
    expect(report.grade).toBe('unhealthy');
    expect(report.observed?.violations).toHaveLength(3);
    expect(report.exchanges?.transactions).toHaveLength(5);

    const text = renderFloodPolicyReport(report);
    expect(text).toContain('queue: 4 ops (pressure at 4, saturation at 4), base fee 100');
    expect(text).toMatch(/simulated burst: 7 submissions, peak 4\/4 ops/);
    expect(text).toContain('observed submissions: 8 submissions');
    expect(text).toContain('fairness: 3 violation(s)');
    expect(text).toContain('pending by age: 120 / 30 / 4 / 2');
    expect(text).toContain('1 mismatched');
    expect(text).toMatch(/mempool health: \d+\/100 \(unhealthy\)/);
  });

  it('reports pressure below saturation and stays quiet on healthy metrics', () => {
    const report = new FloodPropagationVerifier({
      capacityOps: 10,
      profile: { low: 9, medium: 0, high: 0, priority: 0 },
    }).verify({
      metrics: {
        'overlay.flood.unique_recv': 10,
        'overlay.flood.duplicate_recv': 5,
        'overlay.recv.get-txset': 10,
        'overlay.recv.dont-have': 1,
        'herder.pending-txs.age0': 3,
        'herder.pending-txs.age1': 0,
      },
      info: { ledger: { maxTxSetSize: 5, baseFee: 200 } },
      exchanges: [],
    });
    expect(report.diagnostics.map((d) => d.rule)).toEqual([FLOOD_QUEUE_PRESSURE]);
    expect(report.baseFee).toBe(200);
    const text = renderFloodPolicyReport(report);
    expect(text).not.toContain('saturated at');
    expect(text).toContain('exchanges: 0 GET_TX_SET');
  });

  it('derives the queue from /info and honours rule overrides', () => {
    const report = new FloodPropagationVerifier({
      queueSizeMultiplier: 3,
      rules: { [FLOOD_QUEUE_SATURATED]: 'off', [FLOOD_METRICS_UNAVAILABLE]: 'off' },
    }).verify({ info: { ledger: { maxTxSetSize: 20 } } });
    expect(report.capacityOps).toBe(60);
    expect(report.diagnostics).toEqual([]);
    expect(renderFloodPolicyReport(report)).not.toContain('metrics:');
  });

  it('grades a moderately unhealthy node as degraded', () => {
    const report = new FloodPropagationVerifier({
      capacityOps: 10,
      rules: { [FLOOD_STALE_PENDING]: 'warning' },
    }).verify({
      metrics: { 'herder.pending-txs.age0': 1, 'herder.pending-txs.age1': 5 },
      exchanges: [{ request: 'garbage' }],
      observed: [{ tx: tx('h', 1000), status: 'rejected', evicted: [], occupancyOps: 0 }],
    });
    expect(report.grade).toBe('healthy');
    const worse = new FloodPropagationVerifier({ capacityOps: 10 }).verify({
      metrics: { 'herder.pending-txs.age0': 1, 'herder.pending-txs.age1': 5 },
      observed: [
        {
          tx: { ...tx('h', 1000), tier: 'high' },
          status: 'rejected',
          evicted: [],
          occupancyOps: 0,
        },
        {
          tx: { ...tx('p', 1000), tier: 'priority' },
          status: 'rejected',
          evicted: [],
          occupancyOps: 0,
        },
      ],
    });
    expect(worse.healthScore).toBe(60);
    expect(worse.grade).toBe('degraded');
  });

  it('registers every rule id', () => {
    const ids = allRules.map((rule) => rule.id);
    for (const id of floodPropagationRuleIds) expect(ids).toContain(id);
    expect(floodPropagationRules).toHaveLength(10);
    for (const rule of floodPropagationRules) expect(() => rule.run({} as never)).not.toThrow();
  });
});

describe('audit-flood-policy', () => {
  const CLI = join(here, '..', '..', 'dist', 'cli.js');
  const run = promisify(execFile);
  async function cli(args: string[]) {
    try {
      const { stdout, stderr } = await run('node', [CLI, 'audit-flood-policy', ...args]);
      return { code: 0, stdout, stderr };
    } catch (error) {
      const e = error as { code: number; stdout: string; stderr: string };
      return { code: e.code, stdout: e.stdout, stderr: e.stderr };
    }
  }
  const files = [
    '--metrics-file',
    join(FIXTURES, 'metrics.json'),
    '--info-file',
    join(FIXTURES, 'info.json'),
    '--exchanges-file',
    join(FIXTURES, 'exchanges.json'),
    '--submissions-file',
    join(FIXTURES, 'submissions-observed.json'),
  ];

  it('audits the fixtures and exits 1 on fairness violations', async () => {
    const text = await cli([...files, '--capacity', '4']);
    expect(text.code).toBe(1);
    expect(text.stdout).toContain('fairness: 3 violation(s)');

    const json = await cli([...files, '--format', 'json', '--profile', 'low=4,priority=1']);
    expect(json.code).toBe(1);
    const report = JSON.parse(json.stdout) as { exchanges: { transactions: { fee: string }[] } };
    expect(report.exchanges.transactions[3]?.fee).toBe('10000');
  });

  it('reads /info and /metrics from --host and survives an unreachable one', async () => {
    const server = createServer((socket) => {
      socket.once('data', (data) => {
        const path = data.toString().split(' ')[1];
        const body =
          path === '/info'
            ? JSON.stringify({ info: { ledger: { maxTxSetSize: 10, baseFee: 100 } } })
            : '{}';
        socket.end(
          `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`,
        );
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    const port = typeof address === 'object' && address !== null ? address.port : 0;
    try {
      const ok = await cli(['--host', '127.0.0.1', '--admin-port', String(port)]);
      expect(ok.stdout).toContain('queue: 20 ops');
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
    const down = await cli(['--host', '127.0.0.1', '--admin-port', String(port)]);
    expect(down.stderr).toContain('Could not read');
    expect(down.code).toBe(0);
  });

  it('rejects bad usage and bad input files', async () => {
    expect((await cli(['--help'])).code).toBe(0);
    expect((await cli(['--format', 'xml'])).code).toBe(2);
    expect((await cli(['--admin-port', '0'])).code).toBe(2);
    expect((await cli(['--bogus'])).code).toBe(2);
    expect((await cli(['--profile', 'cheap=1'])).code).toBe(2);
    const dir = await mkdtemp(join(tmpdir(), 'flood-'));
    try {
      const bad = join(dir, 'bad.json');
      await writeFile(bad, JSON.stringify({ not: 'an array' }));
      expect((await cli(['--exchanges-file', bad])).code).toBe(2);
      expect((await cli(['--submissions-file', bad])).code).toBe(2);
      await writeFile(bad, JSON.stringify([{ tx: {} }]));
      const invalid = await cli(['--submissions-file', bad]);
      expect(invalid.code).toBe(2);
      expect(invalid.stderr).toContain('submissions[0] is not a valid submission event');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
