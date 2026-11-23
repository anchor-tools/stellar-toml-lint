import { afterEach, describe, expect, it } from 'vitest';
import { createServer, type Server, type Socket } from 'node:net';
import { Keypair, Networks } from '@stellar/stellar-base';
import {
  ConnectionFloodingDefenseTester,
  MAX_BURST_CONNECTIONS,
  MIN_CONNECTION_INTERVAL_MS,
  PEER_HANDSHAKE_DROPPED,
  PEER_HANDSHAKE_UNVERIFIED,
  PEER_LATENCY_DEGRADED,
  PEER_NO_THROTTLING_OBSERVED,
  PEER_PORT_UNREACHABLE,
  PEER_SLOW_RECOVERY,
  PEER_UNRESPONSIVE_AFTER_BURST,
  classifyConnectError,
  floodingDefenseRuleIds,
  floodingDefenseRules,
  helloHandshake,
  renderFloodingDefenseReport,
  tcpConnector,
  type ConnectOutcome,
  type ConnectStatus,
  type PeerConnector,
} from '../../src/overlay/floodingTester.js';
import { OverlayHandshakeTester } from '../../src/overlay/handshakeTester.js';
import { allRules } from '../../src/rules/index.js';

const servers: Server[] = [];
const sockets = new Set<Socket>();

afterEach(async () => {
  for (const socket of sockets) socket.destroy();
  sockets.clear();
  await Promise.all(
    servers
      .splice(0)
      .map((server) => new Promise<void>((resolve) => server.close(() => resolve()))),
  );
});

/** A mock peer server on an ephemeral loopback port. */
async function startServer(onConnection: (socket: Socket) => void = () => {}): Promise<number> {
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => {});
    onConnection(socket);
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('no port');
  return address.port;
}

/** A port that nothing listens on. */
async function closedPort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  if (address === null || typeof address === 'string') throw new Error('no port');
  return address.port;
}

/**
 * Scripted connector: returns `phases[n]` for the n-th attempt (the last entry
 * repeats) and counts how many accepted sockets are still open.
 */
function scripted(phases: (ConnectStatus | [ConnectStatus, number])[]) {
  let calls = 0;
  const state = { open: 0, calls: () => calls };
  const connector: PeerConnector = async () => {
    const phase = phases[Math.min(calls, phases.length - 1)]!;
    calls++;
    const [status, latencyMs] = Array.isArray(phase) ? phase : [phase, 5];
    if (status !== 'accepted') return { status, latencyMs, error: status };
    state.open++;
    let closed = false;
    const outcome: ConnectOutcome = {
      status,
      latencyMs,
      close: () => {
        if (closed) return;
        closed = true;
        state.open--;
      },
    };
    return outcome;
  };
  return { connector, state };
}

const FAST = { burst: 4, intervalMs: MIN_CONNECTION_INTERVAL_MS, holdMs: 1, recoveryWindowMs: 0 };

const rules = (diagnostics: { rule: string }[]) => diagnostics.map((d) => d.rule);

describe('ConnectionFloodingDefenseTester with a mock peer server', () => {
  it('passes a healthy peer and closes every socket it opened', async () => {
    const port = await startServer();
    const tester = new ConnectionFloodingDefenseTester({
      ...FAST,
      handshake: async () => true,
    });
    const report = await tester.run('127.0.0.1', port);

    expect(report.ok).toBe(true);
    expect(report.baseline).toMatchObject({ status: 'accepted', handshake: true });
    expect(report.burst).toMatchObject({ attempted: 4, accepted: 4, rejectionRate: 0 });
    expect(report.burst.firstRejectionAt).toBeUndefined();
    expect(report.burst.latencyP95Ms).toBeGreaterThanOrEqual(0);
    expect(report.recovery).toMatchObject({ recovered: true, polls: 1 });
    expect(report.postBurst.handshake).toBe(true);
    expect(report.openSockets).toBe(0);
    expect(rules(report.diagnostics)).toEqual([PEER_NO_THROTTLING_OBSERVED]);
    expect(report.limits).toEqual({
      burst: 4,
      intervalMs: MIN_CONNECTION_INTERVAL_MS,
      holdMs: 1,
      maxAttemptsPerSecond: 50,
    });

    const text = renderFloodingDefenseReport(report);
    expect(text).toContain('burst: 4/4 accepted');
    expect(text).toContain('handshake accepted');
    expect(text).toContain('tester sockets left open: 0');
    expect(text).toContain('verdict: PASS');
  });

  it('reports an unreachable port without bursting', async () => {
    const port = await closedPort();
    const tester = new ConnectionFloodingDefenseTester({ ...FAST, checkHandshake: false });
    const report = await tester.run('127.0.0.1', port);
    expect(report.ok).toBe(false);
    expect(report.baseline.status).toBe('refused');
    expect(report.burst.attempted).toBe(0);
    expect(rules(report.diagnostics)).toEqual([PEER_PORT_UNREACHABLE]);
    const text = renderFloodingDefenseReport(report);
    expect(text).toContain('baseline: refused');
    expect(text).toContain('handshake skipped');
    expect(text).not.toContain('burst:');
    expect(text).toContain('verdict: FAIL');
  });
});

describe('ConnectionFloodingDefenseTester throttling analysis', () => {
  it('records throttling, the first rejection and slow recovery', async () => {
    const { connector, state } = scripted([
      'accepted', // baseline
      'accepted',
      'accepted',
      'refused',
      'reset', // burst
      'timeout', // first recovery poll
      'accepted', // second recovery poll
    ]);
    const tester = new ConnectionFloodingDefenseTester({
      ...FAST,
      recoveryWindowMs: 2000,
      slowRecoveryMs: 1,
      connector,
      checkHandshake: false,
    });
    const report = await tester.run('node.example', 11625);

    expect(report.burst).toMatchObject({
      attempted: 4,
      accepted: 2,
      refused: 1,
      reset: 1,
      rejectionRate: 0.5,
      firstRejectionAt: 3,
    });
    expect(report.recovery.recovered).toBe(true);
    expect(report.recovery.polls).toBe(2);
    expect(report.recovery.recoveryMs).toBeGreaterThan(1);
    expect(rules(report.diagnostics)).toEqual([PEER_SLOW_RECOVERY]);
    expect(report.ok).toBe(true);
    expect(state.open).toBe(0);
    expect(report.openSockets).toBe(0);
    expect(renderFloodingDefenseReport(report)).toContain('first rejection at attempt 3');
  });

  it('fails a port that never recovers after the burst', async () => {
    const { connector } = scripted(['accepted', 'accepted', 'error']);
    const tester = new ConnectionFloodingDefenseTester({
      ...FAST,
      burst: 2,
      recoveryWindowMs: 300,
      connector,
      handshake: async () => true,
    });
    const report = await tester.run('node.example', 11625);
    expect(report.recovery.recovered).toBe(false);
    expect(report.recovery.polls).toBeGreaterThanOrEqual(1);
    expect(report.burst).toMatchObject({ accepted: 1, errors: 1 });
    expect(report.postBurst).toEqual({});
    expect(rules(report.diagnostics)).toEqual([PEER_UNRESPONSIVE_AFTER_BURST]);
    expect(report.ok).toBe(false);
    expect(renderFloodingDefenseReport(report)).toContain('recovery: NOT recovered');
  });

  it('handles a burst in which every connection is rejected', async () => {
    const { connector } = scripted(['accepted', 'refused']);
    const tester = new ConnectionFloodingDefenseTester({
      ...FAST,
      burst: 2,
      connector,
      checkHandshake: false,
    });
    const report = await tester.run('node.example', 11625);
    expect(report.burst).toMatchObject({ accepted: 0, refused: 2, rejectionRate: 1 });
    expect(report.burst.latencyP50Ms).toBeUndefined();
    const text = renderFloodingDefenseReport(report);
    expect(text).not.toContain('accept latency');
    expect(text).toContain('first rejection at attempt 1');
  });

  it('fails when rate limiting drops a legitimate handshake', async () => {
    const { connector } = scripted(['accepted']);
    let handshakes = 0;
    const tester = new ConnectionFloodingDefenseTester({
      ...FAST,
      connector,
      handshake: async () => ++handshakes === 1,
    });
    const report = await tester.run('node.example', 11625);
    expect(report.baseline.handshake).toBe(true);
    expect(report.postBurst.handshake).toBe(false);
    expect(rules(report.diagnostics)).toContain(PEER_HANDSHAKE_DROPPED);
    expect(report.ok).toBe(false);
    expect(renderFloodingDefenseReport(report)).toContain('handshake failed');
  });

  it('notes when the baseline handshake fails or throws', async () => {
    const { connector } = scripted(['accepted']);
    const tester = new ConnectionFloodingDefenseTester({
      ...FAST,
      connector,
      handshake: async () => {
        throw new Error('no HELLO');
      },
    });
    const report = await tester.run('node.example', 11625);
    expect(report.baseline.handshake).toBe(false);
    expect(rules(report.diagnostics)).toContain(PEER_HANDSHAKE_UNVERIFIED);
    expect(rules(report.diagnostics)).not.toContain(PEER_HANDSHAKE_DROPPED);
  });

  it('warns when connection latency degrades after the burst', async () => {
    const { connector } = scripted([['accepted', 10], 'accepted', ['accepted', 900]]);
    const tester = new ConnectionFloodingDefenseTester({
      ...FAST,
      burst: 1,
      connector,
      checkHandshake: false,
    });
    const report = await tester.run('node.example', 11625);
    expect(report.postBurst.latencyMs).toBe(900);
    expect(rules(report.diagnostics)).toContain(PEER_LATENCY_DEGRADED);
  });

  it('honours rule overrides', async () => {
    const { connector } = scripted(['accepted']);
    const tester = new ConnectionFloodingDefenseTester({
      ...FAST,
      connector,
      checkHandshake: false,
      rules: { [PEER_NO_THROTTLING_OBSERVED]: 'off' },
    });
    expect((await tester.run('node.example', 11625)).diagnostics).toEqual([]);
  });
});

describe('safety limits', () => {
  it('refuses settings beyond the non-intrusive thresholds', () => {
    for (const options of [
      { burst: 0 },
      { burst: MAX_BURST_CONNECTIONS + 1 },
      { burst: 2.5 },
      { intervalMs: MIN_CONNECTION_INTERVAL_MS - 1 },
      { holdMs: 5000 },
      { recoveryWindowMs: 20000 },
      { connectTimeoutMs: 0 },
      { burst: Number.NaN },
    ]) {
      expect(() => new ConnectionFloodingDefenseTester(options)).toThrow(RangeError);
    }
    const defaults = new ConnectionFloodingDefenseTester();
    expect(defaults.burst).toBeLessThanOrEqual(MAX_BURST_CONNECTIONS);
    expect(defaults.intervalMs).toBeGreaterThanOrEqual(MIN_CONNECTION_INTERVAL_MS);
  });

  it('validates the target', async () => {
    const tester = new ConnectionFloodingDefenseTester(FAST);
    await expect(tester.run(' ', 11625)).rejects.toThrow('host must not be empty');
    await expect(tester.run('node.example', 0)).rejects.toThrow(RangeError);
    await expect(tester.run('node.example', 70000)).rejects.toThrow(RangeError);
  });

  it('registers every rule id', () => {
    const ids = allRules.map((rule) => rule.id);
    for (const id of floodingDefenseRuleIds) expect(ids).toContain(id);
    expect(floodingDefenseRules).toHaveLength(7);
    for (const rule of floodingDefenseRules) expect(() => rule.run({} as never)).not.toThrow();
  });
});

describe('tcpConnector', () => {
  it('connects, closes idempotently and classifies refusals', async () => {
    const port = await startServer();
    const accepted = await tcpConnector('127.0.0.1', port, 1000);
    expect(accepted.status).toBe('accepted');
    accepted.close?.();
    accepted.close?.();

    const refused = await tcpConnector('127.0.0.1', await closedPort(), 1000);
    expect(refused.status).toBe('refused');
    expect(refused.error).toBeDefined();
  });

  it('gives up after the connect timeout', async () => {
    // 10.255.255.1 is unroutable: SYNs are dropped (timeout) or rejected by the
    // local network stack (error), but never answered.
    const outcome = await tcpConnector('10.255.255.1', 11625, 50);
    expect(['timeout', 'error']).toContain(outcome.status);
  });

  it('maps socket error codes', () => {
    const error = (code?: string) => Object.assign(new Error(code ?? 'x'), { code });
    expect(classifyConnectError(error('ECONNREFUSED'))).toBe('refused');
    expect(classifyConnectError(error('ECONNRESET'))).toBe('reset');
    expect(classifyConnectError(error('EPIPE'))).toBe('reset');
    expect(classifyConnectError(error('ECONNABORTED'))).toBe('reset');
    expect(classifyConnectError(error('ETIMEDOUT'))).toBe('timeout');
    expect(classifyConnectError(error('EHOSTUNREACH'))).toBe('error');
    expect(classifyConnectError(error())).toBe('error');
  });
});

describe('helloHandshake', () => {
  it('accepts a peer that answers with an overlay HELLO', async () => {
    const validator = Keypair.random();
    const port = await startServer((socket) => {
      socket.once('data', () => {
        socket.write(
          OverlayHandshakeTester.simulateValidatorResponse(
            validator.publicKey(),
            Networks.PUBLIC,
            11625,
            validator,
          ),
        );
      });
    });
    expect(await helloHandshake('127.0.0.1', port, 2000)).toBe(true);
  });

  it('rejects a peer that answers with garbage', async () => {
    const port = await startServer((socket) => {
      socket.once('data', () => socket.write(Buffer.from([0, 0, 0, 4, 1, 2, 3, 4])));
    });
    expect(await helloHandshake('127.0.0.1', port, 2000)).toBe(false);
  });
});
