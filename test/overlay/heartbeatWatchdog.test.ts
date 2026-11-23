import { createHash } from 'node:crypto';
import { createServer, type Server, type Socket } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { xdr } from '@stellar/stellar-base';
import {
  HEARTBEAT_ERRATIC,
  HEARTBEAT_KEEPALIVE_DELAY,
  HEARTBEAT_KEEPALIVE_DISABLED,
  HEARTBEAT_SUDDEN_CLOSURE,
  HEARTBEAT_UNACKNOWLEDGED_SOCKET,
  HEARTBEAT_UNRESPONSIVE,
  HeartbeatConnectionClosedError,
  OverlayHeartbeatWatchdog,
  TcpHeartbeatChannel,
  decodeHeartbeatPong,
  encodeHeartbeatProbe,
  evaluateKeepalive,
  heartbeatProbeId,
  overlayHeartbeatRuleIds,
  overlayHeartbeatRules,
  renderHeartbeatReport,
  type HeartbeatChannel,
  type HeartbeatEndpoint,
  type SocketKeepaliveSnapshot,
} from '../../src/overlay/heartbeatWatchdog.js';
import { frameOverlayMessage, unframeOverlayMessage } from '../../src/overlay/handshakeTester.js';

const ENDPOINT: HeartbeatEndpoint = {
  host: 'validator.example.org',
  port: 11625,
  publicKey: 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF',
};

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

interface MockChannelOptions {
  behavior: (sequence: number) => Promise<number>;
  keepalive?: Partial<SocketKeepaliveSnapshot>;
  closeError?: Error;
}

class MockChannel implements HeartbeatChannel {
  readonly endpoint = ENDPOINT;
  closed = false;
  closeCalls = 0;
  private readonly behavior: (sequence: number) => Promise<number>;
  private readonly keepaliveOverrides: Partial<SocketKeepaliveSnapshot>;
  private readonly closeError?: Error;

  constructor(options: MockChannelOptions) {
    this.behavior = options.behavior;
    this.keepaliveOverrides = options.keepalive ?? {};
    if (options.closeError !== undefined) this.closeError = options.closeError;
  }

  probe(sequence: number): Promise<number> {
    return this.behavior(sequence);
  }

  keepalive(): SocketKeepaliveSnapshot {
    return {
      keepAliveEnabled: true,
      initialDelayMs: 10_000,
      ...this.keepaliveOverrides,
      pendingAcks: this.closed ? 0 : (this.keepaliveOverrides.pendingAcks ?? 0),
      state: this.closed ? 'closed' : (this.keepaliveOverrides.state ?? 'open'),
    };
  }

  async close(): Promise<void> {
    this.closeCalls++;
    if (this.closeError !== undefined) throw this.closeError;
    this.closed = true;
  }
}

describe('heartbeat probe framing', () => {
  it('derives a stable 32-byte probe id per sequence', () => {
    const first = heartbeatProbeId(1);
    expect(first).toHaveLength(32);
    expect(first.equals(heartbeatProbeId(1))).toBe(true);
    expect(first.equals(heartbeatProbeId(2))).toBe(false);
  });

  it('encodes a GET_SCP_QUORUMSET probe that is not itself a pong', () => {
    const frame = encodeHeartbeatProbe(7);
    const payload = unframeOverlayMessage(frame);
    const message = xdr.StellarMessage.fromXDR(Buffer.from(payload));
    expect(message.switch().name).toBe('getScpQuorumset');
    expect(Buffer.from(message.qSetHash()).equals(heartbeatProbeId(7))).toBe(true);
    expect(decodeHeartbeatPong(frame)).toBeUndefined();
  });

  it('decodes a DONT_HAVE pong', () => {
    const id = heartbeatProbeId(3);
    const message = xdr.StellarMessage.dontHave(
      new xdr.DontHave({
        type: xdr.MessageType.getScpQuorumset(),
        reqHash: id,
      }),
    );
    expect(decodeHeartbeatPong(frameOverlayMessage(message.toXDR()))?.equals(id)).toBe(true);
    // Unframed payloads are accepted too.
    expect(decodeHeartbeatPong(new Uint8Array(message.toXDR()))?.equals(id)).toBe(true);
  });

  it('decodes a served SCP_QUORUMSET as a pong over its hash', () => {
    const qSet = new xdr.ScpQuorumSet({
      threshold: 1,
      validators: [xdr.PublicKey.publicKeyTypeEd25519(Buffer.alloc(32, 1))],
      innerSets: [],
    });
    const expected = createHash('sha256').update(qSet.toXDR()).digest();
    const message = xdr.StellarMessage.scpQuorumset(qSet);
    expect(decodeHeartbeatPong(frameOverlayMessage(message.toXDR()))?.equals(expected)).toBe(true);
  });

  it('ignores frames that are not heartbeat acknowledgements', () => {
    expect(decodeHeartbeatPong(new Uint8Array([1, 2]))).toBeUndefined();
    const peers = xdr.StellarMessage.peers([]);
    expect(decodeHeartbeatPong(frameOverlayMessage(peers.toXDR()))).toBeUndefined();
  });
});

describe('evaluateKeepalive', () => {
  it('accepts a healthy keepalive configuration', () => {
    expect(
      evaluateKeepalive({
        keepAliveEnabled: true,
        initialDelayMs: 10_000,
        pendingAcks: 0,
        state: 'open',
      }),
    ).toEqual([]);
  });

  it('warns when TCP keepalive is disabled', () => {
    const checks = evaluateKeepalive({
      keepAliveEnabled: false,
      pendingAcks: 0,
      state: 'open',
    });
    expect(checks[0]?.code).toBe(HEARTBEAT_KEEPALIVE_DISABLED);
    expect(checks[0]?.severity).toBe('warning');
  });

  it('warns when the keepalive delay exceeds the overlay budget', () => {
    const checks = evaluateKeepalive({
      keepAliveEnabled: true,
      initialDelayMs: 120_000,
      pendingAcks: 0,
      state: 'open',
    });
    expect(checks[0]?.code).toBe(HEARTBEAT_KEEPALIVE_DELAY);
  });

  it('detects a closed socket with unacknowledged probes', () => {
    const checks = evaluateKeepalive({
      keepAliveEnabled: false,
      pendingAcks: 2,
      state: 'closed',
    });
    expect(checks.map((check) => check.code)).toContain(HEARTBEAT_UNACKNOWLEDGED_SOCKET);
    expect(checks.find((check) => check.code === HEARTBEAT_UNACKNOWLEDGED_SOCKET)?.severity).toBe(
      'error',
    );
  });

  it('detects a half-open socket whose probes are never acknowledged', () => {
    const checks = evaluateKeepalive(
      {
        keepAliveEnabled: true,
        initialDelayMs: 10_000,
        pendingAcks: 1,
        unacknowledgedSinceMs: 45_000,
        state: 'open',
      },
      { unacknowledgedThresholdMs: 1_000 },
    );
    expect(checks).toHaveLength(1);
    expect(checks[0]?.code).toBe(HEARTBEAT_UNACKNOWLEDGED_SOCKET);
    expect(checks[0]?.message).toContain('45000ms');
  });
});

describe('OverlayHeartbeatWatchdog', () => {
  it('monitors a responsive peer and closes the channel exactly once', async () => {
    const channel = new MockChannel({
      behavior: async () => {
        await sleep(2);
        return Date.now();
      },
    });
    const report = await new OverlayHeartbeatWatchdog({
      timeoutMs: 60,
      intervalMs: 10,
      probeTimeoutMs: 50,
      jitterThresholdMs: 100,
    }).watchChannel(channel);

    expect(report.ok).toBe(true);
    expect(report.connected).toBe(true);
    expect(report.metrics.probesAcknowledged).toBeGreaterThan(0);
    expect(report.metrics.probesMissed).toBe(0);
    expect(report.metrics.meanLatencyMs).toBeGreaterThanOrEqual(0);
    expect(report.closedCleanly).toBe(true);
    expect(report.leakedSockets).toBe(0);
    expect(channel.closeCalls).toBe(1);

    const rendered = renderHeartbeatReport(report);
    expect(rendered).toContain('status: healthy');
    expect(rendered).toContain('probes:');
    expect(rendered).toContain('cleanup: socket closed, 0 leaked');
  });

  it('flags erratic heartbeat latency jitter', async () => {
    let sequence = 0;
    const channel = new MockChannel({
      behavior: async () => {
        sequence++;
        await sleep(sequence % 2 === 0 ? 1 : 20);
        return Date.now();
      },
    });
    const report = await new OverlayHeartbeatWatchdog({
      timeoutMs: 80,
      intervalMs: 5,
      probeTimeoutMs: 100,
      jitterThresholdMs: 1,
    }).watchChannel(channel);

    expect(report.metrics.jitterMs).toBeGreaterThan(1);
    expect(report.metrics.erratic).toBe(true);
    expect(report.warnings.join(' ')).toContain('erratic');
    expect(renderHeartbeatReport(report)).toContain(HEARTBEAT_ERRATIC);
  });

  it('stops after the tolerated number of missed probes', async () => {
    const channel = new MockChannel({
      behavior: () => new Promise<number>(() => {}),
      keepalive: { pendingAcks: 1, unacknowledgedSinceMs: 60_000 },
    });
    const report = await new OverlayHeartbeatWatchdog({
      timeoutMs: 200,
      intervalMs: 5,
      probeTimeoutMs: 5,
      maxMissedProbes: 2,
    }).watchChannel(channel);

    expect(report.ok).toBe(false);
    expect(report.metrics.probesMissed).toBe(2);
    expect(report.metrics.probesAcknowledged).toBe(0);
    expect(report.closedCleanly).toBe(true);
    expect(report.keepaliveChecks.map((check) => check.code)).toContain(
      HEARTBEAT_UNACKNOWLEDGED_SOCKET,
    );
    const rendered = renderHeartbeatReport(report);
    expect(rendered).toContain('status: unresponsive');
    expect(rendered).toContain(HEARTBEAT_UNRESPONSIVE);
    expect(rendered).toContain('fix:');
  });

  it('handles a sudden connection closure without leaking the socket', async () => {
    const channel = new MockChannel({
      behavior: () => Promise.reject(new HeartbeatConnectionClosedError('peer vanished')),
      keepalive: { pendingAcks: 1, state: 'closed', keepAliveEnabled: false },
    });
    const report = await new OverlayHeartbeatWatchdog({ timeoutMs: 100 }).watchChannel(channel);

    expect(report.ok).toBe(false);
    expect(report.suddenClosure).toBe('peer vanished');
    expect(report.probes).toHaveLength(1);
    expect(report.probes[0]?.timedOut).toBe(true);
    expect(report.closedCleanly).toBe(true);
    expect(report.leakedSockets).toBe(0);
    expect(report.keepaliveChecks.map((check) => check.code)).toContain(
      HEARTBEAT_UNACKNOWLEDGED_SOCKET,
    );
    const rendered = renderHeartbeatReport(report);
    expect(rendered).toContain(HEARTBEAT_SUDDEN_CLOSURE);
    expect(rendered).toContain('peer vanished');
  });

  it('continues after a transient probe error and reports a lossy path', async () => {
    let calls = 0;
    const channel = new MockChannel({
      behavior: async () => {
        calls++;
        if (calls === 1) throw new Error('transient write failure');
        return Date.now();
      },
    });
    const report = await new OverlayHeartbeatWatchdog({
      timeoutMs: 60,
      intervalMs: 5,
      probeTimeoutMs: 50,
    }).watchChannel(channel);

    expect(report.metrics.probesAcknowledged).toBeGreaterThan(0);
    expect(report.metrics.probesMissed).toBe(1);
    expect(report.ok).toBe(false);
    expect(report.probes[0]?.error).toBe('transient write failure');
    expect(report.warnings.join(' ')).toContain('were not acknowledged');
  });

  it('reports failed cleanup as a leaked socket', async () => {
    const channel = new MockChannel({
      behavior: async () => Date.now(),
      closeError: new Error('close exploded'),
    });
    const report = await new OverlayHeartbeatWatchdog({
      timeoutMs: 30,
      intervalMs: 5,
      probeTimeoutMs: 20,
    }).watchChannel(channel);

    expect(report.closedCleanly).toBe(false);
    expect(report.leakedSockets).toBe(1);
    expect(report.warnings.join(' ')).toContain('did not close cleanly');
    expect(renderHeartbeatReport(report)).toContain('INCOMPLETE');
  });

  it('reports keepalive misconfiguration as a warning, not a failure', async () => {
    const channel = new MockChannel({
      behavior: async () => Date.now(),
      keepalive: { keepAliveEnabled: false },
    });
    const report = await new OverlayHeartbeatWatchdog({
      timeoutMs: 30,
      intervalMs: 5,
      probeTimeoutMs: 20,
    }).watchChannel(channel);

    expect(report.keepaliveChecks[0]?.code).toBe(HEARTBEAT_KEEPALIVE_DISABLED);
    expect(report.ok).toBe(true);
  });

  it('reports an unreachable endpoint without throwing', async () => {
    const report = await new OverlayHeartbeatWatchdog({
      channelFactory: async () => {
        throw new Error('ECONNREFUSED');
      },
    }).watch(ENDPOINT);

    expect(report.ok).toBe(false);
    expect(report.connected).toBe(false);
    expect(report.probes).toEqual([]);
    expect(report.leakedSockets).toBe(0);
    expect(renderHeartbeatReport(report)).toContain('status: unreachable');
    expect(renderHeartbeatReport(report)).toContain('HOST/PORT');
  });

  it('exposes a stable rule registry', () => {
    expect(overlayHeartbeatRules).toHaveLength(6);
    expect(overlayHeartbeatRuleIds).toContain(HEARTBEAT_UNRESPONSIVE);
    expect(overlayHeartbeatRuleIds).toContain(HEARTBEAT_ERRATIC);
  });
});

interface TestServer {
  port: number;
  close: () => Promise<void>;
}

async function startServer(handler: (socket: Socket) => void): Promise<TestServer> {
  const sockets = new Set<Socket>();
  const server: Server = createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    handler(socket);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('test server has no port');
  return {
    port: address.port,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

function dontHaveResponse(reqHash: Buffer): Buffer {
  const message = xdr.StellarMessage.dontHave(
    new xdr.DontHave({ type: xdr.MessageType.getScpQuorumset(), reqHash }),
  );
  return Buffer.from(frameOverlayMessage(message.toXDR()));
}

describe('TcpHeartbeatChannel', () => {
  const servers: TestServer[] = [];
  afterEach(async () => {
    await Promise.all(servers.splice(0).map((server) => server.close()));
  });

  it('completes a ping/pong exchange and closes idempotently', async () => {
    const server = await startServer((socket) => {
      socket.on('data', (chunk: Buffer) => {
        const message = xdr.StellarMessage.fromXDR(
          Buffer.from(unframeOverlayMessage(new Uint8Array(chunk))),
        );
        socket.write(dontHaveResponse(Buffer.from(message.qSetHash())));
      });
    });
    servers.push(server);

    const channel = await TcpHeartbeatChannel.connect(
      { host: '127.0.0.1', port: server.port },
      { probeTimeoutMs: 500, connectTimeoutMs: 500 },
    );
    expect(channel.keepalive()).toMatchObject({ keepAliveEnabled: true, state: 'open' });
    expect(channel.keepalive().initialDelayMs).toBeGreaterThan(0);

    const acknowledgedAt = await channel.probe(1);
    expect(acknowledgedAt).toBeGreaterThan(0);
    expect(channel.keepalive().pendingAcks).toBe(0);

    await channel.close();
    await channel.close();
    expect(channel.keepalive()).toMatchObject({ state: 'closed', pendingAcks: 0 });
    await expect(channel.probe(2)).rejects.toBeInstanceOf(HeartbeatConnectionClosedError);
  });

  it('surfaces a sudden closure as a connection error', async () => {
    const server = await startServer((socket) => socket.destroy());
    servers.push(server);

    const channel = await TcpHeartbeatChannel.connect(
      { host: '127.0.0.1', port: server.port },
      { probeTimeoutMs: 100, connectTimeoutMs: 500 },
    );
    await expect(channel.probe(1)).rejects.toBeInstanceOf(HeartbeatConnectionClosedError);
    expect(channel.keepalive().state).toBe('closed');
  });

  it('rejects when the overlay port is closed', async () => {
    const server = await startServer(() => {});
    servers.push(server);
    const port = server.port;
    await server.close();
    servers.pop();

    await expect(
      TcpHeartbeatChannel.connect(
        { host: '127.0.0.1', port },
        { probeTimeoutMs: 100, connectTimeoutMs: 500 },
      ),
    ).rejects.toBeInstanceOf(HeartbeatConnectionClosedError);
  });

  it('times out unacknowledged probes', async () => {
    const server = await startServer(() => {});
    servers.push(server);

    const channel = await TcpHeartbeatChannel.connect(
      { host: '127.0.0.1', port: server.port },
      { probeTimeoutMs: 30, connectTimeoutMs: 500 },
    );
    await expect(channel.probe(1)).rejects.toThrow('timed out');
    await channel.close();
  });
});
