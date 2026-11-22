/**
 * TCP keepalive and overlay heartbeat watchdog.
 *
 * Stellar Core keeps an authenticated overlay connection alive by sending a
 * `GET_SCP_QUORUMSET` probe whose 32-byte key is derived from the send time,
 * and by treating the matching `DONT_HAVE` (or `SCP_QUORUMSET`) response as the
 * pong (`Peer::pingPeer` / `maybeProcessPingResponse`). A peer whose socket has
 * been silently dropped by a middlebox never answers, but the TCP socket stays
 * half-open until a keepalive probe fails, so the node burns capacity on a ghost
 * connection and keeps advertising a peer that cannot vote.
 *
 * This watchdog opens a socket with TCP keepalive enabled, sends the same
 * ping-shaped probes on the configured cadence and records every acknowledgement.
 * It reports latency distribution and jitter, flags erratic or unresponsive
 * peers, and — critically for a long-running monitor — closes the socket and
 * clears every timer on all exit paths so a failed probe cannot leak a handle.
 *
 * The channel is pluggable (`HeartbeatChannel`): the default TCP channel speaks
 * the overlay framing and ping/pong message shape, while an operator running an
 * already-authenticated session can supply a channel built on their own
 * handshake. A peer that requires authentication before control messages closes
 * an unauthenticated probe; that is reported as a sudden closure rather than
 * mistaken for an idle connection.
 */

import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { createConnection, type Socket } from 'node:net';
import { xdr } from '@stellar/stellar-base';
import { frameOverlayMessage, unframeOverlayMessage } from './handshakeTester.js';

/** `MessageType::DONT_HAVE` — stellar-core's pong for a probe it cannot serve. */
export const OVERLAY_MESSAGE_DONT_HAVE = 3;
/** `MessageType::GET_SCP_QUORUMSET` — the probe stellar-core uses as a ping. */
export const OVERLAY_MESSAGE_GET_SCP_QUORUMSET = 9;
/** `MessageType::SCP_QUORUMSET` — a served quorum set also completes the ping. */
export const OVERLAY_MESSAGE_SCP_QUORUMSET = 10;

export {
  HEARTBEAT_UNRESPONSIVE,
  HEARTBEAT_ERRATIC,
  HEARTBEAT_KEEPALIVE_DISABLED,
  HEARTBEAT_KEEPALIVE_DELAY,
  HEARTBEAT_UNACKNOWLEDGED_SOCKET,
  HEARTBEAT_SUDDEN_CLOSURE,
  overlayHeartbeatRules,
  overlayHeartbeatRuleIds,
} from './heartbeat-rules.js';
import {
  HEARTBEAT_ERRATIC,
  HEARTBEAT_KEEPALIVE_DISABLED,
  HEARTBEAT_KEEPALIVE_DELAY,
  HEARTBEAT_SUDDEN_CLOSURE,
  HEARTBEAT_UNACKNOWLEDGED_SOCKET,
  HEARTBEAT_UNRESPONSIVE,
} from './heartbeat-rules.js';

/** Default monitoring window, matching the CLI `--timeout` default in seconds. */
export const DEFAULT_HEARTBEAT_TIMEOUT_MS = 10_000;
/** stellar-core probes every five seconds; a second is a safer linter default. */
export const DEFAULT_HEARTBEAT_INTERVAL_MS = 1_000;
/** A socket left idle beyond this is a ghost connection waiting to happen. */
export const DEFAULT_KEEPALIVE_INITIAL_DELAY_MS = 30_000;
/** Jitter above this ratio of the mean latency means responses are erratic. */
export const DEFAULT_JITTER_RATIO = 0.5;

export interface HeartbeatEndpoint {
  host: string;
  port: number;
  /** `[[VALIDATORS]].PUBLIC_KEY`, when the file advertised one. */
  publicKey?: string;
}

/**
 * A live overlay session. Implementations own exactly one socket and must make
 * {@link HeartbeatChannel.close} idempotent.
 */
export interface HeartbeatChannel {
  readonly endpoint: HeartbeatEndpoint;
  /** Sends one probe; resolves with the acknowledgement time in epoch ms. */
  probe(sequence: number): Promise<number>;
  /** Snapshot of TCP keepalive state and outstanding acknowledgements. */
  keepalive(): SocketKeepaliveSnapshot;
  /** Releases the socket and every timer. Safe to call more than once. */
  close(): Promise<void>;
}

export interface SocketKeepaliveSnapshot {
  keepAliveEnabled: boolean;
  initialDelayMs?: number;
  /** Probes written but not yet acknowledged. */
  pendingAcks: number;
  /** How long the oldest outstanding probe has been waiting, in ms. */
  unacknowledgedSinceMs?: number;
  state: 'open' | 'closing' | 'closed';
}

export interface HeartbeatProbe {
  sequence: number;
  sentAt: number;
  acknowledgedAt?: number;
  latencyMs?: number;
  timedOut: boolean;
  error?: string;
}

export interface HeartbeatMetrics {
  probesSent: number;
  probesAcknowledged: number;
  probesMissed: number;
  minLatencyMs?: number;
  maxLatencyMs?: number;
  meanLatencyMs?: number;
  /** Mean absolute difference between consecutive latencies. */
  jitterMs?: number;
  jitterRatio?: number;
  erratic: boolean;
}

export interface KeepaliveCheck {
  code: string;
  severity: 'error' | 'warning';
  message: string;
  suggestion: string;
}

export interface HeartbeatReport {
  endpoint: HeartbeatEndpoint;
  ok: boolean;
  connected: boolean;
  durationMs: number;
  probes: HeartbeatProbe[];
  metrics: HeartbeatMetrics;
  keepalive: SocketKeepaliveSnapshot;
  keepaliveChecks: KeepaliveCheck[];
  warnings: string[];
  suddenClosure?: string;
  /** Always 0 when cleanup succeeded; exposed so monitors can assert it. */
  leakedSockets: number;
  closedCleanly: boolean;
}

export interface HeartbeatWatchdogOptions {
  /** Total monitoring window in milliseconds. */
  timeoutMs?: number;
  /** Delay between probes in milliseconds. */
  intervalMs?: number;
  /** Per-probe acknowledgement deadline in milliseconds. */
  probeTimeoutMs?: number;
  /** Latency jitter above this many ms marks the peer erratic. */
  jitterThresholdMs?: number;
  /** Consecutive missed probes tolerated before the peer is unresponsive. */
  maxMissedProbes?: number;
  /** TCP keepalive idle delay applied to the socket. */
  keepAliveInitialDelayMs?: number;
  /** Transport override used by tests and authenticated sessions. */
  channelFactory?: (endpoint: HeartbeatEndpoint) => Promise<HeartbeatChannel>;
}

/** Thrown when the peer closed the socket while a probe was outstanding. */
export class HeartbeatConnectionClosedError extends Error {
  readonly closure = true;

  constructor(message = 'overlay peer closed the connection') {
    super(message);
    this.name = 'HeartbeatConnectionClosedError';
  }
}

class HeartbeatProbeTimeoutError extends Error {
  constructor() {
    super('overlay heartbeat probe timed out');
    this.name = 'HeartbeatProbeTimeoutError';
  }
}

/**
 * Deterministic probe id, shaped like stellar-core's time-derived
 * `GET_SCP_QUORUMSET` hash. Using the sequence keeps retries distinguishable and
 * makes the mock-peer tests reproducible.
 */
export function heartbeatProbeId(sequence: number): Buffer {
  return createHash('sha256').update(`stellar-toml-lint/heartbeat/v1|${sequence}`).digest();
}

/** Builds the framed ping probe for a sequence. */
export function encodeHeartbeatProbe(sequence: number): Uint8Array {
  return frameOverlayMessage(
    xdr.StellarMessage.getScpQuorumset(heartbeatProbeId(sequence)).toXDR(),
  );
}

/**
 * Extracts the probe id from a frame when it is a pong. Returns `undefined` for
 * frames that are unrelated control traffic, so a peer's HELLO or PEERS cannot
 * be mistaken for a heartbeat acknowledgement.
 */
export function decodeHeartbeatPong(frame: Uint8Array): Buffer | undefined {
  let payload = frame;
  if (frame.length >= 4) {
    const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
    const declared = view.getUint32(0) & 0x7fffffff;
    if (declared > 0 && frame.length === declared + 4) {
      try {
        payload = unframeOverlayMessage(frame);
      } catch {
        payload = frame;
      }
    }
  }

  let message: xdr.StellarMessage;
  try {
    message = xdr.StellarMessage.fromXDR(Buffer.from(payload));
  } catch {
    return undefined;
  }

  const type = message.switch().name;
  if (type === 'dontHave') {
    return Buffer.from(message.dontHave().reqHash());
  }
  if (type === 'scpQuorumset') {
    // stellar-core hashes the served quorum set and matches it against the probe.
    return createHash('sha256').update(message.qSet().toXDR()).digest();
  }
  return undefined;
}

interface PendingProbe {
  id: Buffer;
  sentAt: number;
  resolve: (acknowledgedAt: number) => void;
  reject: (error: Error) => void;
  timer: NodeJS.Timeout;
}

/** Real TCP channel that enables keepalive and speaks the overlay probe shape. */
export class TcpHeartbeatChannel implements HeartbeatChannel {
  readonly endpoint: HeartbeatEndpoint;
  private readonly socket: Socket;
  private readonly pending = new Map<number, PendingProbe>();
  private readonly keepAliveInitialDelayMs: number;
  private readonly probeTimeoutMs: number;
  private buffer: Uint8Array = new Uint8Array(0);
  private closed = false;
  private failure?: Error;

  private constructor(
    socket: Socket,
    endpoint: HeartbeatEndpoint,
    keepAliveInitialDelayMs: number,
    probeTimeoutMs: number,
  ) {
    this.socket = socket;
    this.endpoint = endpoint;
    this.keepAliveInitialDelayMs = keepAliveInitialDelayMs;
    this.probeTimeoutMs = probeTimeoutMs;

    socket.setNoDelay(true);
    socket.setKeepAlive(true, keepAliveInitialDelayMs);
    socket.on('data', (chunk: Buffer) => this.onData(chunk));
    // Once connected, any socket error means the session is gone. Linux usually
    // reports a peer that drops the connection as a plain close, while macOS and
    // Windows surface the same event as ECONNRESET; both are a sudden closure.
    socket.on('error', (error: Error) =>
      this.fail(
        new HeartbeatConnectionClosedError(
          `overlay connection to ${endpoint.host}:${endpoint.port} failed: ${error.message}`,
        ),
      ),
    );
    socket.on('close', () => this.fail(new HeartbeatConnectionClosedError()));
    // A socket that only exists to be probed must never hold the process open.
    socket.unref();
  }

  /** Opens the TCP session. Rejects on connect failure or timeout. */
  static connect(
    endpoint: HeartbeatEndpoint,
    options: {
      keepAliveInitialDelayMs?: number;
      probeTimeoutMs?: number;
      connectTimeoutMs?: number;
    } = {},
  ): Promise<TcpHeartbeatChannel> {
    const keepAliveInitialDelayMs =
      options.keepAliveInitialDelayMs ?? DEFAULT_KEEPALIVE_INITIAL_DELAY_MS;
    const probeTimeoutMs = options.probeTimeoutMs ?? DEFAULT_HEARTBEAT_INTERVAL_MS * 2;
    const connectTimeoutMs = options.connectTimeoutMs ?? probeTimeoutMs;

    return new Promise<TcpHeartbeatChannel>((resolve, reject) => {
      const socket = createConnection({ host: endpoint.host, port: endpoint.port });
      let settled = false;
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        socket.destroy();
        reject(
          new HeartbeatConnectionClosedError(
            `overlay connection to ${endpoint.host}:${endpoint.port} timed out after ${connectTimeoutMs}ms`,
          ),
        );
      }, connectTimeoutMs);
      timer.unref();

      socket.once('connect', () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.removeAllListeners('error');
        resolve(new TcpHeartbeatChannel(socket, endpoint, keepAliveInitialDelayMs, probeTimeoutMs));
      });
      socket.once('error', (error: Error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.destroy();
        reject(
          new HeartbeatConnectionClosedError(
            `overlay connection to ${endpoint.host}:${endpoint.port} failed: ${error.message}`,
          ),
        );
      });
    });
  }

  probe(sequence: number): Promise<number> {
    if (this.closed) {
      return Promise.reject(this.failure ?? new HeartbeatConnectionClosedError());
    }
    return new Promise<number>((resolve, reject) => {
      const id = heartbeatProbeId(sequence);
      const timer = setTimeout(() => {
        this.pending.delete(sequence);
        reject(new HeartbeatProbeTimeoutError());
      }, this.probeTimeoutMs);
      timer.unref();
      this.pending.set(sequence, { id, sentAt: Date.now(), resolve, reject, timer });

      try {
        this.socket.write(Buffer.from(encodeHeartbeatProbe(sequence)));
      } catch (error) {
        clearTimeout(timer);
        this.pending.delete(sequence);
        reject(error instanceof Error ? error : new Error(String(error)));
      }
    });
  }

  keepalive(): SocketKeepaliveSnapshot {
    const oldest = [...this.pending.values()].reduce<PendingProbe | undefined>(
      (earliest, probe) =>
        earliest === undefined || probe.sentAt < earliest.sentAt ? probe : earliest,
      undefined,
    );
    const snapshot: SocketKeepaliveSnapshot = {
      keepAliveEnabled: !this.closed,
      pendingAcks: this.pending.size,
      state: this.closed ? 'closed' : 'open',
    };
    if (!this.closed) snapshot.initialDelayMs = this.keepAliveInitialDelayMs;
    if (oldest !== undefined) snapshot.unacknowledgedSinceMs = Date.now() - oldest.sentAt;
    return snapshot;
  }

  close(): Promise<void> {
    this.fail(new HeartbeatConnectionClosedError('overlay heartbeat channel closed'));
    return Promise.resolve();
  }

  private onData(chunk: Buffer): void {
    if (this.closed) return;
    const combined = Buffer.concat([Buffer.from(this.buffer), chunk]);
    this.buffer = combined;

    while (this.buffer.length >= 4) {
      const frame = Buffer.from(this.buffer);
      const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
      const length = view.getUint32(0) & 0x7fffffff;
      if (length === 0 || frame.length < length + 4) return;
      const bytes = frame.subarray(0, length + 4);
      this.buffer = frame.subarray(length + 4);
      this.acknowledge(decodeHeartbeatPong(bytes));
    }
  }

  private acknowledge(id: Buffer | undefined): void {
    if (id === undefined) return;
    for (const [sequence, pending] of this.pending) {
      if (!pending.id.equals(id)) continue;
      clearTimeout(pending.timer);
      this.pending.delete(sequence);
      pending.resolve(Date.now());
      return;
    }
  }

  /** Fails every outstanding probe exactly once and releases the socket. */
  private fail(error: Error): void {
    if (this.closed) return;
    this.closed = true;
    this.failure = error;
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(error);
    }
    this.pending.clear();
    this.socket.removeAllListeners();
    if (!this.socket.destroyed) this.socket.destroy();
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    timer.unref();
  });
}

function withProbeTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new HeartbeatProbeTimeoutError()), ms);
    timer.unref();
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error instanceof Error ? error : new Error(String(error)));
      },
    );
  });
}

/**
 * Evaluates a socket's keepalive configuration and outstanding probes. The
 * middlebox failure mode this catches is a socket that still looks open while
 * probes go unacknowledged: by the time TCP itself notices, the peer has been
 * unreachable for minutes.
 */
export function evaluateKeepalive(
  snapshot: SocketKeepaliveSnapshot,
  options: { unacknowledgedThresholdMs?: number; maxInitialDelayMs?: number } = {},
): KeepaliveCheck[] {
  const checks: KeepaliveCheck[] = [];
  const maxInitialDelayMs = options.maxInitialDelayMs ?? DEFAULT_KEEPALIVE_INITIAL_DELAY_MS;
  const unacknowledgedThresholdMs =
    options.unacknowledgedThresholdMs ?? DEFAULT_KEEPALIVE_INITIAL_DELAY_MS;

  if (!snapshot.keepAliveEnabled) {
    checks.push({
      code: HEARTBEAT_KEEPALIVE_DISABLED,
      severity: 'warning',
      message: 'TCP keepalive is not enabled; a silently dropped path can leave a ghost socket',
      suggestion: 'Enable SO_KEEPALIVE on the overlay socket so an idle peer is eventually reaped.',
    });
  } else if ((snapshot.initialDelayMs ?? 0) > maxInitialDelayMs) {
    checks.push({
      code: HEARTBEAT_KEEPALIVE_DELAY,
      severity: 'warning',
      message: `TCP keepalive initial delay is ${snapshot.initialDelayMs}ms, above the ${maxInitialDelayMs}ms overlay budget`,
      suggestion: `Lower the keepalive delay to ${maxInitialDelayMs}ms or less so dead peers are detected promptly.`,
    });
  }

  if (snapshot.state === 'closed' && snapshot.pendingAcks > 0) {
    checks.push({
      code: HEARTBEAT_UNACKNOWLEDGED_SOCKET,
      severity: 'error',
      message: `${snapshot.pendingAcks} heartbeat probe(s) were left unacknowledged when the socket closed`,
      suggestion:
        'Treat the peer as offline, remove it from routing, and reconnect from a fresh session.',
    });
  } else if (
    snapshot.pendingAcks > 0 &&
    (snapshot.unacknowledgedSinceMs ?? 0) >= unacknowledgedThresholdMs
  ) {
    checks.push({
      code: HEARTBEAT_UNACKNOWLEDGED_SOCKET,
      severity: 'error',
      message: `${snapshot.pendingAcks} heartbeat probe(s) unacknowledged for ${snapshot.unacknowledgedSinceMs}ms`,
      suggestion:
        'The socket looks open but the peer is not answering; check the firewall/NAT path and drop the session before it is advertised again.',
    });
  }

  return checks;
}

function computeMetrics(
  probes: readonly HeartbeatProbe[],
  jitterThresholdMs: number | undefined,
  suddenClosure: string | undefined,
): HeartbeatMetrics {
  const latencies = probes
    .filter(
      (probe): probe is HeartbeatProbe & { latencyMs: number } => probe.latencyMs !== undefined,
    )
    .map((probe) => probe.latencyMs);
  const missed = probes.length - latencies.length;
  const metrics: HeartbeatMetrics = {
    probesSent: probes.length,
    probesAcknowledged: latencies.length,
    probesMissed: missed,
    erratic: missed > 0 || suddenClosure !== undefined,
  };
  if (latencies.length === 0) return metrics;

  const min = Math.min(...latencies);
  const max = Math.max(...latencies);
  const mean = latencies.reduce((total, value) => total + value, 0) / latencies.length;
  metrics.minLatencyMs = min;
  metrics.maxLatencyMs = max;
  metrics.meanLatencyMs = mean;

  if (latencies.length > 1) {
    let jitterTotal = 0;
    for (let index = 1; index < latencies.length; index++) {
      jitterTotal += Math.abs((latencies[index] as number) - (latencies[index - 1] as number));
    }
    const jitter = jitterTotal / (latencies.length - 1);
    metrics.jitterMs = jitter;
    metrics.jitterRatio = mean === 0 ? 0 : jitter / mean;
    if (jitterThresholdMs !== undefined && jitter > jitterThresholdMs) metrics.erratic = true;
  }

  return metrics;
}

/** Reports whether a set of probes never produced a single acknowledgement. */
function isUnresponsive(probes: readonly HeartbeatProbe[]): boolean {
  return probes.length > 0 && probes.every((probe) => probe.latencyMs === undefined);
}

/**
 * Monitors one overlay session. The channel is always closed in `finally`, even
 * when a probe throws, so the report's `leakedSockets` is 0 on every path and
 * monitoring cannot keep the event loop alive.
 */
export class OverlayHeartbeatWatchdog {
  readonly options: HeartbeatWatchdogOptions;

  constructor(options: HeartbeatWatchdogOptions = {}) {
    this.options = options;
  }

  /** Connects to the endpoint and monitors it. */
  async watch(endpoint: HeartbeatEndpoint): Promise<HeartbeatReport> {
    const timeoutMs = this.options.timeoutMs ?? DEFAULT_HEARTBEAT_TIMEOUT_MS;
    const intervalMs = this.options.intervalMs ?? DEFAULT_HEARTBEAT_INTERVAL_MS;
    const probeTimeoutMs = this.options.probeTimeoutMs ?? Math.min(intervalMs * 2, timeoutMs);

    let channel: HeartbeatChannel;
    try {
      channel =
        this.options.channelFactory !== undefined
          ? await this.options.channelFactory(endpoint)
          : await TcpHeartbeatChannel.connect(endpoint, {
              keepAliveInitialDelayMs:
                this.options.keepAliveInitialDelayMs ?? DEFAULT_KEEPALIVE_INITIAL_DELAY_MS,
              probeTimeoutMs,
              connectTimeoutMs: Math.min(probeTimeoutMs, timeoutMs),
            });
    } catch (error) {
      return this.connectionFailureReport(endpoint, error);
    }

    return this.watchChannel(channel, endpoint);
  }

  /** Monitors an already-open channel; used by tests and authenticated sessions. */
  async watchChannel(
    channel: HeartbeatChannel,
    endpoint: HeartbeatEndpoint = channel.endpoint,
  ): Promise<HeartbeatReport> {
    const timeoutMs = this.options.timeoutMs ?? DEFAULT_HEARTBEAT_TIMEOUT_MS;
    const intervalMs = this.options.intervalMs ?? DEFAULT_HEARTBEAT_INTERVAL_MS;
    const probeTimeoutMs =
      this.options.probeTimeoutMs ?? Math.min(Math.max(intervalMs * 2, 1), timeoutMs);
    const maxMissedProbes = this.options.maxMissedProbes ?? 2;
    const startedAt = Date.now();
    const deadline = startedAt + timeoutMs;
    const probes: HeartbeatProbe[] = [];
    const warnings: string[] = [];
    let suddenClosure: string | undefined;
    let channelClosed = false;
    let beforeClose: SocketKeepaliveSnapshot;
    let closedCleanly: boolean;

    try {
      while (Date.now() < deadline) {
        const sequence = probes.length + 1;
        const sentAt = Date.now();
        try {
          const acknowledgedAt = await withProbeTimeout(
            channel.probe(sequence),
            Math.min(probeTimeoutMs, Math.max(1, deadline - Date.now())),
          );
          probes.push({
            sequence,
            sentAt,
            acknowledgedAt,
            latencyMs: Math.max(0, acknowledgedAt - sentAt),
            timedOut: false,
          });
        } catch (error) {
          if (error instanceof HeartbeatConnectionClosedError) {
            suddenClosure = error.message;
            probes.push({
              sequence,
              sentAt,
              timedOut: true,
              error: error.message,
            });
            break;
          }
          if (error instanceof HeartbeatProbeTimeoutError) {
            probes.push({ sequence, sentAt, timedOut: true, error: 'probe timed out' });
            if (probes.filter((probe) => probe.latencyMs === undefined).length >= maxMissedProbes) {
              break;
            }
          } else {
            probes.push({
              sequence,
              sentAt,
              timedOut: true,
              error: error instanceof Error ? error.message : String(error),
            });
          }
        }
        const remaining = deadline - Date.now();
        if (remaining <= 0) break;
        await sleep(Math.min(intervalMs, remaining));
      }
    } finally {
      beforeClose = channel.keepalive();
      try {
        await channel.close();
        channelClosed = true;
      } catch (error) {
        warnings.push(
          `heartbeat channel did not close cleanly: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
      }
      const afterClose = channel.keepalive();
      closedCleanly =
        channelClosed && afterClose.state === 'closed' && afterClose.pendingAcks === 0;
    }

    const metrics = computeMetrics(probes, this.options.jitterThresholdMs, suddenClosure);
    const keepaliveChecks = evaluateKeepalive(beforeClose);

    if (isUnresponsive(probes)) {
      warnings.push(
        'No heartbeat was acknowledged: the advertised validator is unreachable or requires an authenticated overlay session.',
      );
    }
    if (suddenClosure !== undefined) {
      warnings.push(
        `Connection closed during monitoring (${suddenClosure}); treat the peer as offline and reconnect cleanly.`,
      );
    }
    if (metrics.probesMissed > 0 && !isUnresponsive(probes)) {
      warnings.push(
        `${metrics.probesMissed} of ${metrics.probesSent} probes were not acknowledged; the path is lossy or the peer is overloaded.`,
      );
    }
    if (metrics.erratic && metrics.jitterMs !== undefined) {
      warnings.push(
        `Heartbeat jitter is ${metrics.jitterMs.toFixed(1)}ms against a ${metrics.meanLatencyMs?.toFixed(1)}ms mean; responses are erratic.`,
      );
    }
    if (!closedCleanly) {
      warnings.push('Heartbeat socket cleanup left an outstanding acknowledgement.');
    }

    const ok =
      probes.some((probe) => probe.latencyMs !== undefined) &&
      suddenClosure === undefined &&
      closedCleanly &&
      metrics.probesMissed === 0 &&
      !keepaliveChecks.some((check) => check.severity === 'error');

    return {
      endpoint,
      ok,
      connected: true,
      durationMs: Date.now() - startedAt,
      probes,
      metrics,
      keepalive: beforeClose,
      keepaliveChecks,
      warnings,
      ...(suddenClosure === undefined ? {} : { suddenClosure }),
      leakedSockets: closedCleanly ? 0 : 1,
      closedCleanly,
    };
  }

  private connectionFailureReport(endpoint: HeartbeatEndpoint, error: unknown): HeartbeatReport {
    const text = error instanceof Error ? error.message : String(error);
    return {
      endpoint,
      ok: false,
      connected: false,
      durationMs: 0,
      probes: [],
      metrics: {
        probesSent: 0,
        probesAcknowledged: 0,
        probesMissed: 0,
        erratic: true,
      },
      keepalive: { keepAliveEnabled: false, pendingAcks: 0, state: 'closed' },
      keepaliveChecks: [],
      warnings: [`Could not open an overlay session: ${text}`],
      leakedSockets: 0,
      closedCleanly: true,
    };
  }
}

/** Human-readable terminal report with operator guidance. */
export function renderHeartbeatReport(report: HeartbeatReport): string {
  const { endpoint, metrics } = report;
  const label = `${endpoint.host}:${endpoint.port}`;
  const lines: string[] = [];
  lines.push(
    `Overlay heartbeat: ${label}${endpoint.publicKey === undefined ? '' : ` (${endpoint.publicKey})`}`,
  );
  if (!report.connected) {
    lines.push(`  status: unreachable (${report.warnings.join('; ')})`);
    lines.push(
      '  next: verify HOST/PORT in [[VALIDATORS]] and that 11625 is open to your probe host.',
    );
    return `${lines.join('\n')}\n`;
  }

  const status = !report.ok
    ? isUnresponsive(report.probes)
      ? 'unresponsive'
      : 'degraded'
    : 'healthy';
  lines.push(`  status: ${status}`);
  lines.push(
    `  probes: ${metrics.probesSent} sent, ${metrics.probesAcknowledged} acknowledged, ${metrics.probesMissed} missed`,
  );
  if (metrics.meanLatencyMs !== undefined) {
    lines.push(
      `  latency: min ${metrics.minLatencyMs?.toFixed(1)}ms, mean ${metrics.meanLatencyMs.toFixed(
        1,
      )}ms, max ${metrics.maxLatencyMs?.toFixed(1)}ms`,
    );
    lines.push(
      `  jitter: ${metrics.jitterMs === undefined ? 'n/a' : `${metrics.jitterMs.toFixed(1)}ms`}${
        metrics.jitterRatio === undefined
          ? ''
          : ` (${(metrics.jitterRatio * 100).toFixed(1)}% of mean)`
      }`,
    );
  }
  lines.push(
    `  keepalive: ${report.keepalive.keepAliveEnabled ? 'enabled' : 'disabled'}` +
      (report.keepalive.initialDelayMs === undefined
        ? ''
        : `, initial delay ${report.keepalive.initialDelayMs}ms`),
  );
  lines.push(
    `  cleanup: ${report.closedCleanly ? 'socket closed, 0 leaked' : 'INCOMPLETE — inspect open sockets'}`,
  );

  for (const check of report.keepaliveChecks) {
    lines.push(`  ${check.severity}  ${check.code}  ${check.message}`);
    lines.push(`         fix: ${check.suggestion}`);
  }
  for (const warning of report.warnings) lines.push(`  warning  ${warning}`);

  if (report.metrics.erratic) {
    lines.push(
      `  ${HEARTBEAT_ERRATIC}  Heartbeat responses are erratic; do not route consensus traffic through this peer until latency is stable.`,
    );
  }
  if (isUnresponsive(report.probes)) {
    lines.push(
      `  ${HEARTBEAT_UNRESPONSIVE}  No pong received within ${report.durationMs}ms; remove the peer from rotation and re-check its overlay port.`,
    );
  }
  if (report.suddenClosure !== undefined) {
    lines.push(
      `  ${HEARTBEAT_SUDDEN_CLOSURE}  The socket closed mid-probe; check middlebox idle timeouts and the peer's logs before reconnecting.`,
    );
  }
  return `${lines.join('\n')}\n`;
}
