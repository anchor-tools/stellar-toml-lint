/**
 * Stellar Core peer connection rate-limiting and flooding defense tester.
 *
 * A publicly reachable overlay port has to survive bursts of TCP connections:
 * it should shed excess connections quickly, recover once the burst ends, keep
 * accepting new peers (a node that leaks file descriptors or crashes under
 * rapid connect/close cycles stops doing so), and never let its throttling
 * starve a legitimate, authenticated peer handshake.
 *
 * The tester checks those properties **without being a load generator**. It
 * is meant for operators testing their own nodes, and every synthetic
 * connection is throttled by hard limits that callers cannot raise:
 *
 * - at most {@link MAX_BURST_CONNECTIONS} connections per burst,
 * - at least {@link MIN_CONNECTION_INTERVAL_MS} between connection attempts
 *   (no more than 50 attempts per second),
 * - accepted sockets are held for a short, bounded time and then closed, and
 * - recovery is polled with single connections at a fixed, slow cadence for a
 *   bounded window.
 *
 * Sequence: a baseline connection and handshake, a paced burst, recovery
 * polling, then a post-burst handshake and connection latency check. The
 * tester tracks every socket it opens and reports how many are still open at
 * the end (always zero unless the platform failed to close one).
 */

import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';
import { OverlayHandshakeTester } from './handshakeTester.js';

/** The overlay port refused or timed out on the baseline connection. */
export const PEER_PORT_UNREACHABLE = 'overlay/peer-port-unreachable';
/** The port stopped accepting connections after the burst and did not recover. */
export const PEER_UNRESPONSIVE_AFTER_BURST = 'overlay/peer-unresponsive-after-burst';
/** The port recovered, but slower than the configured threshold. */
export const PEER_SLOW_RECOVERY = 'overlay/peer-slow-recovery';
/** A legitimate handshake that worked before the burst failed after it. */
export const PEER_HANDSHAKE_DROPPED = 'overlay/peer-handshake-dropped';
/** Connection latency after the burst is far above the baseline. */
export const PEER_LATENCY_DEGRADED = 'overlay/peer-latency-degraded';
/** Every burst connection was accepted; no throttling was observed. */
export const PEER_NO_THROTTLING_OBSERVED = 'overlay/peer-no-throttling-observed';
/** The baseline handshake failed, so handshake preservation was not verified. */
export const PEER_HANDSHAKE_UNVERIFIED = 'overlay/peer-handshake-unverified';

/** Hard cap on connections in one burst. */
export const MAX_BURST_CONNECTIONS = 32;
/** Hard floor on the pause between two connection attempts. */
export const MIN_CONNECTION_INTERVAL_MS = 20;
/** Hard cap on how long an accepted burst socket is held open. */
export const MAX_HOLD_MS = 2000;
/** Hard cap on the recovery polling window. */
export const MAX_RECOVERY_WINDOW_MS = 15000;
/** Pause between recovery polls. */
export const RECOVERY_POLL_INTERVAL_MS = 250;

export const DEFAULT_BURST_CONNECTIONS = 16;
export const DEFAULT_CONNECTION_INTERVAL_MS = 50;
export const DEFAULT_HOLD_MS = 250;
export const DEFAULT_CONNECT_TIMEOUT_MS = 2000;
export const DEFAULT_RECOVERY_WINDOW_MS = 10000;
export const DEFAULT_SLOW_RECOVERY_MS = 3000;
/** Post-burst latency above this multiple of the baseline is degraded. */
export const DEFAULT_LATENCY_DEGRADATION_FACTOR = 5;
/** ...and only when it is also above this absolute floor. */
export const LATENCY_DEGRADATION_FLOOR_MS = 200;

export type ConnectStatus = 'accepted' | 'refused' | 'reset' | 'timeout' | 'error';

/** Outcome of one connection attempt. */
export interface ConnectOutcome {
  status: ConnectStatus;
  latencyMs: number;
  /** Error message for anything but `accepted`. */
  error?: string;
  /** Closes the socket; present only for `accepted`. Must be idempotent. */
  close?: () => void;
}

/** Opens one TCP connection; never rejects. */
export type PeerConnector = (
  host: string,
  port: number,
  timeoutMs: number,
) => Promise<ConnectOutcome>;

/** Performs one legitimate peer handshake; resolves `true` when accepted. */
export type PeerHandshake = (host: string, port: number, timeoutMs: number) => Promise<boolean>;

export interface FloodingTesterOptions {
  rules?: RuleOverrides;
  /** Connections in the burst (1..{@link MAX_BURST_CONNECTIONS}). */
  burst?: number;
  /** Pause between attempts in ms (>= {@link MIN_CONNECTION_INTERVAL_MS}). */
  intervalMs?: number;
  /** How long accepted burst sockets stay open (0..{@link MAX_HOLD_MS}). */
  holdMs?: number;
  connectTimeoutMs?: number;
  /** Recovery polling window (<= {@link MAX_RECOVERY_WINDOW_MS}). */
  recoveryWindowMs?: number;
  /** Recovery slower than this is a warning. */
  slowRecoveryMs?: number;
  /** Replaces the TCP connector (tests). */
  connector?: PeerConnector;
  /** Replaces the overlay HELLO handshake probe (tests). */
  handshake?: PeerHandshake;
  /** Set to `false` to skip the handshake checks. */
  checkHandshake?: boolean;
}

export interface BurstStats {
  attempted: number;
  accepted: number;
  refused: number;
  reset: number;
  timedOut: number;
  errors: number;
  /** Share of attempts that were not accepted (0..1). */
  rejectionRate: number;
  /** 1-based attempt number of the first rejection, if any. */
  firstRejectionAt?: number;
  latencyP50Ms?: number;
  latencyP95Ms?: number;
  latencyMaxMs?: number;
}

export interface FloodingDefenseReport {
  ok: boolean;
  host: string;
  port: number;
  limits: { burst: number; intervalMs: number; holdMs: number; maxAttemptsPerSecond: number };
  baseline: { status: ConnectStatus; latencyMs: number; handshake?: boolean };
  burst: BurstStats;
  recovery: { recovered: boolean; recoveryMs?: number; polls: number };
  postBurst: { latencyMs?: number; handshake?: boolean };
  /** Sockets opened by the tester that were still open at the end. */
  openSockets: number;
  diagnostics: Diagnostic[];
}

/** Minimal slice of `node:net`, declared locally to keep `node:` imports dynamic. */
interface TesterSocket {
  destroy(): void;
  setNoDelay(noDelay?: boolean): void;
  once(event: string, listener: (...args: never[]) => void): this;
  on(event: string, listener: (...args: never[]) => void): this;
}

interface TesterNetModule {
  createConnection(options: { host: string; port: number }): TesterSocket;
}

/** Maps a socket error to a connection outcome. */
export function classifyConnectError(error: Error & { code?: string }): ConnectStatus {
  switch (error.code) {
    case 'ECONNREFUSED':
      return 'refused';
    case 'ECONNRESET':
    case 'EPIPE':
    case 'ECONNABORTED':
      return 'reset';
    case 'ETIMEDOUT':
      return 'timeout';
    default:
      return 'error';
  }
}

/** Default connector: one TCP connection with a hard timeout. */
export const tcpConnector: PeerConnector = async (host, port, timeoutMs) => {
  const netModule = 'node:net';
  const net = (await import(/* @vite-ignore */ netModule)) as TesterNetModule;
  const started = Date.now();
  return new Promise<ConnectOutcome>((resolve) => {
    const socket = net.createConnection({ host, port });
    let settled = false;
    const finish = (outcome: ConnectOutcome) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(outcome);
    };
    const timer = setTimeout(() => {
      socket.destroy();
      finish({ status: 'timeout', latencyMs: Date.now() - started, error: 'connect timed out' });
    }, timeoutMs);
    socket.once('connect', () => {
      socket.setNoDelay(true);
      let closed = false;
      finish({
        status: 'accepted',
        latencyMs: Date.now() - started,
        close: () => {
          if (closed) return;
          closed = true;
          socket.destroy();
        },
      });
    });
    socket.on('error', (error: Error & { code?: string }) => {
      socket.destroy();
      finish({
        status: classifyConnectError(error),
        latencyMs: Date.now() - started,
        error: error.message,
      });
    });
  });
};

/** Default handshake: a full overlay HELLO exchange; accepted when a HELLO comes back. */
export const helloHandshake: PeerHandshake = async (host, port, timeoutMs) => {
  const result = await new OverlayHandshakeTester({ timeoutMs }).testValidatorHandshake({
    publicKey: '',
    host,
    port,
    rawEndpoint: `${host}:${port}`,
  });
  return result.remoteHello !== undefined;
};

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Nearest-rank percentile of a non-empty, ascending list. */
function percentile(sorted: number[], fraction: number): number {
  const index = Math.min(sorted.length - 1, Math.ceil(fraction * sorted.length) - 1);
  return sorted[Math.max(index, 0)] as number;
}

function inRange(name: string, value: number, min: number, max: number): number {
  if (!Number.isFinite(value) || value < min || value > max) {
    throw new RangeError(`${name} must be between ${min} and ${max}, got ${value}`);
  }
  return value;
}

function severityFor(
  rule: string,
  fallback: Severity,
  rules: RuleOverrides | undefined,
): Severity | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override ?? fallback;
}

/** Throttled connection-flooding and rate-limiting defense test. */
export class ConnectionFloodingDefenseTester {
  readonly burst: number;
  readonly intervalMs: number;
  readonly holdMs: number;
  private readonly connectTimeoutMs: number;
  private readonly recoveryWindowMs: number;
  private readonly slowRecoveryMs: number;
  private readonly connector: PeerConnector;
  private readonly handshake: PeerHandshake | undefined;
  private readonly rules: RuleOverrides | undefined;
  private open = 0;

  constructor(options: FloodingTesterOptions = {}) {
    this.burst = inRange(
      'burst',
      options.burst ?? DEFAULT_BURST_CONNECTIONS,
      1,
      MAX_BURST_CONNECTIONS,
    );
    if (!Number.isInteger(this.burst)) throw new RangeError('burst must be an integer');
    this.intervalMs = inRange(
      'intervalMs',
      options.intervalMs ?? DEFAULT_CONNECTION_INTERVAL_MS,
      MIN_CONNECTION_INTERVAL_MS,
      60000,
    );
    this.holdMs = inRange('holdMs', options.holdMs ?? DEFAULT_HOLD_MS, 0, MAX_HOLD_MS);
    this.connectTimeoutMs = inRange(
      'connectTimeoutMs',
      options.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS,
      1,
      30000,
    );
    this.recoveryWindowMs = inRange(
      'recoveryWindowMs',
      options.recoveryWindowMs ?? DEFAULT_RECOVERY_WINDOW_MS,
      0,
      MAX_RECOVERY_WINDOW_MS,
    );
    this.slowRecoveryMs = options.slowRecoveryMs ?? DEFAULT_SLOW_RECOVERY_MS;
    this.connector = options.connector ?? tcpConnector;
    this.handshake =
      options.checkHandshake === false ? undefined : (options.handshake ?? helloHandshake);
    this.rules = options.rules;
  }

  /** Opens one connection, counting it while open. */
  private async connect(host: string, port: number): Promise<ConnectOutcome> {
    const outcome = await this.connector(host, port, this.connectTimeoutMs);
    if (outcome.status !== 'accepted' || outcome.close === undefined) return outcome;
    this.open++;
    const close = outcome.close;
    let closed = false;
    return {
      ...outcome,
      close: () => {
        if (closed) return;
        closed = true;
        this.open--;
        close();
      },
    };
  }

  private async probeHandshake(host: string, port: number): Promise<boolean | undefined> {
    if (this.handshake === undefined) return undefined;
    try {
      return await this.handshake(host, port, this.connectTimeoutMs);
    } catch {
      return false;
    }
  }

  async run(host: string, port: number): Promise<FloodingDefenseReport> {
    if (host.trim() === '') throw new RangeError('host must not be empty');
    inRange('port', port, 1, 65535);
    const diagnostics: Diagnostic[] = [];
    const emit = (rule: string, fallback: Severity, message: string, suggestion: string) => {
      const severity = severityFor(rule, fallback, this.rules);
      if (severity === undefined) return;
      diagnostics.push({
        rule,
        severity,
        category: 'network',
        message,
        path: `${host}:${port}`,
        suggestion,
      });
    };
    const limits = {
      burst: this.burst,
      intervalMs: this.intervalMs,
      holdMs: this.holdMs,
      maxAttemptsPerSecond: Math.floor(1000 / this.intervalMs),
    };
    const emptyBurst: BurstStats = {
      attempted: 0,
      accepted: 0,
      refused: 0,
      reset: 0,
      timedOut: 0,
      errors: 0,
      rejectionRate: 0,
    };

    // 1. Baseline: one connection and, optionally, one handshake.
    const baselineConnection = await this.connect(host, port);
    baselineConnection.close?.();
    if (baselineConnection.status !== 'accepted') {
      emit(
        PEER_PORT_UNREACHABLE,
        'error',
        `Peer port ${host}:${port} did not accept a baseline connection (${baselineConnection.status})`,
        'Check that the overlay port is open and that this host is allowed to connect before testing its defenses.',
      );
      return {
        ok: false,
        host,
        port,
        limits,
        baseline: { status: baselineConnection.status, latencyMs: baselineConnection.latencyMs },
        burst: emptyBurst,
        recovery: { recovered: false, polls: 0 },
        postBurst: {},
        openSockets: this.open,
        diagnostics,
      };
    }
    const baselineHandshake = await this.probeHandshake(host, port);

    // 2. Paced burst: one attempt every intervalMs, each accepted socket held
    // for holdMs and then closed.
    const attempts: Promise<ConnectOutcome>[] = [];
    const holds: Promise<void>[] = [];
    for (let index = 0; index < this.burst; index++) {
      const attempt = this.connect(host, port);
      attempts.push(attempt);
      holds.push(
        attempt.then(async (outcome) => {
          if (outcome.close === undefined) return;
          await sleep(this.holdMs);
          outcome.close();
        }),
      );
      if (index < this.burst - 1) await sleep(this.intervalMs);
    }
    const outcomes = await Promise.all(attempts);
    await Promise.all(holds);

    const count = (status: ConnectStatus) => outcomes.filter((o) => o.status === status).length;
    const rejected = outcomes.findIndex((o) => o.status !== 'accepted');
    const latencies = outcomes
      .filter((o) => o.status === 'accepted')
      .map((o) => o.latencyMs)
      .sort((a, b) => a - b);
    const burst: BurstStats = {
      attempted: outcomes.length,
      accepted: count('accepted'),
      refused: count('refused'),
      reset: count('reset'),
      timedOut: count('timeout'),
      errors: count('error'),
      rejectionRate: (outcomes.length - count('accepted')) / outcomes.length,
      ...(rejected === -1 ? {} : { firstRejectionAt: rejected + 1 }),
      ...(latencies.length === 0
        ? {}
        : {
            latencyP50Ms: percentile(latencies, 0.5),
            latencyP95Ms: percentile(latencies, 0.95),
            latencyMaxMs: latencies.at(-1),
          }),
    };

    // 3. Recovery: single connections at a slow, fixed cadence.
    const recoveryStart = Date.now();
    let recovered = false;
    let polls = 0;
    let postLatency: number | undefined;
    do {
      polls++;
      const probe = await this.connect(host, port);
      probe.close?.();
      if (probe.status === 'accepted') {
        recovered = true;
        postLatency = probe.latencyMs;
        break;
      }
      if (Date.now() - recoveryStart + RECOVERY_POLL_INTERVAL_MS > this.recoveryWindowMs) break;
      await sleep(RECOVERY_POLL_INTERVAL_MS);
    } while (Date.now() - recoveryStart <= this.recoveryWindowMs);
    const recoveryMs = recovered ? Date.now() - recoveryStart : undefined;

    // 4. Legitimate peers must still get through.
    const postHandshake = recovered ? await this.probeHandshake(host, port) : undefined;

    if (!recovered) {
      emit(
        PEER_UNRESPONSIVE_AFTER_BURST,
        'error',
        `Peer port ${host}:${port} stopped accepting connections after a ${burst.attempted}-connection burst and did not recover within ${this.recoveryWindowMs}ms`,
        'Check the node for crashes, file-descriptor exhaustion, or a ban list that also catches legitimate peers.',
      );
    } else if (recoveryMs !== undefined && recoveryMs > this.slowRecoveryMs) {
      emit(
        PEER_SLOW_RECOVERY,
        'warning',
        `Peer port ${host}:${port} took ${recoveryMs}ms to accept connections again after the burst`,
        'Shorten connection back-off or ban windows so that legitimate peers are not locked out.',
      );
    }
    if (baselineHandshake === true && postHandshake === false) {
      emit(
        PEER_HANDSHAKE_DROPPED,
        'error',
        `An authenticated overlay handshake with ${host}:${port} succeeded before the burst but failed after it`,
        'Make sure connection rate limiting runs before authentication only for unknown peers, and keeps reserved slots for preferred peers.',
      );
    }
    if (baselineHandshake === false) {
      emit(
        PEER_HANDSHAKE_UNVERIFIED,
        'info',
        `The baseline overlay handshake with ${host}:${port} failed, so handshake preservation was not verified`,
        'Run the test from a host the node accepts as a peer, or check the node with --check-network first.',
      );
    }
    if (
      postLatency !== undefined &&
      postLatency > baselineConnection.latencyMs * DEFAULT_LATENCY_DEGRADATION_FACTOR &&
      postLatency > LATENCY_DEGRADATION_FLOOR_MS
    ) {
      emit(
        PEER_LATENCY_DEGRADED,
        'warning',
        `Connection latency to ${host}:${port} rose from ${baselineConnection.latencyMs}ms to ${postLatency}ms after the burst`,
        'Check the accept queue (listen backlog) and CPU headroom of the node.',
      );
    }
    if (burst.accepted === burst.attempted) {
      emit(
        PEER_NO_THROTTLING_OBSERVED,
        'info',
        `All ${burst.attempted} burst connections to ${host}:${port} were accepted; no rate limiting was observed at this safe burst size`,
        'This is expected for small bursts; confirm MAX_PENDING_CONNECTIONS and firewall rate limits are configured.',
      );
    }

    return {
      ok: !diagnostics.some((d) => d.severity === 'error'),
      host,
      port,
      limits,
      baseline: {
        status: baselineConnection.status,
        latencyMs: baselineConnection.latencyMs,
        ...(baselineHandshake === undefined ? {} : { handshake: baselineHandshake }),
      },
      burst,
      recovery: { recovered, polls, ...(recoveryMs === undefined ? {} : { recoveryMs }) },
      postBurst: {
        ...(postLatency === undefined ? {} : { latencyMs: postLatency }),
        ...(postHandshake === undefined ? {} : { handshake: postHandshake }),
      },
      openSockets: this.open,
      diagnostics,
    };
  }
}

const handshakeLabel = (value: boolean | undefined) =>
  value === undefined ? 'skipped' : value ? 'accepted' : 'failed';

/** Human-readable report. */
export function renderFloodingDefenseReport(report: FloodingDefenseReport): string {
  const { burst } = report;
  const lines = [
    `Peer defense test ${report.host}:${report.port}`,
    `  limits: ${report.limits.burst} connections, ${report.limits.intervalMs}ms apart (<= ${report.limits.maxAttemptsPerSecond}/s), held ${report.limits.holdMs}ms`,
    `  baseline: ${report.baseline.status} in ${report.baseline.latencyMs}ms, handshake ${handshakeLabel(report.baseline.handshake)}`,
  ];
  if (burst.attempted > 0) {
    lines.push(
      `  burst: ${burst.accepted}/${burst.attempted} accepted, ${burst.refused} refused, ${burst.reset} reset, ${burst.timedOut} timed out, ${burst.errors} errors (rejection ${Math.round(burst.rejectionRate * 100)}%)`,
    );
    if (burst.firstRejectionAt !== undefined) {
      lines.push(`  throttling: first rejection at attempt ${burst.firstRejectionAt}`);
    }
    if (burst.latencyP50Ms !== undefined) {
      lines.push(
        `  accept latency: p50 ${burst.latencyP50Ms}ms, p95 ${burst.latencyP95Ms}ms, max ${burst.latencyMaxMs}ms`,
      );
    }
    lines.push(
      report.recovery.recovered
        ? `  recovery: accepting again after ${report.recovery.recoveryMs}ms (${report.recovery.polls} poll(s)), latency ${report.postBurst.latencyMs}ms, handshake ${handshakeLabel(report.postBurst.handshake)}`
        : `  recovery: NOT recovered after ${report.recovery.polls} poll(s)`,
    );
  }
  lines.push(`  tester sockets left open: ${report.openSockets}`);
  lines.push(`  verdict: ${report.ok ? 'PASS' : 'FAIL'}`);
  return `${lines.join('\n')}\n`;
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const floodingDefenseRules: Rule[] = [
  {
    id: PEER_PORT_UNREACHABLE,
    category: 'network',
    severity: 'error',
    description: 'The advertised overlay peer port must accept connections',
    run() {},
  },
  {
    id: PEER_UNRESPONSIVE_AFTER_BURST,
    category: 'network',
    severity: 'error',
    description: 'An overlay peer port must keep accepting connections after a connection burst',
    run() {},
  },
  {
    id: PEER_SLOW_RECOVERY,
    category: 'network',
    severity: 'warning',
    description: 'An overlay peer port should recover quickly after a connection burst',
    run() {},
  },
  {
    id: PEER_HANDSHAKE_DROPPED,
    category: 'network',
    severity: 'error',
    description: 'Connection rate limiting must not drop legitimate authenticated peer handshakes',
    run() {},
  },
  {
    id: PEER_LATENCY_DEGRADED,
    category: 'network',
    severity: 'warning',
    description: 'Overlay connection latency should not degrade sharply after a connection burst',
    run() {},
  },
  {
    id: PEER_NO_THROTTLING_OBSERVED,
    category: 'network',
    severity: 'info',
    description: 'Reports when no connection throttling was observed during the safe burst',
    run() {},
  },
  {
    id: PEER_HANDSHAKE_UNVERIFIED,
    category: 'network',
    severity: 'info',
    description: 'Reports when handshake preservation could not be verified',
    run() {},
  },
];

export const floodingDefenseRuleIds: readonly string[] = floodingDefenseRules.map(
  (rule) => rule.id,
);
