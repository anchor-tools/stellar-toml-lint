/**
 * Bounded overlay connection-churn tester.
 *
 * This is deliberately a sequential, opt-in probe.  It opens only ten short
 * TCP connections to each published validator, closes every socket as soon as
 * the connection state is known, and then checks that one more peer connection
 * can still be accepted.  It is intended to expose an unsafe listener, not to
 * approximate a volumetric denial-of-service attack.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isHostPort, isString } from '../predicates.js';
import { specUrl } from '../spec.js';

export const OVERLAY_UNPROTECTED_CONNECTION_CHURN = 'overlay/unprotected-connection-churn';
export const OVERLAY_PEER_SOCKET_EXHAUSTION = 'overlay/peer-socket-exhaustion';

export const UNPROTECTED_CONNECTION_CHURN_RULE = OVERLAY_UNPROTECTED_CONNECTION_CHURN;
export const PEER_SOCKET_EXHAUSTION_RULE = OVERLAY_PEER_SOCKET_EXHAUSTION;

export const DEFAULT_DOS_ATTEMPTS = 10;
export const DEFAULT_DOS_TIMEOUT_MS = 2_000;

export type DosAttemptStatus = 'accepted' | 'reset' | 'refused' | 'timeout' | 'error' | 'backoff';

export interface DosAttempt {
  status: DosAttemptStatus;
  durationMs: number;
  error?: string;
}

export type DosProbeResult = DosAttempt | boolean | number;

export type DosProbe = (host: string, port: number, timeoutMs: number) => Promise<DosProbeResult>;

export interface OverlayDosOptions {
  rules?: RuleOverrides;
  attempts?: number;
  timeoutMs?: number;
  probe?: DosProbe;
  /** Separate post-churn probe used to represent an already-authorized peer. */
  authorizedProbe?: DosProbe;
}

export interface OverlayDosResult {
  host: string;
  port: number;
  attempts: DosAttempt[];
  authorizedResponsive: boolean;
  acceptedCount: number;
  throttledCount: number;
  timeoutCount: number;
}

interface ValidatorEndpoint {
  host: string;
  port: number;
  path: string;
}

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules: RuleOverrides | undefined,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function parseHostPort(value: string): { host: string; port: number } | undefined {
  const raw = value.trim();
  if (!isHostPort(raw)) return undefined;
  if (raw.startsWith('[')) {
    const end = raw.indexOf(']');
    if (end < 0) return undefined;
    return { host: raw.slice(1, end), port: Number(raw.slice(end + 2)) };
  }
  const separator = raw.lastIndexOf(':');
  return { host: raw.slice(0, separator), port: Number(raw.slice(separator + 1)) };
}

function validatorEndpoints(doc: Record<string, unknown>): ValidatorEndpoint[] {
  if (!Array.isArray(doc.VALIDATORS)) return [];
  const seen = new Set<string>();
  const endpoints: ValidatorEndpoint[] = [];
  doc.VALIDATORS.forEach((entry, index) => {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) return;
    const hostPort = (entry as Record<string, unknown>).HOST;
    if (!isString(hostPort)) return;
    const parsed = parseHostPort(hostPort);
    if (parsed === undefined || !Number.isInteger(parsed.port)) return;
    const key = `${parsed.host.toLowerCase()}:${parsed.port}`;
    if (seen.has(key)) return;
    seen.add(key);
    endpoints.push({ ...parsed, path: `VALIDATORS[${index}].HOST` });
  });
  return endpoints;
}

function normalizeAttempt(result: DosProbeResult): DosAttempt {
  if (typeof result === 'boolean') {
    return { status: result ? 'accepted' : 'reset', durationMs: 0 };
  }
  if (typeof result === 'number') {
    return {
      status: Number.isFinite(result) ? 'accepted' : 'error',
      durationMs: Number.isFinite(result) ? Math.max(0, result) : 0,
    };
  }
  return {
    status: result.status,
    durationMs: Number.isFinite(result.durationMs) ? Math.max(0, result.durationMs) : 0,
    ...(result.error === undefined ? {} : { error: result.error }),
  };
}

async function defaultDosProbe(host: string, port: number, timeoutMs: number): Promise<DosAttempt> {
  const net = await import('node:net');
  const started = performance.now();
  return new Promise((resolve) => {
    let settled = false;
    const socket = net.createConnection({ host, port });
    const finish = (attempt: DosAttempt): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({
        ...attempt,
        durationMs: Math.max(attempt.durationMs, performance.now() - started),
      });
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish({ status: 'accepted', durationMs: 0 }));
    socket.once('timeout', () => finish({ status: 'timeout', durationMs: timeoutMs }));
    socket.once('error', (error: NodeJS.ErrnoException) => {
      const status: DosAttemptStatus =
        error.code === 'ECONNREFUSED'
          ? 'refused'
          : error.code === 'ECONNRESET'
            ? 'reset'
            : error.code === 'ETIMEDOUT'
              ? 'timeout'
              : 'error';
      finish({ status, durationMs: 0, error: error.message });
    });
  });
}

/** Runs the ten sequential attempts for one validator endpoint. */
export async function testOverlayDos(
  host: string,
  port: number,
  options: OverlayDosOptions = {},
): Promise<OverlayDosResult> {
  const attempts: DosAttempt[] = [];
  const probe = options.probe ?? defaultDosProbe;
  const count = Math.max(1, Math.floor(options.attempts ?? DEFAULT_DOS_ATTEMPTS));
  const timeoutMs = Math.max(1, options.timeoutMs ?? DEFAULT_DOS_TIMEOUT_MS);

  for (let index = 0; index < count; index++) {
    try {
      attempts.push(normalizeAttempt(await probe(host, port, timeoutMs)));
    } catch (error) {
      attempts.push({ status: 'error', durationMs: timeoutMs, error: errorMessage(error) });
    }
  }

  let authorizedResponsive = true;
  const authorized = options.authorizedProbe ?? probe;
  try {
    const response = normalizeAttempt(await authorized(host, port, timeoutMs));
    authorizedResponsive = response.status === 'accepted';
  } catch {
    authorizedResponsive = false;
  }

  return {
    host,
    port,
    attempts,
    authorizedResponsive,
    acceptedCount: attempts.filter((attempt) => attempt.status === 'accepted').length,
    throttledCount: attempts.filter((attempt) =>
      ['reset', 'refused', 'backoff'].includes(attempt.status),
    ).length,
    timeoutCount: attempts.filter((attempt) => attempt.status === 'timeout').length,
  };
}

/** Audits every unique `[[VALIDATORS]].HOST` with the bounded probe. */
export async function checkOverlayDos(
  doc: Record<string, unknown>,
  options: OverlayDosOptions = {},
): Promise<Diagnostic[]> {
  const severityWarning = severityFor(
    OVERLAY_UNPROTECTED_CONNECTION_CHURN,
    'warning',
    options.rules,
  );
  const severityError = severityFor(OVERLAY_PEER_SOCKET_EXHAUSTION, 'error', options.rules);
  if (severityWarning === undefined && severityError === undefined) return [];

  const diagnostics: Diagnostic[] = [];
  for (const endpoint of validatorEndpoints(doc)) {
    const result = await testOverlayDos(endpoint.host, endpoint.port, options);
    const path = endpoint.path;
    const target = `${endpoint.host}:${endpoint.port}`;
    const allAccepted = result.acceptedCount === result.attempts.length;
    const hanging = result.timeoutCount > 0;

    if (severityWarning !== undefined && (allAccepted || hanging)) {
      diagnostics.push({
        rule: OVERLAY_UNPROTECTED_CONNECTION_CHURN,
        severity: severityWarning,
        category: 'network',
        message: allAccepted
          ? `${target} accepted all ${result.attempts.length} sequential overlay connections without reset or backoff`
          : `${target} left ${result.timeoutCount} overlay connection${result.timeoutCount === 1 ? '' : 's'} hanging during churn`,
        path,
        helpUri: specUrl('validator-information'),
        suggestion:
          'Configure an overlay connection limit and bounded handshake timeout so excess peers are reset or backed off promptly.',
      });
    }

    if (
      severityError !== undefined &&
      (!result.authorizedResponsive || result.timeoutCount >= Math.ceil(result.attempts.length / 2))
    ) {
      diagnostics.push({
        rule: OVERLAY_PEER_SOCKET_EXHAUSTION,
        severity: severityError,
        category: 'network',
        message: !result.authorizedResponsive
          ? `${target} did not accept a post-churn authorized peer connection`
          : `${target} timed out ${result.timeoutCount} of ${result.attempts.length} overlay connections, indicating socket exhaustion`,
        path,
        helpUri: specUrl('validator-information'),
        suggestion:
          'Lower MAX_PENDING_CONNECTIONS, enforce handshake timeouts, and verify the node remains responsive after connection churn.',
      });
    }
  }
  return diagnostics;
}

export const auditOverlayDos = checkOverlayDos;
export const runOverlayDosTest = testOverlayDos;

export const overlayDosRules: Rule[] = [
  {
    id: OVERLAY_UNPROTECTED_CONNECTION_CHURN,
    category: 'network',
    severity: 'warning',
    description: 'Overlay listeners should throttle excess sequential connection churn',
    run() {},
  },
  {
    id: OVERLAY_PEER_SOCKET_EXHAUSTION,
    category: 'network',
    severity: 'error',
    description: 'Overlay listeners must remain responsive when peer sockets are saturated',
    run() {},
  },
];

export const overlayDosRuleIds: readonly string[] = overlayDosRules.map((rule) => rule.id);
