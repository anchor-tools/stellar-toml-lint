/**
 * Stellar overlay peer-port reachability probe for `[[VALIDATORS]].HOST`.
 *
 * In SEP-20 a validator publishes `HOST = "<host>:<port>"` (e.g.
 * `core.example.com:11625`), and that is the address every peer stellar-core
 * node dials over the overlay network to exchange nomination and ballot
 * messages. A typo'd port, a closed firewall, a NAT that was never forwarded,
 * or an inactive stellar-core process all leave the file looking perfect while
 * no peer can ever connect — the kind of failure the syntax rule
 * (`validators/host`) cannot see because the string matches `host:port` just
 * fine.
 *
 * Runs only under opt-in `--check-network`. A refused or timed-out connection
 * emits `validators/peer-port-unreachable` (warning): the file itself is not
 * wrong, the deployment behind it is, so the finding never fails the lint run
 * on its own. A host that cannot be *resolved* is left to the other checks —
 * DNS health is not this probe's question — and both rule overrides
 * (`--off` / `--error` / `--warn`) and the caller's transport are honoured the
 * same way every other network audit here strikes the bargain.
 */
import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';
import { isHostPort, isString } from '../predicates.js';
import { specUrl } from '../spec.js';

/** How long to wait for a TCP handshake before declaring the port unreachable. */
export const DEFAULT_PROBE_TIMEOUT_MS = 5_000;

/** The rule id the issue names; emitted by {@link checkPeerPortReachability}. */
export const PEER_PORT_UNREACHABLE_RULE = 'validators/peer-port-unreachable';

/**
 * Opens one TCP connection and resolves whether the handshake succeeded.
 * Never rejects: a probe failure is an observation (`false`), not an error.
 */
export type TcpPortProbe = (host: string, port: number, timeoutMs: number) => Promise<boolean>;

/**
 * The default probe: one raw TCP connection with a hard timeout.
 *
 * `node:net` is loaded lazily for the same reason `tls.ts` and
 * `network/cert-expiry.ts` load their built-ins that way: this module sits in
 * the shared rule registry the browser bundle walks, and a static import would
 * drag a Node built-in into every browser build. A browser (or any socket
 * failure) reports "unreachable", never a guess — and the socket is destroyed
 * on every path so a lint run cannot leak handles.
 */
export const defaultTcpProbe: TcpPortProbe = async (host, port, timeoutMs) => {
  const net = await import('node:net').catch(() => null);
  if (net === null) return false;

  return new Promise((resolve) => {
    let settled = false;
    const socket = net.createConnection({ host, port });

    const settle = (reachable: boolean): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(reachable);
    };

    socket.setTimeout(timeoutMs);
    socket.once('connect', () => settle(true));
    socket.once('timeout', () => settle(false));
    socket.once('error', () => settle(false));
  });
};

/**
 * Extracts the `host:port` pairs every `[[VALIDATORS]]` entry declares.
 *
 * Malformed entries are skipped: the offline `validators/host` rule already
 * reports them with a position, and this probe only judges addresses the
 * linter accepts as syntactically valid. Like the certificate audit, the list
 * is deduplicated so two validators publishing the same peer address are
 * probed once.
 */
export function validatorHostsOf(
  doc: Record<string, unknown>,
): { host: string; port: number; path: string }[] {
  const list = doc.VALIDATORS;
  if (!Array.isArray(list)) return [];

  const hosts: { host: string; port: number; path: string }[] = [];
  const seen = new Set<string>();

  list.forEach((entry, index) => {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) return;
    const value = (entry as Record<string, unknown>).HOST;
    if (!isString(value) || !isHostPort(value)) return;

    const at = value.lastIndexOf(':');
    const host = value.slice(0, at);
    const port = Number(value.slice(at + 1));
    const key = `${host}:${port}`;
    if (seen.has(key)) return;
    seen.add(key);
    hosts.push({ host, port, path: `VALIDATORS[${index}].HOST` });
  });

  return hosts;
}

/** Severity for the rule, or `undefined` when switched off. */
function severityFor(
  rules: RuleOverrides | undefined,
  fallback: Severity = 'warning',
): Severity | undefined {
  const override = rules?.[PEER_PORT_UNREACHABLE_RULE];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' || override === 'info'
    ? override
    : fallback;
}

/**
 * The rule object behind the peer-port probe.
 *
 * `run()` is empty like every other network-bound rule's: the diagnostics are
 * emitted by the async {@link checkPeerPortReachability}, and this entry
 * exists so `--list-rules` and `--off`/`--warn`/`--error` know the id.
 */
export const peerPortRule: Rule = {
  id: PEER_PORT_UNREACHABLE_RULE,
  category: 'validators',
  severity: 'warning',
  description: 'A declared validator HOST port should accept TCP connections from peers',
  run() {},
};

/**
 * Probes one peer address. Thin over {@link defaultTcpProbe} so callers (and
 * tests) can inject a transport — the same seam every network audit here exposes.
 */
export async function probeTcpPort(
  host: string,
  port: number,
  timeoutMs: number = DEFAULT_PROBE_TIMEOUT_MS,
  probe: TcpPortProbe = defaultTcpProbe,
): Promise<boolean> {
  return probe(host, port, timeoutMs);
}

/**
 * Audits the overlay reachability of every `[[VALIDATORS]].HOST` the file
 * declares.
 *
 * A port that refuses connections or does not answer within the timeout emits
 * `validators/peer-port-unreachable` (warning) naming the host:port, so the
 * operator hears about the firewall before the network does. The check never
 * terminates the lint run: probe failures are findings, not errors, and every
 * socket error is swallowed into an observation.
 */
export async function checkPeerPortReachability(
  doc: Record<string, unknown>,
  options: {
    rules?: RuleOverrides;
    probe?: TcpPortProbe;
    /** Per-probe timeout in milliseconds. Default 5000. */
    timeoutMs?: number;
  } = {},
): Promise<Diagnostic[]> {
  const hosts = validatorHostsOf(doc);
  if (hosts.length === 0) return [];

  // Nothing to report when the rule is off — and no reason to open sockets.
  const severity = severityFor(options.rules);
  if (severity === undefined) return [];

  const probe = options.probe ?? defaultTcpProbe;
  const timeoutMs = options.timeoutMs ?? DEFAULT_PROBE_TIMEOUT_MS;
  const diagnostics: Diagnostic[] = [];

  for (const { host, port, path } of hosts) {
    // A probe that throws (an exotic transport, a runtime without sockets)
    // degrades to "unreachable" rather than terminating the lint run.
    const reachable = await probe(host, port, timeoutMs).catch(() => false);
    if (reachable) continue;

    diagnostics.push({
      rule: PEER_PORT_UNREACHABLE_RULE,
      severity,
      category: 'validators',
      message: `Validator peer port ${host}:${port} did not accept a TCP connection`,
      path,
      helpUri: specUrl('validator-information'),
      suggestion:
        'Peers dial this address over the Stellar overlay — check the firewall/NAT forwarding for ' +
        `${port} and that stellar-core is running and listening on it.`,
    });
  }

  return diagnostics;
}
