/**
 * IPv6 dual-stack connectivity and DNS AAAA record auditor (issue #383).
 *
 * Mobile networks globally are migrating to IPv6-only access, reaching the
 * IPv4 internet through DNS64/NAT64 gateways. A wallet on such a network can
 * only connect to an anchor endpoint that publishes a DNS AAAA record and
 * accepts a TCP connection over native IPv6; an endpoint with only an A record
 * is unreachable, and an AAAA record whose IPv6 socket never answers is worse,
 * because the failure surfaces as a hang rather than an immediate error.
 *
 * This auditor resolves AAAA records for the anchor domain and every declared
 * service endpoint, then dials each resolved IPv6 address over TCP:
 *
 * - a host with no AAAA record emits `network/missing-ipv6-aaaa-record`
 *   (warning) — the endpoint is invisible to IPv6-only clients.
 * - a host whose AAAA address accepts no connection before the probe timeout
 *   emits `network/ipv6-connection-timeout` (error) — the address exists but
 *   the socket hangs, which strands DNS64 clients mid-request.
 * - any other connection failure (refused, unreachable) emits
 *   `network/ipv6-connection-failed` (warning).
 *
 * Runs only under the opt-in `--check-network --check-ipv6` flags. DNS and
 * socket failures that cannot distinguish "broken endpoint" from "broken
 * resolver" degrade to silence, so the check never invents a finding it cannot
 * observe.
 */
import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';
import { HTTPS_ENDPOINT_FIELDS } from '../spec.js';
import { hostOf, isString } from '../predicates.js';

export const MISSING_IPV6_AAAA_RULE = 'network/missing-ipv6-aaaa-record';
export const IPV6_CONNECTION_TIMEOUT_RULE = 'network/ipv6-connection-timeout';
export const IPV6_CONNECTION_FAILED_RULE = 'network/ipv6-connection-failed';

/** How long a single TCP dial may take before it counts as a timeout. */
const DEFAULT_TIMEOUT_MS = 5_000;

/** The result of resolving AAAA records for one host. */
export type Ipv6LookupResult =
  | { kind: 'ok'; addresses: string[] }
  | { kind: 'none' }
  | { kind: 'error'; detail: string };

/** Resolves the IPv6 addresses a hostname publishes. Injectable for tests. */
export type Ipv6Resolver = (hostname: string) => Promise<Ipv6LookupResult>;

/** The outcome of one TCP dial to an IPv6 address. */
export type Ipv6ConnectionResult =
  | { kind: 'connected' }
  | { kind: 'timeout' }
  | { kind: 'refused' }
  | { kind: 'error'; detail: string };

/** Dials one IPv6 address and reports how the connection ended. */
export type Ipv6Connector = (address: string, port: number, timeoutMs: number) => Promise<Ipv6ConnectionResult>;

export interface Ipv6AuditorOptions {
  rules?: RuleOverrides;
  /**
   * The domain the file is served from. Checked alongside every host declared
   * in the file, since a wallet reaches the file itself over IPv6 too.
   */
  domain?: string;
  /** AAAA resolver override, primarily for tests. */
  resolve?: Ipv6Resolver;
  /** TCP connector override, primarily for tests. */
  connect?: Ipv6Connector;
  /** Timeout for each TCP dial, in milliseconds. */
  timeoutMs?: number;
}

/** Rule objects behind the audit, registered for `--list-rules` and overrides. */
export const ipv6AuditorRules: Rule[] = [
  {
    id: MISSING_IPV6_AAAA_RULE,
    category: 'network',
    severity: 'warning',
    description:
      'A declared endpoint host should publish a DNS AAAA record for IPv6-only clients',
    run() {},
  },
  {
    id: IPV6_CONNECTION_TIMEOUT_RULE,
    category: 'network',
    severity: 'error',
    description: 'A host with an AAAA record must accept a TCP connection over IPv6 within the timeout',
    run() {},
  },
  {
    id: IPV6_CONNECTION_FAILED_RULE,
    category: 'network',
    severity: 'warning',
    description: 'An AAAA-record IPv6 address should accept a TCP connection',
    run() {},
  },
];

export const ipv6AuditorRuleIds: readonly string[] = ipv6AuditorRules.map((rule) => rule.id);

function severityFor(
  rule: string,
  fallback: Severity,
  rules: RuleOverrides | undefined,
): Severity | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' || override === 'info' ? override : fallback;
}

/** One host to probe, with the TOML field that named it. */
interface Ipv6Target {
  host: string;
  port: number;
  path: string;
}

/**
 * Every host the file points clients at, deduplicated by host and port.
 *
 * The `--domain` the file was fetched from is included first: IPv6-only
 * clients must be able to download `/.well-known/stellar.toml` itself before
 * any service endpoint matters.
 */
export function ipv6TargetsOf(
  doc: Record<string, unknown>,
  domain?: string,
): Ipv6Target[] {
  const targets: Ipv6Target[] = [];
  const seen = new Set<string>();

  const add = (host: string | undefined, port: number, path: string): void => {
    if (host === undefined || host === '') return;
    // An IP literal has no AAAA record to resolve; the other network probes
    // (certificate expiry, peer ports) judge literal addresses.
    if (host.includes(':') || /^\d+\.\d+\.\d+\.\d+$/.test(host)) return;
    const key = `${host}:${port}`;
    if (seen.has(key)) return;
    seen.add(key);
    targets.push({ host, port, path });
  };

  if (isString(domain) && domain !== '') {
    const host = domain
      .replace(/^[a-z]+:\/\//i, '')
      .split('/')[0]
      ?.split(':')[0]
      ?.toLowerCase();
    add(host, 443, 'domain');
  }

  const fields: readonly string[] = [...HTTPS_ENDPOINT_FIELDS, 'HORIZON_URL'];
  for (const field of fields) {
    const value = doc[field];
    if (!isString(value)) continue;
    const host = hostOf(value);
    if (host === undefined) continue;
    let port = 443;
    try {
      const url = new URL(value);
      port = url.port === '' ? 443 : Number(url.port);
    } catch {
      // `hostOf` already parsed it; this is unreachable in practice.
    }
    add(host, port, field);
  }

  return targets;
}

/**
 * The default resolver, using the system resolver over `node:dns/promises`.
 *
 * Loaded lazily so the browser bundle never pulls a Node built-in in: a
 * browser reports "not observed" for every host rather than a guess. `ENODATA`
 * and `ENOTFOUND` mean the name publishes no AAAA record; any other failure is
 * an infrastructure outage and is reported as an error so the checker stays
 * silent about it.
 */
const systemResolver: Ipv6Resolver = async (hostname) => {
  const dns = await import('node:dns/promises').catch(() => null);
  if (dns === null) return { kind: 'error', detail: 'node:dns is unavailable in this runtime' };
  try {
    const addresses = await dns.resolve6(hostname);
    return addresses.length > 0 ? { kind: 'ok', addresses } : { kind: 'none' };
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ENODATA' || code === 'ENOTFOUND') {
      return { kind: 'none' };
    }
    return { kind: 'error', detail: `DNS lookup failed (${code ?? 'unknown'})` };
  }
};

/**
 * The default connector: one short TCP dial to a numeric IPv6 address,
 * explicitly restricted to the IPv6 family so a dual-stack address cannot
 * silently fall back to IPv4.
 */
const tcpConnector: Ipv6Connector = async (address, port, timeoutMs) => {
  const net = await import('node:net').catch(() => null);
  if (net === null) return { kind: 'error', detail: 'node:net is unavailable in this runtime' };

  return new Promise<Ipv6ConnectionResult>((resolve) => {
    let settled = false;
    const socket = net.connect({ host: address, port, family: 6 });

    const settle = (result: Ipv6ConnectionResult): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };

    socket.setTimeout(timeoutMs);
    socket.once('connect', () => settle({ kind: 'connected' }));
    socket.once('timeout', () => settle({ kind: 'timeout' }));
    socket.once('error', (error) => {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === 'ECONNREFUSED') {
        settle({ kind: 'refused' });
        return;
      }
      settle({ kind: 'error', detail: code ?? error.message });
    });
  });
};

/** Formats an IPv6 address for display in messages, bracketed when needed. */
function displayAddress(address: string): string {
  return address.includes(':') ? `[${address}]` : address;
}

function report(
  diagnostics: Diagnostic[],
  rule: string,
  fallback: Severity,
  message: string,
  path: string,
  suggestion: string,
  rules: RuleOverrides | undefined,
): void {
  const severity = severityFor(rule, fallback, rules);
  if (severity === undefined) return;
  diagnostics.push({ rule, severity, category: 'network', message, path, suggestion });
}

/**
 * Audits IPv6 reachability for the anchor domain and every declared endpoint.
 *
 * Returns `[]` — never throws — when no rule is enabled, when the document
 * declares no endpoints, or when DNS/socket failures make the observation
 * impossible. Callers get a list of diagnostics safe to append to a run.
 */
export async function auditIpv6Reachability(
  doc: Record<string, unknown>,
  options: Ipv6AuditorOptions = {},
): Promise<Diagnostic[]> {
  const targets = ipv6TargetsOf(doc, options.domain);
  if (targets.length === 0) return [];

  const missingSeverity = severityFor(MISSING_IPV6_AAAA_RULE, 'warning', options.rules);
  const timeoutSeverity = severityFor(IPV6_CONNECTION_TIMEOUT_RULE, 'error', options.rules);
  const failedSeverity = severityFor(IPV6_CONNECTION_FAILED_RULE, 'warning', options.rules);
  // No findings worth a single DNS query: skip the network entirely.
  if (missingSeverity === undefined && timeoutSeverity === undefined && failedSeverity === undefined) {
    return [];
  }

  const resolve = options.resolve ?? systemResolver;
  const connect = options.connect ?? tcpConnector;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const diagnostics: Diagnostic[] = [];

  for (const target of targets) {
    const lookup = await resolve(target.host);
    if (lookup.kind === 'error') continue;

    if (lookup.kind === 'none' || lookup.addresses.length === 0) {
      report(
        diagnostics,
        MISSING_IPV6_AAAA_RULE,
        'warning',
        `${target.path} host ${target.host} has no DNS AAAA record, so it is unreachable from IPv6-only mobile networks`,
        target.path,
        'Publish an AAAA record for this host and serve the endpoint over IPv6, so DNS64/NAT64 clients can connect.',
        options.rules,
      );
      continue;
    }

    for (const address of lookup.addresses) {
      const result = await connect(address, target.port, timeoutMs);
      if (result.kind === 'connected') continue;

      if (result.kind === 'timeout') {
        report(
          diagnostics,
          IPV6_CONNECTION_TIMEOUT_RULE,
          'error',
          `${target.path} host ${target.host} has AAAA record ${displayAddress(address)}, but the TCP connection to it timed out`,
          target.path,
          'Confirm the service listens on IPv6 and that no firewall drops IPv6 SYN packets; DNS64 clients hang on this endpoint.',
          options.rules,
        );
        continue;
      }

      if (result.kind === 'refused') {
        report(
          diagnostics,
          IPV6_CONNECTION_FAILED_RULE,
          'warning',
          `${target.path} host ${target.host} resolves to ${displayAddress(address)}, but the TCP connection was refused`,
          target.path,
          'Bind the service to the IPv6 address published in the AAAA record, or remove the stale DNS record.',
          options.rules,
        );
        continue;
      }

      report(
        diagnostics,
        IPV6_CONNECTION_FAILED_RULE,
        'warning',
        `${target.path} host ${target.host}: IPv6 connection to ${displayAddress(address)} failed (${result.detail})`,
        target.path,
        'Verify IPv6 routing and firewall rules for this endpoint.',
        options.rules,
      );
    }
  }

  return diagnostics;
}
