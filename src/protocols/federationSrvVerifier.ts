/**
 * Federation DNS SRV discovery verifier (RFC 2782).
 *
 * Runs under opt-in `--verify-federation-srv` together with `--domain`.
 *
 * `_stellar-federation._tcp.<domain>` SRV records let clients find a SEP-2
 * federation server without `stellar.toml`. A record with a bad port, an
 * unresolvable target or a conflicting `FEDERATION_SERVER` sends clients to a
 * dead or wrong host, and which one wins differs by client.
 *
 * The SRV lookup is injected so tests (and `--mock-fixtures` runs) never touch
 * real DNS. Each target is probed over HTTPS with a hard timeout so one dead
 * target cannot stall the run.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { hostOf, isString } from '../predicates.js';
import { errorMessage, fetchWithTimeout, isRecord, severityFor } from './verifierSupport.js';

const TARGET_RULE = 'federationsrv/invalid-target';
const PORT_RULE = 'federationsrv/invalid-port';
const ATTR_RULE = 'federationsrv/invalid-priority-weight';
const UNREACHABLE_RULE = 'federationsrv/unreachable-target';
const NOT_FEDERATION_RULE = 'federationsrv/not-a-federation-server';
const CONFLICT_RULE = 'federationsrv/conflicts-with-toml';
const PORT_INFO_RULE = 'federationsrv/non-default-port';

const SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0002.md';

/** Shape of Node's `dns.promises.resolveSrv` records. */
export interface SrvRecord {
  name: string;
  port: number;
  priority: number;
  weight: number;
}

export type SrvResolver = (name: string) => Promise<SrvRecord[]>;

export interface FederationSrvOptions {
  rules?: RuleOverrides;
  domain: string;
  /** Defaults to `node:dns/promises` `resolveSrv`. */
  resolver?: SrvResolver;
  timeoutMs?: number;
  /** Probe each target over HTTPS. */
  probe?: boolean;
}

export interface FederationSrvResult {
  diagnostics: Diagnostic[];
  records: SrvRecord[];
}

const HOSTNAME = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

export function isValidSrvTarget(target: string): boolean {
  const host = target.replace(/\.$/, '');
  // "." is the RFC 2782 "service not available" marker; bare IPs are not names.
  return HOSTNAME.test(host) && !/^\d+(\.\d+){3}$/.test(host);
}

const defaultResolver: SrvResolver = async (name) => {
  // Non-literal specifier keeps the browser bundle from trying to resolve a Node builtin.
  const specifier = 'node:dns/promises';
  const dns = (await import(specifier)) as { resolveSrv: SrvResolver };
  return dns.resolveSrv(name);
};

export class FederationSrvRecordVerifier {
  constructor(
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly options: FederationSrvOptions,
  ) {}

  async verify(doc: Record<string, unknown>): Promise<FederationSrvResult> {
    const diagnostics: Diagnostic[] = [];
    const { domain, rules } = this.options;
    const name = `_stellar-federation._tcp.${domain}`;
    const push = (
      rule: string,
      fallback: 'error' | 'warning' | 'info',
      message: string,
      suggestion: string,
    ): void => {
      const severity = severityFor(rule, fallback, rules);
      if (severity === undefined) return;
      diagnostics.push({
        rule,
        severity,
        category: 'network',
        message,
        path: name,
        helpUri: SPEC,
        suggestion,
      });
    };

    let records: SrvRecord[];
    try {
      records = await (this.options.resolver ?? defaultResolver)(name);
    } catch {
      // No SRV record is normal: discovery then relies on stellar.toml alone.
      return { diagnostics, records: [] };
    }

    for (const r of records) {
      const label = `${r.name}:${r.port}`;
      if (!isValidSrvTarget(r.name)) {
        push(
          TARGET_RULE,
          'error',
          `SRV target "${r.name}" is not a valid hostname`,
          'Point the SRV record at a fully qualified hostname, not an IP address or ".".',
        );
        continue;
      }
      if (!Number.isInteger(r.port) || r.port < 1 || r.port > 65535) {
        push(
          PORT_RULE,
          'error',
          `SRV target ${r.name} has invalid port ${r.port}`,
          'Use a port between 1 and 65535 (443 by default).',
        );
        continue;
      }
      if (r.port !== 443) {
        push(
          PORT_INFO_RULE,
          'info',
          `SRV target ${label} does not use the default port 443`,
          'Federation servers must be served over HTTPS; prefer port 443 so firewalls and clients agree.',
        );
      }
      for (const [field, value] of [
        ['priority', r.priority],
        ['weight', r.weight],
      ] as const) {
        if (!Number.isInteger(value) || value < 0 || value > 65535) {
          push(
            ATTR_RULE,
            'error',
            `SRV target ${label} has invalid ${field} ${value}`,
            `RFC 2782 requires ${field} between 0 and 65535.`,
          );
        }
      }
    }
    // Equal priority with all-zero weights gives clients no basis to balance.
    const byPriority = new Map<number, SrvRecord[]>();
    for (const r of records) byPriority.set(r.priority, [...(byPriority.get(r.priority) ?? []), r]);
    for (const [priority, group] of byPriority) {
      if (group.length > 1 && group.every((r) => r.weight === 0)) {
        push(
          ATTR_RULE,
          'warning',
          `${group.length} SRV targets share priority ${priority} with weight 0, so clients cannot balance load`,
          'Give targets of equal priority non-zero weights, or distinct priorities for failover.',
        );
      }
    }

    const declared = doc.FEDERATION_SERVER;
    const declaredHost = isString(declared) ? hostOf(declared) : undefined;
    if (declaredHost !== undefined && records.length > 0) {
      const hosts = records.map((r) => r.name.replace(/\.$/, '').toLowerCase());
      if (!hosts.includes(declaredHost.toLowerCase())) {
        push(
          CONFLICT_RULE,
          'warning',
          `SRV records point to ${hosts.join(', ')} but FEDERATION_SERVER is ${declaredHost}`,
          'Make the SRV targets and FEDERATION_SERVER name the same host.',
        );
      }
    }

    if (this.options.probe) {
      for (const r of records) {
        if (!isValidSrvTarget(r.name) || r.port < 1 || r.port > 65535) continue;
        const problem = await this.probeTarget(r);
        if (problem !== undefined) {
          push(
            problem.startsWith('does not') ? NOT_FEDERATION_RULE : UNREACHABLE_RULE,
            'warning',
            `SRV target ${r.name}:${r.port} ${problem}`,
            'Serve SEP-2 at /federation on this host, or remove the SRV record.',
          );
        }
      }
    }
    return { diagnostics, records };
  }

  private async probeTarget(r: SrvRecord): Promise<string | undefined> {
    const host = r.name.replace(/\.$/, '');
    const url = `https://${host}${r.port === 443 ? '' : `:${r.port}`}/federation?type=name&q=${encodeURIComponent(`probe*${this.options.domain}`)}`;
    try {
      const res = await fetchWithTimeout(this.fetchImpl, url, {}, this.options.timeoutMs);
      if (res.status >= 500) return `returned HTTP ${res.status}`;
      const body: unknown = await res.json().catch(() => undefined);
      // A SEP-2 server answers with a JSON record or a JSON {"detail"} error;
      // an HTML page or an empty 404 means something else lives here.
      return isRecord(body) && (isString(body.account_id) || isString(body.detail))
        ? undefined
        : 'does not appear to host a SEP-2 federation service';
    } catch (error) {
      return `could not be reached (${errorMessage(error)})`;
    }
  }
}

export async function verifyFederationSrv(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch,
  options: FederationSrvOptions,
): Promise<FederationSrvResult> {
  return new FederationSrvRecordVerifier(fetchImpl, options).verify(doc);
}

const def = (id: string, severity: 'error' | 'warning' | 'info', description: string): Rule => ({
  id,
  category: 'network',
  severity,
  description,
  run() {},
});

export const federationSrvRules: Rule[] = [
  def(TARGET_RULE, 'error', 'Federation SRV targets must be valid hostnames'),
  def(PORT_RULE, 'error', 'Federation SRV ports must be between 1 and 65535'),
  def(ATTR_RULE, 'error', 'Federation SRV priority and weight must follow RFC 2782'),
  def(UNREACHABLE_RULE, 'warning', 'Federation SRV targets must be reachable over HTTPS'),
  def(NOT_FEDERATION_RULE, 'warning', 'Federation SRV targets must host a SEP-2 service'),
  def(CONFLICT_RULE, 'warning', 'Federation SRV records must agree with FEDERATION_SERVER'),
  def(PORT_INFO_RULE, 'info', 'Federation SRV targets should use port 443'),
];

export const federationSrvRuleIds: readonly string[] = federationSrvRules.map((r) => r.id);
