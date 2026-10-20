/**
 * SEP-20 validator peer discovery checks.
 *
 * DNS is intentionally injected at the boundary.  The production resolver
 * uses Node's DNS API, while tests and embedders can provide deterministic SRV
 * and TXT answers without changing process-wide resolver state.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isHostPort, isString } from '../predicates.js';
import { specUrl } from '../spec.js';

export const VALIDATORS_DNS_SRV_RECORD_MISSING = 'validators/dns-srv-record-missing';
export const VALIDATORS_DNS_SRV_TARGET_UNREACHABLE = 'validators/dns-srv-target-unreachable';

export const DNS_SRV_RECORD_MISSING_RULE = VALIDATORS_DNS_SRV_RECORD_MISSING;
export const DNS_SRV_TARGET_UNREACHABLE_RULE = VALIDATORS_DNS_SRV_TARGET_UNREACHABLE;

export interface SrvRecord {
  name: string;
  port: number;
  priority: number;
  weight: number;
}

export interface DnsDiscoveryResolver {
  resolveSrv(name: string): Promise<readonly SrvRecord[]>;
  resolveTxt(name: string): Promise<readonly (readonly string[])[]>;
}

export type DnsTargetProbe = (host: string, port: number, timeoutMs: number) => Promise<boolean>;

export interface DnsDiscoveryOptions {
  rules?: RuleOverrides;
  resolver?: DnsDiscoveryResolver;
  probe?: DnsTargetProbe;
  timeoutMs?: number;
  /** Override the service prefix for installations using a private record. */
  serviceName?: string;
}

export interface DnsDiscoveryResult {
  hostname: string;
  srvName: string;
  records: SrvRecord[];
  invalidRecordCount: number;
  txtRecords: string[];
}

interface DeclaredValidator {
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

function declaredValidators(doc: Record<string, unknown>): DeclaredValidator[] {
  if (!Array.isArray(doc.VALIDATORS)) return [];
  return doc.VALIDATORS.flatMap((entry, index) => {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) return [];
    const value = (entry as Record<string, unknown>).HOST;
    if (!isString(value)) return [];
    const parsed = parseHostPort(value);
    return parsed === undefined ? [] : [{ ...parsed, path: `VALIDATORS[${index}].HOST` }];
  });
}

function normalizeHostname(value: string): string {
  const raw = value
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, '')
    .replace(/\.$/, '');
  return raw;
}

function txtText(records: readonly (readonly string[])[]): string[] {
  return records.map((chunks) => chunks.join('')).filter((record) => record.trim() !== '');
}

function recordIsValid(record: SrvRecord): boolean {
  return (
    typeof record.name === 'string' &&
    Number.isInteger(record.port) &&
    record.port >= 1 &&
    record.port <= 65535 &&
    Number.isInteger(record.priority) &&
    record.priority >= 0 &&
    Number.isInteger(record.weight) &&
    record.weight >= 0
  );
}

function normalizeSrvRecord(value: unknown): SrvRecord | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  const record = value as Record<string, unknown>;
  if (
    typeof record.name !== 'string' ||
    typeof record.port !== 'number' ||
    typeof record.priority !== 'number' ||
    typeof record.weight !== 'number'
  ) {
    return undefined;
  }
  const normalized: SrvRecord = {
    name: record.name,
    port: record.port,
    priority: record.priority,
    weight: record.weight,
  };
  return recordIsValid(normalized) ? normalized : undefined;
}

async function defaultResolver(): Promise<DnsDiscoveryResolver> {
  const dns = await import('node:dns/promises');
  return {
    async resolveSrv(name) {
      return (await dns.resolveSrv(name)).map((record) => ({
        name: record.name,
        port: record.port,
        priority: record.priority,
        weight: record.weight,
      }));
    },
    resolveTxt(name) {
      return dns.resolveTxt(name);
    },
  };
}

async function defaultProbe(host: string, port: number, timeoutMs: number): Promise<boolean> {
  const net = await import('node:net');
  return new Promise((resolve) => {
    let settled = false;
    const socket = net.createConnection({ host, port });
    const finish = (reachable: boolean): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(reachable);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
  });
}

/** Resolves one validator's `_stellar-core._tcp` SRV and companion TXT data. */
export async function resolveValidatorDnsDiscovery(
  hostname: string,
  options: DnsDiscoveryOptions = {},
): Promise<DnsDiscoveryResult> {
  const resolver = options.resolver ?? (await defaultResolver());
  const normalized = normalizeHostname(hostname);
  const prefix = options.serviceName ?? '_stellar-core._tcp';
  const srvName = `${prefix}.${normalized}`;
  let rawRecords: readonly unknown[] = [];
  try {
    rawRecords = await resolver.resolveSrv(srvName);
  } catch {
    rawRecords = [];
  }
  let rawTxt: readonly (readonly string[])[] = [];
  try {
    rawTxt = await resolver.resolveTxt(normalized);
    if (rawTxt.length === 0) rawTxt = await resolver.resolveTxt(srvName);
  } catch {
    try {
      rawTxt = await resolver.resolveTxt(srvName);
    } catch {
      rawTxt = [];
    }
  }
  const records = rawRecords
    .map((record) => normalizeSrvRecord(record))
    .filter((record): record is SrvRecord => record !== undefined);
  return {
    hostname: normalized,
    srvName,
    records,
    invalidRecordCount: rawRecords.length - records.length,
    txtRecords: txtText(rawTxt),
  };
}

function txtEndpoint(record: string): { host: string; port: number } | undefined {
  // Accept the common `host=... port=...`, `target=host:port`, and plain
  // `stellar-core=host:port` forms without treating arbitrary TXT metadata as
  // a peer announcement.
  const target = record.match(/(?:^|[;\s])(target|host|stellar-core)\s*=\s*([^;\s]+)/i)?.[2];
  if (target === undefined) return undefined;
  return parseHostPort(target);
}

function endpointMatches(
  record: SrvRecord,
  declared: readonly DeclaredValidator[],
): DeclaredValidator | undefined {
  const target = normalizeHostname(record.name);
  return declared.find(
    (entry) => normalizeHostname(entry.host) === target && entry.port === record.port,
  );
}

/**
 * Audits DNS discovery records for all declared validators.  Missing DNS data
 * is a warning; a published target that is malformed, undeclared, or cannot
 * accept a TCP connection is an error because crawlers will follow it.
 */
export async function checkValidatorDnsDiscovery(
  doc: Record<string, unknown>,
  options: DnsDiscoveryOptions = {},
): Promise<Diagnostic[]> {
  const declared = declaredValidators(doc);
  if (declared.length === 0) return [];
  const missingSeverity = severityFor(VALIDATORS_DNS_SRV_RECORD_MISSING, 'warning', options.rules);
  const unreachableSeverity = severityFor(
    VALIDATORS_DNS_SRV_TARGET_UNREACHABLE,
    'error',
    options.rules,
  );
  if (missingSeverity === undefined && unreachableSeverity === undefined) return [];

  const probe = options.probe ?? defaultProbe;
  const timeoutMs = Math.max(1, options.timeoutMs ?? 3_000);
  const diagnostics: Diagnostic[] = [];
  const checkedNames = new Set<string>();

  for (const validator of declared) {
    const hostname = normalizeHostname(validator.host);
    if (checkedNames.has(hostname)) continue;
    checkedNames.add(hostname);
    const discovery = await resolveValidatorDnsDiscovery(hostname, options);

    if (discovery.records.length === 0) {
      if (discovery.invalidRecordCount > 0 && unreachableSeverity !== undefined) {
        diagnostics.push({
          rule: VALIDATORS_DNS_SRV_TARGET_UNREACHABLE,
          severity: unreachableSeverity,
          category: 'validators',
          message: `${discovery.srvName} returned ${discovery.invalidRecordCount} SRV record${discovery.invalidRecordCount === 1 ? '' : 's'} with invalid priority, weight, target, or port fields`,
          path: validator.path,
          helpUri: specUrl('validator-information'),
          suggestion:
            'Publish SRV records with integer priority and weight values and a valid 1-65535 overlay port.',
        });
        continue;
      }
      if (missingSeverity !== undefined) {
        diagnostics.push({
          rule: VALIDATORS_DNS_SRV_RECORD_MISSING,
          severity: missingSeverity,
          category: 'validators',
          message: `No ${discovery.srvName} SRV record was published for validator ${hostname}`,
          path: validator.path,
          helpUri: specUrl('validator-information'),
          suggestion: `Publish ${discovery.srvName} with a valid priority, weight, target, and overlay port, or document why direct HOST discovery is required.`,
        });
      }
      continue;
    }

    for (const record of discovery.records) {
      const target = endpointMatches(record, declared);
      const targetHost = normalizeHostname(record.name);
      const reachable =
        target === undefined
          ? false
          : await probe(targetHost, record.port, timeoutMs).catch(() => false);
      if (unreachableSeverity === undefined || (target !== undefined && reachable)) continue;

      diagnostics.push({
        rule: VALIDATORS_DNS_SRV_TARGET_UNREACHABLE,
        severity: unreachableSeverity,
        category: 'validators',
        message:
          target === undefined
            ? `SRV target ${targetHost}:${record.port} is not declared by any [[VALIDATORS]].HOST`
            : `SRV target ${targetHost}:${record.port} did not accept a TCP connection`,
        path: target?.path ?? validator.path,
        helpUri: specUrl('validator-information'),
        suggestion:
          'Make the SRV target and port match a published validator HOST and ensure stellar-core is listening on the overlay port.',
      });
    }

    // TXT is queried and parsed as a consistency signal.  A TXT endpoint that
    // contradicts the SRV target is surfaced through the same actionable rule.
    for (const txt of discovery.txtRecords) {
      const endpoint = txtEndpoint(txt);
      if (endpoint === undefined) continue;
      const match = declared.find(
        (entry) =>
          normalizeHostname(entry.host) === normalizeHostname(endpoint.host) &&
          entry.port === endpoint.port,
      );
      if (match !== undefined) continue;
      if (unreachableSeverity !== undefined) {
        diagnostics.push({
          rule: VALIDATORS_DNS_SRV_TARGET_UNREACHABLE,
          severity: unreachableSeverity,
          category: 'validators',
          message: `TXT peer target ${endpoint.host}:${endpoint.port} is not declared by any [[VALIDATORS]].HOST`,
          path: validator.path,
          helpUri: specUrl('validator-information'),
          suggestion: 'Keep TXT and SRV peer targets aligned with the validator HOST declarations.',
        });
      }
    }
  }
  return diagnostics;
}

export const checkDnsDiscovery = checkValidatorDnsDiscovery;
export const auditValidatorDnsDiscovery = checkValidatorDnsDiscovery;

export const dnsDiscoveryRules: Rule[] = [
  {
    id: VALIDATORS_DNS_SRV_RECORD_MISSING,
    category: 'validators',
    severity: 'warning',
    description: 'Validators advertising DNS discovery should publish an overlay SRV record',
    run() {},
  },
  {
    id: VALIDATORS_DNS_SRV_TARGET_UNREACHABLE,
    category: 'validators',
    severity: 'error',
    description: 'DNS-discovered validator overlay targets must match HOST and accept TCP',
    run() {},
  },
];

export const dnsDiscoveryRuleIds: readonly string[] = dnsDiscoveryRules.map((rule) => rule.id);
