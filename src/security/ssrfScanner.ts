/**
 * SSRF and private-IP exfiltration scanner for advertised endpoints.
 *
 * Wallets and indexers take the URI/URL fields in `stellar.toml` at face value
 * and fetch them. A hostname resolving to 10.0.0.0/8, 169.254.169.254,
 * 127.0.0.1 (or an IPv4-mapped IPv6 form of any of those) turns that trust into
 * a server-side request forgery primitive — potentially exposing cloud
 * metadata credentials.
 *
 * Checks are passive: only DNS lookups through the injected resolver are made.
 * Two successive lookups per host catch the common DNS-rebinding pattern where
 * the first answer is public and a later one is private.
 */
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';

export const SECURITY_SSRF_PRIVATE_IP = 'security/ssrf-private-ip';
export const SECURITY_SSRF_DNS_REBINDING = 'security/ssrf-dns-rebinding';
export const SECURITY_SSRF_TIMEOUT = 'security/ssrf-dns-timeout';

/** A CIDR block that must never be the target of a public SEP-1 endpoint. */
export interface BlockedCidr {
  cidr: string;
  name: string;
}

export const BLOCKED_CIDRS: readonly BlockedCidr[] = [
  { cidr: '0.0.0.0/8', name: 'unspecified' },
  { cidr: '10.0.0.0/8', name: 'RFC 1918 private' },
  { cidr: '100.64.0.0/10', name: 'carrier-grade NAT' },
  { cidr: '127.0.0.0/8', name: 'loopback' },
  { cidr: '169.254.0.0/16', name: 'link-local / cloud metadata' },
  { cidr: '172.16.0.0/12', name: 'RFC 1918 private' },
  { cidr: '192.0.0.0/24', name: 'IETF protocol assignments' },
  { cidr: '192.0.2.0/24', name: 'documentation' },
  { cidr: '192.168.0.0/16', name: 'RFC 1918 private' },
  { cidr: '198.18.0.0/15', name: 'benchmarking' },
  { cidr: '198.51.100.0/24', name: 'documentation' },
  { cidr: '203.0.113.0/24', name: 'documentation' },
  { cidr: '224.0.0.0/4', name: 'multicast' },
  { cidr: '240.0.0.0/4', name: 'reserved' },
  { cidr: '255.255.255.255/32', name: 'broadcast' },
  { cidr: '::/128', name: 'unspecified' },
  { cidr: '::1/128', name: 'loopback' },
  { cidr: 'fc00::/7', name: 'unique local' },
  { cidr: 'fe80::/10', name: 'link-local' },
  { cidr: 'ff00::/8', name: 'multicast' },
  { cidr: '2001:db8::/32', name: 'documentation' },
];

export type SsrfDnsResolver = (
  hostname: string,
  attempt: number,
  signal: AbortSignal,
) => Promise<string[]>;

export interface SsrfOptions {
  rules?: RuleOverrides;
  /** Include this domain when the document has no explicit URLs. */
  domain?: string;
  /** Inject DNS answers. Takes precedence over `fetchImpl`. */
  dnsResolver?: SsrfDnsResolver;
  /** Transport for the default DNS-over-HTTPS responder. */
  fetchImpl?: typeof fetch;
  resolverUrl?: string;
  timeoutMs?: number;
  /** Number of lookups per host; 2 makes rebinding visible. Default 2. */
  resolutionAttempts?: number;
  signal?: AbortSignal;
}

export interface SsrfFinding {
  hostname: string;
  ip: string;
  path: string;
  kind: 'private' | 'rebind';
  reason: string;
  message: string;
  remediation: string;
}

export interface SsrfReport {
  findings: SsrfFinding[];
  hostsChecked: string[];
  timedOut: string[];
  ok: boolean;
}

/** Strips brackets / zone ids and folds IPv4-mapped IPv6 into IPv4. */
export function normalizeIp(raw: string): string | undefined {
  const ip = raw.trim().replace(/^\[/, '').replace(/\]$/, '').split('%')[0]?.toLowerCase() ?? '';
  if (ip === '') return undefined;

  const dotted = ip.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (dotted !== null) return dotted[1] ?? undefined;

  const hex = ip.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (hex !== null) {
    const high = Number.parseInt(hex[1] ?? '', 16);
    const low = Number.parseInt(hex[2] ?? '', 16);
    return `${(high >> 8) & 0xff}.${high & 0xff}.${(low >> 8) & 0xff}.${low & 0xff}`;
  }
  return ip;
}

function ipToBigInt(raw: string): bigint | undefined {
  const ip = normalizeIp(raw);
  if (ip === undefined) return undefined;
  if (ip.includes(':')) {
    const groups = ipv6Groups(ip);
    if (groups === undefined) return undefined;
    let value = 0n;
    for (const group of groups) value = (value << 16n) | BigInt(group);
    return value;
  }
  const parts = ip.split('.');
  if (parts.length !== 4) return undefined;
  let value = 0n;
  for (const part of parts) {
    const octet = Number(part);
    if (!/^\d{1,3}$/.test(part) || octet < 0 || octet > 255) return undefined;
    value = (value << 8n) | BigInt(octet);
  }
  return value;
}

function ipv6Groups(ip: string): number[] | undefined {
  const parts = ip.split('::');
  if (parts.length > 2) return undefined;
  const parse = (group: string): number | undefined => {
    if (!/^[0-9a-f]{1,4}$/.test(group)) return undefined;
    return Number.parseInt(group, 16);
  };
  const left = (parts[0] ?? '') === '' ? [] : (parts[0] ?? '').split(':').map(parse);
  const rightText = parts[1];
  const right = rightText === undefined || rightText === '' ? [] : rightText.split(':').map(parse);
  if ([...left, ...right].some((group) => group === undefined)) return undefined;
  const missing = parts.length === 2 ? 8 - left.length - right.length : 0;
  if (missing < 0 || (parts.length === 1 && left.length !== 8)) return undefined;
  const groups = [...left, ...Array<number>(missing).fill(0), ...right] as number[];
  return groups.length === 8 ? groups : undefined;
}

function cidrToBigInt(
  cidr: string,
): { network: bigint; width: number; version: 4 | 6 } | undefined {
  const [address, prefixText] = cidr.split('/');
  if (address === undefined || prefixText === undefined) return undefined;
  const version = address.includes(':') ? 6 : 4;
  const value = ipToBigInt(address);
  if (value === undefined) return undefined;
  const width = Number(prefixText);
  if (!Number.isInteger(width) || width < 0 || width > (version === 4 ? 32 : 128)) return undefined;
  return { network: value, width, version };
}

const COMPILED_CIDRS = BLOCKED_CIDRS.map((block) => ({
  ...block,
  ...(cidrToBigInt(block.cidr) ?? { network: 0n, width: -1, version: 4 as const }),
}));

/** True when `ip` falls on the wrong side of any blocked CIDR boundary. */
export function isBlockedIp(ip: string): { blocked: boolean; reason: string } {
  const address = ipToBigInt(ip);
  if (address === undefined) return { blocked: false, reason: '' };
  const version = normalizeIp(ip)?.includes(':') ? 6 : 4;
  for (const block of COMPILED_CIDRS) {
    if (block.version !== version || block.width < 0) continue;
    const bits = version === 4 ? 32 : 128;
    const shift = BigInt(bits - block.width);
    if (address >> shift === block.network >> shift) {
      return { blocked: true, reason: block.name };
    }
  }
  return { blocked: false, reason: '' };
}

function isIpLiteral(host: string): boolean {
  return normalizeIp(host) !== undefined && /[:\d]/.test(host);
}

function hostOf(value: string): { host: string; url: string } | undefined {
  const trimmed = value.trim();
  if (!/^https?:\/\//i.test(trimmed)) return undefined;
  try {
    const url = new URL(trimmed);
    const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
    return host === '' ? undefined : { host, url: trimmed };
  } catch {
    return undefined;
  }
}

function collectHosts(
  doc: Record<string, unknown>,
  domain?: string,
): Map<string, { path: string; url: string }> {
  const hosts = new Map<string, { path: string; url: string }>();
  const visit = (value: unknown, path: string): void => {
    if (typeof value === 'string') {
      const found = hostOf(value);
      if (found !== undefined && !hosts.has(found.host)) {
        hosts.set(found.host, { path: path === '' ? 'URL' : path, url: found.url });
      }
      return;
    }
    if (Array.isArray(value)) {
      value.forEach((item, index) => visit(item, `${path}[${index}]`));
      return;
    }
    if (typeof value === 'object' && value !== null) {
      for (const [key, item] of Object.entries(value)) {
        visit(item, path === '' ? key : `${path}.${key}`);
      }
    }
  };
  visit(doc, '');
  if (domain !== undefined && typeof domain === 'string') {
    const host =
      domain
        .replace(/^https?:\/\//, '')
        .split('/')[0]
        ?.toLowerCase() ?? '';
    if (host !== '' && !hosts.has(host)) {
      hosts.set(host, { path: 'DOMAIN', url: `https://${host}/.well-known/stellar.toml` });
    }
  }
  return hosts;
}

function defaultResolver(fetchImpl: typeof fetch, endpoint: string): SsrfDnsResolver {
  return async (hostname, _attempt, signal) => {
    const ips: string[] = [];
    for (const type of ['A', 'AAAA'] as const) {
      const url = new URL(endpoint);
      url.searchParams.set('name', hostname);
      url.searchParams.set('type', type);
      const response = await fetchImpl(url, {
        headers: { accept: 'application/dns-json' },
        signal,
      });
      if (!response.ok) continue;
      const body = (await response.json()) as {
        Answer?: Array<{ type?: number; data?: unknown }>;
      };
      for (const answer of body.Answer ?? []) {
        if (answer.type !== (type === 'A' ? 1 : 28) || typeof answer.data !== 'string') continue;
        ips.push(answer.data);
      }
    }
    return ips;
  };
}

async function resolve(
  resolver: SsrfDnsResolver,
  hostname: string,
  attempt: number,
  options: SsrfOptions,
): Promise<{ ips: string[]; timedOut: boolean }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 5000);
  const onAbort = (): void => controller.abort();
  options.signal?.addEventListener('abort', onAbort, { once: true });
  try {
    const ips = await resolver(hostname, attempt, controller.signal);
    return { ips, timedOut: false };
  } catch {
    return controller.signal.aborted ? { ips: [], timedOut: true } : { ips: [], timedOut: false };
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener('abort', onAbort);
  }
}

function severityFor(rule: string, rules: RuleOverrides | undefined) {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' || override === 'info'
    ? override
    : ('error' as const);
}

const REMEDIATION_PRIVATE =
  'Advertise a hostname that resolves only to a public address. Never publish RFC 1918, loopback, ' +
  'link-local (including 169.254.169.254) or multicast targets; restrict outbound metadata access ' +
  'at the network layer as defence in depth.';
const REMEDIATION_REBIND =
  'Pin the DNS answer before connecting, re-validate the IP immediately prior to each request, and ' +
  'use a DNSSEC-validating resolver. Rebinding from a public to a private address must be treated as ' +
  'an active SSRF attempt.';

/** Scans all advertised URLs and returns an SSRF risk report. */
export async function scanSsrf(
  doc: Record<string, unknown>,
  options: SsrfOptions = {},
): Promise<SsrfReport> {
  const hosts = collectHosts(doc, options.domain);
  const resolver =
    options.dnsResolver ??
    defaultResolver(
      options.fetchImpl ?? fetch,
      options.resolverUrl ?? 'https://cloudflare-dns.com/dns-query',
    );
  const attempts = options.resolutionAttempts ?? 2;
  const findings: SsrfFinding[] = [];
  const timedOut: string[] = [];
  const seen = new Set<string>();

  const addFinding = (finding: SsrfFinding): void => {
    const key = `${finding.hostname}:${finding.kind}:${finding.ip}`;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push(finding);
  };

  for (const [hostname, { path }] of hosts) {
    if (isIpLiteral(hostname)) {
      const check = isBlockedIp(hostname);
      if (check.blocked) {
        addFinding({
          hostname,
          ip: normalizeIp(hostname) ?? hostname,
          path,
          kind: 'private',
          reason: check.reason,
          message: `${path} points at ${hostname}, a ${check.reason} address`,
          remediation: REMEDIATION_PRIVATE,
        });
      }
      continue;
    }

    const answers: string[][] = [];
    for (let attempt = 0; attempt < attempts; attempt++) {
      const result = await resolve(resolver, hostname, attempt, options);
      if (result.timedOut) {
        timedOut.push(hostname);
        break;
      }
      answers.push(result.ips);
    }
    if (answers.length === 0) continue;

    let firstPublic = false;
    for (const [attempt, ips] of answers.entries()) {
      const publicIps = ips.filter((ip) => !isBlockedIp(ip).blocked);
      if (attempt === 0 && publicIps.length > 0) firstPublic = true;
      for (const ip of ips) {
        const check = isBlockedIp(ip);
        if (!check.blocked) continue;
        if (firstPublic && attempt > 0) {
          addFinding({
            hostname,
            ip: normalizeIp(ip) ?? ip,
            path,
            kind: 'rebind',
            reason: check.reason,
            message: `${path} hostname ${hostname} resolved publicly then privately (${ip}) on a later lookup; DNS rebinding detected`,
            remediation: REMEDIATION_REBIND,
          });
        } else {
          addFinding({
            hostname,
            ip: normalizeIp(ip) ?? ip,
            path,
            kind: 'private',
            reason: check.reason,
            message: `${path} hostname ${hostname} resolves to ${ip}, a ${check.reason} address`,
            remediation: REMEDIATION_PRIVATE,
          });
        }
      }
    }
  }

  return { findings, hostsChecked: [...hosts.keys()], timedOut, ok: findings.length === 0 };
}

/** Converts a report into diagnostics with CRITICAL (error) severity. */
export function ssrfDiagnostics(report: SsrfReport, rules?: RuleOverrides): Diagnostic[] {
  const diagnostics: Diagnostic[] = [];
  for (const finding of report.findings) {
    const rule = finding.kind === 'rebind' ? SECURITY_SSRF_DNS_REBINDING : SECURITY_SSRF_PRIVATE_IP;
    const severity = severityFor(rule, rules);
    if (severity === undefined) continue;
    diagnostics.push({
      rule,
      severity,
      category: 'network',
      message: `[CRITICAL] ${finding.message}`,
      path: finding.path,
      suggestion: finding.remediation,
    });
  }
  if (report.timedOut.length > 0) {
    const severity = severityFor(SECURITY_SSRF_TIMEOUT, rules);
    if (severity !== undefined) {
      diagnostics.push({
        rule: SECURITY_SSRF_TIMEOUT,
        severity,
        category: 'network',
        message: `DNS lookup timed out for ${report.timedOut.join(', ')}; SSRF status is unknown`,
        suggestion: 'Re-run with a reachable DNS resolver or increase the timeout budget.',
      });
    }
  }
  return diagnostics;
}

/** Scans the document and converts the result into diagnostics. */
export async function checkSsrf(
  doc: Record<string, unknown>,
  options: SsrfOptions = {},
): Promise<Diagnostic[]> {
  return ssrfDiagnostics(await scanSsrf(doc, options), options.rules);
}

/** Detailed remediation report written to stderr by the CLI. */
export function renderSsrfReport(report: SsrfReport): string {
  const lines = [
    'SSRF / private-IP audit',
    `  Hosts checked: ${report.hostsChecked.length}`,
    `  Findings: ${report.findings.length}`,
  ];
  for (const finding of report.findings) {
    lines.push(
      `  [CRITICAL] ${finding.hostname} -> ${finding.ip} (${finding.reason}, ${finding.kind})`,
    );
    lines.push(`      Path: ${finding.path}`);
    lines.push(`      ${finding.remediation}`);
  }
  for (const host of report.timedOut) lines.push(`  [TIMEOUT] ${host}`);
  return `${lines.join('\n')}\n`;
}

/** Registered so `--off`/`--warn`/`--error` and `--list-rules` know these ids. */
export const ssrfRules: Rule[] = [
  {
    id: SECURITY_SSRF_PRIVATE_IP,
    category: 'network',
    severity: 'error',
    description: 'Advertised endpoints must not resolve to private, loopback or link-local IPs',
    run() {},
  },
  {
    id: SECURITY_SSRF_DNS_REBINDING,
    category: 'network',
    severity: 'error',
    description: 'Advertised hostnames must not rebind from public to private addresses',
    run() {},
  },
  {
    id: SECURITY_SSRF_TIMEOUT,
    category: 'network',
    severity: 'warning',
    description: 'DNS lookups for SSRF checks must complete within the timeout budget',
    run() {},
  },
];

export const ssrfRuleIds: readonly string[] = ssrfRules.map((rule) => rule.id);
