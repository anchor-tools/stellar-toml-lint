import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { hostOf } from '../predicates.js';

export const SECURITY_DNS_RESOLVER_DIVERGENCE = 'security/dns-resolver-divergence';
export const SECURITY_DNSSEC_NOT_ENABLED = 'security/dnssec-not-enabled';
export const DNS_RESOLVER_DIVERGENCE_RULE = SECURITY_DNS_RESOLVER_DIVERGENCE;
export const DNSSEC_NOT_ENABLED_RULE = SECURITY_DNSSEC_NOT_ENABLED;

export interface DnsResolver {
  name: string;
  server: string;
  endpoint: string;
  wireFormat?: boolean;
}

export const DEFAULT_DNS_RESOLVERS: readonly DnsResolver[] = [
  {
    name: 'Cloudflare',
    server: '1.1.1.1',
    endpoint: 'https://cloudflare-dns.com/dns-query',
  },
  {
    name: 'Google',
    server: '8.8.8.8',
    endpoint: 'https://dns.google/resolve',
  },
  {
    name: 'Quad9',
    server: '9.9.9.9',
    endpoint: 'https://dns.quad9.net/dns-query',
    wireFormat: true,
  },
];

export interface DnsIntegrityOptions {
  rules?: RuleOverrides;
  domain?: string;
  resolvers?: readonly DnsResolver[];
  fetchImpl?: typeof fetch;
}

export interface DnsResolverResult {
  resolver: DnsResolver;
  addresses: Record<'A' | 'AAAA', string[]>;
  availableByType: Record<'A' | 'AAAA', boolean>;
  dnssecAuthenticated: boolean;
  available: boolean;
  error?: string;
}

interface DnsJsonRecord {
  type?: unknown;
  data?: unknown;
  address?: unknown;
  ip?: unknown;
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

function normalizeDomain(value: unknown): string | undefined {
  if (typeof value !== 'string' || value.trim() === '') return undefined;
  const raw = value.trim();
  const candidate = raw.includes('://') ? raw : `https://${raw}`;
  try {
    return new URL(candidate).hostname.toLowerCase().replace(/\.$/, '');
  } catch {
    return undefined;
  }
}

function domainFromDocument(
  doc: Record<string, unknown>,
  options: DnsIntegrityOptions,
): { domain: string | undefined; path: string | undefined } {
  const explicit = normalizeDomain(options.domain);
  if (explicit !== undefined) return { domain: explicit, path: undefined };

  const direct = normalizeDomain(doc.DOMAIN);
  if (direct !== undefined) return { domain: direct, path: 'DOMAIN' };

  const documentation = doc.DOCUMENTATION;
  if (
    typeof documentation === 'object' &&
    documentation !== null &&
    !Array.isArray(documentation)
  ) {
    const organizationUrl = (documentation as Record<string, unknown>).ORG_URL;
    const domain = hostOf(organizationUrl);
    if (domain !== undefined)
      return { domain: normalizeDomain(domain), path: 'DOCUMENTATION.ORG_URL' };
  }
  return { domain: undefined, path: undefined };
}

function base64Url(bytes: Uint8Array): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  let output = '';
  for (let index = 0; index < bytes.length; index += 3) {
    const first = bytes[index] ?? 0;
    const second = bytes[index + 1];
    const third = bytes[index + 2];
    output += alphabet[first >> 2];
    output += alphabet[((first & 3) << 4) | ((second ?? 0) >> 4)];
    if (second === undefined) {
      output += '==';
      break;
    }
    output += alphabet[((second & 15) << 2) | ((third ?? 0) >> 6)];
    if (third === undefined) {
      output += '=';
      break;
    }
    output += alphabet[third & 63];
  }
  return output;
}

function encodeDnsQuery(domain: string, type: 'A' | 'AAAA'): Uint8Array {
  const labels = domain.replace(/\.$/, '').split('.');
  const length = 12 + labels.reduce((sum, label) => sum + label.length + 1, 0) + 1 + 4;
  const bytes = new Uint8Array(length);
  const view = new DataView(bytes.buffer);
  view.setUint16(0, 0x1234);
  view.setUint16(2, 0x0100);
  view.setUint16(4, 1);
  let offset = 12;
  for (const label of labels) {
    const labelBytes = new TextEncoder().encode(label);
    if (labelBytes.length === 0 || labelBytes.length > 63) throw new Error('Invalid DNS name');
    bytes[offset] = labelBytes.length;
    bytes.set(labelBytes, offset + 1);
    offset += labelBytes.length + 1;
  }
  bytes[offset] = 0;
  offset += 1;
  view.setUint16(offset, type === 'A' ? 1 : 28);
  view.setUint16(offset + 2, 1);
  return bytes;
}

function dnsQueryUrl(resolver: DnsResolver, domain: string, type: 'A' | 'AAAA'): string {
  const url = new URL(resolver.endpoint);
  if (resolver.wireFormat === true) {
    url.searchParams.set('dns', base64Url(encodeDnsQuery(domain, type)));
  } else {
    url.searchParams.set('name', domain);
    url.searchParams.set('type', type);
  }
  return url.toString();
}

function recordType(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isInteger(value)) return value;
  if (typeof value !== 'string') return undefined;
  const normalized = value.toUpperCase();
  if (normalized === 'A') return 1;
  if (normalized === 'AAAA') return 28;
  return undefined;
}

function addressesFromRecord(record: unknown, requestedType: 'A' | 'AAAA'): string[] {
  if (typeof record === 'string') return [record];
  if (Array.isArray(record))
    return record.flatMap((value) => addressesFromRecord(value, requestedType));
  if (typeof record !== 'object' || record === null) return [];
  const candidate = record as DnsJsonRecord;
  const type = recordType(candidate.type);
  if (type !== undefined && type !== (requestedType === 'A' ? 1 : 28)) return [];
  const value = candidate.data ?? candidate.address ?? candidate.ip;
  return addressesFromRecord(value, requestedType);
}

function normalizedAddresses(value: unknown, requestedType: 'A' | 'AAAA'): string[] {
  const values = addressesFromRecord(value, requestedType)
    .map((address) => {
      const trimmed = address.trim().toLowerCase().replace(/\.$/, '');
      if (requestedType === 'A' || !trimmed.includes(':')) return trimmed;
      try {
        return new URL(`http://[${trimmed}]`).hostname.slice(1, -1).toLowerCase();
      } catch {
        return trimmed;
      }
    })
    .filter((address) => address.length > 0);
  return [...new Set(values)].sort();
}

function readAnswers(body: unknown): unknown {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) return [];
  const record = body as Record<string, unknown>;
  return record.Answer ?? record.answers ?? record.records ?? record.data ?? [];
}

function isDnssecAuthenticated(body: unknown): boolean {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) return false;
  const record = body as Record<string, unknown>;
  if (record.AD === true || record.AD === 1 || record.ad === true || record.ad === 1) return true;
  return false;
}

function hasExplicitDnssecFlag(body: unknown): boolean {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) return false;
  const record = body as Record<string, unknown>;
  return (
    Object.prototype.hasOwnProperty.call(record, 'AD') ||
    Object.prototype.hasOwnProperty.call(record, 'ad')
  );
}

interface DnsPayload {
  addresses: string[];
  authenticated?: boolean;
}

function addressFromDnsBytes(bytes: Uint8Array): string | undefined {
  if (bytes.length === 4) return Array.from(bytes).join('.');
  if (bytes.length !== 16) return undefined;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const groups: string[] = [];
  for (let offset = 0; offset < 16; offset += 2) {
    groups.push(view.getUint16(offset).toString(16));
  }
  return groups.join(':');
}

function skipDnsName(bytes: Uint8Array, offset: number): number {
  let cursor = offset;
  while (cursor < bytes.length) {
    const length = bytes[cursor] ?? 0;
    if (length === 0) return cursor + 1;
    if ((length & 0xc0) === 0xc0) return cursor + 2;
    if ((length & 0xc0) !== 0) throw new Error('Invalid DNS name');
    cursor += length + 1;
  }
  throw new Error('Truncated DNS name');
}

function parseDnsWire(bytes: Uint8Array, requestedType: 'A' | 'AAAA'): DnsPayload {
  if (bytes.length < 12) throw new Error('Truncated DNS response');
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const flags = view.getUint16(2);
  const questionCount = view.getUint16(4);
  const answerCount = view.getUint16(6);
  let offset = 12;
  for (let index = 0; index < questionCount; index++) {
    offset = skipDnsName(bytes, offset);
    if (offset + 4 > bytes.length) throw new Error('Truncated DNS question');
    offset += 4;
  }
  const addresses: string[] = [];
  for (let index = 0; index < answerCount; index++) {
    offset = skipDnsName(bytes, offset);
    if (offset + 10 > bytes.length) throw new Error('Truncated DNS answer');
    const type = view.getUint16(offset);
    const length = view.getUint16(offset + 8);
    const start = offset + 10;
    const end = start + length;
    if (end > bytes.length) throw new Error('Truncated DNS record');
    if (type === (requestedType === 'A' ? 1 : 28)) {
      const address = addressFromDnsBytes(bytes.subarray(start, end));
      if (address !== undefined) addresses.push(address);
    }
    offset = end;
  }
  return { addresses, authenticated: (flags & 0x0020) !== 0 };
}

async function readDnsPayload(
  response: Response,
  requestedType: 'A' | 'AAAA',
): Promise<DnsPayload> {
  const bytes = new Uint8Array(await response.arrayBuffer());
  const contentType = response.headers.get('content-type') ?? '';
  const first = bytes.find(
    (value) => value !== 0x20 && value !== 0x0a && value !== 0x0d && value !== 0x09,
  );
  if (contentType.includes('json') || first === 0x7b || first === 0x5b) {
    const body: unknown = JSON.parse(new TextDecoder().decode(bytes));
    return {
      addresses: normalizedAddresses(readAnswers(body), requestedType),
      ...(hasExplicitDnssecFlag(body) ? { authenticated: isDnssecAuthenticated(body) } : {}),
    };
  }
  return parseDnsWire(bytes, requestedType);
}

async function queryResolver(
  resolver: DnsResolver,
  domain: string,
  fetchImpl: typeof fetch,
): Promise<DnsResolverResult> {
  const addresses: Record<'A' | 'AAAA', string[]> = { A: [], AAAA: [] };
  const availableByType: Record<'A' | 'AAAA', boolean> = { A: true, AAAA: true };
  let authenticated = true;
  let error: string | undefined;

  for (const type of ['A', 'AAAA'] as const) {
    try {
      const response = await fetchImpl(dnsQueryUrl(resolver, domain, type), {
        headers: {
          Accept:
            resolver.wireFormat === true
              ? 'application/dns-message'
              : 'application/dns-json, application/dns-message',
        },
      });
      if (!response.ok) {
        availableByType[type] = false;
        error ??= `returned HTTP ${response.status}`;
        continue;
      }
      const payload = await readDnsPayload(response, type);
      addresses[type] = normalizedAddresses(payload.addresses, type);
      if (payload.authenticated === false) authenticated = false;
    } catch (caught) {
      availableByType[type] = false;
      error ??= caught instanceof Error ? caught.message : String(caught);
    }
  }

  const available = availableByType.A || availableByType.AAAA;
  return {
    resolver,
    addresses,
    availableByType,
    dnssecAuthenticated: authenticated,
    available,
    ...(error === undefined ? {} : { error }),
  };
}

function sameAddresses(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function divergence(results: DnsResolverResult[], rules: RuleOverrides | undefined): Diagnostic[] {
  const availableResults = results.filter((result) => result.available);
  if (availableResults.length < 2) return [];
  const severity = severityFor(SECURITY_DNS_RESOLVER_DIVERGENCE, 'error', rules);
  if (severity === undefined) return [];

  for (const type of ['A', 'AAAA'] as const) {
    const typeResults = availableResults.filter((result) => result.availableByType[type]);
    if (typeResults.length < 2) continue;
    const first = typeResults[0]?.addresses[type] ?? [];
    const divergent = typeResults
      .slice(1)
      .some((result) => !sameAddresses(first, result.addresses[type]));
    if (!divergent) continue;
    const detail = typeResults
      .map((result) => `${result.resolver.name} ${result.addresses[type].join(', ') || '(none)'}`)
      .join('; ');
    return [
      {
        rule: SECURITY_DNS_RESOLVER_DIVERGENCE,
        severity,
        category: 'network',
        message: `${type} DNS answers differ across resolvers: ${detail}`,
        suggestion:
          'Investigate DNS filtering, BGP routing, or resolver policy before publishing the anchor file.',
      },
    ];
  }
  return [];
}

function dnssecWarning(
  results: DnsResolverResult[],
  rules: RuleOverrides | undefined,
): Diagnostic[] {
  const unauthenticated = results.filter(
    (result) => result.available && !result.dnssecAuthenticated,
  );
  if (unauthenticated.length === 0) return [];
  const severity = severityFor(SECURITY_DNSSEC_NOT_ENABLED, 'warning', rules);
  if (severity === undefined) return [];
  return [
    {
      rule: SECURITY_DNSSEC_NOT_ENABLED,
      severity,
      category: 'network',
      message: `DNSSEC authentication was not confirmed by ${unauthenticated.map((result) => result.resolver.name).join(', ')}`,
      suggestion:
        'Publish a DNSSEC-signed domain and use validating recursive resolvers for discovery.',
    },
  ];
}

export async function resolveDnsIntegrity(
  domain: string,
  fetchImpl: typeof fetch = fetch,
  options: Pick<DnsIntegrityOptions, 'resolvers'> = {},
): Promise<DnsResolverResult[]> {
  const resolvers = options.resolvers ?? DEFAULT_DNS_RESOLVERS;
  return Promise.all(resolvers.map((resolver) => queryResolver(resolver, domain, fetchImpl)));
}

export function checkDnsIntegrityForDomain(
  domain: string,
  options?: DnsIntegrityOptions,
): Promise<Diagnostic[]>;
export function checkDnsIntegrityForDomain(
  domain: string,
  fetchImpl?: typeof fetch,
  options?: DnsIntegrityOptions,
): Promise<Diagnostic[]>;
export async function checkDnsIntegrityForDomain(
  domainValue: string,
  fetchOrOptions: typeof fetch | DnsIntegrityOptions = fetch,
  options: DnsIntegrityOptions = {},
): Promise<Diagnostic[]> {
  const { fetchImpl, options: effectiveOptions } = dnsArguments(fetchOrOptions, options);
  const domain = normalizeDomain(domainValue);
  if (domain === undefined) return [];
  const results = await resolveDnsIntegrity(domain, fetchImpl, effectiveOptions);
  return [
    ...divergence(results, effectiveOptions.rules),
    ...dnssecWarning(results, effectiveOptions.rules),
  ];
}

function dnsArguments(
  fetchOrOptions: typeof fetch | DnsIntegrityOptions,
  options: DnsIntegrityOptions,
): { fetchImpl: typeof fetch; options: DnsIntegrityOptions } {
  if (typeof fetchOrOptions === 'function') {
    return { fetchImpl: fetchOrOptions, options };
  }
  return {
    fetchImpl: fetchOrOptions.fetchImpl ?? fetch,
    options: fetchOrOptions,
  };
}

export function checkDnsIntegrity(
  doc: Record<string, unknown>,
  options?: DnsIntegrityOptions,
): Promise<Diagnostic[]>;
export function checkDnsIntegrity(
  doc: Record<string, unknown>,
  fetchImpl?: typeof fetch,
  options?: DnsIntegrityOptions,
): Promise<Diagnostic[]>;
export function checkDnsIntegrity(
  domain: string,
  options?: DnsIntegrityOptions,
): Promise<Diagnostic[]>;
export function checkDnsIntegrity(
  domain: string,
  fetchImpl?: typeof fetch,
  options?: DnsIntegrityOptions,
): Promise<Diagnostic[]>;
export function checkDnsIntegrity(
  input: Record<string, unknown> | string,
  fetchImpl?: typeof fetch,
  options?: DnsIntegrityOptions,
): Promise<Diagnostic[]>;
export async function checkDnsIntegrity(
  input: Record<string, unknown> | string,
  fetchOrOptions: typeof fetch | DnsIntegrityOptions = fetch,
  options: DnsIntegrityOptions = {},
): Promise<Diagnostic[]> {
  const { fetchImpl, options: effectiveOptions } = dnsArguments(fetchOrOptions, options);
  if (typeof input === 'string') {
    return checkDnsIntegrityForDomain(input, fetchImpl, effectiveOptions);
  }
  const { domain, path } = domainFromDocument(input, effectiveOptions);
  if (domain === undefined) return [];
  const diagnostics = await checkDnsIntegrityForDomain(domain, fetchImpl, effectiveOptions);
  return diagnostics.map((diagnostic) => ({
    ...diagnostic,
    ...(path === undefined ? {} : { path }),
  }));
}

export const checkDnssecIntegrity = checkDnsIntegrity;

export const dnsIntegrityRules: Rule[] = [
  {
    id: SECURITY_DNS_RESOLVER_DIVERGENCE,
    category: 'network',
    severity: 'error',
    description: 'DNS resolvers must agree on the anchor domain A and AAAA records',
    run() {},
  },
  {
    id: SECURITY_DNSSEC_NOT_ENABLED,
    category: 'network',
    severity: 'warning',
    description: 'DNS responses should be authenticated by validating recursive resolvers',
    run() {},
  },
];

export const dnsRuleIds: readonly string[] = dnsIntegrityRules.map((rule) => rule.id);
export const dnsIntegrityRuleIds = dnsRuleIds;
