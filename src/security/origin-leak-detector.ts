import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';
import { HTTPS_ENDPOINT_FIELDS } from '../spec.js';
import { hostOf } from '../predicates.js';

export const ORIGIN_IP_EXPOSED_RULE = 'security/origin-ip-exposed';
export const originLeakDetectorRules: Rule[] = [
  {
    id: ORIGIN_IP_EXPOSED_RULE,
    category: 'network',
    severity: 'warning',
    description:
      'Public sibling DNS addresses should not serve stellar.toml outside the declared service DNS',
    run() {},
  },
];

export interface OriginDnsRecords {
  addresses: string[];
  mailHosts: string[];
  textRecords: string[];
}

const EMPTY_RECORDS: OriginDnsRecords = { addresses: [], mailHosts: [], textRecords: [] };

export type OriginResolver = (hostname: string) => Promise<OriginDnsRecords>;
export type OriginProbe = (ip: string, hostname: string, path: string) => Promise<boolean>;

export interface OriginLeakOptions {
  domain?: string;
  rules?: RuleOverrides;
  resolve?: OriginResolver;
  probe?: OriginProbe;
}

function safe<T>(operation: () => Promise<T>): Promise<T | undefined> {
  return operation().catch(() => undefined);
}

const systemResolver: OriginResolver = async (hostname) => {
  const dns = await import('node:dns/promises');
  const [addresses, mail, text] = await Promise.all([
    safe(() => dns.resolve4(hostname)),
    safe(() => dns.resolveMx(hostname)),
    safe(() => dns.resolveTxt(hostname)),
  ]);
  return {
    addresses: addresses ?? [],
    mailHosts: (mail ?? []).map((record) => record.exchange).filter((host) => host !== '.'),
    textRecords: (text ?? []).map((record) => record.join('')),
  };
};

const httpsOriginProbe: OriginProbe = async (ip, hostname, path) => {
  const https = await import('node:https');
  return new Promise((resolve) => {
    const request = https.request(
      {
        hostname: ip,
        servername: hostname,
        port: 443,
        path,
        method: 'GET',
        headers: { host: hostname },
        timeout: 3500,
      },
      (response) => {
        const chunks: Buffer[] = [];
        let size = 0;
        response.on('data', (chunk: Buffer) => {
          size += chunk.length;
          if (size <= 256 * 1024) chunks.push(chunk);
          else request.destroy();
        });
        response.on('end', () => {
          const body = Buffer.concat(chunks).toString('utf8');
          const isStellarToml = /^\s*(?:VERSION|NETWORK_PASSPHRASE)\s*=/m.test(body);
          resolve(
            response.statusCode === 200 &&
              (path === '/.well-known/stellar.toml' ? isStellarToml : body.length > 0),
          );
        });
        response.on('error', () => resolve(false));
      },
    );
    request.on('timeout', () => request.destroy());
    request.on('error', () => resolve(false));
    request.end();
  });
};

function rootDomain(doc: Record<string, unknown>, explicit?: string): string | undefined {
  const candidate =
    explicit ??
    hostOf(
      typeof doc.DOCUMENTATION === 'object' && doc.DOCUMENTATION !== null
        ? (doc.DOCUMENTATION as Record<string, unknown>).ORG_URL
        : undefined,
    );
  if (typeof candidate !== 'string' || candidate === '') return undefined;
  try {
    return new URL(
      candidate.includes('://') ? candidate : `https://${candidate}`,
    ).hostname.toLowerCase();
  } catch {
    return undefined;
  }
}

function spfCandidates(records: string[], domain: string): string[] {
  const candidates = new Set<string>();
  for (const record of records) {
    if (!record.toLowerCase().startsWith('v=spf1')) continue;
    for (const match of record.matchAll(
      /(?:^|\s)(?:ip4:([^\s]+)|(?:a|mx)(?::([^\s]+))?|include:([^\s]+)|redirect=([^\s]+))/gi,
    )) {
      const ip = match[1];
      const host = match[2] ?? match[3] ?? match[4];
      if (ip !== undefined) candidates.add(ip.split('/')[0] ?? ip);
      else if (host !== undefined) candidates.add(host.toLowerCase());
      else candidates.add(domain);
    }
  }
  return [...candidates];
}

function isPublicIpv4(value: string): boolean {
  const octets = value.split('.').map(Number);
  if (
    octets.length !== 4 ||
    octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)
  )
    return false;
  const [first, second, third] = octets as [number, number, number, number];
  return !(
    first === 0 ||
    first === 10 ||
    first === 127 ||
    first >= 224 ||
    (first === 100 && second >= 64 && second <= 127) ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168) ||
    (first === 192 && second === 0 && third === 0) ||
    (first === 198 && (second === 18 || second === 19))
  );
}

function activeSeverity(rules: RuleOverrides | undefined): Severity | undefined {
  const severity = rules?.[ORIGIN_IP_EXPOSED_RULE];
  if (severity === 'off') return undefined;
  return severity === 'error' || severity === 'warning' || severity === 'info'
    ? severity
    : 'warning';
}

/** Finds sibling DNS addresses that directly serve the anchor's stellar.toml. */
export async function auditOriginExposure(
  doc: Record<string, unknown>,
  options: OriginLeakOptions = {},
): Promise<Diagnostic[]> {
  const domain = rootDomain(doc, options.domain);
  const severity = activeSeverity(options.rules);
  if (domain === undefined || severity === undefined) return [];

  const resolve = options.resolve ?? systemResolver;
  const probe = options.probe ?? httpsOriginProbe;
  const endpointPaths = new Map<string, Set<string>>();
  const addEndpoint = (host: string, path: string): void => {
    const paths = endpointPaths.get(host) ?? new Set<string>();
    paths.add(path);
    endpointPaths.set(host, paths);
  };
  for (const field of [...HTTPS_ENDPOINT_FIELDS, 'HORIZON_URL']) {
    const value = doc[field];
    const host = hostOf(value);
    if (host === undefined || typeof value !== 'string') continue;
    try {
      const url = new URL(value);
      addEndpoint(host.toLowerCase(), url.pathname || '/');
    } catch {
      addEndpoint(host.toLowerCase(), '/');
    }
  }
  addEndpoint(domain, '/.well-known/stellar.toml');
  const endpointHosts = new Set(endpointPaths.keys());

  const [endpointRecords, rootRecords] = await Promise.all([
    Promise.all([...endpointHosts].map((host) => resolve(host).catch(() => EMPTY_RECORDS))),
    resolve(domain).catch(() => EMPTY_RECORDS),
  ]);
  const edgeAddresses = new Set(endpointRecords.flatMap((records) => records.addresses));
  const candidates = new Set<string>([
    `mail.${domain}`,
    `origin.${domain}`,
    `direct.${domain}`,
    ...rootRecords.mailHosts,
    ...spfCandidates(rootRecords.textRecords, domain),
  ]);

  const ips = new Set<string>();
  for (const candidate of candidates) {
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(candidate)) {
      if (isPublicIpv4(candidate)) ips.add(candidate);
      continue;
    }
    if (
      candidate !== domain &&
      !candidate.endsWith(`.${domain}`) &&
      !rootRecords.mailHosts.includes(candidate)
    )
      continue;
    const records = await resolve(candidate).catch(() => EMPTY_RECORDS);
    for (const ip of records.addresses) if (isPublicIpv4(ip)) ips.add(ip);
  }

  const exposed: string[] = [];
  for (const ip of ips) {
    if (edgeAddresses.has(ip)) continue;
    for (const hostname of endpointHosts) {
      for (const path of endpointPaths.get(hostname) ?? []) {
        if (await probe(ip, hostname, path)) {
          exposed.push(ip);
          break;
        }
      }
      if (exposed.includes(ip)) break;
    }
  }
  if (exposed.length === 0) return [];
  return [
    {
      rule: ORIGIN_IP_EXPOSED_RULE,
      severity,
      category: 'network',
      message: `Origin IP address${exposed.length === 1 ? '' : 'es'} ${exposed.join(', ')} serve stellar.toml directly outside the declared service DNS`,
      suggestion:
        'Restrict direct origin access to CDN egress ranges and remove origin IPs from public DNS records',
    },
  ];
}
