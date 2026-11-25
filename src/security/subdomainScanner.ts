/**
 * Passive subdomain takeover / orphaned DNS scanner.
 *
 * SEP-1 anchors are discovered through DNS: a `stellar.toml` is served from
 * `https://<domain>/.well-known/stellar.toml`, and wallets follow the URLs it
 * advertises. An abandoned CNAME (an old S3 bucket, a deleted GitHub Pages
 * site, an orphaned Fastly service, …) lets a third party claim the resource
 * the name points at and serve a forged stellar.toml for the anchor.
 *
 * This module is deliberately *passive*: it only looks at DNS answers (CNAME,
 * NS, A and AAAA). It never connects to the CNAME target, never tries to claim
 * a resource, and never sends a request to anything but the configured DNS
 * resolver. A CNAME is called dangling when its target does not resolve; the
 * provider signature then tells us how likely a takeover is.
 */
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';

export const SECURITY_DNS_TAKEOVER_CNAME = 'security/dns-takeover-cname';
export const SECURITY_DNS_TAKEOVER_NS = 'security/dns-takeover-ns';
export const SECURITY_DNS_TAKEOVER_TIMEOUT = 'security/dns-takeover-timeout';

export type TakeoverDnsRecordType = 'CNAME' | 'NS' | 'A' | 'AAAA';
export type TakeoverRisk = 'critical' | 'high' | 'medium' | 'low';

/** One DNS answer, normalized across JSON and wire-format resolvers. */
export interface TakeoverDnsRecord {
  type: TakeoverDnsRecordType;
  value: string;
}

export interface TakeoverDnsResponse {
  status: string;
  records: TakeoverDnsRecord[];
}

/**
 * The seam tests use to inject canned DNS answers. The `signal` is aborted
 * after {@link SubdomainTakeoverOptions.timeoutMs} so a hung resolver cannot
 * hang a CI job.
 */
export type TakeoverDnsResolver = (
  domain: string,
  type: TakeoverDnsRecordType,
  signal: AbortSignal,
) => Promise<TakeoverDnsResponse>;

/** A well-known "claimable resource" hostname pattern. */
export interface TakeoverSignature {
  id: string;
  provider: string;
  pattern: RegExp;
  remediation: string;
}

/** Signatures ordered from most to least commonly hijacked. */
export const TAKEOVER_SIGNATURES: readonly TakeoverSignature[] = [
  {
    id: 'aws-s3',
    provider: 'AWS S3 / CloudFront',
    pattern:
      /(?:^|\.)(?:s3[.-][^.]+\.amazonaws\.com|s3\.amazonaws\.com|s3-website[^.]*\.amazonaws\.com|cloudfront\.net)$/i,
    remediation:
      'Delete the CNAME or re-create the exact bucket/distribution (including its region) under the anchor account.',
  },
  {
    id: 'github-pages',
    provider: 'GitHub Pages',
    pattern: /(?:^|\.)(?:github\.io|githubusercontent\.com)$/i,
    remediation:
      'Remove the CNAME, or restore the repository and its custom-domain configuration before it can be claimed.',
  },
  {
    id: 'fastly',
    provider: 'Fastly',
    pattern: /(?:^|\.)(?:map\.)?fastly\.net$/i,
    remediation: 'Delete the CNAME or point it at a Fastly service the anchor still controls.',
  },
  {
    id: 'cloudflare',
    provider: 'Cloudflare',
    pattern: /(?:^|\.)(?:cdn\.cloudflare\.com|cloudflare\.com)$/i,
    remediation: 'Remove the stale CNAME or reattach it to an active Cloudflare zone.',
  },
  {
    id: 'azure',
    provider: 'Microsoft Azure',
    pattern: /(?:^|\.)(?:azurewebsites\.net|cloudapp\.azure\.com|azureedge\.net|azurefd\.net)$/i,
    remediation:
      'Delete the CNAME or restore the Azure resource before someone else claims its name.',
  },
  {
    id: 'heroku',
    provider: 'Heroku',
    pattern: /(?:^|\.)(?:herokuapp\.com|herokudns\.com)$/i,
    remediation: 'Remove the CNAME or repoint it to a live Heroku app owned by the anchor.',
  },
  {
    id: 'netlify',
    provider: 'Netlify',
    pattern: /(?:^|\.)(?:netlify\.app|netlify\.com)$/i,
    remediation: 'Delete the CNAME or restore the Netlify site and its custom domain.',
  },
  {
    id: 'vercel',
    provider: 'Vercel',
    pattern: /(?:^|\.)(?:vercel\.app|vercel\.com)$/i,
    remediation: 'Delete the CNAME or restore the Vercel deployment that owns it.',
  },
  {
    id: 'aws-route53-delegation',
    provider: 'AWS Route 53 delegation',
    pattern: /(?:^|\.)awsdns-\d+\.(?:com|net|org|co\.uk)$/i,
    remediation: 'Remove the stale NS delegation or restore the Route 53 hosted zone.',
  },
];

export interface SubdomainTakeoverOptions {
  rules?: RuleOverrides;
  /** Domain to audit in addition to the ones found in the document. */
  domain?: string;
  /** Inject a DNS responder. Takes precedence over `fetchImpl`. */
  dnsResolver?: TakeoverDnsResolver;
  /** Transport for the default DNS-over-HTTPS responder. */
  fetchImpl?: typeof fetch;
  /** DoH endpoint used by the default responder. */
  resolverUrl?: string;
  /** Per-query timeout in milliseconds. Default 5000. */
  timeoutMs?: number;
  /** Caller cancellation. */
  signal?: AbortSignal;
}

export interface TakeoverFinding {
  domain: string;
  target: string;
  recordType: 'CNAME' | 'NS';
  risk: TakeoverRisk;
  signature?: TakeoverSignature;
  message: string;
  remediation: string;
}

export interface SubdomainTakeoverReport {
  findings: TakeoverFinding[];
  domainsChecked: string[];
  timedOut: string[];
  ok: boolean;
}

const DNS_TYPE_CODES: Record<number, TakeoverDnsRecordType> = {
  1: 'A',
  2: 'NS',
  5: 'CNAME',
  28: 'AAAA',
};

function normalizeHost(value: string): string | undefined {
  const trimmed = value.trim().toLowerCase().replace(/\.$/, '');
  if (trimmed === '' || trimmed.length > 253) return undefined;
  if (!/^(?:[a-z0-9_-]+\.)+[a-z]{2,}$/.test(trimmed)) return undefined;
  if (trimmed.split('.').some((label) => label.length > 63)) return undefined;
  return trimmed;
}

/** Extracts a hostname from a URL or from a bare `example.com` value. */
function hostOfValue(value: string): string | undefined {
  const trimmed = value.trim();
  if (trimmed === '' || /\s/.test(trimmed)) return undefined;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
    try {
      const host = new URL(trimmed).hostname;
      return host === '' || /^\d+\.\d+\.\d+\.\d+$/.test(host) ? undefined : normalizeHost(host);
    } catch {
      return undefined;
    }
  }
  return normalizeHost(trimmed);
}

const MULTI_LABEL_SUFFIXES = new Set([
  'co.uk',
  'org.uk',
  'ac.uk',
  'gov.uk',
  'com.au',
  'net.au',
  'org.au',
  'co.nz',
  'co.jp',
  'com.br',
  'com.cn',
  'co.in',
]);

/** Best-effort registrable domain; a full PSL is unnecessary for triage. */
function apexOf(host: string): string | undefined {
  if (host.startsWith('_')) return undefined;
  const labels = host.split('.');
  if (labels.length < 2) return undefined;
  const lastTwo = labels.slice(-2).join('.');
  if (labels.length >= 3 && MULTI_LABEL_SUFFIXES.has(lastTwo)) {
    return labels.slice(-3).join('.');
  }
  return lastTwo;
}

function collectDomains(doc: Record<string, unknown>, domain?: string): string[] {
  const hosts = new Set<string>();
  const visit = (value: unknown): void => {
    if (typeof value === 'string') {
      const host = hostOfValue(value);
      if (host !== undefined) hosts.add(host);
      return;
    }
    if (Array.isArray(value)) {
      value.forEach(visit);
      return;
    }
    if (typeof value === 'object' && value !== null) {
      Object.values(value).forEach(visit);
    }
  };
  visit(doc);

  for (const explicit of [domain, doc.DOMAIN]) {
    if (typeof explicit !== 'string') continue;
    const host = hostOfValue(explicit);
    if (host !== undefined) hosts.add(host);
  }
  for (const host of [...hosts]) {
    const apex = apexOf(host);
    if (apex !== undefined) hosts.add(apex);
  }
  return [...hosts].sort();
}

/** Default passive DNS-over-HTTPS responder. */
function defaultResolver(fetchImpl: typeof fetch, endpoint: string): TakeoverDnsResolver {
  return async (domain, type, signal) => {
    const url = new URL(endpoint);
    url.searchParams.set('name', domain);
    url.searchParams.set('type', type);
    const response = await fetchImpl(url, {
      headers: { accept: 'application/dns-json' },
      signal,
    });
    if (!response.ok) return { status: 'SERVFAIL', records: [] };
    const body = (await response.json()) as {
      Status?: number;
      Answer?: Array<{ type?: number; data?: unknown }>;
    };
    const records: TakeoverDnsRecord[] = [];
    for (const answer of body.Answer ?? []) {
      const recordType = typeof answer.type === 'number' ? DNS_TYPE_CODES[answer.type] : undefined;
      if (recordType === undefined || typeof answer.data !== 'string') continue;
      records.push({ type: recordType, value: answer.data.replace(/\.$/, '').toLowerCase() });
    }
    const status = body.Status === 3 ? 'NXDOMAIN' : body.Status === 2 ? 'SERVFAIL' : 'NOERROR';
    return { status, records };
  };
}

interface QueryResult {
  response?: TakeoverDnsResponse;
  timedOut: boolean;
}

async function query(
  resolver: TakeoverDnsResolver,
  domain: string,
  type: TakeoverDnsRecordType,
  options: SubdomainTakeoverOptions,
): Promise<QueryResult> {
  const controller = new AbortController();
  const timeoutMs = options.timeoutMs ?? 5000;
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const onAbort = (): void => controller.abort();
  options.signal?.addEventListener('abort', onAbort, { once: true });
  try {
    const response = await resolver(domain, type, controller.signal);
    return { response, timedOut: false };
  } catch {
    return controller.signal.aborted
      ? { timedOut: true }
      : { response: { status: 'SERVFAIL', records: [] }, timedOut: false };
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener('abort', onAbort);
  }
}

function matchingSignature(target: string): TakeoverSignature | undefined {
  return TAKEOVER_SIGNATURES.find((signature) => signature.pattern.test(target));
}

function riskFor(
  signature: TakeoverSignature | undefined,
  recordType: 'CNAME' | 'NS',
): TakeoverRisk {
  if (signature !== undefined) return 'critical';
  return recordType === 'CNAME' ? 'high' : 'medium';
}

function severityFor(rule: string, risk: TakeoverRisk, rules: RuleOverrides | undefined) {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  if (override === 'error' || override === 'warning' || override === 'info') return override;
  return risk === 'critical' ? ('error' as const) : ('warning' as const);
}

/** Scans every domain referenced by the document and returns a risk report. */
export async function scanSubdomainTakeover(
  doc: Record<string, unknown>,
  options: SubdomainTakeoverOptions = {},
): Promise<SubdomainTakeoverReport> {
  const domains = collectDomains(doc, options.domain);
  const resolver =
    options.dnsResolver ??
    defaultResolver(
      options.fetchImpl ?? fetch,
      options.resolverUrl ?? 'https://cloudflare-dns.com/dns-query',
    );
  const findings: TakeoverFinding[] = [];
  const timedOut: string[] = [];

  for (const domain of domains) {
    const cnameResult = await query(resolver, domain, 'CNAME', options);
    if (cnameResult.timedOut) {
      timedOut.push(domain);
      continue;
    }
    const cnames = (cnameResult.response?.records ?? []).filter(
      (record) => record.type === 'CNAME',
    );

    if (cnames.length > 0) {
      for (const cname of cnames) {
        const target = cname.value.replace(/\.$/, '').toLowerCase();
        const [a, aaaa] = await Promise.all([
          query(resolver, target, 'A', options),
          query(resolver, target, 'AAAA', options),
        ]);
        if (a.timedOut || aaaa.timedOut) {
          timedOut.push(target);
          continue;
        }
        const resolves =
          (a.response?.records.some((record) => record.type === 'A') ?? false) ||
          (aaaa.response?.records.some((record) => record.type === 'AAAA') ?? false);
        if (resolves) continue;

        const signature = matchingSignature(target);
        const risk = riskFor(signature, 'CNAME');
        findings.push({
          domain,
          target,
          recordType: 'CNAME',
          risk,
          ...(signature === undefined ? {} : { signature }),
          message:
            signature === undefined
              ? `CNAME ${domain} -> ${target} does not resolve; the name can be claimed`
              : `CNAME ${domain} -> ${target} matches the ${signature.provider} signature and does not resolve`,
          remediation:
            signature?.remediation ??
            'Remove the dangling CNAME or repoint it to a resource the anchor controls.',
        });
      }
      continue;
    }

    // No CNAME: check NS delegation. A delegation to a provider name that no
    // longer exists can be re-registered to host a rogue zone.
    const nsResult = await query(resolver, domain, 'NS', options);
    if (nsResult.timedOut) {
      timedOut.push(domain);
      continue;
    }
    for (const ns of (nsResult.response?.records ?? []).filter((record) => record.type === 'NS')) {
      const target = ns.value.replace(/\.$/, '').toLowerCase();
      const signature = matchingSignature(target);
      if (signature === undefined) continue;
      const check = await query(resolver, target, 'A', options);
      if (check.timedOut) {
        timedOut.push(target);
        continue;
      }
      if (check.response?.status !== 'NXDOMAIN') continue;
      const risk = riskFor(signature, 'NS');
      findings.push({
        domain,
        target,
        recordType: 'NS',
        risk,
        signature,
        message: `NS delegation ${domain} -> ${target} points at a non-existent ${signature.provider} nameserver`,
        remediation: signature.remediation,
      });
    }
  }

  return { findings, domainsChecked: domains, timedOut, ok: findings.length === 0 };
}

/** Converts a risk report into the linter's diagnostic stream. */
export function takeoverDiagnostics(
  report: SubdomainTakeoverReport,
  rules?: RuleOverrides,
): Diagnostic[] {
  const diagnostics: Diagnostic[] = [];

  for (const finding of report.findings) {
    const rule =
      finding.recordType === 'CNAME' ? SECURITY_DNS_TAKEOVER_CNAME : SECURITY_DNS_TAKEOVER_NS;
    const severity = severityFor(rule, finding.risk, rules);
    if (severity === undefined) continue;
    diagnostics.push({
      rule,
      severity,
      category: 'network',
      message: `[${finding.risk.toUpperCase()}] ${finding.message}`,
      path: finding.domain,
      suggestion: finding.remediation,
    });
  }

  if (report.timedOut.length > 0) {
    const severity = severityFor(SECURITY_DNS_TAKEOVER_TIMEOUT, 'medium', rules);
    if (severity !== undefined) {
      diagnostics.push({
        rule: SECURITY_DNS_TAKEOVER_TIMEOUT,
        severity,
        category: 'network',
        message: `DNS lookup timed out for ${report.timedOut.join(', ')}; takeover status is unknown`,
        suggestion: 'Re-run with a reachable DNS resolver or increase the timeout budget.',
      });
    }
  }
  return diagnostics;
}

/** Scans the document and converts the result into diagnostics. */
export async function checkSubdomainTakeover(
  doc: Record<string, unknown>,
  options: SubdomainTakeoverOptions = {},
): Promise<Diagnostic[]> {
  return takeoverDiagnostics(await scanSubdomainTakeover(doc, options), options.rules);
}

/** Human-readable risk report, written to stderr by the CLI. */
export function renderTakeoverReport(report: SubdomainTakeoverReport): string {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const finding of report.findings) counts[finding.risk]++;
  const lines = [
    'Subdomain takeover audit',
    `  Domains checked: ${report.domainsChecked.length}`,
    `  Risk: ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low`,
  ];
  for (const finding of report.findings) {
    lines.push(`  [${finding.risk.toUpperCase()}] ${finding.domain} -> ${finding.target}`);
    lines.push(`      ${finding.remediation}`);
  }
  for (const domain of report.timedOut) lines.push(`  [TIMEOUT] ${domain}`);
  return `${lines.join('\n')}\n`;
}

/** Registered so `--off`/`--warn`/`--error` know these ids. */
export const subdomainTakeoverRules: Rule[] = [
  {
    id: SECURITY_DNS_TAKEOVER_CNAME,
    category: 'network',
    severity: 'error',
    description: 'Anchor domains must not have dangling CNAMEs to claimable cloud resources',
    run() {},
  },
  {
    id: SECURITY_DNS_TAKEOVER_NS,
    category: 'network',
    severity: 'warning',
    description: 'Anchor domains must not delegate to non-existent nameservers',
    run() {},
  },
  {
    id: SECURITY_DNS_TAKEOVER_TIMEOUT,
    category: 'network',
    severity: 'warning',
    description: 'DNS lookups for takeover checks must complete within the timeout budget',
    run() {},
  },
];

export const subdomainTakeoverRuleIds: readonly string[] = subdomainTakeoverRules.map(
  (rule) => rule.id,
);
