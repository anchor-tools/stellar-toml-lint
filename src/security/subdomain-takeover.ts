import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { endpointsOf } from '../network/cert-expiry.js';

export const SECURITY_DANGLING_CNAME_TAKEOVER_RISK = 'security/dangling-cname-takeover-risk';

export interface CnameTargetPattern {
  provider: string;
  suffix: string;
  response: RegExp;
}

export const DEFAULT_TAKEOVER_PATTERNS: readonly CnameTargetPattern[] = [
  {
    provider: 'Amazon S3',
    suffix: 's3.amazonaws.com',
    response: /(?:NoSuchBucket|specified bucket does not exist)/i,
  },
  {
    provider: 'GitHub Pages',
    suffix: 'github.io',
    response: /There isn't a GitHub Pages site here/i,
  },
  {
    provider: 'Heroku',
    suffix: 'herokuapp.com',
    response: /(?:No such app|herokucdn\.com\/error-pages\/no-such-app)/i,
  },
];

export interface SubdomainTakeoverOptions {
  rules?: RuleOverrides;
  resolveCname?: (hostname: string) => Promise<string[]>;
  fetchImpl?: typeof fetch;
  patterns?: readonly CnameTargetPattern[];
}

interface DeclaredHost {
  host: string;
  field: string;
}

function severityFor(rules: RuleOverrides | undefined): 'warning' | 'error' | undefined {
  const override = rules?.[SECURITY_DANGLING_CNAME_TAKEOVER_RISK];
  if (override === 'off') return undefined;
  return override === 'warning' || override === 'error' ? override : 'error';
}

function hostname(value: unknown): string | undefined {
  if (typeof value !== 'string' || value.trim() === '') return undefined;
  const candidate = value.includes('://') ? value : `https://${value}`;
  try {
    return new URL(candidate).hostname.toLowerCase().replace(/\.$/, '');
  } catch {
    return undefined;
  }
}

function declaredHosts(doc: Record<string, unknown>): DeclaredHost[] {
  const hosts = new Map<string, DeclaredHost>();
  for (const endpoint of endpointsOf(doc)) {
    hosts.set(endpoint.host, { host: endpoint.host, field: endpoint.field });
  }
  const domain = hostname(doc.DOMAIN);
  if (domain !== undefined) hosts.set(domain, { host: domain, field: 'DOMAIN' });

  const documentation = doc.DOCUMENTATION;
  const visit = (value: unknown, path: string): void => {
    if (typeof value === 'string') {
      const host = hostname(value);
      if (host !== undefined) hosts.set(host, { host, field: path });
    } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      for (const [key, child] of Object.entries(value)) visit(child, `${path}.${key}`);
    } else if (Array.isArray(value)) {
      value.forEach((child, index) => visit(child, `${path}[${index}]`));
    }
  };
  visit(documentation, 'DOCUMENTATION');
  return [...hosts.values()];
}

function matchingPattern(
  target: string,
  patterns: readonly CnameTargetPattern[],
): CnameTargetPattern | undefined {
  const normalized = target.toLowerCase().replace(/\.$/, '');
  return patterns.find((pattern) => {
    const suffix = pattern.suffix.toLowerCase().replace(/^\.|\.$/g, '');
    return normalized === suffix || normalized.endsWith(`.${suffix}`);
  });
}

async function hasUnclaimedSignature(
  host: string,
  pattern: CnameTargetPattern,
  fetchImpl: typeof fetch,
): Promise<boolean> {
  for (const protocol of ['https:', 'http:']) {
    try {
      const response = await fetchImpl(`${protocol}//${host}/`, {
        method: 'GET',
        redirect: 'manual',
        signal: AbortSignal.timeout(5_000),
      });
      const body = await response.text();
      if (pattern.response.test(body)) return true;
    } catch {
      // An unreachable service is not evidence that its resource is unclaimed.
    }
  }
  return false;
}

export async function checkSubdomainTakeover(
  doc: Record<string, unknown>,
  options: SubdomainTakeoverOptions = {},
): Promise<Diagnostic[]> {
  const severity = severityFor(options.rules);
  if (severity === undefined) return [];

  const resolveCname =
    options.resolveCname ??
    (async (host: string) => {
      const dns = await import('node:dns/promises');
      return dns.resolveCname(host);
    });
  const fetchImpl = options.fetchImpl ?? fetch;
  const patterns = options.patterns ?? DEFAULT_TAKEOVER_PATTERNS;
  const diagnostics: Diagnostic[] = [];
  for (const endpoint of declaredHosts(doc)) {
    let targets: string[];
    try {
      targets = await resolveCname(endpoint.host);
    } catch {
      continue;
    }
    for (const target of targets) {
      const pattern = matchingPattern(target, patterns);
      if (pattern === undefined) continue;
      if (!(await hasUnclaimedSignature(endpoint.host, pattern, fetchImpl))) continue;
      diagnostics.push({
        rule: SECURITY_DANGLING_CNAME_TAKEOVER_RISK,
        severity,
        category: 'network',
        message: `${endpoint.host} points to an unclaimed ${pattern.provider} resource (${target})`,
        path: endpoint.field,
        suggestion:
          'Claim the referenced SaaS resource or remove the stale CNAME record before publishing the endpoint.',
      });
      break;
    }
  }
  return diagnostics;
}

export const subdomainTakeoverRules: Rule[] = [
  {
    id: SECURITY_DANGLING_CNAME_TAKEOVER_RISK,
    category: 'network',
    severity: 'error',
    description: 'Declared hostnames must not alias unclaimed third-party hosting resources',
    run() {},
  },
];
