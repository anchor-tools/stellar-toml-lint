import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { HTTPS_ENDPOINT_FIELDS } from '../spec.js';
import { hostOf, isString } from '../predicates.js';

export const SECURITY_MISSING_CAA_RULE = 'security/missing-caa-records';
export const SECURITY_UNAUTHORIZED_CA_RULE = 'security/unauthorized-issuing-ca';

export interface CaaRecord {
  issue?: string;
  issuewild?: string;
}

export type CaaResolver = (hostname: string) => Promise<CaaRecord[] | undefined>;
export type CertificateIssuerProbe = (hostname: string) => Promise<string | undefined>;

export interface CaaAuditorOptions {
  rules?: RuleOverrides;
  resolveCaa?: CaaResolver;
  certificateIssuer?: CertificateIssuerProbe;
  domain?: string;
}

export const caaAuditorRules: Rule[] = [
  {
    id: SECURITY_MISSING_CAA_RULE,
    category: 'network',
    severity: 'warning',
    description: 'Anchor domains should publish CAA issuer policies',
    run() {},
  },
  {
    id: SECURITY_UNAUTHORIZED_CA_RULE,
    category: 'network',
    severity: 'error',
    description: 'The active TLS certificate issuer should be authorized by CAA',
    run() {},
  },
];

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules: RuleOverrides | undefined,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

const systemCaaResolver: CaaResolver = async (hostname) => {
  const dns = await import('node:dns/promises').catch(() => null);
  if (dns === null) return undefined;
  const labels = hostname.split('.');
  for (let index = 0; index < labels.length - 1; index += 1) {
    try {
      const records = await dns.resolveCaa(labels.slice(index).join('.'));
      if (records.length > 0) return records;
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== 'ENODATA' && code !== 'ENOTFOUND') return undefined;
    }
  }
  return [];
};

const systemCertificateIssuer: CertificateIssuerProbe = async (hostname) => {
  const tls = await import('node:tls').catch(() => null);
  if (tls === null) return undefined;
  return new Promise((resolve) => {
    let settled = false;
    const socket = tls.connect({ host: hostname, port: 443, servername: hostname });
    const finish = (issuer: string | undefined): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(issuer);
    };
    socket.setTimeout(5_000);
    socket.once('secureConnect', () => {
      const issuer = socket.getPeerCertificate().issuer;
      const text =
        typeof issuer === 'string'
          ? issuer
          : issuer === undefined
            ? ''
            : [issuer.O, issuer.CN].filter((part) => typeof part === 'string').join(' ');
      finish(text || undefined);
    });
    socket.once('timeout', () => finish(undefined));
    socket.once('error', () => finish(undefined));
  });
};

function targetsOf(doc: Record<string, unknown>, domain?: string): string[] {
  const targets = new Set<string>();
  const rootValue = domain ?? doc.DOMAIN;
  const root =
    typeof rootValue === 'string'
      ? (() => {
          try {
            const candidate = rootValue.includes('://') ? rootValue : `https://${rootValue}`;
            return new URL(candidate).hostname;
          } catch {
            return undefined;
          }
        })()
      : undefined;
  if (root !== undefined) targets.add(root.toLowerCase());
  const documentation = doc.DOCUMENTATION;
  if (
    typeof documentation === 'object' &&
    documentation !== null &&
    !Array.isArray(documentation)
  ) {
    const organizationUrl = hostOf((documentation as Record<string, unknown>).ORG_URL);
    if (organizationUrl !== undefined) targets.add(organizationUrl.toLowerCase());
  }
  for (const field of HTTPS_ENDPOINT_FIELDS) {
    const value = doc[field];
    if (!isString(value)) continue;
    const host = hostOf(value);
    if (host !== undefined) targets.add(host.toLowerCase());
  }
  return [...targets];
}

const caAliases: Readonly<Record<string, string[]>> = {
  'letsencrypt.org': ["let's encrypt", 'isrg'],
  'digicert.com': ['digicert'],
  'sectigo.com': ['sectigo', 'comodo'],
  'globalsign.com': ['globalsign'],
  'amazon.com': ['amazon'],
  'pki.goog': ['google trust services', 'google'],
};

export function isCaaIssuerAuthorized(issuer: string, caaValues: readonly string[]): boolean {
  const normalizedIssuer = issuer.toLowerCase();
  return caaValues.some((value) => {
    const ca = value.split(';', 1)[0]?.trim().toLowerCase();
    if (!ca) return false;
    if (normalizedIssuer.includes(ca)) return true;
    const aliases = caAliases[ca];
    return aliases?.some((alias) => normalizedIssuer.includes(alias)) ?? false;
  });
}

export async function auditCaa(
  doc: Record<string, unknown>,
  options: CaaAuditorOptions = {},
): Promise<Diagnostic[]> {
  const diagnostics: Diagnostic[] = [];
  const targets = targetsOf(doc, options.domain);
  const resolveCaa = options.resolveCaa ?? systemCaaResolver;
  const certificateIssuer = options.certificateIssuer ?? systemCertificateIssuer;

  for (const host of targets) {
    const records = await resolveCaa(host);
    if (records === undefined) continue;
    const issue = records.map((record) => record.issue).filter((value): value is string => !!value);
    const issuewild = records
      .map((record) => record.issuewild)
      .filter((value): value is string => !!value);
    if (issue.length === 0 || issuewild.length === 0) {
      const severity = severityFor(SECURITY_MISSING_CAA_RULE, 'warning', options.rules);
      if (severity !== undefined) {
        diagnostics.push({
          rule: SECURITY_MISSING_CAA_RULE,
          severity,
          category: 'network',
          message: `${host} is missing CAA issue or issuewild authorization records`,
          suggestion:
            'Publish CAA issue and issuewild records for the Certificate Authorities you trust.',
        });
      }
    }

    const issuer = await certificateIssuer(host);
    if (issuer !== undefined && issue.length > 0 && !isCaaIssuerAuthorized(issuer, issue)) {
      const severity = severityFor(SECURITY_UNAUTHORIZED_CA_RULE, 'error', options.rules);
      if (severity !== undefined) {
        diagnostics.push({
          rule: SECURITY_UNAUTHORIZED_CA_RULE,
          severity,
          category: 'network',
          message: `${host} currently serves a certificate from ${issuer}, which is not authorized by its CAA issue records`,
          suggestion:
            'Authorize the active Certificate Authority in DNS CAA records or replace the certificate.',
        });
      }
    }
  }

  return diagnostics;
}
