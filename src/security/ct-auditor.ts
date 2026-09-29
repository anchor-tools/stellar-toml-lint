/**
 * Anchor TLS Certificate Transparency (CT) and public-key pin auditor.
 *
 * Anchors handle fiat flows, so a rogue or compromised CA issuing a certificate
 * for the anchor's domain is a serious threat. This auditor queries public CT
 * log aggregators for certificates issued for the anchor domain and flags
 * certificates whose issuer is not a recognized CA, as well as domains with no
 * CT evidence at all (a sign of missing Signed Certificate Timestamps).
 *
 * Runs under the opt-in `--check-network` flag and degrades to silence when the
 * CT log API is unreachable.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';

export const SECURITY_MISSING_SCT_TIMESTAMPS = 'security/missing-sct-timestamps';
export const SECURITY_UNRECOGNIZED_CA_IN_CT_LOGS = 'security/unrecognized-ca-in-ct-logs';

export const MISSING_SCT_TIMESTAMPS_RULE = SECURITY_MISSING_SCT_TIMESTAMPS;
export const UNRECOGNIZED_CA_IN_CT_LOGS_RULE = SECURITY_UNRECOGNIZED_CA_IN_CT_LOGS;

/** crt.sh aggregates Google Argon and Cloudflare Nimbus CT logs. */
export const DEFAULT_CT_LOG_URL = 'https://crt.sh/';

/**
 * Recognized CA issuers. Matched case-insensitively as substrings of the CT
 * `issuer_name`, so an entry like `C=US, O=DigiCert Inc, CN=DigiCert TLS RSA`
 * is recognized while an unexpected issuer is not.
 */
export const DEFAULT_TRUSTED_CAS: readonly string[] = [
  "Let's Encrypt",
  'ISRG',
  'DigiCert',
  'GlobalSign',
  'Sectigo',
  'Comodo',
  'Google Trust Services',
  'Amazon',
  'Cloudflare',
  'Entrust',
  'GoDaddy',
];

export interface CtCertificate {
  issuer?: string;
  commonName?: string;
  notBefore?: string;
  notAfter?: string;
}

export interface CtAuditOptions {
  rules?: RuleOverrides;
  fetchImpl?: typeof fetch;
  trustedCas?: readonly string[];
  logUrl?: string;
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

function isTrustedIssuer(issuer: string, trustedCas: readonly string[]): boolean {
  const normalized = issuer.toLowerCase();
  return trustedCas.some((ca) => normalized.includes(ca.toLowerCase()));
}

/**
 * Query a CT log aggregator for certificates issued for `domain`.
 * Returns `undefined` when the log cannot be reached so callers can skip.
 */
export async function fetchCtEntries(
  domain: string,
  options: CtAuditOptions = {},
): Promise<CtCertificate[] | undefined> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const base = options.logUrl ?? DEFAULT_CT_LOG_URL;
  const url = `${base.replace(/\/$/, '')}/?q=${encodeURIComponent(`%.${domain}`)}&output=json`;

  try {
    const response = await fetchImpl(url, { headers: { Accept: 'application/json' } });
    if (!response.ok) return undefined;
    const body = (await response.json()) as unknown;
    if (!Array.isArray(body)) return undefined;

    const certificates: CtCertificate[] = [];
    for (const entry of body) {
      if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) continue;
      const record = entry as Record<string, unknown>;
      const issuer = typeof record.issuer_name === 'string' ? record.issuer_name : undefined;
      certificates.push({
        ...(issuer === undefined ? {} : { issuer }),
        ...(typeof record.common_name === 'string' ? { commonName: record.common_name } : {}),
        ...(typeof record.not_before === 'string' ? { notBefore: record.not_before } : {}),
        ...(typeof record.not_after === 'string' ? { notAfter: record.not_after } : {}),
      });
    }
    return certificates;
  } catch {
    return undefined;
  }
}

/** Pure analysis of CT entries for a domain. */
export function analyzeCtCertificates(
  domain: string,
  certificates: readonly CtCertificate[],
  options: CtAuditOptions = {},
): Diagnostic[] {
  const { rules } = options;
  const trustedCas = options.trustedCas ?? DEFAULT_TRUSTED_CAS;
  const diagnostics: Diagnostic[] = [];

  const missingSctSeverity = severityFor(SECURITY_MISSING_SCT_TIMESTAMPS, 'warning', rules);
  if (missingSctSeverity !== undefined && certificates.length === 0) {
    diagnostics.push({
      rule: SECURITY_MISSING_SCT_TIMESTAMPS,
      severity: missingSctSeverity,
      category: 'network',
      message: `No Certificate Transparency entries were found for ${domain}, so TLS connections may lack Signed Certificate Timestamps`,
      suggestion:
        'Serve certificates that embed SCTs and verify the CT log coverage for the anchor domain.',
    });
  }

  const unrecognizedSeverity = severityFor(SECURITY_UNRECOGNIZED_CA_IN_CT_LOGS, 'warning', rules);
  if (unrecognizedSeverity !== undefined) {
    const unrecognized = [
      ...new Set(
        certificates
          .map((certificate) => certificate.issuer)
          .filter((issuer): issuer is string => typeof issuer === 'string')
          .filter((issuer) => !isTrustedIssuer(issuer, trustedCas)),
      ),
    ];
    if (unrecognized.length > 0) {
      diagnostics.push({
        rule: SECURITY_UNRECOGNIZED_CA_IN_CT_LOGS,
        severity: unrecognizedSeverity,
        category: 'network',
        message: `CT logs show ${domain} was issued certificates by unrecognized CA(s): ${unrecognized.join('; ')}`,
        suggestion:
          'Investigate unexpected issuers for rogue or mis-issued certificates and consider pinning the expected CA.',
      });
    }
  }

  return diagnostics;
}

export async function checkCertificateTransparency(
  domain: string,
  options: CtAuditOptions = {},
): Promise<Diagnostic[]> {
  const certificates = await fetchCtEntries(domain, options);
  if (certificates === undefined) return [];
  return analyzeCtCertificates(domain, certificates, options);
}

/** Domain-aware entry point for a parsed stellar.toml document. */
export async function checkCertificateTransparencyFromDocument(
  doc: Record<string, unknown>,
  options: CtAuditOptions = {},
): Promise<Diagnostic[]> {
  const direct = normalizeDomain(doc.DOMAIN);
  let domain = direct;
  if (domain === undefined) {
    const documentation = doc.DOCUMENTATION;
    if (
      typeof documentation === 'object' &&
      documentation !== null &&
      !Array.isArray(documentation)
    ) {
      domain = normalizeDomain((documentation as Record<string, unknown>).ORG_URL);
    }
  }
  if (domain === undefined) return [];
  return checkCertificateTransparency(domain, options);
}

export const ctAuditorRules: Rule[] = [
  {
    id: SECURITY_MISSING_SCT_TIMESTAMPS,
    category: 'network',
    severity: 'warning',
    description: 'Anchor TLS certificates should provide Signed Certificate Timestamps',
    run() {},
  },
  {
    id: SECURITY_UNRECOGNIZED_CA_IN_CT_LOGS,
    category: 'network',
    severity: 'warning',
    description: 'Certificates in CT logs should be issued by recognized CAs',
    run() {},
  },
];

export const ctAuditorRuleIds: readonly string[] = ctAuditorRules.map((rule) => rule.id);
