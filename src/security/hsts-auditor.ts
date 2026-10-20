import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';
import { HTTPS_ENDPOINT_FIELDS } from '../spec.js';
import { isString } from '../predicates.js';

export const MISSING_HSTS_HEADER_RULE = 'security/missing-hsts-header';
export const INSUFFICIENT_HSTS_MAX_AGE_RULE = 'security/insufficient-hsts-max-age';

const MINIMUM_MAX_AGE = 31_536_000;
const HSTS_DOC =
  'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security';
const CHECKED_FIELDS = [...HTTPS_ENDPOINT_FIELDS, 'HORIZON_URL'];

export interface HstsOptions {
  rules?: RuleOverrides;
}

function severityFor(
  rule: string,
  fallback: Severity,
  rules: RuleOverrides | undefined,
): Severity | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' || override === 'info'
    ? override
    : fallback;
}

function endpointsOf(doc: Record<string, unknown>): { field: string; url: string }[] {
  const seen = new Set<string>();
  const endpoints: { field: string; url: string }[] = [];
  for (const field of CHECKED_FIELDS) {
    const value = doc[field];
    if (!isString(value)) continue;
    try {
      const url = new URL(value);
      if (url.protocol !== 'https:') continue;
      const normalized = url.toString();
      if (seen.has(normalized)) continue;
      seen.add(normalized);
      endpoints.push({ field, url: normalized });
    } catch {
      // The offline URL rule owns malformed endpoint values.
    }
  }
  return endpoints;
}

function parseDirectives(header: string): Map<string, string | true> {
  const directives = new Map<string, string | true>();
  for (const item of header.split(';')) {
    const separator = item.indexOf('=');
    const name = (separator < 0 ? item : item.slice(0, separator)).trim().toLowerCase();
    if (name === '') continue;
    const value =
      separator < 0
        ? true
        : item
            .slice(separator + 1)
            .trim()
            .replace(/^"|"$/g, '');
    directives.set(name, value);
  }
  return directives;
}

/** Checks the HSTS policy served by each declared HTTPS endpoint. */
export async function checkHsts(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: HstsOptions = {},
): Promise<Diagnostic[]> {
  const endpoints = endpointsOf(doc);
  const missingSeverity = severityFor(MISSING_HSTS_HEADER_RULE, 'error', options.rules);
  const weakSeverity = severityFor(INSUFFICIENT_HSTS_MAX_AGE_RULE, 'warning', options.rules);
  if (endpoints.length === 0 || (missingSeverity === undefined && weakSeverity === undefined))
    return [];

  const diagnostics: Diagnostic[] = [];
  for (const endpoint of endpoints) {
    let response: Response;
    try {
      response = await fetchImpl(endpoint.url, { method: 'HEAD', redirect: 'follow' });
    } catch {
      continue;
    }

    const header = response.headers.get('strict-transport-security');
    if (header === null) {
      if (missingSeverity !== undefined) {
        diagnostics.push({
          rule: MISSING_HSTS_HEADER_RULE,
          severity: missingSeverity,
          category: 'network',
          message: `${endpoint.field} endpoint does not serve a Strict-Transport-Security header`,
          path: endpoint.field,
          helpUri: HSTS_DOC,
          suggestion: 'Serve HSTS with max-age=31536000; includeSubDomains; preload over HTTPS.',
        });
      }
      continue;
    }

    const directives = parseDirectives(header);
    const rawMaxAge = directives.get('max-age');
    const maxAge = typeof rawMaxAge === 'string' && /^\d+$/.test(rawMaxAge) ? Number(rawMaxAge) : 0;
    const deficiencies: string[] = [];
    if (!Number.isSafeInteger(maxAge) || maxAge < MINIMUM_MAX_AGE) {
      deficiencies.push('max-age must be at least 31536000 seconds');
    }
    if (!directives.has('includesubdomains')) deficiencies.push('includeSubDomains is missing');
    if (!directives.has('preload')) deficiencies.push('preload is missing');
    if (deficiencies.length === 0 || weakSeverity === undefined) continue;

    diagnostics.push({
      rule: INSUFFICIENT_HSTS_MAX_AGE_RULE,
      severity: weakSeverity,
      category: 'network',
      message: `${endpoint.field} endpoint has an incomplete HSTS policy: ${deficiencies.join('; ')}`,
      path: endpoint.field,
      helpUri: HSTS_DOC,
      suggestion: 'Use max-age=31536000 or greater with includeSubDomains and preload directives.',
    });
  }
  return diagnostics;
}

export const hstsAuditorRules: Rule[] = [
  {
    id: MISSING_HSTS_HEADER_RULE,
    category: 'network',
    severity: 'error',
    description: 'Every declared HTTPS endpoint should serve a Strict-Transport-Security header',
    run() {},
  },
  {
    id: INSUFFICIENT_HSTS_MAX_AGE_RULE,
    category: 'network',
    severity: 'warning',
    description: 'HSTS should use a one-year max-age, includeSubDomains, and preload',
    run() {},
  },
];
