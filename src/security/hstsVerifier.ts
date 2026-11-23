/**
 * HSTS header and preload eligibility verifier.
 *
 * Runs under opt-in `--audit-hsts`.
 *
 * Without HSTS a first visit over plain HTTP can be stripped to an attacker
 * controlled connection. Hosts are the apex domain plus every subdomain
 * `stellar.toml` points at (ORG_URL and the `*_SERVER` / `*_URL` endpoints).
 * Criteria follow the Chromium preload list (hstspreload.org): a `max-age` of
 * at least one year, plus `includeSubDomains` and `preload` on the apex.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { hostOf, isString } from '../predicates.js';
import { errorMessage, fetchWithTimeout, severityFor } from '../protocols/verifierSupport.js';

const MISSING_RULE = 'hsts/missing-header';
const INVALID_RULE = 'hsts/invalid-header';
const SHORT_RULE = 'hsts/short-max-age';
const SUBDOMAINS_RULE = 'hsts/missing-include-subdomains';
const PRELOAD_RULE = 'hsts/missing-preload';
const UNREACHABLE_RULE = 'hsts/unreachable';

const SPEC = 'https://hstspreload.org/#deployment-recommendations';

/** One year, the Chromium preload minimum. */
export const MIN_MAX_AGE = 31_536_000;

export interface HstsPolicy {
  maxAge: number;
  includeSubDomains: boolean;
  preload: boolean;
}

/** Parses a `Strict-Transport-Security` value; returns an error string for malformed input. */
export function parseHsts(header: string): HstsPolicy | { error: string } {
  let maxAge: number | undefined;
  let includeSubDomains = false;
  let preload = false;
  const seen = new Set<string>();
  for (const raw of header.split(';')) {
    const part = raw.trim();
    if (part === '') continue;
    const eq = part.indexOf('=');
    const name = (eq === -1 ? part : part.slice(0, eq)).trim().toLowerCase();
    const value =
      eq === -1
        ? undefined
        : part
            .slice(eq + 1)
            .trim()
            .replace(/^"(.*)"$/, '$1');
    if (seen.has(name)) return { error: `duplicate directive "${name}"` };
    seen.add(name);
    if (name === 'max-age') {
      if (value === undefined || !/^\d+$/.test(value)) {
        return { error: `max-age must be a non-negative integer, got "${value ?? ''}"` };
      }
      maxAge = Number(value);
    } else if (name === 'includesubdomains') includeSubDomains = true;
    else if (name === 'preload') preload = true;
  }
  if (maxAge === undefined) return { error: 'max-age directive is required' };
  return { maxAge, includeSubDomains, preload };
}

/** Hosts worth checking: `domain` first, then every host the file points at. */
export function collectHosts(doc: Record<string, unknown>, domain?: string): string[] {
  const hosts = new Set<string>();
  if (domain) hosts.add(domain.toLowerCase());
  for (const [key, value] of Object.entries(doc)) {
    if (key !== 'ORG_URL' && !/_(SERVER|URL)(_SEP[0-9]+)?$/.test(key)) continue;
    const host = hostOf(value);
    if (host) hosts.add(host);
  }
  const org = doc.DOCUMENTATION;
  if (typeof org === 'object' && org !== null) {
    const host = hostOf((org as Record<string, unknown>).ORG_URL);
    if (host) hosts.add(host);
  }
  return [...hosts];
}

export interface HstsOptions {
  rules?: RuleOverrides;
  /** The apex domain; its policy is held to the full preload criteria. */
  domain?: string;
  timeoutMs?: number;
}

export interface HstsHostResult {
  host: string;
  apex: boolean;
  header?: string;
  policy?: HstsPolicy;
  /** `PRELOAD-READY`, `COMPLIANT`, `PARTIAL` or `FAIL`. */
  badge: 'PRELOAD-READY' | 'COMPLIANT' | 'PARTIAL' | 'FAIL' | 'UNREACHABLE';
}

export interface HstsResult {
  diagnostics: Diagnostic[];
  hosts: HstsHostResult[];
}

export class HstsSecurityVerifier {
  constructor(
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly options: HstsOptions = {},
  ) {}

  async verify(doc: Record<string, unknown>): Promise<HstsResult> {
    const diagnostics: Diagnostic[] = [];
    const hosts: HstsHostResult[] = [];
    const apexHost = (this.options.domain ?? hostOf(doc.ORG_URL))?.toLowerCase();

    for (const host of collectHosts(doc, this.options.domain)) {
      const apex = host === apexHost;
      const push = (
        rule: string,
        fallback: 'error' | 'warning',
        message: string,
        suggestion: string,
      ): void => {
        const severity = severityFor(rule, fallback, this.options.rules);
        if (severity === undefined) return;
        diagnostics.push({
          rule,
          severity,
          category: 'network',
          message: `${host}: ${message}`,
          path: host,
          helpUri: SPEC,
          suggestion,
        });
      };

      let header: string | null;
      try {
        const res = await fetchWithTimeout(
          this.fetchImpl,
          `https://${host}/`,
          { method: 'HEAD', redirect: 'manual' },
          this.options.timeoutMs,
        );
        header = res.headers.get('strict-transport-security');
      } catch (error) {
        push(
          UNREACHABLE_RULE,
          'warning',
          `could not be reached over HTTPS (${errorMessage(error)})`,
          'Make sure the host answers over HTTPS within a few seconds.',
        );
        hosts.push({ host, apex, badge: 'UNREACHABLE' });
        continue;
      }

      if (!isString(header) || header.trim() === '') {
        push(
          MISSING_RULE,
          'error',
          'no Strict-Transport-Security header',
          'Send "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload".',
        );
        hosts.push({ host, apex, badge: 'FAIL' });
        continue;
      }
      const policy = parseHsts(header);
      if ('error' in policy) {
        push(
          INVALID_RULE,
          'error',
          `malformed Strict-Transport-Security header (${policy.error})`,
          'Use the form "max-age=<seconds>; includeSubDomains; preload".',
        );
        hosts.push({ host, apex, header, badge: 'FAIL' });
        continue;
      }

      let failed = false;
      let partial = false;
      if (policy.maxAge < MIN_MAX_AGE) {
        failed = true;
        push(
          SHORT_RULE,
          'error',
          `max-age ${policy.maxAge} is below one year (${MIN_MAX_AGE})`,
          `Raise max-age to at least ${MIN_MAX_AGE}.`,
        );
      }
      // The preload list is keyed on the apex; subdomains inherit from it.
      if (apex && !policy.includeSubDomains) {
        partial = true;
        push(
          SUBDOMAINS_RULE,
          'warning',
          'includeSubDomains is missing',
          'Add includeSubDomains so every subdomain is protected too.',
        );
      }
      if (apex && !policy.preload) {
        partial = true;
        push(
          PRELOAD_RULE,
          'warning',
          'preload directive is missing, so the domain is not preload eligible',
          'Add preload, then submit the domain at hstspreload.org.',
        );
      }
      hosts.push({
        host,
        apex,
        header,
        policy,
        badge: failed ? 'FAIL' : partial ? 'PARTIAL' : apex ? 'PRELOAD-READY' : 'COMPLIANT',
      });
    }
    return { diagnostics, hosts };
  }
}

export async function auditHsts(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: HstsOptions = {},
): Promise<HstsResult> {
  return new HstsSecurityVerifier(fetchImpl, options).verify(doc);
}

export function renderHstsBadges(result: HstsResult): string {
  if (result.hosts.length === 0) return '';
  const lines = result.hosts.map((h) => `  [${h.badge}] ${h.host}${h.apex ? ' (apex)' : ''}`);
  return `HSTS compliance\n${lines.join('\n')}\n`;
}

const def = (id: string, description: string): Rule => ({
  id,
  category: 'network',
  severity: 'warning',
  description,
  run() {},
});

export const hstsRules: Rule[] = [
  def(MISSING_RULE, 'Hosts must send a Strict-Transport-Security header'),
  def(INVALID_RULE, 'The Strict-Transport-Security header must be well formed'),
  def(SHORT_RULE, 'HSTS max-age must be at least one year'),
  def(SUBDOMAINS_RULE, 'The apex HSTS policy should include subdomains'),
  def(PRELOAD_RULE, 'The apex HSTS policy should carry the preload directive'),
  def(UNREACHABLE_RULE, 'Hosts must be reachable over HTTPS to check HSTS'),
];

export const hstsRuleIds: readonly string[] = hstsRules.map((r) => r.id);
