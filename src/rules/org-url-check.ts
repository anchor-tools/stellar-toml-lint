import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isString, isUrl } from '../predicates.js';
import { specUrl } from '../spec.js';

/**
 * Opt-in-with-domain probe of the `ORG_URL` a SEP-1 file advertises.
 *
 * `ORG_URL` in `[DOCUMENTATION]` is the primary canonical identity anchor for
 * the organization publishing the file. A value that fails DNS resolution,
 * presents an expired TLS certificate, or simply answers 5xx breaks automated
 * anchor vetting and wallet trust even when the rest of the file is flawless.
 *
 * Like the other network audits, the rule object registered below exists so
 * `--list-rules` and `--off`/`--warn`/`--error` know the id; the probe itself
 * only runs from {@link lintDomain}, so offline runs stay pure and offline.
 */

const UNREACHABLE_RULE = 'network/org-url-unreachable';

interface AuditOptions {
  rules?: RuleOverrides;
}

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules?: RuleOverrides,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}

/**
 * Probes `url` with HEAD, falling back to GET when the server rejects the
 * method (405/501). Returns `undefined` when the endpoint is reachable with a
 * valid TLS session, or a human-readable reason when it is not.
 */
async function probeEndpoint(url: string, fetchImpl: typeof fetch): Promise<string | undefined> {
  let methodRejected = false;
  try {
    const response = await fetchImpl(url, { method: 'HEAD', redirect: 'follow' });
    if (response.ok) return undefined;
    if (response.status !== 405 && response.status !== 501) {
      return `ORG_URL at ${url} returned HTTP ${response.status}`;
    }
    methodRejected = true;
  } catch (error) {
    return `Could not reach ORG_URL at ${url}: ${errorMessage(error)}`;
  }

  if (methodRejected) {
    try {
      const response = await fetchImpl(url, { method: 'GET', redirect: 'follow' });
      if (response.ok) return undefined;
      return `ORG_URL at ${url} returned HTTP ${response.status}`;
    } catch (error) {
      return `Could not reach ORG_URL at ${url}: ${errorMessage(error)}`;
    }
  }

  return undefined;
}

/**
 * Probes `DOCUMENTATION.ORG_URL` over HTTPS so a dead or misconfigured
 * identity anchor is caught at lint time.
 *
 * Silent when the file has no `[DOCUMENTATION].ORG_URL`, when the value is not
 * a parseable `https://` URL (the offline `documentation` rules already report
 * that), or when the rule is switched off — a probe that would be ignored is
 * a probe that should not be made.
 */
export async function checkOrgUrl(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: AuditOptions = {},
): Promise<Diagnostic[]> {
  const severity = severityFor(UNREACHABLE_RULE, 'error', options.rules);
  if (severity === undefined) return [];

  const documentation = doc.DOCUMENTATION;
  if (typeof documentation !== 'object' || documentation === null || Array.isArray(documentation)) {
    return [];
  }

  const orgUrl = (documentation as Record<string, unknown>).ORG_URL;
  if (!isString(orgUrl) || !isUrl(orgUrl)) return [];

  let parsed: URL;
  try {
    parsed = new URL(orgUrl);
  } catch {
    return [];
  }
  if (parsed.protocol !== 'https:') return [];

  const detail = await probeEndpoint(orgUrl, fetchImpl);
  if (detail === undefined) return [];

  return [
    {
      rule: UNREACHABLE_RULE,
      severity,
      category: 'network',
      message: detail,
      path: 'DOCUMENTATION.ORG_URL',
      helpUri: specUrl('specification'),
      suggestion:
        'Confirm ORG_URL resolves over DNS, presents a valid TLS certificate, and answers before wallets and vetting tools probe it.',
    },
  ];
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const orgUrlRules: Rule[] = [
  {
    id: UNREACHABLE_RULE,
    category: 'network',
    severity: 'error',
    description: 'ORG_URL must be a reachable HTTPS endpoint with valid TLS',
    run() {},
  },
];

/** Rule ids emitted by {@link checkOrgUrl}. */
export const orgUrlRuleIds: readonly string[] = orgUrlRules.map((rule) => rule.id);
