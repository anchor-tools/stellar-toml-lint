import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isString, isUrl } from '../predicates.js';
import { specUrl } from '../spec.js';
import { documentationOf } from './documentation.js';

const MISSING_PRIVACY_POLICY_RULE = 'documentation/missing-privacy-policy';
const MISSING_TERMS_OF_SERVICE_RULE = 'documentation/missing-terms-of-service';
const LEGAL_URL_UNREACHABLE_RULE = 'documentation/legal-url-unreachable';

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
 * Probes a URL with HEAD, falling back to GET when the server rejects the
 * method (405/501). Returns `undefined` when the endpoint responds with HTTP
 * 200, or a human-readable reason when it does not.
 */
async function probeLegalUrl(url: string, fetchImpl: typeof fetch): Promise<string | undefined> {
  let methodRejected = false;
  try {
    const response = await fetchImpl(url, { method: 'HEAD', redirect: 'follow' });
    if (response.ok) return undefined;
    if (response.status !== 405 && response.status !== 501) {
      return `URL ${url} returned HTTP ${response.status}`;
    }
    methodRejected = true;
  } catch (error) {
    return `Could not reach ${url}: ${errorMessage(error)}`;
  }

  if (methodRejected) {
    try {
      const response = await fetchImpl(url, { method: 'GET', redirect: 'follow' });
      if (response.ok) return undefined;
      return `URL ${url} returned HTTP ${response.status}`;
    } catch (error) {
      return `Could not reach ${url}: ${errorMessage(error)}`;
    }
  }

  return undefined;
}

/**
 * Probes `DOCUMENTATION.ORG_PRIVACY_POLICY` and `DOCUMENTATION.ORG_TERMS_OF_SERVICE`
 * to verify they are reachable over HTTPS.
 *
 * Presence checks run offline via the registered rules; this function only
 * handles the network reachability probes that require a live transport.
 */
export async function checkDocCompliance(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: AuditOptions = {},
): Promise<Diagnostic[]> {
  const diagnostics: Diagnostic[] = [];
  const documentation = documentationOf(doc);
  if (!documentation) return diagnostics;

  for (const field of ['ORG_PRIVACY_POLICY', 'ORG_TERMS_OF_SERVICE'] as const) {
    const value = documentation[field];
    if (!isString(value) || !isUrl(value)) continue;

    let parsed: URL;
    try {
      parsed = new URL(value);
    } catch {
      continue;
    }
    if (parsed.protocol !== 'https:') continue;

    const detail = await probeLegalUrl(value, fetchImpl);
    if (detail === undefined) continue;

    const severity = severityFor(LEGAL_URL_UNREACHABLE_RULE, 'error', options.rules);
    if (severity) {
      diagnostics.push({
        rule: LEGAL_URL_UNREACHABLE_RULE,
        severity,
        category: 'documentation',
        message: detail,
        path: `DOCUMENTATION.${field}`,
        helpUri: specUrl('organization-documentation'),
        suggestion:
          'Confirm the URL resolves over DNS, presents a valid TLS certificate, and responds with HTTP 200.',
      });
    }
  }

  return diagnostics;
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const docComplianceRules: Rule[] = [
  {
    id: MISSING_PRIVACY_POLICY_RULE,
    category: 'documentation',
    severity: 'info',
    description: 'DOCUMENTATION.ORG_PRIVACY_POLICY should be present',
    run(ctx) {
      const documentation = documentationOf(ctx.doc);
      if (!documentation) return;
      if (!documentation.ORG_URL) return;

      if (documentation.ORG_PRIVACY_POLICY === undefined) {
        ctx.report({
          rule: MISSING_PRIVACY_POLICY_RULE,
          category: 'documentation',
          message: 'DOCUMENTATION.ORG_PRIVACY_POLICY is missing',
          path: 'DOCUMENTATION.ORG_PRIVACY_POLICY',
          helpUri: specUrl('organization-documentation'),
          suggestion: 'Add a link to your organization\'s privacy policy.',
        });
      }
    },
  },
  {
    id: MISSING_TERMS_OF_SERVICE_RULE,
    category: 'documentation',
    severity: 'info',
    description: 'DOCUMENTATION.ORG_TERMS_OF_SERVICE should be present',
    run(ctx) {
      const documentation = documentationOf(ctx.doc);
      if (!documentation) return;
      if (!documentation.ORG_URL) return;

      if (documentation.ORG_TERMS_OF_SERVICE === undefined) {
        ctx.report({
          rule: MISSING_TERMS_OF_SERVICE_RULE,
          category: 'documentation',
          message: 'DOCUMENTATION.ORG_TERMS_OF_SERVICE is missing',
          path: 'DOCUMENTATION.ORG_TERMS_OF_SERVICE',
          helpUri: specUrl('organization-documentation'),
          suggestion: 'Add a link to your organization\'s terms of service.',
        });
      }
    },
  },
  {
    id: LEGAL_URL_UNREACHABLE_RULE,
    category: 'documentation',
    severity: 'error',
    description: 'Legal policy URLs must be reachable over HTTPS with HTTP 200',
    run() {},
  },
];

/** Rule ids emitted by {@link checkDocCompliance}. */
export const docComplianceRuleIds: readonly string[] = docComplianceRules.map((rule) => rule.id);
