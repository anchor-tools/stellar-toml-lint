import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isInteger, isString, isUrl } from '../predicates.js';
import { specUrl } from '../spec.js';

/**
 * Opt-in validation of the `HORIZON_URL` endpoint a SEP-1 file advertises.
 *
 * Wallets and exchanges talk to this Horizon instance for balances, payments,
 * and SEP-10 challenges, so a misconfigured, offline, or protocol-lagged
 * endpoint breaks integrations even when the file itself is perfect. The
 * check is deliberately network-bound: it only runs when the caller asks for
 * `--check-network`, and the rule objects registered alongside it exist so
 * `--list-rules` and `--off` know about the diagnostics the async audit emits.
 */

const UNREACHABLE_RULE = 'network/horizon-unreachable';
const OUTDATED_RULE = 'network/horizon-protocol-outdated';

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

function unreachable(detail: string, rules: RuleOverrides | undefined): Diagnostic[] {
  const severity = severityFor(UNREACHABLE_RULE, 'error', rules);
  if (severity === undefined) return [];

  return [
    {
      rule: UNREACHABLE_RULE,
      severity,
      category: 'network',
      message: detail,
      path: 'HORIZON_URL',
      helpUri: specUrl('general-information'),
      suggestion: 'Confirm HORIZON_URL points at a live Horizon instance and that it is reachable.',
    },
  ];
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}

/**
 * GETs `HORIZON_URL` and asserts the response is a Horizon root document
 * whose `current_protocol_version` the instance's Core actually supports.
 *
 * Silent when the file has no `HORIZON_URL`, or when the value is not a
 * parseable URL — `general/horizon-url` already reports that offline, and
 * fetching a garbage URL would only duplicate the finding as a network error.
 */
export async function checkHorizon(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: AuditOptions = {},
): Promise<Diagnostic[]> {
  const horizonUrl = doc.HORIZON_URL;
  if (!isString(horizonUrl) || !isUrl(horizonUrl)) return [];

  let response: Response;
  try {
    response = await fetchImpl(horizonUrl);
  } catch (error) {
    return unreachable(
      `Could not reach HORIZON_URL at ${horizonUrl}: ${errorMessage(error)}`,
      options.rules,
    );
  }

  if (!response.ok) {
    return unreachable(
      `HORIZON_URL at ${horizonUrl} returned HTTP ${response.status}`,
      options.rules,
    );
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    return unreachable(`HORIZON_URL at ${horizonUrl} did not return valid JSON`, options.rules);
  }

  // A Horizon root always carries its protocol versions; anything else that
  // answers 200 (an HTML captive portal, a reverse-proxy splash page) is not
  // the endpoint the file advertises.
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    return unreachable(
      `HORIZON_URL at ${horizonUrl} did not return a Horizon root document`,
      options.rules,
    );
  }

  const root = body as Record<string, unknown>;
  if (!isInteger(root.current_protocol_version)) {
    return unreachable(
      `HORIZON_URL at ${horizonUrl} did not return a Horizon root document (missing current_protocol_version)`,
      options.rules,
    );
  }

  const diagnostics: Diagnostic[] = [];
  const coreSupported = root.core_supported_protocol_version;
  const current = root.current_protocol_version;

  // `current_protocol_version` must be supported by the stack behind the
  // endpoint. Core advertising a lower ceiling than the network's active
  // protocol means the instance is outdated and will fail wallet traffic.
  if (isInteger(coreSupported) && current > coreSupported) {
    const severity = severityFor(OUTDATED_RULE, 'warning', options.rules);
    if (severity !== undefined) {
      diagnostics.push({
        rule: OUTDATED_RULE,
        severity,
        category: 'network',
        message: `HORIZON_URL reports current protocol ${current}, but core only supports ${coreSupported}`,
        path: 'HORIZON_URL',
        helpUri: specUrl('general-information'),
        suggestion: `Upgrade the stellar-core instance behind HORIZON_URL to a version that supports protocol ${current}.`,
      });
    }
  }

  return diagnostics;
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const horizonRules: Rule[] = [
  {
    id: UNREACHABLE_RULE,
    category: 'network',
    severity: 'error',
    description: 'HORIZON_URL must respond with a valid Horizon root document',
    run() {},
  },
  {
    id: OUTDATED_RULE,
    category: 'network',
    severity: 'warning',
    description: 'HORIZON_URL core must support the network current protocol version',
    run() {},
  },
];

/** Rule ids emitted by {@link checkHorizon}. */
export const horizonRuleIds: readonly string[] = horizonRules.map((rule) => rule.id);
