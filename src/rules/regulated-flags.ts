import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';
import { checkIssuerFlags, horizonUrlFor } from '../network-checks.js';
import { isAccountId, isString } from '../predicates.js';
import { currenciesOf, isTomlPointer } from './currencies.js';

/**
 * The issuer-authorization audit behind `[[CURRENCIES]].regulated`.
 *
 * In SEP-1, `regulated = true` tells a wallet that payments into the asset are
 * gated on compliance checks; on-chain that gating only exists when the
 * issuing account has `AUTH_REQUIRED` set, so a file claiming an asset is
 * regulated while its issuer authorizes nobody is a lie wallets cannot detect
 * on their own. Each `regulated = true` entry is therefore cross-referenced
 * against the issuer account's flags on Horizon, under opt-in `--check-network`.
 *
 * The audit lives in its own module rather than inside `currencies.ts` so the
 * network-bound half of the currency rules stays separable from the offline
 * ones — the same split `horizon-check.ts` and `sep38-endpoints.ts` follow.
 * The rule objects have empty `run()` bodies: the diagnostics come from the
 * async {@link checkRegulatedIssuerFlags}, and the entries exist so
 * `--list-rules` and `--off`/`--warn`/`--error` know the ids.
 */

const SEP8_SPEC_URL =
  'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0008.md';

/** The id issue #136 specifies for the `auth_required` assertion. */
const REGULATED_FLAG_REQUIRED_RULE = 'currencies/regulated-asset-missing-auth-required';
const REGULATED_FLAG_REVOCABLE_RULE = 'currencies/regulated-missing-auth-revocable-flag';
const REGULATED_FLAGS_UNVERIFIABLE_RULE = 'currencies/regulated-issuer-flags-unverifiable';

/**
 * The rule objects behind the SEP-8 issuer-flags audit.
 *
 * Like the other network-bound rules, `run()` is empty: the diagnostics are
 * emitted by the async {@link checkRegulatedIssuerFlags}.
 */
export const regulatedFlagRules: Rule[] = [
  {
    id: REGULATED_FLAG_REQUIRED_RULE,
    category: 'currencies',
    severity: 'error',
    description:
      'A SEP-8 regulated issuer must set AUTH_REQUIRED_FLAG so the issuer controls who may hold the asset',
    run() {},
  },
  {
    id: REGULATED_FLAG_REVOCABLE_RULE,
    category: 'currencies',
    severity: 'warning',
    description:
      'A SEP-8 regulated issuer should set AUTH_REVOCABLE_FLAG so unauthorized holders can be frozen',
    run() {},
  },
  {
    id: REGULATED_FLAGS_UNVERIFIABLE_RULE,
    category: 'currencies',
    severity: 'warning',
    description: 'A SEP-8 issuer authorization flags could not be verified against Horizon',
    run() {},
  },
];

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules?: RuleOverrides,
): Severity | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

function finding(
  rule: string,
  fallback: 'error' | 'warning',
  detail: string,
  path: string,
  helpUri: string,
  suggestion: string,
  rules: RuleOverrides | undefined,
): Diagnostic[] {
  const severity = severityFor(rule, fallback, rules);
  if (severity === undefined) return [];

  return [
    {
      rule,
      severity,
      category: 'currencies',
      message: detail,
      path,
      helpUri,
      suggestion,
    },
  ];
}

/**
 * Audits the issuer accounts behind every `regulated=true` classic currency.
 *
 * SEP-8 requires the issuer to have set `AUTH_REQUIRED` and `AUTH_REVOCABLE`.
 * Each entry is checked once against Horizon; when flags cannot be obtained
 * (outage, missing account) the entry degrades to a warning rather than
 * failing the run.
 */
export async function checkRegulatedIssuerFlags(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: { rules?: RuleOverrides } = {},
): Promise<Diagnostic[]> {
  const horizonUrl = horizonUrlFor(
    typeof doc.NETWORK_PASSPHRASE === 'string' ? doc.NETWORK_PASSPHRASE : undefined,
  );
  const diagnostics: Diagnostic[] = [];

  for (const [index, entry] of currenciesOf(doc).entries()) {
    const issuer = entry.issuer;
    if (
      isTomlPointer(entry) ||
      entry.regulated !== true ||
      !isString(issuer) ||
      !isAccountId(issuer)
    ) {
      continue;
    }

    const path = `CURRENCIES[${index}].issuer`;

    const flags = await checkIssuerFlags(issuer, horizonUrl, fetchImpl);
    if (flags === undefined) {
      diagnostics.push(
        ...finding(
          REGULATED_FLAGS_UNVERIFIABLE_RULE,
          'warning',
          `Could not verify the authorization flags of SEP-8 issuer ${issuer} on Horizon`,
          path,
          SEP8_SPEC_URL,
          'Confirm the issuer account exists on the network and that Horizon is reachable.',
          options.rules,
        ),
      );
      continue;
    }

    if (!flags.authRequired) {
      diagnostics.push(
        ...finding(
          REGULATED_FLAG_REQUIRED_RULE,
          'error',
          `SEP-8 issuer ${issuer} does not set AUTH_REQUIRED_FLAG on the network`,
          path,
          SEP8_SPEC_URL,
          'SEP-8 requires the issuer to set AUTH_REQUIRED so only authorized accounts can hold the asset.',
          options.rules,
        ),
      );
    }

    if (!flags.authRevocable) {
      diagnostics.push(
        ...finding(
          REGULATED_FLAG_REVOCABLE_RULE,
          'warning',
          `SEP-8 issuer ${issuer} does not set AUTH_REVOCABLE_FLAG on the network`,
          path,
          SEP8_SPEC_URL,
          'SEP-8 requires AUTH_REVOCABLE so the issuer can freeze accounts that violate its terms.',
          options.rules,
        ),
      );
    }
  }

  return diagnostics;
}
