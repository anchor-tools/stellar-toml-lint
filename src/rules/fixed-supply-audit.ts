import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';
import { checkIssuerLockStatus, horizonUrlFor } from '../network-checks.js';
import { isAccountId, isString } from '../predicates.js';
import { specUrl } from '../spec.js';
import { currenciesOf, isTomlPointer } from './currencies.js';

const ACCOUNT_NOT_LOCKED_RULE = 'currencies/fixed-supply-account-not-locked';
const ACCOUNT_LOCK_UNVERIFIABLE_RULE = 'currencies/fixed-supply-account-lock-unverifiable';

export const fixedSupplyLockRules: Rule[] = [
  {
    id: ACCOUNT_NOT_LOCKED_RULE,
    category: 'currencies',
    severity: 'warning',
    description: 'A fixed-supply issuer should not retain signing weight to mint more tokens',
    run() {},
  },
  {
    id: ACCOUNT_LOCK_UNVERIFIABLE_RULE,
    category: 'currencies',
    severity: 'warning',
    description: 'A fixed-supply issuer lock could not be verified against Horizon',
    run() {},
  },
];

function isNativeAsset(entry: Record<string, unknown>): boolean {
  if (!isString(entry.code)) return false;
  const code = entry.code.toLowerCase();
  return (
    code === 'native' ||
    (code === 'xlm' && entry.issuer === undefined && entry.contract === undefined)
  );
}

function severityFor(rule: string, rules?: RuleOverrides): Severity | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : 'warning';
}

function report(
  diagnostics: Diagnostic[],
  rule: string,
  message: string,
  path: string,
  suggestion: string,
  rules?: RuleOverrides,
): void {
  const severity = severityFor(rule, rules);
  if (severity === undefined) return;
  diagnostics.push({
    rule,
    severity,
    category: 'currencies',
    message,
    path,
    helpUri: specUrl('currency-documentation'),
    suggestion,
  });
}

/** Audits whether fixed or capped classic assets can still be minted. */
export async function checkFixedSupplyIssuerLocks(
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
      isNativeAsset(entry) ||
      (entry.fixed_number === undefined && entry.max_number === undefined) ||
      !isString(issuer) ||
      !isAccountId(issuer)
    ) {
      continue;
    }

    const path = `CURRENCIES[${index}].issuer`;
    const status = await checkIssuerLockStatus(issuer, horizonUrl, fetchImpl);
    if (status === undefined) {
      report(
        diagnostics,
        ACCOUNT_LOCK_UNVERIFIABLE_RULE,
        `Could not verify whether fixed-supply issuer ${issuer} is locked on Horizon`,
        path,
        'Confirm the issuer account exists on the selected network and that Horizon is reachable.',
        options.rules,
      );
      continue;
    }

    if (!status.locked) {
      report(
        diagnostics,
        ACCOUNT_NOT_LOCKED_RULE,
        `Fixed-supply issuer ${issuer} can still sign minting or account-management operations (master weight ${status.masterKeyWeight}, active signer weight ${status.activeSignerWeight}, medium threshold ${status.medThreshold}, high threshold ${status.highThreshold})`,
        path,
        'Set the issuer master weight to 0 and ensure active signers cannot meet the medium or high threshold; set is_unlimited = true if continuous minting is intentional.',
        options.rules,
      );
    }
  }

  return diagnostics;
}
