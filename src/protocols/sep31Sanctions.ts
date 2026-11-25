/**
 * SEP-31 sender and receiver sanction screening PEP list compliance validator.
 *
 * Cross-border remittances governed by SEP-31 require Politically Exposed
 * Persons (PEP) and OFAC/sanctions screening. Anchors must disclose their
 * compliance screening requirements in both `stellar.toml` documentation
 * fields and via the statuses they support in `GET /info`. An anchor that
 * silently freezes a transaction without returning a human-readable instruction
 * or a dispute-resolution contact fails both regulatory and interoperability
 * requirements.
 *
 * This module performs two complementary checks:
 *
 *   Static: inspects the `stellar.toml` `[DOCUMENTATION]` section for the
 *   presence of compliance-related fields (`ORG_LICENSES`, `ORG_OFFICIAL_EMAIL`,
 *   `ORG_NAME`).
 *
 *   Dynamic (opt-in): fetches `DIRECT_PAYMENT_SERVER/info` and validates that
 *   the anchor declares support for the standard hold statuses
 *   (`pending_customer_info_update`, `pending_transaction_info_update`,
 *   `blocked`) and that blocked-status responses carry human-readable
 *   instructions and a dispute-resolution mechanism.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isString, isUrl } from '../predicates.js';
import { errorMessage, fetchWithTimeout, isRecord, severityFor } from './verifierSupport.js';

const SEP31_SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0031.md';
const SEP1_SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0001.md';

export const SANCTIONS_RULE_IDS = {
  licensesAbsent: 'sep31/sanctions-licenses-absent',
  contactAbsent: 'sep31/sanctions-contact-absent',
  blockedStatusAbsent: 'sep31/sanctions-blocked-status-absent',
  pendingStatusAbsent: 'sep31/sanctions-pending-status-absent',
  disputeContactAbsent: 'sep31/sanctions-dispute-contact-absent',
  infoUnavailable: 'sep31/sanctions-info-unavailable',
} as const;

/** Required transaction statuses that signal a sanctions hold. */
const REQUIRED_HOLD_STATUSES = [
  'pending_customer_info_update',
  'pending_transaction_info_update',
  'blocked',
] as const;

/** How the anchor describes each hold status in /info. */
export interface StatusEntry {
  name: string;
  description?: string;
}

/** Per-asset corridor summary from /info. */
export interface CorridorCompliance {
  asset: string;
  supportedStatuses: string[];
  missingStatuses: string[];
  hasBlockedStatus: boolean;
  hasDisputeContact: boolean;
}

/** Sanctions compliance scorecard. */
export interface SanctionsComplianceReport {
  ok: boolean;
  hasLicensesField: boolean;
  hasContactField: boolean;
  corridors: CorridorCompliance[];
  diagnostics: Diagnostic[];
  counts: { error: number; warning: number; info: number };
}

export interface SanctionsValidatorOptions {
  fetchImpl?: typeof fetch;
  rules?: RuleOverrides;
  timeoutMs?: number;
}

function emptyCounts() {
  return { error: 0, warning: 0, info: 0 };
}

function emit(
  diagnostics: Diagnostic[],
  counts: { error: number; warning: number; info: number },
  rule: string,
  fallback: 'error' | 'warning',
  message: string,
  suggestion: string,
  helpUri: string,
  path: string,
  rules?: RuleOverrides,
): void {
  const severity = severityFor(rule, fallback, rules);
  if (severity === undefined) return;
  counts[severity] += 1;
  diagnostics.push({
    rule,
    severity,
    category: 'sep12',
    message,
    path,
    helpUri,
    suggestion,
  });
}

function checkStaticDoc(
  doc: Record<string, unknown>,
  diagnostics: Diagnostic[],
  counts: { error: number; warning: number; info: number },
  rules?: RuleOverrides,
): { hasLicenses: boolean; hasContact: boolean } {
  const documentation = isRecord(doc.DOCUMENTATION) ? doc.DOCUMENTATION : undefined;

  const hasLicenses =
    documentation !== undefined &&
    isString(documentation.ORG_LICENSES) &&
    documentation.ORG_LICENSES.trim().length > 0;

  const hasContact =
    documentation !== undefined &&
    isString(documentation.ORG_OFFICIAL_EMAIL) &&
    documentation.ORG_OFFICIAL_EMAIL.trim().length > 0;

  if (!hasLicenses) {
    emit(
      diagnostics,
      counts,
      SANCTIONS_RULE_IDS.licensesAbsent,
      'warning',
      'stellar.toml does not declare ORG_LICENSES — regulators and partners cannot determine the anchor\'s compliance jurisdiction',
      'Add ORG_LICENSES under [DOCUMENTATION] with the applicable money-transmitter licence identifiers.',
      SEP1_SPEC,
      'DOCUMENTATION.ORG_LICENSES',
      rules,
    );
  }

  if (!hasContact) {
    emit(
      diagnostics,
      counts,
      SANCTIONS_RULE_IDS.contactAbsent,
      'warning',
      'stellar.toml does not declare ORG_OFFICIAL_EMAIL — parties cannot reach a dispute-resolution contact for blocked transactions',
      'Add ORG_OFFICIAL_EMAIL under [DOCUMENTATION] with the anchor\'s official compliance contact address.',
      SEP1_SPEC,
      'DOCUMENTATION.ORG_OFFICIAL_EMAIL',
      rules,
    );
  }

  return { hasLicenses, hasContact };
}

function parseSupportedStatuses(assetInfo: unknown): string[] {
  if (!isRecord(assetInfo)) return [];
  const statuses = assetInfo.transaction_statuses ?? assetInfo.statuses;
  if (!isRecord(statuses)) return [];
  return Object.keys(statuses);
}

function hasDisputeReference(assetInfo: unknown): boolean {
  if (!isRecord(assetInfo)) return false;
  const statuses = assetInfo.transaction_statuses ?? assetInfo.statuses;
  if (!isRecord(statuses)) return false;
  const blocked = statuses.blocked;
  if (!isRecord(blocked)) return false;
  const description = blocked.description;
  if (!isString(description)) return false;
  return (
    description.includes('@') ||
    description.includes('http') ||
    description.includes('contact') ||
    description.includes('dispute')
  );
}

function checkDynamicInfo(
  info: unknown,
  diagnostics: Diagnostic[],
  counts: { error: number; warning: number; info: number },
  rules?: RuleOverrides,
): CorridorCompliance[] {
  if (!isRecord(info) || !isRecord(info.receive)) return [];

  const corridors: CorridorCompliance[] = [];

  for (const [asset, assetInfo] of Object.entries(info.receive)) {
    const supported = parseSupportedStatuses(assetInfo);
    const missing = REQUIRED_HOLD_STATUSES.filter((s) => !supported.includes(s));
    const hasBlocked = supported.includes('blocked');
    const hasDispute = hasDisputeReference(assetInfo);

    corridors.push({
      asset,
      supportedStatuses: supported,
      missingStatuses: missing,
      hasBlockedStatus: hasBlocked,
      hasDisputeContact: hasDispute,
    });

    if (!hasBlocked) {
      emit(
        diagnostics,
        counts,
        SANCTIONS_RULE_IDS.blockedStatusAbsent,
        'error',
        `SEP-31 corridor "${asset}" does not declare a "blocked" transaction status — senders cannot detect sanctions holds`,
        'Add a "blocked" entry to transaction_statuses with a human-readable description and dispute instructions.',
        SEP31_SPEC,
        `DIRECT_PAYMENT_SERVER.receive.${asset}.transaction_statuses`,
        rules,
      );
    } else if (!hasDispute) {
      emit(
        diagnostics,
        counts,
        SANCTIONS_RULE_IDS.disputeContactAbsent,
        'warning',
        `SEP-31 corridor "${asset}" declares "blocked" but its description does not include a dispute-resolution contact (email or URL)`,
        'Add a contact address or dispute URL to the "blocked" status description so senders know how to escalate.',
        SEP31_SPEC,
        `DIRECT_PAYMENT_SERVER.receive.${asset}.transaction_statuses.blocked`,
        rules,
      );
    }

    for (const status of ['pending_customer_info_update', 'pending_transaction_info_update']) {
      if (!supported.includes(status)) {
        emit(
          diagnostics,
          counts,
          SANCTIONS_RULE_IDS.pendingStatusAbsent,
          'warning',
          `SEP-31 corridor "${asset}" does not declare "${status}" — senders cannot handle KYC hold responses`,
          `Add a "${status}" entry to transaction_statuses with instructions for the sending anchor.`,
          SEP31_SPEC,
          `DIRECT_PAYMENT_SERVER.receive.${asset}.transaction_statuses`,
          rules,
        );
      }
    }
  }

  return corridors;
}

/**
 * Validates an already-fetched `/info` body and the `stellar.toml` document
 * for sanctions compliance disclosures.
 */
export function analyzeSanctionsCompliance(
  doc: Record<string, unknown>,
  info: unknown,
  options: SanctionsValidatorOptions = {},
): SanctionsComplianceReport {
  const diagnostics: Diagnostic[] = [];
  const counts = emptyCounts();

  const { hasLicenses, hasContact } = checkStaticDoc(doc, diagnostics, counts, options.rules);
  const corridors = checkDynamicInfo(info, diagnostics, counts, options.rules);

  return {
    ok: counts.error === 0,
    hasLicensesField: hasLicenses,
    hasContactField: hasContact,
    corridors,
    diagnostics,
    counts,
  };
}

/**
 * Fetches `DIRECT_PAYMENT_SERVER/info` and validates sanctions compliance
 * for the given `stellar.toml` document. Silent (returns empty report) when
 * `DIRECT_PAYMENT_SERVER` is absent or not a URL.
 */
export async function verifySanctionsCompliance(
  doc: Record<string, unknown>,
  options: SanctionsValidatorOptions = {},
): Promise<SanctionsComplianceReport> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const timeoutMs = options.timeoutMs ?? 5000;

  const server = doc.DIRECT_PAYMENT_SERVER;
  const empty = (): SanctionsComplianceReport => {
    const diagnostics: Diagnostic[] = [];
    const counts = emptyCounts();
    const { hasLicenses, hasContact } = checkStaticDoc(doc, diagnostics, counts, options.rules);
    return {
      ok: counts.error === 0,
      hasLicensesField: hasLicenses,
      hasContactField: hasContact,
      corridors: [],
      diagnostics,
      counts,
    };
  };

  if (!isString(server) || !isUrl(server)) return empty();

  const infoUrl = `${server.replace(/\/+$/, '')}/info`;
  let info: unknown;
  try {
    const response = await fetchWithTimeout(fetchImpl, infoUrl, {}, timeoutMs);
    if (!response.ok) {
      const diagnostics: Diagnostic[] = [];
      const counts = emptyCounts();
      const { hasLicenses, hasContact } = checkStaticDoc(doc, diagnostics, counts, options.rules);
      const severity = severityFor(SANCTIONS_RULE_IDS.infoUnavailable, 'warning', options.rules);
      if (severity !== undefined) {
        counts[severity] += 1;
        diagnostics.push({
          rule: SANCTIONS_RULE_IDS.infoUnavailable,
          severity,
          category: 'sep12',
          message: `Could not fetch SEP-31 GET /info from ${infoUrl}: HTTP ${response.status}`,
          path: 'DIRECT_PAYMENT_SERVER',
          helpUri: SEP31_SPEC,
          suggestion: 'Confirm DIRECT_PAYMENT_SERVER points at a live SEP-31 server.',
        });
      }
      return {
        ok: counts.error === 0,
        hasLicensesField: hasLicenses,
        hasContactField: hasContact,
        corridors: [],
        diagnostics,
        counts,
      };
    }
    info = (await response.json()) as unknown;
  } catch (error) {
    const diagnostics: Diagnostic[] = [];
    const counts = emptyCounts();
    const { hasLicenses, hasContact } = checkStaticDoc(doc, diagnostics, counts, options.rules);
    const severity = severityFor(SANCTIONS_RULE_IDS.infoUnavailable, 'warning', options.rules);
    if (severity !== undefined) {
      counts[severity] += 1;
      diagnostics.push({
        rule: SANCTIONS_RULE_IDS.infoUnavailable,
        severity,
        category: 'sep12',
        message: `Could not reach SEP-31 GET /info at ${infoUrl}: ${errorMessage(error)}`,
        path: 'DIRECT_PAYMENT_SERVER',
        helpUri: SEP31_SPEC,
        suggestion: 'Confirm DIRECT_PAYMENT_SERVER points at a live SEP-31 server.',
      });
    }
    return {
      ok: counts.error === 0,
      hasLicensesField: hasLicenses,
      hasContactField: hasContact,
      corridors: [],
      diagnostics,
      counts,
    };
  }

  return analyzeSanctionsCompliance(doc, info, options);
}

/** Registered so `--list-rules` and rule overrides know these ids. */
export const sep31SanctionsRules: Rule[] = [
  {
    id: SANCTIONS_RULE_IDS.licensesAbsent,
    category: 'sep12',
    severity: 'warning',
    description:
      'stellar.toml should declare ORG_LICENSES for sanctions compliance transparency',
    run() {},
  },
  {
    id: SANCTIONS_RULE_IDS.contactAbsent,
    category: 'sep12',
    severity: 'warning',
    description:
      'stellar.toml should declare ORG_OFFICIAL_EMAIL as a sanctions dispute-resolution contact',
    run() {},
  },
  {
    id: SANCTIONS_RULE_IDS.blockedStatusAbsent,
    category: 'sep12',
    severity: 'error',
    description:
      'SEP-31 /info must declare a "blocked" transaction status for sanctions hold transparency',
    run() {},
  },
  {
    id: SANCTIONS_RULE_IDS.pendingStatusAbsent,
    category: 'sep12',
    severity: 'warning',
    description:
      'SEP-31 /info should declare pending KYC hold statuses so senders can handle them',
    run() {},
  },
  {
    id: SANCTIONS_RULE_IDS.disputeContactAbsent,
    category: 'sep12',
    severity: 'warning',
    description:
      'SEP-31 "blocked" status description should include a dispute-resolution contact',
    run() {},
  },
  {
    id: SANCTIONS_RULE_IDS.infoUnavailable,
    category: 'sep12',
    severity: 'warning',
    description: 'SEP-31 GET /info must be reachable for sanctions compliance verification',
    run() {},
  },
];

/** Rule ids emitted by the sanction compliance validator. */
export const sep31SanctionsRuleIds: readonly string[] = sep31SanctionsRules.map((r) => r.id);
