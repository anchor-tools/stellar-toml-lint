/**
 * Cryptographic key separation and account reuse auditor.
 *
 * Each public key in a `stellar.toml` stands for a different responsibility:
 * `SIGNING_KEY` authenticates SEP-10 and SEP-45 sessions, `[[CURRENCIES]].issuer`
 * is the root that can mint and claw back an asset, `ACCOUNTS` are the
 * operational accounts that move money, `[[VALIDATORS]].PUBLIC_KEY` votes in
 * quorum, and `collateral_addresses` hold the reserves. NIST SP 800-57 asks for
 * exactly this kind of separation — a key that signs user sessions must not be
 * the key that issues the asset — because the session key is the one exposed to
 * the internet.
 *
 * The auditor builds the key/role association graph straight out of the
 * document, reports every account that carries more than one role, and then
 * asks Horizon whether those accounts are really single-key and whether an
 * issuer is submitting operational transactions. Failures to reach Horizon
 * degrade the network checks to nothing rather than to warnings about an
 * account nobody looked at.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isAccountId, isString } from '../predicates.js';
import { errorMessage, fetchWithTimeout } from '../protocols/verifierSupport.js';
import { horizonUrlFor } from '../network-checks.js';
import { specUrl } from '../spec.js';

const SIGNING_ISSUER_RULE = 'keys/signing-issuer-reuse';
const ISSUER_OPERATIONAL_RULE = 'keys/issuer-operational-account';
const VALIDATOR_REUSE_RULE = 'keys/validator-key-reuse';
const COLLATERAL_REUSE_RULE = 'keys/collateral-issuer-reuse';
const SINGLE_SIGNER_RULE = 'keys/single-signer-root-account';
const OPERATIONAL_ACTIVITY_RULE = 'keys/issuer-operational-activity';

/** Roles SEP-1 gives to an account, in the order the diagram lists them. */
export type KeyRole =
  | 'signing-key'
  | 'uri-request-signing-key'
  | 'declared-account'
  | 'asset-issuer'
  | 'validator-identity'
  | 'collateral-address';

const ROLE_ORDER: KeyRole[] = [
  'signing-key',
  'uri-request-signing-key',
  'declared-account',
  'asset-issuer',
  'validator-identity',
  'collateral-address',
];

/**
 * Operation types that mean an account is being used to move value or trade,
 * as Horizon names them. Issuer administration (`allow_trust`,
 * `set_options`, `inflation`) is deliberately absent: that work belongs to the
 * issuer and is not a separation problem.
 */
export const OPERATIONAL_OPERATIONS: readonly string[] = [
  'payment',
  'path_payment',
  'path_payment_strict_receive',
  'path_payment_strict_send',
  'manage_offer',
  'create_passive_sell_offer',
  'create_account',
  'account_merge',
  'claim_claimable_balance',
  'invoke_contract',
];

export interface KeyRoleOccurrence {
  role: KeyRole;
  /** SEP-1 field the role was read from, reported as the diagnostic path. */
  path: string;
  /** Currency code or validator alias, when the role is per-entry. */
  label?: string;
}

export interface KeyAssignment {
  account: string;
  roles: KeyRoleOccurrence[];
}

export interface AccountProfile {
  account: string;
  roles: KeyRole[];
  /** False when Horizon could not be reached for this account. */
  available: boolean;
  signerWeights?: number[];
  thresholds?: { low: number; med: number; high: number };
  operationTypes?: string[];
  error?: string;
}

export interface KeySeparationFinding {
  code: string;
  severity: 'error' | 'warning';
  message: string;
  account: string;
  suggestion: string;
}

export interface KeySeparationReport {
  ok: boolean;
  horizonUrl: string;
  assignments: KeyAssignment[];
  reused: KeyAssignment[];
  profiles: AccountProfile[];
  findings: KeySeparationFinding[];
}

export interface KeySeparationOptions {
  rules?: RuleOverrides;
  /** Overrides the Horizon derived from NETWORK_PASSPHRASE. */
  horizonUrl?: string;
  /** Query Horizon for signers and operations; on by default. */
  queryNetwork?: boolean;
  timeoutMs?: number;
}

/** Resolves the effective severity for a rule, or `undefined` when it is turned off. */
function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules?: RuleOverrides,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

function addAssignment(
  byAccount: Map<string, KeyRoleOccurrence[]>,
  account: unknown,
  occurrence: KeyRoleOccurrence,
): void {
  if (!isString(account) || !isAccountId(account)) return;
  const roles = byAccount.get(account);
  if (roles === undefined) byAccount.set(account, [occurrence]);
  else roles.push(occurrence);
}

/**
 * Builds the key/role association graph: one node per declared account, one
 * edge per SEP-1 field that names it.
 */
export function collectKeyAssignments(doc: Record<string, unknown>): KeyAssignment[] {
  const byAccount = new Map<string, KeyRoleOccurrence[]>();

  addAssignment(byAccount, doc.SIGNING_KEY, { role: 'signing-key', path: 'SIGNING_KEY' });
  addAssignment(byAccount, doc.URI_REQUEST_SIGNING_KEY, {
    role: 'uri-request-signing-key',
    path: 'URI_REQUEST_SIGNING_KEY',
  });

  if (Array.isArray(doc.ACCOUNTS)) {
    doc.ACCOUNTS.forEach((account, index) => {
      addAssignment(byAccount, account, {
        role: 'declared-account',
        path: `ACCOUNTS[${index}]`,
      });
    });
  }

  if (Array.isArray(doc.CURRENCIES)) {
    doc.CURRENCIES.forEach((entry, index) => {
      if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) return;
      const currency = entry as Record<string, unknown>;
      const label = isString(currency.code) ? currency.code : undefined;
      addAssignment(byAccount, currency.issuer, {
        role: 'asset-issuer',
        path: `CURRENCIES[${index}].issuer`,
        ...(label === undefined ? {} : { label }),
      });
      if (Array.isArray(currency.collateral_addresses)) {
        currency.collateral_addresses.forEach((address, addressIndex) => {
          addAssignment(byAccount, address, {
            role: 'collateral-address',
            path: `CURRENCIES[${index}].collateral_addresses[${addressIndex}]`,
            ...(label === undefined ? {} : { label }),
          });
        });
      }
    });
  }

  if (Array.isArray(doc.VALIDATORS)) {
    doc.VALIDATORS.forEach((entry, index) => {
      if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) return;
      const validator = entry as Record<string, unknown>;
      const label = isString(validator.ALIAS) ? validator.ALIAS : undefined;
      addAssignment(byAccount, validator.PUBLIC_KEY, {
        role: 'validator-identity',
        path: `VALIDATORS[${index}].PUBLIC_KEY`,
        ...(label === undefined ? {} : { label }),
      });
    });
  }

  const assignments: KeyAssignment[] = [];
  for (const [account, roles] of byAccount) {
    roles.sort((left, right) => ROLE_ORDER.indexOf(left.role) - ROLE_ORDER.indexOf(right.role));
    assignments.push({ account, roles });
  }
  return assignments.sort((left, right) => left.account.localeCompare(right.account));
}

function describeOccurrence(occurrence: KeyRoleOccurrence): string {
  return occurrence.label === undefined
    ? `${occurrence.role} (${occurrence.path})`
    : `${occurrence.role} (${occurrence.path}, ${occurrence.label})`;
}

interface HorizonAccountBody {
  thresholds?: { low_threshold?: unknown; med_threshold?: unknown; high_threshold?: unknown };
  signers?: { weight?: unknown }[];
  _embedded?: { records?: { type?: unknown }[] };
}

function toNumber(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0;
}

export class KeySeparationAuditor {
  private readonly fetchImpl: typeof fetch;
  private readonly options: KeySeparationOptions;

  constructor(fetchImpl: typeof fetch = fetch, options: KeySeparationOptions = {}) {
    this.fetchImpl = fetchImpl;
    this.options = options;
  }

  /** Overlap detection on the document, then the Horizon-backed checks. */
  async audit(doc: Record<string, unknown>): Promise<KeySeparationReport> {
    const assignments = collectKeyAssignments(doc);
    const reused = assignments.filter(
      (assignment) => new Set(assignment.roles.map((occurrence) => occurrence.role)).size > 1,
    );
    const horizonUrl =
      this.options.horizonUrl ??
      horizonUrlFor(isString(doc.NETWORK_PASSPHRASE) ? doc.NETWORK_PASSPHRASE : undefined);

    const findings: KeySeparationFinding[] = [];
    const emit = (
      code: string,
      fallback: 'error' | 'warning',
      account: string,
      message: string,
      suggestion: string,
    ): void => {
      const severity = severityFor(code, fallback, this.options.rules);
      if (severity === undefined) return;
      findings.push({ code, severity, account, message, suggestion });
    };

    for (const assignment of reused) {
      const roles = [...new Set(assignment.roles.map((occurrence) => occurrence.role))];
      const described = assignment.roles.map(describeOccurrence).join(', ');

      if (roles.includes('asset-issuer') && roles.includes('signing-key')) {
        emit(
          SIGNING_ISSUER_RULE,
          'error',
          assignment.account,
          `${assignment.account} is both the SEP-10 SIGNING_KEY and an asset issuer: ${described}`,
          'Keep the issuing root offline and give SIGNING_KEY its own account; a leaked session key would otherwise mint assets.',
        );
      }
      if (roles.includes('asset-issuer') && roles.includes('declared-account')) {
        emit(
          ISSUER_OPERATIONAL_RULE,
          'error',
          assignment.account,
          `${assignment.account} is an asset issuer and also listed in ACCOUNTS as an operational account: ${described}`,
          'Fund hot wallets from the issuer and list only those hot wallets in ACCOUNTS.',
        );
      }
      if (
        roles.includes('validator-identity') &&
        roles.some((role) => role !== 'validator-identity')
      ) {
        emit(
          VALIDATOR_REUSE_RULE,
          'error',
          assignment.account,
          `${assignment.account} votes as a validator and also serves an anchor role: ${described}`,
          'A validator identity must be dedicated to quorum voting; reuse it and one anchor compromise becomes a consensus compromise.',
        );
      }
      if (roles.includes('collateral-address') && roles.includes('asset-issuer')) {
        emit(
          COLLATERAL_REUSE_RULE,
          'warning',
          assignment.account,
          `${assignment.account} is both the reserve address and the issuing account: ${described}`,
          'Hold collateral in an account separate from the issuer so the reserve attestation is meaningful.',
        );
      }
    }

    const profiles: AccountProfile[] =
      this.options.queryNetwork === false ? [] : await this.profile(assignments, horizonUrl);

    for (const profile of profiles) {
      if (!profile.available) continue;
      const weights = (profile.signerWeights ?? []).filter((weight) => weight > 0);
      const high = profile.thresholds?.high ?? 0;
      const singleKey = weights.length <= 1 && (weights[0] ?? 0) >= Math.max(high, 1);
      if (
        singleKey &&
        (profile.roles.includes('asset-issuer') || profile.roles.includes('signing-key'))
      ) {
        emit(
          SINGLE_SIGNER_RULE,
          'warning',
          profile.account,
          `${profile.account} is controlled by a single signer weight (${weights.join(', ') || 'none'}) at high threshold ${high}`,
          'Add signers and raise the high threshold so issuing and authentication keys need more than one party.',
        );
      }

      const operational = (profile.operationTypes ?? []).filter((type) =>
        OPERATIONAL_OPERATIONS.includes(type),
      );
      if (profile.roles.includes('asset-issuer') && operational.length > 0) {
        emit(
          OPERATIONAL_ACTIVITY_RULE,
          'warning',
          profile.account,
          `Issuer account ${profile.account} has recent ${[...new Set(operational)].join(', ')} operations`,
          'Submit operational transactions from an ACCOUNTS entry, not from the issuer.',
        );
      }
    }

    return {
      ok: findings.every((finding) => finding.severity !== 'error'),
      horizonUrl,
      assignments,
      reused,
      profiles,
      findings,
    };
  }

  /** Reads signers, thresholds and the recent operations of every declared account. */
  private async profile(
    assignments: KeyAssignment[],
    horizonUrl: string,
  ): Promise<AccountProfile[]> {
    const profiles: AccountProfile[] = [];
    for (const assignment of assignments) {
      const roles = [...new Set(assignment.roles.map((occurrence) => occurrence.role))];
      try {
        const account = await this.fetchJson(`${horizonUrl}/accounts/${assignment.account}`);
        const operations = await this.fetchJson(
          `${horizonUrl}/accounts/${assignment.account}/operations?limit=10&order=desc`,
        );
        profiles.push({
          account: assignment.account,
          roles,
          available: true,
          signerWeights: (account.signers ?? [])
            .map((signer) => toNumber(signer.weight))
            .filter((weight) => weight > 0),
          thresholds: {
            low: toNumber(account.thresholds?.low_threshold),
            med: toNumber(account.thresholds?.med_threshold),
            high: toNumber(account.thresholds?.high_threshold),
          },
          operationTypes: (operations._embedded?.records ?? [])
            .map((record) => (isString(record.type) ? record.type : ''))
            .filter((type) => type.length > 0),
        });
      } catch (error) {
        profiles.push({
          account: assignment.account,
          roles,
          available: false,
          error: errorMessage(error),
        });
      }
    }
    return profiles;
  }

  private async fetchJson(url: string): Promise<HorizonAccountBody> {
    const response = await fetchWithTimeout(this.fetchImpl, url, {}, this.options.timeoutMs);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return (await response.json()) as HorizonAccountBody;
  }
}

/** Diagnostics plus the report, for the CLI subcommand and the library caller. */
export async function auditKeySeparation(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: KeySeparationOptions = {},
): Promise<{ diagnostics: Diagnostic[]; report: KeySeparationReport }> {
  const report = await new KeySeparationAuditor(fetchImpl, options).audit(doc);
  const pathOf = (account: string): string | undefined =>
    report.assignments.find((assignment) => assignment.account === account)?.roles[0]?.path;
  const diagnostics: Diagnostic[] = report.findings.map((finding) => {
    const path = pathOf(finding.account);
    return {
      rule: finding.code,
      severity: finding.severity,
      category: 'network',
      message: finding.message,
      ...(path === undefined ? {} : { path }),
      helpUri: specUrl('general-information'),
      suggestion: finding.suggestion,
    };
  });
  return { diagnostics, report };
}

/**
 * The role assignment diagram: one node per account, one branch per SEP-1 field
 * that names it, so a reused key is visible as a node with two branches.
 */
export function renderKeyRoleDiagram(assignments: KeyAssignment[]): string {
  if (assignments.length === 0) return '  no accounts declared\n';
  const lines: string[] = ['  key role assignments'];
  for (const assignment of assignments) {
    lines.push(`    ${assignment.account}`);
    assignment.roles.forEach((occurrence, index) => {
      const last = index === assignment.roles.length - 1;
      lines.push(`      ${last ? '└─' : '├─'} ${describeOccurrence(occurrence)}`);
    });
  }
  return `${lines.join('\n')}\n`;
}

export function renderKeySeparationReport(report: KeySeparationReport): string {
  const lines: string[] = [];
  lines.push(`Key separation: ${report.ok ? 'clean' : 'issues found'}`);
  lines.push(`  accounts: ${report.assignments.length}, reused: ${report.reused.length}`);
  lines.push(`  horizon: ${report.horizonUrl}`);
  lines.push(renderKeyRoleDiagram(report.assignments).replace(/\n$/, ''));
  for (const profile of report.profiles) {
    lines.push(
      profile.available
        ? `  ${profile.account}  signers=${(profile.signerWeights ?? []).length} weights=[${(
            profile.signerWeights ?? []
          ).join(',')}] thresholds=${profile.thresholds?.low}/${profile.thresholds?.med}/${
            profile.thresholds?.high
          } ops=${profile.operationTypes?.join(',') ?? '-'}`
        : `  ${profile.account}  horizon unavailable: ${profile.error}`,
    );
  }
  for (const finding of report.findings) {
    lines.push(`  ${finding.severity}  ${finding.code}  ${finding.message}`);
    lines.push(`         fix: ${finding.suggestion}`);
  }
  if (report.findings.length === 0) {
    lines.push('  Every declared account carries a single role.');
  }
  return `${lines.join('\n')}\n`;
}

/** Registered so `--list-rules`, completions and `--off`/`--warn`/`--error` know these ids. */
export const keySeparationRules: Rule[] = [
  {
    id: SIGNING_ISSUER_RULE,
    category: 'network',
    severity: 'error',
    description: 'SIGNING_KEY must not also be an asset issuing account',
    run() {},
  },
  {
    id: ISSUER_OPERATIONAL_RULE,
    category: 'network',
    severity: 'error',
    description: 'An asset issuer must not be listed in ACCOUNTS as an operational account',
    run() {},
  },
  {
    id: VALIDATOR_REUSE_RULE,
    category: 'network',
    severity: 'error',
    description: 'A validator identity must not be reused for an anchor role',
    run() {},
  },
  {
    id: COLLATERAL_REUSE_RULE,
    category: 'network',
    severity: 'warning',
    description: 'Collateral reserve addresses should be separate from the issuing account',
    run() {},
  },
  {
    id: SINGLE_SIGNER_RULE,
    category: 'network',
    severity: 'warning',
    description: 'Issuing and signing accounts should require more than one signer',
    run() {},
  },
  {
    id: OPERATIONAL_ACTIVITY_RULE,
    category: 'network',
    severity: 'warning',
    description: 'Issuing accounts should not submit operational transactions',
    run() {},
  },
];

export const keySeparationRuleIds: readonly string[] = keySeparationRules.map((rule) => rule.id);
