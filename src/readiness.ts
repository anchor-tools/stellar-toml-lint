/**
 * Wallet listing readiness score (`--readiness`).
 *
 * SEP-1 observes that wallets and exchanges decide whether to list an asset
 * "based on the completeness of their Account Information and Documentation
 * sections". A file can therefore be free of errors and still be turned down:
 * the fields wallets actually read are recommended, not required, and a binary
 * exit code cannot express the difference.
 *
 * This module turns a {@link LintResult} into a deterministic 0–100 score
 * across three weighted pillars, a letter grade, and a checklist that names
 * each gap. It reads only the parsed document and the recorded diagnostics, so
 * it never touches the network.
 */
import type { LintResult } from './types.js';
import { ANCHOR_ASSET_TYPES, ISSUANCE_FIELDS } from './spec.js';
import { hostOf, isEmail, isHttpsUrl, isSameOrSubdomain, isString, isUrl } from './predicates.js';

/** The three scoring pillars, in report order. */
export type ReadinessPillarId = 'protocol' | 'identity' | 'transparency';

/** Letter grade bands: A+ 95–100, A 90–94, B 80–89, C 70–79, D 60–69, F <60. */
export type ReadinessGrade = 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';

/** One checklist entry, and the points it contributes to its pillar. */
export interface ReadinessCheck {
  /** Stable machine-readable id, e.g. `identity/org-logo`. */
  id: string;
  pillar: ReadinessPillarId;
  /** What the check looks for, shown in the checklist. */
  label: string;
  passed: boolean;
  /** Points earned. Partial credit is possible on the protocol pillar. */
  points: number;
  /** Points the check is worth when fully satisfied. */
  maxPoints: number;
  /** Why it failed, or what is missing. Absent when the check passed. */
  detail?: string;
  /** Concrete next step. Absent when the check passed. */
  suggestion?: string;
}

/** A weighted scoring group, plus the checks that make it up. */
export interface ReadinessPillar {
  id: ReadinessPillarId;
  label: string;
  score: number;
  maxScore: number;
  checks: ReadinessCheck[];
}

export interface ReadinessReport {
  /** Overall score, 0–100. */
  score: number;
  grade: ReadinessGrade;
  pillars: ReadinessPillar[];
  /** Every check across the pillars, flattened for easy iteration. */
  checklist: ReadinessCheck[];
  /** `true` when the source could not be parsed; every pillar then scores 0. */
  parseFailure: boolean;
}

/** Pillar ceilings, which also make up the 100-point total. */
export const PROTOCOL_MAX_SCORE = 40;
export const IDENTITY_MAX_SCORE = 30;
export const TRANSPARENCY_MAX_SCORE = 30;
export const READINESS_MAX_SCORE = PROTOCOL_MAX_SCORE + IDENTITY_MAX_SCORE + TRANSPARENCY_MAX_SCORE;

/** Points lost per error-severity finding in the protocol pillar. */
export const PROTOCOL_ERROR_DEDUCTION = 15;

/**
 * Throwaway mail providers that no serious anchor would use for an official
 * contact address. Kept deliberately short and well-known: a false positive
 * here would take points off a legitimate operator.
 */
export const DISPOSABLE_EMAIL_DOMAINS: ReadonlySet<string> = new Set([
  '10minutemail.com',
  'dispostable.com',
  'fakeinbox.com',
  'getnada.com',
  'grr.la',
  'guerrillamail.com',
  'guerrillamail.net',
  'mailcatch.com',
  'maildrop.cc',
  'mailinator.com',
  'mailnesia.com',
  'mintemail.com',
  'sharklasers.com',
  'tempmail.com',
  'tempmail.net',
  'temp-mail.org',
  'throwaway.email',
  'throwawaymail.com',
  'trashmail.com',
  'yopmail.com',
]);

/** Maps a 0–100 score onto its letter grade. */
export function gradeFor(score: number): ReadinessGrade {
  if (score >= 95) return 'A+';
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

/** A table value, or `undefined` for anything that is not one. */
function tableOf(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

/** Reads the `[DOCUMENTATION]` table, or `undefined` when it is absent. */
function documentationOf(
  doc: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  return doc === undefined ? undefined : tableOf(doc.DOCUMENTATION);
}

/**
 * The real `[[CURRENCIES]]` entries.
 *
 * `undefined` means the source itself is unavailable (a parse failure), which
 * is scored differently from a parsed document that declares no currencies at
 * all — the latter is vacuously fine, the former unknown.
 */
function currenciesOf(
  doc: Record<string, unknown> | undefined,
): Record<string, unknown>[] | undefined {
  if (doc === undefined) return undefined;
  const list = doc.CURRENCIES;
  if (!Array.isArray(list)) return [];
  return list
    .map(tableOf)
    .filter(isPresent)
    .filter((entry) => entry.toml === undefined);
}

function isPresent<T>(value: T | undefined): value is T {
  return value !== undefined;
}

/** Non-empty string test, so whitespace does not count as documentation. */
function isFilled(value: unknown): value is string {
  return isString(value) && value.trim() !== '';
}

/** XLM's supply is a protocol property, so no issuance policy is expected. */
function isNativeAsset(entry: Record<string, unknown>): boolean {
  if (!isString(entry.code)) return false;
  const code = entry.code.toLowerCase();
  return code === 'native' || (code === 'xlm' && entry.issuer === undefined);
}

function emailDomain(value: unknown): string | undefined {
  if (!isString(value)) return undefined;
  return value.split('@')[1]?.toLowerCase();
}

interface CheckSpec {
  id: string;
  pillar: ReadinessPillarId;
  label: string;
  maxPoints: number;
  passed: boolean;
  points?: number;
  detail?: string;
  suggestion?: string;
}

/** Assembles a checklist entry, defaulting to all-or-nothing scoring. */
function buildCheck(spec: CheckSpec): ReadinessCheck {
  return {
    id: spec.id,
    pillar: spec.pillar,
    label: spec.label,
    passed: spec.passed,
    points: spec.points ?? (spec.passed ? spec.maxPoints : 0),
    maxPoints: spec.maxPoints,
    ...(spec.detail !== undefined ? { detail: spec.detail } : {}),
    ...(spec.suggestion !== undefined ? { suggestion: spec.suggestion } : {}),
  };
}

/**
 * The protocol pillar is the only one that can award partial credit: a file
 * with three errors is not perfect, but it is closer to listable than one that
 * does not parse at all.
 */
function protocolChecks(result: LintResult, parseFailure: boolean): ReadinessCheck[] {
  const errors = result.counts.error;
  const lost = Math.min(errors * PROTOCOL_ERROR_DEDUCTION, PROTOCOL_MAX_SCORE);
  const points = parseFailure ? 0 : PROTOCOL_MAX_SCORE - lost;

  return [
    buildCheck({
      id: 'protocol/parses',
      pillar: 'protocol',
      label: 'File parses as valid TOML',
      maxPoints: 0,
      passed: !parseFailure,
      ...(parseFailure
        ? {
            detail: 'The file could not be parsed, so no other pillar can be scored.',
            suggestion: 'Fix the syntax error reported by file/parse, then run readiness again.',
          }
        : {}),
    }),
    buildCheck({
      id: 'protocol/no-errors',
      pillar: 'protocol',
      label: 'No SEP-1 protocol or syntax errors',
      maxPoints: PROTOCOL_MAX_SCORE,
      passed: errors === 0,
      points,
      ...(errors > 0
        ? {
            detail: `${errors} error${errors === 1 ? '' : 's'} found; each error costs ${PROTOCOL_ERROR_DEDUCTION} points.`,
            suggestion:
              'Fix the errors reported by `stellar-toml-lint` before applying for a listing.',
          }
        : {}),
    }),
  ];
}

/**
 * Organization Identity & Trust (30 points).
 *
 * These are the fields a wallet's listing review reads first: who the operator
 * is, whether the contact address is really theirs, and whether the business
 * can be located and called.
 */
function identityChecks(documentation: Record<string, unknown> | undefined): ReadinessCheck[] {
  const pillar: ReadinessPillarId = 'identity';
  const orgName = documentation?.ORG_NAME;
  const orgUrl = documentation?.ORG_URL;
  const orgLogo = documentation?.ORG_LOGO;
  const officialEmail = documentation?.ORG_OFFICIAL_EMAIL;
  const orgHost = hostOf(orgUrl);
  const mailDomain = emailDomain(officialEmail);

  const nameOk = isFilled(orgName);
  const urlOk = isHttpsUrl(orgUrl);
  const logoOk = isUrl(orgLogo) && /\.png(\?|#|$)/i.test(String(orgLogo));
  const emailOk =
    isEmail(officialEmail) &&
    orgHost !== undefined &&
    mailDomain !== undefined &&
    isSameOrSubdomain(mailDomain, orgHost);
  const disposable = mailDomain !== undefined && DISPOSABLE_EMAIL_DOMAINS.has(mailDomain);
  const contactDomainOk = mailDomain !== undefined && !disposable;
  const physicalOk = isHttpsUrl(documentation?.ORG_PHYSICAL_ADDRESS_ATTESTATION);
  const phoneOk = isHttpsUrl(documentation?.ORG_PHONE_NUMBER_ATTESTATION);

  return [
    buildCheck({
      id: 'identity/org-name',
      pillar,
      label: 'ORG_NAME names the organization',
      maxPoints: 5,
      passed: nameOk,
      ...(nameOk
        ? {}
        : {
            detail: 'No [DOCUMENTATION].ORG_NAME is set.',
            suggestion: 'Add ORG_NAME with the legal entity that operates the anchor.',
          }),
    }),
    buildCheck({
      id: 'identity/org-url',
      pillar,
      label: 'ORG_URL is an https:// URL',
      maxPoints: 5,
      passed: urlOk,
      ...(urlOk
        ? {}
        : {
            detail: 'ORG_URL is missing or is not an https:// URL.',
            suggestion: 'Add ORG_URL, e.g. ORG_URL="https://your-anchor.com".',
          }),
    }),
    buildCheck({
      id: 'identity/org-logo',
      pillar,
      label: 'ORG_LOGO is a PNG',
      maxPoints: 6,
      passed: logoOk,
      ...(logoOk
        ? {}
        : {
            detail: 'ORG_LOGO is missing, is not a URL, or does not point at a .png file.',
            suggestion: 'Publish a square PNG on a transparent background as ORG_LOGO.',
          }),
    }),
    buildCheck({
      id: 'identity/official-email',
      pillar,
      label: 'ORG_OFFICIAL_EMAIL is on the ORG_URL domain',
      maxPoints: 7,
      passed: emailOk,
      ...(emailOk
        ? {}
        : {
            detail:
              orgHost === undefined
                ? 'ORG_OFFICIAL_EMAIL cannot be checked without a valid ORG_URL.'
                : `ORG_OFFICIAL_EMAIL is not a valid address at the ORG_URL domain ${orgHost}.`,
            suggestion: 'Use an address at your own domain, e.g. partners@your-anchor.com.',
          }),
    }),
    buildCheck({
      id: 'identity/email-not-disposable',
      pillar,
      label: 'Official email is not a disposable address',
      maxPoints: 2,
      passed: contactDomainOk,
      ...(contactDomainOk
        ? {}
        : {
            detail:
              mailDomain === undefined
                ? 'No official email is set, so there is no contact domain to vet.'
                : `${mailDomain} is a throwaway mail provider.`,
            suggestion: 'Use an official contact address on your own domain.',
          }),
    }),
    buildCheck({
      id: 'identity/physical-attestation',
      pillar,
      label: 'Physical address attestation is published',
      maxPoints: 3,
      passed: physicalOk,
      ...(physicalOk
        ? {}
        : {
            detail: 'No ORG_PHYSICAL_ADDRESS_ATTESTATION is set.',
            suggestion: 'Publish a signed document on your own domain proving your address.',
          }),
    }),
    buildCheck({
      id: 'identity/phone-attestation',
      pillar,
      label: 'Phone number attestation is published',
      maxPoints: 2,
      passed: phoneOk,
      ...(phoneOk
        ? {}
        : {
            detail: 'No ORG_PHONE_NUMBER_ATTESTATION is set.',
            suggestion: 'Publish a signed document on your own domain proving your phone number.',
          }),
    }),
  ];
}

const ANCHOR_ASSET_TYPE_SET: ReadonlySet<string> = new Set(ANCHOR_ASSET_TYPES);

const UNPARSEABLE = 'The file could not be parsed, so this cannot be evaluated.';

/**
 * Asset & Anchor Transparency (30 points).
 *
 * A wallet will not list a token whose supply, backing, or redemption path is
 * ambiguous, so each of those is scored from the `[[CURRENCIES]]` entries.
 */
function transparencyChecks(
  doc: Record<string, unknown> | undefined,
  currencies: Record<string, unknown>[] | undefined,
): ReadinessCheck[] {
  const pillar: ReadinessPillarId = 'transparency';

  const issuable =
    currencies === undefined ? undefined : currencies.filter((entry) => !isNativeAsset(entry));
  const policyOffenders =
    issuable === undefined
      ? undefined
      : issuable.filter(
          (entry) => ISSUANCE_FIELDS.filter((field) => entry[field] !== undefined).length !== 1,
        );

  const anchored =
    currencies === undefined
      ? undefined
      : currencies.filter((entry) => entry.is_asset_anchored === true);
  const typeOffenders =
    anchored === undefined
      ? undefined
      : anchored.filter(
          (entry) =>
            !isString(entry.anchor_asset_type) ||
            !ANCHOR_ASSET_TYPE_SET.has(entry.anchor_asset_type),
        );
  const redemptionOffenders =
    anchored === undefined
      ? undefined
      : anchored.filter((entry) => !isFilled(entry.redemption_instructions));
  const reserveOffenders =
    anchored === undefined
      ? undefined
      : anchored.filter((entry) => !isUrl(entry.attestation_of_reserve));

  const webAuthOk = isHttpsUrl(doc?.WEB_AUTH_ENDPOINT);
  const transferOk = isHttpsUrl(doc?.TRANSFER_SERVER_SEP0024);

  return [
    buildCheck({
      id: 'transparency/issuance-policy',
      pillar,
      label: 'Every currency declares one issuance policy',
      maxPoints: 6,
      ...buildGap(
        UNPARSEABLE,
        policyOffenders,
        issuable,
        (missing, total) =>
          `${missing} of ${total} currencies do not declare exactly one of fixed_number, max_number, or is_unlimited.`,
        'Add exactly one issuance policy to each currency entry.',
      ),
    }),
    buildCheck({
      id: 'transparency/anchor-asset-type',
      pillar,
      label: 'Anchored assets declare an anchor_asset_type',
      maxPoints: 6,
      ...buildGap(
        UNPARSEABLE,
        typeOffenders,
        anchored,
        (missing, total) =>
          `${missing} of ${total} anchored assets have no valid anchor_asset_type.`,
        `Use one of ${ANCHOR_ASSET_TYPES.join(', ')} for anchor_asset_type.`,
      ),
    }),
    buildCheck({
      id: 'transparency/redemption-instructions',
      pillar,
      label: 'Anchored assets explain how to redeem',
      maxPoints: 6,
      ...buildGap(
        UNPARSEABLE,
        redemptionOffenders,
        anchored,
        (missing, total) =>
          `${missing} of ${total} anchored assets have no redemption_instructions.`,
        'Tell holders how to redeem the token, step by step.',
      ),
    }),
    buildCheck({
      id: 'transparency/reserve-attestation',
      pillar,
      label: 'Anchored assets publish a reserve attestation',
      maxPoints: 6,
      ...buildGap(
        UNPARSEABLE,
        reserveOffenders,
        anchored,
        (missing, total) =>
          `${missing} of ${total} anchored assets have no attestation_of_reserve.`,
        'Publish a proof-of-reserves document and link it from the currency entry.',
      ),
    }),
    buildCheck({
      id: 'transparency/web-auth-endpoint',
      pillar,
      label: 'WEB_AUTH_ENDPOINT (SEP-10) is declared',
      maxPoints: 3,
      passed: webAuthOk,
      ...(webAuthOk
        ? {}
        : {
            detail: doc === undefined ? UNPARSEABLE : 'No https:// WEB_AUTH_ENDPOINT is set.',
            suggestion: 'Add WEB_AUTH_ENDPOINT so wallets can authenticate users with SEP-10.',
          }),
    }),
    buildCheck({
      id: 'transparency/transfer-server',
      pillar,
      label: 'TRANSFER_SERVER_SEP0024 (SEP-24) is declared',
      maxPoints: 3,
      passed: transferOk,
      ...(transferOk
        ? {}
        : {
            detail: doc === undefined ? UNPARSEABLE : 'No https:// TRANSFER_SERVER_SEP0024 is set.',
            suggestion: 'Add TRANSFER_SERVER_SEP0024 so wallets can deposit and withdraw.',
          }),
    }),
  ];
}

/**
 * Builds the optional `detail`/`suggestion`/`passed` fields for a check that
 * fails on a list of offenders, distinguishing "unknown" (no source) from
 * "nothing to flag".
 */
function buildGap(
  unparseable: string,
  offenders: Record<string, unknown>[] | undefined,
  scope: Record<string, unknown>[] | undefined,
  describe: (missing: number, total: number) => string,
  suggestion: string,
): { passed: boolean; detail?: string; suggestion?: string } {
  if (offenders === undefined) return { passed: false, detail: unparseable };
  if (offenders.length === 0) return { passed: true };
  return {
    passed: false,
    detail: describe(offenders.length, scope?.length ?? offenders.length),
    suggestion,
  };
}

function makePillar(
  id: ReadinessPillarId,
  label: string,
  checks: ReadinessCheck[],
  maxScore: number,
): ReadinessPillar {
  const score = checks.reduce((total, check) => total + check.points, 0);
  return { id, label, score, maxScore, checks };
}

/**
 * Scores a lint result for wallet listing readiness.
 *
 * Deterministic by construction: the same diagnostics and document always
 * produce the same report, with no clock, no randomness, and no network access.
 */
export function calculateReadiness(result: LintResult): ReadinessReport {
  const parsed = result.parsed;
  const parseFailure = parsed === undefined;

  const protocol = protocolChecks(result, parseFailure);
  const identity = identityChecks(documentationOf(parsed));
  const transparency = transparencyChecks(parsed, currenciesOf(parsed));

  const pillars: ReadinessPillar[] = [
    makePillar('protocol', 'Protocol & Syntax Compliance', protocol, PROTOCOL_MAX_SCORE),
    makePillar('identity', 'Organization Identity & Trust', identity, IDENTITY_MAX_SCORE),
    makePillar('transparency', 'Asset & Anchor Transparency', transparency, TRANSPARENCY_MAX_SCORE),
  ];

  const score = pillars.reduce((total, pillar) => total + pillar.score, 0);

  return {
    score,
    grade: gradeFor(score),
    pillars,
    checklist: pillars.flatMap((pillar) => pillar.checks),
    parseFailure,
  };
}
