/**
 * Multi-signature master weight zero locking and permanent immutability
 * auditor (issue #390).
 *
 * Non-custodial and algorithmic stablecoin issuers commonly guarantee their
 * supply can never grow by locking the issuing account permanently: the master
 * key weight is set to 0 and every signer is removed or zeroed, so no
 * combination of keys can ever authorize another operation. When an asset's
 * documentation claims a "fixed supply" or an "immutable" token, holders rely
 * on that mathematical guarantee.
 *
 * This auditor cross-references those documentation claims with the account
 * Horizon reports:
 *
 * - `master_weight` must be 0 — otherwise the master key can still sign.
 * - No signer may retain a positive weight — otherwise a hidden signer can
 *   still authorize issuance, minting, or a threshold change.
 * - The combined signing weight must fall below the account's medium and high
 *   thresholds, so future operations are mathematically impossible rather than
 *   merely inconvenient.
 *
 * A claimed-immutable asset whose issuer can still sign emits
 * `security/false-immutability-claim` (error). When Horizon cannot be reached
 * to verify a claim, `security/immutability-unverifiable` (warning) is emitted
 * instead of a false accusation.
 *
 * Runs under the opt-in `--check-network` flag.
 */
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isAccountId, isString } from '../predicates.js';
import { specUrl } from '../spec.js';

export const FALSE_IMMUTABILITY_CLAIM_RULE = 'security/false-immutability-claim';
export const IMMUTABILITY_UNVERIFIABLE_RULE = 'security/immutability-unverifiable';

/** The Horizon instance serving the network a passphrase names; mainnet by default. */
function horizonUrlFor(passphrase: string | undefined): string {
  return passphrase === 'Test SDF Network ; September 2015'
    ? 'https://horizon-testnet.stellar.org'
    : 'https://horizon.stellar.org';
}

/**
 * Documentation phrases that promise no further tokens can ever be minted.
 *
 * The match is case-insensitive and deliberately conservative: a false
 * immutability accusation against a token that merely mentions "fixed rates"
 * would be worse than missing a vague claim, so only explicit supply or
 * immutability language counts.
 */
const IMMUTABILITY_CLAIM_PATTERN =
  /immutable|fixed[- ]supply|permanently locked|no (?:further|additional) (?:mint|issuance)|cannot be (?:minted|changed|modified)/i;

/** The currency documentation fields a claim may hide in. */
const CLAIM_FIELDS = ['conditions', 'desc', 'name'] as const;

/** A signer as Horizon reports it on an account record. */
export interface HorizonAccountSigner {
  key: string;
  weight: number;
}

/** The account facts an immutability verdict depends on. */
export interface ImmutabilityAccountRecord {
  accountId: string;
  masterWeight: number;
  signers: readonly HorizonAccountSigner[];
  lowThreshold: number;
  medThreshold: number;
  highThreshold: number;
}

/** The mathematical verdict for one issuer account. */
export interface ImmutabilityVerdict {
  /** True when no signature set can ever authorize an operation on the account. */
  locked: boolean;
  masterWeight: number;
  /** Count of non-master signers holding a positive weight. */
  activeSigners: number;
  /** Combined weight of all non-master signers. */
  activeSignerWeight: number;
  medThreshold: number;
  highThreshold: number;
  /** Human-readable explanations for every reason the account is not locked. */
  reasons: string[];
}

/** One documentation claim found on a currency entry. */
export interface ImmutabilityClaim {
  field: string;
  text: string;
}

/**
 * The immutability claims a `[[CURRENCIES]]` entry's documentation makes.
 *
 * Only free-text fields are scanned. The structured issuance fields
 * (`fixed_number`, `max_number`) are audited separately by the fixed-supply
 * lock check, which judges them against the same on-chain account state.
 */
export function immutabilityClaimsOf(entry: Record<string, unknown>): ImmutabilityClaim[] {
  const claims: ImmutabilityClaim[] = [];
  for (const field of CLAIM_FIELDS) {
    const value = entry[field];
    if (isString(value) && IMMUTABILITY_CLAIM_PATTERN.test(value)) {
      claims.push({ field, text: value });
    }
  }
  return claims;
}

/**
 * Computes whether an account is permanently locked from its weights and
 * thresholds, with no network access.
 *
 * The master key is the signer entry whose key equals the account id; Horizon
 * reports its weight both as `master_weight` and as a `signers` entry. Only
 * non-master signers with a positive weight keep the account operable. An
 * account is locked only when it has no master weight, no active signers, and
 * a combined signing weight below both the medium and high thresholds —
 * thresholds of 0 mean operations need no signatures at all, so they cannot
 * lock anything.
 */
export function analyzeImmutability(record: ImmutabilityAccountRecord): ImmutabilityVerdict {
  const reasons: string[] = [];
  const { accountId, masterWeight, signers, medThreshold, highThreshold } = record;

  const activeSigners = signers.filter(
    (signer) => signer.key !== accountId && Number.isFinite(signer.weight) && signer.weight > 0,
  );
  const activeSignerWeight = activeSigners.reduce((sum, signer) => sum + signer.weight, 0);
  const totalWeight = Math.max(0, masterWeight) + activeSignerWeight;

  if (masterWeight !== 0) {
    reasons.push(`the master key still carries weight ${masterWeight}`);
  }
  if (activeSigners.length > 0) {
    const keys = activeSigners.map((signer) => signer.key).join(', ');
    reasons.push(
      `${activeSigners.length} signer${activeSigners.length === 1 ? '' : 's'} still carry weight (${keys})`,
    );
  }
  if (medThreshold > 0 && totalWeight >= medThreshold) {
    reasons.push(
      `the combined signing weight ${totalWeight} still meets the medium threshold ${medThreshold}`,
    );
  }
  if (highThreshold > 0 && totalWeight >= highThreshold) {
    reasons.push(
      `the combined signing weight ${totalWeight} still meets the high threshold ${highThreshold}`,
    );
  }
  if (medThreshold === 0 && highThreshold === 0) {
    reasons.push('the medium and high thresholds are 0, so operations require no signatures');
  }

  return {
    locked: reasons.length === 0,
    masterWeight,
    activeSigners: activeSigners.length,
    activeSignerWeight,
    medThreshold,
    highThreshold,
    reasons,
  };
}

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules: RuleOverrides | undefined,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Reads a non-negative integer threshold, treating malformed entries as absent. */
function readWeight(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 ? value : undefined;
}

/**
 * Queries Horizon for the issuer account and returns its immutability facts.
 *
 * Returns `undefined` — never throws — when Horizon is unreachable, answers
 * with a non-200 status, or returns a record that has no usable weight and
 * threshold data.
 */
export async function fetchImmutabilityRecord(
  accountId: string,
  horizonUrl: string,
  fetchImpl: typeof fetch = fetch,
): Promise<ImmutabilityAccountRecord | undefined> {
  let body: unknown;
  try {
    const base = horizonUrl.replace(/\/+$/, '');
    const response = await fetchImpl(`${base}/accounts/${encodeURIComponent(accountId)}`);
    if (!response.ok) return undefined;
    body = await response.json();
  } catch {
    return undefined;
  }

  if (!isRecord(body)) return undefined;
  const masterWeight = readWeight(body.master_key_weight);
  if (masterWeight === undefined || !Array.isArray(body.signers)) return undefined;

  const signers: HorizonAccountSigner[] = [];
  for (const raw of body.signers) {
    if (!isRecord(raw)) continue;
    const key = raw.key;
    const weight = readWeight(raw.weight);
    if (isString(key) && weight !== undefined) signers.push({ key, weight });
  }

  const thresholds = isRecord(body.thresholds) ? body.thresholds : {};
  return {
    accountId,
    masterWeight,
    signers,
    lowThreshold: readWeight(thresholds.low_threshold) ?? 0,
    medThreshold: readWeight(thresholds.med_threshold) ?? 0,
    highThreshold: readWeight(thresholds.high_threshold) ?? 0,
  };
}

export interface ImmutabilityAuditorOptions {
  rules?: RuleOverrides;
  /** Overrides the Horizon base URL derived from `NETWORK_PASSPHRASE`. */
  horizonUrl?: string;
  fetchImpl?: typeof fetch;
}

/** The classic `[[CURRENCIES]]` entries this file declares, with their paths. */
function classicIssuerEntries(
  doc: Record<string, unknown>,
): { issuer: string; index: number; entry: Record<string, unknown> }[] {
  const list = doc.CURRENCIES;
  if (!Array.isArray(list)) return [];

  const entries: { issuer: string; index: number; entry: Record<string, unknown> }[] = [];
  list.forEach((raw, index) => {
    if (!isRecord(raw) || raw.toml !== undefined) return;
    if (isString(raw.code)) {
      const code = raw.code.toLowerCase();
      if (code === 'native' || code === 'xlm') return;
    }
    if (isString(raw.issuer) && isAccountId(raw.issuer)) {
      entries.push({ issuer: raw.issuer, index, entry: raw });
    }
  });
  return entries;
}

/**
 * Audits every issuer account whose asset documentation claims a fixed supply
 * or immutability against the account's on-chain signing state.
 *
 * A claim whose account can still sign emits `security/false-immutability-claim`
 * (error). An unverifiable claim emits `security/immutability-unverifiable`
 * (warning), so a Horizon outage degrades the audit rather than failing a run
 * whose evidence could not be collected.
 */
export async function checkImmutabilityClaims(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: ImmutabilityAuditorOptions = {},
): Promise<Diagnostic[]> {
  const passphrase =
    typeof doc.NETWORK_PASSPHRASE === 'string' ? doc.NETWORK_PASSPHRASE : undefined;
  const horizonUrl = options.horizonUrl ?? horizonUrlFor(passphrase);

  const falseClaimSeverity = severityFor(FALSE_IMMUTABILITY_CLAIM_RULE, 'error', options.rules);
  const unverifiableSeverity = severityFor(
    IMMUTABILITY_UNVERIFIABLE_RULE,
    'warning',
    options.rules,
  );
  if (falseClaimSeverity === undefined && unverifiableSeverity === undefined) return [];

  const diagnostics: Diagnostic[] = [];
  const transport = options.fetchImpl ?? fetchImpl;

  for (const { issuer, index, entry } of classicIssuerEntries(doc)) {
    const claims = immutabilityClaimsOf(entry);
    if (claims.length === 0) continue;

    const issuerPath = `CURRENCIES[${index}].issuer`;
    const claimSummary = claims
      .map((claim) => {
        const text = claim.text.length > 80 ? `${claim.text.slice(0, 77)}...` : claim.text;
        return `${claim.field} ("${text}")`;
      })
      .join(', ');

    const record = await fetchImmutabilityRecord(issuer, horizonUrl, transport);
    const verdict = record === undefined ? undefined : analyzeImmutability(record);

    if (verdict === undefined) {
      if (unverifiableSeverity !== undefined) {
        diagnostics.push({
          rule: IMMUTABILITY_UNVERIFIABLE_RULE,
          severity: unverifiableSeverity,
          category: 'currencies',
          message: `Could not verify whether issuer ${issuer} is permanently locked, despite an immutability claim in ${claimSummary}`,
          path: issuerPath,
          helpUri: specUrl('currency-documentation'),
          suggestion:
            'Confirm the issuer account exists on the selected network and that Horizon is reachable, then re-run.',
        });
      }
      continue;
    }

    if (!verdict.locked && falseClaimSeverity !== undefined) {
      diagnostics.push({
        rule: FALSE_IMMUTABILITY_CLAIM_RULE,
        severity: falseClaimSeverity,
        category: 'currencies',
        message: `Issuer ${issuer} claims a fixed supply or immutable token in ${claimSummary}, but the account is not permanently locked: ${verdict.reasons.join('; ')}`,
        path: issuerPath,
        helpUri: specUrl('currency-documentation'),
        suggestion:
          'Set the issuer master weight to 0, remove or zero every signer, and keep the medium/high thresholds above the remaining weight — or remove the immutability claim from the asset documentation.',
      });
    }
  }

  return diagnostics;
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const immutabilityAuditorRules: Rule[] = [
  {
    id: FALSE_IMMUTABILITY_CLAIM_RULE,
    category: 'currencies',
    severity: 'error',
    description:
      'An asset claiming a fixed supply or immutability must have a permanently locked issuer account',
    run() {},
  },
  {
    id: IMMUTABILITY_UNVERIFIABLE_RULE,
    category: 'currencies',
    severity: 'warning',
    description:
      'An immutability claim could not be verified against the issuer account on Horizon',
    run() {},
  },
];

export const immutabilityAuditorRuleIds: readonly string[] = immutabilityAuditorRules.map(
  (rule) => rule.id,
);
