/**
 * Multi-signature weight and threshold audit for an anchor's `SIGNING_KEY`
 * and `[[CURRENCIES]]` issuer accounts (issue #94).
 *
 * In SEP-1, `SIGNING_KEY` is the root of cryptographic authority for SEP-10
 * web authentication and challenge transactions, while `[[CURRENCIES]].issuer`
 * accounts gate asset issuance. Production anchors rarely control these
 * accounts with a single master key; they configure multisignature schemes
 * (2-of-3, 3-of-5, ...) with distinct low/medium/high thresholds. If the
 * declared key does not carry enough weight on-chain to satisfy the account's
 * operational thresholds — or key rotation happened on Horizon without the
 * `stellar.toml` being updated — transactions fail with `tx_bad_auth`.
 *
 * This auditor queries the Horizon `/accounts/{id}` endpoint for the declared
 * `SIGNING_KEY` and every issuer account, inspects each account's signer
 * topology and threshold configuration, and flags:
 *
 * - `security/signing-key-insufficient-weight` (error) — the declared signing
 *   key holds weight but cannot meet `med_threshold` on its own.
 * - `security/unreachable-threshold` (error) — the combined weight of all
 *   signers cannot reach the medium (or high) threshold, so the account is
 *   permanently locked. Mentions when the master key weight is 0, since it
 *   then cannot restore access either.
 * - `security/single-signer-high-threshold` (warning) — a single signer meets
 *   the high threshold by itself, so one compromised key controls the account.
 *
 * It also keeps the earlier governance checks from the single-signature
 * auditor: `security/signing-key-single-signature` (warning) fires when a
 * lone master key with no additional signers controls the account.
 *
 * Runs under the opt-in `--check-network` flag and degrades to silence when
 * Horizon cannot be reached.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { horizonUrlFor } from '../network-checks.js';

/** Legacy single-signature governance checks (kept for compatibility). */
export const SECURITY_SIGNING_KEY_SINGLE_SIGNATURE = 'security/signing-key-single-signature';
export const SECURITY_SIGNING_KEY_UNUSABLE = 'security/signing-key-unusable';

/** Issue #94 rules. */
export const SECURITY_SIGNING_KEY_INSUFFICIENT_WEIGHT = 'security/signing-key-insufficient-weight';
export const SECURITY_UNREACHABLE_THRESHOLD = 'security/unreachable-threshold';
export const SECURITY_SINGLE_SIGNER_HIGH_THRESHOLD = 'security/single-signer-high-threshold';

export const SIGNING_KEY_SINGLE_SIGNATURE_RULE = SECURITY_SIGNING_KEY_SINGLE_SIGNATURE;
export const SIGNING_KEY_UNUSABLE_RULE = SECURITY_SIGNING_KEY_UNUSABLE;

/** A signer entry as Horizon reports it on an account record. */
export interface HorizonSigner {
  key: string;
  weight: number;
  type?: string;
}

export interface MultisigAnalysisInput {
  /** The account id; its master key appears in `signers` with the same key. */
  accountId: string;
  /** Human label for diagnostics, e.g. `SIGNING_KEY` or `issuer USD`. */
  role?: string;
  signers: readonly HorizonSigner[];
  /**
   * Weight of the account's master key. Defaults to the weight of the signer
   * entry matching `accountId`, or 0 when that entry is absent.
   */
  masterWeight?: number;
  /** Threshold configuration; missing or invalid entries count as 0. */
  lowThreshold?: number;
  medThreshold?: number;
  highThreshold?: number;
}

export interface MultisigAuditOptions {
  rules?: RuleOverrides;
  /** Overrides the Horizon base URL derived from `NETWORK_PASSPHRASE`. */
  horizonUrl?: string;
  fetchImpl?: typeof fetch;
  /** Label used in diagnostics when auditing a specific account. */
  role?: string;
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

function thresholdOf(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : undefined;
}

/**
 * Pure threshold verification for one account's signer topology (issue #94).
 *
 * The master key is the signer whose key equals the account id (Horizon
 * includes it in the `signers` array, or reports its weight as
 * `master_weight`). The checks are deterministic:
 *
 * 1. The declared signing key alone must be able to meet `med_threshold`.
 * 2. The combined signer weight must reach the medium/high thresholds;
 *    otherwise the account is permanently locked (a deadlock).
 * 3. No single signer may meet the high threshold on its own.
 */
export function analyzeAccountThresholds(
  input: MultisigAnalysisInput,
  options: MultisigAuditOptions = {},
): Diagnostic[] {
  const { rules, role } = options;
  const diagnostics: Diagnostic[] = [];
  const { accountId, signers } = input;
  const label = role ?? input.role ?? 'SIGNING_KEY';

  const master = signers.find((signer) => signer.key === accountId);
  const masterWeight =
    input.masterWeight ?? (master === undefined ? 0 : Math.max(0, master.weight));
  const additional = signers.filter((signer) => signer.key !== accountId && signer.weight > 0);
  const masterListed = master !== undefined;
  const totalWeight =
    signers.reduce((sum, signer) => sum + Math.max(0, signer.weight), 0) +
    (masterListed ? 0 : masterWeight);

  const med = thresholdOf(input.medThreshold);
  const high = thresholdOf(input.highThreshold);

  // A single master key with no independent signers is a single point of
  // failure: one compromised or lost key controls every SEP-10 challenge.
  if (masterWeight > 0 && additional.length === 0) {
    const severity = severityFor(SECURITY_SIGNING_KEY_SINGLE_SIGNATURE, 'warning', rules);
    if (severity !== undefined) {
      diagnostics.push({
        rule: SECURITY_SIGNING_KEY_SINGLE_SIGNATURE,
        severity,
        category: 'principals',
        message: `${label} ${accountId} is controlled by a single master key of weight ${masterWeight} with no additional signers`,
        suggestion:
          'Adopt multi-signature governance: set the master key weight to 0 and add independent signing keys whose combined weight meets the medium threshold.',
      });
    }
  }

  // Issue #94: the declared signing key must be able to satisfy the account's
  // medium threshold on its own; otherwise anchor operations fail with
  // tx_bad_auth unless a co-signer completes the signature set.
  if (med !== undefined && med > 0 && masterWeight > 0 && masterWeight < med) {
    const severity = severityFor(SECURITY_SIGNING_KEY_INSUFFICIENT_WEIGHT, 'error', rules);
    if (severity !== undefined) {
      diagnostics.push({
        rule: SECURITY_SIGNING_KEY_INSUFFICIENT_WEIGHT,
        severity,
        category: 'principals',
        message: `${label} ${accountId} has weight ${masterWeight}, below the account medium threshold of ${med}, so it cannot authorize operations on its own`,
        suggestion:
          'Increase the signing key weight to meet med_threshold, lower the threshold, or confirm co-signers are always available to complete the signature set.',
      });
    }
  }

  // Issue #94: deadlock detection. When no combination of signers can reach a
  // threshold the account declares, it is permanently locked. With a master
  // weight of 0 it cannot even restore access by re-adding the master key.
  const unreachable =
    med !== undefined && totalWeight < med
      ? { name: 'medium', value: med }
      : high !== undefined && high > 0 && totalWeight < high
        ? { name: 'high', value: high }
        : undefined;
  if (unreachable !== undefined) {
    const severity = severityFor(SECURITY_UNREACHABLE_THRESHOLD, 'error', rules);
    if (severity !== undefined) {
      diagnostics.push({
        rule: SECURITY_UNREACHABLE_THRESHOLD,
        severity,
        category: 'principals',
        message: `${label} ${accountId}: total signer weight ${totalWeight} cannot reach the ${unreachable.name} threshold of ${unreachable.value}, so the account is permanently locked${
          masterWeight === 0 ? ' and the master key weight is 0, so it cannot restore access' : ''
        }`,
        suggestion:
          'Add or re-weight signers so their combined weight meets the threshold, or lower the threshold to a value the remaining signers can reach.',
      });
    }
  }

  // Issue #94: a single signer that reaches the high threshold by itself
  // concentrates full control of the account in one key.
  if (high !== undefined && high > 0) {
    const alone = signers.find((signer) => Math.max(0, signer.weight) >= high);
    if (alone !== undefined) {
      const severity = severityFor(SECURITY_SINGLE_SIGNER_HIGH_THRESHOLD, 'warning', rules);
      if (severity !== undefined) {
        diagnostics.push({
          rule: SECURITY_SINGLE_SIGNER_HIGH_THRESHOLD,
          severity,
          category: 'principals',
          message: `Signer ${alone.key} has weight ${alone.weight}, meeting the ${label.toLowerCase()} account high threshold of ${high} on its own; a single compromised key can authorize every operation`,
          suggestion:
            'Distribute signer weights so no single key meets the high threshold, or raise the threshold to require multiple signatures.',
        });
      }
    }
  }

  return diagnostics;
}

/**
 * Query Horizon for `accountId` and audit its signer topology and thresholds.
 *
 * Returns `[]` — never throws — when Horizon is unreachable, times out, or
 * returns a non-200 or malformed response, so a network outage cannot fail a
 * run that would otherwise pass.
 */
export async function auditAccountThresholds(
  accountId: string,
  horizonUrl: string,
  fetchImpl: typeof fetch = fetch,
  options: MultisigAuditOptions = {},
): Promise<Diagnostic[]> {
  let body: unknown;
  try {
    const base = horizonUrl.replace(/\/+$/, '');
    const response = await fetchImpl(`${base}/accounts/${encodeURIComponent(accountId)}`);
    if (!response.ok) return [];
    body = await response.json();
  } catch {
    return [];
  }

  if (typeof body !== 'object' || body === null || Array.isArray(body)) return [];
  const record = body as Record<string, unknown>;

  const rawSigners = record.signers;
  if (!Array.isArray(rawSigners)) return [];

  const signers: HorizonSigner[] = [];
  for (const entry of rawSigners) {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) continue;
    const signer = entry as Record<string, unknown>;
    if (typeof signer.key === 'string' && typeof signer.weight === 'number') {
      signers.push({
        key: signer.key,
        weight: signer.weight,
        ...(typeof signer.type === 'string' ? { type: signer.type } : {}),
      });
    }
  }

  const rawThresholds = record.thresholds;
  const thresholds =
    typeof rawThresholds === 'object' && rawThresholds !== null && !Array.isArray(rawThresholds)
      ? (rawThresholds as Record<string, unknown>)
      : {};

  return analyzeAccountThresholds(
    {
      accountId,
      signers,
      ...(typeof record.master_weight === 'number' ? { masterWeight: record.master_weight } : {}),
      ...(thresholdOf(thresholds.low_threshold) !== undefined
        ? { lowThreshold: thresholds.low_threshold as number }
        : {}),
      ...(thresholdOf(thresholds.med_threshold) !== undefined
        ? { medThreshold: thresholds.med_threshold as number }
        : {}),
      ...(thresholdOf(thresholds.high_threshold) !== undefined
        ? { highThreshold: thresholds.high_threshold as number }
        : {}),
    },
    options,
  );
}

/**
 * Audit the `SIGNING_KEY` and every `[[CURRENCIES]].issuer` account declared
 * in a parsed `stellar.toml`, resolving the Horizon instance from
 * `NETWORK_PASSPHRASE` (mainnet by default). Issuer accounts are audited once
 * even when several currencies share an issuer.
 */
export async function checkSigningKeyMultisig(
  doc: Record<string, unknown>,
  options: MultisigAuditOptions = {},
): Promise<Diagnostic[]> {
  const targets: Array<{ accountId: string; role: string }> = [];

  const signingKey = doc.SIGNING_KEY;
  if (typeof signingKey === 'string' && signingKey.trim() !== '') {
    targets.push({ accountId: signingKey.trim(), role: 'SIGNING_KEY' });
  }

  const currencies = Array.isArray(doc.CURRENCIES) ? doc.CURRENCIES : [];
  for (const entry of currencies) {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) continue;
    const currency = entry as Record<string, unknown>;
    if (typeof currency.issuer !== 'string' || currency.issuer.trim() === '') continue;
    const issuer = currency.issuer.trim();
    if (targets.some((target) => target.accountId === issuer)) continue;
    targets.push({
      accountId: issuer,
      role: typeof currency.code === 'string' ? `issuer ${currency.code}` : 'issuer',
    });
  }

  if (targets.length === 0) return [];

  const passphrase =
    typeof doc.NETWORK_PASSPHRASE === 'string' ? doc.NETWORK_PASSPHRASE : undefined;
  const horizonUrl = options.horizonUrl ?? horizonUrlFor(passphrase);
  const fetchImpl = options.fetchImpl ?? fetch;

  const perAccount = await Promise.all(
    targets.map((target) =>
      auditAccountThresholds(target.accountId, horizonUrl, fetchImpl, {
        ...options,
        role: target.role,
      }),
    ),
  );
  return perAccount.flat();
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const multisigRules: Rule[] = [
  {
    id: SECURITY_SIGNING_KEY_INSUFFICIENT_WEIGHT,
    category: 'principals',
    severity: 'error',
    description:
      'SIGNING_KEY does not carry enough weight to meet the account medium threshold on its own',
    run() {},
  },
  {
    id: SECURITY_UNREACHABLE_THRESHOLD,
    category: 'principals',
    severity: 'error',
    description:
      'Combined signer weight cannot reach the account thresholds, leaving the account permanently locked',
    run() {},
  },
  {
    id: SECURITY_SINGLE_SIGNER_HIGH_THRESHOLD,
    category: 'principals',
    severity: 'warning',
    description:
      'A single signer meets the high threshold by itself, concentrating control in one key',
    run() {},
  },
  {
    id: SECURITY_SIGNING_KEY_SINGLE_SIGNATURE,
    category: 'principals',
    severity: 'warning',
    description:
      'SIGNING_KEY should be protected by multi-signature governance, not a single master key',
    run() {},
  },
  {
    id: SECURITY_SIGNING_KEY_UNUSABLE,
    category: 'principals',
    severity: 'error',
    description:
      'Total signer weight cannot meet the medium threshold, so the account cannot sign at all',
    run() {},
  },
];

export const multisigRuleIds: readonly string[] = multisigRules.map((rule) => rule.id);
