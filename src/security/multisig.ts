/**
 * Multi-signature governance audit for an anchor's `SIGNING_KEY`.
 *
 * In enterprise Stellar anchor deployments `SIGNING_KEY` is the root of
 * cryptographic authority for SEP-10 web authentication, challenge
 * transactions, and custodial assertions. An account controlled by a single
 * master key (weight 1, threshold 1) is a single point of failure: one
 * exfiltrated or lost key compromises every challenge the anchor signs.
 *
 * Security best practice is multi-signature governance — master key weight 0
 * with several independent signing keys whose combined weight meets a medium
 * or high threshold, so no single key authorizes operations alone.
 *
 * This auditor queries the Horizon `/accounts/{id}` endpoint, inspects the
 * account's signer topology and threshold configuration, and flags:
 *
 * - `security/signing-key-single-signature` (warning) — the master key holds
 *   weight and there are no additional signers, so a single private key
 *   controls the account. Recommend a multi-sig threshold setup.
 * - `security/signing-key-unusable` (error) — the total available signer
 *   weight cannot meet `med_threshold`, so the account is locked and cannot
 *   authorize operations at all.
 *
 * Runs under the opt-in `--check-network` flag and degrades to silence when
 * Horizon cannot be reached.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { horizonUrlFor } from '../network-checks.js';

export const SECURITY_SIGNING_KEY_SINGLE_SIGNATURE = 'security/signing-key-single-signature';
export const SECURITY_SIGNING_KEY_UNUSABLE = 'security/signing-key-unusable';

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
  signers: readonly HorizonSigner[];
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
 * Pure analysis of an account's signer topology and thresholds.
 *
 * The master key is the signer whose key equals the account id (Horizon
 * includes it in the `signers` array). Additional signers are every other
 * entry with positive weight. An account is single-signature when the master
 * key holds weight and no additional signers exist; it is unusable when the
 * combined weight of all signers cannot meet `med_threshold`.
 */
export function analyzeAccountThresholds(
  input: MultisigAnalysisInput,
  options: MultisigAuditOptions = {},
): Diagnostic[] {
  const { rules } = options;
  const diagnostics: Diagnostic[] = [];
  const { accountId, signers, medThreshold } = input;

  const master = signers.find((signer) => signer.key === accountId);
  const masterKeyWeight = master === undefined ? 0 : Math.max(0, master.weight);
  const additional = signers.filter((signer) => signer.key !== accountId && signer.weight > 0);
  const additionalSignerWeight = additional.reduce((sum, signer) => sum + signer.weight, 0);

  // A single master key with no independent signers is a single point of
  // failure: one compromised or lost key controls every SEP-10 challenge.
  if (masterKeyWeight > 0 && additional.length === 0) {
    const severity = severityFor(SECURITY_SIGNING_KEY_SINGLE_SIGNATURE, 'warning', rules);
    if (severity !== undefined) {
      diagnostics.push({
        rule: SECURITY_SIGNING_KEY_SINGLE_SIGNATURE,
        severity,
        category: 'principals',
        message: `SIGNING_KEY ${accountId} is controlled by a single master key of weight ${masterKeyWeight} with no additional signers`,
        suggestion:
          'Adopt multi-signature governance: set the master key weight to 0 and add independent signing keys whose combined weight meets the medium threshold.',
      });
    }
  }

  // The account must be able to reach its own medium threshold; when it
  // cannot, no signer combination can authorize operations and the anchor
  // cannot sign SEP-10 challenges at all.
  const med = thresholdOf(medThreshold);
  if (med !== undefined) {
    const totalWeight = masterKeyWeight + additionalSignerWeight;
    if (totalWeight < med) {
      const severity = severityFor(SECURITY_SIGNING_KEY_UNUSABLE, 'error', rules);
      if (severity !== undefined) {
        diagnostics.push({
          rule: SECURITY_SIGNING_KEY_UNUSABLE,
          severity,
          category: 'principals',
          message: `Total signer weight ${totalWeight} cannot meet the medium threshold of ${med}, so the account cannot authorize any transaction`,
          suggestion:
            'Restore signer weight so the combined weight meets med_threshold, or lower the threshold to a value the remaining signers can reach.',
        });
      }
    }
  }

  return diagnostics;
}

/**
 * Query Horizon for the account behind `accountId` and audit its signer
 * topology and thresholds.
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
 * Audit the `SIGNING_KEY` declared in a parsed `stellar.toml`, resolving the
 * Horizon instance from `NETWORK_PASSPHRASE` (mainnet by default).
 */
export async function checkSigningKeyMultisig(
  doc: Record<string, unknown>,
  options: MultisigAuditOptions = {},
): Promise<Diagnostic[]> {
  const signingKey = doc.SIGNING_KEY;
  if (typeof signingKey !== 'string' || signingKey.trim() === '') return [];

  const passphrase =
    typeof doc.NETWORK_PASSPHRASE === 'string' ? doc.NETWORK_PASSPHRASE : undefined;
  const horizonUrl = options.horizonUrl ?? horizonUrlFor(passphrase);
  const fetchImpl = options.fetchImpl ?? fetch;

  return auditAccountThresholds(signingKey, horizonUrl, fetchImpl, options);
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const multisigRules: Rule[] = [
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
