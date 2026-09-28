/**
 * Compromised anchor signing-key revocation and rotation detection.
 *
 * When an anchor rotates its `SIGNING_KEY`, stale `stellar.toml` files cached
 * by CDNs and wallets keep advertising the old key. This auditor fetches the
 * anchor account from Horizon, inspects the on-chain signer list, and flags a
 * declared `SIGNING_KEY` that has been revoked (weight 0 or removed) or
 * effectively superseded by a different primary signer.
 *
 * Runs under the opt-in `--check-network` flag and degrades to silence when
 * Horizon cannot be reached.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { horizonUrlFor } from '../network-checks.js';

export const SECURITY_REVOKED_SIGNING_KEY = 'security/revoked-signing-key';
export const SECURITY_UNRECORDED_KEY_ROTATION = 'security/unrecorded-key-rotation';

export const REVOKED_SIGNING_KEY_RULE = SECURITY_REVOKED_SIGNING_KEY;
export const UNRECORDED_KEY_ROTATION_RULE = SECURITY_UNRECORDED_KEY_ROTATION;

export interface HorizonSigner {
  key: string;
  weight: number;
  type?: string;
}

export interface KeyRevocationAnalysisInput {
  signingKey: string;
  signers: readonly HorizonSigner[];
  /** Medium threshold from the account, when known. */
  medThreshold?: number;
}

export interface KeyRevocationOptions {
  rules?: RuleOverrides;
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

/** Pure analysis of a declared signing key against on-chain signers. */
export function analyzeSigningKeyRevocation(
  input: KeyRevocationAnalysisInput,
  options: KeyRevocationOptions = {},
): Diagnostic[] {
  const { rules } = options;
  const diagnostics: Diagnostic[] = [];
  const { signingKey, signers, medThreshold } = input;

  const declared = signers.find((signer) => signer.key === signingKey);

  if (declared === undefined || declared.weight <= 0) {
    const severity = severityFor(SECURITY_REVOKED_SIGNING_KEY, 'error', rules);
    if (severity !== undefined) {
      diagnostics.push({
        rule: SECURITY_REVOKED_SIGNING_KEY,
        severity,
        category: 'principals',
        message:
          declared === undefined
            ? `SIGNING_KEY ${signingKey} is no longer a signer on the anchor account`
            : `SIGNING_KEY ${signingKey} has on-chain weight 0 and can no longer sign transactions`,
        suggestion:
          'Publish the current signing key in stellar.toml and purge the revoked key from caches and CDNs.',
      });
    }
    return diagnostics;
  }

  const superseding =
    medThreshold === undefined
      ? undefined
      : signers.find(
          (signer) =>
            signer.key !== signingKey && signer.weight >= medThreshold && signer.weight > 0,
        );

  if (superseding !== undefined && declared.weight < medThreshold!) {
    const severity = severityFor(SECURITY_UNRECORDED_KEY_ROTATION, 'warning', rules);
    if (severity !== undefined) {
      diagnostics.push({
        rule: SECURITY_UNRECORDED_KEY_ROTATION,
        severity,
        category: 'principals',
        message: `SIGNING_KEY ${signingKey} has weight ${declared.weight} below the medium threshold of ${medThreshold}, while ${superseding.key} can authorize operations`,
        suggestion:
          'Update stellar.toml to advertise the signer that actually controls the account.',
      });
    }
  }

  return diagnostics;
}

/**
 * Fetch the anchor account and analyse the declared `SIGNING_KEY`.
 * Returns `[]` when Horizon is unreachable or the account cannot be read.
 */
export async function checkSigningKeyRevocation(
  doc: Record<string, unknown>,
  options: KeyRevocationOptions = {},
): Promise<Diagnostic[]> {
  const signingKey = doc.SIGNING_KEY;
  if (typeof signingKey !== 'string' || signingKey.trim() === '') return [];

  const passphrase =
    typeof doc.NETWORK_PASSPHRASE === 'string' ? doc.NETWORK_PASSPHRASE : undefined;
  const horizonUrl = options.horizonUrl ?? horizonUrlFor(passphrase);
  const fetchImpl = options.fetchImpl ?? fetch;

  let body: unknown;
  try {
    const response = await fetchImpl(`${horizonUrl}/accounts/${encodeURIComponent(signingKey)}`);
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

  const thresholds = record.thresholds;
  const medThreshold =
    typeof thresholds === 'object' && thresholds !== null && !Array.isArray(thresholds)
      ? (thresholds as Record<string, unknown>).med_threshold
      : undefined;

  return analyzeSigningKeyRevocation(
    {
      signingKey,
      signers,
      ...(typeof medThreshold === 'number' ? { medThreshold } : {}),
    },
    options,
  );
}

export const keyRevocationRules: Rule[] = [
  {
    id: SECURITY_REVOKED_SIGNING_KEY,
    category: 'principals',
    severity: 'error',
    description: 'The published SIGNING_KEY must still hold weight on the anchor account',
    run() {},
  },
  {
    id: SECURITY_UNRECORDED_KEY_ROTATION,
    category: 'principals',
    severity: 'warning',
    description: 'A superseding primary signer on-chain should be reflected in stellar.toml',
    run() {},
  },
];

export const keyRevocationRuleIds: readonly string[] = keyRevocationRules.map((rule) => rule.id);
