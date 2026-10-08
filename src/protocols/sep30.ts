/**
 * SEP-30 Server-based Key Derivation Validator.
 *
 * Validates the RECOVERY_SERVER /accounts endpoint and asserts that recovery
 * signers return valid Ed25519 signer public keys.
 *
 * Runs under opt-in --check-network --verify-sep30 when RECOVERY_SERVER is
 * present in stellar.toml.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isString, isUrl } from '../predicates.js';
import { StrKey } from '@stellar/stellar-base';

export const IDENTITY_SCHEMA_MISMATCH_RULE = 'sep30/identity-schema-mismatch';
export const INVALID_SIGNER_RESPONSE_RULE = 'sep30/invalid-signer-response';
export const SERVER_UNREACHABLE_RULE = 'sep30/server-unreachable';

const SEP30_SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0030.md';

export interface Sep30Options {
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Validates the RECOVERY_SERVER /accounts endpoint per SEP-30 and checks
 * that recovery signers contain valid Ed25519 public keys.
 */
export async function verifySep30(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: Sep30Options = {},
): Promise<Diagnostic[]> {
  const recoveryServer = doc.RECOVERY_SERVER;
  if (!isString(recoveryServer) || !isUrl(recoveryServer)) return [];

  const base = recoveryServer.replace(/\/+$/, '');
  const diagnostics: Diagnostic[] = [];

  // 1. Fetch GET /accounts for identity recovery
  let accountsBody: Record<string, unknown> | null = null;
  try {
    const res = await fetchImpl(`${base}/accounts`, { redirect: 'follow' });
    if (!res.ok) {
      const sev = severityFor(SERVER_UNREACHABLE_RULE, 'error', options.rules);
      if (sev) {
        diagnostics.push({
          rule: SERVER_UNREACHABLE_RULE,
          severity: sev,
          category: 'network',
          message: `RECOVERY_SERVER /accounts returned HTTP ${res.status}`,
          path: 'RECOVERY_SERVER',
          helpUri: SEP30_SPEC,
          suggestion:
            'Ensure RECOVERY_SERVER is online and the /accounts endpoint returns HTTP 200.',
        });
      }
      return diagnostics;
    }

    const data = await res.json();
    if (!isRecord(data)) {
      const sev = severityFor(INVALID_SIGNER_RESPONSE_RULE, 'error', options.rules);
      if (sev) {
        diagnostics.push({
          rule: INVALID_SIGNER_RESPONSE_RULE,
          severity: sev,
          category: 'network',
          message: 'RECOVERY_SERVER /accounts response must be a JSON object',
          path: 'RECOVERY_SERVER',
          helpUri: SEP30_SPEC,
          suggestion: 'Ensure /accounts returns a valid JSON object.',
        });
      }
      return diagnostics;
    }
    accountsBody = data;
  } catch (error) {
    const sev = severityFor(SERVER_UNREACHABLE_RULE, 'error', options.rules);
    if (sev) {
      diagnostics.push({
        rule: SERVER_UNREACHABLE_RULE,
        severity: sev,
        category: 'network',
        message: `Could not reach RECOVERY_SERVER /accounts at ${base}/accounts: ${(error as Error).message}`,
        path: 'RECOVERY_SERVER',
        helpUri: SEP30_SPEC,
        suggestion: 'Verify that RECOVERY_SERVER is online and accessible.',
      });
    }
    return diagnostics;
  }

  // 2. Validate identity recovery schema
  const identitySchema = accountsBody.identity;
  if (!isRecord(identitySchema)) {
    const sev = severityFor(IDENTITY_SCHEMA_MISMATCH_RULE, 'warning', options.rules);
    if (sev) {
      diagnostics.push({
        rule: IDENTITY_SCHEMA_MISMATCH_RULE,
        severity: sev,
        category: 'network',
        message: 'RECOVERY_SERVER /accounts identity schema is missing or invalid',
        path: 'RECOVERY_SERVER',
        helpUri: SEP30_SPEC,
        suggestion: 'Ensure /accounts returns an identity object with proper schema per SEP-30.',
      });
    }
    // Cannot validate signers if there's no identity schema
    return diagnostics;
  }

  // 3. Validate recovery signers are valid Ed25519 public keys
  const signers = identitySchema.signers;
  if (!Array.isArray(signers)) {
    const sev = severityFor(INVALID_SIGNER_RESPONSE_RULE, 'error', options.rules);
    if (sev) {
      diagnostics.push({
        rule: INVALID_SIGNER_RESPONSE_RULE,
        severity: sev,
        category: 'network',
        message: 'RECOVERY_SERVER /accounts signers must be an array',
        path: 'RECOVERY_SERVER',
        helpUri: SEP30_SPEC,
        suggestion: 'Ensure /accounts signers field is a JSON array.',
      });
    }
    return diagnostics;
  }

  for (let i = 0; i < signers.length; i++) {
    const signer = signers[i];
    if (typeof signer !== 'string') {
      const sev = severityFor(INVALID_SIGNER_RESPONSE_RULE, 'error', options.rules);
      if (sev) {
        diagnostics.push({
          rule: INVALID_SIGNER_RESPONSE_RULE,
          severity: sev,
          category: 'network',
          message: `RECOVERY_SERVER /accounts signer at index ${i} must be a string`,
          path: `RECOVERY_SERVER.signers[${i}]`,
          helpUri: SEP30_SPEC,
          suggestion: 'Ensure each signer is a valid Ed25519 public key string.',
        });
      }
      continue;
    }

    if (!StrKey.isValidEd25519PublicKey(signer)) {
      const sev = severityFor(INVALID_SIGNER_RESPONSE_RULE, 'error', options.rules);
      if (sev) {
        diagnostics.push({
          rule: INVALID_SIGNER_RESPONSE_RULE,
          severity: sev,
          category: 'network',
          message: `RECOVERY_SERVER /accounts signer at index ${i} is not a valid Ed25519 public key`,
          path: `RECOVERY_SERVER.signers[${i}]`,
          helpUri: SEP30_SPEC,
          suggestion: 'Ensure each signer is a valid Ed25519 public key (starts with G).',
        });
      }
    }
  }

  return diagnostics;
}

/** Registered rules for SEP-30 auditor */
export const sep30Rules: Rule[] = [
  {
    id: SERVER_UNREACHABLE_RULE,
    category: 'network',
    severity: 'error',
    description: 'RECOVERY_SERVER /accounts endpoint must be reachable and return HTTP 200',
    run() {},
  },
  {
    id: INVALID_SIGNER_RESPONSE_RULE,
    category: 'network',
    severity: 'error',
    description: 'RECOVERY_SERVER /accounts signers must be valid Ed25519 public keys',
    run() {},
  },
  {
    id: IDENTITY_SCHEMA_MISMATCH_RULE,
    category: 'network',
    severity: 'warning',
    description: 'RECOVERY_SERVER /accounts identity schema must be present and valid',
    run() {},
  },
];

export const sep30RuleIds: readonly string[] = sep30Rules.map((rule) => rule.id);
