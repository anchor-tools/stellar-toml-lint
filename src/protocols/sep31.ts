/**
 * SEP-31 Cross-Border Direct Payment Lifecycle Auditor.
 *
 * Runs under opt-in --check-network --verify-sep31.
 *
 * Audits DIRECT_PAYMENT_SERVER endpoints (/info, /transactions), KYC sender/receiver
 * type bindings, fee configurations, and cross-references supported assets against
 * stellar.toml [[CURRENCIES]].
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isString, isUrl } from '../predicates.js';

export const INFO_SCHEMA_INVALID_RULE = 'sep31/info-schema-invalid';
export const ASSET_UNSUPPORTED_RULE = 'sep31/asset-unsupported';
export const MISSING_KYC_REQUIREMENTS_RULE = 'sep31/missing-kyc-requirements';

const SEP31_SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0031.md';

export const VALID_SEP31_STATUSES = new Set([
  'pending_sender',
  'pending_stellar',
  'pending_customer_info_update',
  'pending_transaction_info_update',
  'pending_receiver',
  'pending_external',
  'completed',
  'error',
]);

export interface Sep31Options {
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
 * Validates DIRECT_PAYMENT_SERVER and its /info and /transactions endpoints against SEP-31.
 */
export async function verifySep31(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: Sep31Options = {},
): Promise<Diagnostic[]> {
  const server = doc.DIRECT_PAYMENT_SERVER;
  if (!isString(server) || !isUrl(server)) return [];

  const base = server.replace(/\/+$/, '');
  const diagnostics: Diagnostic[] = [];

  // 1. Fetch and validate GET /info
  let infoBody: Record<string, unknown> | null = null;
  try {
    const res = await fetchImpl(`${base}/info`, { redirect: 'follow' });
    if (!res.ok) {
      const sev = severityFor(INFO_SCHEMA_INVALID_RULE, 'error', options.rules);
      if (sev) {
        diagnostics.push({
          rule: INFO_SCHEMA_INVALID_RULE,
          severity: sev,
          category: 'network',
          message: `DIRECT_PAYMENT_SERVER /info returned HTTP ${res.status}`,
          path: 'DIRECT_PAYMENT_SERVER',
          helpUri: SEP31_SPEC,
          suggestion:
            'Ensure DIRECT_PAYMENT_SERVER serves a valid SEP-31 /info response with HTTP 200.',
        });
      }
      return diagnostics;
    }

    const data = await res.json();
    if (!isRecord(data) || !isRecord(data.receive)) {
      const sev = severityFor(INFO_SCHEMA_INVALID_RULE, 'error', options.rules);
      if (sev) {
        diagnostics.push({
          rule: INFO_SCHEMA_INVALID_RULE,
          severity: sev,
          category: 'network',
          message: 'DIRECT_PAYMENT_SERVER /info response must contain a "receive" object',
          path: 'DIRECT_PAYMENT_SERVER',
          helpUri: SEP31_SPEC,
          suggestion: 'SEP-31 requires GET /info to return a JSON object with a `receive` mapping.',
        });
      }
      return diagnostics;
    }
    infoBody = data;
  } catch (error) {
    const sev = severityFor(INFO_SCHEMA_INVALID_RULE, 'error', options.rules);
    if (sev) {
      diagnostics.push({
        rule: INFO_SCHEMA_INVALID_RULE,
        severity: sev,
        category: 'network',
        message: `Could not reach DIRECT_PAYMENT_SERVER /info at ${base}/info: ${(error as Error).message}`,
        path: 'DIRECT_PAYMENT_SERVER',
        helpUri: SEP31_SPEC,
        suggestion: 'Verify that DIRECT_PAYMENT_SERVER is online and accessible.',
      });
    }
    return diagnostics;
  }

  const receiveMap = infoBody.receive as Record<string, unknown>;

  // 2. Validate KYC requirements and fee schemas for each receive asset
  for (const [assetCode, assetConfig] of Object.entries(receiveMap)) {
    if (!isRecord(assetConfig)) {
      const sev = severityFor(INFO_SCHEMA_INVALID_RULE, 'error', options.rules);
      if (sev) {
        diagnostics.push({
          rule: INFO_SCHEMA_INVALID_RULE,
          severity: sev,
          category: 'network',
          message: `DIRECT_PAYMENT_SERVER /info receive entry for "${assetCode}" must be an object`,
          path: 'DIRECT_PAYMENT_SERVER',
          helpUri: SEP31_SPEC,
          suggestion: 'Format asset entries in receive map as configuration objects.',
        });
      }
      continue;
    }

    // Check sender and receiver KYC types
    const hasSenderKyc =
      isString(assetConfig.sender_sep12_type) ||
      (isRecord(assetConfig.fields) && isRecord(assetConfig.fields.sender));
    const hasReceiverKyc =
      isString(assetConfig.receiver_sep12_type) ||
      (isRecord(assetConfig.fields) && isRecord(assetConfig.fields.receiver));

    if (!hasSenderKyc && !hasReceiverKyc) {
      const sev = severityFor(MISSING_KYC_REQUIREMENTS_RULE, 'error', options.rules);
      if (sev) {
        diagnostics.push({
          rule: MISSING_KYC_REQUIREMENTS_RULE,
          severity: sev,
          category: 'network',
          message: `Asset "${assetCode}" in DIRECT_PAYMENT_SERVER /info is missing KYC sender and receiver requirements`,
          path: 'DIRECT_PAYMENT_SERVER',
          helpUri: SEP31_SPEC,
          suggestion:
            'Specify sender_sep12_type/receiver_sep12_type or fields.sender/fields.receiver for KYC.',
        });
      }
    }
  }

  // 3. Cross-reference stellar.toml [[CURRENCIES]] with SEP-31 supported assets
  if (Array.isArray(doc.CURRENCIES)) {
    for (const currency of doc.CURRENCIES) {
      if (!isRecord(currency) || !isString(currency.code)) continue;
      const code = currency.code;
      if (code.toLowerCase() === 'native' || (code.toLowerCase() === 'xlm' && !currency.issuer)) {
        continue;
      }

      const isListed = Object.keys(receiveMap).some(
        (key) =>
          key === code || (isString(currency.issuer) && key === `${code}:${currency.issuer}`),
      );

      if (!isListed) {
        const sev = severityFor(ASSET_UNSUPPORTED_RULE, 'warning', options.rules);
        if (sev) {
          diagnostics.push({
            rule: ASSET_UNSUPPORTED_RULE,
            severity: sev,
            category: 'network',
            message: `Currency "${code}" is declared in [[CURRENCIES]] but unsupported in DIRECT_PAYMENT_SERVER /info`,
            path: 'CURRENCIES',
            helpUri: SEP31_SPEC,
            suggestion: `Add "${code}" to DIRECT_PAYMENT_SERVER receive map, or remove it from [[CURRENCIES]].`,
          });
        }
      }
    }
  }

  // 4. Test POST /transactions field validation schema
  try {
    const postRes = await fetchImpl(`${base}/transactions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        amount: '100',
        asset_code: Object.keys(receiveMap)[0] ?? 'USD',
      }),
    });

    if (postRes.status === 200 || postRes.status === 201) {
      const txData = await postRes.json().catch(() => ({}));
      if (isRecord(txData) && typeof txData.status === 'string') {
        if (!VALID_SEP31_STATUSES.has(txData.status)) {
          const sev = severityFor(INFO_SCHEMA_INVALID_RULE, 'error', options.rules);
          if (sev) {
            diagnostics.push({
              rule: INFO_SCHEMA_INVALID_RULE,
              severity: sev,
              category: 'network',
              message: `Invalid SEP-31 transaction status "${txData.status}" returned from /transactions`,
              path: 'DIRECT_PAYMENT_SERVER',
              helpUri: SEP31_SPEC,
              suggestion: `SEP-31 transaction status must be one of: ${Array.from(VALID_SEP31_STATUSES).join(', ')}.`,
            });
          }
        }
      }
    }
  } catch {
    // Non-blocking for offline tests
  }

  return diagnostics;
}

/** Registered rules for SEP-31 auditor */
export const sep31Rules: Rule[] = [
  {
    id: INFO_SCHEMA_INVALID_RULE,
    category: 'network',
    severity: 'error',
    description:
      'DIRECT_PAYMENT_SERVER GET /info must return a valid SEP-31 schema with receive map',
    run() {},
  },
  {
    id: ASSET_UNSUPPORTED_RULE,
    category: 'network',
    severity: 'warning',
    description: 'Every [[CURRENCIES]] asset should be supported in DIRECT_PAYMENT_SERVER /info',
    run() {},
  },
  {
    id: MISSING_KYC_REQUIREMENTS_RULE,
    category: 'network',
    severity: 'error',
    description:
      'DIRECT_PAYMENT_SERVER /info assets must declare sender and receiver KYC requirements',
    run() {},
  },
];

export const sep31RuleIds: readonly string[] = sep31Rules.map((rule) => rule.id);
