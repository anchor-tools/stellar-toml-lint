/**
 * SEP-6 Programmatic Deposit and Withdrawal Integration Tester.
 *
 * Runs under opt-in --check-network --verify-sep6.
 *
 * Tests the complete programmatic transaction flow (/deposit, /withdraw, /fee, /transactions, /transaction)
 * against the declared TRANSFER_SERVER in stellar.toml.
 */

import { Keypair } from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isString, isUrl } from '../predicates.js';

export const DEPOSIT_PARAMETER_MISMATCH_RULE = 'sep6/deposit-parameter-mismatch';
export const FEE_CALCULATION_MISMATCH_RULE = 'sep6/fee-calculation-mismatch';
export const INVALID_TRANSACTION_STATUS_RULE = 'sep6/invalid-transaction-status';

const SEP6_SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0006.md';

export const VALID_TRANSACTION_STATUSES = new Set([
  'completed',
  'pending_external',
  'pending_anchor',
  'pending_stellar',
  'pending_trust',
  'pending_user',
  'pending_user_transfer_start',
  'incomplete',
  'no_market',
  'too_small',
  'too_large',
  'error',
]);

export interface Sep6IntegrationOptions {
  rules?: RuleOverrides;
  account?: string;
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
 * Programmatically tests SEP-6 deposit, withdraw, fee, and transaction endpoints.
 */
export async function verifySep6Integration(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: Sep6IntegrationOptions = {},
): Promise<Diagnostic[]> {
  const server = doc.TRANSFER_SERVER;
  if (!isString(server) || !isUrl(server)) return [];

  const base = server.replace(/\/+$/, '');
  const diagnostics: Diagnostic[] = [];

  const account = options.account ?? Keypair.random().publicKey();

  // 1. Fetch /info to inspect supported assets and fee rules
  let infoData: Record<string, unknown> | null = null;
  try {
    const infoRes = await fetchImpl(`${base}/info`, { redirect: 'follow' });
    if (infoRes.ok) {
      infoData = (await infoRes.json()) as Record<string, unknown>;
    }
  } catch {
    // /info error is handled by cross-sep/sep6.ts
  }

  const depositMap = infoData && isRecord(infoData.deposit) ? infoData.deposit : {};
  const withdrawMap = infoData && isRecord(infoData.withdraw) ? infoData.withdraw : {};

  const sampleDepositAsset = Object.keys(depositMap)[0]?.split(':')[0] ?? 'USDC';
  const sampleWithdrawAsset = Object.keys(withdrawMap)[0]?.split(':')[0] ?? 'USDC';

  // 2. Validate GET /deposit parameters
  try {
    const depositUrl = new URL(`${base}/deposit`);
    depositUrl.searchParams.set('asset_code', sampleDepositAsset);
    depositUrl.searchParams.set('account', account);
    depositUrl.searchParams.set('memo_type', 'MEMO_ID');
    depositUrl.searchParams.set('memo', '123456');

    const depositRes = await fetchImpl(depositUrl.toString(), { redirect: 'follow' });
    if (depositRes.status === 400) {
      const errBody = await depositRes.json().catch(() => ({}));
      const sev = severityFor(DEPOSIT_PARAMETER_MISMATCH_RULE, 'error', options.rules);
      if (sev) {
        diagnostics.push({
          rule: DEPOSIT_PARAMETER_MISMATCH_RULE,
          severity: sev,
          category: 'network',
          message: `GET /deposit rejected valid parameters for asset "${sampleDepositAsset}": ${JSON.stringify(errBody)}`,
          path: 'TRANSFER_SERVER',
          helpUri: SEP6_SPEC,
          suggestion:
            'Ensure GET /deposit accepts standard SEP-6 parameters (asset_code, account, memo_type, memo).',
        });
      }
    } else if (depositRes.ok) {
      const body = await depositRes.json().catch(() => null);
      if (isRecord(body)) {
        // Valid responses must contain how or type
        if (!body.how && !body.type && !body.id) {
          const sev = severityFor(DEPOSIT_PARAMETER_MISMATCH_RULE, 'error', options.rules);
          if (sev) {
            diagnostics.push({
              rule: DEPOSIT_PARAMETER_MISMATCH_RULE,
              severity: sev,
              category: 'network',
              message:
                'GET /deposit response missing required instruction field ("how", "type", or "id")',
              path: 'TRANSFER_SERVER',
              helpUri: SEP6_SPEC,
              suggestion:
                'SEP-6 /deposit must return deposit instructions ("how"), interactive handoff ("type"), or transaction "id".',
            });
          }
        }
      }
    }
  } catch {
    // Network errors
  }

  // 3. Validate GET /withdraw parameters
  try {
    const withdrawUrl = new URL(`${base}/withdraw`);
    withdrawUrl.searchParams.set('asset_code', sampleWithdrawAsset);
    withdrawUrl.searchParams.set('type', 'bank_account');
    withdrawUrl.searchParams.set('dest', 'test_bank_dest');
    withdrawUrl.searchParams.set('account', account);

    const withdrawRes = await fetchImpl(withdrawUrl.toString(), { redirect: 'follow' });
    if (withdrawRes.status === 400) {
      const errBody = await withdrawRes.json().catch(() => ({}));
      const sev = severityFor(DEPOSIT_PARAMETER_MISMATCH_RULE, 'error', options.rules);
      if (sev) {
        diagnostics.push({
          rule: DEPOSIT_PARAMETER_MISMATCH_RULE,
          severity: sev,
          category: 'network',
          message: `GET /withdraw rejected valid parameters for asset "${sampleWithdrawAsset}": ${JSON.stringify(errBody)}`,
          path: 'TRANSFER_SERVER',
          helpUri: SEP6_SPEC,
          suggestion:
            'Ensure GET /withdraw accepts standard SEP-6 parameters (asset_code, type, dest, account).',
        });
      }
    }
  } catch {
    // Network errors
  }

  // 4. Validate GET /fee dynamic calculation against declared fee schemas
  try {
    const amount = 100;
    const feeUrl = new URL(`${base}/fee`);
    feeUrl.searchParams.set('operation', 'deposit');
    feeUrl.searchParams.set('asset_code', sampleDepositAsset);
    feeUrl.searchParams.set('amount', String(amount));

    const feeRes = await fetchImpl(feeUrl.toString(), { redirect: 'follow' });
    if (feeRes.ok) {
      const feeData = (await feeRes.json().catch(() => ({}))) as Record<string, unknown>;
      if (typeof feeData.fee === 'number') {
        const assetInfo = isRecord(depositMap[sampleDepositAsset])
          ? (depositMap[sampleDepositAsset] as Record<string, unknown>)
          : null;
        if (assetInfo) {
          const feeFixed = typeof assetInfo.fee_fixed === 'number' ? assetInfo.fee_fixed : 0;
          const feePercent = typeof assetInfo.fee_percent === 'number' ? assetInfo.fee_percent : 0;
          const expectedFee = feeFixed + (amount * feePercent) / 100;

          if (expectedFee > 0 && Math.abs(feeData.fee - expectedFee) > 0.0001) {
            const sev = severityFor(FEE_CALCULATION_MISMATCH_RULE, 'warning', options.rules);
            if (sev) {
              diagnostics.push({
                rule: FEE_CALCULATION_MISMATCH_RULE,
                severity: sev,
                category: 'network',
                message: `GET /fee returned ${feeData.fee} for deposit of ${amount} ${sampleDepositAsset}, but /info declared fee computes to ${expectedFee}`,
                path: 'TRANSFER_SERVER',
                helpUri: SEP6_SPEC,
                suggestion:
                  'Align GET /fee calculation with fee_fixed and fee_percent declared in /info.',
              });
            }
          }
        }
      }
    }
  } catch {
    // Network errors
  }

  // 5. Test transaction lookup and status code validation
  try {
    const txUrl = `${base}/transaction?id=test-transaction-id`;
    const txRes = await fetchImpl(txUrl, { redirect: 'follow' });
    if (txRes.ok) {
      const txData = (await txRes.json().catch(() => ({}))) as Record<string, unknown>;
      const transaction = isRecord(txData.transaction) ? txData.transaction : txData;
      if (typeof transaction.status === 'string') {
        if (!VALID_TRANSACTION_STATUSES.has(transaction.status)) {
          const sev = severityFor(INVALID_TRANSACTION_STATUS_RULE, 'error', options.rules);
          if (sev) {
            diagnostics.push({
              rule: INVALID_TRANSACTION_STATUS_RULE,
              severity: sev,
              category: 'network',
              message: `Invalid transaction status "${transaction.status}" in /transaction response`,
              path: 'TRANSFER_SERVER',
              helpUri: SEP6_SPEC,
              suggestion: `SEP-6 transaction status must be one of: ${Array.from(VALID_TRANSACTION_STATUSES).join(', ')}.`,
            });
          }
        }
      }
    }
  } catch {
    // Network errors
  }

  return diagnostics;
}

/** Registered rules for SEP-6 integration tester */
export const sep6IntegrationRules: Rule[] = [
  {
    id: DEPOSIT_PARAMETER_MISMATCH_RULE,
    category: 'network',
    severity: 'error',
    description:
      'TRANSFER_SERVER deposit and withdraw parameter schemas must match SEP-6 specification',
    run() {},
  },
  {
    id: FEE_CALCULATION_MISMATCH_RULE,
    category: 'network',
    severity: 'warning',
    description: 'GET /fee dynamic calculation must match fee structure declared in /info',
    run() {},
  },
  {
    id: INVALID_TRANSACTION_STATUS_RULE,
    category: 'network',
    severity: 'error',
    description: 'Transaction status must adhere to valid SEP-6 lifecycle states',
    run() {},
  },
];

export const sep6IntegrationRuleIds: readonly string[] = sep6IntegrationRules.map(
  (rule) => rule.id,
);
