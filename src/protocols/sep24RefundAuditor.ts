/**
 * SEP-24 refund lifecycle and memo matching auditor.
 *
 * Runs under `stellar-toml-lint verify-refund --domain <domain> --tx-id <id>`.
 *
 * When an interactive deposit or withdrawal fails after the user has already
 * sent funds, SEP-24 requires the anchor to refund them and describe the refund
 * in the transaction's `refunds` object. A refund that is short by its own fee,
 * points at a transaction that never landed, or pays the wrong account is a
 * silent loss of user money. The audit therefore checks both layers:
 *
 *   - the `refunds` schema (`amount_refunded`, `amount_fee`, `payments[]`), and
 *   - each refund payment against Horizon: existence, success, destination,
 *     asset, and memo.
 *
 * Only public keys and transaction hashes are reported; the SEP-10 token is
 * never echoed.
 */

import type { Diagnostic, Rule, RuleCategory, RuleOverrides, Severity } from '../types.js';
import { fetchWithTimeout, isRecord, severityFor, toScaled } from './verifierSupport.js';

const UNVERIFIABLE_RULE = 'sep24/refund-unverifiable';
const SCHEMA_RULE = 'sep24/refund-schema-invalid';
const FEE_EXCEEDS_RULE = 'sep24/refund-fee-exceeds-amount';
const MISSING_PAYMENT_RULE = 'sep24/refund-missing-payment';
const TX_NOT_FOUND_RULE = 'sep24/refund-transaction-not-found';
const TX_FAILED_RULE = 'sep24/refund-transaction-failed';
const DESTINATION_RULE = 'sep24/refund-destination-mismatch';
const ASSET_RULE = 'sep24/refund-asset-mismatch';
const MEMO_RULE = 'sep24/refund-memo-mismatch';

const SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0024.md';
const CATEGORY: RuleCategory = 'network';
const DEFAULT_HORIZON = 'https://horizon.stellar.org';

export interface RefundPayment {
  id: string;
  idType?: string;
  amount?: string;
  fee?: string;
}

export interface RefundRecord {
  amountRefunded?: string;
  amountFee?: string;
  payments: RefundPayment[];
}

export interface RefundSchemaIssue {
  code: string;
  message: string;
}

/** Parses the `refunds` object, tolerating partial payloads but recording why. */
export function parseRefundRecord(raw: unknown): {
  record?: RefundRecord;
  issues: RefundSchemaIssue[];
} {
  const issues: RefundSchemaIssue[] = [];
  if (!isRecord(raw)) {
    return {
      issues: [{ code: SCHEMA_RULE, message: '`refunds` is missing or is not an object' }],
    };
  }

  const amountRefunded = raw.amount_refunded;
  const amountFee = raw.amount_fee;
  for (const [field, value] of [
    ['amount_refunded', amountRefunded],
    ['amount_fee', amountFee],
  ] as const) {
    if (value === undefined) {
      issues.push({ code: SCHEMA_RULE, message: `refunds.${field} is missing` });
    } else if (typeof value !== 'string' || toScaled(value) === undefined) {
      issues.push({ code: SCHEMA_RULE, message: `refunds.${field} is not a decimal amount` });
    }
  }

  const payments: RefundPayment[] = [];
  if (!Array.isArray(raw.payments)) {
    issues.push({ code: SCHEMA_RULE, message: 'refunds.payments is missing or is not an array' });
  } else if (raw.payments.length === 0) {
    issues.push({ code: MISSING_PAYMENT_RULE, message: 'refunds.payments is empty' });
  } else {
    raw.payments.forEach((entry, index) => {
      if (!isRecord(entry)) {
        issues.push({ code: SCHEMA_RULE, message: `refunds.payments[${index}] is not an object` });
        return;
      }
      if (typeof entry.id !== 'string' || entry.id.trim() === '') {
        issues.push({ code: SCHEMA_RULE, message: `refunds.payments[${index}].id is missing` });
        return;
      }
      for (const field of ['amount', 'fee'] as const) {
        const value = entry[field];
        if (value !== undefined && (typeof value !== 'string' || toScaled(value) === undefined)) {
          issues.push({
            code: SCHEMA_RULE,
            message: `refunds.payments[${index}].${field} is not a decimal amount`,
          });
        }
      }
      payments.push({
        id: entry.id,
        ...(typeof entry.id_type === 'string' ? { idType: entry.id_type } : {}),
        ...(typeof entry.amount === 'string' ? { amount: entry.amount } : {}),
        ...(typeof entry.fee === 'string' ? { fee: entry.fee } : {}),
      });
    });
  }

  const refunded = typeof amountRefunded === 'string' ? toScaled(amountRefunded) : undefined;
  const fee = typeof amountFee === 'string' ? toScaled(amountFee) : undefined;
  if (refunded !== undefined && fee !== undefined && fee > refunded) {
    issues.push({
      code: FEE_EXCEEDS_RULE,
      message: `refunds.amount_fee (${String(amountFee)}) exceeds amount_refunded (${String(amountRefunded)})`,
    });
  }

  const record: RefundRecord = {
    ...(typeof amountRefunded === 'string' ? { amountRefunded } : {}),
    ...(typeof amountFee === 'string' ? { amountFee } : {}),
    payments,
  };
  return { record, issues };
}

/** What the refund must have paid, derived from the original SEP-24 transaction. */
export interface RefundExpectation {
  /** Account the original deposit came from (refund destination). */
  sender?: string;
  assetCode?: string;
  assetIssuer?: string;
  memo?: string;
  memoType?: string;
}

export interface PaymentVerification {
  id: string;
  found: boolean;
  successful?: boolean;
  destination?: string;
  assetCode?: string;
  assetIssuer?: string;
  memo?: string;
  memoType?: string;
  matched: boolean;
}

export interface Sep24RefundReport {
  transferServer: string;
  transactionId: string;
  horizonUrl: string;
  status?: string;
  refunds?: RefundRecord;
  expectation: RefundExpectation;
  payments: PaymentVerification[];
  findings: { code: string; severity: Severity; message: string }[];
  ok: boolean;
}

export interface Sep24RefundResult {
  report: Sep24RefundReport;
  diagnostics: Diagnostic[];
}

export interface Sep24RefundOptions {
  rules?: RuleOverrides;
  transferServer?: string;
  transactionId?: string;
  token?: string;
  horizonUrl?: string;
  timeoutMs?: number;
}

function ruleDiagnostics(
  code: string,
  fallback: Severity,
  message: string,
  suggestion: string,
  rules?: RuleOverrides,
  path = 'TRANSFER_SERVER_SEP0024',
): Diagnostic[] {
  const severity = severityFor(code, fallback, rules);
  if (severity === undefined) return [];
  return [{ rule: code, severity, category: CATEGORY, message, path, helpUri: SPEC, suggestion }];
}

function stringField(source: Record<string, unknown>, key: string): string | undefined {
  const value = source[key];
  return typeof value === 'string' && value !== '' ? value : undefined;
}

/**
 * Matches a Horizon payment record against the refund expectation.
 *
 * A record satisfies the audit when it is a payment (or create_account) to the
 * original sender, in the same asset, carrying the original deposit memo when
 * one was supplied.
 */
export function matchHorizonPayment(
  record: Record<string, unknown>,
  expectation: RefundExpectation,
): Omit<PaymentVerification, 'id' | 'found'> {
  const destination =
    stringField(record, 'to') ?? stringField(record, 'account') ?? stringField(record, 'funder');
  const assetCode =
    stringField(record, 'asset_code') ?? (record.asset_type === 'native' ? 'XLM' : undefined);
  const assetIssuer = stringField(record, 'asset_issuer');
  const memo = stringField(record, 'memo');
  const memoType = stringField(record, 'memo_type');

  const destinationOk = expectation.sender === undefined || destination === expectation.sender;
  const assetOk =
    expectation.assetCode === undefined ||
    (assetCode ?? 'XLM').toUpperCase() === expectation.assetCode.toUpperCase();
  const issuerOk = expectation.assetIssuer === undefined || assetIssuer === expectation.assetIssuer;
  const memoOk = expectation.memo === undefined || memo === expectation.memo;

  return {
    ...(destination === undefined ? {} : { destination }),
    ...(assetCode === undefined ? {} : { assetCode }),
    ...(assetIssuer === undefined ? {} : { assetIssuer }),
    ...(memo === undefined ? {} : { memo }),
    ...(memoType === undefined ? {} : { memoType }),
    matched: destinationOk && assetOk && issuerOk && memoOk,
  };
}

export class Sep24RefundAuditor {
  private readonly fetchImpl: typeof fetch;
  private readonly options: Sep24RefundOptions;

  constructor(fetchImpl: typeof fetch = fetch, options: Sep24RefundOptions = {}) {
    this.fetchImpl = fetchImpl;
    this.options = options;
  }

  async audit(doc: Record<string, unknown>): Promise<Sep24RefundResult> {
    const transferServer =
      this.options.transferServer ??
      (typeof doc.TRANSFER_SERVER_SEP0024 === 'string'
        ? doc.TRANSFER_SERVER_SEP0024
        : typeof doc.TRANSFER_SERVER === 'string'
          ? doc.TRANSFER_SERVER
          : undefined);
    const transactionId = this.options.transactionId;
    const horizonUrl = (this.options.horizonUrl ?? DEFAULT_HORIZON).replace(/\/+$/, '');

    const report: Sep24RefundReport = {
      transferServer: transferServer ?? '',
      transactionId: transactionId ?? '',
      horizonUrl,
      expectation: {},
      payments: [],
      findings: [],
      ok: false,
    };
    const diagnostics: Diagnostic[] = [];
    const add = (items: Diagnostic[]): void => {
      diagnostics.push(...items);
      for (const item of items) {
        report.findings.push({ code: item.rule, severity: item.severity, message: item.message });
      }
    };

    if (transferServer === undefined || transactionId === undefined || transactionId === '') {
      add(
        ruleDiagnostics(
          UNVERIFIABLE_RULE,
          'warning',
          'No SEP-24 transfer server or transaction id supplied, so refunds cannot be audited',
          'Pass --domain <domain> --tx-id <id> for an anchor that advertises a SEP-24 server.',
          this.options.rules,
        ),
      );
      return { report, diagnostics };
    }
    if (this.options.token === undefined || this.options.token.trim() === '') {
      add(
        ruleDiagnostics(
          UNVERIFIABLE_RULE,
          'warning',
          'No SEP-10 token supplied, so GET /transaction cannot be authorised',
          'Obtain a token from POST /auth and pass it with --sep10-token <jwt>.',
          this.options.rules,
        ),
      );
      return { report, diagnostics };
    }

    const url = new URL(`${transferServer.replace(/\/+$/, '')}/transaction`);
    url.searchParams.set('id', transactionId);
    let transaction: Record<string, unknown>;
    try {
      const response = await fetchWithTimeout(
        this.fetchImpl,
        url.toString(),
        {
          method: 'GET',
          headers: {
            accept: 'application/json',
            authorization: `Bearer ${this.options.token}`,
          },
        },
        this.options.timeoutMs ?? 8000,
      );
      if (!response.ok) {
        add(
          ruleDiagnostics(
            UNVERIFIABLE_RULE,
            'warning',
            `GET /transaction returned HTTP ${response.status}`,
            'Confirm the transaction id belongs to this anchor and the token is valid.',
            this.options.rules,
          ),
        );
        return { report, diagnostics };
      }
      const body: unknown = await response.json();
      let wrapped: unknown = body;
      if (isRecord(body) && 'transaction' in body) {
        if (!isRecord(body.transaction)) {
          add(
            ruleDiagnostics(
              UNVERIFIABLE_RULE,
              'warning',
              'GET /transaction response is not a transaction object',
              'Return the transaction as `{ "transaction": { ... } }`.',
              this.options.rules,
            ),
          );
          return { report, diagnostics };
        }
        wrapped = body.transaction;
      }
      if (!isRecord(wrapped)) {
        add(
          ruleDiagnostics(
            UNVERIFIABLE_RULE,
            'warning',
            'GET /transaction response is not a transaction object',
            'Return the transaction as `{ "transaction": { ... } }`.',
            this.options.rules,
          ),
        );
        return { report, diagnostics };
      }
      transaction = wrapped;
    } catch (error) {
      add(
        ruleDiagnostics(
          UNVERIFIABLE_RULE,
          'warning',
          `GET /transaction failed: ${error instanceof Error ? error.message : String(error)}`,
          'Confirm the SEP-24 server is reachable from the audit host.',
          this.options.rules,
        ),
      );
      return { report, diagnostics };
    }

    report.status = stringField(transaction, 'status');
    report.expectation = {
      ...(stringField(transaction, 'from') === undefined
        ? {}
        : { sender: stringField(transaction, 'from') }),
      ...(stringField(transaction, 'asset_code') === undefined
        ? {}
        : { assetCode: stringField(transaction, 'asset_code') }),
      ...(stringField(transaction, 'deposit_memo') === undefined
        ? {}
        : {
            memo: stringField(transaction, 'deposit_memo'),
            memoType: stringField(transaction, 'deposit_memo_type'),
          }),
    };

    const { record, issues } = parseRefundRecord(transaction.refunds);
    if (record !== undefined) report.refunds = record;
    for (const issue of issues) {
      add(
        ruleDiagnostics(
          issue.code,
          issue.code === MISSING_PAYMENT_RULE ? 'error' : 'error',
          issue.message,
          'Return amount_refunded, amount_fee and a non-empty payments array per SEP-24.',
          this.options.rules,
          'refunds',
        ),
      );
    }

    if (record !== undefined) {
      for (const payment of record.payments) {
        const findingsBefore = report.findings.length;
        const verification = await this.verifyPayment(payment, report.expectation);
        report.payments.push(verification);
        if (!verification.found) {
          add(
            ruleDiagnostics(
              TX_NOT_FOUND_RULE,
              'error',
              `Refund payment ${payment.id} was not found on Horizon`,
              'Return the hash of a transaction that actually landed on the network.',
              this.options.rules,
              'refunds.payments',
            ),
          );
          continue;
        }
        if (verification.successful === false) {
          add(
            ruleDiagnostics(
              TX_FAILED_RULE,
              'error',
              `Refund transaction ${payment.id} failed on-chain`,
              'Send a new refund payment; a failed transaction moves no funds.',
              this.options.rules,
              'refunds.payments',
            ),
          );
        }
        if (
          report.expectation.sender !== undefined &&
          verification.destination !== undefined &&
          verification.destination !== report.expectation.sender
        ) {
          add(
            ruleDiagnostics(
              DESTINATION_RULE,
              'error',
              `Refund ${payment.id} paid ${verification.destination}, not the original sender ${report.expectation.sender}`,
              'Send refunds to the account that funded the original transfer.',
              this.options.rules,
              'refunds.payments',
            ),
          );
        }
        if (
          report.expectation.assetCode !== undefined &&
          verification.assetCode !== undefined &&
          verification.assetCode.toUpperCase() !== report.expectation.assetCode.toUpperCase()
        ) {
          add(
            ruleDiagnostics(
              ASSET_RULE,
              'error',
              `Refund ${payment.id} paid ${verification.assetCode}, expected ${report.expectation.assetCode}`,
              'Refund the asset the user originally sent.',
              this.options.rules,
              'refunds.payments',
            ),
          );
        }
        if (
          report.expectation.memo !== undefined &&
          verification.memo !== undefined &&
          verification.memo !== report.expectation.memo
        ) {
          add(
            ruleDiagnostics(
              MEMO_RULE,
              'error',
              `Refund ${payment.id} memo does not match the original deposit memo`,
              'Carry the original deposit memo on the refund transaction.',
              this.options.rules,
              'refunds.payments',
            ),
          );
        }
        if (
          verification.successful !== false &&
          !verification.matched &&
          report.findings.length === findingsBefore
        ) {
          add(
            ruleDiagnostics(
              DESTINATION_RULE,
              'error',
              `Refund payment ${payment.id} does not pay the original sender in the original asset`,
              'Verify the on-chain payment destination, asset and memo against the deposit.',
              this.options.rules,
              'refunds.payments',
            ),
          );
        }
      }
    }

    report.ok = report.findings.length === 0;
    return { report, diagnostics };
  }

  private async verifyPayment(
    payment: RefundPayment,
    expectation: RefundExpectation,
  ): Promise<PaymentVerification> {
    const base = this.options.horizonUrl?.replace(/\/+$/, '') ?? DEFAULT_HORIZON;
    try {
      const txResponse = await fetchWithTimeout(
        this.fetchImpl,
        `${base}/transactions/${encodeURIComponent(payment.id)}`,
        { method: 'GET', headers: { accept: 'application/json' } },
        this.options.timeoutMs ?? 8000,
      );
      if (!txResponse.ok) return { id: payment.id, found: false, matched: false };
      const tx: unknown = await txResponse.json();
      if (!isRecord(tx)) return { id: payment.id, found: false, matched: false };

      const paymentsResponse = await fetchWithTimeout(
        this.fetchImpl,
        `${base}/transactions/${encodeURIComponent(payment.id)}/payments`,
        { method: 'GET', headers: { accept: 'application/json' } },
        this.options.timeoutMs ?? 8000,
      );
      let records: Record<string, unknown>[] = [];
      if (paymentsResponse.ok) {
        const body: unknown = await paymentsResponse.json();
        const embedded = isRecord(body) && isRecord(body._embedded) ? body._embedded : undefined;
        const list = embedded?.records;
        if (Array.isArray(list)) records = list.filter(isRecord);
      }

      const memo = stringField(tx, 'memo');
      const memoType = stringField(tx, 'memo_type');
      // The memo lives on the transaction envelope, not the payment record, so
      // fold it back in before judging a match.
      const withMemo = (entry: Record<string, unknown>): Record<string, unknown> =>
        entry.memo === undefined && memo !== undefined ? { ...entry, memo } : entry;
      const candidates = records.map(withMemo);
      const matched = candidates.find((entry) => matchHorizonPayment(entry, expectation).matched);
      // When nothing matches, expose the first record's fields so the caller can
      // name the dimension that differs instead of only saying "mismatch".
      const candidate = matched ?? candidates[0];
      const match =
        candidate === undefined ? { matched: false } : matchHorizonPayment(candidate, expectation);
      return {
        id: payment.id,
        found: true,
        successful: tx.successful === true,
        ...match,
        ...(match.memo === undefined && memo !== undefined ? { memo } : {}),
        ...(match.memoType === undefined && memoType !== undefined ? { memoType } : {}),
      };
    } catch {
      return { id: payment.id, found: false, matched: false };
    }
  }
}

export async function auditSep24Refunds(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: Sep24RefundOptions = {},
): Promise<Sep24RefundResult> {
  return new Sep24RefundAuditor(fetchImpl, options).audit(doc);
}

export function renderSep24RefundReport(report: Sep24RefundReport): string {
  const lines = [
    'SEP-24 refund lifecycle',
    `  transfer server: ${report.transferServer || 'not advertised'}`,
    `  transaction:     ${report.transactionId}`,
    `  status:          ${report.status ?? 'unknown'}`,
    `  horizon:         ${report.horizonUrl}`,
  ];
  if (report.refunds !== undefined) {
    lines.push(
      `  refunded:        ${report.refunds.amountRefunded ?? '?'} (fee ${report.refunds.amountFee ?? '?'})`,
    );
  } else {
    lines.push('  refunded:        none recorded');
  }
  for (const payment of report.payments) {
    const state = !payment.found ? 'not found' : payment.matched ? 'matched' : 'mismatched';
    lines.push(`  payment ${payment.id}: ${state}`);
  }
  lines.push(`  result:          ${report.ok ? 'PASS' : 'FAIL'}`);
  for (const finding of report.findings) {
    lines.push(`  [${finding.severity}] ${finding.code}: ${finding.message}`);
  }
  return `${lines.join('\n')}\n`;
}

export const sep24RefundRules: Rule[] = [
  {
    id: UNVERIFIABLE_RULE,
    category: CATEGORY,
    severity: 'warning',
    description: 'SEP-24 refunds could not be audited',
    run() {},
  },
  {
    id: SCHEMA_RULE,
    category: CATEGORY,
    severity: 'error',
    description: 'SEP-24 refunds must match the documented schema',
    run() {},
  },
  {
    id: FEE_EXCEEDS_RULE,
    category: CATEGORY,
    severity: 'error',
    description: 'Refund fee must not exceed the refunded amount',
    run() {},
  },
  {
    id: MISSING_PAYMENT_RULE,
    category: CATEGORY,
    severity: 'error',
    description: 'A refund must list at least one payment',
    run() {},
  },
  {
    id: TX_NOT_FOUND_RULE,
    category: CATEGORY,
    severity: 'error',
    description: 'Refund payment hashes must exist on Horizon',
    run() {},
  },
  {
    id: TX_FAILED_RULE,
    category: CATEGORY,
    severity: 'error',
    description: 'Refund transactions must have succeeded on-chain',
    run() {},
  },
  {
    id: DESTINATION_RULE,
    category: CATEGORY,
    severity: 'error',
    description: 'Refunds must pay the original sender',
    run() {},
  },
  {
    id: ASSET_RULE,
    category: CATEGORY,
    severity: 'error',
    description: 'Refunds must use the original asset',
    run() {},
  },
  {
    id: MEMO_RULE,
    category: CATEGORY,
    severity: 'error',
    description: 'Refunds must carry the original memo',
    run() {},
  },
];

export const sep24RefundRuleIds: readonly string[] = sep24RefundRules.map((rule) => rule.id);
