/**
 * Cross-SEP atomic quote execution and expiration verifier.
 *
 * Runs under opt-in --check-network --audit-quotes.
 *
 * An anchor that offers both SEP-38 and SEP-6 binds them by handing the
 * `quote_id` returned from `POST /quote` on `ANCHOR_QUOTE_SERVER` to
 * `GET /deposit` on `TRANSFER_SERVER`. The promise a firm quote makes is a
 * price and a fee schedule that survive until execution; an anchor that
 * re-prices the trade, drops the `quote_id`, or invents a `total_fee` that
 * disagrees with the quoted breakdown turns a quoted deposit into a payment
 * that fails at submission, days after the file was shipped.
 *
 * This auditor performs the binding once against the live endpoints: it books a
 * quote, executes it through SEP-6, and compares price, expiry, and fee totals.
 * It never touches the ledger, so the audit is read-only against the anchor's
 * own HTTP surface.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isString, isUrl } from '../predicates.js';

const MISMATCHED_FEE_RULE = 'quotes/mismatched-quote-fee';
const BINDING_UNSUPPORTED_RULE = 'quotes/quote-binding-unsupported';

const QUOTE_SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0038.md';
const TRANSFER_SPEC =
  'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0006.md';

/** Account the audit authenticates as; a valid key, but nothing is submitted. */
const AUDIT_ACCOUNT = 'GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY';

/** Quote amount asked for when the file gives no reason to prefer another. */
const AUDIT_SELL_AMOUNT = '100.00';

/** Fiat leg the quote is priced against; SEP-38 pairs are mostly fiat. */
const AUDIT_BUY_ASSET = 'iso4217:USD';

interface AuditOptions {
  rules?: RuleOverrides;
  /**
   * SEP-10 JWT presented to `TRANSFER_SERVER`. `/deposit` requires one, so an
   * audit without a token only reports what an unauthenticated call can see.
   */
  token?: string;
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

function finding(
  rule: string,
  fallback: 'error' | 'warning',
  message: string,
  path: string,
  helpUri: string,
  suggestion: string,
  rules: RuleOverrides | undefined,
): Diagnostic[] {
  const severity = severityFor(rule, fallback, rules);
  if (severity === undefined) return [];
  return [{ rule, severity, category: 'network', message, path, helpUri, suggestion }];
}

/** Numeric value of a SEP-38/SEP-6 amount string, or `undefined` if unusable. */
function amountOf(value: unknown): number | undefined {
  if (typeof value === 'number') return Number.isFinite(value) ? value : undefined;
  if (typeof value !== 'string') return undefined;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

/** Two money amounts agree when they differ by less than one stroop. */
function sameAmount(left: number, right: number): boolean {
  return Math.abs(left - right) < 0.0000001;
}

/**
 * The `[[CURRENCIES]]` asset the audit sells: the first classic asset with an
 * issuer, since SEP-38 firm quotes pair classic assets against fiat. Pointer
 * entries are skipped — their definition lives in a file this audit does not
 * fetch — and `code` is what SEP-6 `asset_code` expects.
 */
function sellCurrencyOf(
  doc: Record<string, unknown>,
): { code: string; issuer: string } | undefined {
  const currencies = doc.CURRENCIES;
  if (!Array.isArray(currencies)) return undefined;
  for (const entry of currencies) {
    if (!isRecord(entry) || entry.toml !== undefined) continue;
    if (isString(entry.code) && isString(entry.issuer)) {
      return { code: entry.code, issuer: entry.issuer };
    }
  }
  return undefined;
}

/** Sum of the `fees` array a SEP-38 quote declares, in the quoted asset. */
function quotedFeeTotal(quote: Record<string, unknown>): number | undefined {
  if (!Array.isArray(quote.fees)) return undefined;
  let total = 0;
  for (const fee of quote.fees) {
    if (!isRecord(fee)) return undefined;
    const amount = amountOf(fee.amount);
    if (amount === undefined) return undefined;
    total += amount;
  }
  return total;
}

/**
 * The `total_fee` a SEP-6 deposit response charges for the bound quote.
 *
 * SEP-6 keys this `total_fee` in `/deposit` responses that carry a quote; a
 * plain `fee` is accepted for anchors that report the breakdown per line item.
 */
function chargedFeeTotal(body: Record<string, unknown>): number | undefined {
  const direct = amountOf(body.total_fee);
  if (direct !== undefined) return direct;
  if (!Array.isArray(body.fees)) return undefined;
  let total = 0;
  for (const fee of body.fees) {
    if (!isRecord(fee)) return undefined;
    const amount = amountOf(fee.total ?? fee.amount);
    if (amount === undefined) return undefined;
    total += amount;
  }
  return total;
}

/** Book a firm quote on `ANCHOR_QUOTE_SERVER`; `undefined` when it cannot be booked. */
async function requestQuote(
  base: string,
  sellAsset: string,
  fetchImpl: typeof fetch,
): Promise<Record<string, unknown> | undefined> {
  try {
    const response = await fetchImpl(`${base}/quote`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        sell_asset: sellAsset,
        buy_asset: AUDIT_BUY_ASSET,
        sell_amount: AUDIT_SELL_AMOUNT,
      }),
    });
    if (!response.ok) return undefined;
    const body = await response.json();
    return isRecord(body) ? body : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Executes a booked quote through SEP-6 `GET /deposit` with its `quote_id`.
 *
 * The outcome is told apart by *why* the endpoint refused: a refusal naming the
 * quote means the anchor advertises both servers but will not bind them, while
 * any other non-200 is a SEP-6 problem the quote audit has no business
 * reporting. `undefined` means the endpoint could not be reached at all.
 */
async function executeDeposit(
  base: string,
  assetCode: string,
  quoteId: string,
  fetchImpl: typeof fetch,
  token?: string,
): Promise<{ status: number; body?: Record<string, unknown>; rejectsQuote: boolean } | undefined> {
  const params = new URLSearchParams({ asset_code: assetCode, account: AUDIT_ACCOUNT });
  params.set('quote_id', quoteId);
  try {
    const response = await fetchImpl(`${base}/deposit?${params.toString()}`, {
      ...(token === undefined ? {} : { headers: { authorization: `Bearer ${token}` } }),
    });
    if (response.ok) {
      const body = await response.json().catch(() => undefined);
      return { status: response.status, ...(isRecord(body) ? { body } : {}), rejectsQuote: false };
    }
    const text = await response.text().catch(() => '');
    return {
      status: response.status,
      rejectsQuote: /quote/i.test(text),
    };
  } catch {
    return undefined;
  }
}

/**
 * Books a firm quote on `ANCHOR_QUOTE_SERVER` and executes it on
 * `TRANSFER_SERVER`, then asserts the price and fee schedule survive the trip.
 *
 * Silent when the file declares neither endpoint as a usable URL, when it
 * declares no classic asset to sell, or when either endpoint cannot be reached
 * — reachability belongs to `sep38/*` and `network/sep6-*`.
 */
export async function auditQuoteBinding(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: AuditOptions = {},
): Promise<Diagnostic[]> {
  const quoteServer = doc.ANCHOR_QUOTE_SERVER;
  const transferServer = doc.TRANSFER_SERVER;
  if (!isString(quoteServer) || !isUrl(quoteServer)) return [];
  if (!isString(transferServer) || !isUrl(transferServer)) return [];

  const currency = sellCurrencyOf(doc);
  if (currency === undefined) return [];

  const sellAsset = `stellar:${currency.code}:${currency.issuer}`;
  const quote = await requestQuote(quoteServer.replace(/\/+$/, ''), sellAsset, fetchImpl);
  if (quote === undefined) return [];

  const quoteId = quote.id;
  if (!isString(quoteId) || quoteId.length === 0) return [];

  const deposit = await executeDeposit(
    transferServer.replace(/\/+$/, ''),
    currency.code,
    quoteId,
    fetchImpl,
    options.token,
  );
  if (deposit === undefined) return [];

  if (deposit.body === undefined) {
    if (deposit.rejectsQuote) {
      return finding(
        BINDING_UNSUPPORTED_RULE,
        'warning',
        `TRANSFER_SERVER /deposit rejected the quote_id "${quoteId}" booked on ANCHOR_QUOTE_SERVER with HTTP ${deposit.status}`,
        'TRANSFER_SERVER',
        TRANSFER_SPEC,
        'SEP-6 accepts quote_id on /deposit and /withdraw; execute the firm quote issued by the anchor SEP-38 server',
        options.rules,
      );
    }
    return [];
  }

  const diagnostics: Diagnostic[] = [];

  // Expiration atomicity: a quote must stay executable until its own expiry,
  // so a deposit that reports an earlier deadline is not the trade that was
  // priced.
  const quotedExpiry = Date.parse(String(quote.expire_after ?? ''));
  const executedExpiry = Date.parse(String(deposit.body.expires_at ?? ''));
  if (
    Number.isFinite(quotedExpiry) &&
    Number.isFinite(executedExpiry) &&
    executedExpiry < quotedExpiry
  ) {
    diagnostics.push(
      ...finding(
        MISMATCHED_FEE_RULE,
        'error',
        `SEP-6 /deposit executes quote "${quoteId}" with expiry ${new Date(executedExpiry).toISOString()}, earlier than the quoted ${new Date(quotedExpiry).toISOString()}`,
        'TRANSFER_SERVER',
        QUOTE_SPEC,
        'Bind the deposit to the SEP-38 quote expiry so the price holds for the window that was quoted',
        options.rules,
      ),
    );
  }

  const quotedPrice = amountOf(quote.price);
  const executedPrice = amountOf(deposit.body.price ?? deposit.body.quote_price);
  if (
    quotedPrice !== undefined &&
    executedPrice !== undefined &&
    !sameAmount(quotedPrice, executedPrice)
  ) {
    diagnostics.push(
      ...finding(
        MISMATCHED_FEE_RULE,
        'error',
        `SEP-6 /deposit prices quote "${quoteId}" at ${executedPrice} instead of the quoted ${quotedPrice}`,
        'TRANSFER_SERVER',
        QUOTE_SPEC,
        'A firm SEP-38 quote must execute at its quoted price; re-pricing at /deposit breaks the guarantee wallets rely on',
        options.rules,
      ),
    );
  }

  const declaredFees = quotedFeeTotal(quote);
  const chargedFees = chargedFeeTotal(deposit.body);
  if (
    declaredFees !== undefined &&
    chargedFees !== undefined &&
    !sameAmount(declaredFees, chargedFees)
  ) {
    diagnostics.push(
      ...finding(
        MISMATCHED_FEE_RULE,
        'error',
        `SEP-6 /deposit charges a total_fee of ${chargedFees} for quote "${quoteId}", but SEP-38 declared ${declaredFees}`,
        'TRANSFER_SERVER',
        QUOTE_SPEC,
        'Report the same fee breakdown the quote declared, so the amount the wallet quoted is the amount that settles',
        options.rules,
      ),
    );
  }

  return diagnostics;
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const quoteBindingRules: Rule[] = [
  {
    id: MISMATCHED_FEE_RULE,
    category: 'network',
    severity: 'error',
    description: 'SEP-6 must execute a SEP-38 quote at its quoted price, fees, and expiry',
    run() {},
  },
  {
    id: BINDING_UNSUPPORTED_RULE,
    category: 'network',
    severity: 'warning',
    description: 'An anchor declaring SEP-38 and SEP-6 should accept quote_id on /deposit',
    run() {},
  },
];

/** Rule ids emitted by {@link auditQuoteBinding}. */
export const quoteBindingRuleIds: readonly string[] = quoteBindingRules.map((rule) => rule.id);
