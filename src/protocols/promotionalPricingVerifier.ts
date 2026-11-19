/**
 * Anchor promotional pricing verifier.
 *
 * Runs under opt-in `--verify-promotions` (or `stellar-toml-lint
 * verify-promotions --domain <domain>`); quotes are only requested with
 * `--check-network`.
 *
 * Anchors advertise "0% fee" or "1% fees until 2026-12-31" in `stellar.toml`
 * descriptions. Wallets show those claims, so a SEP-38 quote that charges more
 * is a deceptive-pricing bug. This reads the claims, asks `ANCHOR_QUOTE_SERVER`
 * for indicative prices (`GET /price`, which needs no SEP-10 session, unlike
 * `/quote`) at test volumes, and compares using exact integer arithmetic.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isHttpsUrl, isString } from '../predicates.js';
import {
  errorMessage,
  feePercentUnits,
  fetchWithTimeout,
  isRecord,
  severityFor,
  toScaled,
} from './verifierSupport.js';

const MISMATCH_RULE = 'promotions/fee-mismatch';
const EXPIRED_RULE = 'promotions/expired-claim';
const UNVERIFIABLE_RULE = 'promotions/unverifiable-claim';

const SPEC =
  'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0038.md#get-price';

/** Percentage fee units are 1/10000 of a percent, e.g. 1.5% = 15000n. */
const PCT = 10000n;
/** Quotes may round; allow 0.01% before calling a claim deceptive. */
const TOLERANCE = 100n;

export interface PromoClaim {
  /** Where it was found, e.g. `CURRENCIES[0].desc`. */
  path: string;
  text: string;
  /** Advertised fee in percent units, `undefined` for unquantified "discounted" claims. */
  feePercent?: bigint;
  /** ISO date the promotion ends, if stated. */
  expires?: string;
  /** `CODE:ISSUER` when the claim sits on a currency entry. */
  asset?: string;
}

export interface PromotionalPricingOptions {
  rules?: RuleOverrides;
  /** Probe SEP-38 for actual fees. */
  checkQuotes?: boolean;
  /** Sell amounts to test. Defaults to 100 and 10000. */
  volumes?: string[];
  /** Overrides today's date, for tests. */
  now?: Date;
  timeoutMs?: number;
}

export interface PromotionalPricingResult {
  diagnostics: Diagnostic[];
  claims: PromoClaim[];
}

const ZERO_FEE =
  /\b(0(?:\.0+)?\s*%\s*(?:fees?|commission)|zero[- ]fees?|no[- ]fees?|fee[- ]free|free (?:transfers?|remittances?|withdrawals?|deposits?))\b/i;
const PERCENT_FEE = /\b(\d{1,2}(?:\.\d{1,4})?)\s*%\s*(?:flat\s+)?(?:fees?|commission)\b/i;
const DISCOUNT =
  /\b(discount(?:ed)?\s+(?:spread|fees?|rates?)|cash-?back|rebate|promo(?:tional)?\s+(?:pricing|rates?))\b/i;
const EXPIRY =
  /\b(?:until|through|ends?(?:\s+on)?|expires?(?:\s+on)?|valid\s+(?:until|through))\s+(\d{4}-\d{2}-\d{2})\b/i;

/** Extracts promotional pricing claims from free text. */
export function parsePromoClaim(
  path: string,
  text: string,
  asset?: string,
): PromoClaim | undefined {
  const base = { path, text, ...(asset !== undefined ? { asset } : {}) };
  const expires = EXPIRY.exec(text)?.[1];
  const withExpiry = expires !== undefined ? { ...base, expires } : base;
  if (ZERO_FEE.test(text)) return { ...withExpiry, feePercent: 0n };
  const pct = PERCENT_FEE.exec(text)?.[1];
  if (pct !== undefined) {
    const scaled = toScaled(pct);
    if (scaled !== undefined) return { ...withExpiry, feePercent: (scaled * PCT) / 10n ** 7n };
  }
  return DISCOUNT.test(text) ? withExpiry : undefined;
}

/** Collects claims from `[DOCUMENTATION]` and every currency description. */
export function collectPromoClaims(doc: Record<string, unknown>): PromoClaim[] {
  const claims: PromoClaim[] = [];
  const add = (c: PromoClaim | undefined): void => {
    if (c) claims.push(c);
  };
  const documentation = doc.DOCUMENTATION;
  if (isRecord(documentation)) {
    for (const [key, value] of Object.entries(documentation)) {
      if (isString(value)) add(parsePromoClaim(`DOCUMENTATION.${key}`, value));
    }
  }
  const currencies = doc.CURRENCIES;
  if (Array.isArray(currencies)) {
    currencies.forEach((c, i) => {
      if (!isRecord(c)) return;
      const asset = isString(c.code) && isString(c.issuer) ? `${c.code}:${c.issuer}` : undefined;
      for (const key of ['desc', 'conditions']) {
        const value = c[key];
        if (isString(value)) add(parsePromoClaim(`CURRENCIES[${i}].${key}`, value, asset));
      }
    });
  }
  return claims;
}

/** `10000n` -> `1%`, for messages. */
export function formatPercent(units: bigint): string {
  const whole = units / PCT;
  const frac = (units % PCT).toString().padStart(4, '0').replace(/0+$/, '');
  return `${whole}${frac ? `.${frac}` : ''}%`;
}

export class PromotionalPricingVerifier {
  constructor(
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly options: PromotionalPricingOptions = {},
  ) {}

  async verify(doc: Record<string, unknown>): Promise<PromotionalPricingResult> {
    const diagnostics: Diagnostic[] = [];
    const claims = collectPromoClaims(doc);
    const now = this.options.now ?? new Date();
    const push = (
      rule: string,
      fallback: 'error' | 'warning' | 'info',
      claim: PromoClaim,
      message: string,
      suggestion: string,
    ): void => {
      const severity = severityFor(rule, fallback, this.options.rules);
      if (severity === undefined) return;
      diagnostics.push({
        rule,
        severity,
        category: 'documentation',
        message,
        path: claim.path,
        helpUri: SPEC,
        suggestion,
      });
    };

    const server = doc.ANCHOR_QUOTE_SERVER;
    for (const claim of claims) {
      if (claim.expires !== undefined && new Date(`${claim.expires}T23:59:59Z`) < now) {
        push(
          EXPIRED_RULE,
          'warning',
          claim,
          `Promotional claim expired on ${claim.expires} but is still published`,
          'Remove the expired promotion from stellar.toml, or extend it if it still applies.',
        );
        continue;
      }
      if (claim.feePercent === undefined || !this.options.checkQuotes) continue;
      if (!isString(server) || !isHttpsUrl(server)) {
        push(
          UNVERIFIABLE_RULE,
          'info',
          claim,
          'Promotional fee claim cannot be checked without ANCHOR_QUOTE_SERVER',
          'Declare ANCHOR_QUOTE_SERVER so wallets can verify the advertised fee.',
        );
        continue;
      }
      await this.checkClaim(server.replace(/\/+$/, ''), claim, push);
    }
    return { diagnostics, claims };
  }

  private async checkClaim(
    base: string,
    claim: PromoClaim,
    push: (r: string, s: 'error' | 'warning' | 'info', c: PromoClaim, m: string, g: string) => void,
  ): Promise<void> {
    const claimed = claim.feePercent as bigint;
    try {
      const pair = await this.pickPair(base, claim.asset);
      if (pair === undefined) {
        push(
          UNVERIFIABLE_RULE,
          'info',
          claim,
          'Promotional fee claim has no SEP-38 asset pair to price',
          'List the promoted asset in the quote server /info response.',
        );
        return;
      }
      for (const amount of this.options.volumes ?? ['100', '10000']) {
        const q = new URLSearchParams({
          sell_asset: pair.sell,
          buy_asset: pair.buy,
          sell_amount: amount,
          context: 'sep31',
        });
        const res = await fetchWithTimeout(
          this.fetchImpl,
          `${base}/price?${q}`,
          {},
          this.options.timeoutMs,
        );
        const body: unknown = await res.json().catch(() => undefined);
        const fee = isRecord(body) && isRecord(body.fee) ? body.fee.total : undefined;
        const actual = isString(fee) ? feePercentUnits(fee, amount) : undefined;
        if (!res.ok || actual === undefined) {
          push(
            UNVERIFIABLE_RULE,
            'info',
            claim,
            `Quote for ${amount} ${pair.sell} returned no usable fee (HTTP ${res.status})`,
            'Return fee.total in SEP-38 /price responses.',
          );
          return;
        }
        if (actual > claimed + TOLERANCE) {
          push(
            MISMATCH_RULE,
            'error',
            claim,
            `Advertised ${formatPercent(claimed)} fee but the quote for ${amount} ${pair.sell} charges ${formatPercent(actual)}`,
            'Change the quote server pricing or correct the promotional text so the advertised fee is what users pay.',
          );
          return;
        }
      }
    } catch (error) {
      push(
        UNVERIFIABLE_RULE,
        'info',
        claim,
        `Promotional fee could not be verified (${errorMessage(error)})`,
        'Make sure ANCHOR_QUOTE_SERVER answers /info and /price.',
      );
    }
  }

  /** Sell the promoted asset (or the first listed one) for any other listed asset. */
  private async pickPair(
    base: string,
    asset?: string,
  ): Promise<{ sell: string; buy: string } | undefined> {
    const res = await fetchWithTimeout(this.fetchImpl, `${base}/info`, {}, this.options.timeoutMs);
    const body: unknown = await res.json().catch(() => undefined);
    const list = isRecord(body) && Array.isArray(body.assets) ? body.assets : [];
    const ids = list.flatMap((a) => (isRecord(a) && isString(a.asset) ? [a.asset] : []));
    const sell = ids.find((id) => asset !== undefined && id.endsWith(`:${asset}`)) ?? ids[0];
    const buy = ids.find((id) => id !== sell);
    return sell !== undefined && buy !== undefined ? { sell, buy } : undefined;
  }
}

export async function verifyPromotions(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: PromotionalPricingOptions = {},
): Promise<PromotionalPricingResult> {
  return new PromotionalPricingVerifier(fetchImpl, options).verify(doc);
}

const def = (id: string, severity: 'error' | 'warning' | 'info', description: string): Rule => ({
  id,
  category: 'documentation',
  severity,
  description,
  run() {},
});

export const promotionalPricingRules: Rule[] = [
  def(MISMATCH_RULE, 'error', 'Advertised promotional fees must match SEP-38 quote fees'),
  def(EXPIRED_RULE, 'warning', 'Expired promotional claims must be removed'),
  def(UNVERIFIABLE_RULE, 'info', 'Promotional fee claims should be verifiable through SEP-38'),
];

export const promotionalPricingRuleIds: readonly string[] = promotionalPricingRules.map(
  (r) => r.id,
);
