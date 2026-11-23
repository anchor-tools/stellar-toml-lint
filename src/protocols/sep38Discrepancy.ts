/**
 * SEP-38 indicative vs firm quote discrepancy auditor.
 *
 * Runs under opt-in `--audit-sep38-spreads` (or `stellar-toml-lint
 * sep38-spreads --domain <domain>`).
 *
 * SEP-38 exposes two different promises. `GET /prices` is indicative: a
 * non-binding estimate that wallets show before the user commits. `POST /quote`
 * is firm: a price locked until `expires_at`, which the anchor must execute.
 * The gap between the two is where an anchor can quietly widen its spread
 * between the number the user saw and the number they signed.
 *
 * This auditor prices the same trade at small, medium and large volumes through
 * both endpoints, converts the buy/sell amounts into an effective rate, and
 * compares the firm rate against the indicative one with exact integer
 * arithmetic. It also checks that the firm quote's fee is covered by the fee the
 * file discloses, that every quote carries a usable expiry, and — when the
 * anchor also declares `TRANSFER_SERVER` — that an expired quote is refused
 * rather than accepted.
 *
 * The audit is read-only against the anchor's own HTTP surface: it books quotes
 * but never submits a transfer or touches the ledger.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isHttpsUrl, isString } from '../predicates.js';
import { fetchWithTimeout, isRecord, severityFor } from './verifierSupport.js';
import { collectPromoClaims } from './promotionalPricingVerifier.js';
import { pickPair, type Sep38Pair } from './sep38CircuitBreaker.js';

const SPREAD_RULE = 'sep38/spread-exceeds-tolerance';
const FEE_RULE = 'sep38/fee-exceeds-disclosure';
const EXPIRY_MISSING_RULE = 'sep38/quote-expiry-missing';
const EXPIRED_RULE = 'sep38/firm-quote-expired';
const LIFETIME_RULE = 'sep38/quote-lifetime-exceeds-limit';
const EXPIRED_ACCEPTED_RULE = 'sep38/expired-quote-accepted';
const UNVERIFIABLE_RULE = 'sep38/quote-audit-unverifiable';

const SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0038.md';

/** Account the expiry probe executes as; a valid key, but nothing is submitted. */
const AUDIT_ACCOUNT = 'GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY';

/** Default allowance between the indicative and firm rate, in basis points. */
export const DEFAULT_SPREAD_TOLERANCE_BPS = 50n;

/** A quote advertised beyond this is too long to be a firm promise worth trusting. */
export const DEFAULT_MAX_QUOTE_LIFETIME_SECONDS = 300;

/** Decimal digits kept for rates. Stellar amounts have 7; prices can be finer. */
export const RATE_SCALE = 12;

/** How long the expiry probe is willing to wait for a quote to lapse. */
const DEFAULT_MAX_EXPIRY_WAIT_MS = 2000;

/** One trade size the audit prices through both endpoints. */
export interface QuoteTier {
  label: string;
  sellAmount: string;
}

/** Small, medium and large volumes, so a tiered spread table cannot hide. */
export const DEFAULT_QUOTE_TIERS: readonly QuoteTier[] = [
  { label: 'small', sellAmount: '10' },
  { label: 'medium', sellAmount: '1000' },
  { label: 'large', sellAmount: '100000' },
];

export interface MonotonicWallClock {
  /** Wall-clock epoch milliseconds. Tests inject a deterministic clock. */
  wallNow(): number;
}

export const systemWallClock: MonotonicWallClock = { wallNow: () => Date.now() };

/** Default pause for the expiry probe; tests inject an instant sleep instead. */
export const systemSleep = (ms: number): Promise<unknown> =>
  new Promise((resolve) => setTimeout(resolve, ms));

export interface Sep38QuoteDiscrepancyOptions {
  rules?: RuleOverrides;
  /** Quote server base; defaults to `ANCHOR_QUOTE_SERVER`. */
  quoteServer?: string;
  sellAsset?: string;
  buyAsset?: string;
  /** Trade sizes to price. Defaults to {@link DEFAULT_QUOTE_TIERS}. */
  tiers?: readonly QuoteTier[];
  /** Allowed indicative-to-firm gap, in basis points. Defaults to 50n. */
  toleranceBps?: bigint;
  /** Longest plausible firm-quote lifetime. Defaults to 300s. */
  maxQuoteLifetimeSeconds?: number;
  /** Transfer server used to prove expired quotes are refused. */
  transferServer?: string;
  /** Ask the transfer server to execute an expired quote. Defaults to true. */
  probeExpiredExecution?: boolean;
  /** Longest wait for a quote to lapse before the probe is skipped. */
  maxExpiryWaitMs?: number;
  timeoutMs?: number;
  clock?: MonotonicWallClock;
  sleep?: (ms: number) => Promise<unknown>;
  /** SEP-10 token, when the transfer server requires one to answer at all. */
  token?: string;
}

/** What both endpoints said about one trade size. */
export interface QuoteTierObservation {
  tier: string;
  sellAmount: string;
  /** Price from `GET /prices`, as advertised. */
  indicativePrice?: string;
  /** `buy_amount / sell_amount` from the firm quote. */
  firmRate?: string;
  /** Gap between the firm and indicative rate, in basis points. */
  spreadBps?: bigint;
  /** The firm quote's own fee as a percentage of the sell amount, in bps. */
  declaredFeeBps?: bigint;
  quoteId?: string;
  expiresAt?: string;
  lifetimeSeconds?: number;
}

export interface Sep38DiscrepancyResult {
  diagnostics: Diagnostic[];
  observations: QuoteTierObservation[];
  summary: string;
}

/** A decimal string, read exactly into an integer of `10^-scale` units. */
export function parseScaledDecimal(value: unknown, scale = RATE_SCALE): bigint | undefined {
  const text =
    typeof value === 'number'
      ? Number.isFinite(value)
        ? String(value)
        : undefined
      : isString(value)
        ? value.trim()
        : undefined;
  if (text === undefined) return undefined;
  const match = /^(\d+)(?:\.(\d+))?$/.exec(text);
  if (match === null) return undefined;
  const fraction = (match[2] ?? '').slice(0, scale).padEnd(scale, '0');
  return BigInt(match[1] as string) * 10n ** BigInt(scale) + BigInt(fraction);
}

/** Renders a scaled integer back as a plain decimal string. */
export function formatScaledDecimal(value: bigint, scale = RATE_SCALE): string {
  const negative = value < 0n;
  const magnitude = negative ? -value : value;
  const unit = 10n ** BigInt(scale);
  const fraction = (magnitude % unit).toString().padStart(scale, '0').replace(/0+$/, '');
  return `${negative ? '-' : ''}${magnitude / unit}${fraction === '' ? '' : `.${fraction}`}`;
}

/**
 * `|firmRate - indicativePrice| / indicativePrice` in basis points.
 *
 * Computed by cross-multiplying the scaled integers, so no division happens
 * until the final integer step and no floating-point rounding can shrink a
 * hidden spread below the tolerance.
 */
export function rateSpreadBps(
  buyAmount: string,
  sellAmount: string,
  indicativePrice: string,
  scale = RATE_SCALE,
): bigint | undefined {
  const buy = parseScaledDecimal(buyAmount, scale);
  const sell = parseScaledDecimal(sellAmount, scale);
  const price = parseScaledDecimal(indicativePrice, scale);
  if (buy === undefined || sell === undefined || price === undefined) return undefined;
  const reference = price * sell;
  if (reference === 0n) return undefined;
  const difference = buy * 10n ** BigInt(scale) - price * sell;
  const magnitude = difference < 0n ? -difference : difference;
  return (magnitude * 10000n) / reference;
}

/** `fee / amount` in basis points, using the same exact-integer arithmetic. */
export function feeBps(
  feeAmount: string,
  sellAmount: string,
  scale = RATE_SCALE,
): bigint | undefined {
  const fee = parseScaledDecimal(feeAmount, scale);
  const sell = parseScaledDecimal(sellAmount, scale);
  if (fee === undefined || sell === undefined || sell === 0n) return undefined;
  return (fee * 10000n) / sell;
}

/**
 * The highest fee the file itself discloses, in basis points.
 *
 * Promotional text such as "1% fees" is a public promise; the firm quote's own
 * fee has to fit inside it. Claims without a number ("discounted") do not
 * disclose a bound and are ignored here.
 */
export function advertisedFeeBps(doc: Record<string, unknown>): bigint | undefined {
  let highest: bigint | undefined;
  for (const claim of collectPromoClaims(doc)) {
    if (claim.feePercent === undefined) continue;
    // A percent is 100 basis points; claim units are 1/10000 of a percent.
    const bps = claim.feePercent / 100n;
    if (highest === undefined || bps > highest) highest = bps;
  }
  return highest;
}

/** The `price` for `buyAsset` from a SEP-38 `GET /prices` body, kept as text. */
export function indicativePriceFrom(body: unknown, buyAsset: string): string | undefined {
  if (!isRecord(body) || !Array.isArray(body.buy_assets)) return undefined;
  for (const entry of body.buy_assets) {
    if (!isRecord(entry) || entry.asset !== buyAsset) continue;
    if (isString(entry.price)) return entry.price;
    if (typeof entry.price === 'number' && Number.isFinite(entry.price)) {
      return String(entry.price);
    }
  }
  return undefined;
}

/** Sum of the `fees` array a firm quote declares, as an exact scaled integer. */
function sumDeclaredFees(fees: readonly unknown[]): bigint {
  let total = 0n;
  for (const fee of fees) {
    if (!isRecord(fee)) continue;
    const amount = parseScaledDecimal(fee.amount);
    if (amount !== undefined) total += amount;
  }
  return total;
}

/** The firm quote's fee total as decimal text, from `fee.total` or `fees`. */
export function quoteFeeTotal(quote: Record<string, unknown>): string | undefined {
  const fee = quote.fee;
  if (isRecord(fee)) {
    if (isString(fee.total)) return fee.total;
    if (typeof fee.total === 'number' && Number.isFinite(fee.total)) return String(fee.total);
  }
  if (Array.isArray(quote.fees)) {
    return formatScaledDecimal(sumDeclaredFees(quote.fees));
  }
  return undefined;
}

function formatBps(bps: bigint): string {
  return `${bps} bps`;
}

/** Reason the expiry probe reached, so the caller can decide what to report. */
export type ExpiredQuoteVerdict = 'accepted' | 'rejected' | 'unknown';

export class Sep38QuoteDiscrepancyAuditor {
  constructor(
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly options: Sep38QuoteDiscrepancyOptions = {},
  ) {}

  async audit(doc: Record<string, unknown>): Promise<Sep38DiscrepancyResult> {
    const server = this.options.quoteServer ?? doc.ANCHOR_QUOTE_SERVER;
    if (!isString(server) || !isHttpsUrl(server)) {
      return {
        diagnostics: [],
        observations: [],
        summary: 'No usable ANCHOR_QUOTE_SERVER to probe.',
      };
    }

    const base = server.replace(/\/+$/, '');
    const pair = await this.resolvePair(base);
    if (pair === undefined) {
      return {
        diagnostics: this.finding(
          UNVERIFIABLE_RULE,
          'info',
          'ANCHOR_QUOTE_SERVER exposes fewer than two assets, so no SEP-38 pair can be priced',
          'Advertise at least one quotable pair in /info so indicative and firm prices can be compared.',
        ),
        observations: [],
        summary: 'No quotable pair advertised.',
      };
    }

    const clock = this.options.clock ?? systemWallClock;
    const tolerance = this.options.toleranceBps ?? DEFAULT_SPREAD_TOLERANCE_BPS;
    const maxLifetime = this.options.maxQuoteLifetimeSeconds ?? DEFAULT_MAX_QUOTE_LIFETIME_SECONDS;
    const disclosedFee = advertisedFeeBps(doc);
    const tiers = this.options.tiers ?? DEFAULT_QUOTE_TIERS;
    const diagnostics: Diagnostic[] = [];
    const observations: QuoteTierObservation[] = [];
    const quotedAt = clock.wallNow();
    let answered = 0;
    let worstSpread: bigint | undefined;

    for (const tier of tiers) {
      const indicative = await this.readIndicative(base, pair, tier.sellAmount);
      const quote = await this.readQuote(base, pair, tier.sellAmount);
      if (indicative !== undefined) answered++;

      const observation: QuoteTierObservation = {
        tier: tier.label,
        sellAmount: tier.sellAmount,
        ...(indicative === undefined ? {} : { indicativePrice: indicative }),
      };

      if (quote === undefined) {
        observations.push(observation);
        continue;
      }
      answered++;

      const sellAmount = isString(quote.sell_amount) ? quote.sell_amount : tier.sellAmount;
      const buyAmount = isString(quote.buy_amount) ? quote.buy_amount : undefined;

      if (buyAmount !== undefined && indicative !== undefined) {
        const spread = rateSpreadBps(buyAmount, sellAmount, indicative);
        if (spread !== undefined) {
          observation.spreadBps = spread;
          const buy = parseScaledDecimal(buyAmount);
          const sell = parseScaledDecimal(sellAmount);
          if (buy !== undefined && sell !== undefined && sell !== 0n) {
            observation.firmRate = formatScaledDecimal((buy * 10n ** BigInt(RATE_SCALE)) / sell);
          }
          if (worstSpread === undefined || spread > worstSpread) worstSpread = spread;
          const allowance = tolerance + (disclosedFee ?? 0n);
          if (spread > allowance) {
            diagnostics.push(
              ...this.finding(
                SPREAD_RULE,
                'error',
                `Firm quote for the ${tier.label} tier (${sellAmount} ${pair.sell}) prices at ${observation.firmRate} against an indicative ${indicative}, a ${formatBps(spread)} spread beyond the ${formatBps(allowance)} allowance`,
                `Quote ${sellAmount} at the same rate as GET /prices, or narrow the spread to the ${formatBps(tolerance)} tolerance before advertising it as indicative.`,
              ),
            );
          }
        }
      }

      const feeTotal = quoteFeeTotal(quote);
      if (feeTotal !== undefined) {
        const declared = feeBps(feeTotal, sellAmount);
        if (declared !== undefined) {
          observation.declaredFeeBps = declared;
          if (disclosedFee !== undefined && declared > disclosedFee + tolerance) {
            diagnostics.push(
              ...this.finding(
                FEE_RULE,
                'error',
                `Firm quote for the ${tier.label} tier charges ${formatBps(declared)} in fees, above the ${formatBps(disclosedFee)} disclosed in stellar.toml`,
                'Charge the fee the file discloses, or update the disclosure so the quoted price and the published fee agree.',
              ),
            );
          }
        }
      }

      if (isString(quote.id)) observation.quoteId = quote.id;

      const expiresAtRaw = isString(quote.expires_at)
        ? quote.expires_at
        : isString(quote.expire_after)
          ? quote.expire_after
          : undefined;
      if (expiresAtRaw === undefined) {
        diagnostics.push(
          ...this.finding(
            EXPIRY_MISSING_RULE,
            'error',
            `Firm quote for the ${tier.label} tier carries no expires_at`,
            'Always return expires_at on POST /quote; an unbounded quote cannot be proven to be firm or safely rejected after the fact.',
          ),
        );
      } else {
        observation.expiresAt = expiresAtRaw;
        const expiresAt = Date.parse(expiresAtRaw);
        if (!Number.isFinite(expiresAt)) {
          diagnostics.push(
            ...this.finding(
              EXPIRY_MISSING_RULE,
              'error',
              `Firm quote for the ${tier.label} tier has an unparseable expires_at "${expiresAtRaw}"`,
              'Return expires_at as an ISO-8601 timestamp so wallets and this audit can enforce the quote window.',
            ),
          );
        } else {
          const lifetimeSeconds = (expiresAt - quotedAt) / 1000;
          observation.lifetimeSeconds = lifetimeSeconds;
          if (expiresAt <= quotedAt) {
            diagnostics.push(
              ...this.finding(
                EXPIRED_RULE,
                'error',
                `POST /quote returned a ${tier.label}-tier quote that was already expired at ${expiresAtRaw}`,
                'Issue quotes whose expires_at is in the future; a quote that is born expired cannot be executed as quoted.',
              ),
            );
          } else if (lifetimeSeconds > maxLifetime) {
            diagnostics.push(
              ...this.finding(
                LIFETIME_RULE,
                'warning',
                `Firm quote for the ${tier.label} tier lives ${lifetimeSeconds.toFixed(1)}s, beyond the ${maxLifetime}s limit`,
                `Cap expires_at at ${maxLifetime}s so a stale rate cannot be executed long after it was priced.`,
              ),
            );
          }
        }
      }

      observations.push(observation);
    }

    if (answered === 0) {
      return {
        diagnostics: [
          ...diagnostics,
          ...this.finding(
            UNVERIFIABLE_RULE,
            'info',
            `ANCHOR_QUOTE_SERVER ${base} answered no usable /prices or /quote for ${pair.sell} -> ${pair.buy}`,
            'Return SEP-38 /prices and /quote responses so wallets can compare indicative and firm pricing.',
          ),
        ],
        observations,
        summary: `No quote could be priced for ${pair.sell} -> ${pair.buy}.`,
      };
    }

    if (this.options.probeExpiredExecution !== false) {
      diagnostics.push(...(await this.probeExpiredQuote(doc, pair, observations, clock)));
    }

    return {
      diagnostics,
      observations,
      summary: `${observations.length} tiers priced for ${pair.sell} -> ${pair.buy}; worst spread ${
        worstSpread === undefined ? 'unmeasured' : formatBps(worstSpread)
      }.`,
    };
  }

  /**
   * Executes an expired quote through SEP-6 `GET /deposit` and expects a
   * refusal. Nothing is submitted: a 2xx here means the anchor accepted terms
   * it had already invalidated.
   *
   * The probe is skipped when no quote carries a usable future expiry, when the
   * quote outlives `maxExpiryWaitMs`, and when no `TRANSFER_SERVER` is known —
   * silently, because those are not failures of the anchor.
   */
  private async probeExpiredQuote(
    doc: Record<string, unknown>,
    pair: Sep38Pair,
    observations: readonly QuoteTierObservation[],
    clock: MonotonicWallClock,
  ): Promise<Diagnostic[]> {
    const transferServer = this.options.transferServer ?? doc.TRANSFER_SERVER;
    if (!isString(transferServer) || !isHttpsUrl(transferServer)) return [];

    const candidate = observations.find(
      (observation) =>
        observation.quoteId !== undefined &&
        observation.expiresAt !== undefined &&
        Date.parse(observation.expiresAt) > clock.wallNow(),
    );
    if (candidate === undefined || candidate.expiresAt === undefined) return [];

    const expiresAt = Date.parse(candidate.expiresAt);
    const maxWait = this.options.maxExpiryWaitMs ?? DEFAULT_MAX_EXPIRY_WAIT_MS;
    const waitMs = expiresAt - clock.wallNow();
    if (!Number.isFinite(expiresAt) || waitMs > maxWait) return [];

    const sleep = this.options.sleep ?? systemSleep;
    if (waitMs > 0) await sleep(waitMs + 1);

    const verdict = await this.executeExpiredQuote(
      transferServer.replace(/\/+$/, ''),
      pair,
      candidate,
    );
    if (verdict !== 'accepted') return [];
    return this.finding(
      EXPIRED_ACCEPTED_RULE,
      'error',
      `TRANSFER_SERVER accepted expired quote "${candidate.quoteId}" for ${pair.sell} after ${candidate.expiresAt}`,
      'Reject quote_id values whose expires_at has passed; an expired quote must not be executable or co-signable.',
    );
  }

  private async executeExpiredQuote(
    transferServer: string,
    pair: Sep38Pair,
    observation: QuoteTierObservation,
  ): Promise<ExpiredQuoteVerdict> {
    const assetCode = pair.sell.split(':')[1] ?? '';
    const params = new URLSearchParams({
      asset_code: assetCode,
      account: AUDIT_ACCOUNT,
      quote_id: observation.quoteId as string,
    });
    try {
      const response = await fetchWithTimeout(
        this.fetchImpl,
        `${transferServer}/deposit?${params.toString()}`,
        this.options.token === undefined
          ? {}
          : { headers: { authorization: `Bearer ${this.options.token}` } },
        this.options.timeoutMs,
      );
      return response.ok ? 'accepted' : 'rejected';
    } catch {
      return 'unknown';
    }
  }

  private async resolvePair(base: string): Promise<Sep38Pair | undefined> {
    if (this.options.sellAsset !== undefined) {
      return pickPair([], this.options.sellAsset, this.options.buyAsset);
    }
    try {
      const response = await fetchWithTimeout(
        this.fetchImpl,
        `${base}/info`,
        {},
        this.options.timeoutMs,
      );
      if (!response.ok) return undefined;
      const body: unknown = await response.json().catch(() => undefined);
      const assets = isRecord(body) && Array.isArray(body.assets) ? body.assets : [];
      return pickPair(assets);
    } catch {
      return undefined;
    }
  }

  private async readIndicative(
    base: string,
    pair: Sep38Pair,
    sellAmount: string,
  ): Promise<string | undefined> {
    const params = new URLSearchParams({
      sell_asset: pair.sell,
      buy_asset: pair.buy,
      sell_amount: sellAmount,
    });
    try {
      const response = await fetchWithTimeout(
        this.fetchImpl,
        `${base}/prices?${params.toString()}`,
        {},
        this.options.timeoutMs,
      );
      if (!response.ok) return undefined;
      const body: unknown = await response.json().catch(() => undefined);
      return indicativePriceFrom(body, pair.buy);
    } catch {
      return undefined;
    }
  }

  private async readQuote(
    base: string,
    pair: Sep38Pair,
    sellAmount: string,
  ): Promise<Record<string, unknown> | undefined> {
    try {
      const response = await fetchWithTimeout(
        this.fetchImpl,
        `${base}/quote`,
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            sell_asset: pair.sell,
            buy_asset: pair.buy,
            sell_amount: sellAmount,
            context: 'sep38',
          }),
        },
        this.options.timeoutMs,
      );
      if (!response.ok) return undefined;
      const body: unknown = await response.json().catch(() => undefined);
      return isRecord(body) ? body : undefined;
    } catch {
      return undefined;
    }
  }

  /** Severity-aware diagnostic builder, honouring `--off`/`--warn`/`--error`. */
  private finding(
    rule: string,
    fallback: 'error' | 'warning' | 'info',
    message: string,
    suggestion: string,
  ): Diagnostic[] {
    const severity = severityFor(rule, fallback, this.options.rules);
    if (severity === undefined) return [];
    return [
      {
        rule,
        severity,
        category: 'network',
        message,
        path: 'ANCHOR_QUOTE_SERVER',
        helpUri: SPEC,
        suggestion,
      },
    ];
  }
}

export async function auditSep38QuoteDiscrepancies(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: Sep38QuoteDiscrepancyOptions = {},
): Promise<Sep38DiscrepancyResult> {
  return new Sep38QuoteDiscrepancyAuditor(fetchImpl, options).audit(doc);
}

const def = (id: string, severity: 'error' | 'warning' | 'info', description: string): Rule => ({
  id,
  category: 'network',
  severity,
  description,
  run() {},
});

export const sep38DiscrepancyRules: Rule[] = [
  def(
    SPREAD_RULE,
    'error',
    'SEP-38 firm quote spreads must stay within the advertised indicative rate and tolerance',
  ),
  def(FEE_RULE, 'error', 'SEP-38 firm quote fees must not exceed fees disclosed in stellar.toml'),
  def(EXPIRY_MISSING_RULE, 'error', 'SEP-38 firm quotes must carry a parseable expires_at'),
  def(EXPIRED_RULE, 'error', 'SEP-38 must not issue quotes that are already expired'),
  def(LIFETIME_RULE, 'warning', 'SEP-38 firm quote lifetimes must stay bounded'),
  def(EXPIRED_ACCEPTED_RULE, 'error', 'Expired SEP-38 quotes must not be accepted at execution'),
  def(UNVERIFIABLE_RULE, 'info', 'SEP-38 quote pricing should be verifiable'),
];

export const sep38DiscrepancyRuleIds: readonly string[] = sep38DiscrepancyRules.map(
  (rule) => rule.id,
);
