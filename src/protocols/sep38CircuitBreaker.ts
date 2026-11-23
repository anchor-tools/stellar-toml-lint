/**
 * SEP-38 RFQ circuit-breaker verifier.
 *
 * Runs under opt-in `--audit-sep38-volatility` (or `stellar-toml-lint
 * sep38-volatility --domain <domain>`).
 *
 * A firm SEP-38 quote is a promise to trade at a price until `expires_at`. In a
 * volatile crypto pair that promise is only safe while the underlying market
 * sits inside the anchor's volatility band: a quote that stays executable for
 * minutes after the on-chain price has moved 5% is either honoured at a loss by
 * the anchor or rejected at execution after the wallet has already committed
 * the transfer. Both outcomes are financial bugs, so a quote server must
 * (a) cap quote lifetimes with a buffer sized for volatility, and (b) re-price
 * or invalidate quotes when the market leaves that buffer.
 *
 * This verifier books quotes from `POST /quote` while sampling `GET /prices`
 * over several simulated on-chain SDEX phases (steady, shock up, shock down).
 * It measures quote lifetimes with high-resolution timestamps and compares the
 * quoted price against the simulated market price to detect anchors that keep
 * serving a stale rate through a shock.
 *
 * The audit never executes a quote or moves funds: it only reads the anchor's
 * own HTTP surface.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isHttpsUrl, isString } from '../predicates.js';
import { fetchWithTimeout, isRecord, severityFor } from './verifierSupport.js';

const TOO_LONG_RULE = 'sep38/quote-window-too-long';
const UNBOUNDED_RULE = 'sep38/quote-window-unbounded';
const TOO_SHORT_RULE = 'sep38/quote-window-too-short';
const NO_PROTECTION_RULE = 'sep38/no-volatility-protection';
const STALE_FEED_RULE = 'sep38/stale-price-feed';
const UNVERIFIABLE_RULE = 'sep38/volatility-unverifiable';

const SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0038.md';

/** Standard volatility buffer for crypto pairs, in seconds. */
export const DEFAULT_MAX_QUOTE_DURATION_SECONDS = 60;

/**
 * Below this a quote is unusable in practice: a wallet needs time to sign and
 * submit, and the quote can lapse between the user seeing it and confirming.
 */
export const DEFAULT_MIN_QUOTE_DURATION_SECONDS = 5;

/** A quote advertised further out than this is effectively unbounded. */
const UNBOUNDED_SECONDS = 365 * 24 * 60 * 60;

/**
 * Sub-second slack for clock and transport skew: a quote measured at 60.0s is
 * the advertised 60s buffer, not a violation.
 */
const DURATION_EPSILON_SECONDS = 0.5;

/** Default market movements, expressed as a percentage of the baseline price. */
const DEFAULT_PHASES: readonly MarketPhase[] = [
  { label: 'steady', shockPercent: 0 },
  { label: 'shock-up', shockPercent: 5 },
  { label: 'shock-down', shockPercent: -5 },
];

/** High-resolution timing hooks. Tests inject a deterministic clock. */
export interface MonotonicClock {
  /** Wall-clock epoch milliseconds, used for `expires_at` arithmetic. */
  wallNow(): number;
  /** Monotonic milliseconds, used for elapsed/round-trip measurements. */
  monotonicNow(): number;
}

export const systemClock: MonotonicClock = {
  wallNow: () => Date.now(),
  monotonicNow: () => performance.now(),
};

/** One simulated market phase, expressed as a move from the baseline price. */
export interface MarketPhase {
  label: string;
  shockPercent: number;
}

export interface Sep38CircuitBreakerOptions {
  rules?: RuleOverrides;
  /** Quote server base; defaults to `ANCHOR_QUOTE_SERVER`. */
  quoteServer?: string;
  /** Pair to probe; defaults to the first volatile pair from `/info`. */
  sellAsset?: string;
  buyAsset?: string;
  sellAmount?: string;
  /** Quotes booked per market phase. Defaults to 2. */
  intervalsPerPhase?: number;
  /** Delay between rounds, in milliseconds. Defaults to 100. */
  intervalMs?: number;
  /** Simulated SDEX price phases, in order. */
  phases?: readonly MarketPhase[];
  /** Longest acceptable lifetime in a volatile crypto pair. Defaults to 60s. */
  maxQuoteDurationSeconds?: number;
  /** Shortest lifetime a wallet can realistically use. Defaults to 5s. */
  minQuoteDurationSeconds?: number;
  /** Move beyond this percentage counts as a volatility-band breach. Defaults to 1%. */
  volatilityBandPercent?: number;
  timeoutMs?: number;
  clock?: MonotonicClock;
  sleep?: (ms: number) => Promise<unknown>;
}

export interface QuoteSample {
  phase: string;
  /** Move the simulated SDEX price made from the baseline, in percent. */
  shockPercent: number;
  /** Simulated market price for this phase. */
  expectedMarketPrice: number;
  /** Price the anchor advertised on `GET /prices`, when it answered. */
  advertisedPrice?: number;
  /** Price returned by `POST /quote`, when it answered. */
  quotePrice?: number;
  /** Quote lifetime in seconds, `undefined` for an unbounded quote. */
  durationSeconds?: number;
  /** High-resolution round trip of `POST /quote`, in milliseconds. */
  quoteLatencyMs?: number;
  /** Round trip of `GET /prices`, in milliseconds. */
  pricesLatencyMs?: number;
}

export interface CircuitBreakerResult {
  diagnostics: Diagnostic[];
  samples: QuoteSample[];
  /** Human-readable summary of what was exercised. */
  summary: string;
}

export interface Sep38Pair {
  sell: string;
  buy: string;
  /** True when neither leg is fiat, i.e. the pair can move intraday. */
  volatile: boolean;
}

function isFiatAsset(asset: string): boolean {
  return asset.startsWith('iso4217:');
}

/** A pair is volatile when both legs are crypto rather than fiat. */
export function isVolatilePair(sell: string, buy: string): boolean {
  return !isFiatAsset(sell) && !isFiatAsset(buy);
}

function amountOf(value: unknown): number | undefined {
  if (typeof value === 'number') return Number.isFinite(value) ? value : undefined;
  if (!isString(value)) return undefined;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

/** Percentage difference of `value` from `reference`. */
export function percentDelta(value: number, reference: number): number {
  if (!Number.isFinite(value) || !Number.isFinite(reference) || reference === 0) {
    return Number.POSITIVE_INFINITY;
  }
  return Math.abs((value - reference) / reference) * 100;
}

/** Applies a simulated SDEX shock to a baseline price. */
export function applyShock(baseline: number, shockPercent: number): number {
  return baseline * (1 + shockPercent / 100);
}

/** The `price` for `buyAsset` from a SEP-38 `GET /prices` body. */
export function priceFromPricesBody(body: unknown, buyAsset: string): number | undefined {
  if (!isRecord(body) || !Array.isArray(body.buy_assets)) return undefined;
  const entries = body.buy_assets.filter(isRecord);
  const match = entries.find((entry) => entry.asset === buyAsset);
  return match === undefined ? undefined : amountOf(match.price);
}

/**
 * Picks a pair to probe from the quote server's `/info` assets: the first pair
 * of crypto legs, falling back to the first two assets when the anchor lists
 * only fiat. Returns `undefined` when fewer than two assets are advertised.
 */
export function pickPair(
  assets: readonly unknown[],
  preferredSell?: string,
  preferredBuy?: string,
): Sep38Pair | undefined {
  const ids = assets.flatMap((asset) =>
    isRecord(asset) && isString(asset.asset) ? [asset.asset] : [],
  );
  if (preferredSell !== undefined) {
    const buy = preferredBuy ?? ids.find((id) => id !== preferredSell);
    return buy === undefined
      ? undefined
      : { sell: preferredSell, buy, volatile: isVolatilePair(preferredSell, buy) };
  }
  for (const sell of ids) {
    for (const buy of ids) {
      if (sell !== buy && isVolatilePair(sell, buy)) return { sell, buy, volatile: true };
    }
  }
  const [sell, buy] = ids;
  return sell !== undefined && buy !== undefined && sell !== buy
    ? { sell, buy, volatile: isVolatilePair(sell, buy) }
    : undefined;
}

/** Lifetime in seconds between `expiresAt` and the response timestamp. */
export function quoteDurationSeconds(expiresAt: number, observedAtMs: number): number {
  return (expiresAt - observedAtMs) / 1000;
}

export class Sep38CircuitBreakerVerifier {
  constructor(
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly options: Sep38CircuitBreakerOptions = {},
  ) {}

  async verify(doc: Record<string, unknown>): Promise<CircuitBreakerResult> {
    const server = this.options.quoteServer ?? doc.ANCHOR_QUOTE_SERVER;
    if (!isString(server) || !isHttpsUrl(server)) {
      return { diagnostics: [], samples: [], summary: 'No usable ANCHOR_QUOTE_SERVER to probe.' };
    }
    const base = server.replace(/\/+$/, '');
    const pair = await this.resolvePair(base);
    if (pair === undefined) {
      return {
        diagnostics: this.finding(
          UNVERIFIABLE_RULE,
          'info',
          'ANCHOR_QUOTE_SERVER /info lists fewer than two assets, so no SEP-38 pair can be exercised',
          'ANCHOR_QUOTE_SERVER',
          'Advertise at least one quotable asset pair in /info so wallets (and this audit) can price a trade.',
        ),
        samples: [],
        summary: 'No quotable pair advertised.',
      };
    }

    const clock = this.options.clock ?? systemClock;
    const sleep =
      this.options.sleep ?? ((ms: number) => new Promise((resolve) => setTimeout(resolve, ms)));
    const phases = this.options.phases ?? DEFAULT_PHASES;
    const rounds = Math.max(1, this.options.intervalsPerPhase ?? 2);
    const intervalMs = Math.max(0, this.options.intervalMs ?? 100);
    const amount = this.options.sellAmount ?? '100.00';

    const samples: QuoteSample[] = [];
    let baseline: number | undefined;
    let sawQuote = false;

    for (const phase of phases) {
      for (let round = 0; round < rounds; round++) {
        const pricesStart = clock.monotonicNow();
        const advertised = await this.readPrices(base, pair);
        const pricesLatencyMs = clock.monotonicNow() - pricesStart;

        const quoteStart = clock.monotonicNow();
        const quote = await this.readQuote(base, pair, amount, clock);
        const quoteLatencyMs = clock.monotonicNow() - quoteStart;

        if (baseline === undefined) {
          baseline = advertised.price ?? quote?.price;
        }
        if (quote !== undefined) sawQuote = true;

        samples.push({
          phase: phase.label,
          shockPercent: phase.shockPercent,
          expectedMarketPrice:
            baseline === undefined ? 0 : applyShock(baseline, phase.shockPercent),
          ...(advertised.price !== undefined ? { advertisedPrice: advertised.price } : {}),
          ...(quote?.price !== undefined ? { quotePrice: quote.price } : {}),
          ...(quote?.durationSeconds !== undefined
            ? { durationSeconds: quote.durationSeconds }
            : {}),
          ...(quote === undefined ? {} : { quoteLatencyMs }),
          ...(advertised.price === undefined ? {} : { pricesLatencyMs }),
        });

        if (round < rounds - 1 && intervalMs > 0) await sleep(intervalMs);
      }
    }

    if (!sawQuote) {
      return {
        diagnostics: this.finding(
          UNVERIFIABLE_RULE,
          'info',
          `ANCHOR_QUOTE_SERVER ${base} answered neither a usable /prices price nor a /quote for ${pair.sell} -> ${pair.buy}`,
          'ANCHOR_QUOTE_SERVER',
          'Return SEP-38 price and quote responses so wallets can price the pair and this audit can check its volatility handling.',
        ),
        samples,
        summary: `No quote could be booked for ${pair.sell} -> ${pair.buy}.`,
      };
    }

    const diagnostics = this.assess(pair, samples);
    return {
      diagnostics,
      samples,
      summary: `${samples.length} samples over ${phases.length} market phases for ${pair.sell} -> ${pair.buy}${
        pair.volatile ? ' (volatile pair)' : ' (fiat pair)'
      }.`,
    };
  }

  /** Emits at most one diagnostic per rule, describing the worst observation. */
  private assess(pair: Sep38Pair, samples: readonly QuoteSample[]): Diagnostic[] {
    const diagnostics: Diagnostic[] = [];
    const maxDuration = this.options.maxQuoteDurationSeconds ?? DEFAULT_MAX_QUOTE_DURATION_SECONDS;
    const minDuration = this.options.minQuoteDurationSeconds ?? DEFAULT_MIN_QUOTE_DURATION_SECONDS;
    const band = this.options.volatilityBandPercent ?? 1;

    const bounded = samples.filter((s) => s.durationSeconds !== undefined);
    const durations = bounded.flatMap((s) => s.durationSeconds as number);
    const unbounded = samples.length - bounded.length;

    if (pair.volatile) {
      const longest = durations.length > 0 ? Math.max(...durations) : undefined;
      if (longest !== undefined && longest > maxDuration + DURATION_EPSILON_SECONDS) {
        diagnostics.push(
          ...this.finding(
            TOO_LONG_RULE,
            'error',
            `Quotes for the volatile pair ${pair.sell} -> ${pair.buy} live ${longest.toFixed(1)}s, beyond the ${maxDuration}s volatility buffer`,
            'ANCHOR_QUOTE_SERVER',
            `Cap expires_at at ${maxDuration}s for crypto pairs: a longer window leaves the anchor or the user exposed to a market move it cannot re-price.`,
          ),
        );
      }
    }

    if (unbounded > 0) {
      diagnostics.push(
        ...this.finding(
          UNBOUNDED_RULE,
          'warning',
          `${unbounded} of ${samples.length} quotes for ${pair.sell} -> ${pair.buy} advertised no usable expires_at`,
          'ANCHOR_QUOTE_SERVER',
          'Always return expires_at on POST /quote; an indefinitely valid quote cannot be invalidated when the market moves.',
        ),
      );
    }

    const shortest = durations.length > 0 ? Math.min(...durations) : undefined;
    if (shortest !== undefined && shortest < minDuration) {
      diagnostics.push(
        ...this.finding(
          TOO_SHORT_RULE,
          'warning',
          `Quotes for ${pair.sell} -> ${pair.buy} expire after ${shortest.toFixed(1)}s, too quickly for a wallet to sign and submit`,
          'ANCHOR_QUOTE_SERVER',
          `Give users at least ${minDuration}s to accept a quote, ideally while still staying inside the volatility buffer.`,
        ),
      );
    }

    // Circuit breaker: in every shock phase the quote must track the simulated
    // SDEX price. The worst breach is what matters — a quote stale by 4% of a
    // 5% move is exactly the loss the breaker exists to prevent.
    let worstQuoteBreach: { sample: QuoteSample; delta: number } | undefined;
    let worstFeedBreach: { sample: QuoteSample; delta: number } | undefined;
    for (const sample of samples) {
      if (Math.abs(sample.shockPercent) <= band) continue;
      if (sample.quotePrice !== undefined) {
        const delta = percentDelta(sample.quotePrice, sample.expectedMarketPrice);
        if (delta > band && (worstQuoteBreach === undefined || delta > worstQuoteBreach.delta)) {
          worstQuoteBreach = { sample, delta };
        }
      }
      if (sample.advertisedPrice !== undefined) {
        const delta = percentDelta(sample.advertisedPrice, sample.expectedMarketPrice);
        if (delta > band && (worstFeedBreach === undefined || delta > worstFeedBreach.delta)) {
          worstFeedBreach = { sample, delta };
        }
      }
    }

    if (worstQuoteBreach !== undefined) {
      const { sample, delta } = worstQuoteBreach;
      diagnostics.push(
        ...this.finding(
          NO_PROTECTION_RULE,
          'warning',
          `During the ${sample.phase} phase the quote for ${pair.sell} -> ${pair.buy} stayed at ${sample.quotePrice} while the simulated SDEX price moved to ${round(sample.expectedMarketPrice)} (${delta.toFixed(2)}% stale)`,
          'ANCHOR_QUOTE_SERVER',
          'Re-price or invalidate open quotes once the market leaves the volatility band; a quote that survives the move is executable at a stale rate.',
        ),
      );
    }

    if (worstFeedBreach !== undefined) {
      const { sample, delta } = worstFeedBreach;
      diagnostics.push(
        ...this.finding(
          STALE_FEED_RULE,
          'warning',
          `ANCHOR_QUOTE_SERVER /prices advertised ${sample.advertisedPrice} during the ${sample.phase} phase, ${delta.toFixed(2)}% away from the simulated SDEX price ${round(sample.expectedMarketPrice)}`,
          'ANCHOR_QUOTE_SERVER',
          'Feed /prices from a fresh SDEX or exchange reference and bound its age; a stale price feed defeats every downstream circuit breaker.',
        ),
      );
    }

    return diagnostics;
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
      const body: unknown = await response.json().catch(() => undefined);
      const assets = isRecord(body) && Array.isArray(body.assets) ? body.assets : [];
      return pickPair(assets, this.options.sellAsset, this.options.buyAsset);
    } catch {
      return undefined;
    }
  }

  private async readPrices(base: string, pair: Sep38Pair): Promise<{ price?: number }> {
    const params = new URLSearchParams({ sell_asset: pair.sell, buy_asset: pair.buy });
    try {
      const response = await fetchWithTimeout(
        this.fetchImpl,
        `${base}/prices?${params.toString()}`,
        {},
        this.options.timeoutMs,
      );
      if (!response.ok) return {};
      const body: unknown = await response.json().catch(() => undefined);
      const price = priceFromPricesBody(body, pair.buy);
      return price === undefined ? {} : { price };
    } catch {
      return {};
    }
  }

  private async readQuote(
    base: string,
    pair: Sep38Pair,
    amount: string,
    clock: MonotonicClock,
  ): Promise<{ price: number; durationSeconds?: number } | undefined> {
    const wallStart = clock.wallNow();
    const monotonicStart = clock.monotonicNow();
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
            sell_amount: amount,
            context: 'sep38',
          }),
        },
        this.options.timeoutMs,
      );
      if (!response.ok) return undefined;
      const body: unknown = await response.json().catch(() => undefined);
      if (!isRecord(body)) return undefined;
      const price = amountOf(body.price);
      if (price === undefined) return undefined;

      // Elapsed is measured on the monotonic clock so a cold, blocked or slow
      // response cannot inflate the apparent quote lifetime.
      const elapsed = clock.monotonicNow() - monotonicStart;
      const observedAt = wallStart + elapsed;
      const expiresAt = isString(body.expires_at) ? Date.parse(body.expires_at) : Number.NaN;
      if (!Number.isFinite(expiresAt)) return { price };
      const durationSeconds = quoteDurationSeconds(expiresAt, observedAt);
      if (durationSeconds > UNBOUNDED_SECONDS) return { price };
      return { price, durationSeconds };
    } catch {
      return undefined;
    }
  }

  /** Severity-aware diagnostic builder, honouring `--off`/`--warn`/`--error`. */
  private finding(
    rule: string,
    fallback: 'error' | 'warning' | 'info',
    message: string,
    path: string,
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
        path,
        helpUri: SPEC,
        suggestion,
      },
    ];
  }
}

function round(value: number): number {
  return Math.round(value * 100) / 100;
}

export async function verifySep38Volatility(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: Sep38CircuitBreakerOptions = {},
): Promise<CircuitBreakerResult> {
  return new Sep38CircuitBreakerVerifier(fetchImpl, options).verify(doc);
}

const def = (id: string, severity: 'error' | 'warning' | 'info', description: string): Rule => ({
  id,
  category: 'network',
  severity,
  description,
  run() {},
});

export const sep38CircuitBreakerRules: Rule[] = [
  def(
    TOO_LONG_RULE,
    'error',
    'SEP-38 quote lifetimes must stay within the volatility buffer for crypto pairs',
  ),
  def(UNBOUNDED_RULE, 'warning', 'SEP-38 quotes must carry a finite expires_at'),
  def(TOO_SHORT_RULE, 'warning', 'SEP-38 quote lifetimes must leave time to sign and submit'),
  def(
    NO_PROTECTION_RULE,
    'warning',
    'SEP-38 quotes must re-price or invalidate when the market leaves the volatility band',
  ),
  def(STALE_FEED_RULE, 'warning', 'SEP-38 /prices must track the underlying market'),
  def(UNVERIFIABLE_RULE, 'info', 'SEP-38 volatility handling should be verifiable'),
];

export const sep38CircuitBreakerRuleIds: readonly string[] = sep38CircuitBreakerRules.map(
  (rule) => rule.id,
);
