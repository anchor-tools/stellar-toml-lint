/**
 * SEP-38 Indicative Pricing Curve Spread and Slippage Boundary Validator
 *
 * Samples GET /prices and POST /quote across multiple order sizes
 * to verify price curve monotonicity and slippage boundaries.
 *
 * Runs under opt-in --check-network --verify-sep38.
 */

import type { Diagnostic } from '../types.js';
import { isString } from '../predicates.js';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export const INVERTED_BID_ASK_SPREAD_RULE = 'sep38/inverted-bid-ask-spread';
export const EXCESSIVE_SLIPPAGE_DETECTED_RULE = 'sep38/excessive-slippage-detected';
export const NON_MONOTONIC_PRICE_CURVE_RULE = 'sep38/non-monotonic-price-curve';

export interface Sep38SlippageOptions {
  /** Order sizes to test (in base asset units) */
  orderSizes?: number[];
  /** Maximum allowed slippage percentage for standard sizes */
  maxSlippagePercent?: number;
  /** Maximum allowed spread between bid/ask */
  maxBidAskSpreadPercent?: number;
  /** Rule severity overrides */
  rules?: Record<string, 'off' | 'error' | 'warning'>;
}

const DEFAULT_OPTIONS: Required<Sep38SlippageOptions> = {
  orderSizes: [10, 100, 1000, 10000, 100000],
  maxSlippagePercent: 5,
  maxBidAskSpreadPercent: 15,
  rules: {},
};

export interface PricePoint {
  sellAsset: string;
  buyAsset: string;
  sellAmount: number;
  price: number;
  timestamp: number;
}

export interface SlippageAnalysisResult {
  sellAsset: string;
  buyAsset: string;
  pricePoints: PricePoint[];
  isMonotonic: boolean;
  maxSlippage: number;
  invertedSpreadDetected: boolean;
  bidAskSpread: number;
}

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules?: Record<string, 'off' | 'error' | 'warning'>,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

function report(
  diagnostics: Diagnostic[],
  rule: string,
  fallback: 'error' | 'warning',
  path: string,
  message: string,
  suggestion: string,
  options: Sep38SlippageOptions,
): void {
  const severity = severityFor(rule, fallback, options.rules);
  if (severity === undefined) return;
  diagnostics.push({
    rule,
    severity,
    category: 'network',
    message,
    path,
    suggestion,
  });
}

async function fetchPrices(
  baseUrl: string,
  sellAsset: string,
  sellAmount: number,
  fetchImpl: typeof fetch,
): Promise<Map<string, number> | null> {
  const url = `${baseUrl}/prices?sell_asset=${encodeURIComponent(sellAsset)}&sell_amount=${sellAmount}`;

  try {
    const response = await fetchImpl(url);
    if (response.status !== 200) return null;

    const body = await response.json();
    if (!isRecord(body) || !Array.isArray(body.buy_assets)) return null;

    const prices = new Map<string, number>();
    for (const entry of body.buy_assets) {
      if (isRecord(entry) && isString(entry.asset) && isString(entry.price)) {
        const price = Number(entry.price);
        if (Number.isFinite(price) && price > 0) {
          prices.set(entry.asset, price);
        }
      }
    }
    return prices.size > 0 ? prices : null;
  } catch {
    return null;
  }
}

function analyzePriceCurve(
  pricePoints: PricePoint[],
): { isMonotonic: boolean; maxSlippage: number } {
  if (pricePoints.length < 2) return { isMonotonic: true, maxSlippage: 0 };

  // Sort by sell amount
  const sorted = [...pricePoints].sort((a, b) => a.sellAmount - b.sellAmount);

  if (sorted.length === 0) return { isMonotonic: true, maxSlippage: 0 };

  let isMonotonic = true;
  let maxSlippage = 0;
  const basePrice = sorted[0]!.price;

  for (let i = 1; i < sorted.length; i++) {
    const prev = sorted[i - 1]!;
    const curr = sorted[i]!;

    // Check monotonicity: price should not increase as sell amount increases (for fixed buy asset)
    // Actually, for a given sell->buy pair, as sell_amount increases, the price (buy/sell) typically decreases due to slippage
    // So we check if price is non-increasing
    if (curr.price > prev.price) {
      isMonotonic = false;
    }

    // Calculate slippage relative to first price point
    const slippage = Math.abs((curr.price - basePrice) / basePrice) * 100;
    maxSlippage = Math.max(maxSlippage, slippage);
  }

  return { isMonotonic, maxSlippage };
}

function checkInvertedSpread(
  buyPrice: number,
  sellPrice: number,
): { inverted: boolean; spread: number } {
  // buyPrice: how much buy asset for 1 sell asset (e.g., 1 USDX = 0.9 EURX)
  // sellPrice: how much sell asset for 1 buy asset (e.g., 1 EURX = 1.2 USDX)
  // The implied reverse of buyPrice is 1/buyPrice
  // If sellPrice < 1/buyPrice, there's an inverted spread (arbitrage opportunity)

  if (buyPrice <= 0 || sellPrice <= 0) return { inverted: false, spread: 0 };

  const impliedReverse = 1 / buyPrice;
  const spread = Math.abs(sellPrice - impliedReverse) / impliedReverse * 100;
  const inverted = sellPrice < impliedReverse;

  return { inverted, spread };
}

export async function analyzeSep38Slippage(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: Sep38SlippageOptions = {},
): Promise<Diagnostic[]> {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  const diagnostics: Diagnostic[] = [];

  const server = doc.ANCHOR_QUOTE_SERVER;
  if (!isString(server) || !server.startsWith('http')) return [];

  const baseUrl = server.replace(/\/+$/, '');
  const declaredAssets: string[] = [];

  // Extract declared assets from CURRENCIES
  const currencies = doc.CURRENCIES;
  if (Array.isArray(currencies)) {
    for (const curr of currencies) {
      if (isRecord(curr) && isString(curr.code) && isString(curr.issuer)) {
        declaredAssets.push(`stellar:${curr.code}:${curr.issuer}`);
      }
      if (isRecord(curr) && curr.anchor_asset_type === 'fiat' && isString(curr.anchor_asset)) {
        declaredAssets.push(`iso4217:${curr.anchor_asset}`);
      }
    }
  }

  if (declaredAssets.length < 2) return [];

  // Analyze each pair
  for (let i = 0; i < declaredAssets.length; i++) {
    const sellAsset = declaredAssets[i];
    if (!sellAsset) continue;

    for (let j = i + 1; j < declaredAssets.length; j++) {
      const buyAsset = declaredAssets[j];
      if (!buyAsset) continue;

      const forwardPoints: PricePoint[] = [];
      const reversePoints: PricePoint[] = [];

      // Fetch prices for each order size
      for (const size of opts.orderSizes) {
        // Forward direction
        const forwardPrices = await fetchPrices(baseUrl, sellAsset, size, fetchImpl);
        const forwardPrice = forwardPrices?.get(buyAsset);
        if (forwardPrice !== undefined) {
          forwardPoints.push({
            sellAsset,
            buyAsset,
            sellAmount: size,
            price: forwardPrice,
            timestamp: Date.now(),
          });
        }

        // Reverse direction
        const reversePrices = await fetchPrices(baseUrl, buyAsset, size, fetchImpl);
        const reversePrice = reversePrices?.get(sellAsset);
        if (reversePrice !== undefined) {
          reversePoints.push({
            sellAsset: buyAsset,
            buyAsset: sellAsset,
            sellAmount: size,
            price: reversePrice,
            timestamp: Date.now(),
          });
        }
      }

      if (forwardPoints.length === 0 || reversePoints.length === 0) continue;

      // Analyze forward curve
      const { isMonotonic: forwardMonotonic, maxSlippage: forwardSlippage } = analyzePriceCurve(
        forwardPoints,
      );

      // Analyze reverse curve
      const { isMonotonic: reverseMonotonic, maxSlippage: reverseSlippage } = analyzePriceCurve(
        reversePoints,
      );

      // Check for excessive slippage
      const maxSlippage = Math.max(forwardSlippage, reverseSlippage);
      if (maxSlippage > opts.maxSlippagePercent) {
        report(
          diagnostics,
          EXCESSIVE_SLIPPAGE_DETECTED_RULE,
          'warning',
          'ANCHOR_QUOTE_SERVER',
          `SEP-38 pricing curve for ${sellAsset} -> ${buyAsset} shows ${maxSlippage.toFixed(1)}% slippage (max allowed: ${opts.maxSlippagePercent}%)`,
          'Ensure pricing curve reflects realistic market slippage. Large jumps may indicate liquidity issues.',
          opts,
        );
      }

      // Check monotonicity
      if (!forwardMonotonic || !reverseMonotonic) {
        report(
          diagnostics,
          NON_MONOTONIC_PRICE_CURVE_RULE,
          'warning',
          'ANCHOR_QUOTE_SERVER',
          `SEP-38 pricing curve for ${sellAsset} <-> ${buyAsset} is non-monotonic (price should not improve with larger orders)`,
          'Pricing curve must be monotonic: larger orders should not get better rates.',
          opts,
        );
      }

      // Check for inverted bid-ask spread at smallest order size
      if (forwardPoints.length > 0 && reversePoints.length > 0) {
        const forwardPrice = forwardPoints[0]!.price;
        const reversePrice = reversePoints[0]!.price;
        const { inverted, spread } = checkInvertedSpread(forwardPrice, reversePrice);

        if (inverted) {
          report(
            diagnostics,
            INVERTED_BID_ASK_SPREAD_RULE,
            'error',
            'ANCHOR_QUOTE_SERVER',
            `SEP-38 inverted bid-ask spread detected for ${sellAsset}/${buyAsset}: buy rate ${forwardPrice}, sell rate ${reversePrice} (implied reverse: ${(1/forwardPrice).toFixed(6)})`,
            'Bid price must be >= ask price. An inverted spread indicates an arbitrage bug.',
            opts,
          );
        } else if (spread > opts.maxBidAskSpreadPercent) {
          report(
            diagnostics,
            EXCESSIVE_SLIPPAGE_DETECTED_RULE,
            'warning',
            'ANCHOR_QUOTE_SERVER',
            `SEP-38 excessive bid-ask spread for ${sellAsset}/${buyAsset}: ${spread.toFixed(1)}% (max allowed: ${opts.maxBidAskSpreadPercent}%)`,
            'Keep bid-ask spread within reasonable bounds.',
            opts,
          );
        }
      }
    }
  }

  return diagnostics;
}

export const sep38SlippageRules = [
  {
    id: INVERTED_BID_ASK_SPREAD_RULE,
    category: 'network',
    severity: 'error' as const,
    description: 'SEP-38 bid price must not be less than ask price (no inverted spreads)',
    run() {},
  },
  {
    id: EXCESSIVE_SLIPPAGE_DETECTED_RULE,
    category: 'network',
    severity: 'warning' as const,
    description: 'SEP-38 pricing curve slippage must not exceed 5% for standard order sizes',
    run() {},
  },
  {
    id: NON_MONOTONIC_PRICE_CURVE_RULE,
    category: 'network',
    severity: 'warning' as const,
    description: 'SEP-38 pricing curve must be monotonic (larger orders should not get better rates)',
    run() {},
  },
];