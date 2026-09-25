/**
 * SEP-38 `GET /info` and `GET /prices` responses for the local mock server.
 *
 * Every declared asset can be exchanged for every other at a flat mock price
 * of 1, which is enough for a client to exercise its quote flow end to end.
 */
import type { MockAsset } from './assets.js';

export interface Sep38Info {
  assets: { asset: string }[];
}

interface Sep38Price {
  asset: string;
  price: string;
  decimals: number;
}

/** The SEP-38 identifiers the mock quotes, with the decimals to quote each in. */
function quotable(assets: MockAsset[]): Map<string, number> {
  const ids = new Map<string, number>();
  for (const asset of assets) {
    if (asset.sep38 !== undefined) ids.set(asset.sep38, asset.decimals);
    if (asset.offChain !== undefined) ids.set(asset.offChain, 2);
  }
  return ids;
}

export function sep38Info(assets: MockAsset[]): Sep38Info {
  return { assets: [...quotable(assets).keys()].map((asset) => ({ asset })) };
}

export type Sep38PricesResult =
  | { status: 200; body: { buy_assets: Sep38Price[] } | { sell_assets: Sep38Price[] } }
  | { status: 400; body: { error: string } };

/**
 * `GET /prices?sell_asset=...&sell_amount=...` lists what `sell_asset` buys;
 * `?buy_asset=...&buy_amount=...` lists what buys `buy_asset`.
 */
export function sep38Prices(assets: MockAsset[], query: URLSearchParams): Sep38PricesResult {
  const ids = quotable(assets);
  const sell = query.get('sell_asset');
  const buy = query.get('buy_asset');

  const counterparties = (asset: string): Sep38Price[] =>
    [...ids]
      .filter(([id]) => id !== asset)
      .map(([id, decimals]) => ({ asset: id, price: (1).toFixed(decimals), decimals }));

  if (sell !== null) {
    if (!ids.has(sell)) return { status: 400, body: { error: `unsupported sell_asset: ${sell}` } };
    if (query.get('sell_amount') === null) {
      return { status: 400, body: { error: 'sell_amount is required with sell_asset' } };
    }
    return { status: 200, body: { buy_assets: counterparties(sell) } };
  }
  if (buy !== null) {
    if (!ids.has(buy)) return { status: 400, body: { error: `unsupported buy_asset: ${buy}` } };
    if (query.get('buy_amount') === null) {
      return { status: 400, body: { error: 'buy_amount is required with buy_asset' } };
    }
    return { status: 200, body: { sell_assets: counterparties(buy) } };
  }
  return { status: 400, body: { error: 'sell_asset or buy_asset is required' } };
}
