/**
 * The SEP-24 `GET /info` response for the local mock server.
 */
import type { MockAsset } from './assets.js';

interface Sep24AssetInfo {
  enabled: true;
  min_amount: number;
  max_amount: number;
}

export interface Sep24Info {
  deposit: Record<string, Sep24AssetInfo>;
  withdraw: Record<string, Sep24AssetInfo>;
  fee: { enabled: boolean };
  features: { account_creation: boolean; claimable_balances: boolean };
}

/** Every declared currency, enabled for both deposit and withdrawal. */
export function sep24Info(assets: MockAsset[]): Sep24Info {
  const deposit: Record<string, Sep24AssetInfo> = {};
  const withdraw: Record<string, Sep24AssetInfo> = {};
  for (const asset of assets) {
    const info: Sep24AssetInfo = { enabled: true, min_amount: 1, max_amount: 1_000_000 };
    deposit[asset.code] = info;
    withdraw[asset.code] = info;
  }
  return {
    deposit,
    withdraw,
    fee: { enabled: false },
    features: { account_creation: true, claimable_balances: true },
  };
}
