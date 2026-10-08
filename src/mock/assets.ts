/**
 * The assets a mock anchor serves, read once from `[[CURRENCIES]]`.
 */
import { currenciesOf, isTomlPointer } from '../rules/currencies.js';
import { isString } from '../predicates.js';

export interface MockAsset {
  /** The asset code SEP-24 keys its `/info` maps by (`native` for XLM). */
  code: string;
  /** The SEP-38 identifier: `stellar:CODE:ISSUER` or `stellar:native`. */
  sep38: string | undefined;
  /** `iso4217:XXX` for a fiat-anchored currency, the off-chain side of a quote. */
  offChain: string | undefined;
  /** Decimal places to quote with. */
  decimals: number;
}

export function mockAssetsOf(doc: Record<string, unknown>): MockAsset[] {
  const assets: MockAsset[] = [];
  for (const entry of currenciesOf(doc)) {
    if (isTomlPointer(entry) || !isString(entry.code)) continue;

    const native = entry.code.toLowerCase() === 'native';
    const code = native ? 'native' : entry.code;
    const sep38 = native
      ? 'stellar:native'
      : isString(entry.issuer)
        ? `stellar:${code}:${entry.issuer}`
        : undefined;
    const offChain =
      entry.anchor_asset_type === 'fiat' && isString(entry.anchor_asset)
        ? `iso4217:${entry.anchor_asset}`
        : undefined;
    const decimals =
      typeof entry.display_decimals === 'number' && Number.isInteger(entry.display_decimals)
        ? entry.display_decimals
        : 7;

    assets.push({ code, sep38, offChain, decimals });
  }
  return assets;
}
