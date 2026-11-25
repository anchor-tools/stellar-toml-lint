/**
 * ERC-4626 tokenized vault reserve and yield auditor.
 *
 * Runs under opt-in `--audit-erc4626-vaults`; vault contracts and Horizon are
 * only queried with `--check-network`.
 *
 * A currency backed by vault shares declares its collateral as
 * `collateral_vaults = [{ chain, vault, shares, rpc?, share_price?, tolerance_bps? }]`.
 * For each vault the auditor calls `decimals()`, `asset()` (and the asset's
 * `decimals()`), `totalAssets()` and `convertToAssets(shares)` over JSON-RPC,
 * then:
 *
 * - checks the held shares never redeem for more than `totalAssets()`;
 * - derives the live share price from `convertToAssets(10^decimals)` and flags
 *   a price below par (a loss or depeg) or drift from the declared
 *   `share_price` beyond `tolerance_bps` (default 50);
 * - sums the net asset value of all vaults backing a currency and requires it
 *   to cover the issued Stellar supply.
 *
 * `convertToAssets` rounds down per the ERC-4626 spec, and every ratio here
 * also rounds down, so the audit never overstates backing.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isHttpsUrl, isString } from '../predicates.js';
import { errorMessage, isRecord } from '../protocols/verifierSupport.js';
import {
  AMOUNT_SCALE,
  DEFAULT_EVM_RPC,
  EVM_ADDRESS,
  abiWords,
  bridgeRule,
  covers,
  diagnosticSink,
  encodeUint256,
  ethCall,
  formatBps,
  formatUnits,
  horizonFor,
  parseUnits,
  ratioBps,
  stellarSupply,
} from './bridgeSupport.js';
import type { Push, RpcOptions, StellarAsset } from './bridgeSupport.js';

const INVALID_RULE = 'erc4626/invalid-vault';
const RPC_RULE = 'erc4626/rpc-unavailable';
const ACCOUNTING_RULE = 'erc4626/inconsistent-accounting';
const PAR_RULE = 'erc4626/share-price-below-par';
const DRIFT_RULE = 'erc4626/share-price-drift';
const SUPPLY_RULE = 'erc4626/supply-unavailable';
const NAV_RULE = 'erc4626/insufficient-nav';

const SPEC = 'https://eips.ethereum.org/EIPS/eip-4626';
const DEFAULT_TOLERANCE_BPS = 50;
/** NAV is summed across vaults at this many decimals. */
const NAV_DECIMALS = 18;

const SEL = {
  decimals: '0x313ce567',
  asset: '0x38d52e0f',
  totalAssets: '0x01e1d114',
  convertToAssets: '0x07a2d13a',
};

interface VaultDecl {
  path: string;
  chain: string;
  rpc: string;
  vault: string;
  shares: string;
  sharePrice?: string;
  toleranceBps: number;
}

/** One vault's state, in the standardized multi-currency yield report shape. */
export interface VaultReport {
  path: string;
  currency: string;
  chain: string;
  vault: string;
  underlying?: string;
  shares: string;
  /** Underlying assets the held shares redeem for. */
  assets?: string;
  totalAssets?: string;
  /** Underlying assets per whole share. */
  sharePrice?: string;
}

export interface CurrencyNav {
  currency: string;
  nav: string;
  supply?: string;
  coverage?: string;
}

export interface Erc4626Options extends RpcOptions {
  rules?: RuleOverrides;
  /** Query the vaults and Horizon. */
  probe?: boolean;
  horizonUrl?: string;
  /** Known Stellar supplies keyed `CODE:ISSUER` or `CODE`, skipping Horizon. */
  supplies?: Record<string, string>;
}

export interface Erc4626Result {
  diagnostics: Diagnostic[];
  vaults: VaultReport[];
  nav: CurrencyNav[];
}

function parseVault(raw: unknown, path: string, push: Push): VaultDecl | undefined {
  const bad = (message: string, suggestion: string): undefined => {
    push(INVALID_RULE, 'error', message, path, suggestion);
    return undefined;
  };
  if (!isRecord(raw))
    return bad('Collateral vault must be a table', 'Use { chain, vault, shares }.');
  if (raw.standard !== undefined && raw.standard !== 'erc4626') return undefined;
  if (!isString(raw.vault) || !EVM_ADDRESS.test(raw.vault)) {
    return bad('Vault address must be a 0x-prefixed 20-byte address', 'Copy the vault contract.');
  }
  const chain = isString(raw.chain) ? raw.chain.toLowerCase() : '';
  const rpc = raw.rpc ?? DEFAULT_EVM_RPC[chain];
  if (!isHttpsUrl(rpc)) {
    return bad(
      `Vault chain "${chain}" has no https RPC endpoint`,
      `Use one of ${Object.keys(DEFAULT_EVM_RPC).join(', ')} or set rpc = "https://...".`,
    );
  }
  const shares = typeof raw.shares === 'number' ? String(raw.shares) : raw.shares;
  if (!isString(shares) || parseUnits(shares, NAV_DECIMALS) === undefined) {
    return bad('Vault shares must be a non-negative decimal amount', 'E.g. shares = "1250000.5".');
  }
  const price = typeof raw.share_price === 'number' ? String(raw.share_price) : raw.share_price;
  if (price !== undefined && (!isString(price) || parseUnits(price, NAV_DECIMALS) === undefined)) {
    return bad('share_price must be a decimal amount of assets per share', 'E.g. "1.0425".');
  }
  const tolerance = raw.tolerance_bps ?? DEFAULT_TOLERANCE_BPS;
  if (typeof tolerance !== 'number' || !Number.isInteger(tolerance) || tolerance < 0) {
    return bad('tolerance_bps must be a non-negative integer', 'E.g. 50 for 0.5%.');
  }
  return {
    path,
    chain,
    rpc: rpc as string,
    vault: raw.vault,
    shares,
    ...(price === undefined ? {} : { sharePrice: price as string }),
    toleranceBps: tolerance,
  };
}

class PrecisionError extends Error {
  constructor(decimals: number) {
    super(`Vault shares have more than the vault's ${decimals} decimals`);
  }
}

const toNav = (amount: bigint, decimals: number): bigint =>
  decimals <= NAV_DECIMALS
    ? amount * 10n ** BigInt(NAV_DECIMALS - decimals)
    : amount / 10n ** BigInt(decimals - NAV_DECIMALS);

export class Erc4626VaultAuditor {
  constructor(
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly options: Erc4626Options = {},
  ) {}

  async audit(doc: Record<string, unknown>): Promise<Erc4626Result> {
    const diagnostics: Diagnostic[] = [];
    const push = diagnosticSink(diagnostics, SPEC, this.options.rules);
    const result: Erc4626Result = { diagnostics, vaults: [], nav: [] };
    const currencies = Array.isArray(doc.CURRENCIES) ? doc.CURRENCIES : [];
    for (const [i, currency] of currencies.entries()) {
      if (!isRecord(currency) || currency.collateral_vaults === undefined) continue;
      const base = `CURRENCIES[${i}].collateral_vaults`;
      if (!Array.isArray(currency.collateral_vaults)) {
        push(INVALID_RULE, 'error', 'collateral_vaults must be an array', base, 'Use [{ ... }].');
        continue;
      }
      const code = String(currency.code);
      let nav = 0n;
      let complete = this.options.probe === true;
      for (const [j, raw] of currency.collateral_vaults.entries()) {
        const decl = parseVault(raw, `${base}[${j}]`, push);
        if (decl === undefined) continue;
        const report: VaultReport = {
          path: decl.path,
          currency: code,
          chain: decl.chain,
          vault: decl.vault,
          shares: decl.shares,
        };
        result.vaults.push(report);
        if (!this.options.probe) continue;
        const assets = await this.probeVault(decl, report, push);
        if (assets === undefined) complete = false;
        else nav += assets;
      }
      if (complete && isString(currency.issuer)) {
        const asset = { code, issuer: currency.issuer };
        result.nav.push(await this.checkNav(doc, asset, nav, base, push));
      }
    }
    return result;
  }

  /** Probes one vault; returns the held shares' value at {@link NAV_DECIMALS}. */
  private async probeVault(
    decl: VaultDecl,
    report: VaultReport,
    push: Push,
  ): Promise<bigint | undefined> {
    const call = async (to: string, data: string): Promise<bigint> =>
      abiWords(await ethCall(this.fetchImpl, decl.rpc, to, data, this.options))[0] ?? 0n;
    let shareDecimals: number;
    let assetDecimals: number;
    let total: bigint;
    let assets: bigint;
    let perShare: bigint;
    let sharesRaw: bigint | undefined;
    try {
      shareDecimals = Number(await call(decl.vault, SEL.decimals));
      const underlying = `0x${(await call(decl.vault, SEL.asset)).toString(16).padStart(40, '0')}`;
      report.underlying = underlying;
      assetDecimals = Number(await call(underlying, SEL.decimals));
      if (shareDecimals > 36 || assetDecimals > 36) throw new Error('implausible decimals');
      sharesRaw = parseUnits(decl.shares, shareDecimals);
      if (sharesRaw === undefined) throw new PrecisionError(shareDecimals);
      total = await call(decl.vault, SEL.totalAssets);
      assets = await call(decl.vault, SEL.convertToAssets + encodeUint256(sharesRaw));
      const one = 10n ** BigInt(shareDecimals);
      perShare = await call(decl.vault, SEL.convertToAssets + encodeUint256(one));
    } catch (error) {
      if (error instanceof PrecisionError) {
        push(
          INVALID_RULE,
          'error',
          error.message,
          decl.path,
          'Round shares to the vault decimals.',
        );
        return undefined;
      }
      push(
        RPC_RULE,
        'warning',
        `Could not read vault ${decl.vault} on ${decl.chain} (${errorMessage(error)})`,
        decl.path,
        'Check the RPC endpoint and that the address is an ERC-4626 vault, or retry later.',
      );
      return undefined;
    }
    report.assets = formatUnits(assets, assetDecimals);
    report.totalAssets = formatUnits(total, assetDecimals);
    report.sharePrice = formatUnits(perShare, assetDecimals);
    if (assets > total) {
      push(
        ACCOUNTING_RULE,
        'error',
        `Held shares redeem for ${report.assets} but the vault reports totalAssets ${report.totalAssets}`,
        decl.path,
        'convertToAssets and totalAssets disagree; the vault accounting cannot be trusted.',
      );
    }
    const par = 10n ** BigInt(assetDecimals);
    if (perShare < par) {
      push(
        PAR_RULE,
        'warning',
        `Vault share price ${report.sharePrice} is below par (1.0); the vault has lost value`,
        decl.path,
        'Re-check the reserve: a vault trading below its deposit value may be depegged.',
      );
    }
    if (decl.sharePrice !== undefined) {
      const declared = parseUnits(decl.sharePrice, NAV_DECIMALS) as bigint;
      const live = toNav(perShare, assetDecimals);
      const diff = declared > live ? declared - live : live - declared;
      const drift = live === 0n ? undefined : (diff * 10000n) / live;
      if (drift === undefined || drift > BigInt(decl.toleranceBps)) {
        push(
          DRIFT_RULE,
          'warning',
          `Declared share_price ${decl.sharePrice} differs from the live rate ${report.sharePrice}` +
            (drift === undefined ? '' : ` by ${formatBps(drift)}`),
          decl.path,
          'Update the pricing formula so it tracks convertToAssets() as yield accrues.',
        );
      }
    }
    return toNav(assets, assetDecimals);
  }

  private async checkNav(
    doc: Record<string, unknown>,
    asset: StellarAsset,
    nav: bigint,
    path: string,
    push: Push,
  ): Promise<CurrencyNav> {
    const out: CurrencyNav = { currency: asset.code, nav: formatUnits(nav, NAV_DECIMALS) };
    let supply: bigint;
    try {
      supply = await stellarSupply(
        this.fetchImpl,
        horizonFor(doc, this.options.horizonUrl),
        asset,
        this.options.supplies,
        this.options.timeoutMs,
      );
    } catch (error) {
      push(
        SUPPLY_RULE,
        'warning',
        `Could not read the Stellar supply of ${asset.code} (${errorMessage(error)})`,
        path,
        'Check HORIZON_URL; NAV backing cannot be computed without the issued supply.',
      );
      return out;
    }
    out.supply = formatUnits(supply, AMOUNT_SCALE);
    if (supply === 0n) return out;
    out.coverage = formatBps(ratioBps(nav, NAV_DECIMALS, supply, AMOUNT_SCALE));
    if (!covers(nav, NAV_DECIMALS, supply, AMOUNT_SCALE)) {
      push(
        NAV_RULE,
        'error',
        `${asset.code} vault NAV ${out.nav} covers only ${out.coverage} of supply ${out.supply}`,
        path,
        'Issued supply exceeds the vault-backed net asset value; add collateral or burn supply.',
      );
    }
    return out;
  }
}

export async function auditErc4626Vaults(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: Erc4626Options = {},
): Promise<Erc4626Result> {
  return new Erc4626VaultAuditor(fetchImpl, options).audit(doc);
}

/** Exposed for callers that build their own calldata. */
export const erc4626Selectors: Readonly<Record<string, string>> = SEL;

export const erc4626Rules: Rule[] = [
  bridgeRule(INVALID_RULE, 'error', 'collateral_vaults entries must be well formed'),
  bridgeRule(RPC_RULE, 'warning', 'ERC-4626 vaults must be readable over RPC'),
  bridgeRule(ACCOUNTING_RULE, 'error', 'Held vault shares must not exceed totalAssets'),
  bridgeRule(PAR_RULE, 'warning', 'Vault share price should not fall below par'),
  bridgeRule(DRIFT_RULE, 'warning', 'Declared share prices must track convertToAssets'),
  bridgeRule(SUPPLY_RULE, 'warning', 'The Stellar supply must be readable to check NAV'),
  bridgeRule(NAV_RULE, 'error', 'Vault NAV must cover the issued Stellar supply'),
];

export const erc4626RuleIds: readonly string[] = erc4626Rules.map((r) => r.id);
