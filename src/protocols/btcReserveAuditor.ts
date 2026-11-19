/**
 * Bitcoin custodial reserve UTXO auditor.
 *
 * Runs under opt-in `--audit-btc-reserves`; UTXO and supply lookups only run
 * with `--check-network`.
 *
 * Anchors issuing wrapped BTC list their custody addresses in a currency's
 * SEP-1 `collateral_addresses`. Counting mempool (0-conf) or shallow outputs
 * as backing reports reserves a re-org or a double spend can take away, so
 * only outputs with at least `minConfirmations` (default 6) count. The
 * confirmed total is reconciled against the asset's supply on Stellar with
 * exact integer math: 1 satoshi = 10^-8 BTC and 1 stroop = 10^-7 units, so
 * one stroop of wrapped BTC needs 10 satoshis of reserve.
 *
 * UTXO and supply sources are injected; the defaults use an Esplora API and
 * the issuer's Horizon `/assets` record.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isAccountId, isHttpsUrl, isString } from '../predicates.js';
import {
  errorMessage,
  fetchWithTimeout,
  isRecord,
  severityFor,
  toScaled,
} from './verifierSupport.js';

const ADDRESS_RULE = 'btcreserve/invalid-address';
const NETWORK_RULE = 'btcreserve/network-mismatch';
const NO_ADDRESSES_RULE = 'btcreserve/no-reserve-addresses';
const UNCONFIRMED_RULE = 'btcreserve/unconfirmed-excluded';
const DUST_RULE = 'btcreserve/dust-utxos';
const SWEEP_RULE = 'btcreserve/pending-sweep';
const DEFICIT_RULE = 'btcreserve/reserve-deficit';
const LOOKUP_RULE = 'btcreserve/lookup-failed';

const SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0001.md';
const PUBLIC_PASSPHRASE = 'Public Global Stellar Network ; September 2015';
/** Satoshis per stroop of a 7-decimal Stellar asset tracking BTC 1:1. */
export const SATS_PER_STROOP = 10n;
/** Outputs below this many satoshis cost more to spend than they are worth. */
export const DUST_LIMIT_SATS = 546;

export type BtcAddressType = 'p2pkh' | 'p2sh' | 'p2wpkh' | 'p2wsh' | 'p2tr';

export interface BtcAddressInfo {
  type: BtcAddressType;
  network: 'mainnet' | 'testnet';
}

export interface Utxo {
  txid: string;
  vout: number;
  value: number;
  confirmations: number;
  /** Spent by a transaction still in the mempool (e.g. a sweep). */
  spentInMempool?: boolean;
}

export type UtxoProvider = (address: string) => Promise<Utxo[]>;
/** Total supply of `code:issuer` in stroops. */
export type SupplyProvider = (code: string, issuer: string) => Promise<bigint>;

export interface BtcReserveOptions {
  rules?: RuleOverrides;
  probe?: boolean;
  minConfirmations?: number;
  /** Count dust outputs toward reserves. Defaults to false. */
  countDust?: boolean;
  utxoProvider?: UtxoProvider;
  supplyProvider?: SupplyProvider;
  esploraUrl?: string;
  timeoutMs?: number;
}

export interface ReserveReport {
  code: string;
  issuer: string;
  confirmedSats: bigint;
  unconfirmedSats: bigint;
  supplyStroops?: bigint;
  /** Confirmed reserve minus required reserve, in satoshis (negative = deficit). */
  deltaSats?: bigint;
}

export interface BtcReserveResult {
  diagnostics: Diagnostic[];
  reports: ReserveReport[];
}

const BECH32 = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function bech32Polymod(values: number[]): number {
  const gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    gen.forEach((g, i) => {
      if ((top >>> i) & 1) chk ^= g;
    });
  }
  return chk >>> 0;
}

function decodeSegwit(address: string): BtcAddressInfo | undefined {
  if (address !== address.toLowerCase() && address !== address.toUpperCase()) return undefined;
  const a = address.toLowerCase();
  const sep = a.lastIndexOf('1');
  const hrp = a.slice(0, sep);
  if (hrp !== 'bc' && hrp !== 'tb') return undefined;
  const data = [...a.slice(sep + 1)].map((c) => BECH32.indexOf(c));
  if (data.length < 7 || data.some((d) => d < 0)) return undefined;
  const expanded = [...hrp].map((c) => c.charCodeAt(0) >> 5);
  expanded.push(0, ...[...hrp].map((c) => c.charCodeAt(0) & 31));
  const check = bech32Polymod([...expanded, ...data]);
  const version = data[0] as number;
  // BIP-173 (bech32) for v0, BIP-350 (bech32m) for v1+.
  if (check !== (version === 0 ? 1 : 0x2bc830a3)) return undefined;
  let acc = 0;
  let bits = 0;
  const program: number[] = [];
  for (const d of data.slice(1, -6)) {
    acc = (acc << 5) | d;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      program.push((acc >> bits) & 0xff);
    }
  }
  if (bits >= 5 || (acc & ((1 << bits) - 1)) !== 0) return undefined;
  const network = hrp === 'bc' ? 'mainnet' : 'testnet';
  if (version === 0 && program.length === 20) return { type: 'p2wpkh', network };
  if (version === 0 && program.length === 32) return { type: 'p2wsh', network };
  if (version === 1 && program.length === 32) return { type: 'p2tr', network };
  return undefined;
}

async function decodeBase58Check(address: string): Promise<BtcAddressInfo | undefined> {
  let n = 0n;
  for (const c of address) {
    const i = BASE58.indexOf(c);
    if (i < 0) return undefined;
    n = n * 58n + BigInt(i);
  }
  const bytes: number[] = [];
  for (; n > 0n; n >>= 8n) bytes.unshift(Number(n & 0xffn));
  for (const c of address) {
    if (c !== '1') break;
    bytes.unshift(0);
  }
  if (bytes.length !== 25) return undefined;
  const payload = new Uint8Array(bytes.slice(0, 21));
  const first = new Uint8Array(await crypto.subtle.digest('SHA-256', payload));
  const second = new Uint8Array(await crypto.subtle.digest('SHA-256', first));
  if (bytes.slice(21).some((b, i) => b !== second[i])) return undefined;
  switch (bytes[0]) {
    case 0x00:
      return { type: 'p2pkh', network: 'mainnet' };
    case 0x05:
      return { type: 'p2sh', network: 'mainnet' };
    case 0x6f:
      return { type: 'p2pkh', network: 'testnet' };
    case 0xc4:
      return { type: 'p2sh', network: 'testnet' };
    default:
      return undefined;
  }
}

/** Validates a P2PKH, P2SH, P2WPKH, P2WSH or P2TR address including its checksum. */
export async function parseBtcAddress(address: string): Promise<BtcAddressInfo | undefined> {
  if (/^(bc|tb)1/i.test(address)) return decodeSegwit(address);
  return decodeBase58Check(address);
}

/** Converts a Stellar amount string (7 decimals) to stroops. */
export function toStroops(amount: string): bigint | undefined {
  return toScaled(amount);
}

/** Formats satoshis as BTC with 8 decimals, keeping the sign. */
export function formatBtc(sats: bigint): string {
  const sign = sats < 0n ? '-' : '';
  const abs = sats < 0n ? -sats : sats;
  return `${sign}${abs / 100000000n}.${(abs % 100000000n).toString().padStart(8, '0')}`;
}

function isBtcCurrency(entry: Record<string, unknown>): boolean {
  const anchored = String(entry.anchor_asset ?? '').toUpperCase();
  const code = String(entry.code ?? '').toUpperCase();
  return anchored === 'BTC' || /^[A-Z]?BTC$/.test(code);
}

export class BtcReserveUtxoAuditor {
  private horizon = 'https://horizon.stellar.org';

  constructor(
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly options: BtcReserveOptions = {},
  ) {}

  async audit(doc: Record<string, unknown>): Promise<BtcReserveResult> {
    const diagnostics: Diagnostic[] = [];
    const reports: ReserveReport[] = [];
    const push = (
      rule: string,
      fallback: 'error' | 'warning' | 'info',
      message: string,
      path: string,
      suggestion: string,
    ): void => {
      const severity = severityFor(rule, fallback, this.options.rules);
      if (severity === undefined) return;
      diagnostics.push({
        rule,
        severity,
        category: 'currencies',
        message,
        path,
        helpUri: SPEC,
        suggestion,
      });
    };
    const isPublic = doc.NETWORK_PASSPHRASE === PUBLIC_PASSPHRASE;
    if (isHttpsUrl(doc.HORIZON_URL)) this.horizon = String(doc.HORIZON_URL).replace(/\/+$/, '');
    const currencies = Array.isArray(doc.CURRENCIES) ? doc.CURRENCIES : [];

    for (const [i, entry] of currencies.entries()) {
      if (!isRecord(entry) || !isBtcCurrency(entry)) continue;
      const path = `CURRENCIES[${i}]`;
      const raw = entry.collateral_addresses;
      if (!Array.isArray(raw) || raw.length === 0) {
        push(
          NO_ADDRESSES_RULE,
          'warning',
          `${path} is a BTC-backed asset but declares no collateral_addresses`,
          `${path}.collateral_addresses`,
          'List every custody address so holders can verify the reserve.',
        );
        continue;
      }
      const addresses: string[] = [];
      for (const [j, address] of raw.entries()) {
        const info = isString(address) ? await parseBtcAddress(address) : undefined;
        const at = `${path}.collateral_addresses[${j}]`;
        if (!info) {
          push(
            ADDRESS_RULE,
            'error',
            `${at} is not a valid Bitcoin address`,
            at,
            'Use a P2PKH (1...), P2SH (3...), P2WPKH (bc1q...) or P2TR (bc1p...) address.',
          );
        } else if (isPublic && info.network === 'testnet') {
          push(
            NETWORK_RULE,
            'error',
            `${at} is a Bitcoin testnet address but the file targets the Stellar public network`,
            at,
            'Publish mainnet custody addresses for a public-network asset.',
          );
        } else addresses.push(address as string);
      }
      if (this.options.probe && addresses.length > 0) {
        reports.push(await this.reconcile(entry, path, addresses, push));
      }
    }
    return { diagnostics, reports };
  }

  private async reconcile(
    entry: Record<string, unknown>,
    path: string,
    addresses: string[],
    push: (
      rule: string,
      fallback: 'error' | 'warning' | 'info',
      message: string,
      path: string,
      suggestion: string,
    ) => void,
  ): Promise<ReserveReport> {
    const minConf = this.options.minConfirmations ?? 6;
    const code = String(entry.code ?? '');
    const issuer = String(entry.issuer ?? '');
    const report: ReserveReport = { code, issuer, confirmedSats: 0n, unconfirmedSats: 0n };
    let dust = 0;
    let lookupFailed = false;

    for (const address of addresses) {
      let utxos: Utxo[];
      try {
        utxos = await (this.options.utxoProvider ?? this.esplora.bind(this))(address);
      } catch (error) {
        lookupFailed = true;
        push(
          LOOKUP_RULE,
          'warning',
          `UTXOs for ${address} could not be fetched (${errorMessage(error)})`,
          `${path}.collateral_addresses`,
          'Retry, or point --audit-btc-reserves at a reachable Esplora/Electrum backend.',
        );
        continue;
      }
      for (const u of utxos) {
        const value = BigInt(u.value);
        if (u.spentInMempool) {
          push(
            SWEEP_RULE,
            'warning',
            `${u.txid}:${u.vout} (${formatBtc(value)} BTC) on ${address} is being spent by an unconfirmed transaction`,
            `${path}.collateral_addresses`,
            'Outputs with a pending spend are not counted until the sweep confirms.',
          );
          report.unconfirmedSats += value;
        } else if (u.confirmations < minConf) {
          report.unconfirmedSats += value;
        } else if (u.value < DUST_LIMIT_SATS && !this.options.countDust) {
          dust++;
        } else report.confirmedSats += value;
      }
    }

    if (report.unconfirmedSats > 0n) {
      push(
        UNCONFIRMED_RULE,
        'info',
        `${formatBtc(report.unconfirmedSats)} BTC for ${code} has fewer than ${minConf} confirmations or a pending spend and is not counted`,
        `${path}.collateral_addresses`,
        `Only outputs with at least ${minConf} confirmations back the wrapped supply.`,
      );
    }
    if (dust > 0) {
      push(
        DUST_RULE,
        'info',
        `${dust} dust output${dust === 1 ? '' : 's'} below ${DUST_LIMIT_SATS} sats for ${code} not counted`,
        `${path}.collateral_addresses`,
        'Consolidate dust outputs; they cost more to spend than they hold.',
      );
    }
    if (lookupFailed || !isAccountId(issuer)) return report;

    try {
      const supply = await (this.options.supplyProvider ?? this.horizonSupply.bind(this))(
        code,
        issuer,
      );
      report.supplyStroops = supply;
      report.deltaSats = report.confirmedSats - supply * SATS_PER_STROOP;
    } catch (error) {
      push(
        LOOKUP_RULE,
        'warning',
        `Supply of ${code} could not be fetched (${errorMessage(error)})`,
        path,
        'Make sure HORIZON_URL is reachable.',
      );
      return report;
    }
    if (report.deltaSats < 0n) {
      push(
        DEFICIT_RULE,
        'error',
        `${code} is under-reserved by ${formatBtc(-report.deltaSats)} BTC (${-report.deltaSats} sats): ${formatBtc(report.confirmedSats)} BTC confirmed for ${formatBtc(report.supplyStroops * SATS_PER_STROOP)} BTC issued`,
        path,
        'Top up the custody addresses or burn excess supply until confirmed reserves cover issuance.',
      );
    }
    return report;
  }

  private async esplora(address: string): Promise<Utxo[]> {
    const base = (this.options.esploraUrl ?? 'https://blockstream.info/api').replace(/\/+$/, '');
    const get = async (path: string): Promise<Response> => {
      const res = await fetchWithTimeout(
        this.fetchImpl,
        `${base}${path}`,
        {},
        this.options.timeoutMs,
      );
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res;
    };
    const tip = Number(await (await get('/blocks/tip/height')).text());
    const body: unknown = await (await get(`/address/${address}/utxo`)).json();
    if (!Array.isArray(body) || !Number.isFinite(tip))
      throw new Error('malformed Esplora response');
    return body.filter(isRecord).map((u) => {
      const status = isRecord(u.status) ? u.status : {};
      const height = typeof status.block_height === 'number' ? status.block_height : undefined;
      return {
        txid: String(u.txid),
        vout: Number(u.vout),
        value: Number(u.value),
        confirmations: status.confirmed === true && height !== undefined ? tip - height + 1 : 0,
      };
    });
  }

  private async horizonSupply(code: string, issuer: string): Promise<bigint> {
    const url = `${this.horizon}/assets?asset_code=${encodeURIComponent(code)}&asset_issuer=${issuer}`;
    const res = await fetchWithTimeout(this.fetchImpl, url, {}, this.options.timeoutMs);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const body: unknown = await res.json();
    const records = isRecord(body) && isRecord(body._embedded) ? body._embedded.records : undefined;
    const asset = Array.isArray(records) ? records[0] : undefined;
    if (!isRecord(asset)) throw new Error('asset not found on Horizon');
    const balances = isRecord(asset.balances) ? asset.balances : {};
    let total = 0n;
    for (const value of [
      ...Object.values(balances),
      asset.claimable_balances_amount,
      asset.liquidity_pools_amount,
      asset.contracts_amount,
    ]) {
      if (isString(value)) total += toStroops(value) ?? 0n;
    }
    return total;
  }
}

export async function auditBtcReserves(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: BtcReserveOptions = {},
): Promise<BtcReserveResult> {
  return new BtcReserveUtxoAuditor(fetchImpl, options).audit(doc);
}

const def = (id: string, severity: 'error' | 'warning' | 'info', description: string): Rule => ({
  id,
  category: 'currencies',
  severity,
  description,
  run() {},
});

export const btcReserveRules: Rule[] = [
  def(ADDRESS_RULE, 'error', 'BTC collateral addresses must be valid Bitcoin addresses'),
  def(NETWORK_RULE, 'error', 'BTC collateral addresses must match the Stellar network'),
  def(NO_ADDRESSES_RULE, 'warning', 'BTC-backed assets should declare collateral_addresses'),
  def(UNCONFIRMED_RULE, 'info', 'Shallow or unconfirmed UTXOs are not counted as reserves'),
  def(DUST_RULE, 'info', 'Dust UTXOs are not counted as reserves'),
  def(SWEEP_RULE, 'warning', 'Reserve UTXOs with a pending spend are not counted'),
  def(DEFICIT_RULE, 'error', 'Confirmed BTC reserves must cover the wrapped supply'),
  def(LOOKUP_RULE, 'warning', 'Reserve and supply lookups should succeed'),
];

export const btcReserveRuleIds: readonly string[] = btcReserveRules.map((r) => r.id);
