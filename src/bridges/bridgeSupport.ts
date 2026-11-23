/**
 * Shared plumbing for the cross-chain bridge verifiers (Chainlink PoR,
 * Solana escrow, ERC-4626 vaults, Wormhole VAAs): a small JSON-RPC client,
 * EVM `eth_call` / ABI word decoding, exact decimal scaling and the Stellar
 * supply lookup every reserve check compares against.
 *
 * All amounts are BigInt in the asset's smallest unit. Comparisons across
 * chains cross-multiply instead of dividing, so a 9-decimal SPL balance and a
 * 7-decimal Stellar supply are compared without any rounding.
 */

import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';
import { isAccountId, isContractId, isHttpsUrl, isString } from '../predicates.js';
import { DEFAULT_HORIZON } from '../protocols/clawbackAuditGenerator.js';
import {
  AMOUNT_SCALE,
  fetchWithTimeout,
  isRecord,
  severityFor,
  toScaled,
  trimTrailingSlashes,
} from '../protocols/verifierSupport.js';
import { bytesToBigInt, hexToBytes } from './evmCrypto.js';

/** Public JSON-RPC endpoints used when a declaration names a chain but no `rpc`. */
export const DEFAULT_EVM_RPC: Readonly<Record<string, string>> = {
  ethereum: 'https://ethereum-rpc.publicnode.com',
  arbitrum: 'https://arbitrum-one-rpc.publicnode.com',
  avalanche: 'https://avalanche-c-chain-rpc.publicnode.com',
  polygon: 'https://polygon-bor-rpc.publicnode.com',
  base: 'https://base-rpc.publicnode.com',
  optimism: 'https://optimism-rpc.publicnode.com',
};

export const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/;

/** A JSON-RPC failure; `rateLimited` distinguishes throttling from outages. */
export class RpcError extends Error {
  constructor(
    message: string,
    readonly rateLimited = false,
  ) {
    super(message);
    this.name = 'RpcError';
  }
}

export interface RpcOptions {
  timeoutMs?: number;
  /** Retries after HTTP 429 or a rate-limit JSON-RPC error. Default 1. */
  retries?: number;
  /** Wait before each retry. Default 250ms. */
  retryDelayMs?: number;
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

async function rpcOnce(
  fetchImpl: typeof fetch,
  url: string,
  method: string,
  params: unknown[],
  timeoutMs: number | undefined,
): Promise<unknown> {
  const res = await fetchWithTimeout(
    fetchImpl,
    url,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    },
    timeoutMs,
  );
  if (res.status === 429) throw new RpcError(`${method} was rate limited (HTTP 429)`, true);
  if (!res.ok) throw new RpcError(`${method} returned HTTP ${res.status}`);
  const body: unknown = await res.json().catch(() => undefined);
  if (!isRecord(body)) throw new RpcError(`${method} returned a non JSON-RPC body`);
  if (isRecord(body.error)) {
    const code = body.error.code;
    const text = isString(body.error.message) ? body.error.message : 'unknown error';
    throw new RpcError(`${method} failed: ${text}`, code === 429 || code === -32005);
  }
  if (!('result' in body)) throw new RpcError(`${method} returned no result`);
  return body.result;
}

/** One JSON-RPC 2.0 call, retrying only when the node says it is rate limiting us. */
export async function jsonRpc(
  fetchImpl: typeof fetch,
  url: string,
  method: string,
  params: unknown[],
  options: RpcOptions = {},
): Promise<unknown> {
  const retries = options.retries ?? 1;
  for (let attempt = 0; ; attempt++) {
    try {
      return await rpcOnce(fetchImpl, url, method, params, options.timeoutMs);
    } catch (error) {
      if (!(error instanceof RpcError && error.rateLimited) || attempt >= retries) throw error;
      await sleep(options.retryDelayMs ?? 250);
    }
  }
}

/** `eth_call` against `latest`, returning the raw return data. */
export async function ethCall(
  fetchImpl: typeof fetch,
  rpc: string,
  to: string,
  data: string,
  options: RpcOptions = {},
): Promise<Uint8Array> {
  const result = await jsonRpc(fetchImpl, rpc, 'eth_call', [{ to, data }, 'latest'], options);
  const bytes = isString(result) ? hexToBytes(result) : undefined;
  if (bytes === undefined) throw new RpcError('eth_call returned malformed hex');
  if (bytes.length === 0) throw new RpcError(`eth_call to ${to} returned no data (no contract?)`);
  return bytes;
}

/** Splits ABI return data into 32-byte unsigned words. */
export function abiWords(data: Uint8Array): bigint[] {
  const words: bigint[] = [];
  for (let i = 0; i + 32 <= data.length; i += 32) words.push(bytesToBigInt(data.slice(i, i + 32)));
  return words;
}

/** Reinterprets an ABI word as a two's complement `int256`. */
export function toInt256(word: bigint): bigint {
  return word >= 1n << 255n ? word - (1n << 256n) : word;
}

export function encodeUint256(value: bigint): string {
  return value.toString(16).padStart(64, '0');
}

/** Parses a non-negative decimal string into base units; `undefined` if it has too many decimals. */
export function parseUnits(value: unknown, decimals: number): bigint | undefined {
  const text = typeof value === 'number' && Number.isFinite(value) ? String(value) : value;
  if (!isString(text)) return undefined;
  const m = /^(\d+)(?:\.(\d+))?$/.exec(text.trim());
  if (!m) return undefined;
  const fraction = m[2] ?? '';
  if (fraction.length > decimals) return undefined;
  return BigInt(m[1] as string) * 10n ** BigInt(decimals) + BigInt(fraction.padEnd(decimals, '0'));
}

export function formatUnits(value: bigint, decimals: number): string {
  const negative = value < 0n;
  const abs = negative ? -value : value;
  const base = 10n ** BigInt(decimals);
  const fraction = (abs % base).toString().padStart(decimals, '0').replace(/0+$/, '');
  return `${negative ? '-' : ''}${abs / base}${fraction ? `.${fraction}` : ''}`;
}

/** `a / b` with both sides at their own decimals, in basis points, rounded down. */
export function ratioBps(a: bigint, aDecimals: number, b: bigint, bDecimals: number): bigint {
  return (a * 10n ** BigInt(bDecimals) * 10000n) / (b * 10n ** BigInt(aDecimals));
}

/** Exact `a >= b` across decimal scales. */
export function covers(a: bigint, aDecimals: number, b: bigint, bDecimals: number): boolean {
  return a * 10n ** BigInt(bDecimals) >= b * 10n ** BigInt(aDecimals);
}

export function formatBps(bps: bigint): string {
  return `${formatUnits(bps, 2)}%`;
}

export interface StellarAsset {
  code: string;
  issuer: string;
}

/** Resolves `CODE:ISSUER`, or a bare `CODE` declared once in `CURRENCIES`. */
export function resolveAsset(doc: Record<string, unknown>, ref: unknown): StellarAsset | undefined {
  if (!isString(ref)) return undefined;
  const [code, issuer] = ref.split(':');
  if (code === undefined || !/^[A-Za-z0-9]{1,12}$/.test(code)) return undefined;
  if (issuer !== undefined) return isAccountId(issuer) ? { code, issuer } : undefined;
  const matches = (Array.isArray(doc.CURRENCIES) ? doc.CURRENCIES : []).filter(
    (c) => isRecord(c) && c.code === code && isAccountId(c.issuer),
  );
  return matches.length === 1 && isRecord(matches[0])
    ? { code, issuer: matches[0].issuer as string }
    : undefined;
}

export function horizonFor(doc: Record<string, unknown>, override?: string): string {
  const url = override ?? (isHttpsUrl(doc.HORIZON_URL) ? (doc.HORIZON_URL as string) : undefined);
  return trimTrailingSlashes(url ?? DEFAULT_HORIZON);
}

const SUPPLY_FIELDS = [
  'claimable_balances_amount',
  'liquidity_pools_amount',
  'contracts_amount',
] as const;

/**
 * Total issued supply of a Stellar asset in stroops (7 decimals): trustline
 * balances plus claimable balances, liquidity pools and Soroban contracts.
 * `supplies` (keyed `CODE:ISSUER` or `CODE`) short-circuits Horizon so audits
 * can run offline against provided evidence.
 */
export async function stellarSupply(
  fetchImpl: typeof fetch,
  horizon: string,
  asset: StellarAsset,
  supplies: Record<string, string> | undefined,
  timeoutMs?: number,
): Promise<bigint> {
  const given = supplies?.[`${asset.code}:${asset.issuer}`] ?? supplies?.[asset.code];
  if (given !== undefined) {
    const scaled = toScaled(given);
    if (scaled === undefined) throw new Error(`provided supply "${given}" is not a decimal`);
    return scaled;
  }
  const url = `${horizon}/assets?asset_code=${encodeURIComponent(asset.code)}&asset_issuer=${asset.issuer}&limit=1`;
  const res = await fetchWithTimeout(fetchImpl, url, {}, timeoutMs);
  if (!res.ok) throw new Error(`Horizon /assets returned HTTP ${res.status}`);
  const body: unknown = await res.json();
  const records = isRecord(body) && isRecord(body._embedded) ? body._embedded.records : undefined;
  if (!Array.isArray(records)) throw new Error('Horizon /assets returned an unexpected body');
  const record: unknown = records[0];
  if (!isRecord(record)) return 0n;
  const parts: unknown[] = isRecord(record.balances)
    ? Object.values(record.balances)
    : [record.amount];
  for (const field of SUPPLY_FIELDS) parts.push(record[field]);
  let total = 0n;
  for (const part of parts) {
    if (part === undefined) continue;
    const scaled = isString(part) ? toScaled(part) : undefined;
    if (scaled === undefined) throw new Error('Horizon /assets returned a malformed amount');
    total += scaled;
  }
  return total;
}

export { AMOUNT_SCALE };

export type Push = (
  rule: string,
  fallback: Severity,
  message: string,
  path: string,
  suggestion: string,
) => void;

/** A diagnostic sink that honours `--off` / `--error` / `--warn` overrides. */
export function diagnosticSink(
  out: Diagnostic[],
  helpUri: string,
  rules: RuleOverrides | undefined,
): Push {
  return (rule, fallback, message, path, suggestion) => {
    const severity = severityFor(rule, fallback, rules);
    if (severity === undefined) return;
    out.push({ rule, severity, category: 'network', message, path, helpUri, suggestion });
  };
}

export const bridgeRule = (id: string, severity: Severity, description: string): Rule => ({
  id,
  category: 'network',
  severity,
  description,
  run() {},
});

/**
 * Shared parsing for `[[BRIDGES]]` tables used by the bridge auditors.
 */
export type BridgeChain = 'soroban' | 'evm' | 'solana';

export interface BridgeDecl {
  index: number;
  name: string;
  chain: BridgeChain | undefined;
  contract: unknown;
  raw: Record<string, unknown>;
}

export function bridgesOf(doc: Record<string, unknown>): BridgeDecl[] {
  const list = doc.BRIDGES;
  if (!Array.isArray(list)) return [];
  const out: BridgeDecl[] = [];
  list.forEach((raw, index) => {
    if (!isRecord(raw)) return;
    const chain = typeof raw.CHAIN === 'string' ? raw.CHAIN.toLowerCase() : '';
    out.push({
      index,
      name: typeof raw.NAME === 'string' && raw.NAME !== '' ? raw.NAME : `bridge #${index + 1}`,
      chain: chain === 'soroban' || chain === 'evm' || chain === 'solana' ? chain : undefined,
      contract: raw.CONTRACT,
      raw,
    });
  });
  return out;
}

/** Address format check per chain: C... strkey, 0x + 40 hex, or a base58 public key. */
export function isValidBridgeContract(chain: BridgeChain, contract: unknown): boolean {
  if (typeof contract !== 'string') return false;
  if (chain === 'soroban') return isContractId(contract);
  if (chain === 'evm') return /^0x[0-9a-fA-F]{40}$/.test(contract);
  return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(contract);
}
