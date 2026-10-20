/**
 * Multi-chain cryptographic proof-of-reserve auditor.
 *
 * SEP-1 `[[CURRENCIES]]` entries can publish `collateral_addresses` on
 * external chains. Holding a reserve address is not the same as holding enough
 * reserve: if the balances behind those addresses are lower than the asset's
 * circulating Stellar supply, holders cannot redeem every token.
 *
 * This module infers the chain from each address (or an explicit
 * `collateral_chain`/`origin_network` hint), reads the native or token balance
 * over a public RPC/REST endpoint, reads the Stellar supply from Horizon, and
 * compares the two with exact BigInt arithmetic. It is opt-in under
 * `--check-network --audit-reserves`; unreachable endpoints degrade to silence
 * so a flaky RPC never produces a false insolvency finding.
 */
import { StrKey } from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';
import { specUrl } from '../spec.js';
import { isString } from '../predicates.js';
import { horizonUrlFor } from '../network-checks.js';
import { fetchMintedSupply, scaleAmount, stroopsFromDecimal } from '../validators/bridgeReserve.js';

export const COLLATERAL_RESERVE_DEFICIT_RULE = 'security/collateral-reserve-deficit';
export const UNSUPPORTED_COLLATERAL_CHAIN_RULE = 'security/unsupported-collateral-chain';
export const SECURITY_COLLATERAL_RESERVE_DEFICIT = COLLATERAL_RESERVE_DEFICIT_RULE;
export const SECURITY_UNSUPPORTED_COLLATERAL_CHAIN = UNSUPPORTED_COLLATERAL_CHAIN_RULE;
export const RESERVE_DEFICIT_RULE = COLLATERAL_RESERVE_DEFICIT_RULE;

export const DEFAULT_ETHEREUM_RPC_URL = 'https://ethereum-rpc.publicnode.com';
export const DEFAULT_BITCOIN_API_URL = 'https://blockstream.info/api';
export const DEFAULT_SOLANA_RPC_URL = 'https://api.mainnet-beta.solana.com';

const STELLAR_DECIMALS = 7;

export type CollateralChain = 'ethereum' | 'bitcoin' | 'solana' | 'stellar' | 'unsupported';

export interface CollateralAccount {
  address: string;
  chain: CollateralChain;
  /** Dotted path to the address in the TOML file. */
  path: string;
  /** `CURRENCIES[n]` path shared by addresses on the same entry. */
  entryPath: string;
  entryIndex: number;
  code?: string;
  issuer?: string;
  /** Token contract/mint when the reserve is not the chain's native asset. */
  tokenAddress?: string;
  /** Decimal precision of the reserve amount. */
  decimals?: number;
}

export interface ProofOfReserveOptions {
  rules?: RuleOverrides;
  fetchImpl?: typeof fetch;
  fetch?: typeof fetch;
  horizonUrl?: string;
  evmRpcUrl?: string;
  ethereumRpcUrl?: string;
  rpcUrl?: string;
  bitcoinApiUrl?: string;
  bitcoinRpcUrl?: string;
  solanaRpcUrl?: string;
  rpcUrls?: Partial<Record<'ethereum' | 'bitcoin' | 'solana' | 'stellar', string>>;
  /** Token contract/mint keyed by chain, when it is not in the TOML entry. */
  tokenAddresses?: Partial<Record<string, string>>;
  /** Reserve decimal precision keyed by chain. */
  decimals?: Partial<Record<string, number>>;
}

export interface ReserveSnapshot {
  chain: CollateralChain;
  address: string;
  amount: bigint;
  decimals: number;
  /** `native`, `token`, or `unsupported`. */
  kind: 'native' | 'token' | 'unsupported';
  tokenAddress?: string;
}

/* ------------------------------------------------------------------ *
 * Address and declaration parsing
 * ------------------------------------------------------------------ */

const CHAIN_ALIASES: Record<string, CollateralChain> = {
  eth: 'ethereum',
  ethereum: 'ethereum',
  evm: 'ethereum',
  erc20: 'ethereum',
  'erc-20': 'ethereum',
  eip155: 'ethereum',
  btc: 'bitcoin',
  bitcoin: 'bitcoin',
  sol: 'solana',
  solana: 'solana',
  stellar: 'stellar',
  xlm: 'stellar',
  stellarxlm: 'stellar',
};

function normalizeChain(value: unknown): CollateralChain | undefined {
  if (!isString(value)) return undefined;
  return CHAIN_ALIASES[value.trim().toLowerCase()];
}

/**
 * Infers a chain from an address. Solana's base58 alphabet overlaps Bitcoin's,
 * so the well-known Bitcoin prefixes are tested before the generic base58
 * fallback.
 */
export function inferCollateralChain(address: string): CollateralChain {
  const value = address.trim();

  if (/^0x[0-9a-fA-F]{40}$/.test(value)) return 'ethereum';
  if (StrKey.isValidEd25519PublicKey(value)) return 'stellar';
  if (/^(1|3|bc1q|tb1q|m|n|2)[1-9A-HJ-NP-Za-km-z]{20,80}$/i.test(value)) return 'bitcoin';
  if (/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(value)) return 'solana';
  return 'unsupported';
}

function splitChainPrefix(value: string): { chain?: CollateralChain; address: string } {
  const eip155 = /^eip155:\d+:(.+)$/i.exec(value);
  if (eip155 !== null && eip155[1] !== undefined) {
    return { chain: 'ethereum', address: eip155[1] };
  }

  const match = /^([a-z0-9-]+):(.+)$/i.exec(value);
  if (match === null || match[1] === undefined || match[2] === undefined) {
    return { address: value };
  }
  const chain = normalizeChain(match[1]);
  if (chain === undefined) return { address: value };
  return { chain, address: match[2] };
}

const TOKEN_FIELDS = [
  'collateral_token_address',
  'collateral_token',
  'token_contract',
  'collateral_contract',
  'asset_contract',
  'origin_contract',
  'token_address',
  'token_mint',
] as const;

const DECIMAL_FIELDS = ['collateral_decimals', 'origin_decimals', 'token_decimals'] as const;

function firstString(
  entry: Record<string, unknown>,
  fields: readonly string[],
): string | undefined {
  for (const field of fields) {
    const value = entry[field];
    if (isString(value) && value.trim() !== '') return value.trim();
  }
  return undefined;
}

function firstDecimals(entry: Record<string, unknown>): number | undefined {
  for (const field of DECIMAL_FIELDS) {
    const value = entry[field];
    if (typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= 36) {
      return value;
    }
  }
  return undefined;
}

function chainHintFor(
  entry: Record<string, unknown>,
  addressIndex: number,
): CollateralChain | undefined {
  const chains = entry.collateral_chains;
  if (Array.isArray(chains) && isString(chains[addressIndex])) {
    const chain = normalizeChain(chains[addressIndex]);
    if (chain !== undefined) return chain;
  }
  for (const field of ['collateral_chain', 'collateral_network', 'origin_network', 'chain']) {
    const chain = normalizeChain(entry[field]);
    if (chain !== undefined) return chain;
  }
  return undefined;
}

function hasChainHint(entry: Record<string, unknown>, addressIndex: number): boolean {
  const chains = entry.collateral_chains;
  if (
    Array.isArray(chains) &&
    isString(chains[addressIndex]) &&
    chains[addressIndex].trim() !== ''
  ) {
    return true;
  }
  for (const field of ['collateral_chain', 'collateral_network', 'origin_network', 'chain']) {
    if (isString(entry[field]) && entry[field].trim() !== '') return true;
  }
  return false;
}

function tokenForAddress(entry: Record<string, unknown>, addressIndex: number): string | undefined {
  const tokens = entry.collateral_token_addresses;
  if (Array.isArray(tokens) && isString(tokens[addressIndex])) return tokens[addressIndex];
  return firstString(entry, TOKEN_FIELDS);
}

/**
 * Reads every declared collateral address from `[[CURRENCIES]]`.
 *
 * Entries that are `toml` pointers are skipped: their addresses belong to the
 * linked file, which the linter follows separately.
 */
export function collateralAccountsOf(doc: Record<string, unknown>): CollateralAccount[] {
  const currencies = doc.CURRENCIES;
  if (!Array.isArray(currencies)) return [];

  const accounts: CollateralAccount[] = [];
  currencies.forEach((raw, entryIndex) => {
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return;
    const entry = raw as Record<string, unknown>;
    if (entry.toml !== undefined) return;

    const addresses = entry.collateral_addresses;
    if (!Array.isArray(addresses)) return;

    const entryPath = `CURRENCIES[${entryIndex}]`;
    addresses.forEach((rawAddress, addressIndex) => {
      if (!isString(rawAddress) || rawAddress.trim() === '') return;
      const prefixed = splitChainPrefix(rawAddress.trim());
      const hint = chainHintFor(entry, addressIndex);
      const chain =
        hint ??
        (hasChainHint(entry, addressIndex)
          ? 'unsupported'
          : (prefixed.chain ?? inferCollateralChain(prefixed.address)));
      const tokenAddress = tokenForAddress(entry, addressIndex);
      const decimals = firstDecimals(entry);
      accounts.push({
        address: prefixed.address,
        chain,
        path: `${entryPath}.collateral_addresses[${addressIndex}]`,
        entryPath,
        entryIndex,
        ...(isString(entry.code) ? { code: entry.code } : {}),
        ...(isString(entry.issuer) ? { issuer: entry.issuer } : {}),
        ...(tokenAddress === undefined ? {} : { tokenAddress }),
        ...(decimals === undefined ? {} : { decimals }),
      });
    });
  });
  return accounts;
}

export const collateralReserveAccountsOf = collateralAccountsOf;

/* ------------------------------------------------------------------ *
 * Balance readers
 * ------------------------------------------------------------------ */

class ReserveReadError extends Error {}

async function jsonRpc(
  endpoint: string,
  method: string,
  params: unknown[],
  fetchImpl: typeof fetch,
): Promise<unknown> {
  let response: Response;
  try {
    response = await fetchImpl(endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    });
  } catch (error) {
    throw new ReserveReadError(
      `could not reach ${endpoint}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (!response.ok) {
    throw new ReserveReadError(`${endpoint} returned HTTP ${response.status}`);
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw new ReserveReadError(`${endpoint} did not return valid JSON`);
  }

  const envelope = body as { result?: unknown; error?: { message?: unknown } };
  if (envelope.error !== undefined && envelope.error !== null) {
    throw new ReserveReadError(
      `${endpoint} answered with an error${isString(envelope.error.message) ? `: ${envelope.error.message}` : ''}`,
    );
  }
  return envelope.result;
}

function hexQuantity(value: unknown, detail: string): bigint {
  if (!isString(value) || !/^0x[0-9a-fA-F]+$/.test(value)) {
    throw new ReserveReadError(`RPC did not return a hex quantity for ${detail}`);
  }
  return BigInt(value);
}

/** Reads an EVM native (`eth_getBalance`) or ERC-20 (`balanceOf`) balance. */
export async function fetchEthereumBalance(
  rpcUrl: string,
  address: string,
  tokenAddress: string | undefined,
  decimals: number,
  fetchImpl: typeof fetch,
): Promise<ReserveSnapshot> {
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
    throw new ReserveReadError(`"${address}" is not a 20-byte EVM address`);
  }

  if (tokenAddress !== undefined) {
    if (!/^0x[0-9a-fA-F]{40}$/.test(tokenAddress)) {
      throw new ReserveReadError(`"${tokenAddress}" is not a 20-byte ERC-20 contract address`);
    }
    const padded = address.slice(2).toLowerCase().padStart(64, '0');
    const data = `0x70a08231${padded}`;
    const result = await jsonRpc(
      rpcUrl,
      'eth_call',
      [{ to: tokenAddress, data }, 'latest'],
      fetchImpl,
    );
    return {
      chain: 'ethereum',
      address,
      amount: hexQuantity(result, `token ${tokenAddress}`),
      decimals,
      kind: 'token',
      tokenAddress,
    };
  }

  const result = await jsonRpc(rpcUrl, 'eth_getBalance', [address, 'latest'], fetchImpl);
  return {
    chain: 'ethereum',
    address,
    amount: hexQuantity(result, address),
    decimals: 18,
    kind: 'native',
  };
}

export const fetchEvmBalance = fetchEthereumBalance;

function bitcoinSatoshis(body: unknown): bigint | undefined {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) return undefined;
  const record = body as Record<string, unknown>;

  const stats = record.chain_stats;
  if (typeof stats === 'object' && stats !== null && !Array.isArray(stats)) {
    const values = stats as Record<string, unknown>;
    const funded = values.funded_txo_sum;
    const spent = values.spent_txo_sum;
    if (typeof funded === 'number' && typeof spent === 'number') {
      return BigInt(funded) - BigInt(spent);
    }
  }

  for (const field of ['final_balance', 'balance']) {
    const value = record[field];
    if (typeof value === 'number' && Number.isInteger(value)) return BigInt(value);
    if (isString(value) && /^\d+$/.test(value)) return BigInt(value);
  }

  const data = record.data;
  if (typeof data === 'object' && data !== null && !Array.isArray(data)) {
    const nested = data as Record<string, unknown>;
    for (const field of ['final_balance', 'balance', 'confirmed']) {
      const value = nested[field];
      if (typeof value === 'number' && Number.isInteger(value)) return BigInt(value);
      if (isString(value) && /^\d+$/.test(value)) return BigInt(value);
    }
  }
  return undefined;
}

/** Reads a Bitcoin address balance from a Blockstream-compatible REST API. */
export async function fetchBitcoinBalance(
  apiUrl: string,
  address: string,
  fetchImpl: typeof fetch,
): Promise<ReserveSnapshot> {
  const url = apiUrl.includes('{address}')
    ? apiUrl.replace('{address}', encodeURIComponent(address))
    : `${apiUrl.replace(/\/+$/, '')}/address/${encodeURIComponent(address)}`;

  let response: Response;
  try {
    response = await fetchImpl(url);
  } catch (error) {
    throw new ReserveReadError(
      `could not reach ${apiUrl}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (!response.ok) throw new ReserveReadError(`${apiUrl} returned HTTP ${response.status}`);

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw new ReserveReadError(`${apiUrl} did not return valid JSON`);
  }

  const amount = bitcoinSatoshis(body);
  if (amount === undefined) {
    throw new ReserveReadError(`the Bitcoin API returned no satoshi balance for ${address}`);
  }
  return { chain: 'bitcoin', address, amount, decimals: 8, kind: 'native' };
}

function solanaTokenAmount(body: unknown): { amount: bigint; decimals: number } | undefined {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) return undefined;
  const accounts = (body as { value?: unknown }).value;
  if (!Array.isArray(accounts)) return undefined;

  let total = 0n;
  let decimals = 0;
  for (const raw of accounts) {
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) continue;
    const account = raw as Record<string, unknown>;
    const data = account.account;
    if (typeof data !== 'object' || data === null || Array.isArray(data)) continue;
    const parsed = (data as Record<string, unknown>).data;
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) continue;
    const info = (parsed as Record<string, unknown>).parsed;
    if (typeof info !== 'object' || info === null || Array.isArray(info)) continue;
    const tokenAmount = (info as Record<string, unknown>).info;
    if (typeof tokenAmount !== 'object' || tokenAmount === null || Array.isArray(tokenAmount)) {
      continue;
    }
    const amountInfo = (tokenAmount as Record<string, unknown>).tokenAmount;
    if (typeof amountInfo !== 'object' || amountInfo === null || Array.isArray(amountInfo)) {
      continue;
    }
    const value = (amountInfo as Record<string, unknown>).amount;
    const tokenDecimals = (amountInfo as Record<string, unknown>).decimals;
    if (typeof value !== 'string' || !/^\d+$/.test(value)) continue;
    total += BigInt(value);
    if (typeof tokenDecimals === 'number' && Number.isInteger(tokenDecimals)) {
      decimals = tokenDecimals;
    }
  }
  return { amount: total, decimals };
}

/** Reads a Solana native (lamports) or SPL-token balance over JSON-RPC. */
export async function fetchSolanaBalance(
  rpcUrl: string,
  address: string,
  tokenMint: string | undefined,
  decimals: number,
  fetchImpl: typeof fetch,
): Promise<ReserveSnapshot> {
  if (tokenMint !== undefined) {
    const result = await jsonRpc(
      rpcUrl,
      'getTokenAccountsByOwner',
      [address, { mint: tokenMint }, { encoding: 'jsonParsed' }],
      fetchImpl,
    );
    const parsed = solanaTokenAmount(result);
    if (parsed === undefined) {
      throw new ReserveReadError(`the Solana RPC returned no token accounts for ${address}`);
    }
    return {
      chain: 'solana',
      address,
      amount: parsed.amount,
      decimals: parsed.decimals || decimals,
      kind: 'token',
      tokenAddress: tokenMint,
    };
  }

  const result = await jsonRpc(rpcUrl, 'getBalance', [address], fetchImpl);
  const value =
    typeof result === 'object' && result !== null && !Array.isArray(result)
      ? (result as Record<string, unknown>).value
      : undefined;
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    throw new ReserveReadError(`the Solana RPC returned no lamport balance for ${address}`);
  }
  return { chain: 'solana', address, amount: BigInt(value), decimals: 9, kind: 'native' };
}

function stellarBalanceAmount(body: unknown, tokenAddress: string | undefined): bigint | undefined {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) return undefined;
  const balances = (body as Record<string, unknown>).balances;
  if (!Array.isArray(balances)) return undefined;

  let total = 0n;
  for (const raw of balances) {
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) continue;
    const balance = raw as Record<string, unknown>;
    if (tokenAddress !== undefined) {
      const asset = `${String(balance.asset_code ?? '')}:${String(balance.asset_issuer ?? '')}`;
      if (asset.toLowerCase() !== tokenAddress.toLowerCase()) continue;
    } else if (balance.asset_type !== 'native') {
      continue;
    }
    if (!isString(balance.balance)) continue;
    const stroops = stroopsFromDecimal(balance.balance);
    if (stroops !== undefined) total += stroops;
  }
  return total;
}

/** Reads a Stellar native or `CODE:ISSUER` trustline balance from Horizon. */
export async function fetchStellarBalance(
  horizonUrl: string,
  address: string,
  tokenAddress: string | undefined,
  fetchImpl: typeof fetch,
): Promise<ReserveSnapshot> {
  const base = horizonUrl.replace(/\/+$/, '');
  let response: Response;
  try {
    response = await fetchImpl(`${base}/accounts/${encodeURIComponent(address)}`);
  } catch (error) {
    throw new ReserveReadError(
      `could not reach Horizon at ${horizonUrl}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (!response.ok) throw new ReserveReadError(`Horizon returned HTTP ${response.status}`);

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw new ReserveReadError('Horizon did not return valid JSON');
  }
  const amount = stellarBalanceAmount(body, tokenAddress);
  if (amount === undefined) {
    throw new ReserveReadError(`Horizon returned no readable balance for ${address}`);
  }
  return {
    chain: 'stellar',
    address,
    amount,
    decimals: STELLAR_DECIMALS,
    kind: tokenAddress === undefined ? 'native' : 'token',
    ...(tokenAddress === undefined ? {} : { tokenAddress }),
  };
}

function defaultDecimals(chain: CollateralChain): number {
  switch (chain) {
    case 'ethereum':
      return 18;
    case 'bitcoin':
      return 8;
    case 'solana':
      return 9;
    case 'stellar':
      return STELLAR_DECIMALS;
    default:
      return 0;
  }
}

/** Reads one collateral account using the endpoint configured for its chain. */
export async function fetchCollateralBalance(
  account: CollateralAccount,
  options: ProofOfReserveOptions,
  fetchImpl: typeof fetch,
): Promise<ReserveSnapshot> {
  if (account.chain === 'unsupported') {
    return {
      chain: 'unsupported',
      address: account.address,
      amount: 0n,
      decimals: 0,
      kind: 'unsupported',
    };
  }

  const tokenAddress = account.tokenAddress ?? options.tokenAddresses?.[account.chain] ?? undefined;
  const decimals =
    account.decimals ??
    options.decimals?.[account.chain] ??
    (tokenAddress === undefined ? defaultDecimals(account.chain) : defaultDecimals(account.chain));

  switch (account.chain) {
    case 'ethereum':
      return fetchEthereumBalance(
        options.evmRpcUrl ??
          options.ethereumRpcUrl ??
          options.rpcUrls?.ethereum ??
          options.rpcUrl ??
          DEFAULT_ETHEREUM_RPC_URL,
        account.address,
        tokenAddress,
        decimals,
        fetchImpl,
      );
    case 'bitcoin':
      return fetchBitcoinBalance(
        options.bitcoinApiUrl ??
          options.bitcoinRpcUrl ??
          options.rpcUrls?.bitcoin ??
          DEFAULT_BITCOIN_API_URL,
        account.address,
        fetchImpl,
      );
    case 'solana':
      return fetchSolanaBalance(
        options.solanaRpcUrl ?? options.rpcUrls?.solana ?? DEFAULT_SOLANA_RPC_URL,
        account.address,
        tokenAddress,
        decimals,
        fetchImpl,
      );
    case 'stellar':
      return fetchStellarBalance(
        options.horizonUrl ?? options.rpcUrls?.stellar ?? horizonUrlFor(undefined),
        account.address,
        tokenAddress,
        fetchImpl,
      );
  }
}

/* ------------------------------------------------------------------ *
 * Comparison and audit
 * ------------------------------------------------------------------ */

function severityFor(
  rule: string,
  fallback: Severity,
  rules: RuleOverrides | undefined,
): Severity | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override ?? fallback;
}

export interface ReserveComparisonInput {
  reserve: bigint | number | string;
  supply: bigint | number | string;
  reserveDecimals?: number;
  supplyDecimals?: number;
  path?: string;
  asset?: string;
  chain?: string;
}

/**
 * Compares a reserve balance with a supply using exact integer scaling.
 * Returns a deficit diagnostic only when reserve < supply.
 */
export function compareCollateralReserve(
  input: ReserveComparisonInput,
  options: ProofOfReserveOptions = {},
): Diagnostic[] {
  const reserveDecimals = input.reserveDecimals ?? STELLAR_DECIMALS;
  const supplyDecimals = input.supplyDecimals ?? STELLAR_DECIMALS;
  const target = Math.max(reserveDecimals, supplyDecimals);
  const reserve = scaleAmount(BigInt(input.reserve), reserveDecimals, target);
  const supply = scaleAmount(BigInt(input.supply), supplyDecimals, target);
  if (reserve >= supply) return [];

  const severity = severityFor(COLLATERAL_RESERVE_DEFICIT_RULE, 'error', options.rules);
  if (severity === undefined) return [];

  const path = input.path ?? 'CURRENCIES.collateral_addresses';
  const shortfall = supply - reserve;
  return [
    {
      rule: COLLATERAL_RESERVE_DEFICIT_RULE,
      severity,
      category: 'network',
      message: `${path} declares ${input.asset ?? 'an asset'} on ${input.chain ?? 'an external chain'} with a reserve of ${reserve} (${target}dp) against a circulating supply of ${supply} (${target}dp) — a shortfall of ${shortfall}`,
      path,
      helpUri: specUrl('currency-information'),
      suggestion:
        'Top up the collateral reserve, burn or redeem the excess Stellar supply, and pause issuance until the reserve covers circulating supply.',
    },
  ];
}

export const collateralReserveDeficitDiagnostics = compareCollateralReserve;
export const compareReserveToSupply = compareCollateralReserve;

function unsupportedChainDiagnostic(
  account: CollateralAccount,
  options: ProofOfReserveOptions,
): Diagnostic | undefined {
  const severity = severityFor(UNSUPPORTED_COLLATERAL_CHAIN_RULE, 'warning', options.rules);
  if (severity === undefined) return undefined;
  return {
    rule: UNSUPPORTED_COLLATERAL_CHAIN_RULE,
    severity,
    category: 'network',
    message: `${account.path} uses collateral address "${account.address}", whose blockchain cannot be inferred or is not supported by the proof-of-reserve auditor`,
    path: account.path,
    helpUri: specUrl('currency-information'),
    suggestion:
      'Prefix the address with its chain (e.g. ethereum:0x…, bitcoin:bc1…, solana:…, stellar:G…) or set collateral_chain; supported chains are Ethereum, Bitcoin, Solana, and Stellar.',
  };
}

function normalizeArgs(
  fetchImplOrOptions: typeof fetch | ProofOfReserveOptions | undefined,
  maybeOptions: ProofOfReserveOptions,
): { fetchImpl: typeof fetch; options: ProofOfReserveOptions } {
  if (typeof fetchImplOrOptions === 'function') {
    return { fetchImpl: fetchImplOrOptions, options: maybeOptions };
  }
  const options = fetchImplOrOptions ?? {};
  return { fetchImpl: options.fetchImpl ?? options.fetch ?? fetch, options };
}

/**
 * Audits every declared collateral reserve against the asset's Stellar supply.
 *
 * All addresses attached to one `[[CURRENCIES]]` entry jointly back that
 * asset, so their balances are summed before comparison. If any supported
 * address cannot be read, the comparison is skipped for that entry: partial
 * data must not manufacture a deficit.
 */
export async function checkProofOfReserve(
  doc: Record<string, unknown>,
  fetchImplOrOptions: typeof fetch | ProofOfReserveOptions = fetch,
  maybeOptions: ProofOfReserveOptions = {},
): Promise<Diagnostic[]> {
  const { fetchImpl, options } = normalizeArgs(fetchImplOrOptions, maybeOptions);
  const accounts = collateralAccountsOf(doc);
  if (accounts.length === 0) return [];

  const diagnostics: Diagnostic[] = [];
  const byEntry = new Map<number, CollateralAccount[]>();
  for (const account of accounts) {
    const group = byEntry.get(account.entryIndex) ?? [];
    group.push(account);
    byEntry.set(account.entryIndex, group);
  }

  const passphrase = isString(doc.NETWORK_PASSPHRASE) ? doc.NETWORK_PASSPHRASE : undefined;
  const horizonUrl = options.horizonUrl ?? horizonUrlFor(passphrase);

  for (const group of byEntry.values()) {
    const first = group[0] as CollateralAccount;
    const reserves: ReserveSnapshot[] = [];
    let complete = true;

    for (const account of group) {
      if (account.chain === 'unsupported') {
        const diagnostic = unsupportedChainDiagnostic(account, options);
        if (diagnostic !== undefined) diagnostics.push(diagnostic);
        complete = false;
        continue;
      }
      try {
        reserves.push(await fetchCollateralBalance(account, options, fetchImpl));
      } catch {
        // An unreachable RPC is not evidence of insolvency; skip the entry.
        complete = false;
      }
    }

    if (!complete || reserves.length === 0) continue;
    if (first.code === undefined || first.issuer === undefined) continue;

    let supplyStroops: bigint;
    try {
      supplyStroops = await fetchMintedSupply(horizonUrl, first.code, first.issuer, fetchImpl);
    } catch {
      continue;
    }
    if (supplyStroops === 0n) continue;

    const targetDecimals = Math.max(
      STELLAR_DECIMALS,
      ...reserves.map((reserve) => reserve.decimals),
    );
    const totalReserve = reserves.reduce(
      (total, reserve) => total + scaleAmount(reserve.amount, reserve.decimals, targetDecimals),
      0n,
    );
    const supply = scaleAmount(supplyStroops, STELLAR_DECIMALS, targetDecimals);

    diagnostics.push(
      ...compareCollateralReserve(
        {
          reserve: totalReserve,
          supply,
          reserveDecimals: targetDecimals,
          supplyDecimals: targetDecimals,
          path: first.entryPath,
          asset: first.code,
          chain: [...new Set(group.map((account) => account.chain))].join(', '),
        },
        options,
      ),
    );
  }

  return diagnostics;
}

export const checkCollateralReserves = checkProofOfReserve;
export const auditProofOfReserve = checkProofOfReserve;
export const auditCollateralReserves = checkProofOfReserve;
export const auditReserves = checkProofOfReserve;
export const checkReserves = checkProofOfReserve;
export const auditReserveBalances = checkProofOfReserve;
export const proofOfReserveAuditor = checkProofOfReserve;

/** Rule objects registered for `--list-rules` and severity overrides. */
export const proofOfReserveRules: Rule[] = [
  {
    id: COLLATERAL_RESERVE_DEFICIT_RULE,
    category: 'network',
    severity: 'error',
    description: 'External collateral reserve must cover the circulating Stellar supply',
    run() {},
  },
  {
    id: UNSUPPORTED_COLLATERAL_CHAIN_RULE,
    category: 'network',
    severity: 'warning',
    description: 'Collateral address chain must be supported by the proof-of-reserve auditor',
    run() {},
  },
];

export const collateralReserveRules = proofOfReserveRules;
export const reserveAuditorRules = proofOfReserveRules;
export const proofOfReserveAuditorRules = proofOfReserveRules;
export const proofOfReserveRuleIds: readonly string[] = proofOfReserveRules.map((rule) => rule.id);
