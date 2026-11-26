/**
 * Solana SPL -> Soroban bridge custody escrow invariant verifier.
 *
 * Runs under opt-in `--verify-solana-bridge` (or `stellar-toml-lint
 * verify-solana-bridge --domain <domain>`); Solana and Horizon are only queried
 * with `--check-network`.
 *
 * A currency bridged from Solana declares
 * `solana_bridge = { spl_mint, escrow_program, escrow_token_account, rpc? }`.
 * The verifier reads the escrow token account over Solana JSON-RPC
 * (`getAccountInfo` to confirm it holds the declared mint, then
 * `getTokenAccountBalance`), reads the asset's issued supply from Horizon and
 * enforces `locked on Solana >= minted on Stellar`. Balances are compared by
 * cross-multiplying raw integers, so a 9-decimal SPL amount and a 7-decimal
 * Stellar amount are compared exactly with no rounding in either direction.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isHttpsUrl, isString } from '../predicates.js';
import { errorMessage, isRecord } from '../protocols/verifierSupport.js';
import {
  AMOUNT_SCALE,
  bridgeRule,
  covers,
  diagnosticSink,
  formatUnits,
  horizonFor,
  jsonRpc,
  stellarSupply,
} from './bridgeSupport.js';
import type { Push, RpcOptions, StellarAsset } from './bridgeSupport.js';

const CONFIG_RULE = 'solbridge/invalid-config';
const RPC_RULE = 'solbridge/rpc-unavailable';
const ESCROW_RULE = 'solbridge/escrow-mismatch';
const SUPPLY_RULE = 'solbridge/supply-unavailable';
const DEFICIT_RULE = 'solbridge/reserve-deficit';

const SPEC = 'https://solana.com/docs/rpc/http/gettokenaccountbalance';

export const DEFAULT_SOLANA_RPC = 'https://api.mainnet-beta.solana.com';

/** SPL Token and Token-2022 program ids; an escrow token account must be owned by one. */
export const SPL_TOKEN_PROGRAMS: readonly string[] = [
  'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
  'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb',
];

const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/** Decodes a base58 string; `undefined` on any character outside the alphabet. */
export function base58Decode(text: string): Uint8Array | undefined {
  let value = 0n;
  for (const ch of text) {
    const digit = BASE58.indexOf(ch);
    if (digit < 0) return undefined;
    value = value * 58n + BigInt(digit);
  }
  const bytes: number[] = [];
  while (value > 0n) {
    bytes.unshift(Number(value % 256n));
    value /= 256n;
  }
  for (const ch of text) {
    if (ch !== '1') break;
    bytes.unshift(0);
  }
  return Uint8Array.from(bytes);
}

/** A 32-byte base58 Solana public key (account, mint or program id). */
export function isSolanaAddress(v: unknown): v is string {
  return isString(v) && v.length >= 32 && v.length <= 44 && base58Decode(v)?.length === 32;
}

export interface SolanaBridge {
  path: string;
  asset: StellarAsset;
  splMint: string;
  escrowProgram: string;
  escrowTokenAccount: string;
  rpc: string;
}

export interface SolanaBridgeReport {
  path: string;
  asset: string;
  locked?: string;
  minted?: string;
  /** `locked - minted` in Stellar units; negative is a deficit. */
  surplus?: string;
}

export interface SolanaEscrowOptions extends RpcOptions {
  rules?: RuleOverrides;
  /** Query Solana and Horizon. */
  probe?: boolean;
  horizonUrl?: string;
  /** Known Stellar supplies keyed `CODE:ISSUER` or `CODE`, skipping Horizon. */
  supplies?: Record<string, string>;
}

export interface SolanaEscrowResult {
  diagnostics: Diagnostic[];
  bridges: SolanaBridgeReport[];
}

function collectBridges(doc: Record<string, unknown>, push: Push): SolanaBridge[] {
  const out: SolanaBridge[] = [];
  if (!Array.isArray(doc.CURRENCIES)) return out;
  doc.CURRENCIES.forEach((currency, i) => {
    if (!isRecord(currency) || currency.solana_bridge === undefined) return;
    const path = `CURRENCIES[${i}].solana_bridge`;
    const b = currency.solana_bridge;
    const bad = (message: string, suggestion: string): void =>
      push(CONFIG_RULE, 'error', message, path, suggestion);
    if (!isRecord(b)) return bad('solana_bridge must be a table', 'Use an inline table.');
    if (!isString(currency.code) || !isString(currency.issuer)) {
      return bad('A bridged currency needs code and issuer', 'Declare the Stellar asset.');
    }
    for (const field of ['spl_mint', 'escrow_program', 'escrow_token_account'] as const) {
      if (!isSolanaAddress(b[field])) {
        return bad(
          `solana_bridge.${field} is not a base58 Solana address`,
          'Use the 32-byte base58 address shown by the Solana explorer.',
        );
      }
    }
    const rpc = b.rpc ?? DEFAULT_SOLANA_RPC;
    if (!isHttpsUrl(rpc)) return bad('solana_bridge.rpc must be an https URL', 'Use https://.');
    out.push({
      path,
      asset: { code: currency.code, issuer: currency.issuer },
      splMint: b.spl_mint as string,
      escrowProgram: b.escrow_program as string,
      escrowTokenAccount: b.escrow_token_account as string,
      rpc: rpc as string,
    });
  });
  return out;
}

export class SolanaEscrowInvariantVerifier {
  constructor(
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly options: SolanaEscrowOptions = {},
  ) {}

  async verify(doc: Record<string, unknown>): Promise<SolanaEscrowResult> {
    const diagnostics: Diagnostic[] = [];
    const push = diagnosticSink(diagnostics, SPEC, this.options.rules);
    const bridges: SolanaBridgeReport[] = [];
    for (const bridge of collectBridges(doc, push)) {
      const report: SolanaBridgeReport = { path: bridge.path, asset: bridge.asset.code };
      bridges.push(report);
      if (this.options.probe) await this.probe(doc, bridge, report, push);
    }
    return { diagnostics, bridges };
  }

  /** Reads the escrow's locked balance as `[raw amount, decimals]`, checking its mint first. */
  private async readEscrow(
    bridge: SolanaBridge,
    push: Push,
  ): Promise<[bigint, number] | undefined> {
    const rpc = (method: string, params: unknown[]): Promise<unknown> =>
      jsonRpc(this.fetchImpl, bridge.rpc, method, params, this.options);
    let info: unknown;
    let balance: unknown;
    try {
      info = await rpc('getAccountInfo', [bridge.escrowTokenAccount, { encoding: 'jsonParsed' }]);
      balance = await rpc('getTokenAccountBalance', [bridge.escrowTokenAccount]);
    } catch (error) {
      push(
        RPC_RULE,
        'warning',
        `Could not read escrow ${bridge.escrowTokenAccount} (${errorMessage(error)})`,
        bridge.path,
        'Check the Solana RPC endpoint, or retry later if rate limited.',
      );
      return undefined;
    }
    const account = isRecord(info) && isRecord(info.value) ? info.value : undefined;
    const data = account && isRecord(account.data) ? account.data.parsed : undefined;
    const mint = isRecord(data) && isRecord(data.info) ? data.info.mint : undefined;
    if (account === undefined || !SPL_TOKEN_PROGRAMS.includes(String(account.owner))) {
      push(
        ESCROW_RULE,
        'error',
        `Escrow ${bridge.escrowTokenAccount} is not an SPL token account`,
        bridge.path,
        'Point escrow_token_account at the token account the bridge program locks funds in.',
      );
      return undefined;
    }
    if (mint !== bridge.splMint) {
      push(
        ESCROW_RULE,
        'error',
        `Escrow holds mint ${String(mint)}, not the declared ${bridge.splMint}`,
        bridge.path,
        'The escrow must hold the bridged SPL mint; fix spl_mint or escrow_token_account.',
      );
      return undefined;
    }
    const value = isRecord(balance) && isRecord(balance.value) ? balance.value : undefined;
    const amount = value?.amount;
    const decimals = value?.decimals;
    if (
      !isString(amount) ||
      !/^\d+$/.test(amount) ||
      typeof decimals !== 'number' ||
      !Number.isInteger(decimals) ||
      decimals < 0 ||
      decimals > 36
    ) {
      push(
        RPC_RULE,
        'warning',
        'getTokenAccountBalance returned a malformed balance',
        bridge.path,
        'Check that the RPC endpoint is a Solana JSON-RPC node.',
      );
      return undefined;
    }
    return [BigInt(amount), decimals];
  }

  private async probe(
    doc: Record<string, unknown>,
    bridge: SolanaBridge,
    report: SolanaBridgeReport,
    push: Push,
  ): Promise<void> {
    const escrow = await this.readEscrow(bridge, push);
    if (escrow === undefined) return;
    const [locked, decimals] = escrow;
    report.locked = formatUnits(locked, decimals);
    let minted: bigint;
    try {
      minted = await stellarSupply(
        this.fetchImpl,
        horizonFor(doc, this.options.horizonUrl),
        bridge.asset,
        this.options.supplies,
        this.options.timeoutMs,
      );
    } catch (error) {
      push(
        SUPPLY_RULE,
        'warning',
        `Could not read the Stellar supply of ${bridge.asset.code} (${errorMessage(error)})`,
        bridge.path,
        'Check HORIZON_URL; the invariant cannot be checked without the minted supply.',
      );
      return;
    }
    report.minted = formatUnits(minted, AMOUNT_SCALE);
    // Express both sides at the finer of the two scales for an exact difference.
    const scale = Math.max(decimals, AMOUNT_SCALE);
    const lockedAtScale = locked * 10n ** BigInt(scale - decimals);
    const mintedAtScale = minted * 10n ** BigInt(scale - AMOUNT_SCALE);
    report.surplus = formatUnits(lockedAtScale - mintedAtScale, scale);
    if (!covers(locked, decimals, minted, AMOUNT_SCALE)) {
      push(
        DEFICIT_RULE,
        'error',
        `${bridge.asset.code} bridge is under-reserved: ${report.locked} locked on Solana, ${report.minted} minted on Stellar (deficit ${formatUnits(mintedAtScale - lockedAtScale, scale)})`,
        bridge.path,
        'Minted supply exceeds the escrowed collateral; halt minting and reconcile the bridge.',
      );
    }
  }
}

export async function verifySolanaBridges(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: SolanaEscrowOptions = {},
): Promise<SolanaEscrowResult> {
  return new SolanaEscrowInvariantVerifier(fetchImpl, options).verify(doc);
}

export const solanaEscrowRules: Rule[] = [
  bridgeRule(CONFIG_RULE, 'error', 'solana_bridge declarations must use valid Solana addresses'),
  bridgeRule(RPC_RULE, 'warning', 'The Solana escrow must be readable over JSON-RPC'),
  bridgeRule(ESCROW_RULE, 'error', 'The escrow must be an SPL token account for the declared mint'),
  bridgeRule(SUPPLY_RULE, 'warning', 'The Stellar supply must be readable to check the invariant'),
  bridgeRule(
    DEFICIT_RULE,
    'error',
    'Tokens locked on Solana must cover the supply minted on Stellar',
  ),
];

export const solanaEscrowRuleIds: readonly string[] = solanaEscrowRules.map((r) => r.id);
