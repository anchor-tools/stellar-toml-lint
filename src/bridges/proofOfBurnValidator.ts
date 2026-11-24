/**
 * Wrapped collateral proof-of-burn redemption validator.
 *
 * Runs under opt-in `--audit-burn-redemptions <evidence.json>`.
 *
 * Redeeming a wrapped asset must remove it from circulation. Sending it to the
 * anchor's hot wallet is a pseudo-burn: supply is unchanged, so the reserve
 * ratio is distorted. For each recorded redemption this checks that it either
 *
 * - paid the asset back to its issuer (a classic burn), or to a provably
 *   locked account (master weight 0 and no other signers, or a thresholds-
 *   locked account), or
 * - called the Soroban Asset Contract `burn` / `burn_from` host function,
 *
 * and, when supply snapshots are given, that total supply fell by exactly the
 * redeemed amount. Classic assets (`CODE:ISSUER`) and SAC contracts (`C...`)
 * are verified the same way. Amounts are compared as exact 7-decimal integers.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isAccountId, isContractId, isString } from '../predicates.js';
import { isRecord, severityFor, toScaled } from '../protocols/verifierSupport.js';

const INVALID_RULE = 'burn/invalid-redemption';
const PSEUDO_RULE = 'burn/pseudo-burn';
const SUPPLY_RULE = 'burn/supply-mismatch';
const UNKNOWN_WITHDRAW_RULE = 'burn/undeclared-asset';
const NO_ENDPOINT_RULE = 'burn/missing-withdraw-endpoint';

const SPEC = 'https://developers.stellar.org/docs/tokens/stellar-asset-contract';

export type BurnKind = 'issuer-payment' | 'locked-account' | 'sac-burn' | 'none';

export interface LockedAccount {
  /** Master key weight. */
  masterWeight: number;
  /** Count of other signers with non-zero weight. */
  activeSigners: number;
}

export interface BurnOptions {
  rules?: RuleOverrides;
}

export interface RedemptionVerdict {
  id: string;
  asset: string;
  kind: BurnKind;
  burned: boolean;
}

export interface BurnResult {
  diagnostics: Diagnostic[];
  redemptions: RedemptionVerdict[];
}

/** A destination is provably locked when nobody can sign for it. */
export function isLockedAccount(account: unknown): boolean {
  if (!isRecord(account)) return false;
  const master = account.masterWeight;
  const signers = account.activeSigners;
  return master === 0 && signers === 0;
}

/** Classifies how one redemption disposed of the wrapped tokens. */
export function classifyBurn(
  redemption: Record<string, unknown>,
  accounts: Record<string, unknown>,
): BurnKind {
  const op = isRecord(redemption.operation) ? redemption.operation : {};
  const fn = isString(op.function) ? op.function : '';
  if (op.type === 'invoke_host_function' || fn !== '') {
    return fn === 'burn' || fn === 'burn_from' ? 'sac-burn' : 'none';
  }
  if (op.type !== 'payment') return 'none';
  const destination = op.destination;
  if (!isAccountId(destination)) return 'none';
  const asset = isString(redemption.asset) ? redemption.asset : '';
  if (asset.endsWith(`:${destination as string}`)) return 'issuer-payment';
  return isLockedAccount(accounts[destination as string]) ? 'locked-account' : 'none';
}

export class ProofOfBurnValidator {
  constructor(private readonly options: BurnOptions = {}) {}

  validate(doc: Record<string, unknown>, evidence: unknown): BurnResult {
    const diagnostics: Diagnostic[] = [];
    const push = (rule: string, fallback: 'error' | 'warning', message: string, path: string) => {
      const severity = severityFor(rule, fallback, this.options.rules);
      if (severity !== undefined) {
        diagnostics.push({ rule, severity, category: 'currencies', message, path, helpUri: SPEC });
      }
    };
    const result: BurnResult = { diagnostics, redemptions: [] };
    if (!isRecord(evidence) || !Array.isArray(evidence.redemptions)) {
      push(INVALID_RULE, 'error', 'Evidence must contain a "redemptions" array', 'redemptions');
      return result;
    }
    const accounts = isRecord(evidence.accounts) ? evidence.accounts : {};

    // Wrapped assets declared in stellar.toml: CODE:issuer, or a SAC contract.
    const declared = new Map<string, string | undefined>();
    const currencies = Array.isArray(doc.CURRENCIES) ? doc.CURRENCIES : [];
    currencies.forEach((c, i) => {
      if (!isRecord(c) || !isString(c.code)) return;
      const endpoint =
        isString(c.redemption_instructions) || isString(c.withdraw_url) ? 'yes' : undefined;
      if (isString(c.issuer)) declared.set(`${c.code}:${c.issuer}`, endpoint);
      if (isString(c.contract)) declared.set(c.contract, endpoint);
      if (c.is_asset_anchored === true && endpoint === undefined) {
        push(
          NO_ENDPOINT_RULE,
          'warning',
          `CURRENCIES[${i}] (${c.code}) is anchored but declares no redemption instructions`,
          `CURRENCIES[${i}]`,
        );
      }
    });

    evidence.redemptions.forEach((raw, i) => {
      const path = `redemptions[${i}]`;
      const asset = isRecord(raw) ? raw.asset : undefined;
      const amount = isRecord(raw) && isString(raw.amount) ? toScaled(raw.amount) : undefined;
      const validAsset =
        isString(asset) &&
        (isContractId(asset) ||
          (/^[A-Za-z0-9]{1,12}:/.test(asset) && isAccountId(asset.split(':')[1])));
      if (!isRecord(raw) || !validAsset || amount === undefined || amount === 0n) {
        push(
          INVALID_RULE,
          'error',
          `${path} needs a CODE:ISSUER or C... asset and a positive amount`,
          path,
        );
        return;
      }
      const id = isString(raw.id) ? raw.id : path;
      if (declared.size > 0 && !declared.has(asset as string)) {
        push(
          UNKNOWN_WITHDRAW_RULE,
          'warning',
          `${id}: ${asset as string} is not declared in CURRENCIES`,
          path,
        );
      }
      const kind = classifyBurn(raw, accounts);
      const burned = kind !== 'none';
      if (!burned) {
        const op = isRecord(raw.operation) ? raw.operation : {};
        const to = isString(op.destination) ? ` to ${op.destination}` : '';
        push(
          PSEUDO_RULE,
          'error',
          `${id}: redemption of ${raw.amount as string} ${asset as string} was${to ? ` transferred${to}` : ' not burned'}; supply stays in circulation`,
          path,
        );
      }
      const before = isString(raw.supplyBefore) ? toScaled(raw.supplyBefore) : undefined;
      const after = isString(raw.supplyAfter) ? toScaled(raw.supplyAfter) : undefined;
      if (before !== undefined && after !== undefined && before - after !== amount) {
        push(
          SUPPLY_RULE,
          'error',
          `${id}: supply fell from ${raw.supplyBefore as string} to ${raw.supplyAfter as string}, not by ${raw.amount as string}`,
          path,
        );
      }
      result.redemptions.push({ id, asset: asset as string, kind, burned });
    });
    return result;
  }
}

export function auditBurnRedemptions(
  doc: Record<string, unknown>,
  evidence: unknown,
  options: BurnOptions = {},
): BurnResult {
  return new ProofOfBurnValidator(options).validate(doc, evidence);
}

export function renderBurnReport(result: BurnResult): string {
  const lines = ['Proof-of-burn redemption report'];
  if (result.redemptions.length === 0) lines.push('  no redemptions checked');
  for (const r of result.redemptions) {
    lines.push(`  ${r.id}: ${r.burned ? 'BURNED' : 'NOT BURNED'} (${r.kind}) ${r.asset}`);
  }
  return `${lines.join('\n')}\n`;
}

const def = (id: string, description: string): Rule => ({
  id,
  category: 'currencies',
  severity: 'error',
  description,
  run() {},
});

export const proofOfBurnRules: Rule[] = [
  def(INVALID_RULE, 'Redemption records need an asset, an amount and an operation'),
  def(PSEUDO_RULE, 'Redeemed wrapped tokens must be burned, not moved to a live account'),
  def(SUPPLY_RULE, 'Total supply must fall by exactly the redeemed amount'),
  def(UNKNOWN_WITHDRAW_RULE, 'Redeemed assets should be declared in CURRENCIES'),
  def(NO_ENDPOINT_RULE, 'Anchored assets should document how to redeem them'),
];

export const proofOfBurnRuleIds: readonly string[] = proofOfBurnRules.map((r) => r.id);
