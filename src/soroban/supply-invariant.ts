import { Address, xdr } from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { specUrl } from '../spec.js';
import { isString } from '../predicates.js';
import { queryLedgerEntry } from '../soroban.js';

export const SUPPLY_INVARIANT_RULE = 'soroban/supply-invariant-violation';

/** Maximum ledgers Horizon and Soroban RPC can differ before consistency is lost (~50s). */
const MAX_LEDGER_WINDOW = 10;

interface AuditOptions {
  rules?: RuleOverrides;
  rpcUrl?: string;
  horizonUrl?: string;
  fetchImpl?: typeof fetch;
}

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules?: RuleOverrides,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

/**
 * Builds a ledger key for contractData persistent entry with key `scvSymbol(sym)`.
 */
export function totalSupplyContractDataKey(contractId: string, sym: string): string {
  const key = xdr.LedgerKey.contractData(
    new xdr.LedgerKeyContractData({
      contract: new Address(contractId).toScAddress(),
      key: xdr.ScVal.scvSymbol(sym),
      durability: xdr.ContractDataDurability.persistent(),
    }),
  );
  return key.toXDR('base64');
}

/**
 * Extracts a BigInt supply (in Stroops, 7 decimals) from a contractData ledger entry XDR.
 */
export function extractSupplyFromXdr(entryXdr: unknown): bigint | undefined {
  if (!isString(entryXdr)) return undefined;
  try {
    const data = xdr.LedgerEntryData.fromXDR(entryXdr, 'base64');
    const contractData = data.contractData();
    const val = contractData.val();

    if (val.switch().name === 'scvI128') {
      const parts = val.i128();
      const hi = BigInt(parts.hi().toString());
      const lo = BigInt(parts.lo().toString());
      return (hi << 64n) | (lo & 0xffffffffffffffffn);
    }
    if (val.switch().name === 'scvI64') {
      return BigInt(val.i64().toString());
    }
    if (val.switch().name === 'scvU128') {
      const parts = val.u128();
      const hi = BigInt(parts.hi().toString());
      const lo = BigInt(parts.lo().toString());
      return (hi << 64n) | (lo & 0xffffffffffffffffn);
    }
    if (val.switch().name === 'scvU64') {
      return BigInt(val.u64().toString());
    }
  } catch {
    return undefined;
  }
  return undefined;
}

/**
 * Converts a Horizon asset amount string (e.g. "1000000.0000000") to Stroops (BigInt).
 */
export function horizonAmountToStroops(amountStr: string): bigint | undefined {
  if (typeof amountStr !== 'string') return undefined;
  const parts = amountStr.trim().split('.');
  const integerPartStr = parts[0] ?? '0';
  const fractionalPartStr = (parts[1] ?? '').padEnd(7, '0').slice(0, 7);

  try {
    const integerPart = BigInt(integerPartStr);
    const fractionalPart = BigInt(fractionalPartStr);
    return integerPart * 10_000_000n + fractionalPart;
  } catch {
    return undefined;
  }
}

/**
 * Formats Stroops (BigInt) to a human-readable decimal string (7 decimals).
 */
export function stroopsToAmountString(stroops: bigint): string {
  const integerPart = stroops / 10_000_000n;
  const fractionalPart = (stroops % 10_000_000n).toString().padStart(7, '0');
  return `${integerPart}.${fractionalPart}`;
}

/**
 * Verifies that the Soroban SAC total_supply matches the Horizon classic asset issued supply.
 * Concurrently queries Horizon and Soroban RPC and asserts observations belong to a consistent ledger window.
 */
export async function auditSupplyInvariant(
  contractId: string,
  assetCode: string,
  assetIssuer: string,
  rpcUrl: string,
  horizonUrl: string,
  fetchImpl: typeof fetch = fetch,
  options: AuditOptions = {},
): Promise<Diagnostic[]> {
  const diagnostics: Diagnostic[] = [];

  const keySupply = totalSupplyContractDataKey(contractId, 'Supply');
  const keyTotalSupply = totalSupplyContractDataKey(contractId, 'total_supply');

  try {
    const [sorobanResSupply, sorobanResTotalSupply, horizonAssetRes, horizonRootRes] =
      await Promise.all([
        queryLedgerEntry(rpcUrl, keySupply, fetchImpl),
        queryLedgerEntry(rpcUrl, keyTotalSupply, fetchImpl),
        fetchImpl(`${horizonUrl}/assets?asset_code=${assetCode}&asset_issuer=${assetIssuer}`),
        fetchImpl(horizonUrl),
      ]);

    const sorobanRes =
      sorobanResSupply?.entryXdr !== undefined ? sorobanResSupply : sorobanResTotalSupply;
    if (sorobanRes === undefined || sorobanRes.entryXdr === undefined) return diagnostics;

    const sorobanLedger = sorobanRes.latestLedger;
    const sorobanSupplyStroops = extractSupplyFromXdr(sorobanRes.entryXdr);
    if (sorobanSupplyStroops === undefined) return diagnostics;

    if (!horizonAssetRes.ok || !horizonRootRes.ok) return diagnostics;

    const horizonRootBody = (await horizonRootRes.json()) as Record<string, unknown>;
    const horizonLedger =
      Number(horizonRootBody.history_latest_ledger) ||
      Number(horizonRootBody.core_latest_ledger) ||
      Number(horizonRootBody.current_protocol_version ? sorobanLedger : 0);

    if (!horizonLedger || Math.abs(sorobanLedger - horizonLedger) > MAX_LEDGER_WINDOW) {
      // Ledger consistency window cannot be established; fail safely
      return diagnostics;
    }

    const horizonAssetBody = (await horizonAssetRes.json()) as {
      _embedded?: { records?: Array<{ amount?: string }> };
    };
    const records = horizonAssetBody._embedded?.records ?? [];
    if (records.length === 0) return diagnostics;

    const classicAmountStr = records[0]?.amount;
    if (classicAmountStr === undefined) return diagnostics;

    const classicSupplyStroops = horizonAmountToStroops(classicAmountStr);
    if (classicSupplyStroops === undefined) return diagnostics;

    if (sorobanSupplyStroops !== classicSupplyStroops) {
      const severity = severityFor(SUPPLY_INVARIANT_RULE, 'error', options.rules);
      if (severity !== undefined) {
        const sorobanFormatted = stroopsToAmountString(sorobanSupplyStroops);
        diagnostics.push({
          rule: SUPPLY_INVARIANT_RULE,
          severity,
          category: 'network',
          message: `Supply invariant mismatch for asset ${assetCode}:${assetIssuer} (contract ${contractId}): Soroban SAC total_supply (${sorobanFormatted}) does not match Horizon classic issued supply (${classicAmountStr})`,
          path: 'CURRENCIES.contract',
          helpUri: specUrl('general-information'),
          suggestion:
            'Investigate supply discrepancy between Soroban SAC state and classic asset issuance on the Stellar ledger.',
        });
      }
    }
  } catch {
    // Fail safely on network or ledger consistency failure
  }

  return diagnostics;
}

export const supplyInvariantRules: Rule[] = [
  {
    id: SUPPLY_INVARIANT_RULE,
    category: 'network',
    severity: 'error',
    description:
      'Soroban SAC total supply must match classic asset issued supply on Horizon within a consistent ledger window',
    run() {},
  },
];
