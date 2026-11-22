import { Networks } from '@stellar/stellar-base';
import type { Diagnostic, RuleOverrides } from '../types.js';
import {
  auditContractBudget,
  checkContracts as checkContractsBase,
  fetchContractWasm,
} from '../soroban.js';
import { auditUpgradeSecurity } from '../soroban/upgrade-auditor.js';
import { auditSupplyInvariant } from '../soroban/supply-invariant.js';
import { auditTomlStorageTtl } from '../soroban/ttlAuditor.js';
import type { TtlAuditorOptions } from '../soroban/ttlAuditor.js';
import { auditWasmReentrancy } from '../soroban/reentrancyValidator.js';
import { rpcUrlFor } from './display-decimals-audit.js';
import { contractIdsOf } from './currencies.js';
import { webAuthContractIdOf } from './general.js';

export interface SorobanAuditOptions {
  rules?: RuleOverrides;
  rpcUrl?: string;
  horizonUrl?: string;
  /**
   * Opt-in storage TTL audit. Passing an object turns it on and forwards the
   * buffer options; leaving it undefined keeps the historical behaviour so
   * the day-scale expiry check above remains the only TTL finding.
   */
  storageTtl?: TtlAuditorOptions;
  /** Opt-in static reentrancy and atomicity analysis of each contract's WASM. */
  auditReentrancy?: boolean;
}

/**
 * Audits every contract declared in the file (TTL, SEP-45 interface, Upgrade Security, static
 * resource budget, and Supply Invariant).
 */
export async function checkContracts(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: SorobanAuditOptions = {},
): Promise<Diagnostic[]> {
  const diagnostics: Diagnostic[] = [];

  const passphrase =
    typeof doc.NETWORK_PASSPHRASE === 'string' ? doc.NETWORK_PASSPHRASE : Networks.PUBLIC;
  const rpcUrl = options.rpcUrl ?? rpcUrlFor(passphrase);
  if (!rpcUrl) return diagnostics;

  const horizonUrl =
    options.horizonUrl ??
    (passphrase === Networks.TESTNET
      ? 'https://horizon-testnet.stellar.org'
      : 'https://horizon.stellar.org');

  // Base TTL and SEP-45 interface checks
  const ttlDiagnostics = await checkContractsBase(doc, fetchImpl, {
    rpcUrl,
    rules: options.rules,
  });
  diagnostics.push(...ttlDiagnostics);

  const authContract = webAuthContractIdOf(doc);
  const targets = [...contractIdsOf(doc), ...(authContract !== undefined ? [authContract] : [])];

  for (const target of targets) {
    const upgradeDiagnostics = await auditUpgradeSecurity(
      target.id,
      rpcUrl,
      horizonUrl,
      fetchImpl,
      { rules: options.rules },
    );
    diagnostics.push(...upgradeDiagnostics);

    diagnostics.push(
      ...(await auditContractBudget(target.id, rpcUrl, fetchImpl, { rules: options.rules })),
    );

    if (options.auditReentrancy) {
      const wasm = await fetchContractWasm(target.id, rpcUrl, fetchImpl);
      if (wasm !== undefined) {
        diagnostics.push(...auditWasmReentrancy(target.id, wasm, { rules: options.rules }));
      }
    }
  }

  // Audit supply invariants for assets declared under [[CURRENCIES]]
  const currencies = doc.CURRENCIES;
  if (Array.isArray(currencies)) {
    for (const entry of currencies) {
      if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) continue;
      const code = entry.code;
      const issuer = entry.issuer;
      const contract = entry.contract;

      if (typeof code === 'string' && typeof issuer === 'string' && typeof contract === 'string') {
        const supplyDiagnostics = await auditSupplyInvariant(
          contract,
          code,
          issuer,
          rpcUrl,
          horizonUrl,
          fetchImpl,
          { rules: options.rules },
        );
        diagnostics.push(...supplyDiagnostics);
      }
    }
  }

  // Opt-in storage TTL audit of every declared contract.
  if (options.storageTtl !== undefined) {
    diagnostics.push(
      ...(await auditTomlStorageTtl(doc, fetchImpl, {
        ...options.storageTtl,
        rpcUrl,
        ...(options.rules !== undefined ? { rules: options.rules } : {}),
      })),
    );
  }

  return diagnostics;
}

export { sorobanRules, sorobanRuleIds } from '../soroban.js';
