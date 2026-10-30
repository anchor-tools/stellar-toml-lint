import { Networks } from '@stellar/stellar-base';
import type { Diagnostic, RuleOverrides } from '../types.js';
import { auditContractBudget, checkContracts as checkContractsBase } from '../soroban.js';
import { auditUpgradeSecurity } from '../soroban/upgrade-auditor.js';
import { auditSupplyInvariant } from '../soroban/supply-invariant.js';
import { rpcUrlFor } from './display-decimals-audit.js';
import { contractIdsOf } from './currencies.js';
import { webAuthContractIdOf } from './general.js';

export interface SorobanAuditOptions {
  rules?: RuleOverrides;
  rpcUrl?: string;
  horizonUrl?: string;
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

  return diagnostics;
}

export { sorobanRules, sorobanRuleIds } from '../soroban.js';
