/**
 * Soroban contract upgradeability and administrative control auditor.
 *
 * A token contract declared in `stellar.toml` may be upgradeable, and whether
 * its administrator is a single key or a real multi-signature controller is a
 * property ecosystem participants need to know before they trust it. This audit
 * reads the contract instance storage for the conventional `admin` or `owner`
 * data key, classifies the administrator as an account or another contract, and
 * for accounts inspects the Stellar account's signing weights via Horizon. A
 * single-key administrator is flagged, as is a contract that ships upgrade
 * functions while its administrator is permanently locked — a contract nobody
 * can ever upgrade or fix.
 *
 * Runs under the opt-in `--check-network` flag like the other on-chain audits,
 * never throws on an RPC outage, and registers rule objects so `--list-rules`
 * and `--off`/`--warn`/`--error` know its ids.
 *
 * Diagnostics:
 * - `soroban/single-signer-contract-admin` (warning)
 * - `soroban/locked-admin-key` (warning)
 */
import { Address, xdr } from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isString } from '../predicates.js';
import { horizonUrlFor } from '../network-checks.js';
import { rpcUrlFor } from '../rules/display-decimals-audit.js';
import { contractCurrenciesOf } from '../rules/currencies.js';
import { specFunctionNames } from '../soroban.js';
import { fetchContractInstanceXdr, fetchContractWasm, severityFor } from './rpc.js';

export const SINGLE_SIGNER_RULE = 'soroban/single-signer-contract-admin';
export const LOCKED_ADMIN_RULE = 'soroban/locked-admin-key';

/**
 * Function names that mark a contract as upgradeable. Soroban's upgrade entry
 * point is conventionally `upgrade`; the Rust SDK's deployer helper is
 * `update_current_contract_wasm`, and some contracts expose `set_admin`.
 */
const UPGRADE_FUNCTIONS = ['upgrade', 'update_current_contract_wasm', 'update_wasm', 'set_admin'];

export interface AdminAuditorOptions {
  rules?: RuleOverrides;
  /** The file path that named the contract, attached to every diagnostic. */
  path?: string;
  /** Soroban RPC endpoint, overriding the one derived from the passphrase. */
  rpcUrl?: string;
  /** Horizon endpoint, overriding the one derived from the passphrase. */
  horizonUrl?: string;
  /** Network passphrase, used to derive the Horizon endpoint when unset. */
  networkPassphrase?: string;
}

/** The administrative key a contract stores, and which name it used. */
export interface AdminKey {
  name: 'admin' | 'owner';
  address: string;
  kind: 'account' | 'contract';
}

/** The signing weights Horizon reports for an account. */
interface AccountSigners {
  masterKeyWeight: number;
  medThreshold: number;
  highThreshold: number;
  signers: { key: string; weight: number }[];
}

function scString(val: xdr.ScVal): string | undefined {
  switch (val.switch().name) {
    case 'scvString':
    case 'scvSymbol':
      return val.value()!.toString();
    default:
      return undefined;
  }
}

/**
 * Reads the `admin` (or `owner`) address out of a contract's instance storage.
 * Returns `undefined` when the entry carries no such key, or the key does not
 * hold an address value.
 */
export function readAdminKey(instanceXdr: unknown): AdminKey | undefined {
  if (!isString(instanceXdr)) return undefined;
  try {
    const data = xdr.LedgerEntryData.fromXDR(instanceXdr, 'base64');
    if (data.switch().name !== 'contractData') return undefined;
    const val = data.contractData().val();
    if (val.switch().name !== 'scvContractInstance') return undefined;

    for (const entry of val.instance().storage() ?? []) {
      const name = scString(entry.key());
      if (name !== 'admin' && name !== 'owner') continue;
      const holder = entry.val();
      if (holder.switch().name !== 'scvAddress') continue;
      const scAddress = holder.address();
      const address = Address.fromScAddress(scAddress).toString();
      const kind = scAddress.switch().name === 'scAddressTypeAccount' ? 'account' : 'contract';
      return { name, address, kind };
    }
    return undefined;
  } catch {
    return undefined;
  }
}

/** Fetches an account's signing configuration from Horizon, or `undefined`. */
async function fetchAccountSigners(
  accountId: string,
  horizonUrl: string,
  fetchImpl: typeof fetch,
): Promise<AccountSigners | undefined> {
  try {
    const response = await fetchImpl(`${horizonUrl}/accounts/${encodeURIComponent(accountId)}`);
    if (!response.ok) return undefined;
    const body = (await response.json()) as Record<string, unknown>;
    const thresholds = body.thresholds;
    const signers = body.signers;
    if (
      !Number.isInteger(body.master_key_weight) ||
      (body.master_key_weight as number) < 0 ||
      typeof thresholds !== 'object' ||
      thresholds === null ||
      Array.isArray(thresholds) ||
      !Array.isArray(signers)
    ) {
      return undefined;
    }
    const t = thresholds as Record<string, unknown>;
    if (!Number.isInteger(t.med_threshold) || !Number.isInteger(t.high_threshold)) {
      return undefined;
    }

    const parsed: { key: string; weight: number }[] = [];
    for (const signer of signers) {
      if (typeof signer !== 'object' || signer === null) return undefined;
      const s = signer as Record<string, unknown>;
      if (typeof s.key !== 'string' || !Number.isInteger(s.weight)) return undefined;
      parsed.push({ key: s.key, weight: s.weight as number });
    }

    return {
      masterKeyWeight: body.master_key_weight as number,
      medThreshold: t.med_threshold as number,
      highThreshold: t.high_threshold as number,
      signers: parsed,
    };
  } catch {
    return undefined;
  }
}

function adminFinding(
  contractId: string,
  options: AdminAuditorOptions,
): (
  rule: string,
  fallback: 'error' | 'warning',
  detail: string,
  suggestion?: string,
) => Diagnostic[] {
  return (rule, fallback, detail, suggestion) => {
    const severity = severityFor(rule, fallback, options.rules);
    if (severity === undefined) return [];
    return [
      {
        rule,
        severity,
        category: 'network',
        message: `Contract ${contractId} ${detail}`,
        ...(options.path !== undefined ? { path: options.path } : {}),
        ...(suggestion !== undefined ? { suggestion } : {}),
      },
    ];
  };
}

/**
 * Assesses one on-chain contract's administrative control. Stays silent when
 * the instance, its stored admin, or the Horizon account cannot be read — a
 * missing answer is not a finding.
 */
export async function auditContractAdmin(
  contractId: string,
  rpcUrl: string,
  fetchImpl: typeof fetch = fetch,
  options: AdminAuditorOptions = {},
): Promise<Diagnostic[]> {
  const instanceXdr = await fetchContractInstanceXdr(contractId, rpcUrl, fetchImpl);
  const admin = readAdminKey(instanceXdr);
  if (admin === undefined || admin.kind !== 'account') return [];

  const wasm = await fetchContractWasm(contractId, rpcUrl, fetchImpl);
  const hasUpgrade =
    wasm !== undefined &&
    (specFunctionNames(wasm) ?? []).some((fn) => UPGRADE_FUNCTIONS.includes(fn));

  const horizonUrl = options.horizonUrl ?? horizonUrlFor(options.networkPassphrase);
  const account = await fetchAccountSigners(admin.address, horizonUrl, fetchImpl);
  if (account === undefined) return [];

  const finding = adminFinding(contractId, options);
  const diagnostics: Diagnostic[] = [];
  const otherSigners = account.signers.filter(
    (signer) => signer.key !== admin.address && signer.weight > 0,
  );
  const reachableWeight = otherSigners.reduce((sum, signer) => sum + signer.weight, 0);
  const locked =
    account.masterKeyWeight === 0 &&
    reachableWeight < Math.max(account.medThreshold, account.highThreshold);

  if (locked) {
    if (hasUpgrade) {
      diagnostics.push(
        ...finding(
          LOCKED_ADMIN_RULE,
          'warning',
          `is upgradeable but its ${admin.name} account (${admin.address}) is permanently locked`,
          'Assign control to a signer that can still authorize an upgrade, or remove the upgrade functions.',
        ),
      );
    }
    return diagnostics;
  }

  if (otherSigners.length === 0) {
    diagnostics.push(
      ...finding(
        SINGLE_SIGNER_RULE,
        'warning',
        `declares a ${admin.name} that is a single-signer account (${admin.address})`,
        'Move the administrative role to a multi-signature account so one key cannot seize the contract.',
      ),
    );
  }

  return diagnostics;
}

/**
 * Audits the administrative control of every contract the file declares under
 * `[[CURRENCIES]]`. Silent when no RPC URL can be derived.
 */
export async function auditTomlContractAdmins(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: AdminAuditorOptions = {},
): Promise<Diagnostic[]> {
  const passphrase =
    typeof doc.NETWORK_PASSPHRASE === 'string' ? doc.NETWORK_PASSPHRASE : undefined;
  const rpcUrl = options.rpcUrl ?? rpcUrlFor(passphrase);
  if (!rpcUrl) return [];

  const diagnostics: Diagnostic[] = [];
  for (const currency of contractCurrenciesOf(doc)) {
    diagnostics.push(
      ...(await auditContractAdmin(currency.id, rpcUrl, fetchImpl, {
        ...options,
        networkPassphrase: options.networkPassphrase ?? passphrase,
        path: currency.path,
      })),
    );
  }
  return diagnostics;
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const adminAuditorRules: Rule[] = [
  {
    id: SINGLE_SIGNER_RULE,
    category: 'network',
    severity: 'warning',
    description: 'A Soroban contract administrator is a single-signer account',
    run() {},
  },
  {
    id: LOCKED_ADMIN_RULE,
    category: 'network',
    severity: 'warning',
    description: 'An upgradeable Soroban contract has a permanently locked administrator',
    run() {},
  },
];

/** Rule ids emitted by {@link auditTomlContractAdmins}. */
export const adminAuditorRuleIds: readonly string[] = adminAuditorRules.map((rule) => rule.id);
