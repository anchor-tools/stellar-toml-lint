/**
 * Soroban cross-contract authorization (auth_entries) security auditor.
 *
 * Soroban contracts implement explicit authentication via `require_auth` or
 * `require_auth_for_args`. Contracts handling tokenized assets must adhere to
 * SEP-42 cross-contract authorization standards to avoid re-entrancy, privilege
 * escalation, or unauthorized token drain.
 *
 * This audit inspects function spec definitions in WebAssembly contract specifications
 * (contractspecv0) to audit authorization structures and verify that sensitive
 * state-mutating operations require signer authorization via Address parameters.
 *
 * Runs under opt-in `--check-network`, never throws on an RPC outage, and
 * registers rule objects so `--list-rules` and `--off`/`--warn`/`--error` know its ids.
 *
 * Diagnostics:
 * - `soroban/missing-auth-parameter` (error)
 * - `soroban/unsafe-unauthorized-mint` (error)
 */
import type { xdr } from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { rpcUrlFor } from '../rules/display-decimals-audit.js';
import { contractCurrenciesOf } from '../rules/currencies.js';
import { extractContractSpecEntries } from './wasm-auditor.js';
import { fetchContractWasm, severityFor } from './rpc.js';

export const MISSING_AUTH_PARAMETER_RULE = 'soroban/missing-auth-parameter';
export const UNSAFE_UNAUTHORIZED_MINT_RULE = 'soroban/unsafe-unauthorized-mint';

export const SEP42_SPEC_URL =
  'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0042.md';

/** State-mutating methods that must accept an Address authorization parameter. */
export const STATE_MUTATING_AUTH_FUNCTIONS = [
  'set_admin',
  'set_owner',
  'set_administrator',
  'transfer',
  'transfer_from',
  'burn',
  'burn_from',
  'clawback',
  'clawback_from',
] as const;

export interface AuthAuditorOptions {
  rules?: RuleOverrides;
  /** The file path that named the contract, attached to every diagnostic. */
  path?: string;
  /** Soroban RPC endpoint, overriding the one derived from the passphrase. */
  rpcUrl?: string;
}

export interface ContractFunctionSpec {
  name: string;
  inputs: { name: string; type: string }[];
  outputs: string[];
}

function authFinding(
  contractId: string,
  options: AuthAuditorOptions,
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
        helpUri: SEP42_SPEC_URL,
        ...(suggestion !== undefined ? { suggestion } : {}),
      },
    ];
  };
}

/**
 * Extracts decoded function definitions from ScSpecEntry objects in a contract spec.
 */
export function extractFunctionSpecs(specEntries: xdr.ScSpecEntry[]): ContractFunctionSpec[] {
  const functions: ContractFunctionSpec[] = [];

  for (const entry of specEntries) {
    if (entry.switch().name !== 'scSpecEntryFunctionV0') continue;
    const fn = entry.functionV0();
    const name = fn.name().toString('utf8');
    const inputs = fn.inputs().map((input) => ({
      name: input.name().toString('utf8'),
      type: input.type().switch().name,
    }));
    const outputs = fn.outputs().map((output) => output.switch().name);

    functions.push({ name, inputs, outputs });
  }

  return functions;
}

/**
 * Verifies that a contract's specification adheres to SEP-42 cross-contract authorization rules.
 */
export function verifyContractAuth(
  wasm: Buffer,
  contractId: string,
  options: AuthAuditorOptions = {},
): Diagnostic[] {
  const specEntries = extractContractSpecEntries(wasm);
  if (specEntries === undefined || specEntries.length === 0) return [];

  const functions = extractFunctionSpecs(specEntries);
  const diagnostics: Diagnostic[] = [];
  const finding = authFinding(contractId, options);

  for (const fn of functions) {
    const hasAddressInput = fn.inputs.some((input) => input.type === 'scSpecTypeAddress');

    // 1. Check mint: Unsafe or unparameterized mint
    if (fn.name === 'mint') {
      if (!hasAddressInput) {
        diagnostics.push(
          ...finding(
            UNSAFE_UNAUTHORIZED_MINT_RULE,
            'error',
            `exposes unparameterized or unauthorized function "${fn.name}" without an Address parameter, violating SEP-42`,
            'Require an Address parameter (e.g., "to" or "admin") in "mint" and invoke require_auth to ensure caller authorization.',
          ),
        );
      }
      continue;
    }

    // 2. Check other state-mutating functions (set_admin, transfer, burn, etc.)
    const isStateMutating = STATE_MUTATING_AUTH_FUNCTIONS.some((name) => name === fn.name);
    if (isStateMutating && !hasAddressInput) {
      diagnostics.push(
        ...finding(
          MISSING_AUTH_PARAMETER_RULE,
          'error',
          `state-mutating function "${fn.name}" lacks an Address authorization parameter, violating SEP-42`,
          `Add an Address parameter to "${fn.name}" so the contract can authenticate invocations with require_auth.`,
        ),
      );
    }
  }

  return diagnostics;
}

/**
 * Audits cross-contract authorization compliance of a single deployed Soroban contract.
 * Stays silent when the contract's WASM cannot be fetched or parsed.
 */
export async function auditContractAuth(
  contractId: string,
  rpcUrl: string,
  fetchImpl: typeof fetch = fetch,
  options: AuthAuditorOptions = {},
): Promise<Diagnostic[]> {
  const wasm = await fetchContractWasm(contractId, rpcUrl, fetchImpl);
  if (wasm === undefined) return [];
  return verifyContractAuth(wasm, contractId, options);
}

/**
 * Audits cross-contract authorization compliance for every contract declared in [[CURRENCIES]].
 */
export async function auditTomlContractAuth(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: AuthAuditorOptions = {},
): Promise<Diagnostic[]> {
  const passphrase =
    typeof doc.NETWORK_PASSPHRASE === 'string' ? doc.NETWORK_PASSPHRASE : undefined;
  const rpcUrl = options.rpcUrl ?? rpcUrlFor(passphrase);
  if (!rpcUrl) return [];

  const diagnostics: Diagnostic[] = [];
  for (const currency of contractCurrenciesOf(doc)) {
    diagnostics.push(
      ...(await auditContractAuth(currency.id, rpcUrl, fetchImpl, {
        ...options,
        path: currency.path,
      })),
    );
  }
  return diagnostics;
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const authAuditorRules: Rule[] = [
  {
    id: MISSING_AUTH_PARAMETER_RULE,
    category: 'network',
    severity: 'error',
    description:
      'A Soroban state-mutating contract function lacks an Address authorization parameter (SEP-42)',
    run() {},
  },
  {
    id: UNSAFE_UNAUTHORIZED_MINT_RULE,
    category: 'network',
    severity: 'error',
    description:
      'A Soroban contract exposes an unparameterized or unauthorized mint function (SEP-42)',
    run() {},
  },
];

/** Rule ids emitted by {@link auditTomlContractAuth}. */
export const authAuditorRuleIds: readonly string[] = authAuditorRules.map((rule) => rule.id);
