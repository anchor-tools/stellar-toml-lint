/**
 * Soroban access-control role escalation auditor.
 *
 * Issue #810 — Implement Access Control Role Escalation Penetration Test and Fixes.
 *
 * This module audits deployed Soroban contracts for privilege-escalation
 * vulnerabilities across the three roles the protocol defines:
 *
 *   admin    — can assign/revoke roles and upgrade the contract
 *   verifier — can authorise regulated-asset operations
 *   pauser   — can pause/unpause the protocol
 *
 * It also covers the two wave-level additions that expand the attack surface:
 *
 *   multi-sig quorum  — an m-of-n signing policy guarding admin operations
 *   timelock          — a mandatory delay between proposal and execution
 *
 * Attack tree covered (see docs/THREAT_MODEL.md for the full written report):
 *
 *   ROOT GOAL: Escalate to admin without holding the admin role
 *
 *   A. Role-assignment paths
 *      A1. Self-assign admin via set_admin without prior admin role  [FIXED]
 *      A2. Assign verifier/pauser to attacker-controlled address     [FIXED]
 *      A3. Remove admin from legitimate holder to lock out governance [FIXED]
 *
 *   B. Quorum bypass paths
 *      B1. Execute admin action with 0 approvals                     [FIXED]
 *      B2. Execute admin action with partial quorum (< threshold)    [FIXED]
 *      B3. Replay already-used approval set                          [FIXED]
 *      B4. Forge quorum by supplying duplicate signers               [FIXED]
 *
 *   C. Timelock bypass paths
 *      C1. Execute proposal before timelock delay expires            [FIXED]
 *      C2. Cancel a pending proposal from an unauthorised caller     [FIXED]
 *      C3. Partial-quorum + stale pending action combination         [FIXED]
 *
 * Diagnostics emitted:
 *   access-control/unprotected-role-assignment      (error)
 *   access-control/unprotected-role-removal         (error)
 *   access-control/quorum-bypass-risk               (error)
 *   access-control/timelock-bypass-risk             (error)
 *   access-control/single-admin-lockout-risk        (warning)
 *   access-control/stale-pending-action-risk        (warning)
 *
 * Runs under opt-in --check-network; never throws on RPC / network faults.
 */

import type { xdr } from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { fetchContractWasm, severityFor } from './rpc.js';
import { extractContractSpecEntries } from './wasm-auditor.js';
import { rpcUrlFor } from '../rules/display-decimals-audit.js';
import { contractCurrenciesOf } from '../rules/currencies.js';

// ─── Rule IDs ────────────────────────────────────────────────────────────────

export const UNPROTECTED_ROLE_ASSIGNMENT_RULE =
  'access-control/unprotected-role-assignment';
export const UNPROTECTED_ROLE_REMOVAL_RULE =
  'access-control/unprotected-role-removal';
export const QUORUM_BYPASS_RISK_RULE = 'access-control/quorum-bypass-risk';
export const TIMELOCK_BYPASS_RISK_RULE = 'access-control/timelock-bypass-risk';
export const SINGLE_ADMIN_LOCKOUT_RULE = 'access-control/single-admin-lockout-risk';
export const STALE_PENDING_ACTION_RULE = 'access-control/stale-pending-action-risk';

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Sensitive role-management function names that MUST require authorisation.
 * Any contract exposing these without an Address parameter is vulnerable to
 * privilege escalation (attack paths A1–A3).
 */
export const ROLE_ASSIGNMENT_FUNCTIONS = [
  'set_admin',
  'set_owner',
  'grant_role',
  'revoke_role',
  'add_admin',
  'remove_admin',
  'transfer_admin',
  'transfer_ownership',
  'set_administrator',
  'assign_role',
  'remove_role',
] as const;

/**
 * Functions whose names strongly suggest quorum/multi-sig management.
 * Contracts exposing these must accept an Address parameter AND declare
 * a threshold argument (u32/i128/u64) to guard against quorum-bypass
 * (attack paths B1–B4).
 */
export const QUORUM_MANAGEMENT_FUNCTIONS = [
  'set_quorum',
  'update_quorum',
  'set_threshold',
  'update_threshold',
  'submit_proposal',
  'approve_proposal',
  'execute_proposal',
  'cast_vote',
  'add_signer',
  'remove_signer',
] as const;

/**
 * Functions whose names strongly suggest timelock management.
 * Contracts exposing these must accept an Address parameter AND declare
 * a numeric delay argument to guard against timelock-bypass (attack paths
 * C1–C3).
 */
export const TIMELOCK_MANAGEMENT_FUNCTIONS = [
  'set_timelock',
  'update_timelock',
  'set_delay',
  'execute_after_delay',
  'schedule_operation',
  'cancel_operation',
  'queue_operation',
  'execute_operation',
] as const;

// ─── Types ───────────────────────────────────────────────────────────────────

export interface AccessControlAuditorOptions {
  rules?: RuleOverrides;
  path?: string;
  rpcUrl?: string;
}

/** Shape of one decoded function spec entry. */
interface FunctionSpec {
  name: string;
  hasAddressInput: boolean;
  hasNumericInput: boolean;
  inputCount: number;
}

// ─── Core logic ──────────────────────────────────────────────────────────────

/**
 * Decodes every function-spec entry from contract WASM into the minimal shape
 * the auditor needs. Returns an empty array when the WASM has no spec section.
 */
export function extractFunctionSpecs(wasm: Buffer): FunctionSpec[] {
  const entries: xdr.ScSpecEntry[] | undefined = extractContractSpecEntries(wasm);
  if (!entries || entries.length === 0) return [];

  const out: FunctionSpec[] = [];
  for (const entry of entries) {
    if (entry.switch().name !== 'scSpecEntryFunctionV0') continue;
    const fn = entry.functionV0();
    const name: string = fn.name().toString('utf8');
    const inputs = fn.inputs();
    let hasAddressInput = false;
    let hasNumericInput = false;
    for (const input of inputs) {
      const typeName = input.type().switch().name;
      if (typeName === 'scSpecTypeAddress') hasAddressInput = true;
      if (
        typeName === 'scSpecTypeU32' ||
        typeName === 'scSpecTypeU64' ||
        typeName === 'scSpecTypeI128' ||
        typeName === 'scSpecTypeU128' ||
        typeName === 'scSpecTypeI64'
      )
        hasNumericInput = true;
    }
    out.push({ name, hasAddressInput, hasNumericInput, inputCount: inputs.length });
  }
  return out;
}

/** Builds a Diagnostic factory for a given contract. */
function makeFinding(
  contractId: string,
  options: AccessControlAuditorOptions,
): (
  rule: string,
  fallback: 'error' | 'warning',
  message: string,
  suggestion?: string,
) => Diagnostic[] {
  return (rule, fallback, message, suggestion) => {
    const severity = severityFor(rule, fallback, options.rules);
    if (severity === undefined) return [];
    return [
      {
        rule,
        severity,
        category: 'network',
        message: `Contract ${contractId}: ${message}`,
        ...(options.path !== undefined ? { path: options.path } : {}),
        ...(suggestion !== undefined ? { suggestion } : {}),
      },
    ];
  };
}

/**
 * Analyses WASM bytecode for access-control vulnerabilities and returns any
 * diagnostics found. Pure — does no I/O.
 */
export function verifyAccessControl(
  wasm: Buffer,
  contractId: string,
  options: AccessControlAuditorOptions = {},
): Diagnostic[] {
  const specs = extractFunctionSpecs(wasm);
  if (specs.length === 0) return [];

  const diagnostics: Diagnostic[] = [];
  const finding = makeFinding(contractId, options);
  const functionNames = new Set(specs.map((f) => f.name));

  // ── Attack path A: Role-assignment / removal ──────────────────────────────

  for (const spec of specs) {
    const isRoleAssignment = (ROLE_ASSIGNMENT_FUNCTIONS as readonly string[]).includes(spec.name);
    if (!isRoleAssignment) continue;

    if (!spec.hasAddressInput) {
      // A1 / A2: role-assignment function with no Address parameter means any
      //          caller can invoke it — direct privilege escalation.
      diagnostics.push(
        ...finding(
          UNPROTECTED_ROLE_ASSIGNMENT_RULE,
          'error',
          `function "${spec.name}" assigns or transfers a privileged role but accepts no Address parameter — any caller can escalate privileges`,
          `Add an Address parameter (caller or new-role-holder) to "${spec.name}" and call require_auth() before mutating role state.`,
        ),
      );
    }

    if (spec.inputCount === 0) {
      // A3: zero-argument role function is trivially callable by anyone,
      //     potentially removing the only admin and locking governance.
      diagnostics.push(
        ...finding(
          UNPROTECTED_ROLE_REMOVAL_RULE,
          'error',
          `function "${spec.name}" takes zero arguments — a zero-argument role function can be called by any account and may irrevocably remove the admin role`,
          `Add at least a caller Address parameter to "${spec.name}". For removal functions, consider requiring a two-step handover.`,
        ),
      );
    }
  }

  // ── Attack path B: Quorum bypass ─────────────────────────────────────────

  const hasQuorumFunctions = specs.some((f) =>
    (QUORUM_MANAGEMENT_FUNCTIONS as readonly string[]).includes(f.name),
  );

  if (hasQuorumFunctions) {
    for (const spec of specs) {
      const isQuorumFn = (QUORUM_MANAGEMENT_FUNCTIONS as readonly string[]).includes(spec.name);
      if (!isQuorumFn) continue;

      if (!spec.hasAddressInput) {
        // B1 / B2: quorum management without caller identity — threshold
        // checks can be bypassed entirely.
        diagnostics.push(
          ...finding(
            QUORUM_BYPASS_RISK_RULE,
            'error',
            `quorum/multi-sig management function "${spec.name}" lacks an Address parameter — quorum checks can be bypassed by an unauthenticated caller`,
            `Require an Address parameter in "${spec.name}" and enforce require_auth() so only authorised signers can affect the quorum.`,
          ),
        );
      }

      if (!spec.hasNumericInput) {
        // B3 / B4: quorum function without a numeric threshold or nonce
        // argument cannot encode the required vote count, enabling quorum
        // bypass via threshold confusion.
        diagnostics.push(
          ...finding(
            QUORUM_BYPASS_RISK_RULE,
            'error',
            `quorum/multi-sig management function "${spec.name}" has no numeric threshold or nonce argument — missing a quorum count enables threshold-confusion attacks`,
            `Add a numeric threshold or proposal-nonce parameter to "${spec.name}" to prevent quorum bypass through parameter omission.`,
          ),
        );
      }
    }

    // B4: duplicate-signer check — if execute_proposal exists but
    // add_signer / remove_signer have no address guard, an attacker can
    // register the same signer multiple times.
    const executeProposal = specs.find((f) => f.name === 'execute_proposal');
    const addSigner = specs.find((f) => f.name === 'add_signer');
    if (executeProposal !== undefined && addSigner !== undefined && !addSigner.hasAddressInput) {
      diagnostics.push(
        ...finding(
          QUORUM_BYPASS_RISK_RULE,
          'error',
          `"add_signer" accepts no Address parameter while "execute_proposal" exists — duplicate signer registrations may inflate apparent quorum`,
          'Guard "add_signer" with require_auth() on the caller address and deduplicate signers on insertion.',
        ),
      );
    }
  }

  // ── Attack path C: Timelock bypass ───────────────────────────────────────

  const hasTimelockFunctions = specs.some((f) =>
    (TIMELOCK_MANAGEMENT_FUNCTIONS as readonly string[]).includes(f.name),
  );

  if (hasTimelockFunctions) {
    for (const spec of specs) {
      const isTimelockFn = (TIMELOCK_MANAGEMENT_FUNCTIONS as readonly string[]).includes(
        spec.name,
      );
      if (!isTimelockFn) continue;

      if (!spec.hasAddressInput) {
        // C1 / C2: timelock bypass by unauthenticated caller.
        diagnostics.push(
          ...finding(
            TIMELOCK_BYPASS_RISK_RULE,
            'error',
            `timelock function "${spec.name}" accepts no Address parameter — the timelock can be bypassed or cancelled by any account`,
            `Require an Address parameter in "${spec.name}" and enforce require_auth() so only the proposer or admin can interact with a pending operation.`,
          ),
        );
      }

      if (!spec.hasNumericInput) {
        // C1: execute-after-delay without a numeric delay argument means
        //     the delay period cannot be enforced on-chain.
        diagnostics.push(
          ...finding(
            TIMELOCK_BYPASS_RISK_RULE,
            'error',
            `timelock function "${spec.name}" has no numeric delay/ledger argument — the time constraint cannot be verified on-chain`,
            `Add a numeric delay (ledger count or timestamp) parameter to "${spec.name}" and compare it against the ledger sequence in the contract body.`,
          ),
        );
      }
    }

  }

  // ── Attack path C3: Partial-quorum + stale pending action interaction ─────
  //
  // This check is independent of whether formal timelock functions exist.
  // The vulnerability arises whenever submit_proposal (quorum path) and any
  // execute path co-exist without a shared numeric nonce — a stale
  // partial-quorum proposal becomes indistinguishable from a fresh one,
  // and can combine with an expired timelock window to replay an operation.
  const hasSubmitProposal = functionNames.has('submit_proposal');
  const hasExecuteOperation =
    functionNames.has('execute_operation') ||
    functionNames.has('execute_after_delay') ||
    functionNames.has('execute_proposal');

  if (hasSubmitProposal && hasExecuteOperation) {
    const submitSpec = specs.find((f) => f.name === 'submit_proposal');
    const executeSpec =
      specs.find((f) => f.name === 'execute_operation') ??
      specs.find((f) => f.name === 'execute_after_delay') ??
      specs.find((f) => f.name === 'execute_proposal');

    if (
      submitSpec !== undefined &&
      executeSpec !== undefined &&
      !submitSpec.hasNumericInput &&
      !executeSpec.hasNumericInput
    ) {
      diagnostics.push(
        ...finding(
          STALE_PENDING_ACTION_RULE,
          'warning',
          '"submit_proposal" and the execute function share no numeric nonce/timestamp — a stale partial-quorum proposal may combine with an expired timelock window to replay an operation',
          'Require a shared numeric proposal-id or ledger-sequence parameter in both "submit_proposal" and the execute function, and reject replays by storing executed proposal ids.',
        ),
      );
    }
  }

  // ── Structural warnings ───────────────────────────────────────────────────

  // If the contract has any admin-role function but no role-transfer or
  // set_admin, there is no recovery path if the admin key is lost.
  const hasAnyAdminFn = specs.some(
    (f) => f.name === 'set_admin' || f.name === 'transfer_admin' || f.name === 'add_admin',
  );
  const hasRemoveAdmin = specs.some(
    (f) => f.name === 'remove_admin' || f.name === 'revoke_role',
  );

  if (hasAnyAdminFn && hasRemoveAdmin && !functionNames.has('transfer_admin')) {
    diagnostics.push(
      ...finding(
        SINGLE_ADMIN_LOCKOUT_RULE,
        'warning',
        'contract exposes "remove_admin" or "revoke_role" but no "transfer_admin" — removing the last admin permanently locks governance',
        'Implement a "transfer_admin" or two-step admin handover pattern so at least one admin always holds the role.',
      ),
    );
  }

  return diagnostics;
}

// ─── Network-backed entry points ─────────────────────────────────────────────

/**
 * Fetches a single deployed contract's WASM and audits it for access-control
 * vulnerabilities. Silently returns `[]` on any RPC or parse error.
 */
export async function auditContractAccessControl(
  contractId: string,
  rpcUrl: string,
  fetchImpl: typeof fetch = fetch,
  options: AccessControlAuditorOptions = {},
): Promise<Diagnostic[]> {
  const wasm = await fetchContractWasm(contractId, rpcUrl, fetchImpl);
  if (wasm === undefined) return [];
  return verifyAccessControl(wasm, contractId, options);
}

/**
 * Audits every contract declared under `[[CURRENCIES]]` in a stellar.toml
 * document for access-control vulnerabilities. Silent when no RPC URL can be
 * derived.
 */
export async function auditTomlAccessControl(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: AccessControlAuditorOptions = {},
): Promise<Diagnostic[]> {
  const passphrase =
    typeof doc.NETWORK_PASSPHRASE === 'string' ? doc.NETWORK_PASSPHRASE : undefined;
  const rpcUrl = options.rpcUrl ?? rpcUrlFor(passphrase);
  if (!rpcUrl) return [];

  const diagnostics: Diagnostic[] = [];
  for (const currency of contractCurrenciesOf(doc)) {
    diagnostics.push(
      ...(await auditContractAccessControl(currency.id, rpcUrl, fetchImpl, {
        ...options,
        path: currency.path,
      })),
    );
  }
  return diagnostics;
}

// ─── Rule registry ───────────────────────────────────────────────────────────

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const accessControlAuditorRules: Rule[] = [
  {
    id: UNPROTECTED_ROLE_ASSIGNMENT_RULE,
    category: 'network',
    severity: 'error',
    description:
      'A Soroban role-assignment function lacks an Address parameter, enabling privilege escalation',
    run() {},
  },
  {
    id: UNPROTECTED_ROLE_REMOVAL_RULE,
    category: 'network',
    severity: 'error',
    description:
      'A Soroban role-removal function accepts no arguments, enabling any caller to lock out governance',
    run() {},
  },
  {
    id: QUORUM_BYPASS_RISK_RULE,
    category: 'network',
    severity: 'error',
    description:
      'A Soroban multi-sig quorum function is missing an Address or threshold parameter, enabling quorum bypass',
    run() {},
  },
  {
    id: TIMELOCK_BYPASS_RISK_RULE,
    category: 'network',
    severity: 'error',
    description:
      'A Soroban timelock function is missing an Address or numeric-delay parameter, enabling timelock bypass',
    run() {},
  },
  {
    id: SINGLE_ADMIN_LOCKOUT_RULE,
    category: 'network',
    severity: 'warning',
    description:
      'A Soroban contract can remove its admin with no transfer path, risking permanent governance lockout',
    run() {},
  },
  {
    id: STALE_PENDING_ACTION_RULE,
    category: 'network',
    severity: 'warning',
    description:
      'A Soroban contract combining multi-sig quorum and timelock lacks a shared nonce, enabling stale-proposal replay',
    run() {},
  },
];

/** Rule ids emitted by {@link auditTomlAccessControl}. */
export const accessControlAuditorRuleIds: readonly string[] = accessControlAuditorRules.map(
  (rule) => rule.id,
);
