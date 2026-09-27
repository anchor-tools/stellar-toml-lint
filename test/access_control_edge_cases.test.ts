/**
 * Access-Control Role Escalation Penetration Tests — Issue #810
 *
 * Structured as an explicit attack tree that mirrors docs/THREAT_MODEL.md.
 * Every describe block maps to one branch of the tree; every `it` block is
 * either a "proven safe" path or a "confirmed finding" with a regression test
 * that would have caught the vulnerability before the fix.
 *
 * Coverage target: ≥ 90 % of the access-control-auditor module lines.
 *
 * Attack tree root: Escalate to admin without holding the admin role.
 *
 *   A. Role-assignment / removal paths
 *   B. Quorum bypass paths (multi-sig)
 *   C. Timelock bypass paths
 *   D. Combined quorum + timelock interaction paths
 *   E. Network / RPC edge cases (graceful degradation)
 *   F. Rule registry smoke tests
 */

import { describe, expect, it } from 'vitest';
import { xdr } from '@stellar/stellar-base';
import {
  // Rule IDs
  UNPROTECTED_ROLE_ASSIGNMENT_RULE,
  UNPROTECTED_ROLE_REMOVAL_RULE,
  QUORUM_BYPASS_RISK_RULE,
  TIMELOCK_BYPASS_RISK_RULE,
  SINGLE_ADMIN_LOCKOUT_RULE,
  STALE_PENDING_ACTION_RULE,
  // Pure analysis
  verifyAccessControl,
  extractFunctionSpecs,
  // Network-backed entry points
  auditContractAccessControl,
  auditTomlAccessControl,
  // Rule registry
  accessControlAuditorRules,
  accessControlAuditorRuleIds,
  // Constant lists (for property-style tests)
  ROLE_ASSIGNMENT_FUNCTIONS,
  QUORUM_MANAGEMENT_FUNCTIONS,
  TIMELOCK_MANAGEMENT_FUNCTIONS,
} from '../src/soroban/access-control-auditor.js';
import {
  specWasm,
  instanceEntryXdr,
  codeEntryXdr,
  adminStorage,
} from './soroban-fixtures.js';

// ─── Shared test helpers ──────────────────────────────────────────────────────

const CONTRACT = 'CACTZSQPCQSSZ5YG3PI3N7WO6JEERKEUHTPILKB4MBANF2K4D2UHKDDU';
const ADMIN = 'GDVEU3DD4KOFECV66VIHWEZOYX4ZKR3WV27L464SIIPOU2IUI3JCZA57';
const ATTACKER = 'GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H';
const RPC = 'https://rpc.test';
const WASM_HASH = Buffer.alloc(32, 0xac);

/**
 * Builds a WASM module with the given function specs.
 * Every entry in `fns` maps to one ScSpecEntryFunctionV0.
 */
function makeWasm(
  fns: Array<{
    name: string;
    inputs?: Array<{ name: string; type: 'address' | 'u32' | 'i128' | 'u64' | 'string' }>;
  }>,
): Buffer {
  const entries = fns.map(({ name, inputs = [] }) => {
    const params = inputs.map(
      (inp) =>
        new xdr.ScSpecFunctionInputV0({
          doc: '',
          name: inp.name,
          type: resolveSpecType(inp.type),
        }),
    );
    return xdr.ScSpecEntry.scSpecEntryFunctionV0(
      new xdr.ScSpecFunctionV0({ doc: '', name, inputs: params, outputs: [] }),
    );
  });
  return specWasm(entries);
}

function resolveSpecType(
  t: 'address' | 'u32' | 'i128' | 'u64' | 'string',
): xdr.ScSpecTypeDef {
  switch (t) {
    case 'address':
      return xdr.ScSpecTypeDef.scSpecTypeAddress();
    case 'u32':
      return xdr.ScSpecTypeDef.scSpecTypeU32();
    case 'u64':
      return xdr.ScSpecTypeDef.scSpecTypeU64();
    case 'string':
      return xdr.ScSpecTypeDef.scSpecTypeString();
    case 'i128':
    default:
      return xdr.ScSpecTypeDef.scSpecTypeI128();
  }
}

/**
 * Minimal RPC stub. Serves both instance and code entries based on the ledger
 * key type, exactly as the real network does.
 */
function makeRpcFetch(wasm: Buffer): typeof fetch {
  const instanceXdr = instanceEntryXdr({
    contractId: CONTRACT,
    wasmHash: WASM_HASH,
    storage: [adminStorage('admin', ADMIN)],
  });
  const codeXdr = codeEntryXdr(wasm, WASM_HASH);

  return (async (_url: string | URL | Request, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)) as { params: { keys: string[] } };
    const key = body.params.keys[0] as string;
    const kind = xdr.LedgerKey.fromXDR(key, 'base64').switch().name;
    const entryXdr = kind === 'contractCode' ? codeXdr : instanceXdr;
    return new Response(
      JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        result: { latestLedger: 1000, entries: [{ xdr: entryXdr, liveUntilLedgerSeq: 2000 }] },
      }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );
  }) as unknown as typeof fetch;
}

// ─── A. Role-assignment / removal attack paths ────────────────────────────────

describe('Attack path A — Role-assignment and removal (issue #810)', () => {
  // ── A1 / A2: self-assignment via unguarded set_admin ──────────────────────

  it('A1 EXPLOIT: zero-arg set_admin allows any caller to seize admin role — regression test', () => {
    // THREAT: attacker calls set_admin() with no arguments and becomes admin.
    // FIX: the auditor MUST flag this as an error.
    const wasm = makeWasm([{ name: 'set_admin', inputs: [] }]);
    const diagnostics = verifyAccessControl(wasm, CONTRACT);

    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: UNPROTECTED_ROLE_ASSIGNMENT_RULE,
        severity: 'error',
      }),
    );
    // The zero-arg removal rule also fires (double-gate).
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: UNPROTECTED_ROLE_REMOVAL_RULE,
        severity: 'error',
      }),
    );
  });

  it('A2 EXPLOIT: set_admin with only a numeric arg (no Address) allows unconstrained reassignment', () => {
    // THREAT: attacker calls set_admin(0) where 0 is an index — no identity check.
    const wasm = makeWasm([{ name: 'set_admin', inputs: [{ name: 'slot', type: 'u32' }] }]);
    const diagnostics = verifyAccessControl(wasm, CONTRACT);

    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: UNPROTECTED_ROLE_ASSIGNMENT_RULE,
        severity: 'error',
      }),
    );
  });

  it('A2 SAFE: set_admin with Address parameter passes — no role-assignment finding', () => {
    // PROOF: correctly guarded set_admin must NOT produce an escalation finding.
    const wasm = makeWasm([
      { name: 'set_admin', inputs: [{ name: 'new_admin', type: 'address' }] },
    ]);
    const diagnostics = verifyAccessControl(wasm, CONTRACT);

    expect(diagnostics.filter((d) => d.rule === UNPROTECTED_ROLE_ASSIGNMENT_RULE)).toHaveLength(0);
  });

  it('A2 EXPLOIT: grant_role without Address enables arbitrary role assignment — regression test', () => {
    const wasm = makeWasm([{ name: 'grant_role', inputs: [{ name: 'role_id', type: 'u32' }] }]);
    const diagnostics = verifyAccessControl(wasm, CONTRACT);

    expect(diagnostics).toContainEqual(
      expect.objectContaining({ rule: UNPROTECTED_ROLE_ASSIGNMENT_RULE, severity: 'error' }),
    );
  });

  it('A2 SAFE: grant_role with Address parameter does not produce an escalation finding', () => {
    const wasm = makeWasm([
      {
        name: 'grant_role',
        inputs: [
          { name: 'to', type: 'address' },
          { name: 'role_id', type: 'u32' },
        ],
      },
    ]);
    const diagnostics = verifyAccessControl(wasm, CONTRACT);
    expect(diagnostics.filter((d) => d.rule === UNPROTECTED_ROLE_ASSIGNMENT_RULE)).toHaveLength(0);
  });

  // ── A3: admin lockout via zero-arg remove ─────────────────────────────────

  it('A3 EXPLOIT: zero-arg remove_admin allows anyone to irrevocably strip governance — regression test', () => {
    // THREAT: attacker calls remove_admin() with no args. Last admin is gone forever.
    const wasm = makeWasm([{ name: 'remove_admin', inputs: [] }]);
    const diagnostics = verifyAccessControl(wasm, CONTRACT);

    expect(diagnostics).toContainEqual(
      expect.objectContaining({ rule: UNPROTECTED_ROLE_REMOVAL_RULE, severity: 'error' }),
    );
  });

  it('A3 EXPLOIT: zero-arg revoke_role allows stripping any role without identity — regression test', () => {
    const wasm = makeWasm([{ name: 'revoke_role', inputs: [] }]);
    const diagnostics = verifyAccessControl(wasm, CONTRACT);

    expect(diagnostics).toContainEqual(
      expect.objectContaining({ rule: UNPROTECTED_ROLE_REMOVAL_RULE, severity: 'error' }),
    );
  });

  it('A3 SAFE: remove_admin with Address parameter does not produce a removal finding', () => {
    const wasm = makeWasm([
      { name: 'remove_admin', inputs: [{ name: 'admin', type: 'address' }] },
    ]);
    const diagnostics = verifyAccessControl(wasm, CONTRACT);
    expect(diagnostics.filter((d) => d.rule === UNPROTECTED_ROLE_REMOVAL_RULE)).toHaveLength(0);
  });

  // Property test: every role-assignment function name triggers the rule when
  // the function has no inputs at all.
  it('A-PROPERTY: all ROLE_ASSIGNMENT_FUNCTIONS without inputs each trigger an error', () => {
    for (const fnName of ROLE_ASSIGNMENT_FUNCTIONS) {
      const wasm = makeWasm([{ name: fnName, inputs: [] }]);
      const diagnostics = verifyAccessControl(wasm, CONTRACT);
      const roleFindings = diagnostics.filter(
        (d) =>
          d.rule === UNPROTECTED_ROLE_ASSIGNMENT_RULE || d.rule === UNPROTECTED_ROLE_REMOVAL_RULE,
      );
      expect(roleFindings.length, `Expected finding for "${fnName}"`).toBeGreaterThan(0);
    }
  });

  // A-LOCKOUT: remove_admin + revoke_role present but no transfer_admin → structural warning
  it('A-LOCKOUT EXPLOIT: contract with remove_admin but no transfer path risks permanent lockout', () => {
    const wasm = makeWasm([
      { name: 'set_admin', inputs: [{ name: 'new_admin', type: 'address' }] },
      { name: 'add_admin', inputs: [{ name: 'a', type: 'address' }] },
      { name: 'remove_admin', inputs: [{ name: 'a', type: 'address' }] },
    ]);
    const diagnostics = verifyAccessControl(wasm, CONTRACT);

    expect(diagnostics).toContainEqual(
      expect.objectContaining({ rule: SINGLE_ADMIN_LOCKOUT_RULE, severity: 'warning' }),
    );
  });

  it('A-LOCKOUT SAFE: transfer_admin present suppresses lockout warning', () => {
    const wasm = makeWasm([
      { name: 'set_admin', inputs: [{ name: 'new_admin', type: 'address' }] },
      { name: 'add_admin', inputs: [{ name: 'a', type: 'address' }] },
      { name: 'remove_admin', inputs: [{ name: 'a', type: 'address' }] },
      { name: 'transfer_admin', inputs: [{ name: 'new_admin', type: 'address' }] },
    ]);
    const diagnostics = verifyAccessControl(wasm, CONTRACT);
    expect(diagnostics.filter((d) => d.rule === SINGLE_ADMIN_LOCKOUT_RULE)).toHaveLength(0);
  });
});

// ─── B. Quorum bypass attack paths ───────────────────────────────────────────

describe('Attack path B — Multi-sig quorum bypass (issue #810)', () => {
  // ── B1: execute with zero approvals ──────────────────────────────────────

  it('B1 EXPLOIT: set_quorum without Address allows threshold reset to 0 — regression test', () => {
    // THREAT: attacker calls set_quorum() with no identity check; sets threshold
    // to 0 and then executes any proposal immediately.
    const wasm = makeWasm([
      {
        name: 'set_quorum',
        inputs: [{ name: 'n', type: 'u32' }], // threshold but no caller identity
      },
    ]);
    const diagnostics = verifyAccessControl(wasm, CONTRACT);

    expect(diagnostics).toContainEqual(
      expect.objectContaining({ rule: QUORUM_BYPASS_RISK_RULE, severity: 'error' }),
    );
  });

  it('B1 SAFE: set_quorum with both Address and threshold passes quorum check', () => {
    const wasm = makeWasm([
      {
        name: 'set_quorum',
        inputs: [
          { name: 'caller', type: 'address' },
          { name: 'threshold', type: 'u32' },
        ],
      },
    ]);
    const diagnostics = verifyAccessControl(wasm, CONTRACT);
    expect(diagnostics.filter((d) => d.rule === QUORUM_BYPASS_RISK_RULE)).toHaveLength(0);
  });

  // ── B2: partial quorum execution ─────────────────────────────────────────

  it('B2 EXPLOIT: approve_proposal without Address allows phantom approvals — regression test', () => {
    // THREAT: anyone can call approve_proposal() and inflate the approval count.
    const wasm = makeWasm([
      {
        name: 'approve_proposal',
        inputs: [{ name: 'proposal_id', type: 'u32' }], // no signer identity
      },
    ]);
    const diagnostics = verifyAccessControl(wasm, CONTRACT);

    expect(diagnostics).toContainEqual(
      expect.objectContaining({ rule: QUORUM_BYPASS_RISK_RULE, severity: 'error' }),
    );
  });

  it('B2 SAFE: approve_proposal with Address and proposal_id passes', () => {
    const wasm = makeWasm([
      {
        name: 'approve_proposal',
        inputs: [
          { name: 'signer', type: 'address' },
          { name: 'proposal_id', type: 'u32' },
        ],
      },
    ]);
    const diagnostics = verifyAccessControl(wasm, CONTRACT);
    expect(diagnostics.filter((d) => d.rule === QUORUM_BYPASS_RISK_RULE)).toHaveLength(0);
  });

  // ── B3: replay of approval set ────────────────────────────────────────────

  it('B3 EXPLOIT: execute_proposal without threshold/nonce enables approval replay — regression test', () => {
    // THREAT: execute_proposal() with no nonce allows a replayed approval
    // set from a previous proposal to immediately execute a new one.
    const wasm = makeWasm([
      {
        name: 'execute_proposal',
        inputs: [
          { name: 'caller', type: 'address' },
          // missing numeric nonce → replay attack
        ],
      },
    ]);
    const diagnostics = verifyAccessControl(wasm, CONTRACT);

    expect(diagnostics).toContainEqual(
      expect.objectContaining({ rule: QUORUM_BYPASS_RISK_RULE, severity: 'error' }),
    );
  });

  // ── B4: duplicate signer inflation ───────────────────────────────────────

  it('B4 EXPLOIT: add_signer without Address guard + execute_proposal enables duplicate signer quorum — regression test', () => {
    // THREAT: attacker calls add_signer() without auth and registers their
    // address N times to reach quorum alone.
    const wasm = makeWasm([
      {
        name: 'add_signer',
        inputs: [{ name: 'weight', type: 'u32' }], // no address identity
      },
      {
        name: 'execute_proposal',
        inputs: [
          { name: 'caller', type: 'address' },
          { name: 'nonce', type: 'u32' },
        ],
      },
    ]);
    const diagnostics = verifyAccessControl(wasm, CONTRACT);

    // Should find quorum-bypass for add_signer (missing address),
    // and the duplicate-signer finding.
    const quorumFindings = diagnostics.filter((d) => d.rule === QUORUM_BYPASS_RISK_RULE);
    expect(quorumFindings.length).toBeGreaterThanOrEqual(1);
  });

  it('B4 SAFE: add_signer with Address guard does not produce duplicate-signer finding', () => {
    const wasm = makeWasm([
      {
        name: 'add_signer',
        inputs: [
          { name: 'signer', type: 'address' },
          { name: 'weight', type: 'u32' },
        ],
      },
      {
        name: 'execute_proposal',
        inputs: [
          { name: 'caller', type: 'address' },
          { name: 'nonce', type: 'u32' },
        ],
      },
    ]);
    const diagnostics = verifyAccessControl(wasm, CONTRACT);
    expect(diagnostics.filter((d) => d.rule === QUORUM_BYPASS_RISK_RULE)).toHaveLength(0);
  });

  // Property test: every QUORUM_MANAGEMENT_FUNCTIONS entry with no inputs fires
  it('B-PROPERTY: all QUORUM_MANAGEMENT_FUNCTIONS without inputs trigger quorum-bypass error', () => {
    for (const fnName of QUORUM_MANAGEMENT_FUNCTIONS) {
      const wasm = makeWasm([{ name: fnName, inputs: [] }]);
      const diagnostics = verifyAccessControl(wasm, CONTRACT);
      const findings = diagnostics.filter((d) => d.rule === QUORUM_BYPASS_RISK_RULE);
      expect(findings.length, `Expected quorum finding for "${fnName}"`).toBeGreaterThan(0);
    }
  });
});

// ─── C. Timelock bypass attack paths ─────────────────────────────────────────

describe('Attack path C — Timelock bypass (issue #810)', () => {
  // ── C1: execute before delay ──────────────────────────────────────────────

  it('C1 EXPLOIT: execute_after_delay without a numeric delay arg allows immediate execution — regression test', () => {
    // THREAT: attacker calls execute_after_delay(caller) with no delay value;
    // the contract has no on-chain way to verify any waiting period.
    const wasm = makeWasm([
      {
        name: 'execute_after_delay',
        inputs: [{ name: 'caller', type: 'address' }],
        // missing numeric delay → timelock trivially bypassed
      },
    ]);
    const diagnostics = verifyAccessControl(wasm, CONTRACT);

    expect(diagnostics).toContainEqual(
      expect.objectContaining({ rule: TIMELOCK_BYPASS_RISK_RULE, severity: 'error' }),
    );
  });

  it('C1 SAFE: execute_after_delay with both Address and numeric delay passes', () => {
    const wasm = makeWasm([
      {
        name: 'execute_after_delay',
        inputs: [
          { name: 'caller', type: 'address' },
          { name: 'delay_ledgers', type: 'u64' },
        ],
      },
    ]);
    const diagnostics = verifyAccessControl(wasm, CONTRACT);
    expect(diagnostics.filter((d) => d.rule === TIMELOCK_BYPASS_RISK_RULE)).toHaveLength(0);
  });

  // ── C2: unauthorised cancel ───────────────────────────────────────────────

  it('C2 EXPLOIT: cancel_operation without Address allows any account to nullify pending ops — regression test', () => {
    // THREAT: attacker cancels a legitimate admin operation before it executes.
    const wasm = makeWasm([
      {
        name: 'cancel_operation',
        inputs: [{ name: 'op_id', type: 'u32' }], // no identity check
      },
    ]);
    const diagnostics = verifyAccessControl(wasm, CONTRACT);

    expect(diagnostics).toContainEqual(
      expect.objectContaining({ rule: TIMELOCK_BYPASS_RISK_RULE, severity: 'error' }),
    );
  });

  it('C2 SAFE: cancel_operation with Address and op_id does not produce a timelock finding', () => {
    const wasm = makeWasm([
      {
        name: 'cancel_operation',
        inputs: [
          { name: 'caller', type: 'address' },
          { name: 'op_id', type: 'u32' },
        ],
      },
    ]);
    const diagnostics = verifyAccessControl(wasm, CONTRACT);
    expect(diagnostics.filter((d) => d.rule === TIMELOCK_BYPASS_RISK_RULE)).toHaveLength(0);
  });

  // ── C3: stale + partial quorum combo is tested in section D ──────────────

  // Property test
  it('C-PROPERTY: all TIMELOCK_MANAGEMENT_FUNCTIONS without inputs trigger timelock-bypass error', () => {
    for (const fnName of TIMELOCK_MANAGEMENT_FUNCTIONS) {
      const wasm = makeWasm([{ name: fnName, inputs: [] }]);
      const diagnostics = verifyAccessControl(wasm, CONTRACT);
      const findings = diagnostics.filter((d) => d.rule === TIMELOCK_BYPASS_RISK_RULE);
      expect(findings.length, `Expected timelock finding for "${fnName}"`).toBeGreaterThan(0);
    }
  });
});

// ─── D. Combined quorum + timelock interaction paths ─────────────────────────

describe('Attack path D — Quorum + timelock interaction (issue #810)', () => {
  // ── C3 combined: partial-quorum + stale pending action ───────────────────

  it('C3 EXPLOIT: submit_proposal + execute_operation both lack nonce — stale-proposal replay — regression test', () => {
    // THREAT: attacker accumulates partial approvals on a stale proposal.
    // A separate expired timelock window re-activates it, combining the two
    // partial states into a completed exploit without ever reaching quorum.
    const wasm = makeWasm([
      {
        name: 'submit_proposal',
        inputs: [{ name: 'caller', type: 'address' }],
        // no nonce → stale proposals are indistinguishable from fresh ones
      },
      {
        name: 'execute_operation',
        inputs: [{ name: 'caller', type: 'address' }],
        // no nonce → can replay any partially-approved proposal
      },
      {
        name: 'set_quorum',
        inputs: [
          { name: 'caller', type: 'address' },
          { name: 'threshold', type: 'u32' },
        ],
      },
      {
        name: 'set_timelock',
        inputs: [
          { name: 'caller', type: 'address' },
          { name: 'delay', type: 'u64' },
        ],
      },
    ]);
    const diagnostics = verifyAccessControl(wasm, CONTRACT);

    expect(diagnostics).toContainEqual(
      expect.objectContaining({ rule: STALE_PENDING_ACTION_RULE, severity: 'warning' }),
    );
  });

  it('C3 SAFE: submit_proposal + execute_operation each carry a numeric nonce — no stale-replay finding', () => {
    const wasm = makeWasm([
      {
        name: 'submit_proposal',
        inputs: [
          { name: 'caller', type: 'address' },
          { name: 'proposal_id', type: 'u32' },
        ],
      },
      {
        name: 'execute_operation',
        inputs: [
          { name: 'caller', type: 'address' },
          { name: 'proposal_id', type: 'u32' },
        ],
      },
    ]);
    const diagnostics = verifyAccessControl(wasm, CONTRACT);
    expect(diagnostics.filter((d) => d.rule === STALE_PENDING_ACTION_RULE)).toHaveLength(0);
  });

  it('C3-VARIANT: submit_proposal + execute_proposal (naming variant) also triggers stale finding when both lack nonce', () => {
    const wasm = makeWasm([
      {
        name: 'submit_proposal',
        inputs: [{ name: 'caller', type: 'address' }],
      },
      {
        name: 'execute_proposal',
        inputs: [{ name: 'caller', type: 'address' }],
      },
    ]);
    const diagnostics = verifyAccessControl(wasm, CONTRACT);

    // execute_proposal also triggers quorum-bypass (no numeric) AND stale-replay
    expect(diagnostics).toContainEqual(
      expect.objectContaining({ rule: STALE_PENDING_ACTION_RULE, severity: 'warning' }),
    );
  });

  it('D-COMBINED: fully correct multi-sig + timelock contract emits zero findings', () => {
    // PROOF: a contract that correctly implements all safeguards produces no
    // diagnostics at all. This is the "green path" for a production-ready contract.
    const wasm = makeWasm([
      // Role management — all guarded
      { name: 'set_admin', inputs: [{ name: 'new_admin', type: 'address' }] },
      { name: 'transfer_admin', inputs: [{ name: 'new_admin', type: 'address' }] },
      { name: 'grant_role', inputs: [{ name: 'to', type: 'address' }, { name: 'role', type: 'u32' }] },
      { name: 'revoke_role', inputs: [{ name: 'from', type: 'address' }, { name: 'role', type: 'u32' }] },
      // Quorum management — address + threshold
      { name: 'set_quorum', inputs: [{ name: 'caller', type: 'address' }, { name: 'threshold', type: 'u32' }] },
      { name: 'submit_proposal', inputs: [{ name: 'caller', type: 'address' }, { name: 'nonce', type: 'u32' }] },
      { name: 'approve_proposal', inputs: [{ name: 'signer', type: 'address' }, { name: 'nonce', type: 'u32' }] },
      { name: 'execute_proposal', inputs: [{ name: 'caller', type: 'address' }, { name: 'nonce', type: 'u32' }] },
      { name: 'add_signer', inputs: [{ name: 'signer', type: 'address' }, { name: 'weight', type: 'u32' }] },
      // Timelock management — address + delay
      { name: 'set_timelock', inputs: [{ name: 'caller', type: 'address' }, { name: 'delay', type: 'u64' }] },
      { name: 'schedule_operation', inputs: [{ name: 'caller', type: 'address' }, { name: 'op_id', type: 'u32' }] },
      { name: 'cancel_operation', inputs: [{ name: 'caller', type: 'address' }, { name: 'op_id', type: 'u32' }] },
      { name: 'execute_operation', inputs: [{ name: 'caller', type: 'address' }, { name: 'op_id', type: 'u32' }] },
    ]);
    const diagnostics = verifyAccessControl(wasm, CONTRACT);
    expect(diagnostics).toHaveLength(0);
  });
});

// ─── E. Network / RPC edge cases ─────────────────────────────────────────────

describe('E — Network and RPC edge cases (issue #810)', () => {
  it('E1: returns empty diagnostics when WASM cannot be fetched (RPC unreachable)', async () => {
    // SAFETY: a network fault must never produce a false finding.
    const failingFetch = async (): Promise<Response> => {
      throw new Error('Network unreachable');
    };
    const diagnostics = await auditContractAccessControl(
      CONTRACT,
      RPC,
      failingFetch as unknown as typeof fetch,
    );
    expect(diagnostics).toEqual([]);
  });

  it('E2: returns empty diagnostics when RPC returns a non-200 status', async () => {
    const badFetch = async (): Promise<Response> =>
      new Response('Service Unavailable', { status: 503 });
    const diagnostics = await auditContractAccessControl(
      CONTRACT,
      RPC,
      badFetch as unknown as typeof fetch,
    );
    expect(diagnostics).toEqual([]);
  });

  it('E3: returns empty diagnostics when RPC returns malformed JSON', async () => {
    const malformedFetch = async (): Promise<Response> =>
      new Response('not-json', { status: 200, headers: { 'content-type': 'application/json' } });
    const diagnostics = await auditContractAccessControl(
      CONTRACT,
      RPC,
      malformedFetch as unknown as typeof fetch,
    );
    expect(diagnostics).toEqual([]);
  });

  it('E4: returns empty diagnostics when WASM has no contractspecv0 section', () => {
    // A plain WASM binary with no custom section.
    const emptyWasm = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
    const diagnostics = verifyAccessControl(emptyWasm, CONTRACT);
    expect(diagnostics).toEqual([]);
  });

  it('E5: returns empty diagnostics when spec section has no function entries', () => {
    // A WASM with a spec section that contains zero entries — e.g. a data-only contract.
    const wasm = specWasm([]);
    const diagnostics = verifyAccessControl(wasm, CONTRACT);
    expect(diagnostics).toEqual([]);
  });

  it('E6: auditTomlAccessControl returns empty when no RPC URL is derivable', async () => {
    const doc = { CURRENCIES: [{ code: 'TEST', contract: CONTRACT }] };
    const diagnostics = await auditTomlAccessControl(doc);
    expect(diagnostics).toEqual([]);
  });

  it('E7: auditTomlAccessControl audits contracts from [[CURRENCIES]] using provided RPC stub', async () => {
    const vulnWasm = makeWasm([{ name: 'set_admin', inputs: [] }]);
    const fetchImpl = makeRpcFetch(vulnWasm);

    const doc = {
      NETWORK_PASSPHRASE: 'Test SDF Network ; September 2015',
      CURRENCIES: [{ code: 'TEST', contract: CONTRACT }],
    };

    const diagnostics = await auditTomlAccessControl(doc, fetchImpl);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({ rule: UNPROTECTED_ROLE_ASSIGNMENT_RULE }),
    );
  });

  it('E8: rule severity is honoured — off disables the finding', () => {
    const wasm = makeWasm([{ name: 'set_admin', inputs: [] }]);
    const diagnostics = verifyAccessControl(wasm, CONTRACT, {
      rules: { [UNPROTECTED_ROLE_ASSIGNMENT_RULE]: 'off' },
    });
    expect(diagnostics.filter((d) => d.rule === UNPROTECTED_ROLE_ASSIGNMENT_RULE)).toHaveLength(0);
  });

  it('E9: rule severity is honoured — error promotes a warning to error', () => {
    const wasm = makeWasm([
      { name: 'set_admin', inputs: [{ name: 'new_admin', type: 'address' }] },
      { name: 'add_admin', inputs: [{ name: 'a', type: 'address' }] },
      { name: 'remove_admin', inputs: [{ name: 'a', type: 'address' }] },
    ]);
    const diagnostics = verifyAccessControl(wasm, CONTRACT, {
      rules: { [SINGLE_ADMIN_LOCKOUT_RULE]: 'error' },
    });
    const finding = diagnostics.find((d) => d.rule === SINGLE_ADMIN_LOCKOUT_RULE);
    expect(finding?.severity).toBe('error');
  });
});

// ─── F. extractFunctionSpecs and rule registry ────────────────────────────────

describe('F — extractFunctionSpecs and rule registry (issue #810)', () => {
  it('F1: extractFunctionSpecs returns correct hasAddressInput flag for address params', () => {
    const wasm = makeWasm([
      { name: 'only_address', inputs: [{ name: 'a', type: 'address' }] },
      { name: 'only_u32', inputs: [{ name: 'n', type: 'u32' }] },
      { name: 'no_inputs', inputs: [] },
    ]);
    const specs = extractFunctionSpecs(wasm);
    expect(specs.find((s) => s.name === 'only_address')?.hasAddressInput).toBe(true);
    expect(specs.find((s) => s.name === 'only_u32')?.hasAddressInput).toBe(false);
    expect(specs.find((s) => s.name === 'no_inputs')?.hasAddressInput).toBe(false);
  });

  it('F2: extractFunctionSpecs returns correct hasNumericInput flag', () => {
    const wasm = makeWasm([
      { name: 'with_u32', inputs: [{ name: 'n', type: 'u32' }] },
      { name: 'with_u64', inputs: [{ name: 'n', type: 'u64' }] },
      { name: 'with_i128', inputs: [{ name: 'n', type: 'i128' }] },
      { name: 'no_numeric', inputs: [{ name: 'a', type: 'address' }] },
    ]);
    const specs = extractFunctionSpecs(wasm);
    expect(specs.find((s) => s.name === 'with_u32')?.hasNumericInput).toBe(true);
    expect(specs.find((s) => s.name === 'with_u64')?.hasNumericInput).toBe(true);
    expect(specs.find((s) => s.name === 'with_i128')?.hasNumericInput).toBe(true);
    expect(specs.find((s) => s.name === 'no_numeric')?.hasNumericInput).toBe(false);
  });

  it('F3: extractFunctionSpecs returns empty array for WASM with no spec section', () => {
    const emptyWasm = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
    expect(extractFunctionSpecs(emptyWasm)).toEqual([]);
  });

  it('F4: accessControlAuditorRules contains all six rule definitions', () => {
    expect(accessControlAuditorRules.map((r) => r.id)).toEqual([
      UNPROTECTED_ROLE_ASSIGNMENT_RULE,
      UNPROTECTED_ROLE_REMOVAL_RULE,
      QUORUM_BYPASS_RISK_RULE,
      TIMELOCK_BYPASS_RISK_RULE,
      SINGLE_ADMIN_LOCKOUT_RULE,
      STALE_PENDING_ACTION_RULE,
    ]);
  });

  it('F5: accessControlAuditorRuleIds matches the rule id list', () => {
    expect(accessControlAuditorRuleIds).toEqual(
      accessControlAuditorRules.map((r) => r.id),
    );
  });

  it('F6: every rule has the correct default severity', () => {
    const severities = Object.fromEntries(
      accessControlAuditorRules.map((r) => [r.id, r.severity]),
    );
    expect(severities[UNPROTECTED_ROLE_ASSIGNMENT_RULE]).toBe('error');
    expect(severities[UNPROTECTED_ROLE_REMOVAL_RULE]).toBe('error');
    expect(severities[QUORUM_BYPASS_RISK_RULE]).toBe('error');
    expect(severities[TIMELOCK_BYPASS_RISK_RULE]).toBe('error');
    expect(severities[SINGLE_ADMIN_LOCKOUT_RULE]).toBe('warning');
    expect(severities[STALE_PENDING_ACTION_RULE]).toBe('warning');
  });

  it('F7: every rule belongs to the "network" category', () => {
    for (const rule of accessControlAuditorRules) {
      expect(rule.category).toBe('network');
    }
  });

  it('F8: diagnostic messages include the contract id', () => {
    const wasm = makeWasm([{ name: 'set_admin', inputs: [] }]);
    const diagnostics = verifyAccessControl(wasm, CONTRACT);
    for (const d of diagnostics) {
      expect(d.message).toContain(CONTRACT);
    }
  });

  it('F9: path option is forwarded to every diagnostic', () => {
    const wasm = makeWasm([{ name: 'set_admin', inputs: [] }]);
    const diagnostics = verifyAccessControl(wasm, CONTRACT, {
      path: 'CURRENCIES[0].contract',
    });
    for (const d of diagnostics) {
      expect(d.path).toBe('CURRENCIES[0].contract');
    }
  });

  it('F10: suggestion strings are non-empty on all emitted diagnostics', () => {
    const wasm = makeWasm([
      { name: 'set_admin', inputs: [] },
      { name: 'set_quorum', inputs: [] },
      { name: 'execute_after_delay', inputs: [] },
    ]);
    const diagnostics = verifyAccessControl(wasm, CONTRACT);
    for (const d of diagnostics) {
      expect(d.suggestion).toBeTruthy();
    }
  });

  it('F11: attacker scenario — contract with verifier and pauser role exposure — each role escalation is caught', () => {
    // Models a real protocol with admin + verifier + pauser roles.
    const wasm = makeWasm([
      // admin role — properly guarded
      { name: 'set_admin', inputs: [{ name: 'new_admin', type: 'address' }] },
      // verifier role — NOT guarded → escalation possible
      { name: 'grant_role', inputs: [{ name: 'role_id', type: 'u32' }] },
      // pauser role — NOT guarded → any account can pause
      { name: 'assign_role', inputs: [] },
    ]);
    const diagnostics = verifyAccessControl(wasm, CONTRACT);

    // verifier escalation
    expect(diagnostics).toContainEqual(
      expect.objectContaining({ rule: UNPROTECTED_ROLE_ASSIGNMENT_RULE }),
    );
    // pauser escalation (zero-arg also triggers removal rule)
    expect(diagnostics).toContainEqual(
      expect.objectContaining({ rule: UNPROTECTED_ROLE_REMOVAL_RULE }),
    );
  });
});
