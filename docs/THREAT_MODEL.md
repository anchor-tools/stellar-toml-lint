# Threat Model — Access Control Role Escalation

**Issue #810** — Access Control Role Escalation Penetration Test and Fixes  
**Scope:** On-chain logic only (social-engineering and off-chain key-custody attacks are out of scope)  
**Assets protected:** `admin`, `verifier`, `pauser` roles plus multi-sig quorum and timelock state

---

## 1. Scope and Trust Boundaries

```
┌─────────────────────────────────────────────────────────┐
│                   Stellar Ledger                        │
│                                                         │
│  ┌─────────────────────────────────────────────────┐    │
│  │  Contract Storage                               │    │
│  │   • admin   : Address  ← guarded write          │    │
│  │   • verifier: Address  ← guarded write          │    │
│  │   • pauser  : Address  ← guarded write          │    │
│  │   • quorum  : u32      ← guarded write          │    │
│  │   • timelock: u64      ← guarded write          │    │
│  │   • proposals: Map     ← guarded write          │    │
│  └─────────────────────────────────────────────────┘    │
│          ▲                                               │
│  ┌───────┴─────────────────────────────────────────┐    │
│  │  Contract Public Interface (WASM spec section)  │    │
│  │  Any Stellar account may call any function      │    │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
          ▲
   Untrusted callers (any Stellar account, including attacker)
```

**Trust boundary:** Only accounts that pass `require_auth()` inside the contract body are trusted.
The contract's public-call surface is fully open to any Stellar account; the runtime does not
restrict who may *call* a function, only whether the *auth check inside* succeeds.

---

## 2. Attack Tree

```
ROOT GOAL: Escalate to admin without legitimately holding the admin role
│
├── A. Role-assignment / removal paths
│   ├── A1. Call set_admin() with no arguments
│   │       → seize admin role unilaterally
│   │       STATUS: FIXED — auditor emits unprotected-role-assignment (error)
│   │
│   ├── A2. Call grant_role / assign_role with only a numeric parameter
│   │       → assign verifier or pauser to attacker address, no identity check
│   │       STATUS: FIXED — auditor emits unprotected-role-assignment (error)
│   │
│   └── A3. Call remove_admin / revoke_role with zero arguments
│           → strip the last admin from the contract, locking governance forever
│           STATUS: FIXED — auditor emits unprotected-role-removal (error)
│                          and single-admin-lockout-risk (warning) when no
│                          transfer_admin path exists
│
├── B. Quorum bypass paths (multi-sig)
│   ├── B1. Call set_quorum() with no Address → reset threshold to 0
│   │       → any subsequent execute_proposal() succeeds with 0 approvals
│   │       STATUS: FIXED — auditor emits quorum-bypass-risk (error)
│   │
│   ├── B2. Call approve_proposal() with no Address → inflate vote count
│   │       → meet quorum with phantom approvals; no signer identity required
│   │       STATUS: FIXED — auditor emits quorum-bypass-risk (error)
│   │
│   ├── B3. Replay a used approval set against a new proposal
│   │       → execute_proposal() with no nonce cannot distinguish old from new
│   │       STATUS: FIXED — auditor emits quorum-bypass-risk (error, missing nonce)
│   │
│   └── B4. Register the same address N times via unguarded add_signer
│           → one attacker address provides N votes, artificially reaching quorum
│           STATUS: FIXED — auditor emits quorum-bypass-risk (error) when
│                          add_signer has no Address guard
│
└── C. Timelock bypass paths
    ├── C1. Call execute_after_delay() with no numeric delay argument
    │       → the contract has no ledger-sequence check, execution is immediate
    │       STATUS: FIXED — auditor emits timelock-bypass-risk (error)
    │
    ├── C2. Call cancel_operation() with no Address
    │       → any account can cancel a legitimate pending operation
    │       STATUS: FIXED — auditor emits timelock-bypass-risk (error)
    │
    └── C3. Partial-quorum + stale pending action combination
            → submit_proposal + execute_operation share no numeric nonce
              A partial-quorum proposal from ledger N is still pending.
              Its timelock window expired without reaching quorum.
              Attacker triggers a fresh execute_operation() without a nonce;
              the contract cannot distinguish the stale proposal from a new one.
              Result: operation executes with fewer than the required approvals.
            STATUS: FIXED — auditor emits stale-pending-action-risk (warning)
```

---

## 3. Confirmed Findings and Remediations

### Finding 1 — Unprotected Role Assignment (A1, A2)

**Severity:** Error  
**Rule:** `access-control/unprotected-role-assignment`  
**Root cause:** Role-assignment function exposes no `Address` parameter; the Soroban runtime
cannot invoke `require_auth` because no identity was supplied.  
**Fix:** Add an `Address` parameter to every role-assignment function and call `require_auth()`
before mutating role storage.  
**Regression test:** `test/access_control_edge_cases.test.ts` — tests A1 EXPLOIT and A2 EXPLOIT.

---

### Finding 2 — Zero-Argument Role Removal (A3)

**Severity:** Error  
**Rule:** `access-control/unprotected-role-removal`  
**Root cause:** A zero-argument function is callable by any account. Applied to role removal, this
allows an attacker to strip every admin, permanently locking governance.  
**Fix:** Require at minimum a caller `Address` parameter on all role-mutation functions; use a
two-step handover for removal so the last admin cannot be removed without a successor.  
**Regression test:** `test/access_control_edge_cases.test.ts` — tests A3 EXPLOIT (remove_admin)
and A3 EXPLOIT (revoke_role).

---

### Finding 3 — Quorum Bypass via Missing Identity or Threshold (B1–B4)

**Severity:** Error  
**Rule:** `access-control/quorum-bypass-risk`  
**Root cause:** Multi-sig management functions missing either an `Address` (enabling unauthenticated
quorum manipulation) or a numeric threshold / nonce (enabling replay or threshold confusion).  
**Fix:** Every quorum function must accept both an `Address` and a numeric threshold or nonce.
Deduplicate signers on insert; reject replayed nonces.  
**Regression tests:** B1–B4 EXPLOIT tests in `test/access_control_edge_cases.test.ts`.

---

### Finding 4 — Timelock Bypass via Missing Identity or Delay (C1, C2)

**Severity:** Error  
**Rule:** `access-control/timelock-bypass-risk`  
**Root cause:** Timelock functions missing an `Address` (unauthorised cancellation / execution) or
a numeric delay argument (no on-chain waiting period).  
**Fix:** Every timelock function must accept both an `Address` and a numeric delay (ledger count or
Unix timestamp). Compare against `env.ledger().sequence()` or `env.ledger().timestamp()`.  
**Regression tests:** C1 EXPLOIT and C2 EXPLOIT in `test/access_control_edge_cases.test.ts`.

---

### Finding 5 — Single-Admin Lockout Risk (A3 structural)

**Severity:** Warning  
**Rule:** `access-control/single-admin-lockout-risk`  
**Root cause:** Contract exposes role-removal functions but no transfer/handover path; removing the
last admin irreversibly locks governance.  
**Fix:** Implement `transfer_admin` or a `propose_admin` / `accept_admin` two-step pattern.  
**Regression test:** A-LOCKOUT EXPLOIT in `test/access_control_edge_cases.test.ts`.

---

### Finding 6 — Stale Partial-Quorum + Timelock Interaction (C3)

**Severity:** Warning  
**Rule:** `access-control/stale-pending-action-risk`  
**Root cause:** Both `submit_proposal` and the execute function lack a shared numeric
proposal-id/nonce, so a stale partial-quorum proposal is indistinguishable from a new one.  A
concurrent expired timelock window can activate it without ever reaching quorum.  
**Fix:** Require a shared proposal-id in both proposal submission and execution; store executed
ids in contract storage and reject re-execution.  
**Regression test:** C3 EXPLOIT in `test/access_control_edge_cases.test.ts`.

---

## 4. Paths Proven Safe

The following scenarios were audited and confirmed to produce **zero findings**:

| Scenario | Evidence |
|----------|----------|
| `set_admin(new_admin: Address)` | A2 SAFE test |
| `grant_role(to: Address, role: u32)` | A2 SAFE (grant_role) test |
| `remove_admin(admin: Address)` | A3 SAFE test |
| `set_quorum(caller: Address, threshold: u32)` | B1 SAFE test |
| `approve_proposal(signer: Address, proposal_id: u32)` | B2 SAFE test |
| `add_signer(signer: Address, weight: u32)` + `execute_proposal(caller, nonce)` | B4 SAFE test |
| `execute_after_delay(caller: Address, delay_ledgers: u64)` | C1 SAFE test |
| `cancel_operation(caller: Address, op_id: u32)` | C2 SAFE test |
| Fully correct multi-sig + timelock contract (all 13 functions guarded) | D-COMBINED SAFE test |

---

## 5. Coverage

The test suite (`test/access_control_edge_cases.test.ts`) achieves ≥ 90 % line coverage on
`src/soroban/access-control-auditor.ts` as required by the acceptance criteria.

Run coverage locally:

```bash
npm run coverage -- --reporter=text
```

---

## 6. Out of Scope

- Social-engineering attacks (phishing, bribery of key holders)
- Off-chain key custody and HSM compromise
- Stellar network-layer denial-of-service
- SEP-1 file manipulation (covered by the linter's other rule categories)

---

## 7. Related Files

| File | Role |
|------|------|
| `src/soroban/access-control-auditor.ts` | Auditor implementation |
| `test/access_control_edge_cases.test.ts` | Penetration tests and regression suite |
| `docs/access-control.md` | Rule documentation and usage guide |
| `docs/THREAT_MODEL.md` | This document |
