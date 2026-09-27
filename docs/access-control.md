# Access-Control Auditor

**Issue #810** — Access Control Role Escalation Penetration Test and Fixes.

## Overview

The `access-control-auditor` module (`src/soroban/access-control-auditor.ts`) inspects deployed
Soroban contract WASM bytecode for privilege-escalation vulnerabilities across the three roles the
protocol defines:

| Role       | Capability                                                   |
|------------|--------------------------------------------------------------|
| `admin`    | Assign / revoke roles, upgrade the contract                  |
| `verifier` | Authorise regulated-asset operations                         |
| `pauser`   | Pause / unpause the protocol                                 |

It also covers the wave-level additions that materially expand the attack surface:

- **Multi-sig quorum** — an m-of-n signing policy that guards admin-tier operations.
- **Timelock** — a mandatory delay between proposal and execution.

The audit runs under the opt-in `--check-network` flag and never throws on RPC or network faults;
a missing answer is not a finding.

---

## Rules

### `access-control/unprotected-role-assignment` (error)

**Attack path A1 / A2** — A function that assigns or transfers a privileged role (`set_admin`,
`grant_role`, `transfer_admin`, …) accepts no `Address` parameter.  Without an identity check the
Soroban runtime cannot call `require_auth`, so any account can invoke the function and seize the
`admin`, `verifier`, or `pauser` role.

**Fix:** Add an `Address` parameter (the intended new role-holder or caller) and call
`require_auth()` inside the function body before mutating storage.

---

### `access-control/unprotected-role-removal` (error)

**Attack path A3** — A role-management function accepts *zero arguments*.  A zero-argument function
is callable by any account.  If it removes or reassigns the admin role it may permanently lock
governance with no recovery path.

**Fix:** Add at minimum a caller `Address` parameter.  For removal functions, consider a two-step
handover pattern so the last admin can never be removed unilaterally.

---

### `access-control/quorum-bypass-risk` (error)

**Attack paths B1–B4** — A quorum or multi-sig management function (`set_quorum`,
`approve_proposal`, `execute_proposal`, `add_signer`, …) is missing either an `Address` parameter
(enabling unauthenticated quorum manipulation) or a numeric threshold / nonce argument (enabling
threshold-confusion or approval-replay attacks).

Specific sub-paths:

| Path | Threat |
|------|--------|
| B1   | Threshold reset to 0 → immediate proposal execution without approvals |
| B2   | Phantom approvals inflate the vote count without a signer identity |
| B3   | Replayed approval set from a prior proposal executes a new one |
| B4   | Duplicate signer registration inflates apparent quorum |

**Fix:** Every quorum function must accept both an `Address` (signer identity) and a numeric
threshold or proposal-nonce.  Deduplicate signers on insertion and reject replayed nonces.

---

### `access-control/timelock-bypass-risk` (error)

**Attack paths C1 / C2** — A timelock function (`execute_after_delay`, `cancel_operation`,
`schedule_operation`, …) is missing either an `Address` parameter (enabling unauthorised
cancellation or execution) or a numeric delay / ledger argument (meaning no waiting period is
enforced on-chain).

**Fix:** Every timelock function must accept both an `Address` and a numeric delay expressed as a
ledger count or timestamp.  The contract body must compare the expected execution ledger against
`env.ledger().sequence()`.

---

### `access-control/single-admin-lockout-risk` (warning)

**Attack path A3 (structural)** — The contract exposes a role-removal function (`remove_admin`,
`revoke_role`) but provides no `transfer_admin` or equivalent handover path.  Removing the last
admin permanently locks governance.

**Fix:** Implement a `transfer_admin` (or two-step `propose_admin` / `accept_admin`) pattern that
ensures at least one admin always holds the role before the old one is relinquished.

---

### `access-control/stale-pending-action-risk` (warning)

**Attack path C3 (combined)** — The contract exposes both `submit_proposal` (multi-sig quorum path)
and an execute function (`execute_operation`, `execute_after_delay`, `execute_proposal`) but neither
carries a numeric proposal-id or nonce.  Without a shared identifier, a stale partial-quorum
proposal can combine with an expired timelock window to replay an operation that was never
legitimately approved.

**Fix:** Require a shared numeric proposal-id or ledger-sequence in both the proposal-submission and
execution functions.  Store executed proposal ids in contract storage and reject any id that has
already been executed.

---

## Usage

```bash
# Run only access-control checks against a testnet contract
stellar-toml-lint stellar.toml \
  --check-network \
  --warn access-control/single-admin-lockout-risk \
  --warn access-control/stale-pending-action-risk

# Disable a specific rule
stellar-toml-lint stellar.toml --check-network --off access-control/stale-pending-action-risk
```

---

## Testing

All rules are covered by `test/access_control_edge_cases.test.ts`, which is structured as an
explicit attack tree.  Each exploit path has:

1. An `EXPLOIT` test that reproduces the original vulnerability and asserts that the auditor emits
   the expected finding (regression guard).
2. A `SAFE` test that confirms a correctly implemented function produces no finding.

Run the suite:

```bash
npm test -- access_control_edge_cases
# or with coverage
npm run coverage
```

---

## References

- `src/soroban/access-control-auditor.ts` — implementation
- `test/access_control_edge_cases.test.ts` — penetration tests and regression suite
- `docs/THREAT_MODEL.md` — full attack-tree report
