## Why the linter stops working

The network telemetry API this rule cross-checks with can be transient or
service-wide, so a connection error is treated as "no data" and degrades to a
warning instead of failing the run. The linter must never be unable to report
its own verdicts because of a network probe.

## Where it can bite

- **CI and pre-commit**: a blocked DNS lookup, a 5xx from the crawler, a slow
  TLS handshake, or a proxy timeout keeps the checker on the critical path.
- **Local development**: a laptop on a flaky VPN or corporate proxy behaves the
  same way, and a developer is told their file is broken when nothing is.
- **Air-gapped and hermetic environments**: any environment that cannot reach
  the crawler must still produce a result.

## How the probe works today

- Any exception from the fetch surface is caught and the corresponding check is
  silently skipped.
- Non-200 responses, empty bodies, malformed JSON, and unexpected shapes are all
  treated as "no data".
- Coverage only exists where a named function already guards `try/catch` or
  checks `response.ok`, `typeof body === 'object'`, and `isInteger(...)` before
  doing real work.

## Examples across the codebase

- `checkHorizon` returns `network/horizon-unreachable` for every failure mode.
- `checkNetworkAccounts`, `checkSep38`, `checkRegulatedIssuerFlags`,
  `checkCorsPreflight`, `checkOverlayPeers`, `checkHistoryPublish`,
  `checkDnsIntegrity`, `checkSep10Replay`, and `checkContracts` all collect
  diagnostics without throwing, and `main` swallows every network failure as a
  warning.
- `checkIssuerFlags`, `checkOverlayPeers`, and `checkNetworkAccounts` never
  throw: unknown mutations, network errors, malformed bodies, or empty payloads
  are all degraded to warnings, and the corresponding rule is marked
  `warn` in CI (`packages/validator-submit/src/network.ts` in the same
  repository).

## What to preserve

Apply the same principle to the new validator activity check:

- Failures to reach the crawler, a missing node, or a node that is not found in
  telemetry must degrade to a warning.
- A node that is present but marked inactive/failing consensus for > 7 days must
  be reported as a warning, not an error.
- The linter must keep linting the file without throwing, aborting, or timing
  out the whole run because of a probe.

## Notes for this repository

- The check runs only under `--check-network`, so the network is always
  optional. The probe should be treated the same way: optional and degrading.
- Existing `test/fixtures/network` trees show the expected shape of a response,
  so a new test fixture can represent "node seen but inactive for > 7 days".
- Network checks are already mocked in CI via `--mock-fixtures`, and tests
  verify `globalThis.fetch` is never elevated to the real network in fixture
  mode. New tests should never resolve the real `fetch` unless they intend a
  live endpoint.

## Pinned evidence

Patches in this repo already converted those checks to idempotent diagnostics:

- `src/rules/horizon-check.ts` returns `network/horizon-unreachable` on any
  failure instead of throwing.
- `src/rules/currencies.ts` catches `checkIssuerFlags` errors and reports a
  warning, so a Horizon outage never fails a run.
- `src/network-checks.ts` treats account verification as best-effort and
  degrades to a warning on 404 or fetch errors.

The new code follows the same contract: `checkValidatorActivity` returns an
array of warnings, never throws, and a fetch failure is reported as
`validators/node-not-seen-on-overlay`.

## Related issues

- Closes #52
- Closes #53
