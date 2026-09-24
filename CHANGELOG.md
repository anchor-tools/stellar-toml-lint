# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Interactive quick-fix code actions over LSP (#42): `stellar-toml-lint --lsp` runs a stdio Language
  Server that publishes diagnostics and answers `textDocument/codeAction` with `WorkspaceEdit`
  replacements for mechanically safe rules — `general/trailing-slash-in-endpoint`,
  `network/passphrase` (near miss), `documentation/social-handles`, `principals/social-handles`,
  and `documentation/phone-e164`. Diagnostics that cannot be corrected safely (parse errors,
  missing tables) offer no action. Shared fix engine lives in `src/fix.ts` for `--fix` (#9) to reuse.

- Text output follows the [NO_COLOR standard](https://no-color.org) explicitly: any non-empty
  `NO_COLOR` disables colour, an empty value counts as unset, and only an explicit `--color`
  overrides it. Covered by `test/no-color.test.ts` (#148).

- `--format junit` emits a JUnit XML test report for CI dashboards that chart test results (Jenkins,
  Bamboo, CircleCI, Azure DevOps). Error-severity findings are reported as `<failure>` elements and
  warnings as `<error>` elements, so a dashboard counting failures matches the exit code (#143).

- `--format checkstyle` emits Checkstyle XML for CI dashboards that ingest the Checkstyle schema
  (Jenkins Warnings NG, Java-adjacent pipelines) (#8): one `<file>` per linted file, one `<error>`
  per diagnostic with `line`, `column`, `severity`, `message`, and `source` (the rule id).

- `validators/invalid-history-url` (error) validates each `[[VALIDATORS]].HISTORY` as a well-formed
  archive URL, including `{0}` template handling.
- `validators/stellar-history-json-unreachable` (error) under `--check-network` fetches each
  validator's archive root and requires it to serve `.well-known/stellar-history.json` with
  `"version": 1` (#144).

- Opt-in `--check-network` flag to query Horizon and report non-existent `SIGNING_KEY` or `ACCOUNTS` entries as warnings (#7).
- `network/horizon-unreachable` and `network/horizon-protocol-outdated` under `--check-network`:
  the linter now GETs `HORIZON_URL` and asserts the response is a valid Horizon root document
  whose `current_protocol_version` is supported by the instance's `core_supported_protocol_version`,
  so a misconfigured, offline, or protocol-lagged Horizon endpoint fails the run instead of
  surfacing later as broken wallet interactions.
- `sep38/prices-endpoint-error`, `sep38/malformed-price-response`, `sep38/quote-endpoint-error`, and
  `sep38/malformed-quote-response` under `--check-network`: when `ANCHOR_QUOTE_SERVER` is declared,
  the linter GETs `/prices?sell_asset=...` for each classic currency and asserts a 200 whose body
  carries a `buy_assets` array of valid price objects, and probes `/quote` for 5xx or non-JSON 200
  answers — so a quote server returning 500s or malformed JSON fails the run instead of surfacing
  later as wallets unable to calculate transaction amounts.

### Changed

- The `validators/history` warning is replaced by `validators/invalid-history-url`, which checks the
  same field more strictly and reports it as an error. Update any `--off validators/history`
  configuration to the new id.

### Added

- SEP-8 regulated issuer flags under `--check-network`: for every `[[CURRENCIES]]` entry marked
  `regulated=true` with a classic `issuer`, the linter reads the issuer account's flags from Horizon.
  A missing `AUTH_REQUIRED` flag emits `currencies/regulated-missing-auth-required-flag` (error), a
  missing `AUTH_REVOCABLE` flag emits `currencies/regulated-missing-auth-revocable-flag` (warning),
  and a Horizon outage or missing account degrades to
  `currencies/regulated-issuer-flags-unverifiable` (warning) so the run still fails cleanly on
  strengthenable-to-fatal findings without depending on network availability.
- Soroban contract liveliness under `--check-contracts`: `src/soroban.ts` queries the Soroban RPC's
  `getLedgerEntries` for the contract instance and its WASM behind every `[[CURRENCIES]].contract`
  and `WEB_AUTH_CONTRACT_ID`, comparing `liveUntilLedgerSeq` against `latestLedger`. Within ~a day of
  expiry it emits `soroban/contract-ttl-expiring-soon` (warning); expired or archived state emits
  `soroban/contract-expired` (error); an unreachable RPC degrades to `soroban/contract-ttl-unavailable`
  (warning). The endpoint is derived from `NETWORK_PASSPHRASE` and overridable with `--soroban-rpc`.
- `security/deprecated-tls-version` and `security/weak-cipher-suite` warnings under `--domain`:
  the linter now inspects the TLS session the host negotiates and flags TLS 1.0/1.1 (and SSLv2/SSLv3),
  plus cipher suites built on 3DES, DES, RC4, CBC, NULL, or EXPORT primitives. Offline linting is
  unaffected, and both rules can be tuned with `--off`, `--warn`, and `--error` like any other.
- `lintDomain` accepts an optional `tlsProbe` so embedders and tests can supply the session instead of
  having one opened for them. `probeTls` is exported for callers that need to measure it themselves.

## [0.1.0]

Initial release.

### Added

- Offline SEP-1 validation of a local `stellar.toml`, with line and column for each finding.
- 47 registered rules across file, general, `[DOCUMENTATION]`, `[[PRINCIPALS]]`, `[[CURRENCIES]]`,
  and `[[VALIDATORS]]` categories, plus parse, encoding, and network checks emitted directly by the
  engine.
- Checksum-accurate Stellar key validation via `@stellar/stellar-base`, so a transposed character in
  an account or contract ID is caught rather than passed by a shape-only regex.
- Cross-field dependency checks: SEP-31 requiring SEP-12, SEP-10 requiring `SIGNING_KEY`, and SEP-45
  requiring both its endpoint and contract ID.
- `--domain` mode, fetching `https://<domain>/.well-known/stellar.toml` and additionally checking
  reachability, `Access-Control-Allow-Origin`, content type, and size.
- Reporters: human-readable text, JSON, SARIF 2.1.0 for GitHub code scanning, and GitHub Actions
  workflow commands for inline PR annotations.
- Per-rule severity configuration via `--off`, `--warn`, and `--error`, plus `--strict` and
  `--max-warnings`.
- Programmatic API exporting `lint`, `lintDomain`, the reporters, and full TypeScript types.
- A composite GitHub Action.

### Notes

Two findings from testing against live anchors shaped the initial release:

- The CORS probe sends an `Origin` request header. Many hosts and CDNs only emit
  `Access-Control-Allow-Origin` when one is present, so probing without it reported a CORS failure
  against correctly-configured anchors.
- `code = "native"` is recognised as XLM, which has no issuing account and whose supply is a protocol
  property. The issuer and issuance-policy rules do not apply to it.

[Unreleased]: https://github.com/anchor-tools/stellar-toml-lint/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/anchor-tools/stellar-toml-lint/releases/tag/v0.1.0
