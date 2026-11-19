# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `--verify-por-feed` / `stellar-toml-lint verify-por-feed --domain <domain>`
  (`src/bridges/chainlinkPorVerifier.ts`): validates Chainlink Proof of Reserve feeds declared in
  `[DOCUMENTATION.PROOF_OF_RESERVES]` or `CURRENCIES[].chainlink_por` (`por/invalid-feed`) and, under
  `--check-network`, reads `decimals()` and `latestRoundData()` over EVM JSON-RPC
  (`por/rpc-unavailable`, `por/invalid-answer`, `por/incomplete-round`, `por/stale-feed` beyond a
  heartbeat of at most 86400s), compares the reserve with the Horizon supply
  (`por/supply-unavailable`, `por/undercollateralized`) and reports the ratio
  (`por/collateralization`).

- `stellar-toml-lint audit-wormhole-vaa --vaa <hex|base64> [--guardian-set <file.json>]`
  (`src/bridges/wormholeVaaAuditor.ts`): parses VAA headers, signatures, bodies and token transfer
  payloads (`wormhole/malformed-vaa`, `wormhole/unsupported-version`, `wormhole/malformed-payload`),
  recovers each guardian signature with a dependency-free Keccak-256 / secp256k1 implementation
  (`src/bridges/evmCrypto.ts`) and enforces the two-thirds quorum (`wormhole/invalid-guardian-index`,
  `wormhole/invalid-signature`, `wormhole/insufficient-quorum`, `wormhole/guardian-set-mismatch`,
  `wormhole/expired-guardian-set`, `wormhole/unverified-signatures`).

- `--verify-solana-bridge` / `stellar-toml-lint verify-solana-bridge --domain <domain>`
  (`src/bridges/solanaEscrowVerifier.ts`): validates `CURRENCIES[].solana_bridge` base58 addresses
  (`solbridge/invalid-config`) and, under `--check-network`, checks the escrow is an SPL token account
  for the declared mint (`solbridge/escrow-mismatch`), reads `getTokenAccountBalance`
  (`solbridge/rpc-unavailable`) and requires locked >= minted with exact decimal normalization
  (`solbridge/supply-unavailable`, `solbridge/reserve-deficit`).

- `--audit-erc4626-vaults` (`src/bridges/erc4626VaultAuditor.ts`): validates
  `CURRENCIES[].collateral_vaults` (`erc4626/invalid-vault`) and, under `--check-network`, calls
  `asset()`, `decimals()`, `totalAssets()` and `convertToAssets()` (`erc4626/rpc-unavailable`) to flag
  inconsistent accounting (`erc4626/inconsistent-accounting`), share prices below par or drifting from
  the declared `share_price` (`erc4626/share-price-below-par`, `erc4626/share-price-drift`) and NAV
  that does not cover the Stellar supply (`erc4626/supply-unavailable`, `erc4626/insufficient-nav`).

- `--audit-esg-disclosures` (`src/protocols/esgComplianceVerifier.ts`): checks
  `[DOCUMENTATION.ORG_ESG]` for a carbon accounting methodology, renewable energy certificates, PUE
  and an attestation (`esg/missing-field`, `esg/invalid-field`, `esg/attestation-expired`), verifies
  the Ed25519 attestation signature under `--check-network` (`esg/attestation-unreachable`,
  `esg/attestation-signature-invalid`) and prints a Platinum/Gold/Silver/Bronze rating to stderr.

- `--verify-federation-srv` (`src/protocols/federationSrvVerifier.ts`): resolves
  `_stellar-federation._tcp.<domain>` (RFC 2782) and checks targets, ports, priority/weight
  (`federationsrv/invalid-target`, `federationsrv/invalid-port`,
  `federationsrv/invalid-priority-weight`, `federationsrv/non-default-port`), conflicts with
  `FEDERATION_SERVER` (`federationsrv/conflicts-with-toml`) and, under `--check-network`, probes each
  target over HTTPS with a timeout (`federationsrv/unreachable-target`,
  `federationsrv/not-a-federation-server`).

- `--verify-promotions` / `stellar-toml-lint verify-promotions --domain <domain>`
  (`src/protocols/promotionalPricingVerifier.ts`): parses "0% fee", "1.5% fee" and "until
  YYYY-MM-DD" claims from `[DOCUMENTATION]` and `CURRENCIES` text, flags expired claims
  (`promotions/expired-claim`) and, under `--check-network`, compares them with SEP-38 `/price` fees
  at test volumes using exact integer math (`promotions/fee-mismatch`,
  `promotions/unverifiable-claim`). `/quote` needs a SEP-10 session, so indicative `/price` is used.

- `--audit-sep30-recovery` (`src/protocols/sep30Verifier.ts`): validates `RECOVERY_SERVER` and
  `RECOVERY_SIGNING_KEYS` (`sep30/invalid-recovery-server`, `sep30/invalid-signing-key`,
  `sep30/insufficient-recovery-quorum`) and, under `--check-network`, probes `POST`/`GET`/`PUT`
  `/accounts/{address}` with no credentials against a throwaway address
  (`sep30/endpoint-unavailable`, `sep30/unauthenticated-recovery`, `sep30/unsupported-auth-method`).
  Signer weights are not readable without an authenticated session, so quorum is judged from the
  number of distinct declared signing keys.

- `stellar-toml-lint audit-clawbacks --asset <code:issuer>` (`src/protocols/clawbackAuditGenerator.ts`):
  scans the issuer's Horizon history for `clawback` and `clawback_claimable_balance` operations,
  verifies each carries an audit memo reference, and generates JSON and Markdown audit trail reports
  with exact stroop precision.

- `--audit-kyc-fsm --domain <domain>` (`src/protocols/kycTierAuditor.ts`): reads the customer
  types advertised by SEP-31 `/info`, observes the SEP-12 `/customer` status for each, and audits the
  status state machine against the four SEP-12 statuses: `sep12/unknown-customer-status`,
  `sep12/status-missing-next-action`, `sep12/circular-status-transition`,
  `sep12/nondeterministic-status-transition` and `sep12/unreachable-status`. Transition diagrams are
  printed to stderr.

- `--audit-consumer-protection` (`src/protocols/consumerProtectionVerifier.ts`): checks that
  `[DOCUMENTATION.ORG_LEGAL]` (or `[DOCUMENTATION]`) declares `ORG_COMPLAINTS_EMAIL`,
  `ORG_DISPUTE_RESOLUTION_URL`, `ORG_JURISDICTION` and `ORG_LICENSES`
  (`consumerprotection/missing-field`, `consumerprotection/invalid-field`), probes the dispute URL
  for a 200 OK with readable content under `--check-network`
  (`consumerprotection/dispute-url-unreachable`), and prints a transparency scorecard.

- `--audit-unicode-security` (`src/cst/unicodeValidator.ts`): scans every key and string value
  for bidirectional override characters (`unicode/bidi-override`, error), zero-width and invisible
  formatting characters (`unicode/invisible-character`), Cyrillic/Greek homoglyphs in domains and
  asset codes (`unicode/homoglyph-spoofing`, error), and malformed language tags
  (`unicode/invalid-language-tag`), following Unicode TR #36.

- SEP-42 cross-contract authorization call-tree simulator under `--check-network`
  (`src/soroban/auth-tree-simulator.ts`): the SAC `mint` and `clawback` calls are dry-run with
  `simulateTransaction` in recording mode, and the returned `SorobanAuthorizationEntry` tree is
  traced, emitting `soroban/unauthorized-cross-contract-call` (error) when the tree authorizes an
  identity other than the account the file publishes as `SIGNING_KEY` or a designated issuer, or
  delegates into a contract the operation never called, and `soroban/unbounded-auth-grant`
  (warning) when a grant names no address, lets a contract authorize itself, or re-delegates the
  authorization further down the tree. Nothing is submitted and no fees are spent.

- Follow and lint `toml` currency pointers. A `[[CURRENCIES]]` entry that points at a separate
  document via `toml` now has that document fetched and linted as part of the same run, so an
  anchor cannot pass with a broken linked asset. Enabled by `--follow-links` and implied by
  `--domain`. Findings from a linked document are prefixed with its URL, a pointer that cannot be
  fetched is a `network/toml-pointer-fetch` warning rather than a hard failure, and fetches are
  capped at 20 so a long currency list cannot fan out unboundedly.

- `--preset validator|anchor-sep24|issuer` applies a curated rule bundle for an organisation's role
  in the ecosystem, so a validator operator, a SEP-24 anchor, and a standalone asset issuer stop
  carrying the same `--off` chain through every workflow. `validator` keeps the validator and
  general file checks and silences the currency and anchor service rules (raising a duplicate
  validator `HOST` or `ALIAS` to `error`); `anchor-sep24` holds the SEP-24, SEP-10, and currency
  requirements at `error` and silences the validator rules; `issuer` holds currency, collateral,
  and documentation completeness at `error` and silences the anchor service rules. A preset is a
  baseline, so an explicit `--off`/`--warn`/`--error` still wins whatever order the flags appear in,
  and an unknown name lists the available presets and exits `2`. Bundles are assembled from the rule
  registry, so a rule registered later joins the group its category puts it in (#20).
- `general/deprecated-field` warns about legacy `AUTH_SERVER` and `DEPOSIT_SERVER` fields,
  unencrypted `FEDERATION_SERVER` values, and documentation keys placed outside `[DOCUMENTATION]`,
  with replacement syntax for SEP-10, SEP-12, SEP-6, and SEP-24 (#126).
- `--format markdown` emits a GitHub-flavored Markdown report built for a workflow's
  `$GITHUB_STEP_SUMMARY`: a pass/fail header with the error, warning, and info counts, a table with a
  row per finding, and collapsible `<details>` blocks carrying suggestions and spec links. `|`, `<`,
  and `>` are escaped so a hostile file cannot break the table or inject markup (#61).
- `--completion bash|zsh|fish` prints a native shell completion script covering every flag, the
  output formats, and the rule ids accepted by `--off`/`--warn`/`--error`. The rule ids come from
  the same registry the linter runs, so they never drift from the actual checks; an unsupported
  shell prints to stderr and exits `2` (#60).
- `network/sep6-missing-asset` (warning), alongside `network/sep6-info-error` and
  `network/sep6-info-malformed`, under `--domain` or `--check-network`: when `TRANSFER_SERVER` is
  declared, `GET <TRANSFER_SERVER>/info` is fetched with redirects followed and every non-native
  `[[CURRENCIES]]` asset must appear in the `deposit` or `withdraw` maps, keyed by bare code or
  `CODE:issuer` (#38).
- `soroban/invalid-auth-contract-interface` (error) under `--check-contracts`: for
  `WEB_AUTH_CONTRACT_ID`, the deployed WASM's `contractspecv0` custom section is parsed and the
  contract is required to export the SEP-45 `web_auth_verify` function. An unreadable interface
  stays silent rather than guessing (#37).

- `textDocument/hover` over LSP (#36): hovering a key or a table header in `stellar.toml` shows a
  Markdown tooltip with the qualified name (`[[CURRENCIES]].display_decimals`), the field's type
  (`integer (0-7)`), the SEP-1 description, the permitted values where the spec enumerates them
  (`live`, `dead`, `test`, `private`), and a link to the anchoring section of SEP-1. Documentation
  lives in `src/spec.ts` beside the `KNOWN_*` sets the linter checks against, with a test asserting
  the two never drift apart; whitespace, comments, and keys SEP-1 does not define show nothing.
- `network/wrong-path` (error) under `--domain`: when `/.well-known/stellar.toml` returns HTTP 404,
  the linter probes `https://<host>/stellar.toml` once. If the root path serves the file, the
  diagnostic says so and points at the SEP-1 location; if the root probe also fails, behaviour is
  unchanged (`network/unreachable` only). At most one extra request, still through the injected
  `fetchImpl` (#3).
- Interactive quick-fix code actions over LSP (#42): `stellar-toml-lint --lsp` runs a stdio Language
  Server that publishes diagnostics and answers `textDocument/codeAction` with `WorkspaceEdit`
  replacements for mechanically safe rules — `general/trailing-slash-in-endpoint`,
  `network/passphrase` (near miss), `documentation/social-handles`, `principals/social-handles`,
  and `documentation/phone-e164`. Diagnostics that cannot be corrected safely (parse errors,
  missing tables) offer no action. Shared fix engine lives in `src/fix.ts` for `--fix` (#9) to reuse.
- Glob patterns in the positional file arguments (`stellar-toml-lint "configs/**/*.toml"`), expanded
  by the linter rather than the shell so the same quoted argument works on Linux, macOS, and
  Windows, where PowerShell and CMD do not expand globs at all. `*`, `?`, `[...]`, and `**` are
  supported; a pattern that matches nothing reports itself and exits `2`; hidden entries are skipped
  unless named. Multi-file runs now close with a summary line — `Checked 4 files: 3 passed, 1 failed
(2 errors, 3 warnings)` — appended by the text reporter only, with the exit code still `1` if any
  file failed and `0` if they all passed (#18).

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
- Overlay and archive integrity audits: `--crawl-peers` decodes bounded `GET_PEERS` discovery
  responses, `--verify-dnssec` compares DNSSEC-validating DoH resolvers, and `--check-network`
  validates the three most recent history checkpoints for complete category archives and chained
  previous-ledger pointers (#90, #91, #92, #96).
- `overlay/invalid-crypto-framing` and `overlay/mac-authentication-failure` audit big-endian frame
  lengths, HKDF-derived session keys, sequence replay, and authenticated tags (#91).

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

### Fixed

- `--lsp` actually serves the protocol now. `main()` called the line-based `lspMain()`, which
  registered a stdin listener and then fell through to `process.exit`, so the process printed
  nothing and exited before a client could send a message. The CLI runs the framed stdio server
  (`src/lsp/server.ts`) instead — diagnostics, quick-fix code actions, and hover — and the
  unreachable server behind it is gone.

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
