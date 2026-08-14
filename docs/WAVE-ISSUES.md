# Wave issue backlog

A pre-scoped backlog for [Drips Wave][wave] cycles. Each entry is sized against Wave's complexity
tiers, so it can be filed as a GitHub issue and added to a Program with the stated level.

| Wave level | Points | Meaning                                       |
| ---------- | ------ | --------------------------------------------- |
| Trivial    | 100    | Typos, small bug fixes, minor copy changes    |
| Medium     | 150    | Standard features or involved bug fixes       |
| High       | 200    | Complex features, refactors, new integrations |

Adding a rule is deliberately mechanical — see [CONTRIBUTING.md](../CONTRIBUTING.md). That makes this
repo a good on-ramp: a first-time contributor can ship a real, tested, user-visible improvement in an
afternoon without needing to hold the whole codebase in their head.

**Before filing:** confirm the item is still open. Several may already be done.

---

## Trivial (100 points)

### 1. Add `--no-suggestions` to the text reporter

`formatText` already accepts `showSuggestions`, but no CLI flag exposes it. Wire up the flag, document
it in the README options table and in `USAGE` in `src/cli.ts`, and add a CLI test.

_Files:_ `src/cli.ts`, `README.md`, `test/cli.test.ts`

### 2. Warn when `ORG_LICENSE_NUMBER` appears without `ORG_LICENSING_AUTHORITY`

A licence number with no issuing authority is unverifiable. Add a `warning` rule in
`src/rules/documentation.ts` covering the three `ORG_LICENSE*` fields.

_Files:_ `src/rules/documentation.ts`, `test/lint.test.ts`, `test/fixtures/broken.toml`

### 3. Detect a `stellar.toml` served at the wrong path

When `--domain` is given, `https://<domain>/stellar.toml` is a common misplacement. If the
`.well-known` path 404s, probe the root and, if found there, say so explicitly rather than reporting a
generic "unreachable".

_Files:_ `src/lint.ts`, `test/lint-domain.test.ts`

### 4. Flag `display_decimals` on the native asset

XLM always displays with 7 decimals; overriding it is meaningless. Emit an `info` diagnostic.

_Files:_ `src/rules/currencies.ts`, `test/lint.test.ts`

---

## Medium (150 points)

### 5. Config file support (`.stellartomlrc.json`)

Reading rule severities from a file avoids long `--off` chains in CI. Support
`.stellartomlrc.json` discovered upward from the linted file, with CLI flags taking precedence.
Validate the shape and produce a clear error on an unknown rule id.

_Files:_ new `src/config.ts`, `src/cli.ts`, `README.md`, new `test/config.test.ts`

### 6. Follow and validate `toml` currency pointers

A `[[CURRENCIES]]` entry may point at a separate per-currency file. Under `--domain` (or a new
`--follow-links`), fetch each pointer and lint it as a currency document, prefixing diagnostics with
the source URL. Bound the number of fetches and handle failures gracefully.

_Files:_ `src/lint.ts`, `src/rules/currencies.ts`, `test/lint-domain.test.ts`

### 7. Verify `SIGNING_KEY` against the network

Optionally (`--check-network`) query Horizon for the account behind `SIGNING_KEY` and each
`ACCOUNTS` entry, reporting accounts that do not exist. Must stay opt-in and must not fail the run on
a Horizon outage — degrade to a warning.

_Files:_ new `src/network-checks.ts`, `src/cli.ts`, tests with an injected fetch

### 8. Checkstyle and JUnit reporters

Some CI systems ingest one of these rather than SARIF. Add both as `--format` options, following the
existing reporter shape.

_Files:_ `src/reporters.ts`, `src/cli.ts`, `test/reporters.test.ts`

### 9. Autofix for mechanically safe rules

Add `--fix` for the unambiguous cases: trailing slashes on endpoints, the `NETWORK_PASSPHRASE`
whitespace normalisation, `@`-prefixed social handles, and URL-valued handle fields. Rewrite only
those spans, preserving comments and formatting everywhere else, and print what changed.

_Files:_ new `src/fix.ts`, `src/cli.ts`, new `test/fix.test.ts`

### 10. Validate `[[CURRENCIES]]` against SEP-41 for contract tokens

When a currency declares `contract`, optionally check that the contract implements the SEP-41 token
interface, and that `display_decimals` matches the contract's own `decimals`.

_Files:_ `src/rules/currencies.ts`, `src/network-checks.ts`

---

## High (200 points)

### 11. A `stellar.toml` formatter

`stellar-toml-lint --format-file` that emits a canonical layout: SEP-1's field order, consistent
quoting, sections in spec order, comments preserved. Needs a format-preserving TOML editor rather
than parse-and-reserialise, since `smol-toml` discards comments.

_Files:_ new `src/format-file.ts`, `src/cli.ts`, extensive round-trip tests

### 12. Language server for editor diagnostics

An LSP server publishing diagnostics as you type in `stellar.toml`, plus completion for SEP-1 field
names and hover text quoting the spec. Ship as `stellar-toml-lint --lsp` or a sibling package, and
document VS Code setup.

_Files:_ new `src/lsp/`, `README.md`

### 13. Cross-SEP consistency checks

Correlate the info file with the endpoints it advertises: `WEB_AUTH_ENDPOINT` returning a challenge
signed by `SIGNING_KEY`, `TRANSFER_SERVER_SEP0024/info` listing the assets in `[[CURRENCIES]]`, and
`ANCHOR_QUOTE_SERVER` supporting the declared pairs. This is where the tool starts to overlap
`@stellar/anchor-tests`, so scope carefully and keep it opt-in.

_Files:_ new `src/cross-sep.ts`, `src/cli.ts`

### 14. Corpus regression harness

Snapshot the linter's output across a corpus of real, public `stellar.toml` files so that any change
in behaviour shows up as a reviewable diff. Fetch on a schedule, cache locally, and never fail CI on
a network error. This is the strongest defence against the false positives that live-site testing
already surfaced twice.

_Files:_ new `test/corpus/`, a scheduled workflow

---

[wave]: https://www.drips.network/wave
