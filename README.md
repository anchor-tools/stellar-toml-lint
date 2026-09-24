# stellar-toml-lint

Validate a Stellar Info File (`stellar.toml`) against **[SEP-1]** — offline, before you deploy it.

[![CI](https://github.com/anchor-tools/stellar-toml-lint/actions/workflows/ci.yml/badge.svg)](https://github.com/anchor-tools/stellar-toml-lint/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/stellar-toml-lint.svg)](https://www.npmjs.com/package/stellar-toml-lint)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)

Documentation website: [stellar-toml-lint docs](https://anchor-tools.github.io/stellar-toml-lint/)

```console
$ npx stellar-toml-lint public/.well-known/stellar.toml

public/.well-known/stellar.toml
  12:1      error    NETWORK_PASSPHRASE has stray whitespace; it must match the Public passphrase byte for byte  network/passphrase
            ↳ Replace it with exactly: Public Global Stellar Network ; September 2015
  31:1      error    CURRENCIES[0].issuer is not a valid Stellar account ID  currencies/issuer-or-contract
            ↳ Check for a transcription error — the checksum does not match.
  34:1      error    CURRENCIES[0] sets fixed_number and is_unlimited, but these issuance policies are mutually exclusive  currencies/issuance-exclusive
            ↳ SEP-1 requires exactly one of fixed_number, max_number, or is_unlimited.
  19:1      warning  DOCUMENTATION.ORG_PHONE_NUMBER is not in E.164 format  documentation/phone-e164
            ↳ Use a leading + and digits only, e.g. "+14155552671".

  4 problems (3 errors, 1 warning, 0 infos)
```

## Why this exists

The official [`@stellar/anchor-tests`][anchor-tests] suite is thorough, but it tests a **live
domain**. That means you find out your info file is broken _after_ you have shipped it — and you
cannot run it in the pull request that introduced the mistake.

`stellar-toml-lint` reads a local file. It runs in a pre-commit hook, in CI, or on your laptop before
a domain exists at all. It is complementary to `anchor-tests`, not a replacement: this catches
everything checkable from the file itself, then hands off to `anchor-tests` for the parts that need
running services.

|                                 | `stellar-toml-lint` | `@stellar/anchor-tests` |
| ------------------------------- | ------------------- | ----------------------- |
| Lints a local file              | ✅                  | ❌                      |
| Needs a deployed domain         | ❌                  | ✅                      |
| Line and column for each fault  | ✅                  | ❌                      |
| Validates key checksums         | ✅                  | partial                 |
| SARIF / code scanning output    | ✅                  | ❌                      |
| Tests live SEP-6/10/24/31 flows | ❌                  | ✅                      |

Because it validates Stellar keys with `@stellar/stellar-base`, it verifies the **CRC16 checksum** —
so a single transposed character in an issuer address is caught, which a `/^G[A-Z2-7]{55}$/` regex
would wave straight through.

## Install

```bash
npm install --save-dev stellar-toml-lint   # project dependency
npx stellar-toml-lint                      # or just run it
```

Requires Node.js 20 or newer. Two runtime dependencies: `smol-toml` and `@stellar/stellar-base`.

## Usage

```bash
# Lint a local file (defaults to ./stellar.toml)
stellar-toml-lint public/.well-known/stellar.toml

# Fetch and lint a live site, including CORS and content-type checks
stellar-toml-lint --domain example.com

# Lint a local file *as if* served from a domain, enabling same-domain checks
stellar-toml-lint public/.well-known/stellar.toml --domain example.com

# Read from stdin
cat stellar.toml | stellar-toml-lint -
```

### Options

| Flag                      | Effect                                                                            |
| ------------------------- | --------------------------------------------------------------------------------- |
| `-d, --domain <d>`        | Serving domain. Enables CORS, content-type, TLS, and `ORG_URL` checks             |
| `-f, --format <fmt>`      | `text` (default), `json`, `sarif`, `github`, `junit`                              |
| `--strict`                | Treat warnings as errors                                                          |
| `--max-warnings <n>`      | Fail if warnings exceed `n`                                                       |
| `--check-network`         | Verify accounts, `HORIZON_URL`, SEP-8 flags, and `ANCHOR_QUOTE_SERVER` online     |
| `--check-contracts`       | Verify Soroban contract and WASM TTL liveliness online                            |
| `--soroban-rpc <url>`     | Soroban RPC endpoint for `--check-contracts` (defaults from `NETWORK_PASSPHRASE`) |
| `--webhook-slack <url>`   | POST a Slack Block Kit card with the run summary                                  |
| `--webhook-discord <url>` | POST a Discord embed with the run summary                                         |
| `--off <rule>`            | Disable a rule (repeatable)                                                       |
| `--error <rule>`          | Raise a rule to error (repeatable)                                                |
| `--warn <rule>`           | Lower a rule to warning (repeatable)                                              |
| `-q, --quiet`             | Show errors only                                                                  |
| `--show-help-urls`        | Print the spec link for each finding                                              |
| `--list-rules`            | Print every rule and exit                                                         |
| `--no-suggestions`        | Hide diagnostic suggestions in the output                                         |
| `--color`                 | Force colour on, overriding `NO_COLOR`                                            |
| `--no-color`              | Force colour off                                                                  |
| `-i, --interactive`       | Full-screen dashboard to walk the findings (falls back to text)                   |

Exit codes: **0** no errors, **1** problems found, **2** bad usage or I/O failure.

Colour output follows the [NO_COLOR standard](https://no-color.org): setting `NO_COLOR` to any
non-empty value disables it, an empty value counts as unset, and stdout not being a terminal
disables it too. An explicit `--color` is the only thing that overrides `NO_COLOR`.

### Walking the findings in a terminal

```console
$ stellar-toml-lint public/.well-known/stellar.toml --interactive
```

A full-screen view for runs with more findings than fit on one screen: `j`/`k` or the arrow keys
move, `Enter` opens the details panel (message, suggestion, spec link), `s` cycles the severity
filter, `/` searches rule names, `f` asks for a fix, `q` quits.

It is deliberately quiet about where it cannot work. If stdout is not a terminal — a pipe, a CI log,
a redirected file — the text reporter is used instead, so nothing ever sprays box-drawing characters
into a build log. Combining `--interactive` with `--format` is refused for the same reason the flag
draws its own view: drop the format flag.

`--quiet` opens it already filtered to errors, which is the same view the text reporter gives with that flag.

`f` currently reports that no fix engine is wired up; #9 tracks the mechanical fixes it will call
into, and the dashboard already routes the keystroke through a callback so that lands as a one-line
change rather than a rewrite.

### Alerting a Slack or Discord channel

```console
$ stellar-toml-lint public/.well-known/stellar.toml \
    --webhook-slack "$SLACK_WEBHOOK" \
    --webhook-discord "$DISCORD_WEBHOOK"
```

One `POST` per channel summarises the whole run: a colour bar that follows the worst severity found
(red for errors, yellow for warnings only, green when clean), the error and warning counts, the most
frequent rules with a line number each, and links into SEP-1. Slack gets a Block Kit card with spec
buttons; Discord gets a Rich Embed with the links inline.

Delivery retries network errors, timeouts and 408/425/429/5xx twice with a 250 ms backoff, and every
request is capped at 5 s. A 4xx is not retried, because a rejected payload will not fix itself. The
exit code always follows the diagnostics and never the webhook: when delivery fails the problem is
reported on stderr and the verdict is unchanged, so a broken alert endpoint cannot turn a clean file
into a failing build.

## In the browser

The linter itself is free of Node built-ins, so it also runs in a page or a worker, under a separate entry point:

```ts
import { createVirtualFileSystem, lintBrowserFile } from 'stellar-toml-lint/browser';

const files = createVirtualFileSystem({ 'stellar.toml': textareaValue });
const result = await lintBrowserFile('stellar.toml', { files });
```

- `lintBrowser(content, options)` — lint a string.
- `lintBrowserFile(path, { files })` and `lintBrowserRun(paths, { files })` — lint out of a virtual file system, which is what replaces `node:fs`.
- `lintBrowserDomain(domain, { fetchImpl })` — fetch `/.well-known/stellar.toml` with the page's own `fetch`. CORS applies here exactly as it does to a wallet, so a host without `Access-Control-Allow-Origin: *` produces the same `network/cors` finding.

A worker wrapper is published as `stellar-toml-lint/worker`. Send `{ type: 'lint', content, options }` and get back `{ type: 'result', result }`, or `{ type: 'error', message }` when the request itself was malformed — the handler answers errors rather than throwing, because a worker that throws loses the request silently. `{ type: 'ping' }` lets a page check the worker is alive before a long run.

One capability does not survive the move: a page cannot observe a TLS session, so the `security/*` audit is skipped in the browser and reported as not observed rather than guessed. `browserCapabilities` says the same thing at runtime, for callers that branch on it.

Both entry points ship their own typings (`dist/browser.d.ts`, `dist/worker.d.ts`), and a test walks the static import graph from them so a `node:` import cannot creep back onto that path.

## In CI

### GitHub Action

```yaml
- uses: anchor-tools/stellar-toml-lint@v1
  with:
    file: public/.well-known/stellar.toml
    strict: true
```

Findings appear as inline annotations on the pull request diff.

To route them into the Security tab instead:

```yaml
- uses: anchor-tools/stellar-toml-lint@v1
  with:
    file: public/.well-known/stellar.toml
    sarif-file: stellar-toml.sarif
  continue-on-error: true

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: stellar-toml.sarif
```

### JUnit XML reports

Jenkins, Bamboo, CircleCI, and Azure DevOps read JUnit XML to draw test pass/fail charts and suite
summaries. `--format junit` emits it for them:

```bash
stellar-toml-lint public/.well-known/stellar.toml --format junit > stellar-toml.xml
```

Each diagnostic becomes a `<testcase>` named after its rule, carrying the message, the suggestion,
the spec link, and the source line. Since only errors fail the run, they are reported as `<failure>`
elements and the warnings and info as `<error>` elements, so a dashboard that counts failures agrees
with the exit code while the softer findings stay visible. Lint one file per report — each run emits
a complete `<testsuites>` document, as the other machine-readable formats do.

### Pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: stellar-toml-lint
        name: Lint stellar.toml
        entry: npx stellar-toml-lint
        language: system
        files: '\.well-known/stellar\.toml$'
```

### Monitoring a deployed anchor

```yaml
on:
  schedule:
    - cron: '23 7 * * *'
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: anchor-tools/stellar-toml-lint@v1
        with:
          domain: example.com
```

This catches the failure mode nobody notices: a CDN or hosting change quietly dropping the
`Access-Control-Allow-Origin` header, which makes the file unreadable to every browser-based wallet
while looking perfectly fine to `curl`.

## Programmatic API

```ts
import { lint, lintDomain, formatText } from 'stellar-toml-lint';
import { readFile } from 'node:fs/promises';

const result = lint(await readFile('stellar.toml', 'utf8'), {
  domain: 'example.com',
  strict: true,
  rules: { 'general/unknown-field': 'off' },
});

// The reporters mirror `--format`: formatText (shown here), formatJson,
// formatJunit, formatSarif, and formatGithub.
if (!result.ok) {
  console.error(formatText(result, { color: true }));
  process.exit(1);
}

// Or check a live site. CORS, content type, size, and the negotiated TLS
// session are checked too.
const live = await lintDomain('example.com');
```

`lintDomain` inspects the TLS session by opening one extra handshake to the host, because Node's
`fetch` does not expose the socket it used. A caller that injects its own `fetch` owns the transport,
so it injects a `tlsProbe` too — otherwise the audit is skipped rather than guessed at:

```ts
const result = await lintDomain('example.com', {}, myFetch, async (host, port) => {
  return { protocol: 'TLSv1.3', cipher: 'TLS_AES_256_GCM_SHA384' };
});
```

Every diagnostic carries a stable `rule` id, a `severity`, a dotted `path` to the offending value, a
source `position`, a link to the relevant part of the spec, and a concrete `suggestion`.

```ts
interface Diagnostic {
  rule: string; // 'currencies/issuance-exclusive'
  severity: 'error' | 'warning' | 'info';
  category:
    'file' | 'general' | 'documentation' | 'principals' | 'currencies' | 'validators' | 'network';
  message: string;
  path?: string; // 'CURRENCIES[1].issuer'
  position?: { line: number; column: number };
  helpUri?: string;
  suggestion?: string;
}
```

## What it checks

Run `stellar-toml-lint --list-rules` for the authoritative list. In summary:

**File** — 100KB size limit, TOML syntax with line and column, UTF-8 BOM detection.

**General** — `VERSION`; `NETWORK_PASSPHRASE` matched byte-for-byte against the known networks;
`https://` on every endpoint field; no trailing slashes on service endpoints
(`WEB_AUTH_ENDPOINT`, `TRANSFER_SERVER`, `TRANSFER_SERVER_SEP0024`, `KYC_SERVER`,
`ANCHOR_QUOTE_SERVER`, `DIRECT_PAYMENT_SERVER` — a trailing `/` turns client sub-routes into
`//info` and triggers redirects that strip `Authorization`); checksum-valid `SIGNING_KEY`,
`URI_REQUEST_SIGNING_KEY`, `WEB_AUTH_CONTRACT_ID`, and `ACCOUNTS`; deprecated fields; unknown fields; empty string values in documentation fields; and uppercase-only Stellar public keys
(`SIGNING_KEY`, `[[CURRENCIES]].issuer`, `[[VALIDATORS]].PUBLIC_KEY`) — lowercase base32 letters are
flagged with the corrected uppercase form, since wallets compare the string when matching accounts.

**Cross-field dependencies** — `DIRECT_PAYMENT_SERVER` (SEP-31) requires `KYC_SERVER` (SEP-12);
`WEB_AUTH_ENDPOINT` (SEP-10) requires `SIGNING_KEY`; SEP-45 needs both its endpoint and contract ID;
`TRANSFER_SERVER_SEP0024` (SEP-24), `KYC_SERVER` (SEP-12), and `ANCHOR_QUOTE_SERVER` (SEP-38) each
require `WEB_AUTH_ENDPOINT`; and a declared `TRANSFER_SERVER` or `TRANSFER_SERVER_SEP0024` needs a
non-empty `[[CURRENCIES]]` list.

**`[DOCUMENTATION]`** — completeness against what wallets weigh when listing an asset; `https://`
URLs; `ORG_URL` matching the serving domain; attestation documents hosted on your own domain;
`ORG_OFFICIAL_EMAIL` at the `ORG_URL` domain; E.164 phone format; handles that are handles, not URLs;
and `ORG_GITHUB` as a valid GitHub username or `https://github.com/<username>` profile URL.

**`[[PRINCIPALS]]`** — name and email present and well-formed; hex photo hashes of plausible length.

**`[[CURRENCIES]]`** — code length and charset; exactly one of `issuer` or `contract`, both checksum
validated; the native XLM asset handled as the special case it is; exactly one issuance policy;
`status` and `anchor_asset_type` enums; `display_decimals` in 0–7; asset-anchored currencies
requiring a valid `anchor_asset_type` and warning when `anchor_asset` is absent; anchored fiat
requiring a declared transfer server; SEP-8 regulated assets carrying an approval server, with
`regulated = true` rejected on the native asset and on Soroban contract tokens; collateral address,
message, and signature lists of equal length; `toml` pointer entries carrying nothing else;
duplicate assets.

Asset-anchored currencies (`is_asset_anchored = true`) must use one of `fiat`, `crypto`, `stock`,
`bond`, `commodity`, `real_estate`, or `other` for `anchor_asset_type`. Missing or invalid values
emit `currencies/missing-anchor-asset-type` as an error. Missing `anchor_asset` metadata emits the
`currencies/missing-anchor-asset-code` warning.

**`[[VALIDATORS]]`** — `ALIAS` matching `^[a-z0-9-]{2,16}$`, unique, and not colliding with a
reserved stellar-core config keyword (`self`, `all`, `default`, `none`, `quorum`, `peers`,
`manual`, `auto`); checksum-valid, unique `PUBLIC_KEY`; `HOST` as `host:port`; `HISTORY` as a
well-formed archive URL, with the `{0}` template parameter accepted and its braces required to
balance.

**Network** (with `--domain`) — reachability, `Access-Control-Allow-Origin: *`, `text/plain` content
type, size, and the security of the TLS session: a negotiated protocol of TLS 1.0, TLS 1.1, SSLv2,
or SSLv3, and cipher suites built on 3DES, DES, RC4, CBC, NULL, or EXPORT primitives. Nothing here
fires for a local file, so offline linting never depends on a network connection.

**Network** (with `--check-network`) — queries the `HORIZON_URL` endpoint the file advertises and
asserts it answers with a valid Horizon root document. An endpoint that is offline, misconfigured,
or returns something other than Horizon JSON emits `network/horizon-unreachable` (error); a
`current_protocol_version` that the instance's `core_supported_protocol_version` does not cover
emits `network/horizon-protocol-outdated` (warning). The same flag also verifies `SIGNING_KEY` and
`ACCOUNTS` exist on the network, and when `ANCHOR_QUOTE_SERVER` is declared it GETs
`/prices?sell_asset=...` for each classic currency and asserts a 200 whose body carries a
`buy_assets` array of valid price objects — a 5xx, unreachable server, or HTML where a price object
belongs emits `sep38/prices-endpoint-error` or `sep38/malformed-price-response` (both errors), so a
wallet that cannot negotiate exchange rates fails the run instead of at transfer time. The
`/quote` route is probed too: a 5xx emits `sep38/quote-endpoint-error`, and a 200 that is not a JSON
object emits `sep38/malformed-quote-response`, while the 400/401/404 a bare unauthenticated GET
legitimately earns stays silent.

For every `[[CURRENCIES]]` entry marked `regulated=true` with a classic `issuer`, the issuer's
account flags are read from Horizon: a missing `AUTH_REQUIRED_FLAG` emits
`currencies/regulated-missing-auth-required-flag` (error) and a missing `AUTH_REVOCABLE_FLAG` emits
`currencies/regulated-missing-auth-revocable-flag` (warning), since SEP-8 needs the issuer to
control who may hold the asset and to be able to freeze offenders. A Horizon outage, missing
account, or unparseable response degrades to the `currencies/regulated-issuer-flags-unverifiable`
warning instead of failing the run.

**Contracts** (with `--check-contracts`) — queries the Soroban RPC for the contract instance and
WASM behind every `[[CURRENCIES]].contract` and `WEB_AUTH_CONTRACT_ID`, comparing each
`liveUntilLedgerSeq` against the network's `latestLedger`. When the effective TTL is within roughly a
day of expiry it emits `soroban/contract-ttl-expiring-soon` (warning); past that point, or when the
instance or WASM entry is absent entirely, it emits `soroban/contract-expired` (error). An
unreachable or malformed RPC degrades to `soroban/contract-ttl-unavailable` (warning). The RPC
endpoint is derived from `NETWORK_PASSPHRASE` (Public, Testnet, or Futurenet) and can be overridden
with `--soroban-rpc`.

### Severity

- **error** — violates SEP-1, or will break a client. Fails the build.
- **warning** — valid but likely wrong, or materially incomplete.
- **info** — worth a look; usually an unrecognised field name.

Tune any rule with `--off`, `--warn`, or `--error`.

## Contributing

New contributors are genuinely welcome — see [CONTRIBUTING.md](./CONTRIBUTING.md). Issues labelled
[`good first issue`][gfi] are scoped to be completable in an afternoon, and adding a rule is mostly a
matter of appending one object to a list and one fixture to a test.

## Maintainers

- [@Kaybee973](https://github.com/Kaybee973)
- [@Olasunkanmi975](https://github.com/Olasunkanmi975)

General enquiries: <anchortools23@gmail.com>. Please use
[issues](https://github.com/anchor-tools/stellar-toml-lint/issues) for bugs and feature requests, and
a [private advisory](https://github.com/anchor-tools/stellar-toml-lint/security/advisories/new) for
anything security-related.

## Funding

This project participates in [Drips](https://www.drips.network). See [FUNDING.json](./FUNDING.json).

## License

[Apache-2.0](./LICENSE)

Not affiliated with or endorsed by the Stellar Development Foundation.

[SEP-1]: https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0001.md
[anchor-tests]: https://github.com/stellar/stellar-anchor-tests
[gfi]: https://github.com/anchor-tools/stellar-toml-lint/labels/good%20first%20issue
