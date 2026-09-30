# Stellar TOML Lint — VS Code extension

Official VS Code client for [`stellar-toml-lint`](https://github.com/anchor-tools/stellar-toml-lint).
It launches the background `stellar-toml-lint --lsp` language server over stdio,
so opened `stellar.toml` files get live SEP-1 diagnostics in the Problems panel,
quick-fix code actions, and hover documentation — no manual settings required.

## Features

- **Automatic activation** for any file named `stellar.toml` or any file inside
  `.well-known/` (e.g. `public/.well-known/stellar.toml`).
- **Live diagnostics** from the LSP server (errors, warnings, info with rule ids,
  suggestions, and SEP-1 links).
- **Quick fixes** for mechanically safe findings (trailing slashes, near-miss
  `NETWORK_PASSPHRASE`, bare social handles, E.164 phones).
- **SEP-1 syntax highlighting** via the bundled TextMate injection grammar.
- **Status bar** showing `$(check) SEP-1 Valid` or `$(error) N Errors`.
- **Commands**:
  - `Stellar TOML: Lint active document` (`stellar-toml.lint`) — force a re-lint.
  - `Stellar TOML: Apply safe fixes` (`stellar-toml.format`) — run the CLI `--fix` pass.
  - `Stellar TOML: Show wallet readiness score` (`stellar-toml.readiness`) — print the
    Wallet Readiness score (`100 − 10·errors − 3·warnings − info`) with its A–F grade
    to the _Stellar TOML Readiness_ output channel.

## Requirements

- VS Code `^1.60.0`.
- Node.js 20+.
- The `stellar-toml-lint` CLI: the extension looks for the built `dist/cli.js`
  next to the checkout first, then falls back to `stellar-toml-lint` on `PATH`
  (`npm install -g stellar-toml-lint`).

## Extension Settings

| Setting                  | Default | Effect                                                          |
| ------------------------ | ------- | --------------------------------------------------------------- |
| `stellarToml.strict`     | `false` | Treat warnings as errors in the status bar verdict.             |
| `stellarToml.domain`     | `""`    | Serving domain for same-domain checks; empty disables them.     |
| `stellarToml.rules`      | `{}`    | Per-rule severities, e.g. `{ "general/unknown-field": "off" }`. |
| `stellarToml.serverPath` | `""`    | Explicit CLI path; empty auto-discovers it or uses `PATH`.      |

```jsonc
// .vscode/settings.json
{
  "stellarToml.strict": true,
  "stellarToml.domain": "example.com",
  "stellarToml.rules": { "general/unknown-field": "off" },
}
```

## Development

```sh
# from the repo root
npm run build            # builds dist/cli.js the extension spawns
npm run build:vscode     # compiles editors/vscode/src -> editors/vscode/out

# package a .vsix (requires @vscode/vsce)
npm run package:vscode
```

The server is resolved as `node <repo>/dist/cli.js --lsp` during development and
as `stellar-toml-lint --lsp` from `PATH` once installed, so the packaged `.vsix`
never needs to ship the whole repo.

## Manual install

```sh
code --install-extension stellar-toml-lint-0.1.0.vsix
```
