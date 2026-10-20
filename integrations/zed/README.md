# Stellar TOML — Zed extension

Official [Zed](https://zed.dev) extension for `stellar.toml` files. It registers
a `Stellar TOML` language, bundles syntax highlights and folding queries, and
launches the [`stellar-toml-lint`](https://github.com/anchor-tools/stellar-toml-lint)
language server for live SEP-1 diagnostics, quick fixes, hover documentation,
and semantic token highlighting.

## Install

1. Install the linter (any one of):

   ```bash
   npm install -g stellar-toml-lint
   brew install anchor-tools/tap/stellar-toml-lint
   ```

   When neither is present but Node is, the extension falls back to
   `npx --yes stellar-toml-lint`, so the first run works without a manual step.

2. In Zed, run `zed: extensions`, search for **Stellar TOML**, and install it.

3. Open any `stellar.toml` (or a file under `.well-known/`) — diagnostics appear
   as you type.

## What it provides

- **Language**: `Stellar TOML`, matched by the `stellar.toml` filename suffix.
- **Grammar**: `tree-sitter-toml`, pinned in `extension.toml`.
- **Queries**: `languages/stellar-toml/highlights.scm`, `folds.scm`,
  `brackets.scm`, `indents.scm`.
- **Language server**: `stellar-toml-lint --lsp`, resolved from `PATH`, then
  `npx`.

## Build

The extension is a Rust crate compiled to WebAssembly. Zed builds it from the
`wasm32-wasip1` target when the extension is installed from source:

```bash
rustup target add wasm32-wasip1
cargo build --release --target wasm32-wasip1
```

The test suite builds it the same way when a Rust toolchain is available and
skips otherwise, so CI without Rust still passes.
