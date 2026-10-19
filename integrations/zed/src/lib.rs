//! Official Zed extension for `stellar.toml`.
//!
//! Zed extensions are compiled to WebAssembly (`wasm32-wasip1`) and loaded by
//! the editor, which calls back into them to discover the language server
//! command for a buffer. This extension registers the `Stellar TOML` language
//! (see `languages/stellar-toml/`) and launches `stellar-toml-lint --lsp`,
//! which speaks the same protocol the VS Code, Neovim, and Sublime clients use.
//!
//! The server is resolved in order of preference:
//!
//! 1. a `stellar-toml-lint` binary already on `PATH` (Homebrew, the release
//!    artifacts, or `npm install -g`);
//! 2. `npx --yes stellar-toml-lint` when Node is available but nothing is
//!    installed, so the first run works without a manual install step;
//! 3. otherwise a clear error telling the user how to install it.
//!
//! Resolving at call time rather than bundling a binary keeps the extension a
//! thin shim: the linter stays the single source of truth, and a user's pinned
//! version wins over whatever the extension would have shipped.

use zed_extension_api::{self as zed, Result};

struct StellarTomlExtension;

impl zed::Extension for StellarTomlExtension {
    fn new() -> Self {
        Self
    }

    fn language_server_command(
        &mut self,
        _language_server_id: &zed::LanguageServerId,
        worktree: &zed::Worktree,
    ) -> Result<zed::Command> {
        if let Some(binary) = worktree.which("stellar-toml-lint") {
            return Ok(zed::Command {
                command: binary,
                args: vec!["--lsp".to_string()],
                env: Default::default(),
            });
        }

        if let Some(npx) = worktree.which("npx") {
            return Ok(zed::Command {
                command: npx,
                args: vec![
                    "--yes".to_string(),
                    "stellar-toml-lint".to_string(),
                    "--lsp".to_string(),
                ],
                env: Default::default(),
            });
        }

        Err(
            "stellar-toml-lint was not found. Install it with \
             `npm install -g stellar-toml-lint`, `brew install anchor-tools/tap/stellar-toml-lint`, \
             or download a release binary, then restart Zed."
                .to_string(),
        )
    }
}

zed::register_extension!(StellarTomlExtension);
