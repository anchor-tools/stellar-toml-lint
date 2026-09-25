# Neovim LSP Package

Official Neovim LSP integration for `stellar.toml` files providing real-time diagnostics, code actions, and hover documentation.

## Features

- **Diagnostics** - Real-time SEP-1 linting diagnostics with virtual text, signs, floats, and underlines
- **Code Actions** - Quick-fix support via `<leader>ca`
- **Hover documentation** - SEP-1 spec links on hover via `K`
- **Auto-attach** - Automatically attaches the LSP when opening `stellar.toml` files
- **Formatting on save** - Auto-fix violations on save via `--fix`
- **Tree-sitter syntax highlighting** - Custom queries for stellar.toml structure

## Installation

### lazy.nvim

```lua
{
  "anchor-tools/stellar-toml-lint",
  dir = "integrations/neovim",
  ft = "stellar.sol",
  config = function()
    local stellar_lint = require("stellar-toml-lint")
    stellar_lint.setup()
  end,
}
```

### packer.nvim

```lua
use {
  "anchor-tools/stellar-toml-lint",
  dir = "integrations/neovim",
  ft = "stellar.sol",
  config = function()
    local stellar_lint = require("stellar-toml-lint")
    stellar_lint.setup()
  end,
}
```

### Manual Installation

1. Clone the repository into `~/.config/nvim/integrations/neovim/`
2. Add the following to your `init.lua`:

```lua
local stellar_lint = require("stellar-toml-lint")
stellar_lint.setup()
```

## Tree-sitter Configuration

For `nvim-treesitter`, add the parser and queries:

```lua
require("nvim-treesitter.configs").setup({
  ensure_installed = { "stellar-toml" },
  highlight = {
    enable = true,
  },
  query_linters = {
    enable = true,
  },
})
```

Place the `stellar-toml.scm` query file in `~/.config/nvim/after/queries/stellar-toml/` or in the `syntax/` directory of this package.

## Configuration Options

```lua
require("stellar-toml-lint").setup({
  command = "stellar-toml-lint",
  args = { "--lsp" },
  filetypes = { "stellar.sol" },
  diagnostics = {
    virtual_text = true,
    signs = true,
    float = true,
    underline = true,
  },
  formatting = {
    format_on_save = true,
  },
})
```

## Upstream Configuration

This package uses `nvim-lspconfig`'s server definition (`lspconfig.lua`) for compatibility with the nvim-lspconfig ecosystem. You can also use it directly with lspconfig:

```lua
require("lspconfig").stellar_toml_lint.setup({
  cmd = { "stellar-toml-lint", "--lsp" },
  filetypes = { "stellar.sol" },
  root_dir = function(fname)
    -- walks up looking for .git or .stellartomlrc.json
  end,
})
```

See [integrations/neovim/](https://github.com/anchor-tools/stellar-toml-lint/tree/main/integrations/neovim/) for the full package.
