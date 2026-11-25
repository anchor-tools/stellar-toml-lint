# LSP-stellar-toml

Official Sublime Text LSP helper package for `stellar.toml` files.

## Features

- **Diagnostics** - Real-time SEP-1 linting diagnostics
- **Completions** - Context-aware completions for stellar.toml keys
- **Hover documentation** - SEP-1 spec links on hover
- **Syntax highlighting** - TOML syntax mapping for stellar.toml files

## Installation

### Package Control

Install via Package Control by searching for `LSP-stellar-toml`.

### Manual

1. Clone this repository to `Packages/LSP-stellar-toml`
2. Install the [LSP](https://packagecontrol.io/packages/LSP) package via Package Control
3. Configure `LSP.sublime-settings` to include the stellar.toml server

## Configuration

Edit `LSP-stellar-toml.sublime-settings`:

```json
{
  "command": ["stellar-toml-lint", "--lsp"],
  "selector": "source.stellar-toml"
}
```

## Development

```bash
cd integrations/sublime
python3 -m py_compile LSP-stellar-toml/plugin.py
```

## Requirements

- Sublime Text 4+
- LSP package (via Package Control)
- stellar-toml-lint CLI installed and available on PATH
