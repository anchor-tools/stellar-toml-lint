# JetBrains IDE Plugin

Official JetBrains plugin for IntelliJ IDEA and WebStorm with real-time SEP-1 linting for `stellar.toml` files.

## Features

- **Real-time diagnostics** - Inline errors, warnings, and info messages as you edit
- **Quick-fix intentions** - Press `Alt+Enter` to see suggested fixes
- **Hover documentation** - View SEP-1 spec documentation on hover
- **File type association** - Automatic recognition of `stellar.toml` and `.well-known/stellar.toml`
- **LSP integration** - Connects to `stellar-toml-lint --lsp` via the IntelliJ LSP API

## Installation

### From JetBrains Marketplace

Install the "Stellar TOML Lint" plugin from the JetBrains Marketplace.

### Manual Installation

1. Build the plugin: `./gradlew buildPlugin`
2. Install the resulting ZIP from `build/distributions/` via `Settings > Plugins > Install Plugin from Disk`

## Development

```bash
cd integrations/jetbrains
./gradlew buildPlugin
```

## Requirements

- `stellar-toml-lint` CLI installed and available on PATH
- IntelliJ IDEA 2024.1+ or WebStorm 2024.1+
