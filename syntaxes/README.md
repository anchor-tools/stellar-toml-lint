# Stellar TOML Syntax Highlighter

A TextMate grammar definition extending standard TOML highlighting specifically for `stellar.toml`.

Features:

- Highlights standard SEP-1 table names (`DOCUMENTATION`, `PRINCIPALS`, `CURRENCIES`, `VALIDATORS`).
- Distinct cryptographic token scopes for Stellar public keys (`G...`, `C...`).
- Global HTTPS endpoint keys as network constants.
- Uppercase global configuration keys.

## VS Code

This syntax definition is wired via injection into `source.toml`. Just ensure your file is recognized as TOML (usually `*.toml`), and these SEP-1 specific highlights will automatically apply.
