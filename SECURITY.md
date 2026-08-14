# Security Policy

## Scope

`stellar-toml-lint` is a linter. It reads a TOML file and, with `--domain`, makes one outbound HTTPS
GET request. It never writes to the network, never executes anything from the file it reads, and
never handles secret keys.

The security-relevant surface is therefore small but not empty:

- **Parsing untrusted input.** A `stellar.toml` from a third party is untrusted. A crash is a bug; a
  hang or unbounded memory growth on a malicious file is a vulnerability.
- **`--domain` fetches a remote URL.** Report anything that could turn that into a request
  somewhere unintended, or that leaks the requesting environment.
- **False negatives with security consequences.** Silently accepting an invalid `SIGNING_KEY`, or
  passing a file whose CORS configuration makes it unreadable to wallets, is in scope — the whole
  point of the tool is to catch those.

## Reporting

Report privately through [GitHub Security Advisories][advisories] rather than a public issue. If you
cannot use advisories, email <anchortools23@gmail.com> instead — please do not include exploit details
in the first message, just enough for us to open a private channel.

Please include the input that triggers it, the version (`stellar-toml-lint --version`), and your Node
version. Strip real keys and personal contact details from any sample file.

Expect an acknowledgement within a few days. Once a fix ships, we will credit you in the release
notes unless you would rather stay anonymous.

## Supported versions

Fixes land on the latest minor release. Given the pre-1.0 version, please upgrade before reporting.

[advisories]: https://github.com/anchor-tools/stellar-toml-lint/security/advisories/new
