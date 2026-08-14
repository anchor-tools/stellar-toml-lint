# Contributing

Thanks for helping out. This project exists so that anchors stop shipping broken `stellar.toml`
files, and almost every improvement starts with someone noticing a real-world mistake the linter
missed.

## Getting set up

```bash
git clone https://github.com/anchor-tools/stellar-toml-lint
cd stellar-toml-lint
npm install
npm test
```

Node.js 20 or newer. There is no build step needed for testing — `vitest` runs the TypeScript
sources directly. The CLI tests are the exception: they exercise the built artifact, so run
`npm run build` first if you are changing `src/cli.ts`.

```bash
npm test            # everything
npm run test:watch  # while you work
npm run typecheck   # tsc --noEmit
npm run lint        # eslint
npm run format      # prettier --write
```

## Adding a rule

This is the most common contribution, and it is deliberately mechanical.

1. **Find the requirement in [SEP-1][sep1].** Every rule must trace to something the spec actually
   says. If the spec is ambiguous, say so in a comment and choose the lenient reading — a false
   positive is worse than a missed warning, because it teaches people to ignore the tool.

2. **Add the rule object** to the right file in `src/rules/`:

   ```ts
   {
     id: 'currencies/my-new-rule',      // category/kebab-case
     category: 'currencies',
     severity: 'warning',
     description: 'One line, shown by --list-rules',
     run(ctx) {
       eachCurrency(ctx, (entry, path) => {
         if (/* everything is fine */) return;
         ctx.report({
           rule: 'currencies/my-new-rule',
           category: 'currencies',
           message: 'What is wrong, as a sentence with no trailing period',
           path: `${path}.field`,
           position: ctx.locate(`${path}.field`),
           helpUri: specUrl('currency-documentation'),
           suggestion: 'What to actually do about it.',
         });
       });
     },
   }
   ```

3. **Add a test** in `test/lint.test.ts` covering both the violation and the case that must stay
   silent. The second half matters more than the first.

4. **Add the defect to `test/fixtures/broken.toml`** and list your rule id in the `detects %s` table.
   Leave `test/fixtures/valid.toml` clean — that fixture asserts zero diagnostics, so it is the
   regression test for false positives.

### Choosing a severity

- `error` — violates SEP-1, or will break a real client. Fails builds.
- `warning` — valid, but likely a mistake, or materially incomplete.
- `info` — worth knowing; usually an unrecognised field name.

When in doubt, start at `warning`. Anything that could fire on a correct file must not be an `error`.

### Writing good messages

The message says what is wrong. The suggestion says what to do. Include the offending value when it
helps, and compute the corrected value when you can — `Replace it with exactly: ...` saves a trip to
the spec. Look at `network/passphrase` for the shape to aim for.

## Reporting a bug

The most useful bug report is a `stellar.toml` snippet plus what you expected. Two kinds are
especially valuable:

- **False positives.** A real, correct file that the linter complains about. These are the highest
  priority — see `git log` for the CORS and native-asset cases that live sites uncovered.
- **Misses.** A broken file that the linter passes.

Strip any real keys or contact details before posting.

## Pull requests

- One logical change per PR.
- Tests for anything that changes behaviour.
- `npm test`, `npm run lint`, and `npm run typecheck` all green.
- Update `README.md` if you added a flag or changed output.
- Add a `CHANGELOG.md` entry under `## Unreleased`.

Commit messages follow [Conventional Commits][cc]: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`,
`chore:`.

## Code style

Prettier and ESLint are authoritative; run `npm run format` before pushing. Beyond that:

- Comments explain _why_, not _what_. If a check encodes a subtlety of the spec, or works around
  something surprising about the real world, say so.
- Prefer narrowing `unknown` with the predicates in `src/predicates.ts` over casting. Every value in
  a parsed TOML document is genuinely unknown, and pretending otherwise is how linters crash on the
  files that need them most.
- No new runtime dependencies without discussion. This runs in other people's CI.

## Releasing

Maintainers only. Bump the version in `package.json` and the `VERSION` constant in `src/cli.ts` —
`test/package.test.ts` fails if the two drift — then update `CHANGELOG.md`, tag, and publish.

## Code of conduct

By participating you agree to the [Code of Conduct](./CODE_OF_CONDUCT.md).

[sep1]: https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0001.md
[cc]: https://www.conventionalcommits.org/
