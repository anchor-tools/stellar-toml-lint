#!/usr/bin/env node
/**
 * Command line entry point.
 *
 * Argument parsing is hand-rolled rather than pulled from a library: the flag
 * set is small and stable, and a linter that anchors run in CI benefits from a
 * dependency tree small enough to audit by eye.
 */
import { readFile } from 'node:fs/promises';
import { basename } from 'node:path';
import process from 'node:process';
import { lint, lintDomain, finalize } from './lint.js';
import { checkNetworkAccounts } from './network-checks.js';
import { formatGithub, formatJson, formatJunit, formatSarif, formatText } from './reporters.js';
import { checkDisplayDecimals } from './rules/display-decimals-audit.js';
import { checkHorizon } from './rules/horizon-check.js';
import { checkSep38 } from './rules/sep38-endpoints.js';
import { allRules } from './rules/index.js';
import type { LintResult, RuleOverrides, Severity } from './types.js';

const VERSION = '0.1.0';
const DEFAULT_PATH = 'stellar.toml';

type Format = 'text' | 'json' | 'sarif' | 'github' | 'junit';

interface Cli {
  noSuggestions?: boolean;
  paths: string[];
  domain?: string;
  format: Format;
  strict: boolean;
  color?: boolean;
  quiet: boolean;
  showHelp: boolean;
  rules: RuleOverrides;
  maxWarnings?: number;
  checkNetwork: boolean;
}

const USAGE = `stellar-toml-lint ${VERSION}

Validate a Stellar Info File (stellar.toml) against SEP-1 — offline.

USAGE
  stellar-toml-lint [file...]            Lint local files (default: ./stellar.toml)
  stellar-toml-lint --domain <domain>    Fetch and lint https://<domain>/.well-known/stellar.toml
  cat stellar.toml | stellar-toml-lint - Lint stdin

OPTIONS
  -d, --domain <domain>   Domain serving the file. Enables CORS, content-type and
                          ORG_URL same-domain checks. Fetches unless files are given.
  -f, --format <fmt>      text (default), json, sarif, github, or junit
      --strict            Treat warnings as errors
      --max-warnings <n>  Fail if warnings exceed n
      --off <rule>        Disable a rule (repeatable)
      --error <rule>      Raise a rule to error (repeatable)
      --warn <rule>       Lower a rule to warning (repeatable)
  -q, --quiet             Report errors only
      --show-help-urls    Print the spec link for each finding
      --no-suggestions    Hide diagnostic suggestions in the output
      --check-network     Verify SIGNING_KEY, ACCOUNTS, HORIZON_URL, and
                          ANCHOR_QUOTE_SERVER against the network
      --color / --no-color
      --list-rules        Print every rule and exit
  -v, --version
  -h, --help

EXIT CODES
  0  no errors            1  errors found            2  bad usage or I/O failure

EXAMPLES
  stellar-toml-lint public/.well-known/stellar.toml
  stellar-toml-lint --domain example.com --strict
  stellar-toml-lint -f sarif > results.sarif
`;

async function main(argv: string[]): Promise<number> {
  let cli: Cli;
  try {
    const parsed = parseArgs(argv);
    if (parsed === 'handled') return 0;
    cli = parsed;
  } catch (error) {
    process.stderr.write(`${message(error)}\n\nRun with --help for usage.\n`);
    return 2;
  }

  const color = cli.color ?? shouldUseColor();
  const results: { name: string; result: LintResult }[] = [];

  try {
    if (cli.domain && cli.paths.length === 0) {
      results.push({
        name: cli.domain,
        result: await lintDomain(cli.domain, {
          strict: cli.strict,
          rules: cli.rules,
          checkNetwork: cli.checkNetwork,
        }),
      });
    } else {
      const paths = cli.paths.length > 0 ? cli.paths : [DEFAULT_PATH];
      for (const path of paths) {
        const source = path === '-' ? await readStdin() : await readFile(path, 'utf8');
        let fileResult = lint(source, {
          strict: cli.strict,
          rules: cli.rules,
          checkNetwork: cli.checkNetwork,
          ...(cli.domain ? { domain: cli.domain } : {}),
        });

        if (cli.checkNetwork && fileResult.parsed) {
          const networkDiagnostics = [
            ...(await checkHorizon(fileResult.parsed, fetch, { rules: cli.rules })),
            ...(await checkNetworkAccounts(fileResult.parsed)),
            ...(await checkDisplayDecimals(fileResult.parsed, fetch, { rules: cli.rules })),
            ...(await checkSep38(fileResult.parsed, fetch, { rules: cli.rules })),
          ];
          if (networkDiagnostics.length > 0) {
            fileResult = finalize(
              [...fileResult.diagnostics, ...networkDiagnostics],
              { strict: cli.strict },
              fileResult.parsed,
            );
          }
        }

        results.push({
          name: path === '-' ? 'stdin' : path,
          result: fileResult,
        });
      }
    }
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }

  for (const { name, result } of results) {
    const filtered = cli.quiet
      ? { ...result, diagnostics: result.diagnostics.filter((d) => d.severity === 'error') }
      : result;

    process.stdout.write(render(filtered, name, cli, color));
  }

  return verdict(results, cli) ? 0 : 1;
}

function render(result: LintResult, name: string, cli: Cli, color: boolean): string {
  switch (cli.format) {
    case 'json':
      return formatJson(result, name);
    case 'sarif':
      return formatSarif(result, name, VERSION);
    case 'github':
      return formatGithub(result, name);
    case 'junit':
      return formatJunit(result, name);
    case 'text':
      return formatText(result, {
        filename: name,
        color,
        showHelp: cli.showHelp,
        showSuggestions: !cli.noSuggestions,
        errorsOnly: cli.quiet,
      });
  }
}

/** Combines per-file verdicts, including the `--max-warnings` threshold. */
function verdict(results: { result: LintResult }[], cli: Cli): boolean {
  const totals = results.reduce(
    (acc, { result }) => {
      acc.error += result.counts.error;
      acc.warning += result.counts.warning;
      return acc;
    },
    { error: 0, warning: 0 },
  );

  if (totals.error > 0) return false;
  if (cli.strict && totals.warning > 0) return false;
  if (cli.maxWarnings !== undefined && totals.warning > cli.maxWarnings) return false;
  return true;
}

function parseArgs(argv: string[]): Cli | 'handled' {
  const cli: Cli = {
    paths: [],
    format: 'text',
    strict: false,
    quiet: false,
    showHelp: false,
    rules: {},
    checkNetwork: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] as string;

    switch (arg) {
      case '-h':
      case '--help':
        process.stdout.write(USAGE);
        return 'handled';

      case '-v':
      case '--version':
        process.stdout.write(`${VERSION}\n`);
        return 'handled';

      case '--list-rules':
        process.stdout.write(listRules());
        return 'handled';

      case '-d':
      case '--domain':
        cli.domain = requireValue(argv, ++i, arg);
        break;

      case '-f':
      case '--format': {
        const value = requireValue(argv, ++i, arg);
        if (!isFormat(value)) {
          throw new Error(
            `Unknown format "${value}". Expected text, json, sarif, github, or junit.`,
          );
        }
        cli.format = value;
        break;
      }

      case '--strict':
        cli.strict = true;
        break;

      case '--no-suggestions':
        cli.noSuggestions = true;
        break;

      case '--check-network':
        cli.checkNetwork = true;
        break;

      case '--max-warnings': {
        const value = Number(requireValue(argv, ++i, arg));
        if (!Number.isInteger(value) || value < 0) {
          throw new Error('--max-warnings expects a non-negative integer.');
        }
        cli.maxWarnings = value;
        break;
      }

      case '--off':
      case '--error':
      case '--warn': {
        const id = requireValue(argv, ++i, arg);
        assertKnownRule(id);
        cli.rules[id] = arg === '--off' ? 'off' : (arg.slice(2) as Severity);
        break;
      }

      case '-q':
      case '--quiet':
        cli.quiet = true;
        break;

      case '--show-help-urls':
        cli.showHelp = true;
        break;

      case '--color':
        cli.color = true;
        break;

      case '--no-color':
        cli.color = false;
        break;

      default:
        if (arg.startsWith('--')) throw new Error(`Unknown option "${arg}".`);
        cli.paths.push(arg);
    }
  }

  return cli;
}

function requireValue(argv: string[], index: number, flag: string): string {
  const value = argv[index];
  if (value === undefined || value.startsWith('-')) {
    throw new Error(`${flag} expects a value.`);
  }
  return value;
}

function isFormat(value: string): value is Format {
  return (
    value === 'text' ||
    value === 'json' ||
    value === 'sarif' ||
    value === 'github' ||
    value === 'junit'
  );
}

/** Rejects typo'd rule ids rather than silently ignoring the override. */
function assertKnownRule(id: string): void {
  if (allRules.some((rule) => rule.id === id)) return;
  const near = allRules
    .map((rule) => rule.id)
    .filter((candidate) => candidate.includes(id) || id.includes(candidate.split('/')[1] ?? ''))
    .slice(0, 3);
  throw new Error(
    `Unknown rule "${id}".${near.length > 0 ? ` Did you mean: ${near.join(', ')}?` : ''} Run --list-rules to see them all.`,
  );
}

function listRules(): string {
  const width = Math.max(...allRules.map((r) => r.id.length));
  const lines = allRules.map(
    (r) => `  ${r.id.padEnd(width)}  ${r.severity.padEnd(7)}  ${r.description}`,
  );
  return `${allRules.length} rules\n\n${lines.join('\n')}\n`;
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString('utf8');
}

/**
 * Decides whether the text reporter emits ANSI colour.
 *
 * Follows the NO_COLOR standard (https://no-color.org): any non-empty NO_COLOR
 * value disables colour, whatever it contains, and an empty value counts as
 * unset. FORCE_COLOR is honoured next, and TTY detection is the fallback.
 *
 * An explicit `--color` or `--no-color` is resolved by `main` before this is
 * consulted, so the flag always wins — that is the only thing that overrides
 * NO_COLOR.
 */
function shouldUseColor(): boolean {
  const noColor = process.env.NO_COLOR;
  if (noColor !== undefined && noColor !== '') return false;
  if (process.env.FORCE_COLOR && process.env.FORCE_COLOR !== '0') return true;
  return process.stdout.isTTY === true;
}

function message(error: unknown): string {
  if (error instanceof Error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') {
      const path = (error as NodeJS.ErrnoException).path ?? DEFAULT_PATH;
      return `Could not find ${path}. Pass a path, or use --domain to check a live site.`;
    }
    if (code === 'EISDIR') {
      const path = (error as NodeJS.ErrnoException).path ?? '';
      return `${path} is a directory. Point at the file, e.g. ${basename(path)}/stellar.toml.`;
    }
    return error.message;
  }
  return String(error);
}

main(process.argv.slice(2))
  .then((code) => process.exit(code))
  .catch((error: unknown) => {
    process.stderr.write(`Unexpected failure: ${message(error)}\n`);
    process.exit(2);
  });
