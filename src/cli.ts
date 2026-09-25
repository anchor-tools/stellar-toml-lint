#!/usr/bin/env node
/**
 * Command line entry point.
 *
 * Argument parsing is hand-rolled rather than pulled from a library: the flag
 * set is small and stable, and a linter that anchors run in CI benefits from a
 * dependency tree small enough to audit by eye.
 */
import { readFile, writeFile } from 'node:fs/promises';
import { watch } from 'node:fs';
import { basename, dirname, resolve } from 'node:path';
import process from 'node:process';
import { assertKnownRule, loadConfig } from './config.js';
import { lint, lintDomain, finalize } from './lint.js';
import { checkNetworkAccounts } from './network-checks.js';
import { checkCorsPreflight } from './network/cors-preflight.js';
import {
  formatCheckstyle,
  formatGithub,
  formatHtml,
  formatJson,
  formatMarkdown,
  formatNdjson,
  formatJunit,
  formatSarif,
  formatSummary,
  formatText,
} from './reporters.js';
import { expandGlob, hasMagic } from './glob.js';
import { checkDisplayDecimals } from './rules/display-decimals-audit.js';
import { checkHorizon } from './rules/horizon-check.js';
import { checkSep38 } from './rules/sep38-endpoints.js';
import { checkRegulatedIssuerFlags } from './rules/currencies.js';
import { checkContracts } from './soroban.js';
import { checkSep6 } from './cross-sep/sep6.js';
import { checkSep10Replay } from './protocols/sep10-replay.js';
import { checkCollateralGovernance } from './security/collateral-governance.js';
import { allRules } from './rules/index.js';
import { PRESETS, resolvePreset, type PresetName } from './presets.js';
import { generateBadgeSvg, generateShieldsEndpoint } from './generators/badge.js';
import {
  generateAnchorPlatformConfig,
  formatAnchorPlatformYaml,
} from './generators/anchor-platform.js';
import { generateOpenApiSpec } from './generators/openapi.js';
import { generateDiagram, type GraphFormat } from './generators/diagram.js';
import { deliverWebhooks, isSupportedWebhookUrl } from './reporters/webhook.js';
import { runHealthCheck, formatHealthCheckTable } from './health-check.js';
import { runDashboard, supportsDashboard } from './ui/dashboard.js';
import { loadPolicy, validatePolicy, evaluatePolicy } from './policy/engine.js';
import { createFixtureFetch } from './mock-fixtures.js';
import { runLspServer } from './lsp/server.js';
import { getTomlJsonSchema } from './schema.js';
import { generateCompletion, isCompletionShell } from './completion.js';
import type { Diagnostic, LintResult, RuleOverrides, Severity } from './types.js';

const VERSION = '0.1.0';
const DEFAULT_PATH = 'stellar.toml';

type Format =
  'text' | 'json' | 'ndjson' | 'sarif' | 'github' | 'junit' | 'html' | 'checkstyle' | 'markdown';

interface Cli {
  noSuggestions?: boolean;
  paths: string[];
  domain?: string;
  format: Format;
  healthCheck?: boolean;
  strict: boolean;
  watch?: boolean;
  color?: boolean;
  quiet: boolean;
  showHelp: boolean;
  rules: RuleOverrides;
  preset?: PresetName;
  maxWarnings?: number;
  checkNetwork: boolean;
  verifySep10: boolean;
  badgeSvg?: string;
  badgeJson?: string;
  exportApConfig?: boolean;
  generateOpenapi?: string;
  webhookSlack?: string;
  webhookDiscord?: string;
  interactive?: boolean;
  checkContracts: boolean;
  sorobanRpc?: string;
  graph?: GraphFormat;
  graphIncludeContracts?: boolean;
  graphIncludeValidators?: boolean;
  graphColorByProtocol?: boolean;
  policy?: string;
  mockFixtures?: string;
  lsp?: boolean;
}

const USAGE = `stellar-toml-lint ${VERSION}

Validate a Stellar Info File (stellar.toml) against SEP-1 — offline.

USAGE
  stellar-toml-lint [file...]            Lint local files (default: ./stellar.toml)
  stellar-toml-lint "configs/**/*.toml"  Lint a glob — quote it so the shell
                                         passes the pattern through instead of
                                         expanding it (or failing to)
  stellar-toml-lint --domain <domain>    Fetch and lint https://<domain>/.well-known/stellar.toml
  cat stellar.toml | stellar-toml-lint - Lint stdin

OPTIONS
  -d, --domain <domain>   Domain serving the file. Enables CORS, content-type and
                          ORG_URL same-domain checks. Fetches unless files are given.
  -f, --format <fmt>      text (default), json, ndjson, sarif, github, junit, html,
                          checkstyle, or markdown (for GitHub step summaries)
      --strict            Treat warnings as errors
      --max-warnings <n>  Fail if warnings exceed n
      --off <rule>        Disable a rule (repeatable)
      --error <rule>      Raise a rule to error (repeatable)
      --warn <rule>       Lower a rule to warning (repeatable)
      --preset <name>     Start from a role's rule bundle: validator, anchor-sep24,
                          or issuer (see PRESETS)
  -i, --interactive       Full-screen dashboard to walk the findings. Needs a TTY;
                          without one the text reporter is used instead
      --lsp               Run as a Language Server on stdio (diagnostics,
                          quick-fix code actions, and SEP-1 hover docs)
  -q, --quiet             Report errors only
      --show-help-urls    Print the spec link for each finding
      --no-suggestions    Hide diagnostic suggestions in the output
      --health-check      Ping declared endpoint URLs to ensure they are live
      --check-network     Verify SIGNING_KEY, ACCOUNTS, HORIZON_URL, SEP-8
                          regulated issuer flags, and ANCHOR_QUOTE_SERVER
                          against the network
      --verify-sep10      Verify SEP-10 nonce uniqueness and replay resistance
      --check-contracts   Verify Soroban contract and WASM TTL liveliness
      --soroban-rpc <url> Soroban RPC endpoint to use with --check-contracts
      --mock-fixtures <dir>
                          Serve network checks from recorded JSON responses under
                          <dir> instead of the network. A URL with no fixture
                          fails instead of making a request (hermetic CI)
      --webhook-slack <url>
                          POST a Slack Block Kit card with the run summary
      --webhook-discord <url>
                          POST a Discord embed with the run summary
      --badge-svg <file>  Generate an SVG compliance badge
      --badge-json <file> Generate a Shields.io JSON endpoint
      --export-ap-config  Export Anchor Platform YAML config to stdout
      --generate-openapi <file>
                          Generate an OpenAPI 3.1 spec (json or yaml extension)
      --graph <fmt>       Generate architecture diagram: mermaid or dot
      --graph-contracts   Include Soroban contracts in diagram
      --graph-validators  Include validators in diagram
      --graph-color       Color nodes by protocol type
      --policy <file>     Evaluate enterprise policy file (JSON or YAML)
      --json-schema       Print a JSON Schema (Draft 2020-12) for stellar.toml
                          to stdout, for editor autocompletion via schema
                          associations
      --color / --no-color
      --list-rules        Print every rule and exit
      --completion <sh>   Print a shell completion script for bash, zsh, or fish
                          (e.g. eval "$(stellar-toml-lint --completion zsh)")
  -v, --version
  -h, --help

CONFIG
  .stellartomlrc.json    Project defaults, discovered upward from the linted
                         file's directory (from the current directory for stdin
                         and --domain), stopping at the filesystem root.
                         Recognises "rules", "strict", and "maxWarnings".
                         CLI flags always override the file; a malformed config
                         or an unknown rule id exits with code 2.

PRESETS
  --preset <name>        Apply a role's rule bundle before anything else, so a
                         team that is only half an ecosystem does not have to
                         copy a long --off chain into every workflow:

    validator            [[VALIDATORS]] and general file checks stay on; the
                         currency issuance and anchor service rules are off.
                         Duplicate validator hosts and aliases fail the build.
    anchor-sep24         SEP-24, SEP-10, and currency requirements at error
                         (a transfer server with no [[CURRENCIES]], an
                         incomplete SEP-45 pair, an undescribed anchored
                         asset). Validator rules are off — an anchor runs no
                         validator nodes.
    issuer               Currency, collateral, and documentation completeness
                         at error. Anchor service rules are off — a standalone
                         issuer runs no servers.

                         A preset is a baseline, not a policy: an explicit
                         --off, --warn, or --error on the same command line
                         still wins, whatever order the flags appear in. For the
                         same reason a preset overrides .stellartomlrc.json.
                         An unknown name lists the available presets and exits
                         with code 2.

EXIT CODES
  0  no errors     1  errors found     2  bad usage, unmatched glob, or I/O failure

EXAMPLES
  stellar-toml-lint public/.well-known/stellar.toml
  stellar-toml-lint "accounts/*/stellar.toml"
  stellar-toml-lint --domain example.com --strict
  stellar-toml-lint --preset validator public/.well-known/stellar.toml
  stellar-toml-lint -f sarif > results.sarif
  stellar-toml-lint --graph mermaid > diagram.mmd
  stellar-toml-lint --graph dot --graph-contracts > diagram.dot
  stellar-toml-lint --policy policy.yaml public/.well-known/stellar.toml
  stellar-toml-lint public/.well-known/stellar.toml --check-network \\\\
    --mock-fixtures ./test/fixtures/network
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

  const runLint = async (cli: Cli, color: boolean): Promise<number> => {
    if (cli.lsp) {
      // The framed stdio server: diagnostics, quick fixes, and hover. It used to
      // be `lspMain()`, which registered a stdin listener and then let `main()`
      // fall through to `process.exit` — so `--lsp` printed nothing and exited
      // before a client could send a single message.
      await runLspServer();
      return 0;
    }

    const results: { name: string; result: LintResult }[] = [];
    // Project defaults from .stellartomlrc.json, overridden by any CLI flag.
    let strict = cli.strict;
    let maxWarnings = cli.maxWarnings;

    try {
      // Fixture mode replaces the transport for every network-bound check, so a
      // hermetic run can never reach the internet by accident.
      const fetchImpl =
        cli.mockFixtures !== undefined ? createFixtureFetch(cli.mockFixtures) : fetch;

      if (cli.domain && cli.paths.length === 0) {
        const config = await loadConfig(process.cwd());
        strict = strict || config.strict;
        maxWarnings ??= config.maxWarnings;
        results.push({
          name: cli.domain,
          result: await lintDomain(
            cli.domain,
            {
              strict,
              rules: { ...config.rules, ...cli.rules },
              checkNetwork: cli.checkNetwork,
            },
            fetchImpl,
          ),
        });
      } else {
        const paths = await expandInputs(cli.paths.length > 0 ? cli.paths : [DEFAULT_PATH]);
        for (const path of paths) {
          const config = await loadConfig(path === '-' ? process.cwd() : dirname(resolve(path)));
          const fileStrict = cli.strict || config.strict;
          strict = strict || config.strict;
          maxWarnings ??= config.maxWarnings;
          const rules = { ...config.rules, ...cli.rules };

          const source = path === '-' ? await readStdin() : await readFile(path, 'utf8');
          let fileResult = lint(source, {
            strict: fileStrict,
            rules,
            checkNetwork: cli.checkNetwork,
            ...(cli.domain ? { domain: cli.domain } : {}),
          });

          if (
            fileResult.parsed &&
            (cli.checkNetwork || cli.checkContracts || cli.domain !== undefined)
          ) {
            const networkDiagnostics: Diagnostic[] = [];

            // SEP-6 is reachable under either flag: `--domain` already means the
            // file was fetched from a live host, and `--check-network` is the
            // explicit opt-in for a local file.
            if (cli.checkNetwork || cli.domain !== undefined) {
              networkDiagnostics.push(
                ...(await checkSep6(fileResult.parsed, fetchImpl, { rules: cli.rules })),
              );
            }

            if (cli.verifySep10 && cli.checkNetwork) {
              const webAuthEndpoint = (fileResult.parsed as Record<string, unknown>)
                .WEB_AUTH_ENDPOINT;
              if (typeof webAuthEndpoint === 'string') {
                const signingKey =
                  typeof (fileResult.parsed as Record<string, unknown>).SIGNING_KEY === 'string'
                    ? ((fileResult.parsed as Record<string, unknown>).SIGNING_KEY as string)
                    : '';
                networkDiagnostics.push(
                  ...(await checkSep10Replay(signingKey, new URL(webAuthEndpoint).origin, {
                    rules: cli.rules,
                    fetchImpl: fetch,
                  })),
                );
              }
            }
            if (cli.checkNetwork) {
              networkDiagnostics.push(
                ...(await checkHorizon(fileResult.parsed, fetchImpl, { rules: cli.rules })),
                ...(await checkNetworkAccounts(fileResult.parsed, fetchImpl)),
                ...(await checkDisplayDecimals(fileResult.parsed, fetchImpl, { rules: cli.rules })),
                ...(await checkSep38(fileResult.parsed, fetchImpl, { rules: cli.rules })),
                ...(await checkRegulatedIssuerFlags(fileResult.parsed, fetchImpl, {
                  rules: cli.rules,
                })),
                ...(await checkCorsPreflight(fileResult.parsed, fetchImpl, { rules: cli.rules })),
              );
            }

            if (cli.checkNetwork) {
              networkDiagnostics.push(
                ...(await checkCollateralGovernance(fileResult.parsed, {
                  rules: cli.rules,
                  fetchImpl: fetch,
                })),
              );
            }

            if (cli.checkContracts) {
              networkDiagnostics.push(
                ...(await checkContracts(fileResult.parsed, fetchImpl, {
                  rules: cli.rules,
                  ...(cli.sorobanRpc !== undefined ? { rpcUrl: cli.sorobanRpc } : {}),
                })),
              );
            }

            if (networkDiagnostics.length > 0) {
              fileResult = finalize(
                [...fileResult.diagnostics, ...networkDiagnostics],
                { strict: fileStrict },
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

    const firstResult = results[0]?.result;

    if (cli.badgeSvg && firstResult) {
      await writeFile(cli.badgeSvg, generateBadgeSvg(firstResult));
    }
    if (cli.badgeJson && firstResult) {
      await writeFile(
        cli.badgeJson,
        JSON.stringify(generateShieldsEndpoint(firstResult), null, 2) + '\n',
      );
    }
    if (cli.exportApConfig && firstResult?.parsed) {
      const config = generateAnchorPlatformConfig(firstResult.parsed);
      process.stdout.write(formatAnchorPlatformYaml(config));
    }
    if (cli.generateOpenapi && firstResult?.parsed) {
      const spec = generateOpenApiSpec(firstResult.parsed);
      const ext =
        cli.generateOpenapi.endsWith('.yaml') || cli.generateOpenapi.endsWith('.yml')
          ? 'yaml'
          : 'json';
      if (ext === 'yaml') {
        const yamlLines: string[] = [];
        yamlLines.push(`openapi: "${spec.openapi}"`);
        yamlLines.push(`info:`);
        yamlLines.push(`  title: "${spec.info.title}"`);
        yamlLines.push(`  version: "${spec.info.version}"`);
        yamlLines.push(`  description: "${spec.info.description}"`);
        await writeFile(cli.generateOpenapi, yamlLines.join('\n') + '\n');
      } else {
        await writeFile(cli.generateOpenapi, JSON.stringify(spec, null, 2) + '\n');
      }
    }

    if (cli.graph && firstResult?.parsed) {
      const diagram = generateDiagram(firstResult.parsed, {
        format: cli.graph,
        includeContracts: cli.graphIncludeContracts,
        includeValidators: cli.graphIncludeValidators,
        colorByProtocol: cli.graphColorByProtocol,
      });
      process.stdout.write(diagram + '\n');
    }

    // Evaluate enterprise policy
    if (cli.policy && firstResult?.parsed) {
      const policy = await loadPolicy(cli.policy);
      const validation = validatePolicy(policy);
      if (!validation.valid) {
        process.stderr.write(`Policy validation failed:\n${validation.errors.join('\n')}\n`);
        return 2;
      }
      const sourcePath = cli.paths[0] ?? DEFAULT_PATH;
      const source = sourcePath === '-' ? await readStdin() : await readFile(sourcePath, 'utf8');
      const policyDiagnostics = evaluatePolicy(policy, firstResult.parsed, source);

      // Convert policy diagnostics to standard diagnostics
      const convertedDiagnostics: Diagnostic[] = policyDiagnostics.map((pd) => ({
        rule: `policy/${pd.rule}`,
        severity: pd.severity,
        category: 'policy',
        message: pd.message,
        path: pd.path,
        position: pd.position,
        suggestion: pd.suggestion,
        helpUri: undefined,
      }));

      if (convertedDiagnostics.length > 0 && results[0]) {
        const finalized = finalize(
          [...firstResult.diagnostics, ...convertedDiagnostics],
          { strict: cli.strict },
          firstResult.parsed,
        );
        results[0] = { name: results[0].name, result: finalized };
      }
    }

    if (cli.interactive && cli.format !== 'text') {
      process.stderr.write(
        `--interactive draws its own view of the findings; drop --format ${cli.format}.\n\nRun with --help for usage.\n`,
      );
      return 2;
    }

    // A dashboard written into a pipe or a file would corrupt the output it is
    // meant to replace, so anything that is not a terminal keeps the text report.
    const dashboard = cli.interactive === true && supportsDashboard(process.stdout);

    if (!cli.exportApConfig && dashboard) {
      await runDashboard(
        results,
        { stdin: process.stdin, stdout: process.stdout },
        { color, ...(cli.quiet ? { filter: 'error' as const } : {}) },
      );
    } else if (!cli.exportApConfig) {
      for (const { name, result } of results) {
        const filtered = cli.quiet
          ? { ...result, diagnostics: result.diagnostics.filter((d) => d.severity === 'error') }
          : result;

        process.stdout.write(render(filtered, name, cli, color));
      }

      // One line closing a multi-file run, so a CI log answers "did the whole
      // set pass?" without anyone counting per-file blocks. Only the text
      // reporter gets it: appending prose to JSON, SARIF, or XML would break the
      // parsers those formats exist for.
      if (results.length > 1 && cli.format === 'text') {
        process.stdout.write(formatSummary(results, { color }));
      }
    }

    if (cli.webhookSlack !== undefined || cli.webhookDiscord !== undefined) {
      const deliveries = await deliverWebhooks(results, {
        ...(cli.webhookSlack !== undefined ? { slack: cli.webhookSlack } : {}),
        ...(cli.webhookDiscord !== undefined ? { discord: cli.webhookDiscord } : {}),
      });

      for (const delivery of deliveries) {
        if (delivery.ok) continue;
        // The exit code stays tied to the diagnostics: a broken alert endpoint
        // must not turn a clean file into a failing build.
        process.stderr.write(
          `Warning: ${delivery.channel} webhook failed after ${delivery.attempts} attempt(s)${
            delivery.error === undefined ? '' : `: ${delivery.error}`
          }\n`,
        );
      }
    }

    let healthCheckFailed = false;
    if (cli.healthCheck) {
      for (const { result } of results) {
        const hcResults = await runHealthCheck(result);
        if (hcResults.length > 0) {
          process.stdout.write(formatHealthCheckTable(hcResults, color));
          if (hcResults.some((r) => r.error || (r.statusCode && r.statusCode >= 400))) {
            healthCheckFailed = true;
          }
        }
      }
    }

    const lintPassed = verdict(results, { strict, maxWarnings });
    return lintPassed && !healthCheckFailed ? 0 : 1;
  };

  const paths = cli.paths.length > 0 ? cli.paths : [DEFAULT_PATH];
  if (cli.watch) {
    return watchFiles(cli.domain ? [] : paths, cli, color, runLint);
  }
  return runLint(cli, color);
}

/**
 * Resolves the positional arguments to a concrete list of paths.
 *
 * Anything holding glob magic is expanded here rather than by the shell, so
 * the same quoted argument works under sh, PowerShell, and CMD — the first two
 * agree on nothing else about quoting. A pattern that matches nothing is a
 * usage mistake rather than a lint result, so it throws and `main` reports it
 * with the exit code 2 every other bad-usage path already uses.
 */
async function expandInputs(inputs: string[]): Promise<string[]> {
  const paths: string[] = [];

  for (const input of inputs) {
    if (input === '-' || !hasMagic(input)) {
      paths.push(input);
      continue;
    }

    const matches = await expandGlob(input);
    if (matches.length === 0) {
      throw new Error(
        `No files matched "${input}". Patterns are expanded by the linter, not the shell — check the path, and quote the pattern so it arrives intact.`,
      );
    }
    paths.push(...matches);
  }

  return [...new Set(paths)];
}

function render(result: LintResult, name: string, cli: Cli, color: boolean): string {
  switch (cli.format) {
    case 'json':
      return formatJson(result, name);
    case 'ndjson':
      return formatNdjson(result, name);
    case 'sarif':
      return formatSarif(result, name, VERSION);
    case 'github':
      return formatGithub(result, name);
    case 'junit':
      return formatJunit(result, name);
    case 'html':
      return formatHtml(result, name);
    case 'checkstyle':
      return formatCheckstyle(result, name, VERSION);
    case 'markdown':
      return formatMarkdown(result, name);
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
function verdict(
  results: { result: LintResult }[],
  options: { strict: boolean; maxWarnings?: number },
): boolean {
  const totals = results.reduce(
    (acc, { result }) => {
      acc.error += result.counts.error;
      acc.warning += result.counts.warning;
      return acc;
    },
    { error: 0, warning: 0 },
  );

  if (totals.error > 0) return false;
  if (options.strict && totals.warning > 0) return false;
  if (options.maxWarnings !== undefined && totals.warning > options.maxWarnings) return false;
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
    verifySep10: false,
    checkContracts: false,
    graphIncludeContracts: false,
    graphIncludeValidators: false,
    graphColorByProtocol: false,
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

      case '--json-schema':
        process.stdout.write(`${JSON.stringify(getTomlJsonSchema(), null, 2)}\n`);
        return 'handled';

      case '--completion': {
        const shell = requireValue(argv, ++i, arg);
        if (!isCompletionShell(shell)) {
          throw new Error(`Unknown shell "${shell}". Expected bash, zsh, or fish.`);
        }
        process.stdout.write(generateCompletion(shell, allRules));
        return 'handled';
      }

      case '--lsp':
        cli.lsp = true;
        break;

      case '-d':
      case '--domain':
        cli.domain = requireValue(argv, ++i, arg);
        break;

      case '-f':
      case '--format': {
        const value = requireValue(argv, ++i, arg);
        if (!isFormat(value)) {
          throw new Error(
            `Unknown format "${value}". Expected text, json, ndjson, sarif, github, junit, html, checkstyle, or markdown.`,
          );
        }
        cli.format = value;
        break;
      }

      case '--strict':
        cli.strict = true;
        break;

      case '-w':
      case '--watch':
        cli.watch = true;
        break;

      case '-i':
      case '--interactive':
        cli.interactive = true;
        break;

      case '--no-suggestions':
        cli.noSuggestions = true;
        break;

      case '--health-check':
        cli.healthCheck = true;
        break;

      case '--check-network':
        cli.checkNetwork = true;
        break;

      case '--verify-sep10':
        cli.verifySep10 = true;
        break;

      case '--check-contracts':
        cli.checkContracts = true;
        break;

      case '--soroban-rpc':
        cli.sorobanRpc = requireValue(argv, ++i, arg);
        break;

      case '--mock-fixtures':
        cli.mockFixtures = requireValue(argv, ++i, arg);
        break;

      case '--webhook-slack':
      case '--webhook-discord': {
        const value = requireValue(argv, ++i, arg);
        if (!isSupportedWebhookUrl(value)) {
          throw new Error(`${arg} expects an http or https URL.`);
        }
        if (arg === '--webhook-slack') cli.webhookSlack = value;
        else cli.webhookDiscord = value;
        break;
      }

      case '--badge-svg':
        cli.badgeSvg = requireValue(argv, ++i, arg);
        break;

      case '--badge-json':
        cli.badgeJson = requireValue(argv, ++i, arg);
        break;

      case '--export-ap-config':
        cli.exportApConfig = true;
        break;

      case '--generate-openapi':
        cli.generateOpenapi = requireValue(argv, ++i, arg);
        break;

      case '--graph': {
        const value = requireValue(argv, ++i, arg);
        if (value !== 'mermaid' && value !== 'dot') {
          throw new Error(`Unknown graph format "${value}". Expected mermaid or dot.`);
        }
        cli.graph = value;
        break;
      }

      case '--graph-contracts':
        cli.graphIncludeContracts = true;
        break;

      case '--graph-validators':
        cli.graphIncludeValidators = true;
        break;

      case '--graph-color':
        cli.graphColorByProtocol = true;
        break;

      case '--policy':
        cli.policy = requireValue(argv, ++i, arg);
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

      case '--preset': {
        const value = requireValue(argv, ++i, arg);
        // Resolved here rather than stored as a name, so an unknown preset is
        // the same exit-2 usage error an unknown rule id is.
        cli.preset = resolvePreset(value).name;
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

  if (cli.preset !== undefined) {
    // The bundle is laid down *after* the loop, so a rule flag wins whether it
    // was typed before or after `--preset`: the preset is a baseline, and the
    // command line is the intent for this run.
    cli.rules = { ...PRESETS[cli.preset].rules, ...cli.rules };
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
    value === 'ndjson' ||
    value === 'sarif' ||
    value === 'github' ||
    value === 'junit' ||
    value === 'html' ||
    value === 'checkstyle' ||
    value === 'markdown'
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
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error: unknown) => {
    process.stderr.write(`Unexpected failure: ${message(error)}\n`);
    process.exitCode = 2;
  });

async function watchFiles(
  paths: string[],
  cli: Cli,
  color: boolean,
  runLint: (cli: Cli, color: boolean) => Promise<number>,
) {
  await runLint(cli, color);

  for (const path of paths) {
    if (path === '-') continue; // can't watch stdin
    let timer: NodeJS.Timeout | null = null;
    try {
      const watcher = watch(path, () => {
        if (timer) clearTimeout(timer);
        timer = setTimeout(async () => {
          timer = null;
          if (process.stdout.isTTY) process.stdout.write('\x1Bc');
          await runLint(cli, color);
        }, 100);
      });
      watcher.on('error', (error) => {
        process.stderr.write(`Warning: Watcher error on ${path}: ${error.message}\n`);
      });
    } catch (error) {
      const e = error as Error;
      process.stderr.write(`Warning: Could not watch ${path}: ${e.message}\n`);
    }
  }

  // Wait indefinitely, exit on SIGINT
  return new Promise<number>(() => {
    process.on('SIGINT', () => process.exit(0));
  });
}
