/**
 * Command-line entry point for the corpus harness.
 *
 *     npm run corpus                 compare against committed snapshots
 *     npm run corpus:update          rewrite them from this run's fetch
 *     npm run corpus -- --filter lobstr-co --offline
 *
 * Exit codes follow the rest of the toolchain: 0 is clean, 1 means the linter's
 * output changed and needs a human (or `corpus:update`), 2 is a usage or
 * catalogue problem. Unreachable hosts are reported but never change the code.
 */
import { appendFile } from 'node:fs/promises';
import { renderMarkdown, renderReport, runCorpus } from './harness.js';

const USAGE = `Usage: npm run corpus [-- <options>]

Compares lint() against every stellar.toml in the catalogue and prints a
reviewable diff when the linter's behaviour has changed.

Options:
  --update            rewrite the committed snapshots from this run's fetch
  --refresh           ignore the cache when fetching (still updates the cache)
  --offline           never touch the network; use the cache at any age
  --filter <name>     only this catalogue entry; repeatable
  --timeout <ms>      per-request timeout (default 15000)
  --ttl <hours>       cache freshness window (default 24)
  -h, --help          show this message

Exit codes:
  0  output matches the snapshots (or the hosts were unreachable)
  1  output differs — review the diff, or rerun with --update
  2  bad usage or an unreadable catalogue
`;

interface CliOptions {
  help: boolean;
  update: boolean;
  refresh: boolean;
  offline: boolean;
  filter: string[];
  timeoutMs?: number;
  ttlHours?: number;
}

function fail(reason: string): never {
  process.stderr.write(`corpus: ${reason}\n\n${USAGE}`);
  process.exit(2);
}

function positiveNumber(flag: string, raw: string | undefined): number {
  const value = raw === undefined ? Number.NaN : Number(raw);
  if (!Number.isFinite(value) || value <= 0) {
    fail(`${flag} expects a positive number, got ${raw ?? '(nothing)'}`);
  }
  return value;
}

function parseArgs(argv: string[]): CliOptions {
  const options: CliOptions = {
    help: false,
    update: false,
    refresh: false,
    offline: false,
    filter: [],
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === undefined) continue;

    switch (arg) {
      case '-h':
      case '--help':
        options.help = true;
        break;
      case '--update':
        options.update = true;
        break;
      case '--refresh':
        options.refresh = true;
        break;
      case '--offline':
        options.offline = true;
        break;
      case '--filter': {
        const value = argv[++i];
        if (value === undefined) fail('--filter expects an entry name');
        options.filter.push(value);
        break;
      }
      case '--timeout': {
        options.timeoutMs = positiveNumber('--timeout', argv[++i]);
        break;
      }
      case '--ttl': {
        options.ttlHours = positiveNumber('--ttl', argv[++i]);
        break;
      }
      default:
        fail(`unknown option ${arg}`);
    }
  }

  if (options.update && options.offline) {
    fail('--update needs the network; it cannot run with --offline');
  }

  return options;
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    process.stdout.write(USAGE);
    return;
  }

  try {
    const report = await runCorpus({
      filter: options.filter,
      update: options.update,
      refresh: options.refresh,
      offline: options.offline,
      timeoutMs: options.timeoutMs,
      ttlHours: options.ttlHours,
    });

    process.stdout.write(renderReport(report));

    const summaryPath = process.env.GITHUB_STEP_SUMMARY;
    if (summaryPath) {
      // A full disk must not turn a green run red.
      await appendFile(summaryPath, renderMarkdown(report), 'utf8').catch((error: unknown) => {
        process.stderr.write(`corpus: could not write step summary: ${String(error)}\n`);
      });
    }

    process.exit(report.needsReview ? 1 : 0);
  } catch (error) {
    process.stderr.write(`corpus: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(2);
  }
}

await main();
