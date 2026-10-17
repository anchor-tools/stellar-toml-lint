/**
 * Command-line entry point for the per-rule regression suite (issue #377).
 *
 *     npm run bench:regression                  measure, enforce, exit 1 on failure
 *     npm run bench:regression -- --update      accept the current timings as baseline
 *     npm run bench:regression -- --json        machine-readable report on stdout
 *     npm run bench:regression -- --filter sep  only rules whose id contains "sep"
 *
 * Exit codes follow the rest of the toolchain: 0 is clean, 1 means a rule blew
 * its latency budget, regressed against the committed baseline, or a regex
 * audit failed, and 2 is a usage problem. The measurement, comparison, and
 * regex audit all live in `regression-harness.ts`, which has no top-level
 * effects so the test suite can drive each piece on its own.
 */
import { relative } from 'node:path';
import {
  BASELINE_PATH,
  DEFAULT_BUDGET_MS,
  DEFAULT_TOLERANCE,
  REPO_ROOT,
  SYNTHETIC_NODES,
  auditRegexes,
  judge,
  loadBaseline,
  measureRules,
  syntheticDocument,
  writeBaseline,
  type RegexProblem,
  type Verdict,
} from './regression-harness.js';
import { allRules } from '../src/rules/index.js';

const USAGE = `Usage: npm run bench:regression [-- <options>]

Benchmarks every lint rule individually against a synthetic stellar.toml,
enforces a per-rule latency budget, and compares each measurement against the
committed baseline.

Options:
  --update, --update-baseline  Rewrite the baseline from this run.
  --json                       Emit the report as JSON instead of a table.
  --filter <text>              Only rules whose id contains <text>.
  --nodes <n>                  Synthetic repeated tables (default ${SYNTHETIC_NODES}).
  --budget <ms>                Per-rule latency budget (default ${DEFAULT_BUDGET_MS}).
  --tolerance <fraction>       Regression threshold (default ${DEFAULT_TOLERANCE}).
  -h, --help                   Print this message.
`;

interface Options {
  update: boolean;
  json: boolean;
  filter: string | undefined;
  nodes: number;
  budgetMs: number;
  tolerance: number;
}

/** Reads a numeric option, rejecting the typo rather than defaulting past it. */
function numericValue(argv: readonly string[], index: number, flag: string): number {
  const raw = argv[index];
  const value = Number(raw);
  if (raw === undefined || !Number.isFinite(value) || value <= 0) {
    throw new Error(`${flag} needs a positive number, got ${raw ?? '(nothing)'}`);
  }
  return value;
}

function parseArgs(argv: readonly string[]): Options | 'help' {
  const options: Options = {
    update: false,
    json: false,
    filter: undefined,
    nodes: SYNTHETIC_NODES,
    budgetMs: DEFAULT_BUDGET_MS,
    tolerance: DEFAULT_TOLERANCE,
  };

  for (let i = 0; i < argv.length; i++) {
    switch (argv[i]) {
      case '-h':
      case '--help':
        return 'help';
      case '--update':
      case '--update-baseline':
        options.update = true;
        break;
      case '--json':
        options.json = true;
        break;
      case '--filter': {
        const value = argv[++i];
        if (value === undefined) throw new Error('--filter needs a value');
        options.filter = value;
        break;
      }
      case '--nodes':
        options.nodes = numericValue(argv, ++i, '--nodes');
        break;
      case '--budget':
        options.budgetMs = numericValue(argv, ++i, '--budget');
        break;
      case '--tolerance':
        options.tolerance = numericValue(argv, ++i, '--tolerance');
        break;
      default:
        throw new Error(`unknown option ${String(argv[i])}`);
    }
  }

  return options;
}

function formatMs(ms: number): string {
  if (!Number.isFinite(ms)) return 'n/a';
  return ms < 1 ? `${(ms * 1000).toFixed(1)}µs` : `${ms.toFixed(3)}ms`;
}

function formatChange(verdict: Verdict): string {
  if (verdict.changeFraction === undefined) return verdict.isNew ? 'new' : '';
  const sign = verdict.changeFraction >= 0 ? '+' : '';
  return `${sign}${(verdict.changeFraction * 100).toFixed(1)}%`;
}

function reportText(
  verdicts: readonly Verdict[],
  regexProblems: readonly RegexProblem[],
  options: Options,
): void {
  const write = (line: string): void => {
    process.stdout.write(`${line}\n`);
  };

  write('='.repeat(84));
  write('stellar-toml-lint per-rule regression suite');
  write('='.repeat(84));
  write('');

  const measured = verdicts.filter((verdict) => Number.isFinite(verdict.timing.meanMs));
  const slowest = [...measured].sort((a, b) => b.timing.meanMs - a.timing.meanMs);

  write('Ten slowest rules:');
  for (const verdict of slowest.slice(0, 10)) {
    write(
      `  ${formatMs(verdict.timing.meanMs).padStart(9)}  ${formatChange(verdict).padStart(8)}  ` +
        `${verdict.timing.rule.padEnd(50)} ${String(verdict.timing.diagnostics).padStart(5)} diag`,
    );
  }

  const unmeasured = verdicts.filter((verdict) => !Number.isFinite(verdict.timing.meanMs));
  const overBudget = verdicts.filter((verdict) => verdict.overBudget);
  const regressed = verdicts.filter((verdict) => verdict.regressed);
  const newRules = verdicts.filter((verdict) => verdict.isNew);

  if (newRules.length > 0) {
    write('');
    write(`${newRules.length} rule(s) have no baseline yet (run with --update to record them):`);
    for (const verdict of newRules) write(`  ${verdict.timing.rule}`);
  }

  if (unmeasured.length > 0) {
    write('');
    write(`${unmeasured.length} rule(s) produced no samples and were not judged:`);
    for (const verdict of unmeasured) write(`  ${verdict.timing.rule}`);
  }

  if (overBudget.length > 0) {
    write('');
    write(`FAIL: ${overBudget.length} rule(s) over budget:`);
    for (const verdict of overBudget) {
      write(
        `  ${verdict.timing.rule} — ${formatMs(verdict.timing.meanMs)} ` +
          `(budget ${verdict.budgetMs}ms)`,
      );
    }
  }

  if (regressed.length > 0) {
    write('');
    write(`FAIL: ${regressed.length} rule(s) slower than baseline:`);
    for (const verdict of regressed) {
      write(
        `  ${verdict.timing.rule} — ${formatMs(verdict.baselineMs ?? Number.NaN)} → ` +
          `${formatMs(verdict.timing.meanMs)} (${formatChange(verdict)})`,
      );
    }
  }

  if (regexProblems.length > 0) {
    write('');
    write(`FAIL: ${regexProblems.length} regex problem(s):`);
    for (const problem of regexProblems) {
      write(`  ${problem.file}:${problem.line} /${problem.pattern}/`);
      write(`    [${problem.kind}] ${problem.detail}`);
    }
  }

  const total = measured.reduce((sum, verdict) => sum + verdict.timing.meanMs, 0);
  write('');
  write('-'.repeat(84));
  write(
    `${measured.length} rules measured, ${formatMs(total)} total; ` +
      `budget ${options.budgetMs}ms/rule, tolerance ${(options.tolerance * 100).toFixed(0)}%`,
  );

  if (overBudget.length === 0 && regressed.length === 0 && regexProblems.length === 0) {
    write('No regressions.');
  }
}

async function main(): Promise<number> {
  let options: Options | 'help';
  try {
    options = parseArgs(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n\n${USAGE}`);
    return 2;
  }

  if (options === 'help') {
    process.stdout.write(USAGE);
    return 0;
  }

  // A `const` binding so the narrowing survives into the closure below.
  const resolved: Options = options;
  const filter = resolved.filter;
  const rules =
    filter === undefined ? allRules : allRules.filter((rule) => rule.id.includes(filter));

  if (rules.length === 0) {
    process.stderr.write(`no rules match --filter ${filter ?? ''}\n`);
    return 2;
  }

  const source = syntheticDocument(options.nodes);
  const measurement = await measureRules(rules, source);

  // The regex audit runs on every invocation, including `--update`: a baseline
  // refresh must never launder a catastrophic matcher into the committed
  // numbers.
  const regexProblems = auditRegexes();

  if (options.update) {
    const baseline = writeBaseline(measurement, options.nodes);
    process.stdout.write(
      `Wrote ${Object.keys(baseline.rules).length} rule timings to ` +
        `${relative(REPO_ROOT, BASELINE_PATH)} (node ${baseline.node}).\n`,
    );
    if (regexProblems.length === 0) return 0;
    reportText(
      judge(measurement, undefined, options.budgetMs, options.tolerance),
      regexProblems,
      options,
    );
    return 1;
  }

  const verdicts = judge(measurement, loadBaseline(), options.budgetMs, options.tolerance);

  if (options.json) {
    process.stdout.write(
      `${JSON.stringify(
        {
          nodes: options.nodes,
          node: process.version,
          calibrationMs: measurement.calibrationMs,
          verdicts,
          regexProblems,
        },
        null,
        2,
      )}\n`,
    );
  } else {
    reportText(verdicts, regexProblems, options);
  }

  const failed =
    verdicts.some((verdict) => verdict.overBudget || verdict.regressed) || regexProblems.length > 0;
  return failed ? 1 : 0;
}

// `process.exitCode` rather than `process.exit()`: the JSON report is large
// enough that writing it to a pipe does not complete synchronously, and
// `process.exit` discards whatever is still buffered. Setting the code and
// letting the event loop drain is what makes `--json | jq` produce whole JSON.
process.exitCode = await main().catch((error: unknown) => {
  process.stderr.write(
    `bench:regression: ${error instanceof Error ? error.stack : String(error)}\n`,
  );
  return 2;
});
