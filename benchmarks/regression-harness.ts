/**
 * Per-rule performance regression harness (issue #377).
 *
 * `benchmarks/runner.ts` measures the linter end to end, which answers "is the
 * tool fast enough?" but not "which rule made it slower?". With 80+ rules
 * sharing one pass over the document, a rule that quietly acquired a quadratic
 * regex or a synchronous `statSync` adds a few milliseconds to a total that is
 * already tens of milliseconds — invisible in the aggregate, and paid by every
 * pipeline that runs this tool on every push.
 *
 * So this suite benchmarks each rule *individually* against one large synthetic
 * document, holds each to a per-rule latency budget, and compares every
 * measurement against a committed baseline. Three failure modes, three checks:
 *
 * - **A new rule that is slow from the start** — caught by the budget
 *   ({@link DEFAULT_BUDGET_MS}), which needs no history to be useful.
 * - **An existing rule that got slower** — caught by comparing to
 *   `benchmarks/baselines/rule-latency.json` and flagging a rise over
 *   {@link DEFAULT_TOLERANCE}.
 * - **A matcher that is fast on normal input and catastrophic on hostile
 *   input** — caught by {@link auditRegexes}, which screens every URL and key
 *   validation regex in `src/` statically with the ReDoS detector from issue
 *   #380 and then *times* the worst ones against adversarial strings. A
 *   timing-only check would miss these entirely: the whole point of
 *   catastrophic backtracking is that it does not show up until the input is
 *   chosen to trigger it.
 *
 * On measurement noise: CI runners are shared and their timings are not
 * reproducible, so a bare "20% slower than last time" gate would fail builds at
 * random. Two guards make it usable. A regression must exceed both the
 * percentage tolerance *and* {@link NOISE_FLOOR_MS} in absolute terms, so a
 * rule that moved from 4µs to 6µs is ignored while one that moved from 0.4ms to
 * 0.6ms is not; and the baseline records the statistical error of each
 * measurement, so a comparison against a baseline that was itself noisy is
 * widened rather than trusted.
 *
 * This module holds the measurement, the audit, and the comparison, with no
 * top-level effects, so the test suite can exercise each piece directly.
 * `regression-suite.ts` is the command-line entry that drives it.
 */
import { Bench } from 'tinybench';
import type { Statistics, Task } from 'tinybench';
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import type { Position, Rule, RuleContext } from '../src/types.js';
import { parseCst, firstError } from '../src/cst/parser.js';
import { evaluateDocument } from '../src/cst/visitor.js';
import { SourceIndex } from '../src/source-index.js';
import { analyzeRegex, extractRegexLiterals } from '../src/rules/redos-detector.js';

const here = dirname(fileURLToPath(import.meta.url));

/** Repository root, used to label file paths in the report. */
export const REPO_ROOT = join(here, '..');
const root = REPO_ROOT;
const srcDir = join(root, 'src');
/** Where the committed per-rule timings live. */
export const BASELINE_PATH = join(here, 'baselines', 'rule-latency.json');

/** Synthetic nodes of each repeated kind. The issue asks for 1,000. */
export const SYNTHETIC_NODES = 1_000;

/** Latency budget one rule may spend on the synthetic document, in ms. */
export const DEFAULT_BUDGET_MS = 0.5;

/**
 * Per-rule allowances for the handful of rules that walk the whole document.
 *
 * Two different problems need the same short list, so they share one table.
 *
 * **Budget.** A single flat budget across 250 rules compares two kinds of work:
 * most rules read a handful of named keys and finish in tens of nanoseconds,
 * while a few walk *every string in the document* looking for a shape — an
 * `http://` URL, an untrimmed value, a `web+stellar:` URI. On the 1,000-node
 * synthetic document that is roughly 25,000 string visits, and no amount of
 * optimisation brings it under half a millisecond. Raising the global budget
 * would lose the gate for the other 245 rules, so these are named instead.
 *
 * **Tolerance.** These are also the rules whose timings move most between
 * processes. Measured across repeated runs on an idle machine, the heaviest of
 * them vary by about 26% run to run even after warm-up, because whether V8
 * inlines a 25,000-iteration walk is a decision made once per process and not
 * always the same way. Within a single run the sampling error is under 6%, so
 * the variance is the compiler's, not the sampler's — and a 20% gate against a
 * baseline recorded in a *different* process therefore fails at random. They
 * get 50%, which still catches the doubling that a quadratic regression
 * produces.
 *
 * Adding a rule here should be a conscious decision in review. Making a rule
 * cheap enough to remove from this list is always the better change.
 */
export interface RuleAllowance {
  /** Latency budget for this rule, in milliseconds. */
  budgetMs: number;
  /** Fractional rise over baseline this rule may show without failing. */
  tolerance: number;
  /** Why this rule needs an allowance. */
  reason: string;
}

export const RULE_ALLOWANCES: Readonly<Record<string, RuleAllowance>> = {
  'general/insecure-http-url': {
    budgetMs: 4,
    tolerance: 0.5,
    reason: 'scans every string value in the document for an http:// prefix',
  },
  'general/untrimmed-string-value': {
    budgetMs: 4,
    tolerance: 0.5,
    reason: 'scans every string value for leading or trailing whitespace',
  },
  'currencies/issuer-or-contract': {
    budgetMs: 4,
    tolerance: 0.5,
    reason: 'validates the issuer/contract pairing of all 1,000 CURRENCIES entries',
  },
  'validators/public-key': {
    budgetMs: 4,
    tolerance: 0.5,
    reason: 'decodes and checksums the public key of all 1,000 VALIDATORS entries',
  },
  'validators/invalid-history-url': {
    budgetMs: 4,
    tolerance: 0.5,
    reason: 'parses the HISTORY URL of all 1,000 VALIDATORS entries',
  },
  // These three each re-walk the whole document for `web+stellar:` URIs,
  // because `checkSep7Uris` returns every finding and each rule filters for
  // its own. Collapsing them into one pass would remove all three entries.
  'sep7/invalid-uri-scheme': {
    budgetMs: 4,
    tolerance: 0.5,
    reason: 'walks the whole document for web+stellar: URIs',
  },
  'sep7/invalid-signature': {
    budgetMs: 4,
    tolerance: 0.5,
    reason: 'walks the whole document for web+stellar: URIs',
  },
  'sep7/unsupported-replacement-field': {
    budgetMs: 4,
    tolerance: 0.5,
    reason: 'walks the whole document for web+stellar: URIs',
  },
  'currencies/urls': {
    budgetMs: 2,
    tolerance: 0.5,
    reason: 'validates the URL fields of all 1,000 CURRENCIES entries',
  },
  'validators/alias': {
    budgetMs: 2,
    tolerance: 0.5,
    reason: 'validates the ALIAS format of all 1,000 VALIDATORS entries',
  },
  // The two style rules each walk every line of the synthetic document (822 KB,
  // 26k lines) to locate structural lines, and each does so independently
  // because a rule may not rely on another having run. Sharing one scan through
  // a per-document cache would remove both entries.
  'style/mixed-indentation': {
    budgetMs: 25,
    tolerance: 0.5,
    reason: 'walks every line of the 822 KB synthetic document for mixed tab/space indents',
  },
  'style/misaligned-table-key': {
    budgetMs: 25,
    tolerance: 0.5,
    reason: 'walks every line of the 822 KB synthetic document comparing sibling indentation',
  },
};

/** Fractional rise over baseline that counts as a regression. */
export const DEFAULT_TOLERANCE = 0.2;

/**
 * Absolute rise a regression must also clear, in milliseconds.
 *
 * Most rules run in single-digit microseconds, where a 20% swing is scheduler
 * noise rather than a code change. Requiring 0.05ms of real movement as well
 * keeps the gate pointed at regressions a user could notice.
 */
export const NOISE_FLOOR_MS = 0.05;

/** Patterns that must stay fast however hostile the input (issue #380). */
const ADVERSARIAL_INPUTS: readonly { label: string; build: (size: number) => string }[] = [
  { label: 'long run of letters', build: (n) => 'a'.repeat(n) },
  { label: 'long run of digits', build: (n) => '1'.repeat(n) },
  { label: 'letters then a rejecting byte', build: (n) => `${'a'.repeat(n)}!` },
  { label: 'whitespace then a rejecting byte', build: (n) => `${' '.repeat(n)}!` },
  { label: 'url-ish prefix then a long tail', build: (n) => `https://${'a'.repeat(n)}` },
  { label: 'dotted tail with no terminator', build: (n) => `a${'.a'.repeat(n / 2)}` },
  { label: 'underscored key with no terminator', build: (n) => `a${'_a'.repeat(n / 2)}!` },
];

/** How long one adversarial match may take before it counts as a hang, in ms. */
export const REGEX_BUDGET_MS = 25;

/** Characters an adversarial probe grows to. */
export const ADVERSARIAL_SIZE = 20_000;

/** Task name used for the calibration workload, kept out of the rule results. */
const CALIBRATION_NAME = '__calibration__';

/**
 * A fixed workload benchmarked alongside the rules to normalise the results.
 *
 * Absolute milliseconds are not comparable between two runs, let alone between
 * a developer's laptop and a shared CI runner: measured here, the *same* rule
 * on the *same* machine varies by 30–50% between consecutive runs as the CPU
 * changes frequency and the cache warms. A committed baseline of raw
 * milliseconds therefore cannot support a 20% gate — it fails at random.
 *
 * So every rule's time is divided by this workload's time from the same run,
 * and the baseline stores that ratio. Machine speed, thermal state, and Node
 * version cancel out of the ratio, leaving the thing we actually want to gate:
 * how much work this rule does relative to a fixed amount of work.
 *
 * The workload itself is deliberately boring — string and array operations in
 * the same shape as a rule's hot path, with a result that is returned so V8
 * cannot eliminate it, and no allocation large enough to drag the GC in.
 */
function calibrationWorkload(): number {
  let total = 0;
  for (let i = 0; i < 2_000; i++) {
    const text = `calibration-${i}-value`;
    if (text.startsWith('calibration')) total += text.length;
    const at = text.lastIndexOf('-');
    total += Number(text.slice(at + 1).length);
    total += text.trim() === text ? 1 : 0;
  }
  return total;
}

/* ------------------------------------------------------------------ *
 * Synthetic document
 * ------------------------------------------------------------------ */

/**
 * A valid-ish `stellar.toml` with `nodes` of every repeated table.
 *
 * Deliberately *valid* rather than broken: a rule that bails on the first
 * malformed value would benchmark as instant while doing none of the work it
 * does in practice. The keys are the real SEP-1 spellings so the rules that
 * look them up actually find something, and the values are distinct per entry
 * so a rule that de-duplicates has a real set to build.
 */
export function syntheticDocument(nodes: number = SYNTHETIC_NODES): string {
  const lines: string[] = [
    'VERSION = "2.7.0"',
    'NETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"',
    'SIGNING_KEY = "GCKFBEIYV2U22IO2BJ4KVJOIP7XPWQGQFKKWXR6DOSJBV7STMAQSMTGG"',
    'HORIZON_URL = "https://horizon.example.com"',
    'FEDERATION_SERVER = "https://federation.example.com"',
    'TRANSFER_SERVER = "https://transfer.example.com"',
    'TRANSFER_SERVER_SEP0024 = "https://transfer.example.com/sep24"',
    'KYC_SERVER = "https://kyc.example.com"',
    'WEB_AUTH_ENDPOINT = "https://auth.example.com/auth"',
    'DIRECT_PAYMENT_SERVER = "https://payment.example.com"',
    'ANCHOR_QUOTE_SERVER = "https://quote.example.com"',
    '',
    '[DOCUMENTATION]',
    'ORG_NAME = "Example Anchor Limited"',
    'ORG_DBA = "Example Anchor"',
    'ORG_URL = "https://example.com"',
    'ORG_LOGO = "https://example.com/logo.png"',
    'ORG_DESCRIPTION = "A synthetic anchor used only to benchmark rule predicates."',
    'ORG_PHYSICAL_ADDRESS = "1 Example Street, Exampleton, EX1 1EX, Exampleland"',
    'ORG_OFFICIAL_EMAIL = "ops@example.com"',
    'ORG_SUPPORT_EMAIL = "support@example.com"',
    'ORG_TWITTER = "exampleanchor"',
    'ORG_GITHUB = "exampleanchor"',
    'ORG_LICENSING_AUTHORITY = "Exampleland Financial Authority"',
    'ORG_LICENSE_TYPE = "Money Services Business"',
    'ORG_LICENSE_NUMBER = "EX-12345"',
    '',
  ];

  // A fixed pool of valid-looking Stellar account ids, cycled so every entry
  // differs without needing 1,000 real keys.
  const accounts = [
    'GCKFBEIYV2U22IO2BJ4KVJOIP7XPWQGQFKKWXR6DOSJBV7STMAQSMTGG',
    'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN',
    'GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H',
    'GAIU5J3XK7K4VJQZ6X5Y3K2M1N0P9Q8R7S6T5U4V3W2X1Y0ZABCDEFG',
  ];
  const account = (i: number): string => accounts[i % accounts.length] as string;

  for (let i = 0; i < nodes; i++) {
    lines.push(
      '[[PRINCIPALS]]',
      `name = "Example Officer ${i}"`,
      `email = "officer${i}@example.com"`,
      `twitter = "officer${i}"`,
      `github = "officer${i}"`,
      '',
      '[[CURRENCIES]]',
      `code = "AST${String(i).padStart(3, '0')}"`,
      `issuer = "${account(i)}"`,
      'status = "live"',
      'display_decimals = 7',
      `name = "Synthetic Asset ${i}"`,
      `desc = "An asset that exists only to give the currency rules something to walk."`,
      'is_asset_anchored = true',
      'anchor_asset_type = "fiat"',
      'anchor_asset = "USD"',
      `image = "https://example.com/assets/ast${i}.png"`,
      `redemption_instructions = "Contact support@example.com to redeem asset ${i}."`,
      '',
      '[[VALIDATORS]]',
      `ALIAS = "example-validator-${i}"`,
      `DISPLAY_NAME = "Example Validator ${i}"`,
      `PUBLIC_KEY = "${account(i + 1)}"`,
      `HOST = "validator-${i}.example.com:11625"`,
      `HISTORY = "https://history.example.com/validator-${i}/"`,
      '',
    );
  }

  return lines.join('\n');
}

/* ------------------------------------------------------------------ *
 * Measurement
 * ------------------------------------------------------------------ */

/** One rule's measured latency on the synthetic document. */
export interface RuleTiming {
  rule: string;
  /** Mean milliseconds per invocation, as measured on this machine. */
  meanMs: number;
  /**
   * {@link meanMs} divided by the calibration workload's time from the same
   * run. This is the comparable number — see {@link calibrationWorkload}.
   */
  units: number;
  /** Relative margin of error of the mean, as a fraction (0.05 = ±5%). */
  rmeFraction: number;
  /** Invocations the sampler completed. */
  samples: number;
  /** Diagnostics the rule produced, so a silently-dead rule is visible. */
  diagnostics: number;
}

/** One measurement run: the rule timings plus the calibration they share. */
export interface Measurement {
  timings: RuleTiming[];
  /** The calibration workload's mean, in milliseconds, for this run. */
  calibrationMs: number;
}

/** The committed baseline file's shape. */
export interface Baseline {
  /** Schema version, so a format change is a loud failure rather than a quiet one. */
  version: 2;
  /** When the baseline was recorded, ISO 8601. */
  recordedAt: string;
  /** Node version it was recorded on, for provenance only — units are portable. */
  node: string;
  /** Synthetic node count the timings correspond to. */
  nodes: number;
  /** The calibration workload's milliseconds when this baseline was recorded. */
  calibrationMs: number;
  /** Rule id -> recorded measurement, in calibration units. */
  rules: Record<string, { units: number; rmeFraction: number }>;
}

/**
 * Builds the context one rule receives, matching what `lint()` constructs.
 *
 * Built once and shared across the benchmarked rules so the measurement covers
 * the rule's own work rather than parsing. `report` accumulates into an array
 * the caller resets between rules; a rule that reports 1,000 diagnostics is
 * doing real work and its array growth is part of its cost.
 */
function buildContext(source: string, sink: { count: number }): RuleContext {
  const document = parseCst(source);
  const syntaxError = firstError(document);
  if (syntaxError !== undefined) {
    throw new Error(`synthetic document does not parse: ${syntaxError.message}`);
  }
  const evaluation = evaluateDocument(document);
  const valueError = evaluation.errors[0];
  if (valueError !== undefined) {
    throw new Error(`synthetic document does not evaluate: ${valueError.message}`);
  }

  const index = new SourceIndex(source, document);
  return {
    doc: evaluation.value,
    cst: document,
    source,
    options: {},
    locate: (path: string): Position | undefined => index.get(path),
    report: () => {
      sink.count++;
    },
  };
}

/** The latency statistics of a finished task, or `undefined` if it has none. */
function statisticsOf(result: Task['result'] | undefined): Statistics | undefined {
  if (result === undefined || result === null) return undefined;
  return 'latency' in result ? result.latency : undefined;
}

/**
 * How long one benchmarked iteration should take, in milliseconds.
 *
 * Each iteration runs the rule in a loop sized to hit this target, so a rule
 * costing 20ns and one costing 2ms are both sampled in comparable chunks. The
 * alternative — letting the sampler run a fixed wall-clock budget per task —
 * sounds simpler and is not: tinybench treats `time` as a *minimum*, so a 20ns
 * rule gets sampled four million times in 120ms. Measured, that put 539MB of
 * sample bookkeeping through the heap for two tasks, and across 250 it turned a
 * 40-second suite into a multi-minute GC thrash.
 */
const BATCH_TARGET_MS = 0.5;

/**
 * Samples taken per rule.
 *
 * Fixed rather than time-derived, so every rule gets the same statistical
 * treatment: 200 samples of ~0.5ms is 100ms per rule, which across 250 rules is
 * a suite that finishes in well under a minute while giving the slow rules far
 * better error bars than a wall-clock budget did (44% relative error, measured,
 * on a 2ms task).
 */
const SAMPLES_PER_RULE = 200;

/** Milliseconds spent estimating one rule's per-call cost before sizing it. */
const PROBE_MS = 8;

/** The per-call cost of `run`, estimated by repeating it for {@link PROBE_MS}. */
function probePerCallMs(run: () => void): number {
  const start = performance.now();
  let calls = 0;
  // An upper bound on calls as well as time: a rule costing nanoseconds would
  // otherwise spin tens of millions of times just to fill the probe window.
  while (calls < 200_000 && performance.now() - start < PROBE_MS) {
    run();
    calls++;
  }
  const elapsed = performance.now() - start;
  return calls === 0 ? elapsed : elapsed / calls;
}

/** Calls per benchmarked iteration, so each iteration lands near the target. */
function batchSizeFor(perCallMs: number): number {
  if (!(perCallMs > 0)) return 1_024;
  return Math.max(1, Math.min(200_000, Math.round(BATCH_TARGET_MS / perCallMs)));
}

/** Benchmarks each rule individually against the synthetic document. */
export async function measureRules(rules: readonly Rule[], source: string): Promise<Measurement> {
  const sink = { count: 0 };
  const ctx = buildContext(source, sink);

  // Warm up every rule before measuring, and record two things while doing it:
  // how many diagnostics it produces (so a silently-dead rule is visible in the
  // report) and whether it throws. The first invocation pays for V8's
  // interpreter tier and for any lazy table a rule builds, neither of which a
  // steady-state run pays per file.
  const diagnosticCounts = new Map<string, number>();
  const broken = new Set<string>();
  for (const rule of rules) {
    sink.count = 0;
    try {
      rule.run(ctx);
    } catch {
      // `lint()` catches rule errors too, so a throwing rule is not fatal here.
      // It is excluded from the benchmark rather than measured: timing an
      // exception path would record the cost of the stack unwind, not the rule.
      broken.add(rule.id);
    }
    diagnosticCounts.set(rule.id, sink.count);
  }

  const measurable = rules.filter((rule) => !broken.has(rule.id));

  // Size each rule's batch from a short probe, before the bench starts, so the
  // sampler itself does no adaptive work.
  const batchSizes = new Map<string, number>();
  for (const rule of measurable) {
    batchSizes.set(rule.id, batchSizeFor(probePerCallMs(() => rule.run(ctx))));
  }
  const calibrationBatch = batchSizeFor(probePerCallMs(() => void calibrationWorkload()));

  // `time: 0` leaves the iteration count as the only limit, which is the point:
  // every task takes exactly SAMPLES_PER_RULE samples.
  const bench = new Bench({
    time: 0,
    iterations: SAMPLES_PER_RULE,
    warmup: true,
    warmupTime: 0,
    warmupIterations: 60,
  });

  // Measured inside the same bench run, interleaved with the rules, so it
  // absorbs the same thermal and scheduling conditions they do.
  bench.add(CALIBRATION_NAME, () => {
    for (let i = 0; i < calibrationBatch; i++) calibrationWorkload();
  });

  for (const rule of measurable) {
    const batch = batchSizes.get(rule.id) ?? 1;
    bench.add(rule.id, () => {
      for (let i = 0; i < batch; i++) rule.run(ctx);
    });
  }

  await bench.run();

  const calibrationTask = bench.tasks.find((task) => task.name === CALIBRATION_NAME);
  const calibrationMs =
    (statisticsOf(calibrationTask?.result)?.mean ?? Number.NaN) / calibrationBatch;

  const measured = new Map<string, RuleTiming>();
  for (const task of bench.tasks) {
    if (task.name === CALIBRATION_NAME) continue;
    // `task.result` is a union: a task that errored or was aborted before it
    // gathered samples carries no statistics. Report those as NaN rather than
    // as a suspiciously fast zero, so the comparison skips them instead of
    // recording a baseline nothing can ever beat.
    const stats = statisticsOf(task.result);
    const batch = batchSizes.get(task.name) ?? 1;
    const meanMs = (stats?.mean ?? Number.NaN) / batch;
    measured.set(task.name, {
      rule: task.name,
      meanMs,
      units: calibrationMs > 0 ? meanMs / calibrationMs : Number.NaN,
      rmeFraction: (stats?.rme ?? 0) / 100,
      samples: stats?.samplesCount ?? 0,
      diagnostics: diagnosticCounts.get(task.name) ?? 0,
    });
  }

  // Report in the order `allRules` declares, with the rules that threw carried
  // through as unmeasured rather than dropped: a rule that started throwing is
  // something the report must show, not hide.
  const timings = rules.map(
    (rule) =>
      measured.get(rule.id) ?? {
        rule: rule.id,
        meanMs: Number.NaN,
        units: Number.NaN,
        rmeFraction: 0,
        samples: 0,
        diagnostics: diagnosticCounts.get(rule.id) ?? 0,
      },
  );

  return { timings, calibrationMs };
}

/* ------------------------------------------------------------------ *
 * Regex backtracking audit
 * ------------------------------------------------------------------ */

/** One regex that either analyses as unsafe or measures as slow. */
export interface RegexProblem {
  file: string;
  line: number;
  pattern: string;
  /** `'static'` when the detector flagged its shape, `'timing'` when it hung. */
  kind: 'static' | 'timing';
  detail: string;
}

/** Every `.ts` file under `src/`, recursively. */
function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sourceFiles(path);
    return path.endsWith('.ts') ? [path] : [];
  });
}

/**
 * Screens every regex literal in `src/` statically, then times the ones that
 * validate URLs and keys against adversarial input.
 *
 * Both halves are needed. The static pass catches the structure
 * (`(a+)+`) whatever input exists; the timing pass catches a pattern whose
 * blow-up comes from something the detector does not model, and proves the
 * static verdict was not merely optimistic.
 */
export function auditRegexes(): RegexProblem[] {
  const problems: RegexProblem[] = [];

  for (const file of sourceFiles(srcDir)) {
    const label = relative(root, file);
    const source = readFileSync(file, 'utf8');

    for (const literal of extractRegexLiterals(source)) {
      const report = analyzeRegex(literal.pattern, literal.flags);
      // A literal the scanner misread will not compile; skip rather than
      // failing the build over the scanner's own ambiguity.
      if (report.parseError !== undefined) continue;

      for (const finding of report.findings) {
        problems.push({
          file: label,
          line: literal.line,
          pattern: literal.pattern,
          kind: 'static',
          detail: `${finding.complexity} backtracking in \`${finding.fragment}\` — ${finding.detail}`,
        });
      }

      // Only patterns that could face a document's own values are worth
      // timing: those are the URL, key, handle, and identifier validators.
      if (!validatesUntrustedInput(literal.pattern)) continue;

      let regex: RegExp;
      try {
        regex = new RegExp(literal.pattern, literal.flags.replace(/[gy]/g, ''));
      } catch {
        continue;
      }

      for (const adversarial of ADVERSARIAL_INPUTS) {
        const input = adversarial.build(ADVERSARIAL_SIZE);
        const start = performance.now();
        try {
          regex.test(input);
        } catch {
          continue;
        }
        const elapsed = performance.now() - start;
        if (elapsed > REGEX_BUDGET_MS) {
          problems.push({
            file: label,
            line: literal.line,
            pattern: literal.pattern,
            kind: 'timing',
            detail:
              `took ${elapsed.toFixed(1)}ms on ${ADVERSARIAL_SIZE} characters of ` +
              `"${adversarial.label}" (budget ${REGEX_BUDGET_MS}ms)`,
          });
        }
      }
    }
  }

  return problems;
}

/**
 * `true` when a pattern looks like it validates a value from the document.
 *
 * A pattern that only ever sees this tool's own short strings — a CLI flag, a
 * rule id, a severity name — cannot be driven by an attacker, so timing it
 * against 20 KB of adversarial input would measure nothing anybody can
 * exploit. The URL, scheme, key, handle, and e-mail shapes can be.
 */
function validatesUntrustedInput(pattern: string): boolean {
  return /https?|:\/\/|@|\[A-Z|\[a-z|\[0-9|\\d|\\w|\\s|G\[A-Z2-7\]|C\[A-Z2-7\]/.test(pattern);
}

/* ------------------------------------------------------------------ *
 * Baseline comparison
 * ------------------------------------------------------------------ */

/** One rule's verdict against the budget and the baseline. */
export interface Verdict {
  timing: RuleTiming;
  /** The budget actually applied, after {@link RULE_ALLOWANCES}. */
  budgetMs: number;
  /** Baseline measurement in calibration units, when the rule has one. */
  baselineUnits?: number;
  /**
   * The baseline expressed in this run's milliseconds, for the report. Derived
   * from the units, so it is what the baseline *would* have measured here.
   */
  baselineMs?: number;
  /** Fractional change against the baseline, when there is one. */
  changeFraction?: number;
  /** `true` when the rule exceeded its latency budget. */
  overBudget: boolean;
  /** `true` when the rule got materially slower than its baseline. */
  regressed: boolean;
  /** `true` when the rule is new since the baseline was recorded. */
  isNew: boolean;
}

/**
 * Compares measurements against budget and baseline.
 *
 * A regression must clear three bars: the percentage tolerance, the absolute
 * noise floor, and the combined statistical error of both measurements. The
 * third is what stops a baseline recorded on a noisy runner from failing every
 * subsequent build.
 */
export function judge(
  measurement: Measurement,
  baseline: Baseline | undefined,
  budgetMs = DEFAULT_BUDGET_MS,
  tolerance = DEFAULT_TOLERANCE,
): Verdict[] {
  const { timings, calibrationMs } = measurement;

  // How much slower this machine is than the one that recorded the baseline,
  // measured by the calibration workload rather than assumed. A shared CI
  // runner came in at 2.7x a developer laptop, which turns a 0.5ms budget into
  // a gate on the runner's speed rather than on the rule's cost. Scaling the
  // absolute thresholds by the same ratio the comparison already uses makes
  // "0.5ms" mean "0.5ms of work as the baseline machine would measure it",
  // which is the thing worth holding constant.
  const scale =
    baseline !== undefined && baseline.calibrationMs > 0 && calibrationMs > 0
      ? calibrationMs / baseline.calibrationMs
      : 1;
  const noiseFloorMs = NOISE_FLOOR_MS * scale;

  return timings.map((timing) => {
    const recorded = baseline?.rules[timing.rule];
    const allowance = RULE_ALLOWANCES[timing.rule];
    const allowed = (allowance?.budgetMs ?? budgetMs) * scale;
    const allowedRise = Math.max(allowance?.tolerance ?? 0, tolerance);
    const overBudget = Number.isFinite(timing.meanMs) && timing.meanMs > allowed;

    if (recorded === undefined) {
      return {
        timing,
        budgetMs: allowed,
        overBudget,
        regressed: false,
        isNew: baseline !== undefined,
      };
    }

    // Compared in calibration units, not milliseconds: the ratio is what
    // survives a different machine (or the same machine a minute later).
    const changeFraction =
      recorded.units > 0 ? (timing.units - recorded.units) / recorded.units : 0;
    const absoluteRise = (timing.units - recorded.units) * calibrationMs;
    // Widen the tolerance by however uncertain the two measurements were.
    const uncertainty = recorded.rmeFraction + timing.rmeFraction;
    const regressed = changeFraction > allowedRise + uncertainty && absoluteRise > noiseFloorMs;

    return {
      timing,
      budgetMs: allowed,
      baselineUnits: recorded.units,
      baselineMs: recorded.units * calibrationMs,
      changeFraction,
      overBudget,
      regressed,
      isNew: false,
    };
  });
}

/**
 * The calibration ratio between a run and the baseline it is compared against.
 *
 * Exposed so the report can say *why* the thresholds moved, rather than
 * leaving a reader to wonder why a 0.5ms budget admitted a 1.2ms rule.
 */
export function calibrationScale(measurement: Measurement, baseline: Baseline | undefined): number {
  if (baseline === undefined || baseline.calibrationMs <= 0 || measurement.calibrationMs <= 0) {
    return 1;
  }
  return measurement.calibrationMs / baseline.calibrationMs;
}

/** Reads the committed baseline, or `undefined` when there is none yet. */
export function loadBaseline(path: string = BASELINE_PATH): Baseline | undefined {
  if (!existsSync(path)) return undefined;
  const parsed = JSON.parse(readFileSync(path, 'utf8')) as Baseline;
  if (parsed.version !== 2) {
    throw new Error(
      `baseline ${path} has unsupported version ${String(parsed.version)}; ` +
        're-record it with `npm run bench:regression -- --update`',
    );
  }
  return parsed;
}

/** Writes the measurements as the new baseline. */
export function writeBaseline(
  measurement: Measurement,
  nodes: number,
  path: string = BASELINE_PATH,
): Baseline {
  const baseline: Baseline = {
    version: 2,
    recordedAt: new Date().toISOString(),
    node: process.version,
    nodes,
    calibrationMs: Number(measurement.calibrationMs.toFixed(5)),
    rules: Object.fromEntries(
      [...measurement.timings]
        .sort((a, b) => a.rule.localeCompare(b.rule))
        .map((timing) => [
          timing.rule,
          {
            units: Number(timing.units.toFixed(4)),
            rmeFraction: Number(timing.rmeFraction.toFixed(4)),
          },
        ]),
    ),
  };

  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(baseline, null, 2)}\n`);
  return baseline;
}
