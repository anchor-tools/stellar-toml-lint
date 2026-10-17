# Benchmarks

Two harnesses, answering two different questions.

| Command                    | Question                               | File                  |
| -------------------------- | -------------------------------------- | --------------------- |
| `npm run bench`            | Is the linter fast enough, end to end? | `runner.ts`           |
| `npm run bench:regression` | Which _rule_ got slower?               | `regression-suite.ts` |

## End-to-end throughput (`runner.ts`)

Generates synthetic configurations from 10KB to 5MB and checks each against a fixed threshold.

```bash
npm run bench
```

| File size | Threshold |
| --------- | --------- |
| < 10KB    | 5ms       |
| < 100KB   | 20ms      |
| < 1MB     | 50ms      |
| < 5MB     | 200ms     |

Output:

```
[PASS] small      | Lines:    100 | Size:  5.2KB | Time:  1.23ms | Memory:  2.10MB
[PASS] medium     | Lines:   1000 | Size: 52.3KB | Time:  5.67ms | Memory:  4.50MB
[PASS] large      | Lines:  10000 | Size: 523.1KB | Time: 15.42ms | Memory: 12.30MB
[PASS] xlarge     | Lines: 100000 | Size: 5.1MB | Time: 45.21ms | Memory: 45.20MB
```

## Per-rule regression suite (`regression-suite.ts`, issue #377)

The aggregate above cannot tell you _which_ rule regressed. With 250+ rules sharing one pass, a
rule that acquires a quadratic regex adds a few milliseconds to a total that is already tens of
milliseconds — invisible in the aggregate, and paid by every pipeline that runs this tool.

```bash
npm run bench:regression                  # measure, enforce, exit 1 on failure
npm run bench:regression -- --update      # accept the current timings as the baseline
npm run bench:regression -- --json        # machine-readable report
npm run bench:regression -- --filter sep  # only rules whose id contains "sep"
npm run bench:regression -- --help        # every option
```

Three checks:

1. **Latency budget** — 0.5ms per rule on a 1,000-node synthetic document. Catches a rule that was
   slow from its first commit, which a baseline comparison structurally cannot. Eight rules that
   walk every string in the document have a documented allowance in `RULE_ALLOWANCES`, each with
   its reason.
2. **Baseline comparison** — a rise over 20% against `baselines/rule-latency.json` fails.
3. **Regex audit** — every regex literal in `src/` is screened statically with the ReDoS detector
   from issue #380, and the ones that validate URLs and keys are then _timed_ against 20 KB of
   adversarial input.

### Why the measurements are normalised

Raw milliseconds are not comparable between two runs, let alone between a laptop and a CI runner.
Measured here, the same rule on the same machine varied by 30–50% between consecutive runs: within
a run the sampling error is under 6%, so the variance is V8 deciding differently about inlining,
once per process, not the sampler.

So every rule's time is divided by a fixed calibration workload benchmarked in the same run, and
the baseline stores that ratio. Two further guards keep the gate usable: a regression must clear
the percentage tolerance _and_ a 0.05ms absolute floor (most rules run in tens of nanoseconds,
where a 20% swing is scheduler noise), and the tolerance is widened by the statistical error both
measurements reported.

### Why each rule is measured in batches

tinybench treats its `time` option as a _minimum_, so a rule costing 20ns is sampled four million
times in 120ms. Measured, that put 539MB of sample bookkeeping through the heap for two tasks, and
across 250 rules it turned a 40-second suite into a multi-minute GC thrash. Instead, each rule is
probed once to estimate its per-call cost, then benchmarked in a loop sized to make one iteration
take ~0.5ms, for a fixed 200 samples. Every rule gets the same statistical treatment and the suite
finishes in about ten seconds.

### In CI

[`.github/workflows/benchmarks.yml`](../.github/workflows/benchmarks.yml) runs both harnesses. On a
pull request it re-records the baseline from the base commit **on the same runner** before
measuring the PR, so the comparison is PR-vs-base rather than PR-vs-someone's-laptop, and a flagged
regression must reproduce in a second run before the job fails.

### Updating the baseline

Re-record it when a rule legitimately got slower or faster, or when rules are added:

```bash
npm run bench:regression -- --update
```

Commit the result. The regex audit still runs during an update, so a baseline refresh cannot
launder a catastrophic matcher into the committed numbers.

### Layout

| File                          | Holds                                                                                                    |
| ----------------------------- | -------------------------------------------------------------------------------------------------------- |
| `runner.ts`                   | The end-to-end throughput harness.                                                                       |
| `regression-suite.ts`         | The per-rule CLI: argument parsing, reporting, exit codes.                                               |
| `regression-harness.ts`       | Measurement, the regex audit, and the comparison — no effects, so `test/benchmarks/` drives it directly. |
| `baselines/rule-latency.json` | Committed per-rule timings, in calibration units.                                                        |

## Requirements

Node.js 20+. Both harnesses run on `vite-node`, already a devDependency for the corpus harness, so
neither needs a runner downloaded at CI time.
