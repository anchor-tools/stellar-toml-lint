# The regression corpus

A linter earns trust by being right about files its authors have never seen. This
directory runs `lint()` over a catalogue of real, published `stellar.toml` files and
diffs the output against committed snapshots, so any change in behaviour — a rule that
started firing, one that stopped, a message that moved — arrives as something a human
can read.

It is the direct answer to a problem this project has already hit twice: a rule that is
technically correct and still fires on a file nobody was looking at.

## Layout

| Path                    | Purpose                                                               |
| ----------------------- | --------------------------------------------------------------------- |
| `corpus.json`           | The catalogue: names and URLs. The only file you edit by hand.        |
| `harness.ts`            | Fetch, lint, diff, report. No I/O on import; every effect injectable. |
| `run.ts`                | The command-line entry point behind `npm run corpus`.                 |
| `harness.test.ts`       | Offline tests with a stubbed fetcher and temp directories.            |
| `snapshots/<name>.json` | What the linter said, last time. Committed; reviewed like code.       |
| `.cache/`               | Recent fetches, so a run is kind to third parties. Git-ignored.       |
| `.diff/`                | Expected vs. actual snapshots when something changed. Git-ignored.    |

## Commands

```sh
npm run corpus            # compare against the snapshots (exit 1 if anything changed)
npm run corpus:update     # accept the current output by rewriting the snapshots
```

Options go after `--`:

```sh
npm run corpus -- --filter lobstr-co --refresh
npm run corpus -- --offline --ttl 168
```

| Flag              | Meaning                                                      |
| ----------------- | ------------------------------------------------------------ |
| `--update`        | Rewrite the snapshots from this run's fetch.                 |
| `--refresh`       | Ignore the cache when fetching (the cache is still updated). |
| `--offline`       | Never touch the network; use the cache whatever its age.     |
| `--filter <name>` | Only this catalogue entry. Repeatable.                       |
| `--timeout <ms>`  | Per-request timeout, default `15000`.                        |
| `--ttl <hours>`   | Cache freshness window, default `24`.                        |

Exit codes follow the rest of the toolchain: `0` clean, `1` the linter's output changed
and needs a reviewer (or `corpus:update`), `2` bad usage or an unreadable catalogue.

## The three rules

**The catalogue stores URLs, not content.** The files stay where they are published.
Nothing is copied into this repository except what the linter said about them, which is
what keeps the snapshots small, reviewable, and honest about being derived data.

**A network problem is never a test failure.** A host that is down, slow, or on strike
is reported as `unreachable` and the run still succeeds. Otherwise a third party's
downtime would look like our regression, and the first flaky run would teach everyone to
ignore the check. A fetch that fails does fall back to a cached copy if one exists —
a day-old body still beats losing the entry.

**Everything is deterministic.** Snapshots are JSON with no timestamps and no ordering
surprises: identical lint output always renders to identical bytes, so a diff means
exactly one thing — the linter's behaviour changed. That also makes `snapshots/`
stable enough that a botched merge conflict shows up as a diff rather than as churn.

## Adding an entry

Append an object to `corpus.json`:

```json
{ "name": "example-com", "url": "https://example.com/.well-known/stellar.toml", "note": "why" }
```

Names are lowercase letters, digits, and dashes; they become the snapshot filename and
must be unique. The note is for reviewers — say what makes the file interesting (dense
comments, unusual validator layout, a documentation section that is nearly empty).
Prefer a site that is unlikely to disappear. Then:

```sh
npm run corpus:update
```

and commit the new snapshot with the catalogue change. Read the diff before you commit
it: on a brand-new entry the snapshot _is_ the review.

## Reviewing a change

When `npm run corpus` exits non-zero it prints one section per changed entry:

```
lobstr-co (https://lobstr.co/.well-known/stellar.toml)
  source changed: the published file differs from the one last snapshotted
  counts: error 0 -> 1, warning 1 -> 1
  + currencies/urls CURRENCIES[0].toml (31:1): ...
  ~ documentation/present DOCUMENTATION: "No [DOCUMENTATION] table, ..." -> "..."
```

Two things tell you whose fault it is:

- **`source changed`** means the site was edited. The linter is describing a different
  file now; decide whether the new output is right and then run `corpus:update`.
- **No `source changed`** means the bytes are identical and the linter's behaviour
  changed. That one is ours — a rule, a message, or a refactor moved, and the diff is
  the evidence.

`.diff/` holds the full expected and actual snapshots for each changed entry, which CI
uploads as an artifact.

## Continuous integration

[`.github/workflows/corpus.yml`](../../.github/workflows/corpus.yml) runs the harness
weekly and on demand. It is deliberately **not** a merge gate: it needs the network, and
its findings are meant for a person rather than for blocking a pull request. Its run
summary is written to the Actions step summary, and the diff is uploaded as an artifact.

Dispatching it with `update: true` fetches afresh, rewrites the snapshots, and uploads
them as a second artifact — a convenient way to refresh the corpus from a machine that
is not yours, at the cost of committing by hand afterwards.
