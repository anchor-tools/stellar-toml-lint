/**
 * The corpus harness.
 *
 * A linter earns trust by being right about files its authors have never seen.
 * This module snapshots `lint()`'s output across a catalogue of real, public
 * `stellar.toml` files so that any change in behaviour shows up as a reviewable
 * diff — the defence against the false positives that live-site testing has
 * already surfaced twice.
 *
 * Three rules shape the design:
 *
 * - **The catalogue stores URLs, not content.** The files stay where they are
 *   published; we only ever commit what the linter said about them.
 * - **A network problem is never a test failure.** A host that is down, slow, or
 *   on strike reports `unreachable` and the run still succeeds, so a flaky
 *   third party cannot redden CI. Only a change in *our* output does that.
 * - **Everything is deterministic.** Snapshots are JSON with no timestamps or
 *   ordering surprises, so a diff means exactly one thing: the linter's
 *   behaviour changed.
 */
import { createHash } from 'node:crypto';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { lint } from '../../src/lint.js';
import type { Diagnostic } from '../../src/types.js';

export const HERE = dirname(fileURLToPath(import.meta.url));
export const DEFAULT_CATALOG_PATH = join(HERE, 'corpus.json');
export const DEFAULT_SNAPSHOTS_DIR = join(HERE, 'snapshots');
export const DEFAULT_CACHE_DIR = join(HERE, '.cache');
export const DEFAULT_DIFF_DIR = join(HERE, '.diff');

/** How long a cached fetch stays fresh enough to skip the network. */
export const DEFAULT_TTL_HOURS = 24;
/** Per-request timeout, so one dead host cannot stall the whole run. */
export const DEFAULT_TIMEOUT_MS = 15_000;

/** One entry in the catalogue: where a real file lives. */
export interface CorpusEntry {
  /** Stable, filesystem-safe id used for the snapshot filename. */
  name: string;
  url: string;
  note?: string;
}

export interface Counts {
  error: number;
  warning: number;
  info: number;
}

/** What the linter said about one corpus file. This is the committed unit. */
export interface Snapshot {
  url: string;
  domain: string;
  /** Identity of the fetched bytes, so a diff can say who changed. */
  sourceSha256: string;
  ok: boolean;
  counts: Counts;
  diagnostics: Diagnostic[];
}

export type FetchOutcome = { ok: true; body: string } | { ok: false; error: string };
export type Fetcher = (url: string, timeoutMs: number) => Promise<FetchOutcome>;

export type EntryStatus =
  /** Output matches the committed snapshot. */
  | 'matched'
  /** Output differs from the committed snapshot — the reviewer's job starts here. */
  | 'changed'
  /** Catalogued but never snapshotted. */
  | 'missing'
  /** --update created the first snapshot for this entry. */
  | 'created'
  /** --update rewrote an existing snapshot. */
  | 'updated'
  /** Could not fetch it and had no cache to fall back on. Never a failure. */
  | 'unreachable';

export interface EntryOutcome {
  entry: CorpusEntry;
  status: EntryStatus;
  /** Where the body came from when the entry could be loaded. */
  source?: 'network' | 'cache';
  /** Why the entry is unreachable. */
  detail?: string;
  counts?: Counts;
  /** Human-readable change report, empty when nothing changed. */
  diff: string[];
}

export interface RunReport {
  outcomes: EntryOutcome[];
  matched: number;
  changed: number;
  missing: number;
  created: number;
  updated: number;
  unreachable: number;
  /**
   * True when the caller should exit non-zero: something published here has
   * changed and a human has to look at it. Unreachable entries never set it —
   * that would make a third party's downtime look like our regression — and
   * neither does --update, which has already accepted the new output.
   */
  needsReview: boolean;
}

export interface RunOptions {
  catalogPath?: string;
  snapshotsDir?: string;
  cacheDir?: string;
  diffDir?: string;
  /** Only these catalogue names; an unknown name is a usage error. */
  filter?: string[];
  /** Rewrite snapshots from this run's fetch. */
  update?: boolean;
  /** Ignore the cache when reading (still writes on a successful fetch). */
  refresh?: boolean;
  /** Never touch the network; use the cache at any age. */
  offline?: boolean;
  ttlHours?: number;
  timeoutMs?: number;
  /** Injected in tests; defaults to global `fetch`. */
  fetcher?: Fetcher;
  now?: () => number;
}

/**
 * The default fetcher: one GET, a hard timeout, and an error string instead of
 * a throw. Callers never have to catch anything.
 */
export const fetchBody: Fetcher = async (url, timeoutMs) => {
  try {
    const response = await fetch(url, {
      redirect: 'follow',
      signal: AbortSignal.timeout(timeoutMs),
      headers: {
        'User-Agent':
          'stellar-toml-lint-corpus (+https://github.com/anchor-tools/stellar-toml-lint)',
        Accept: 'text/plain, text/*;q=0.9, */*;q=0.1',
      },
    });
    if (!response.ok) return { ok: false, error: `HTTP ${response.status}` };
    return { ok: true, body: await response.text() };
  } catch (error) {
    const detail = error instanceof Error ? error.message.split('\n')[0]?.trim() : undefined;
    return { ok: false, error: detail || String(error) };
  }
};

/** Parses and validates the catalogue, failing loudly on a bad entry. */
export function readCatalog(text: string): CorpusEntry[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw new Error(`corpus catalogue is not valid JSON: ${message(error)}`);
  }

  if (!Array.isArray(parsed)) throw new Error('corpus catalogue must be a JSON array of entries');

  const names = new Set<string>();
  return parsed.map((raw, index) => {
    if (typeof raw !== 'object' || raw === null) {
      throw new Error(`corpus catalogue entry ${index} is not an object`);
    }
    const entry = raw as Record<string, unknown>;
    const { name, url, note } = entry;

    if (typeof name !== 'string' || !/^[a-z0-9][a-z0-9-]*$/.test(name)) {
      throw new Error(
        `corpus catalogue entry ${index} has an invalid name; use lowercase letters, digits and dashes`,
      );
    }
    if (names.has(name)) throw new Error(`corpus catalogue lists "${name}" twice`);
    names.add(name);

    if (typeof url !== 'string' || !url.startsWith('https://')) {
      throw new Error(`corpus entry "${name}" must be an https:// URL`);
    }
    if (note !== undefined && typeof note !== 'string') {
      throw new Error(`corpus entry "${name}" has a non-string note`);
    }

    return note === undefined ? { name, url } : { name, url, note };
  });
}

/** Lints one fetched body and freezes the result as a snapshot. */
export function snapshotFor(entry: CorpusEntry, body: string): Snapshot {
  const url = new URL(entry.url);
  const result = lint(body, { domain: url.host });
  return {
    url: entry.url,
    domain: url.host,
    sourceSha256: sha256(body),
    ok: result.ok,
    counts: {
      error: result.counts.error,
      warning: result.counts.warning,
      info: result.counts.info,
    },
    diagnostics: result.diagnostics,
  };
}

/** Serialises a snapshot. Byte-identical input always yields identical bytes. */
export function renderSnapshot(snapshot: Snapshot): string {
  return `${JSON.stringify(snapshot, null, 2)}\n`;
}

/** Reads a committed snapshot, or `undefined` when it is absent or corrupt. */
export function parseSnapshot(text: string): Snapshot | undefined {
  try {
    const value = JSON.parse(text) as Partial<Snapshot>;
    if (typeof value.url !== 'string' || !Array.isArray(value.diagnostics)) return undefined;
    if (typeof value.counts !== 'object' || value.counts === null) return undefined;
    return value as Snapshot;
  } catch {
    return undefined;
  }
}

/**
 * The reviewable part of a diff: what the linter now says that it did not say
 * before, what it no longer says, and what it says differently. Diagnostics are
 * paired by rule, path and position first, so a message that changed reads as a
 * change rather than as one removal plus one addition.
 */
export function diffSnapshots(before: Snapshot | undefined, after: Snapshot): string[] {
  if (!before) {
    return ['  no committed snapshot yet', ...after.diagnostics.map((d) => `  + ${describe(d)}`)];
  }

  const lines: string[] = [];

  if (before.sourceSha256 !== after.sourceSha256) {
    lines.push('  source changed: the published file differs from the one last snapshotted');
  }
  if (before.ok !== after.ok) {
    lines.push(`  verdict changed: ok=${before.ok} -> ok=${after.ok}`);
  }

  const countDelta = (label: keyof Counts): string =>
    `${label} ${before.counts[label]} -> ${after.counts[label]}`;
  if (
    before.counts.error !== after.counts.error ||
    before.counts.warning !== after.counts.warning
  ) {
    lines.push(`  counts: ${countDelta('error')}, ${countDelta('warning')}`);
  }

  const beforeGroups = groupBy(before.diagnostics, anchor);
  const afterGroups = groupBy(after.diagnostics, anchor);

  for (const key of orderedKeys(afterGroups, beforeGroups)) {
    const old = beforeGroups.get(key) ?? [];
    const now = afterGroups.get(key) ?? [];
    const shared = Math.min(old.length, now.length);

    for (let i = 0; i < shared; i++) {
      const was = old[i];
      const is = now[i];
      if (was && is && !sameDiagnostic(was, is)) {
        lines.push(`  ~ ${label(is)}: ${describeDelta(was, is)}`);
      }
    }
    for (let i = shared; i < now.length; i++) {
      const is = now[i];
      if (is) lines.push(`  + ${describe(is)}`);
    }
    for (let i = shared; i < old.length; i++) {
      const was = old[i];
      if (was) lines.push(`  - ${describe(was)}`);
    }
  }

  return lines;
}

/** Runs the whole catalogue and reports what it found. */
export async function runCorpus(options: RunOptions = {}): Promise<RunReport> {
  const catalogPath = options.catalogPath ?? DEFAULT_CATALOG_PATH;
  const snapshotsDir = options.snapshotsDir ?? DEFAULT_SNAPSHOTS_DIR;
  const cacheDir = options.cacheDir ?? DEFAULT_CACHE_DIR;
  const diffDir = options.diffDir ?? DEFAULT_DIFF_DIR;
  const fetcher = options.fetcher ?? fetchBody;
  const now = options.now ?? Date.now;
  const ttlMs = (options.ttlHours ?? DEFAULT_TTL_HOURS) * 3_600_000;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  const entries = readCatalog(await readFile(catalogPath, 'utf8'));
  const selected = select(entries, options.filter ?? []);

  await mkdir(snapshotsDir, { recursive: true });
  await mkdir(cacheDir, { recursive: true });
  // Leftovers from an earlier run would otherwise be uploaded alongside the
  // current diff and read as if they still applied.
  await rm(diffDir, { recursive: true, force: true });
  await mkdir(diffDir, { recursive: true });

  const outcomes: EntryOutcome[] = [];

  for (const entry of selected) {
    const loaded = await loadBody({
      entry,
      cacheDir,
      fetcher,
      timeoutMs,
      ttlMs,
      offline: options.offline ?? false,
      refresh: options.refresh ?? false,
      // An update wants the bytes the site is serving *now*.
      skipFreshCache: options.update === true,
      now: now(),
    });

    if (!loaded.ok) {
      outcomes.push({ entry, status: 'unreachable', detail: loaded.error, diff: [] });
      continue;
    }

    const snapshot = snapshotFor(entry, loaded.body);
    const snapshotPath = join(snapshotsDir, `${entry.name}.json`);
    const previousText = await readIfExists(snapshotPath);
    const previous = previousText === undefined ? undefined : parseSnapshot(previousText);
    const rendered = renderSnapshot(snapshot);
    const diff = previousText === rendered ? [] : diffFor(previousText, previous, snapshot);

    if (options.update) {
      if (previousText !== rendered) {
        await writeFile(snapshotPath, rendered, 'utf8');
        await writeDiffArtifacts(diffDir, entry, previousText, rendered);
        outcomes.push({
          entry,
          status: previousText === undefined ? 'created' : 'updated',
          source: loaded.source,
          counts: snapshot.counts,
          diff,
        });
      } else {
        outcomes.push({
          entry,
          status: 'matched',
          source: loaded.source,
          counts: snapshot.counts,
          diff: [],
        });
      }
      continue;
    }

    const status: EntryStatus =
      previousText === undefined ? 'missing' : previousText === rendered ? 'matched' : 'changed';
    if (status !== 'matched') await writeDiffArtifacts(diffDir, entry, previousText, rendered);

    outcomes.push({ entry, status, source: loaded.source, counts: snapshot.counts, diff });
  }

  const tally = (status: EntryStatus): number => outcomes.filter((o) => o.status === status).length;
  const compareMode = options.update !== true;

  return {
    outcomes,
    matched: tally('matched'),
    changed: tally('changed') + tally('missing'),
    missing: tally('missing'),
    created: tally('created'),
    updated: tally('updated'),
    unreachable: tally('unreachable'),
    needsReview: compareMode && tally('changed') + tally('missing') > 0,
  };
}

function diffFor(
  previousText: string | undefined,
  previous: Snapshot | undefined,
  snapshot: Snapshot,
): string[] {
  if (previousText !== undefined && previous === undefined) {
    return ['  the committed snapshot is unreadable; regenerate it with --update'];
  }
  return diffSnapshots(previous, snapshot);
}

/** One human-readable line per entry, plus the change reports. */
export function renderReport(report: RunReport): string {
  const width = Math.max(11, ...report.outcomes.map((o) => o.entry.name.length));
  const lines = report.outcomes.map((outcome) => {
    const name = outcome.entry.name.padEnd(width);
    if (outcome.status === 'unreachable') {
      return `${outcome.status.padEnd(11)} ${name} ${outcome.detail ?? ''}`;
    }
    const counts = outcome.counts;
    const summary = counts
      ? `${counts.error} errors, ${counts.warning} warnings, ${counts.info} infos`
      : '';
    const cache = outcome.source === 'cache' ? ' (cached)' : '';
    return `${outcome.status.padEnd(11)} ${name} ${summary}${cache}`;
  });

  lines.push('');
  lines.push(
    `${report.outcomes.length} entries: ${report.matched} matched, ${report.changed} changed, ` +
      `${report.created} created, ${report.updated} updated, ${report.unreachable} unreachable`,
  );

  for (const outcome of report.outcomes) {
    if (outcome.diff.length === 0) continue;
    lines.push('');
    lines.push(`${outcome.entry.name} (${outcome.entry.url})`);
    lines.push(...outcome.diff);
  }

  return `${lines.join('\n')}\n`;
}

/** Markdown for the GitHub Actions step summary. */
export function renderMarkdown(report: RunReport): string {
  const lines = [
    '## Corpus run',
    '',
    '| entry | status | errors | warnings | notes |',
    '| --- | --- | ---: | ---: | --- |',
  ];

  for (const outcome of report.outcomes) {
    const counts = outcome.counts;
    const notes = outcome.detail ?? (outcome.source === 'cache' ? 'served from cache' : '');
    lines.push(
      `| ${outcome.entry.name} | ${outcome.status} | ${counts?.error ?? '—'} | ${
        counts?.warning ?? '—'
      } | ${notes} |`,
    );
  }

  const reviewed = report.outcomes.filter((outcome) => outcome.diff.length > 0);
  if (reviewed.length > 0) {
    lines.push('', '### Changes to review', '');
    lines.push('```text');
    for (const outcome of reviewed) {
      lines.push(`${outcome.entry.name} (${outcome.entry.url})`);
      lines.push(...outcome.diff);
      lines.push('');
    }
    lines[lines.length - 1] = '```';
  } else if (report.needsReview) {
    lines.push('', 'Run `npm run corpus:update` to accept these snapshots.');
  } else if (report.created + report.updated > 0) {
    lines.push('', `Rewrote ${report.created + report.updated} snapshot(s); commit the result.`);
  } else if (report.unreachable > 0) {
    lines.push('', 'No behavioural changes; some hosts were unreachable.');
  } else {
    lines.push('', 'No behavioural changes.');
  }

  return `${lines.join('\n')}\n`;
}

interface LoadOptions {
  entry: CorpusEntry;
  cacheDir: string;
  fetcher: Fetcher;
  timeoutMs: number;
  ttlMs: number;
  offline: boolean;
  refresh: boolean;
  skipFreshCache: boolean;
  now: number;
}

type LoadResult =
  { ok: true; body: string; source: 'network' | 'cache' } | { ok: false; error: string };

/**
 * Gets a body for an entry: a cache fresh enough to trust, else the network,
 * else a stale cache — because a day-old copy still beats losing the entry to a
 * transient DNS blip.
 */
async function loadBody(options: LoadOptions): Promise<LoadResult> {
  const { entry, cacheDir, fetcher, timeoutMs, ttlMs, offline, refresh, skipFreshCache, now } =
    options;

  if (!refresh && !skipFreshCache) {
    const fresh = await readCache(cacheDir, entry, offline ? Infinity : ttlMs, now);
    if (fresh !== undefined) return { ok: true, body: fresh, source: 'cache' };
  }

  if (offline) {
    return { ok: false, error: 'offline: no cached copy of this entry' };
  }

  const fetched = await fetcher(entry.url, timeoutMs);
  if (!fetched.ok) {
    const stale = refresh ? undefined : await readCache(cacheDir, entry, Infinity, now);
    if (stale !== undefined) return { ok: true, body: stale, source: 'cache' };
    return { ok: false, error: fetched.error };
  }

  await writeCache(cacheDir, entry, fetched.body, now);
  return { ok: true, body: fetched.body, source: 'network' };
}

async function readCache(
  cacheDir: string,
  entry: CorpusEntry,
  maxAgeMs: number,
  now: number,
): Promise<string | undefined> {
  try {
    const meta = JSON.parse(await readFile(join(cacheDir, `${entry.name}.meta.json`), 'utf8')) as {
      url?: unknown;
      fetchedAt?: unknown;
    };
    if (meta.url !== entry.url || typeof meta.fetchedAt !== 'number') return undefined;
    if (now - meta.fetchedAt > maxAgeMs) return undefined;
    return await readFile(join(cacheDir, `${entry.name}.toml`), 'utf8');
  } catch {
    return undefined;
  }
}

async function writeCache(
  cacheDir: string,
  entry: CorpusEntry,
  body: string,
  fetchedAt: number,
): Promise<void> {
  await mkdir(cacheDir, { recursive: true });
  await writeFile(join(cacheDir, `${entry.name}.toml`), body, 'utf8');
  await writeFile(
    join(cacheDir, `${entry.name}.meta.json`),
    `${JSON.stringify({ url: entry.url, fetchedAt }, null, 2)}\n`,
    'utf8',
  );
}

/** Copies the old and new snapshots so CI can upload them as an artifact. */
async function writeDiffArtifacts(
  diffDir: string,
  entry: CorpusEntry,
  expected: string | undefined,
  actual: string,
): Promise<void> {
  await mkdir(diffDir, { recursive: true });
  await writeFile(
    join(diffDir, `${entry.name}.expected.json`),
    expected ?? '# no committed snapshot\n',
    'utf8',
  );
  await writeFile(join(diffDir, `${entry.name}.actual.json`), actual, 'utf8');
}

function select(entries: CorpusEntry[], filter: string[]): CorpusEntry[] {
  if (filter.length === 0) return entries;
  const known = new Set(entries.map((entry) => entry.name));
  const unknown = filter.filter((name) => !known.has(name));
  if (unknown.length > 0) {
    throw new Error(
      `unknown corpus ${unknown.length === 1 ? 'entry' : 'entries'}: ${unknown.join(', ')}. ` +
        `Known: ${[...known].join(', ')}`,
    );
  }
  return entries.filter((entry) => filter.includes(entry.name));
}

function sha256(body: string): string {
  return createHash('sha256').update(body, 'utf8').digest('hex');
}

/** Identifies a diagnostic across two snapshots: same rule, path and place. */
function anchor(diagnostic: Diagnostic): string {
  const position = diagnostic.position
    ? `${diagnostic.position.line}:${diagnostic.position.column}`
    : '';
  return `${diagnostic.rule}|${diagnostic.path ?? ''}|${position}`;
}

function describe(diagnostic: Diagnostic): string {
  const place = [
    diagnostic.path,
    diagnostic.position ? `(${diagnostic.position.line}:${diagnostic.position.column})` : '',
  ]
    .filter(Boolean)
    .join(' ');
  return `${diagnostic.rule} ${diagnostic.severity}${place ? ` ${place}` : ''}: ${diagnostic.message}`;
}

function label(diagnostic: Diagnostic): string {
  const place = diagnostic.position
    ? ` (${diagnostic.position.line}:${diagnostic.position.column})`
    : '';
  return `${diagnostic.rule}${diagnostic.path ? ` ${diagnostic.path}` : ''}${place}`;
}

function describeDelta(before: Diagnostic, after: Diagnostic): string {
  const parts: string[] = [];
  if (before.severity !== after.severity) {
    parts.push(`severity ${before.severity} -> ${after.severity}`);
  }
  if (before.category !== after.category) {
    parts.push(`category ${before.category} -> ${after.category}`);
  }
  if (before.message !== after.message) {
    parts.push(`"${before.message}" -> "${after.message}"`);
  }
  if (before.helpUri !== after.helpUri) parts.push(`helpUri -> ${after.helpUri}`);
  if (before.suggestion !== after.suggestion) parts.push('suggestion changed');
  return parts.join('; ');
}

function sameDiagnostic(a: Diagnostic, b: Diagnostic): boolean {
  return (
    a.severity === b.severity &&
    a.category === b.category &&
    a.message === b.message &&
    a.helpUri === b.helpUri &&
    a.suggestion === b.suggestion
  );
}

function groupBy(items: Diagnostic[], key: (d: Diagnostic) => string): Map<string, Diagnostic[]> {
  const groups = new Map<string, Diagnostic[]>();
  for (const item of items) {
    const bucket = groups.get(key(item));
    if (bucket) bucket.push(item);
    else groups.set(key(item), [item]);
  }
  return groups;
}

/** After-keys first (new findings read first), then keys only the old had. */
function orderedKeys(
  after: Map<string, Diagnostic[]>,
  before: Map<string, Diagnostic[]>,
): string[] {
  const keys = [...after.keys()];
  for (const key of before.keys()) if (!after.has(key)) keys.push(key);
  return keys;
}

async function readIfExists(path: string): Promise<string | undefined> {
  try {
    return await readFile(path, 'utf8');
  } catch {
    return undefined;
  }
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
