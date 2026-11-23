/**
 * GitOps deployment drift detection (#571).
 *
 * Under GitOps the stellar.toml in version control is the source of truth and a
 * pipeline publishes it to `https://<domain>/.well-known/stellar.toml`. Drift
 * happens in two directions, and they need different fixes:
 *
 * - **unreleased**: a change merged to Git that has not reached production
 *   (a deploy failed silently, or never ran). Fix: redeploy.
 * - **uncommitted**: production was edited out-of-band and the change does not
 *   exist anywhere in Git. Fix: commit it, or revert the server.
 *
 * A plain two-way diff of HEAD against live cannot tell these apart. So the
 * detector walks the file's Git history to find the revision that is actually
 * deployed — an exact semantic match, or failing that the closest one — and
 * does a three-way comparison of base (deployed) / HEAD / live. A path changed
 * only on the Git side is unreleased, only on the live side is uncommitted, and
 * on both sides to different values is diverged.
 *
 * Comparison is semantic: the TOML is parsed and flattened to dotted paths, so
 * comments, whitespace, key order and quoting style never count as drift, and
 * `[[CURRENCIES]]` entries are matched by `code`/`issuer` rather than position.
 */
import { execFile } from 'node:child_process';
import { readFile, realpath, stat } from 'node:fs/promises';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { promisify } from 'node:util';
import { parse as parseToml } from 'smol-toml';
import { formatUnifiedDiff } from '../line-diff.js';

const run = promisify(execFile);

/** Default timeout for fetching the live stellar.toml, in milliseconds. */
export const DEFAULT_FETCH_TIMEOUT = 10_000;

/** How many historical revisions of the file are searched for the deployed one. */
export const DEFAULT_MAX_HISTORY = 50;

/** Live responses larger than this are rejected; SEP-1 caps the file at 100 KB. */
const MAX_LIVE_BYTES = 1024 * 1024;

/** Which side of the deployment a difference lives on. */
export type DriftType = 'unreleased' | 'uncommitted' | 'diverged';

/** What happened to a path, read from the side that changed. */
export type ChangeKind = 'added' | 'removed' | 'changed';

/** One semantic difference between the Git and live configurations. */
export interface DriftFinding {
  /** Flattened path, e.g. `SIGNING_KEY` or `CURRENCIES[code=USDC].status`. */
  path: string;
  driftType: DriftType;
  kind: ChangeKind;
  /** Errors are changes nobody can account for; unreleased work is a warning. */
  severity: 'error' | 'warning';
  /** Value at the Git ref (HEAD by default); absent when the path is missing there. */
  git?: unknown;
  /** Value on the live server; absent when the path is missing there. */
  live?: unknown;
  /** Value at the deployed revision, when one was identified. */
  base?: unknown;
  message: string;
}

/** A commit that touched the file. */
export interface CommitInfo {
  sha: string;
  shortSha: string;
  /** ISO-8601 commit date. */
  date: string;
  subject: string;
}

/**
 * How the deployed revision was identified:
 * - `exact`: live is semantically identical to this commit's file.
 * - `closest`: no exact match; this commit's file differs from live the least.
 * - `none`: no Git history was available (not a repository, untracked file).
 */
export type DeployedMatch = 'exact' | 'closest' | 'none';

export interface DriftReport {
  status: 'in-sync' | 'drift';
  inSync: boolean;
  domain?: string;
  liveUrl: string;
  checkedAt: string;
  git: {
    /** The stellar.toml that was compared, as given on disk. */
    file: string;
    /** Path relative to the repository root, when inside one. */
    repoPath?: string;
    ref: string;
    /** Commit the ref resolved to. */
    head?: CommitInfo;
    /** Revision live is believed to be running. */
    deployed?: CommitInfo;
    deployedMatch: DeployedMatch;
    /** Commits after the deployed revision that touched the file, newest first. */
    unreleasedCommits: CommitInfo[];
    /** True when the working copy differs from the ref (it is not what was compared). */
    workingTreeDirty: boolean;
  };
  summary: {
    total: number;
    unreleased: number;
    uncommitted: number;
    diverged: number;
  };
  findings: DriftFinding[];
  /** Raw sources, for the line-level diff. Not part of the JSON alert. */
  sources: { git: string; live: string };
}

export type DriftErrorCode =
  | 'timeout'
  | 'network'
  | 'http'
  | 'too-large'
  | 'invalid-domain'
  | 'git-file-not-found'
  | 'unparseable-git'
  | 'unparseable-live';

/** Operational failure: the check could not be performed. Maps to exit code 2. */
export class DriftDetectionError extends Error {
  readonly code: DriftErrorCode;
  constructor(code: DriftErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'DriftDetectionError';
    this.code = code;
  }
}

export interface DriftDetectionOptions {
  /** Anchor home domain; the live file is fetched from its `/.well-known/`. */
  domain?: string;
  /** Explicit live URL, overriding `domain` (staging, a CDN origin, tests). */
  url?: string;
  /**
   * The repository's stellar.toml, or a directory containing it (checked for
   * `.well-known/stellar.toml`, then `stellar.toml`). Defaults to the cwd.
   */
  gitPath?: string;
  /** Git ref treated as the desired state. Defaults to `HEAD`. */
  ref?: string;
  /** Fetch timeout in milliseconds. */
  timeoutMs?: number;
  /** Maximum historical revisions searched for the deployed one. */
  maxHistory?: number;
  /** Injected for tests. */
  fetch?: typeof fetch;
  /** Injected for tests. */
  now?: () => Date;
}

/** Turn `example.com`, `https://example.com/`, … into the SEP-1 URL. */
export function liveUrlForDomain(domain: string): string {
  const host = domain
    .trim()
    .replace(/^https?:\/\//i, '')
    .replace(/\/.*$/, '');
  if (!/^[a-z0-9.-]+(:\d+)?$/i.test(host) || !host.includes('.')) {
    throw new DriftDetectionError('invalid-domain', `Invalid domain: ${domain}`);
  }
  return `https://${host}/.well-known/stellar.toml`;
}

/**
 * Fetch the live stellar.toml. Timeouts, transport failures and non-2xx
 * responses throw rather than returning empty content: "the server was down"
 * must never be reported as "every key was removed".
 */
export async function fetchLiveToml(
  url: string,
  options: { timeoutMs?: number; fetch?: typeof fetch } = {},
): Promise<string> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_FETCH_TIMEOUT;
  const doFetch = options.fetch ?? fetch;
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);

  try {
    const response = await doFetch(url, {
      signal: controller.signal,
      headers: { accept: 'text/plain, application/toml, */*' },
      redirect: 'follow',
    });
    if (!response.ok) {
      throw new DriftDetectionError(
        'http',
        `Could not fetch ${url}: HTTP ${response.status}${response.statusText ? ` ${response.statusText}` : ''}`,
      );
    }
    const declared = Number(response.headers.get('content-length') ?? '0');
    if (declared > MAX_LIVE_BYTES) {
      throw new DriftDetectionError('too-large', `${url} is larger than ${MAX_LIVE_BYTES} bytes`);
    }
    const text = await response.text();
    if (Buffer.byteLength(text) > MAX_LIVE_BYTES) {
      throw new DriftDetectionError('too-large', `${url} is larger than ${MAX_LIVE_BYTES} bytes`);
    }
    return text;
  } catch (error) {
    if (error instanceof DriftDetectionError) throw error;
    if (timedOut) {
      throw new DriftDetectionError('timeout', `Timed out after ${timeoutMs} ms fetching ${url}`, {
        cause: error,
      });
    }
    const reason =
      error instanceof Error
        ? ((error.cause as Error | undefined)?.message ?? error.message)
        : String(error);
    throw new DriftDetectionError('network', `Could not fetch ${url}: ${reason}`, { cause: error });
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// Semantic flattening and diffing
// ---------------------------------------------------------------------------

/** Fields that identify an entry in an array of tables, in preference order. */
const IDENTITY_FIELDS: Record<string, string[][]> = {
  CURRENCIES: [['code', 'issuer'], ['code'], ['contract']],
  VALIDATORS: [['PUBLIC_KEY'], ['ALIAS']],
  PRINCIPALS: [['email'], ['name']],
};
const GENERIC_IDENTITY = [['code'], ['id'], ['name'], ['PUBLIC_KEY'], ['ALIAS']];

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === 'object' && value !== null && !Array.isArray(value) && !(value instanceof Date)
  );
}

/** Stable text form of a leaf, used both for equality and for display. */
function canonical(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  if (Array.isArray(value)) return `[${value.map(canonical).sort().join(',')}]`;
  if (isPlainObject(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${key}=${canonical(value[key])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

/** Choose a label per array-of-tables entry; fall back to position when ambiguous. */
function entryLabels(tableName: string, entries: Record<string, unknown>[]): string[] {
  const candidates = IDENTITY_FIELDS[tableName] ?? GENERIC_IDENTITY;
  for (const fields of candidates) {
    const labels = entries.map((entry) =>
      fields.every((field) => typeof entry[field] === 'string' || typeof entry[field] === 'number')
        ? fields.map((field) => `${field}=${String(entry[field])}`).join(',')
        : undefined,
    );
    if (labels.every((label) => label !== undefined) && new Set(labels).size === labels.length) {
      return labels as string[];
    }
  }
  return entries.map((_, index) => String(index));
}

/** Flatten a parsed document into `path → leaf value`. */
export function flattenToml(doc: Record<string, unknown>): Map<string, unknown> {
  const out = new Map<string, unknown>();
  const walk = (value: unknown, path: string, name: string): void => {
    if (isPlainObject(value)) {
      const keys = Object.keys(value);
      if (keys.length === 0 && path) out.set(path, {});
      for (const key of keys) walk(value[key], path ? `${path}.${key}` : key, key);
      return;
    }
    if (Array.isArray(value) && value.length > 0 && value.every(isPlainObject)) {
      const entries = value as Record<string, unknown>[];
      const labels = entryLabels(name, entries);
      entries.forEach((entry, index) => walk(entry, `${path}[${labels[index]}]`, name));
      return;
    }
    out.set(path, value);
  };
  walk(doc, '', '');
  return out;
}

interface PathChange {
  path: string;
  kind: ChangeKind;
  before?: unknown;
  after?: unknown;
}

/** Semantic differences from `before` to `after`, sorted by path. */
export function diffFlattened(
  before: Map<string, unknown>,
  after: Map<string, unknown>,
): PathChange[] {
  const changes: PathChange[] = [];
  const paths = new Set([...before.keys(), ...after.keys()]);
  for (const path of [...paths].sort()) {
    const had = before.has(path);
    const has = after.has(path);
    if (had && !has) changes.push({ path, kind: 'removed', before: before.get(path) });
    else if (!had && has) changes.push({ path, kind: 'added', after: after.get(path) });
    else if (canonical(before.get(path)) !== canonical(after.get(path))) {
      changes.push({ path, kind: 'changed', before: before.get(path), after: after.get(path) });
    }
  }
  return changes;
}

function parseOrThrow(source: string, code: DriftErrorCode, label: string): Map<string, unknown> {
  try {
    return flattenToml(parseToml(source) as Record<string, unknown>);
  } catch (error) {
    const reason = error instanceof Error ? error.message.split('\n')[0] : String(error);
    throw new DriftDetectionError(code, `${label} is not valid TOML: ${reason}`, { cause: error });
  }
}

function tryParse(source: string): Map<string, unknown> | undefined {
  try {
    return flattenToml(parseToml(source) as Record<string, unknown>);
  } catch {
    return undefined;
  }
}

/** Render a leaf as TOML-ish text for messages and the semantic diff. */
export function formatValue(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  if (Array.isArray(value)) return `[${value.map(formatValue).join(', ')}]`;
  if (isPlainObject(value)) {
    const keys = Object.keys(value);
    return keys.length === 0
      ? '{}'
      : `{ ${keys.map((k) => `${k} = ${formatValue(value[k])}`).join(', ')} }`;
  }
  return JSON.stringify(value);
}

/**
 * Three-way classification. With no base every difference is `diverged`,
 * because without history there is no way to say which side moved.
 */
export function classifyDrift(
  git: Map<string, unknown>,
  live: Map<string, unknown>,
  base?: Map<string, unknown>,
): DriftFinding[] {
  const findings: DriftFinding[] = [];
  const val = (map: Map<string, unknown> | undefined, path: string) =>
    map?.has(path) ? map.get(path) : undefined;
  const same = (a: Map<string, unknown>, b: Map<string, unknown>, path: string) =>
    a.has(path) === b.has(path) &&
    (!a.has(path) || canonical(a.get(path)) === canonical(b.get(path)));

  for (const change of diffFlattened(git, live)) {
    const { path } = change;
    const entry = {
      path,
      ...(git.has(path) ? { git: git.get(path) } : {}),
      ...(live.has(path) ? { live: live.get(path) } : {}),
      ...(base?.has(path) ? { base: base.get(path) } : {}),
    };

    let driftType: DriftType;
    let kind: ChangeKind;
    if (base && same(base, live, path)) {
      // Live still has the deployed value; Git moved on.
      driftType = 'unreleased';
      kind = !base.has(path) ? 'added' : !git.has(path) ? 'removed' : 'changed';
    } else if (base && same(base, git, path)) {
      // Git still has the deployed value; production was edited.
      driftType = 'uncommitted';
      kind = !base.has(path) ? 'added' : !live.has(path) ? 'removed' : 'changed';
    } else {
      // Read Git → live: "added" means live has a path Git lacks.
      driftType = 'diverged';
      kind = change.kind;
    }

    findings.push({
      ...entry,
      driftType,
      kind,
      severity: driftType === 'unreleased' ? 'warning' : 'error',
      message: describe(
        driftType,
        kind,
        path,
        val(git, path),
        val(live, path),
        git.has(path),
        live.has(path),
      ),
    });
  }
  return findings;
}

function describe(
  driftType: DriftType,
  kind: ChangeKind,
  path: string,
  gitValue: unknown,
  liveValue: unknown,
  inGit: boolean,
  inLive: boolean,
): string {
  if (driftType === 'unreleased') {
    if (kind === 'added') return `${path} was added in Git but is not deployed yet`;
    if (kind === 'removed') return `${path} was removed in Git but is still live`;
    return `${path} changed in Git to ${formatValue(gitValue)}; live still serves ${formatValue(liveValue)}`;
  }
  if (driftType === 'uncommitted') {
    if (kind === 'added') return `${path} was added on production but is not in Git`;
    if (kind === 'removed') return `${path} was removed on production but is still in Git`;
    return `${path} was changed on production to ${formatValue(liveValue)}; Git has ${formatValue(gitValue)}`;
  }
  if (!inGit) return `${path} exists on production but not in Git`;
  if (!inLive) return `${path} exists in Git but not on production`;
  return `${path} differs: Git has ${formatValue(gitValue)}, live serves ${formatValue(liveValue)}`;
}

// ---------------------------------------------------------------------------
// Git access
// ---------------------------------------------------------------------------

async function git(cwd: string, args: string[]): Promise<string> {
  const { stdout } = await run('git', args, { cwd, maxBuffer: 16 * 1024 * 1024 });
  return stdout;
}

/** Resolve `--git-path` to a concrete stellar.toml on disk. */
export async function resolveTomlPath(gitPath: string = process.cwd()): Promise<string> {
  const absolute = resolve(gitPath);
  let info;
  try {
    info = await stat(absolute);
  } catch {
    throw new DriftDetectionError('git-file-not-found', `Could not find ${gitPath}`);
  }
  if (info.isFile()) return absolute;
  for (const candidate of [
    join(absolute, '.well-known', 'stellar.toml'),
    join(absolute, 'stellar.toml'),
  ]) {
    try {
      if ((await stat(candidate)).isFile()) return candidate;
    } catch {
      /* try the next one */
    }
  }
  throw new DriftDetectionError(
    'git-file-not-found',
    `No stellar.toml found in ${gitPath} (looked for .well-known/stellar.toml and stellar.toml)`,
  );
}

interface GitContext {
  root: string;
  repoPath: string;
}

async function gitContext(file: string): Promise<GitContext | undefined> {
  try {
    const root = (await git(dirname(file), ['rev-parse', '--show-toplevel'])).trim();
    const repoPath = relative(await realpath(root), await realpath(file))
      .split(sep)
      .join('/');
    return { root, repoPath };
  } catch {
    return undefined;
  }
}

const LOG_FORMAT = '%H%x1f%h%x1f%cI%x1f%s';

function parseLog(stdout: string): CommitInfo[] {
  return stdout
    .split('\n')
    .filter(Boolean)
    .map((line) => {
      const [sha = '', shortSha = '', date = '', subject = ''] = line.split('\x1f');
      return { sha, shortSha, date, subject };
    });
}

async function showFile(ctx: GitContext, rev: string): Promise<string | undefined> {
  try {
    return await git(ctx.root, ['show', `${rev}:${ctx.repoPath}`]);
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// Detector
// ---------------------------------------------------------------------------

export class GitOpsDriftDetector {
  private readonly options: DriftDetectionOptions;

  constructor(options: DriftDetectionOptions = {}) {
    this.options = options;
  }

  /** Fetch live, read Git, locate the deployed revision, and classify every difference. */
  async detect(): Promise<DriftReport> {
    const { domain, url } = this.options;
    if (!domain && !url) {
      throw new DriftDetectionError('invalid-domain', 'A domain (or live URL) is required');
    }
    const liveUrl = url ?? liveUrlForDomain(domain!);
    const ref = this.options.ref ?? 'HEAD';
    const file = await resolveTomlPath(this.options.gitPath);
    const ctx = await gitContext(file);

    // Desired state: the file at `ref`, or the working copy outside Git.
    const workingCopy = await readFile(file, 'utf8');
    let gitSource = workingCopy;
    let head: CommitInfo | undefined;
    let history: CommitInfo[] = [];
    if (ctx) {
      const atRef = await showFile(ctx, ref);
      if (atRef !== undefined) {
        gitSource = atRef;
        head = parseLog(await git(ctx.root, ['log', '-1', `--format=${LOG_FORMAT}`, ref]))[0];
        const max = this.options.maxHistory ?? DEFAULT_MAX_HISTORY;
        history = parseLog(
          await git(ctx.root, [
            'log',
            `-n${max}`,
            `--format=${LOG_FORMAT}`,
            ref,
            '--',
            ctx.repoPath,
          ]),
        );
      }
    }
    const gitDoc = parseOrThrow(gitSource, 'unparseable-git', `${ctx?.repoPath ?? file} at ${ref}`);

    const liveSource = await fetchLiveToml(liveUrl, {
      ...(this.options.timeoutMs !== undefined ? { timeoutMs: this.options.timeoutMs } : {}),
      ...(this.options.fetch ? { fetch: this.options.fetch } : {}),
    });
    const liveDoc = parseOrThrow(liveSource, 'unparseable-live', liveUrl);

    // Find the deployed revision. `history[0]` is the newest commit touching the
    // file, whose content equals the file at `ref`, so start the search there.
    let deployed: CommitInfo | undefined;
    let deployedDoc: Map<string, unknown> | undefined;
    let deployedMatch: DeployedMatch = 'none';
    let deployedIndex = -1;
    if (ctx && history.length > 0) {
      let best: { index: number; distance: number; doc: Map<string, unknown> } | undefined;
      for (let index = 0; index < history.length; index++) {
        const source = index === 0 ? gitSource : await showFile(ctx, history[index]!.sha);
        const doc = source === undefined ? undefined : index === 0 ? gitDoc : tryParse(source);
        if (!doc) continue;
        const distance = diffFlattened(doc, liveDoc).length;
        if (!best || distance < best.distance) best = { index, distance, doc };
        if (distance === 0) break;
      }
      if (best) {
        deployedIndex = best.index;
        deployed = history[best.index];
        deployedDoc = best.doc;
        deployedMatch = best.distance === 0 ? 'exact' : 'closest';
      }
    }

    const findings = classifyDrift(gitDoc, liveDoc, deployedDoc);
    const count = (type: DriftType) => findings.filter((f) => f.driftType === type).length;
    // Commits newer than the deployed one only matter if something is unreleased.
    const unreleasedCommits = deployedIndex > 0 ? history.slice(0, deployedIndex) : [];

    return {
      status: findings.length === 0 ? 'in-sync' : 'drift',
      inSync: findings.length === 0,
      ...(domain ? { domain } : {}),
      liveUrl,
      checkedAt: (this.options.now?.() ?? new Date()).toISOString(),
      git: {
        file,
        ...(ctx ? { repoPath: ctx.repoPath } : {}),
        ref,
        ...(head ? { head } : {}),
        ...(deployed ? { deployed } : {}),
        deployedMatch,
        unreleasedCommits,
        workingTreeDirty: ctx !== undefined && head !== undefined && workingCopy !== gitSource,
      },
      summary: {
        total: findings.length,
        unreleased: count('unreleased'),
        uncommitted: count('uncommitted'),
        diverged: count('diverged'),
      },
      findings,
      sources: { git: gitSource, live: liveSource },
    };
  }
}

/** Convenience wrapper around {@link GitOpsDriftDetector}. */
export function detectDrift(options: DriftDetectionOptions): Promise<DriftReport> {
  return new GitOpsDriftDetector(options).detect();
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/** Structured alert payload for webhooks: the report minus the raw sources. */
export function renderDriftJson(report: DriftReport): string {
  const { sources: _sources, ...alert } = report;
  return `${JSON.stringify({ type: 'stellar-toml-drift', version: 1, ...alert }, jsonReplacer, 2)}\n`;
}

/** Error payload in the same envelope, so a webhook consumer sees one shape. */
export function renderDriftErrorJson(error: DriftDetectionError | Error, liveUrl?: string): string {
  return `${JSON.stringify(
    {
      type: 'stellar-toml-drift',
      version: 1,
      status: 'error',
      ...(liveUrl ? { liveUrl } : {}),
      error: {
        code: error instanceof DriftDetectionError ? error.code : 'unknown',
        message: error.message,
      },
    },
    null,
    2,
  )}\n`;
}

function jsonReplacer(_key: string, value: unknown): unknown {
  return value instanceof Date ? value.toISOString() : value;
}

/** Line-level unified diff of the Git file against the live file. */
export function renderDriftLineDiff(
  report: DriftReport,
  options: { color?: boolean } = {},
): string {
  return formatUnifiedDiff(
    report.git.repoPath ?? 'stellar.toml',
    report.sources.git,
    report.sources.live,
    options,
  );
}

const SECTION_TITLES: Record<DriftType, string> = {
  unreleased: 'unreleased: committed to Git, not deployed',
  uncommitted: 'uncommitted: changed on production, not in Git',
  diverged: 'diverged: changed on both sides',
};

/** Human report: header, unreleased commits, and a colorized git-style semantic diff. */
export function renderDriftText(report: DriftReport, options: { color?: boolean } = {}): string {
  const color = options.color ?? false;
  const paint = (code: number, reset: number) => (text: string) =>
    color ? `\x1b[${code}m${text}\x1b[${reset}m` : text;
  const red = paint(31, 39);
  const green = paint(32, 39);
  const yellow = paint(33, 39);
  const cyan = paint(36, 39);
  const bold = paint(1, 22);
  const dim = paint(2, 22);

  const { git: g } = report;
  const gitLabel = `${g.ref}${g.head ? ` (${g.head.shortSha})` : ''}:${g.repoPath ?? g.file}`;
  const out: string[] = [];
  out.push(bold(`GitOps drift check: ${report.liveUrl}`));
  out.push(`  Git:      ${gitLabel}`);
  if (g.deployed) {
    const how = g.deployedMatch === 'exact' ? 'exact match' : 'closest match';
    out.push(`  Deployed: ${g.deployed.shortSha} ${g.deployed.subject} ${dim(`(${how})`)}`);
  } else {
    out.push(`  Deployed: ${dim('unknown (no Git history for this file)')}`);
  }
  if (g.workingTreeDirty) {
    out.push(
      yellow(`  Note: working copy has local changes; compared ${g.ref}, not the working copy.`),
    );
  }

  if (report.inSync) {
    out.push('', green('✔ In sync: live stellar.toml matches Git.'));
    return `${out.join('\n')}\n`;
  }

  if (g.unreleasedCommits.length > 0) {
    out.push('', bold(`Unreleased commits (${g.unreleasedCommits.length}):`));
    for (const commit of g.unreleasedCommits) {
      out.push(`  ${yellow(commit.shortSha)} ${commit.date.slice(0, 10)} ${commit.subject}`);
    }
  }

  out.push(
    '',
    bold(`--- a/${g.repoPath ?? 'stellar.toml'} (git ${g.ref})`),
    bold(`+++ b/${report.liveUrl} (live)`),
  );
  for (const type of ['unreleased', 'uncommitted', 'diverged'] as const) {
    const section = report.findings.filter((f) => f.driftType === type);
    if (section.length === 0) continue;
    out.push(cyan(`@@ ${SECTION_TITLES[type]} (${section.length}) @@`));
    for (const finding of section) {
      if ('git' in finding) out.push(red(`-${finding.path} = ${formatValue(finding.git)}`));
      if ('live' in finding) out.push(green(`+${finding.path} = ${formatValue(finding.live)}`));
    }
  }

  const { summary } = report;
  const parts = [
    summary.unreleased ? `${summary.unreleased} unreleased` : '',
    summary.uncommitted ? `${summary.uncommitted} uncommitted` : '',
    summary.diverged ? `${summary.diverged} diverged` : '',
  ].filter(Boolean);
  out.push('', red(`✖ Drift detected: ${summary.total} difference(s) — ${parts.join(', ')}.`));
  if (summary.unreleased) out.push(dim('  Unreleased changes: re-run the deployment pipeline.'));
  if (summary.uncommitted || summary.diverged) {
    out.push(dim('  Out-of-band changes: commit them to Git, or redeploy to revert production.'));
  }
  return `${out.join('\n')}\n`;
}
