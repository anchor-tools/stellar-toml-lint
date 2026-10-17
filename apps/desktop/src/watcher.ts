/**
 * Folder watching with coalesced change batches (issue #371).
 *
 * Deliberately built on `node:fs` alone, with no `electron` import, so the
 * watching logic is testable without a browser process and reusable by the CLI
 * if it ever wants it.
 *
 * Two problems make a naive `fs.watch` handler wrong for this app:
 *
 * - **Editors do not write files, they replace them.** A save in VS Code, vim,
 *   or Sublime is a write to a temporary file followed by a rename over the
 *   original. The watcher sees a burst — `rename`, `change`, sometimes a
 *   `rename` of the temp file too — for what the user experienced as one
 *   keystroke. Linting on each event means linting a file that is half-written,
 *   reporting a parse error, and notifying about it. {@link createBatcher}
 *   collapses a burst into one batch after the writes stop.
 * - **A watched folder contains more than configuration.** `node_modules`, a
 *   `.git` directory, and an editor's own swap files all generate events, and a
 *   compliance officer's folder may contain thousands of them.
 *   {@link isLintableTomlPath} and {@link isIgnoredDirectory} keep the scan
 *   pointed at the files SEP-1 actually describes.
 *
 * The debounce window is the one tuning decision worth stating: 250ms is long
 * enough that an atomic-rename burst lands inside it and short enough that the
 * tray turns red while the user is still looking at the editor.
 */
import { readdirSync, statSync, watch, type FSWatcher } from 'node:fs';
import { basename, join, relative, sep } from 'node:path';

/** Default quiet period before a change batch is delivered, in milliseconds. */
export const DEFAULT_DEBOUNCE_MS = 250;

/** How deep the initial scan walks below the chosen folder. */
export const DEFAULT_MAX_DEPTH = 6;

/**
 * Directory names never walked or watched.
 *
 * `.well-known` is deliberately *not* here: it is exactly where a served
 * `stellar.toml` lives, and the whole point is to lint the file as deployed.
 */
export const IGNORED_DIRECTORIES: ReadonlySet<string> = new Set([
  'node_modules',
  '.git',
  '.hg',
  '.svn',
  'dist',
  'build',
  'out',
  'coverage',
  '.next',
  '.cache',
  '.venv',
  'vendor',
  'target',
]);

/** `true` when a directory should not be walked or watched. */
export function isIgnoredDirectory(name: string): boolean {
  return IGNORED_DIRECTORIES.has(name);
}

/**
 * `true` when a path is a file this app should lint.
 *
 * Any `.toml` counts, not only one named `stellar.toml`: anchors routinely keep
 * `stellar.staging.toml` beside the real one, and a linter that ignored it
 * would miss the file most likely to be broken. Editor temporaries and the
 * dotfiles that pile up beside a real file are excluded — a `.stellar.toml.swp`
 * is vim's business, and linting a `~`-suffixed backup reports problems in a
 * file nobody is going to deploy.
 */
export function isLintableTomlPath(path: string): boolean {
  const name = basename(path);
  if (name.startsWith('.')) return false;
  if (name.endsWith('~')) return false;
  // Atomic-save temporaries: `stellar.toml.tmp`, `4913`, `.#stellar.toml`.
  if (/\.(tmp|swp|swx|bak|orig|rej)$/i.test(name)) return false;
  return name.toLowerCase().endsWith('.toml');
}

/**
 * Collapses a burst of items into one batch once they stop arriving.
 *
 * The scheduler is injected so a test can drive it without waiting: passing
 * `setTimeout`/`clearTimeout` is the production case, and a fake pair makes the
 * debounce deterministic. Items are de-duplicated, because a single save
 * genuinely does produce the same path several times.
 */
export interface Batcher<T> {
  /** Adds an item and (re)starts the quiet period. */
  push(item: T): void;
  /** Delivers whatever has accumulated, immediately. */
  flush(): void;
  /** Drops what has accumulated without delivering it. */
  cancel(): void;
  /** Items currently waiting. */
  pending(): T[];
}

/** Timer functions {@link createBatcher} needs, so tests can supply their own. */
export interface Scheduler {
  setTimeout(callback: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

const realScheduler: Scheduler = {
  setTimeout: (callback, ms) => setTimeout(callback, ms),
  clearTimeout: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>),
};

export function createBatcher<T>(
  debounceMs: number,
  deliver: (batch: T[]) => void,
  scheduler: Scheduler = realScheduler,
): Batcher<T> {
  // A Set, so one save reported three times becomes one entry.
  let waiting = new Set<T>();
  let handle: unknown;

  const stop = (): void => {
    if (handle !== undefined) {
      scheduler.clearTimeout(handle);
      handle = undefined;
    }
  };

  const flush = (): void => {
    stop();
    if (waiting.size === 0) return;
    const batch = [...waiting];
    waiting = new Set<T>();
    deliver(batch);
  };

  return {
    push(item: T): void {
      waiting.add(item);
      // Restart the window on every item: the batch is delivered once the
      // writes go quiet, not a fixed time after the first one.
      stop();
      handle = scheduler.setTimeout(flush, debounceMs);
    },
    flush,
    cancel(): void {
      stop();
      waiting = new Set<T>();
    },
    pending(): T[] {
      return [...waiting];
    },
  };
}

/**
 * Lists the lintable TOML files under `directory`.
 *
 * Synchronous on purpose: it runs once when a folder is chosen, off the frame
 * path, and an async walk here would buy nothing but a more complicated
 * cancellation story. Unreadable entries are skipped rather than thrown —
 * a folder the user picked may contain something they cannot read, and that is
 * not a reason to refuse the whole folder.
 */
export function findTomlFiles(directory: string, maxDepth: number = DEFAULT_MAX_DEPTH): string[] {
  const found: string[] = [];

  const walk = (dir: string, depth: number): void => {
    if (depth > maxDepth) return;

    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }

    for (const entry of entries) {
      const path = join(dir, entry);
      let isDirectory: boolean;
      try {
        isDirectory = statSync(path).isDirectory();
      } catch {
        continue;
      }

      if (isDirectory) {
        if (!isIgnoredDirectory(entry)) walk(path, depth + 1);
        continue;
      }
      if (isLintableTomlPath(path)) found.push(path);
    }
  };

  walk(directory, 0);
  return found.sort();
}

/**
 * `true` when a path reported by a recursive watch is one we care about.
 *
 * A recursive `fs.watch` reports paths relative to the watched root, including
 * events from directories we chose not to walk. Filtering here rather than in
 * the handler keeps `node_modules` churn from waking the linter at all.
 */
export function isRelevantChange(root: string, changed: string): boolean {
  const rel = relative(root, changed);
  // `..` means the event escaped the watched root; ignore it.
  if (rel.startsWith('..')) return false;

  const segments = rel.split(sep);
  const directories = segments.slice(0, -1);
  if (directories.some(isIgnoredDirectory)) return false;

  return isLintableTomlPath(changed);
}

/** What a {@link DirectoryWatcher} needs to run. */
export interface WatcherOptions {
  /** Absolute path of the folder to watch. */
  directory: string;
  /** Called with the absolute paths that changed, once writes go quiet. */
  onChange: (paths: string[]) => void;
  /** Called when the watch itself fails, e.g. the folder was deleted. */
  onError?: (error: Error) => void;
  debounceMs?: number;
  /** `fs.watch`, injectable so tests need no real filesystem events. */
  watchImpl?: typeof watch;
  scheduler?: Scheduler;
}

/**
 * Watches one folder recursively and reports coalesced batches of TOML changes.
 *
 * Recursive `fs.watch` is supported natively on macOS and Windows and, since
 * Node 20, on Linux too. When the platform refuses the recursive flag the
 * watcher falls back to watching the chosen folder non-recursively rather than
 * failing outright: a compliance officer who keeps `stellar.toml` in one
 * directory — the common case — still gets what they came for, and
 * {@link DirectoryWatcher.recursive} says which mode is in effect so the UI can
 * be honest about it.
 */
export class DirectoryWatcher {
  /** `false` when the platform rejected a recursive watch and we fell back. */
  recursive = true;

  private watcher: FSWatcher | undefined;
  private readonly batcher: Batcher<string>;
  private readonly options: WatcherOptions;
  private readonly watchImpl: typeof watch;

  constructor(options: WatcherOptions) {
    this.options = options;
    this.watchImpl = options.watchImpl ?? watch;
    this.batcher = createBatcher<string>(
      options.debounceMs ?? DEFAULT_DEBOUNCE_MS,
      (paths) => options.onChange(paths),
      options.scheduler,
    );
  }

  /** Begins watching. Safe to call twice; the second call is a no-op. */
  start(): void {
    if (this.watcher !== undefined) return;

    const handle = (_event: unknown, filename: string | Buffer | null): void => {
      if (filename === null) return;
      const name = typeof filename === 'string' ? filename : filename.toString('utf8');
      const absolute = join(this.options.directory, name);
      if (!isRelevantChange(this.options.directory, absolute)) return;
      this.batcher.push(absolute);
    };

    try {
      this.watcher = this.watchImpl(this.options.directory, { recursive: true }, handle);
    } catch {
      this.recursive = false;
      try {
        this.watcher = this.watchImpl(this.options.directory, handle);
      } catch (error) {
        this.options.onError?.(error instanceof Error ? error : new Error(String(error)));
        return;
      }
    }

    this.watcher.on('error', (error: Error) => {
      this.options.onError?.(error);
    });
  }

  /** Stops watching and drops any batch still waiting. */
  stop(): void {
    this.batcher.cancel();
    this.watcher?.close();
    this.watcher = undefined;
  }

  /** Delivers a waiting batch now, rather than when the window elapses. */
  flush(): void {
    this.batcher.flush();
  }
}
