import { afterEach, describe, expect, it } from 'vitest';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { FSWatcher, watch as watchFn } from 'node:fs';
import {
  DEFAULT_DEBOUNCE_MS,
  DirectoryWatcher,
  createBatcher,
  findTomlFiles,
  isIgnoredDirectory,
  isLintableTomlPath,
  isRelevantChange,
  type Scheduler,
} from '../../apps/desktop/src/watcher.js';
import {
  MAX_NOTIFICATIONS,
  notificationsFor,
  totalsFor,
  tooltipFor,
  trayStateFor,
  type ScanSnapshot,
} from '../../apps/desktop/src/status.js';
import { mergeScan, scanFiles } from '../../apps/desktop/src/scanner.js';
import { lint } from '../../src/lint.js';

const temporaries: string[] = [];

afterEach(() => {
  for (const dir of temporaries.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function workspace(): string {
  const dir = mkdtempSync(join(tmpdir(), 'stellar-desktop-'));
  temporaries.push(dir);
  return dir;
}

/** A scheduler whose timers fire only when the test says so. */
function manualScheduler(): Scheduler & { tick(): void; pending: number } {
  let queued: (() => void) | undefined;
  return {
    setTimeout(callback: () => void) {
      queued = callback;
      return 1;
    },
    clearTimeout() {
      queued = undefined;
    },
    tick() {
      const run = queued;
      queued = undefined;
      run?.();
    },
    get pending() {
      return queued === undefined ? 0 : 1;
    },
  };
}

/** A snapshot literal, with the timestamp filled in. */
function snapshot(files: Array<[string, number, number?, boolean?]>): ScanSnapshot {
  return {
    files: files.map(([path, errors, warnings = 0, unreadable]) => ({
      path,
      errors,
      warnings,
      ...(unreadable === undefined ? {} : { unreadable }),
    })),
    scannedAt: 1_700_000_000_000,
  };
}

/* ------------------------------------------------------------------ *
 * Which files are watched
 * ------------------------------------------------------------------ */

describe('file selection', () => {
  it('accepts any .toml, not only one named stellar.toml', () => {
    // Anchors keep `stellar.staging.toml` beside the real one, and that is
    // the file most likely to be broken.
    expect(isLintableTomlPath('/a/stellar.toml')).toBe(true);
    expect(isLintableTomlPath('/a/stellar.staging.toml')).toBe(true);
    expect(isLintableTomlPath('/a/.well-known/stellar.toml')).toBe(true);
    expect(isLintableTomlPath('/a/STELLAR.TOML')).toBe(true);
  });

  it('ignores editor temporaries and backups', () => {
    // Linting a half-written atomic-save temp file is how a watcher ends up
    // notifying about a parse error that never existed.
    for (const path of [
      '/a/stellar.toml.tmp',
      '/a/stellar.toml.swp',
      '/a/stellar.toml.bak',
      '/a/stellar.toml~',
      '/a/.stellar.toml',
      '/a/.#stellar.toml',
      '/a/stellar.toml.orig',
    ]) {
      expect(isLintableTomlPath(path)).toBe(false);
    }
  });

  it('ignores files that are not TOML at all', () => {
    expect(isLintableTomlPath('/a/README.md')).toBe(false);
    expect(isLintableTomlPath('/a/tomlish')).toBe(false);
  });

  it('skips the directories that generate churn but hold no config', () => {
    expect(isIgnoredDirectory('node_modules')).toBe(true);
    expect(isIgnoredDirectory('.git')).toBe(true);
    expect(isIgnoredDirectory('dist')).toBe(true);
    // `.well-known` is exactly where a served stellar.toml lives.
    expect(isIgnoredDirectory('.well-known')).toBe(false);
    expect(isIgnoredDirectory('config')).toBe(false);
  });

  it('judges a change by its directory as well as its name', () => {
    const root = '/watch';
    expect(isRelevantChange(root, '/watch/stellar.toml')).toBe(true);
    expect(isRelevantChange(root, '/watch/public/.well-known/stellar.toml')).toBe(true);
    expect(isRelevantChange(root, '/watch/node_modules/pkg/stellar.toml')).toBe(false);
    expect(isRelevantChange(root, '/watch/.git/stellar.toml')).toBe(false);
    expect(isRelevantChange(root, '/watch/README.md')).toBe(false);
    // An event that escaped the watched root.
    expect(isRelevantChange(root, '/elsewhere/stellar.toml')).toBe(false);
  });

  it('walks a real folder, skipping the ignored directories', () => {
    const dir = workspace();
    mkdirSync(join(dir, 'public', '.well-known'), { recursive: true });
    mkdirSync(join(dir, 'node_modules', 'pkg'), { recursive: true });
    writeFileSync(join(dir, 'stellar.toml'), 'VERSION = "2.0.0"\n');
    writeFileSync(join(dir, 'public', '.well-known', 'stellar.toml'), 'VERSION = "2.0.0"\n');
    writeFileSync(join(dir, 'node_modules', 'pkg', 'stellar.toml'), 'VERSION = "2.0.0"\n');
    writeFileSync(join(dir, 'notes.md'), '# notes\n');

    const found = findTomlFiles(dir);
    expect(found).toHaveLength(2);
    expect(found.some((path) => path.includes('node_modules'))).toBe(false);
  });

  it('returns nothing for a folder it cannot read, rather than throwing', () => {
    expect(findTomlFiles(join(workspace(), 'does-not-exist'))).toEqual([]);
  });

  it('stops at the depth limit', () => {
    const dir = workspace();
    const deep = join(dir, 'a', 'b', 'c', 'd', 'e', 'f', 'g');
    mkdirSync(deep, { recursive: true });
    writeFileSync(join(deep, 'stellar.toml'), 'VERSION = "2.0.0"\n');
    expect(findTomlFiles(dir, 2)).toEqual([]);
    expect(findTomlFiles(dir, 10)).toHaveLength(1);
  });
});

/* ------------------------------------------------------------------ *
 * Debouncing
 * ------------------------------------------------------------------ */

describe('change batching', () => {
  it('collapses an atomic-save burst into one batch', () => {
    // A single save in a real editor is a write, a rename, and often a second
    // rename. Linting each one would lint a half-written file.
    const scheduler = manualScheduler();
    const batches: string[][] = [];
    const batcher = createBatcher<string>(250, (batch) => batches.push(batch), scheduler);

    batcher.push('/a/stellar.toml');
    batcher.push('/a/stellar.toml');
    batcher.push('/a/stellar.toml');
    expect(batches).toEqual([]);

    scheduler.tick();
    expect(batches).toEqual([['/a/stellar.toml']]);
  });

  it('keeps distinct files in one batch', () => {
    const scheduler = manualScheduler();
    const batches: string[][] = [];
    const batcher = createBatcher<string>(250, (batch) => batches.push(batch), scheduler);

    batcher.push('/a/one.toml');
    batcher.push('/a/two.toml');
    scheduler.tick();

    expect(batches).toEqual([['/a/one.toml', '/a/two.toml']]);
  });

  it('restarts the quiet period on each new item', () => {
    // The batch is delivered once writes stop, not a fixed time after the
    // first one — otherwise a long save would be split across two lints.
    const scheduler = manualScheduler();
    const batches: string[][] = [];
    const batcher = createBatcher<string>(250, (batch) => batches.push(batch), scheduler);

    batcher.push('/a/one.toml');
    expect(scheduler.pending).toBe(1);
    batcher.push('/a/two.toml');
    expect(scheduler.pending).toBe(1);
    scheduler.tick();

    expect(batches).toHaveLength(1);
  });

  it('delivers nothing when nothing accumulated', () => {
    const scheduler = manualScheduler();
    const batches: string[][] = [];
    const batcher = createBatcher<string>(250, (batch) => batches.push(batch), scheduler);
    batcher.flush();
    expect(batches).toEqual([]);
  });

  it('can be flushed early and cancelled outright', () => {
    const scheduler = manualScheduler();
    const batches: string[][] = [];
    const batcher = createBatcher<string>(250, (batch) => batches.push(batch), scheduler);

    batcher.push('/a/one.toml');
    batcher.flush();
    expect(batches).toEqual([['/a/one.toml']]);

    batcher.push('/a/two.toml');
    expect(batcher.pending()).toEqual(['/a/two.toml']);
    batcher.cancel();
    scheduler.tick();
    expect(batches).toHaveLength(1);
  });

  it('starts a fresh batch after delivering one', () => {
    const scheduler = manualScheduler();
    const batches: string[][] = [];
    const batcher = createBatcher<string>(250, (batch) => batches.push(batch), scheduler);

    batcher.push('/a/one.toml');
    scheduler.tick();
    batcher.push('/a/two.toml');
    scheduler.tick();

    expect(batches).toEqual([['/a/one.toml'], ['/a/two.toml']]);
  });

  it('uses a debounce long enough to absorb a save and short enough to notice', () => {
    expect(DEFAULT_DEBOUNCE_MS).toBeGreaterThanOrEqual(100);
    expect(DEFAULT_DEBOUNCE_MS).toBeLessThanOrEqual(1_000);
  });
});

/* ------------------------------------------------------------------ *
 * The watcher
 * ------------------------------------------------------------------ */

describe('DirectoryWatcher', () => {
  /** A fake `fs.watch` that lets a test emit events by hand. */
  function fakeWatch(): {
    impl: typeof watchFn;
    emit(filename: string): void;
    calls: Array<{ recursive: boolean }>;
    closed: boolean;
  } {
    const state = { handler: undefined as ((e: string, f: string) => void) | undefined };
    const calls: Array<{ recursive: boolean }> = [];
    const result = { closed: false };

    const impl = ((_path: string, a: unknown, b?: unknown) => {
      const recursive =
        typeof a === 'object' && a !== null && (a as { recursive?: boolean }).recursive === true;
      calls.push({ recursive });
      state.handler = (typeof a === 'function' ? a : b) as (e: string, f: string) => void;
      return {
        close() {
          result.closed = true;
        },
        on() {
          return this;
        },
      } as unknown as FSWatcher;
    }) as typeof watchFn;

    return {
      impl,
      emit: (filename: string) => state.handler?.('change', filename),
      calls,
      get closed() {
        return result.closed;
      },
    };
  }

  it('reports a relevant change after the quiet period', () => {
    const scheduler = manualScheduler();
    const watch = fakeWatch();
    const seen: string[][] = [];

    const watcher = new DirectoryWatcher({
      directory: '/watch',
      onChange: (paths) => seen.push(paths),
      watchImpl: watch.impl,
      scheduler,
    });
    watcher.start();

    watch.emit('stellar.toml');
    expect(seen).toEqual([]);
    scheduler.tick();

    expect(seen).toEqual([[join('/watch', 'stellar.toml')]]);
  });

  it('never wakes the linter for an irrelevant change', () => {
    const scheduler = manualScheduler();
    const watch = fakeWatch();
    const seen: string[][] = [];

    const watcher = new DirectoryWatcher({
      directory: '/watch',
      onChange: (paths) => seen.push(paths),
      watchImpl: watch.impl,
      scheduler,
    });
    watcher.start();

    watch.emit('README.md');
    watch.emit(join('node_modules', 'pkg', 'stellar.toml'));
    watch.emit('stellar.toml.swp');
    scheduler.tick();

    expect(seen).toEqual([]);
  });

  it('asks for a recursive watch', () => {
    const watch = fakeWatch();
    const watcher = new DirectoryWatcher({
      directory: '/watch',
      onChange: () => {},
      watchImpl: watch.impl,
      scheduler: manualScheduler(),
    });
    watcher.start();

    expect(watch.calls[0]?.recursive).toBe(true);
    expect(watcher.recursive).toBe(true);
  });

  it('falls back to a flat watch when the platform refuses recursion', () => {
    // Better to watch the chosen folder only — the common case — than to
    // refuse to watch anything.
    let first = true;
    const calls: Array<{ recursive: boolean }> = [];
    const impl = ((_path: string, a: unknown) => {
      const recursive =
        typeof a === 'object' && a !== null && (a as { recursive?: boolean }).recursive === true;
      calls.push({ recursive });
      if (first) {
        first = false;
        throw new Error('ERR_FEATURE_UNAVAILABLE_ON_PLATFORM');
      }
      return { close() {}, on() {} } as unknown as FSWatcher;
    }) as typeof watchFn;

    const watcher = new DirectoryWatcher({
      directory: '/watch',
      onChange: () => {},
      watchImpl: impl,
      scheduler: manualScheduler(),
    });
    watcher.start();

    expect(calls).toHaveLength(2);
    expect(watcher.recursive).toBe(false);
  });

  it('reports a watch that cannot be established at all', () => {
    const errors: Error[] = [];
    const impl = (() => {
      throw new Error('ENOENT: no such directory');
    }) as unknown as typeof watchFn;

    new DirectoryWatcher({
      directory: '/gone',
      onChange: () => {},
      onError: (error) => errors.push(error),
      watchImpl: impl,
      scheduler: manualScheduler(),
    }).start();

    expect(errors).toHaveLength(1);
    expect(errors[0]?.message).toContain('ENOENT');
  });

  it('closes the underlying watch and drops a pending batch on stop', () => {
    const scheduler = manualScheduler();
    const watch = fakeWatch();
    const seen: string[][] = [];

    const watcher = new DirectoryWatcher({
      directory: '/watch',
      onChange: (paths) => seen.push(paths),
      watchImpl: watch.impl,
      scheduler,
    });
    watcher.start();
    watch.emit('stellar.toml');
    watcher.stop();
    scheduler.tick();

    expect(watch.closed).toBe(true);
    expect(seen).toEqual([]);
  });

  it('is idempotent on start', () => {
    const watch = fakeWatch();
    const watcher = new DirectoryWatcher({
      directory: '/watch',
      onChange: () => {},
      watchImpl: watch.impl,
      scheduler: manualScheduler(),
    });
    watcher.start();
    watcher.start();
    expect(watch.calls).toHaveLength(1);
  });
});

/* ------------------------------------------------------------------ *
 * Scanning
 * ------------------------------------------------------------------ */

describe('scanning', () => {
  const lintSource = (source: string) => {
    const result = lint(source);
    return { errors: result.counts.error, warnings: result.counts.warning };
  };

  it('counts errors and warnings from the real linter', () => {
    const files = { '/a/broken.toml': 'VERSION = "2.0.0"\nORG_URL = "not a url"\n' };
    const result = scanFiles(
      Object.keys(files),
      (path) => files[path as keyof typeof files],
      lintSource,
      () => 1,
    );

    expect(result.files).toHaveLength(1);
    expect(result.scannedAt).toBe(1);
    expect((result.files[0]?.errors ?? 0) + (result.files[0]?.warnings ?? 0)).toBeGreaterThan(0);
  });

  it('marks a file it cannot read as unreadable, not as clean', () => {
    // Zero diagnostics because the file vanished must not render as a green
    // tray — that inverts the signal the app exists to give.
    const result = scanFiles(
      ['/a/gone.toml'],
      () => {
        throw new Error('ENOENT');
      },
      lintSource,
    );

    expect(result.files[0]?.unreadable).toBe(true);
    expect(trayStateFor(result)).toBe('error');
  });

  it('survives a linter that throws', () => {
    const result = scanFiles(
      ['/a/x.toml'],
      () => 'VERSION = "2.0.0"',
      () => {
        throw new Error('rule exploded');
      },
    );
    expect(result.files[0]?.unreadable).toBe(true);
  });

  it('returns entries in a stable order', () => {
    const result = scanFiles(
      ['/a/z.toml', '/a/a.toml', '/a/m.toml'],
      () => 'VERSION = "2.0.0"',
      lintSource,
    );
    expect(result.files.map((file) => file.path)).toEqual(['/a/a.toml', '/a/m.toml', '/a/z.toml']);
  });

  it('merges a partial rescan into the previous snapshot', () => {
    // A save touches one file; re-linting 200 would make the app unusable.
    const previous = snapshot([
      ['/a/one.toml', 0],
      ['/a/two.toml', 0],
    ]);
    const rescanned = snapshot([['/a/two.toml', 3]]);

    const merged = mergeScan(previous, rescanned, () => true);

    expect(merged.files).toHaveLength(2);
    expect(merged.files.find((f) => f.path === '/a/one.toml')?.errors).toBe(0);
    expect(merged.files.find((f) => f.path === '/a/two.toml')?.errors).toBe(3);
  });

  it('drops a file that was deleted rather than calling it broken', () => {
    const previous = snapshot([
      ['/a/one.toml', 0],
      ['/a/two.toml', 0],
    ]);
    const rescanned = snapshot([['/a/two.toml', 0, 0, true]]);

    const merged = mergeScan(previous, rescanned, (path) => path !== '/a/two.toml');

    expect(merged.files.map((f) => f.path)).toEqual(['/a/one.toml']);
  });

  it('adds a file that appeared since the last scan', () => {
    const merged = mergeScan(
      snapshot([['/a/one.toml', 0]]),
      snapshot([['/a/new.toml', 2]]),
      () => true,
    );
    expect(merged.files.map((f) => f.path)).toEqual(['/a/new.toml', '/a/one.toml']);
  });
});

/* ------------------------------------------------------------------ *
 * Tray state and tooltip
 * ------------------------------------------------------------------ */

describe('tray state', () => {
  it('is idle before a folder is chosen', () => {
    // Not `ok`: a green check on an app watching nothing would be a lie.
    expect(trayStateFor(undefined)).toBe('idle');
  });

  it('is green when everything is clean', () => {
    expect(trayStateFor(snapshot([['/a/one.toml', 0]]))).toBe('ok');
    expect(trayStateFor(snapshot([]))).toBe('ok');
  });

  it('is amber for warnings only and red for any error', () => {
    expect(trayStateFor(snapshot([['/a/one.toml', 0, 4]]))).toBe('warning');
    expect(trayStateFor(snapshot([['/a/one.toml', 1, 0]]))).toBe('error');
    expect(
      trayStateFor(
        snapshot([
          ['/a/one.toml', 0, 9],
          ['/a/two.toml', 1],
        ]),
      ),
    ).toBe('error');
  });

  it('counts an unreadable file as an error', () => {
    expect(trayStateFor(snapshot([['/a/one.toml', 0, 0, true]]))).toBe('error');
  });

  it('sums a snapshot', () => {
    const totals = totalsFor(
      snapshot([
        ['/a/one.toml', 2, 1],
        ['/a/two.toml', 0, 3],
        ['/a/three.toml', 0, 0, true],
      ]),
    );
    expect(totals).toEqual({
      files: 3,
      errors: 2,
      warnings: 4,
      filesWithErrors: 1,
      unreadable: 1,
    });
  });
});

describe('tray tooltip', () => {
  it('says what is being watched, in words', () => {
    expect(tooltipFor(undefined, 'App')).toBe('App — no folder watched');
    expect(tooltipFor(snapshot([]), 'App')).toBe('App — no stellar.toml found');
    expect(tooltipFor(snapshot([['/a/one.toml', 0]]), 'App')).toBe('App — 1 file, no problems');
  });

  it('names the counts when there are problems', () => {
    expect(tooltipFor(snapshot([['/a/one.toml', 2, 1]]), 'App')).toBe(
      'App — 1 file, 2 errors, 1 warning',
    );
    expect(tooltipFor(snapshot([['/a/one.toml', 0, 0, true]]), 'App')).toBe(
      'App — 1 file, 1 file unreadable',
    );
  });

  it('pluralises', () => {
    expect(tooltipFor(snapshot([['/a/one.toml', 1]]), 'App')).toContain('1 error');
    expect(tooltipFor(snapshot([['/a/one.toml', 2]]), 'App')).toContain('2 errors');
  });
});

/* ------------------------------------------------------------------ *
 * Notification policy
 * ------------------------------------------------------------------ */

describe('notifications', () => {
  it('fires when a change introduces an error', () => {
    // The behaviour the issue asks for, stated exactly.
    const notices = notificationsFor(
      snapshot([['/a/stellar.toml', 0]]),
      snapshot([['/a/stellar.toml', 2]]),
    );

    expect(notices).toHaveLength(1);
    expect(notices[0]?.title).toBe('stellar.toml now has errors');
    expect(notices[0]?.body).toContain('stellar.toml');
    expect(notices[0]?.body).toContain('2 errors');
    expect(notices[0]?.path).toBe('/a/stellar.toml');
    expect(notices[0]?.resolved).toBe(false);
  });

  it('says nothing when the errors are unchanged', () => {
    // The single most important case: a watcher that re-notifies on every scan
    // is a watcher the user mutes within the hour.
    const broken = snapshot([['/a/stellar.toml', 3]]);
    expect(notificationsFor(broken, broken)).toEqual([]);
    expect(notificationsFor(broken, snapshot([['/a/stellar.toml', 3]]))).toEqual([]);
  });

  it('says nothing when a clean file stays clean', () => {
    const clean = snapshot([['/a/stellar.toml', 0, 5]]);
    expect(notificationsFor(clean, clean)).toEqual([]);
  });

  it('fires again when the error count grows', () => {
    const notices = notificationsFor(
      snapshot([['/a/stellar.toml', 1]]),
      snapshot([['/a/stellar.toml', 4]]),
    );
    expect(notices[0]?.title).toBe('stellar.toml has more errors');
  });

  it('stays quiet when the error count shrinks but is not yet zero', () => {
    // Progress the user is already watching; interrupting them is not help.
    expect(
      notificationsFor(snapshot([['/a/stellar.toml', 4]]), snapshot([['/a/stellar.toml', 1]])),
    ).toEqual([]);
  });

  it('announces a full recovery once', () => {
    const notices = notificationsFor(
      snapshot([['/a/stellar.toml', 2]]),
      snapshot([['/a/stellar.toml', 0]]),
    );
    expect(notices).toHaveLength(1);
    expect(notices[0]?.resolved).toBe(true);
    expect(notices[0]?.title).toContain('resolved');
  });

  it('treats a file that stopped parsing as a new error, not a fix', () => {
    // An unparseable file reports zero diagnostics. Without the weighting,
    // breaking the TOML syntax would look like fixing every error in it.
    const notices = notificationsFor(
      snapshot([['/a/stellar.toml', 2]]),
      snapshot([['/a/stellar.toml', 0, 0, true]]),
    );
    expect(notices).toEqual([]);

    const fromClean = notificationsFor(
      snapshot([['/a/stellar.toml', 0]]),
      snapshot([['/a/stellar.toml', 0, 0, true]]),
    );
    expect(fromClean).toHaveLength(1);
    expect(fromClean[0]?.body).toContain('could not be parsed');
  });

  it('reports already-broken files on the first scan after choosing a folder', () => {
    // The user just pointed the app here; "this one is broken" is the answer
    // they asked for.
    const notices = notificationsFor(undefined, snapshot([['/a/stellar.toml', 1]]));
    expect(notices).toHaveLength(1);
  });

  it('says nothing about a folder that was already clean', () => {
    expect(notificationsFor(undefined, snapshot([['/a/stellar.toml', 0]]))).toEqual([]);
  });

  it('notifies per file when several break at once, up to the cap', () => {
    const notices = notificationsFor(
      snapshot([
        ['/a/one.toml', 0],
        ['/a/two.toml', 0],
      ]),
      snapshot([
        ['/a/one.toml', 1],
        ['/a/two.toml', 1],
      ]),
    );
    expect(notices).toHaveLength(2);
    expect(notices.map((n) => n.path)).toEqual(['/a/one.toml', '/a/two.toml']);
  });

  it('collapses a mass breakage into one notice rather than a toast storm', () => {
    // Fifty files breaking at once is a `git checkout`, not fifty problems.
    const before = Array.from({ length: 50 }, (_, i) => [`/a/f${i}.toml`, 0] as [string, number]);
    const after = Array.from({ length: 50 }, (_, i) => [`/a/f${i}.toml`, 1] as [string, number]);

    const notices = notificationsFor(snapshot(before), snapshot(after));

    expect(notices).toHaveLength(1);
    expect(notices[0]?.title).toContain('50 files');
    expect(MAX_NOTIFICATIONS).toBeGreaterThan(0);
  });

  it('ignores warnings entirely', () => {
    // Warnings are what the tray badge and the window are for.
    expect(
      notificationsFor(snapshot([['/a/one.toml', 0, 0]]), snapshot([['/a/one.toml', 0, 20]])),
    ).toEqual([]);
  });

  it('ignores a file that is new but clean', () => {
    expect(notificationsFor(snapshot([]), snapshot([['/a/new.toml', 0]]))).toEqual([]);
  });

  it('notifies about a file that is new and broken', () => {
    const notices = notificationsFor(snapshot([]), snapshot([['/a/new.toml', 1]]));
    expect(notices).toHaveLength(1);
    expect(notices[0]?.path).toBe('/a/new.toml');
  });
});

/* ------------------------------------------------------------------ *
 * End to end, on a real folder
 * ------------------------------------------------------------------ */

describe('watching a real folder', () => {
  const lintSource = (source: string) => {
    const result = lint(source);
    return { errors: result.counts.error, warnings: result.counts.warning };
  };

  it('turns a clean folder green and a broken edit red, notifying once', async () => {
    const dir = workspace();
    const file = join(dir, 'stellar.toml');
    const { readFileSync } = await import('node:fs');
    // Without an encoding `readFileSync` returns a Buffer, which `lint()`
    // cannot read — the same mistake the main process has to avoid.
    const readText = (path: string): string => readFileSync(path, 'utf8');

    writeFileSync(
      file,
      [
        'VERSION = "2.0.0"',
        'NETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"',
        '',
        '[DOCUMENTATION]',
        'ORG_NAME = "Example"',
        'ORG_URL = "https://example.com"',
        'ORG_LOGO = "https://example.com/logo.png"',
        'ORG_DESCRIPTION = "An example anchor used to exercise the desktop watcher."',
        'ORG_OFFICIAL_EMAIL = "ops@example.com"',
      ].join('\n'),
    );

    const clean = scanFiles(findTomlFiles(dir), readText, lintSource);
    expect(clean.files).toHaveLength(1);
    expect(clean.files[0]?.errors).toBe(0);
    expect(trayStateFor(clean)).toBe('ok');
    expect(notificationsFor(undefined, clean)).toEqual([]);

    // The change a compliance officer would make and regret: plain http.
    writeFileSync(
      file,
      [
        'VERSION = "2.0.0"',
        'NETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"',
        '',
        '[DOCUMENTATION]',
        'ORG_NAME = "Example"',
        'ORG_URL = "http://example.com"',
        'ORG_LOGO = "https://example.com/logo.png"',
        'ORG_DESCRIPTION = "An example anchor used to exercise the desktop watcher."',
        'ORG_OFFICIAL_EMAIL = "ops@example.com"',
      ].join('\n'),
    );

    const broken = scanFiles(findTomlFiles(dir), readText, lintSource);
    expect(broken.files[0]?.errors).toBeGreaterThan(0);
    expect(trayStateFor(broken)).toBe('error');

    const notices = notificationsFor(clean, broken);
    expect(notices).toHaveLength(1);
    expect(notices[0]?.resolved).toBe(false);

    // Scanning again without editing must stay silent.
    const again = scanFiles(findTomlFiles(dir), readText, lintSource);
    expect(notificationsFor(broken, again)).toEqual([]);
  });
});
