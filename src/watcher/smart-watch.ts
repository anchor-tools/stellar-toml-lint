import { watch, type FSWatcher } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

export interface SmartWatchOptions {
  runOffline(paths: string[]): Promise<unknown>;
  runNetwork?(paths: string[]): Promise<unknown>;
  onError?(path: string, error: unknown): void;
  onRun?(phase: 'offline' | 'network', paths: string[]): void;
  debounceMs?: number;
  idleMs?: number;
}

export interface SmartWatch {
  close(): void;
  notifyChange(path: string): void;
}

/** Tracks actual source changes so duplicate filesystem notifications are ignored. */
export function createSourceChangeDetector(): (path: string, source: string) => boolean {
  const fingerprints = new Map<string, string>();
  return (path, source) => {
    const fingerprint = createHash('sha256').update(source).digest('hex');
    const changed = fingerprints.get(path) !== fingerprint;
    fingerprints.set(path, fingerprint);
    return changed;
  };
}

/** Debounces saves, runs local checks first, and waits for an idle window before network checks. */
export function createSmartWatchScheduler(options: SmartWatchOptions): SmartWatch {
  const debounceMs = options.debounceMs ?? 300;
  const idleMs = options.idleMs ?? 3_000;
  const offlineChanged = new Set<string>();
  const networkChanged = new Set<string>();
  let debounceTimer: NodeJS.Timeout | undefined;
  let idleTimer: NodeJS.Timeout | undefined;
  let running = Promise.resolve();
  let closed = false;

  const run = (phase: 'offline' | 'network', paths: string[]): void => {
    if (paths.length === 0) return;
    options.onRun?.(phase, paths);
    const callback = phase === 'offline' ? options.runOffline : options.runNetwork;
    if (callback === undefined) return;
    running = running
      .then(() => callback(paths))
      .then(() => undefined)
      .catch((error: unknown) => options.onError?.(paths[0] ?? '', error));
  };

  const notifyChange = (path: string): void => {
    if (closed) return;
    offlineChanged.add(path);
    networkChanged.add(path);
    if (debounceTimer !== undefined) clearTimeout(debounceTimer);
    if (idleTimer !== undefined) clearTimeout(idleTimer);

    debounceTimer = setTimeout(() => {
      debounceTimer = undefined;
      const paths = [...offlineChanged];
      offlineChanged.clear();
      run('offline', paths);
    }, debounceMs);

    if (options.runNetwork !== undefined) {
      idleTimer = setTimeout(() => {
        idleTimer = undefined;
        const paths = [...networkChanged];
        networkChanged.clear();
        run('network', paths);
      }, idleMs);
    }
  };

  return {
    notifyChange,
    close() {
      closed = true;
      if (debounceTimer !== undefined) clearTimeout(debounceTimer);
      if (idleTimer !== undefined) clearTimeout(idleTimer);
    },
  };
}

/** Watches concrete files and delegates save scheduling to the shared coordinator. */
export async function startSmartWatch(
  paths: string[],
  options: SmartWatchOptions,
): Promise<SmartWatch> {
  const scheduler = createSmartWatchScheduler(options);
  const watchers: FSWatcher[] = [];
  const hasChanged = createSourceChangeDetector();
  for (const path of paths) {
    if (path === '-') continue;
    try {
      hasChanged(path, await readFile(path, 'utf8'));
      const watcher = watch(path, () => {
        void readFile(path, 'utf8')
          .then((source) => {
            if (hasChanged(path, source)) scheduler.notifyChange(path);
          })
          .catch((error: unknown) => options.onError?.(path, error));
      });
      watcher.on('error', (error) => options.onError?.(path, error));
      watchers.push(watcher);
    } catch (error) {
      options.onError?.(path, error);
    }
  }
  return {
    notifyChange: scheduler.notifyChange,
    close() {
      scheduler.close();
      for (const watcher of watchers) watcher.close();
    },
  };
}