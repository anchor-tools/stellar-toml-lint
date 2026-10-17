/**
 * Web Worker thread pool for the browser build.
 *
 * A playground importing a ZIP of multi-tenant anchor files, or a monorepo
 * holding many TOML configurations, cannot lint every file on the page's main
 * thread without freezing the UI. {@link WorkerPool} spins up `N` dedicated
 * Web Workers — one per logical core, from `navigator.hardwareConcurrency` —
 * and batch-processes files off the main thread while the page stays
 * responsive.
 *
 * Each worker speaks the small request/response protocol implemented by the
 * bundled `worker.js` script: `{ type: 'lint', id, content, options }` goes
 * in, `{ type: 'result', id, result }` or `{ type: 'error', id, message }`
 * comes out. Tasks are handed out round-robin to idle workers; a worker that
 * errors is taken out of rotation and replaced, so a single bad worker cannot
 * stall the whole pool. `terminate()` stops every worker and rejects pending
 * work.
 *
 * When Workers are unavailable (or cannot be created) the pool falls back to
 * processing the queue on the current thread, so the same API works
 * everywhere.
 */

import { handleMessage } from '../worker.js';
import type { BrowserLintOptions } from '../browser.js';
import type { LintResult } from '../types.js';

const DEFAULT_CONCURRENCY = 4;
const MAX_CONCURRENCY = 16;

export interface PoolOptions {
  /** How many workers to spawn. Defaults to `navigator.hardwareConcurrency` (clamped to 1..16), then 4. */
  concurrency?: number;
  /** URL of the worker script. Defaults to the bundled `worker.js` next to this module. */
  workerUrl?: string;
}

export interface PoolTask {
  /** File path or mount point, echoed in the result so callers can sort output. */
  path: string;
  /** TOML source to lint. */
  content: string;
  /** Browser lint options forwarded to each worker. */
  options?: BrowserLintOptions;
}

export interface PoolEntry {
  path: string;
  result: LintResult | null;
  error: string | null;
}

export interface Progress {
  completed: number;
  total: number;
  /** `completed / total * 100`, always between 0 and 100. */
  percent: number;
}

type Resolve = (value: PoolEntry) => void;
type Reject = (reason: unknown) => void;

/** Rejection reason used only by `terminate()`; worker failures resolve as
 *  error entries instead of rejecting the batch. */
const TERMINATION = new Error('Worker pool terminated.');

interface QueuedTask {
  id: number;
  task: PoolTask;
}

interface WorkerSlot {
  postMessage(message: unknown): void;
  terminate(): void;
  onmessage: ((event: { data: unknown }) => void) | null;
  onerror: ((event: unknown) => void) | null;
  taskId: number | null;
}

/** The minimal shape `Worker` must have; declared here so this module compiles
 *  without the DOM type library and stays testable in plain Node. */
declare const Worker: {
  new (url: string | URL): WorkerSlot;
};

function hardwareConcurrency(): number | undefined {
  if (typeof navigator === 'undefined') return undefined;
  return (navigator as { hardwareConcurrency?: number }).hardwareConcurrency;
}

function defaultWorkerUrl(): string {
  return new URL('./worker.js', import.meta.url).href;
}

/**
 * A pool of dedicated Web Workers that lints TOML files off the main thread.
 *
 * ```ts
 * const pool = new WorkerPool({ concurrency: navigator.hardwareConcurrency });
 * const entries = await pool.lintFiles([
 *   { path: 'accounts/acme/stellar.toml', content },
 *   { path: 'accounts/globex/stellar.toml', content },
 * ], (progress) => console.log(`${progress.percent}%`));
 * pool.terminate();
 * ```
 */
export class WorkerPool {
  private readonly workerUrl: string;
  private readonly concurrency: number;
  private slots: WorkerSlot[] = [];
  private readonly queue: QueuedTask[] = [];
  private readonly pending = new Map<number, { resolve: Resolve; reject: Reject; path: string }>();
  private nextId = 0;
  private terminated = false;
  private inline = false;
  private total = 0;
  private completed = 0;
  private lastSlot = 0;
  private onProgress?: (progress: Progress) => void;

  constructor(options: PoolOptions = {}) {
    this.workerUrl = options.workerUrl ?? defaultWorkerUrl();
    this.concurrency = Math.min(
      Math.max(options.concurrency ?? hardwareConcurrency() ?? DEFAULT_CONCURRENCY, 1),
      MAX_CONCURRENCY,
    );
    this.spawnWorkers();
  }

  /** How many workers are currently in rotation. */
  get size(): number {
    return this.slots.length;
  }

  /** Tasks queued or in-flight right now. */
  get pendingCount(): number {
    return this.queue.length + this.pending.size;
  }

  /** Last reported progress. */
  get progress(): Progress {
    return progressOf(this.completed, this.total);
  }

  /** Set a progress listener. Called after every finished task. */
  set onProgressListener(listener: (progress: Progress) => void) {
    this.onProgress = listener;
  }

  private spawnWorkers(): void {
    let failures = 0;
    for (let i = 0; i < this.concurrency; i++) {
      try {
        this.slots.push(this.createWorker());
      } catch {
        failures++;
      }
    }
    // If not a single worker could be created, process the queue on this
    // thread instead of failing outright.
    if (this.slots.length === 0 && failures > 0) this.inline = true;
  }

  private createWorker(): WorkerSlot {
    const slot: WorkerSlot = new Worker(this.workerUrl);
    slot.onmessage = (event) => this.handleResponse(slot, event.data);
    slot.onerror = () => this.handleWorkerError(slot);
    return slot;
  }

  /** Lints every file across the pool, in input order, and resolves with one
   *  entry per file. A worker failure marks that file's entry as an error and
   *  never fails the whole batch. */
  async lintFiles(
    tasks: PoolTask[],
    options: { onProgress?: (progress: Progress) => void } = {},
  ): Promise<PoolEntry[]> {
    this.total = tasks.length;
    this.completed = 0;
    if (options.onProgress) this.onProgress = options.onProgress;
    this.reportProgress();

    if (this.inline) {
      const entries: PoolEntry[] = [];
      for (const task of tasks) {
        entries.push(await this.processInline(task));
        this.completed++;
        this.reportProgress();
      }
      return entries;
    }

    return Promise.all(tasks.map((task) => this.submit(task)));
  }

  private async processInline(task: PoolTask): Promise<PoolEntry> {
    const id = this.nextId++;
    try {
      const response = await handleMessage({
        type: 'lint',
        id,
        content: task.content,
        options: task.options,
      });
      if (response.type === 'error') {
        return { path: task.path, result: null, error: response.message };
      }
      if (response.type !== 'result') {
        return { path: task.path, result: null, error: 'Worker returned an unreadable response.' };
      }
      return { path: task.path, result: response.result, error: null };
    } catch (error) {
      return {
        path: task.path,
        result: null,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  private submit(task: PoolTask): Promise<PoolEntry> {
    return new Promise((resolve, reject) => {
      if (this.terminated) {
        reject(TERMINATION);
        return;
      }
      const id = this.nextId++;
      this.pending.set(id, {
        resolve: (entry) => resolve(entry),
        reject: (reason) => {
          // A worker failure marks that file as an error; it never fails the
          // whole batch — only `terminate()` rejects outstanding work.
          if (reason === TERMINATION) return reject(reason);
          resolve({ path: task.path, result: null, error: String(reason) });
        },
        path: task.path,
      });
      this.queue.push({ id, task });
      this.dispatch();
    });
  }

  /** Hands queued tasks to idle workers, round-robin, starting after the last
   *  used worker so work spreads evenly. */
  private dispatch(): void {
    if (this.inline || this.terminated || this.slots.length === 0) return;
    for (let i = 0; i < this.slots.length; i++) {
      const index = (this.lastSlot + i) % this.slots.length;
      const slot = this.slots[index];
      if (!slot || slot.taskId !== null) continue;
      const entry = this.queue.shift();
      if (!entry) break;
      slot.taskId = entry.id;
      this.lastSlot = (index + 1) % this.slots.length;
      slot.postMessage({
        type: 'lint',
        id: entry.id,
        content: entry.task.content,
        options: entry.task.options,
      });
    }
  }

  private handleResponse(slot: WorkerSlot, data: unknown): void {
    const id = (data as { id?: number })?.id;
    if (id === undefined) return;
    const record = this.pending.get(id);
    if (!record) return;
    this.pending.delete(id);
    slot.taskId = null;

    let entry: PoolEntry;
    if (
      data !== null &&
      typeof data === 'object' &&
      (data as { type?: string }).type === 'result'
    ) {
      entry = { path: record.path, result: (data as { result: LintResult }).result, error: null };
    } else {
      entry = {
        path: record.path,
        result: null,
        error:
          data !== null && typeof data === 'object' && 'message' in data
            ? String((data as { message: unknown }).message)
            : 'Worker returned an unreadable response.',
      };
    }

    record.resolve(entry);
    this.completed++;
    this.reportProgress();
    this.dispatch();
  }

  private handleWorkerError(slot: WorkerSlot): void {
    const taskId = slot.taskId;
    if (taskId !== null) {
      const record = this.pending.get(taskId);
      if (record) {
        this.pending.delete(taskId);
        record.reject(new Error('Worker failed while linting.'));
      }
      slot.taskId = null;
      this.completed++;
      this.reportProgress();
    }

    try {
      slot.terminate();
    } catch {
      /* already dead */
    }
    this.slots = this.slots.filter((s) => s !== slot);

    if (!this.terminated) {
      // Replace the dead worker so the pool keeps its concurrency; if we
      // cannot, finish the rest of the queue on this thread.
      try {
        this.slots.push(this.createWorker());
      } catch {
        this.inline = true;
      }
    }
    this.dispatch();
  }

  private reportProgress(): void {
    if (!this.onProgress) return;
    this.onProgress(this.progress);
  }

  /** Stops every worker and rejects every queued or in-flight task. Safe to
   *  call more than once. */
  terminate(): void {
    this.terminated = true;
    this.onProgress = undefined;
    for (const slot of this.slots) {
      try {
        slot.terminate();
      } catch {
        /* no-op */
      }
    }
    this.slots = [];
    for (const record of this.pending.values()) {
      record.reject(TERMINATION);
    }
    this.pending.clear();
    this.queue.length = 0;
  }
}

function progressOf(completed: number, total: number): Progress {
  return {
    completed,
    total,
    percent: total === 0 ? 100 : Math.min(100, Math.round((completed / total) * 100)),
  };
}

/**
 * Convenience wrapper: a short-lived pool that lints `files` in parallel and
 * tears itself down when the run finishes (or fails).
 */
export async function lintBrowserPool(
  files: PoolTask[],
  options: PoolOptions & { onProgress?: (progress: Progress) => void } = {},
): Promise<PoolEntry[]> {
  const { onProgress, ...poolOptions } = options;
  const pool = new WorkerPool(poolOptions);
  try {
    return await pool.lintFiles(files, { onProgress });
  } finally {
    pool.terminate();
  }
}
