/**
 * Multi-threaded Web Worker linting engine.
 *
 * Linting is CPU-bound, and a browser studio cannot afford it on the UI thread.
 * This module owns the pool, the queue, and the cancel path; it deliberately
 * knows nothing about the host worker loader — the caller passes a
 * {@link WorkerFactory}, so the same engine runs under `new Worker(new URL(...))`,
 * `worker_threads`, or a mock in tests.
 *
 * Sources and results cross the thread boundary as transferable `ArrayBuffer`s
 * (see {@link encodeLintSource} / {@link encodeLintResponse}), never as strings
 * that would be copied and left for the GC to chew on twice.
 *
 * When no worker is available the engine degrades to synchronous execution
 * rather than failing: a linter that refuses to run is worse than a slow one.
 */

import { lint } from '../lint.js';
import type { LintOptions, LintResult } from '../types.js';

export interface LintWorkerMessage {
  type: 'lint';
  id: string;
  /** UTF-8 encoded source, transferred. */
  source: ArrayBuffer;
  options?: LintOptions;
}

export type LintWorkerResponse =
  | { type: 'result'; id: string; payload: ArrayBuffer }
  | { type: 'cancelled'; id: string }
  | { type: 'error'; id: string; message: string };

/** Minimal worker surface the engine needs. Deliberately loader-agnostic. */
export interface WorkerPort {
  postMessage(message: unknown, transfer?: ArrayBuffer[]): void;
  terminate(): void;
  onMessage(handler: (data: unknown) => void): void;
  onError?(handler: (error: Error) => void): void;
}

export type WorkerFactory = () => WorkerPort;

export interface LintJob {
  id?: string;
  source: string;
  options?: LintOptions;
}

export interface LintJobOutcome {
  id: string;
  status: 'completed' | 'cancelled' | 'failed';
  durationMs: number;
  result?: LintResult;
  error?: string;
}

export interface WorkerEngineOptions {
  /** Defaults to `navigator.hardwareConcurrency` (or 4) when workers exist. */
  poolSize?: number;
  /** Omit to force synchronous execution. */
  workerFactory?: WorkerFactory;
  /** Injected for tests; defaults to the core `lint`. */
  fallbackLint?: (source: string, options?: LintOptions) => LintResult;
}

export interface WorkerEngineStats {
  poolSize: number;
  active: number;
  queued: number;
  completed: number;
  cancelled: number;
  failed: number;
}

export function encodeLintSource(source: string): ArrayBuffer {
  const bytes = new TextEncoder().encode(source);
  // A fresh, exactly-sized buffer can be transferred without slicing.
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

export function decodeLintSource(buffer: ArrayBuffer): string {
  return new TextDecoder().decode(new Uint8Array(buffer));
}

export function encodeLintResponse(result: LintResult): ArrayBuffer {
  return encodeLintSource(JSON.stringify(result));
}

export function decodeLintResponse(buffer: ArrayBuffer): LintResult {
  return JSON.parse(decodeLintSource(buffer)) as LintResult;
}

export function defaultPoolSize(): number {
  const hardware = (globalThis as { navigator?: { hardwareConcurrency?: number } }).navigator
    ?.hardwareConcurrency;
  if (typeof hardware === 'number' && hardware > 0) return Math.max(1, Math.min(hardware, 8));
  return 4;
}

export function workersAvailable(factory?: WorkerFactory): boolean {
  if (factory !== undefined) return true;
  return typeof (globalThis as { Worker?: unknown }).Worker === 'function';
}

interface QueueEntry {
  job: Required<Pick<LintJob, 'id' | 'source'>> & { options?: LintOptions };
  resolve: (outcome: LintJobOutcome) => void;
  started: number;
}

interface Slot {
  port: WorkerPort;
  busyId?: string;
  started: number;
}

export class WebWorkerLinterEngine {
  private readonly options: WorkerEngineOptions;
  private readonly size: number;
  private readonly slots: Slot[] = [];
  private readonly queue: QueueEntry[] = [];
  private readonly cancelled = new Set<string>();
  private readonly inflight = new Map<string, { entry: QueueEntry; slot: Slot }>();
  private readonly fallbackLint: (source: string, options?: LintOptions) => LintResult;
  private nextId = 0;
  private terminated = false;
  private counters = { completed: 0, cancelled: 0, failed: 0 };

  constructor(options: WorkerEngineOptions = {}) {
    this.options = options;
    this.fallbackLint = options.fallbackLint ?? ((source, lintOptions) => lint(source, lintOptions));
    this.size = workersAvailable(options.workerFactory)
      ? Math.max(1, options.poolSize ?? defaultPoolSize())
      : 0;
    for (let index = 0; index < this.size; index++) {
      this.slots.push(this.spawn());
    }
  }

  get poolSize(): number {
    return this.size;
  }

  get isParallel(): boolean {
    return this.size > 0;
  }

  stats(): WorkerEngineStats {
    return {
      poolSize: this.slots.length,
      active: this.slots.filter((slot) => slot.busyId !== undefined).length,
      queued: this.queue.length,
      ...this.counters,
    };
  }

  /** One lint, resolving to a result; rejects only for a failed job. */
  async run(source: string, options?: LintOptions): Promise<LintResult> {
    const outcome = await this.runAll([{ source, ...(options !== undefined ? { options } : {}) }]);
    const first = outcome[0];
    if (first === undefined) throw new Error('no lint job was scheduled');
    if (first.status === 'completed' && first.result !== undefined) return first.result;
    if (first.status === 'cancelled') throw new Error(`lint job ${first.id} was cancelled`);
    throw new Error(first.error ?? 'lint job failed');
  }

  /** Queues every job and resolves once all of them have settled. */
  async runAll(jobs: readonly LintJob[]): Promise<LintJobOutcome[]> {
    if (this.terminated) throw new Error('linter engine has been terminated');
    // No worker threads: the same jobs run in-process, so callers never have
    // to know which mode they got.
    if (this.size === 0) return this.runSync(jobs);
    const entries = jobs.map((job) => this.prepare(job));
    const promises = entries.map(
      (entry) =>
        new Promise<LintJobOutcome>((resolve) => {
          this.queue.push({ ...entry, resolve, started: 0 });
        }),
    );
    this.drain();
    return Promise.all(promises);
  }

  /**
   * Cancels a queued or in-flight job. An in-flight job cannot be interrupted
   * inside the worker, so its port is terminated and replaced — the thread is
   * genuinely gone, not merely ignored.
   */
  cancel(id: string): boolean {
    if (this.cancelled.has(id)) return true;
    const queuedIndex = this.queue.findIndex((entry) => entry.job.id === id);
    if (queuedIndex !== -1) {
      const [entry] = this.queue.splice(queuedIndex, 1);
      this.cancelled.add(id);
      this.counters.cancelled++;
      entry?.resolve({ id, status: 'cancelled', durationMs: 0 });
      return true;
    }

    const active = this.inflight.get(id);
    if (active === undefined) return false;

    this.inflight.delete(id);
    this.cancelled.add(id);
    this.counters.cancelled++;
    const index = this.slots.indexOf(active.slot);
    active.slot.port.terminate();
    if (index !== -1 && !this.terminated) this.slots[index] = this.spawn();
    active.entry.resolve({
      id,
      status: 'cancelled',
      durationMs: Math.round(performance.now() - active.entry.started),
    });
    this.drain();
    return true;
  }

  cancelAll(): void {
    for (const entry of [...this.queue]) this.cancel(entry.job.id);
    for (const id of [...this.inflight.keys()]) this.cancel(id);
  }

  /** Stops every worker. Safe to call more than once. */
  terminate(): void {
    this.terminated = true;
    for (const slot of this.slots) slot.port.terminate();
    this.slots.length = 0;
    for (const entry of this.queue.splice(0)) {
      entry.resolve({ id: entry.job.id, status: 'cancelled', durationMs: 0 });
    }
    for (const [id, { entry }] of this.inflight) {
      this.inflight.delete(id);
      entry.resolve({ id, status: 'cancelled', durationMs: 0 });
    }
  }

  private prepare(job: LintJob): Omit<QueueEntry, 'resolve' | 'started'> {
    const id = job.id ?? `lint-${++this.nextId}`;
    return {
      job: {
        id,
        source: job.source,
        ...(job.options !== undefined ? { options: job.options } : {}),
      },
    };
  }

  private spawn(): Slot {
    const port = (this.options.workerFactory ?? defaultWorkerFactory)();
    const slot: Slot = { port, started: 0 };
    port.onMessage((data) => this.onMessage(slot, data));
    port.onError?.((error) => this.onWorkerError(slot, error));
    return slot;
  }

  private drain(): void {
    if (this.terminated) return;
    for (const slot of this.slots) {
      if (slot.busyId !== undefined) continue;
      const entry = this.queue.shift();
      if (entry === undefined) return;
      if (this.cancelled.has(entry.job.id)) {
        this.counters.cancelled++;
        entry.resolve({ id: entry.job.id, status: 'cancelled', durationMs: 0 });
        continue;
      }

      entry.started = performance.now();
      slot.busyId = entry.job.id;
      slot.started = entry.started;
      this.inflight.set(entry.job.id, { entry, slot });

      const source = encodeLintSource(entry.job.source);
      const message: LintWorkerMessage = {
        type: 'lint',
        id: entry.job.id,
        source,
        ...(entry.job.options !== undefined ? { options: entry.job.options } : {}),
      };
      slot.port.postMessage(message, [source]);
    }
  }

  private onMessage(slot: Slot, data: unknown): void {
    if (typeof data !== 'object' || data === null) return;
    const message = data as LintWorkerResponse;
    if (message.type === 'cancelled') {
      const active = this.inflight.get(message.id);
      if (active !== undefined) {
        this.inflight.delete(message.id);
        active.slot.busyId = undefined;
        this.counters.cancelled++;
        active.entry.resolve({
          id: message.id,
          status: 'cancelled',
          durationMs: Math.round(performance.now() - active.entry.started),
        });
      }
      this.drain();
      return;
    }

    const active = this.inflight.get(message.id);
    if (active === undefined) return;
    this.inflight.delete(message.id);
    slot.busyId = undefined;
    const durationMs = Math.round(performance.now() - active.entry.started);

    if (message.type === 'error') {
      this.counters.failed++;
      active.entry.resolve({ id: message.id, status: 'failed', durationMs, error: message.message });
    } else {
      try {
        const result = decodeLintResponse(message.payload);
        this.counters.completed++;
        active.entry.resolve({ id: message.id, status: 'completed', durationMs, result });
      } catch (error) {
        this.counters.failed++;
        active.entry.resolve({
          id: message.id,
          status: 'failed',
          durationMs,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }
    this.drain();
  }

  private onWorkerError(slot: Slot, error: Error): void {
    const id = slot.busyId;
    slot.busyId = undefined;
    const index = this.slots.indexOf(slot);
    slot.port.terminate();
    if (index !== -1 && !this.terminated) this.slots[index] = this.spawn();
    if (id !== undefined) {
      const active = this.inflight.get(id);
      this.inflight.delete(id);
      if (active !== undefined) {
        this.counters.failed++;
        active.entry.resolve({
          id,
          status: 'failed',
          durationMs: Math.round(performance.now() - active.entry.started),
          error: error.message,
        });
      }
    }
    this.drain();
  }

  /**
   * Synchronous path used when workers are unavailable. It still returns the
   * same outcome shape so callers do not branch on the execution mode.
   */
  async runSync(jobs: readonly LintJob[]): Promise<LintJobOutcome[]> {
    const outcomes: LintJobOutcome[] = [];
    for (const job of jobs) {
      const id = job.id ?? `lint-${++this.nextId}`;
      const started = performance.now();
      try {
        const result = this.fallbackLint(job.source, job.options);
        this.counters.completed++;
        outcomes.push({
          id,
          status: 'completed',
          durationMs: Math.round(performance.now() - started),
          result,
        });
      } catch (error) {
        this.counters.failed++;
        outcomes.push({
          id,
          status: 'failed',
          durationMs: Math.round(performance.now() - started),
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }
    return outcomes;
  }
}

let defaultFactory: WorkerFactory | undefined;

/**
 * The host registers its loader once at startup:
 * `registerWorkerFactory(() => new Worker(new URL('./linter.worker.js', import.meta.url)))`.
 * Nothing here imports a loader, which keeps the core usable in every runtime.
 */
export function registerWorkerFactory(factory: WorkerFactory): void {
  defaultFactory = factory;
}

function defaultWorkerFactory(): WorkerPort {
  if (defaultFactory === undefined) {
    throw new Error('no WorkerFactory registered; call registerWorkerFactory() first');
  }
  return defaultFactory();
}

/**
 * Creates an engine that falls back to synchronous linting when workers are
 * unavailable, which is the browser-without-Worker and Node-test case.
 */
export function createLinterEngine(options: WorkerEngineOptions = {}): WebWorkerLinterEngine {
  return new WebWorkerLinterEngine(options);
}
