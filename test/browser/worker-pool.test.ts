import { describe, expect, it, vi, afterEach, beforeEach } from 'vitest';
import { lint } from '../../src/lint.js';
import { handleMessage } from '../../src/worker.js';
import { lintBrowserPool, WorkerPool, type PoolTask } from '../../src/browser/worker-pool.js';

/** A cooperative fake Worker: `postMessage` runs the real worker protocol
 *  (`handleMessage`) on a macrotask and posts the response back via `onmessage`. */
class FakeWorker {
  readonly url: string;
  readonly posts: unknown[] = [];
  terminated = false;
  failed = false;
  onmessage: ((event: { data: unknown }) => void) | null = null;
  onerror: ((event: unknown) => void) | null = null;
  taskId: number | null = null;

  constructor(url: string) {
    this.url = url;
    instances.push(this);
  }

  postMessage(message: unknown): void {
    this.posts.push(message);
    void setTimeout(() => this.deliver(message), 0);
  }

  private async deliver(message: unknown): Promise<void> {
    if (this.failed) return;
    try {
      const response = await handleMessage(message as never);
      this.onmessage?.({ data: response });
    } catch (error) {
      this.onerror?.(error);
    }
  }

  terminate(): void {
    this.terminated = true;
  }

  /** Make the worker die on the next message instead of answering. */
  fail(): void {
    this.failed = true;
    void setTimeout(() => {
      this.onerror?.(new Error('simulated worker crash'));
    }, 0);
  }
}

const instances: FakeWorker[] = [];
let workerCalls = 0;
let failWorkerAt: number | undefined;

beforeEach(() => {
  instances.length = 0;
  workerCalls = 0;
  failWorkerAt = undefined;
  vi.stubGlobal(
    'Worker',
    class extends FakeWorker {
      constructor(url: string) {
        super(url);
        const call = workerCalls++;
        if (failWorkerAt !== undefined && call === failWorkerAt) this.fail();
      }
    } as unknown as typeof Worker,
  );
  vi.stubGlobal('navigator', { hardwareConcurrency: 4 } as unknown as Navigator);
});

afterEach(() => {
  instances.length = 0;
  vi.unstubAllGlobals();
});

const valid =
  'VERSION="2.7.0"\nNETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"\n';
const broken = 'VERSION="two"\nSIGNING_KEY="nope"\n';

function tasksOf(n: number): PoolTask[] {
  const tasks: PoolTask[] = [];
  for (let i = 0; i < n; i++) {
    tasks.push({ path: `file-${i}.toml`, content: i % 3 === 0 ? broken : valid });
  }
  return tasks;
}

function contentOf(path: string, all: PoolTask[]): string {
  const found = all.find((t) => t.path === path);
  return found === undefined ? valid : found.content;
}

describe('WorkerPool', () => {
  it('spawns one worker per logical core', async () => {
    const pool = new WorkerPool({ concurrency: 4 });
    expect(pool.size).toBe(4);
    pool.terminate();
  });

  it('clamps concurrency to [1, 16]', async () => {
    expect(new WorkerPool({ concurrency: 0 }).size).toBe(1);
    expect(new WorkerPool({ concurrency: 100 }).size).toBe(16);
    const pool = new WorkerPool();
    expect(pool.size).toBe(4);
    pool.terminate();
  });

  it('lints 20 files in parallel with parity to the main thread', async () => {
    const all = tasksOf(20);
    const pool = new WorkerPool({ concurrency: 4 });
    try {
      const entries = await pool.lintFiles(all);

      expect(entries).toHaveLength(20);
      for (const [index, entry] of entries.entries()) {
        expect(entry.path).toBe(`file-${index}.toml`);
        const expected = lint(contentOf(entry.path, all));
        if (entry.error !== null) {
          // A worker failure is recorded but never fails the whole batch.
          expect(entry.result).toBeNull();
          expect(entry.error).toBeTruthy();
        } else {
          expect(entry.result).toEqual(expected);
          expect(entry.result!.ok).toBe(expected.ok);
          expect(entry.result!.counts).toEqual(expected.counts);
        }
      }
      // Every worker was used, so the parallelism was real.
      expect(instances.filter((w) => w.posts.length > 0).length).toBeGreaterThan(1);
    } finally {
      pool.terminate();
    }
  });

  it('reports progress from 0 to 100 percent', async () => {
    const all = tasksOf(10);
    const captures: Array<{ completed: number; total: number; percent: number }> = [];
    const pool = new WorkerPool({ concurrency: 4 });
    pool.onProgressListener = (progress) => captures.push({ ...progress });
    try {
      await pool.lintFiles(all);
    } finally {
      pool.terminate();
    }

    expect(captures.length).toBeGreaterThan(0);
    expect(captures[0]!.percent).toBe(0);
    const last = captures[captures.length - 1]!;
    expect(last.percent).toBe(100);
    expect(last.completed).toBe(10);
    expect(last.total).toBe(10);
    for (let i = 1; i < captures.length; i++) {
      expect(captures[i]!.percent).toBeGreaterThanOrEqual(captures[i - 1]!.percent);
    }
  });

  it('distributes work round-robin across workers', async () => {
    const all = tasksOf(8);
    const pool = new WorkerPool({ concurrency: 4 });
    try {
      await pool.lintFiles(all);
    } finally {
      pool.terminate();
    }

    // Every worker received exactly two posts: task i went to worker i % 4,
    // so worker i owns tasks i and i + 4 (order within a worker is the
    // submission order).
    expect(instances).toHaveLength(4);
    instances.forEach((worker, index) => {
      expect(worker.posts).toHaveLength(2);
      const ids = worker.posts.map((post) => (post as { id: number }).id).sort((a, b) => a - b);
      expect(ids).toEqual([index, index + 4]);
    });
  });

  it('keeps going when a worker crashes, and marks that file as an error', async () => {
    failWorkerAt = 1; // kill the second worker the pool creates
    const all = tasksOf(6);
    const pool = new WorkerPool({ concurrency: 3 });
    try {
      const entries = await pool.lintFiles(all);

      expect(entries).toHaveLength(6);
      const failed = entries.filter((e) => e.error !== null);
      expect(failed.length).toBeGreaterThan(0);
      for (const entry of failed) {
        expect(entry.result).toBeNull();
        expect(entry.error).toBeTruthy();
      }
      for (const entry of entries.filter((e) => e.error === null)) {
        const expected = lint(contentOf(entry.path, all));
        expect(entry.result!.counts).toEqual(expected.counts);
      }
    } finally {
      pool.terminate();
    }
  });

  it('rejects every pending task when the pool is terminated', async () => {
    const pool = new WorkerPool({ concurrency: 2 });
    const promise = pool.lintFiles(tasksOf(4));
    pool.terminate();
    await expect(promise).rejects.toThrow(/terminated/);
    expect(pool.pendingCount).toBe(0);
    for (const worker of instances) expect(worker.terminated).toBe(true);
  });

  it('falls back to inline processing when Workers cannot be created', async () => {
    vi.stubGlobal(
      'Worker',
      class {
        constructor() {
          throw new Error('Workers are disabled');
        }
      } as unknown as typeof Worker,
    );
    const pool = new WorkerPool({ concurrency: 4 });
    expect(pool.size).toBe(0);

    const all = tasksOf(5);
    const entries = await pool.lintFiles(all);
    expect(entries).toHaveLength(5);
    for (const entry of entries) {
      expect(entry.error).toBeNull();
      expect(entry.result!.counts).toEqual(lint(contentOf(entry.path, all)).counts);
    }
    pool.terminate();
  });
});

describe('lintBrowserPool', () => {
  it('lints a small batch and terminates the pool afterwards', async () => {
    const entries = await lintBrowserPool(
      [
        { path: 'a.toml', content: valid },
        { path: 'b.toml', content: broken },
      ],
      { concurrency: 2 },
    );

    expect(entries).toHaveLength(2);
    expect(entries[0]?.error).toBeNull();
    expect(entries[0]?.result?.ok).toBe(true);
    expect(entries[1]?.error).toBeNull();
    expect(entries[1]?.result?.ok).toBe(false);
  });
});
