/**
 * Offline schema cache for browser runs.
 *
 * The browser build re-fetches SEP schemas, validator metadata, and asset icons
 * on every page load. Those responses are stable for hours, so the studio keeps
 * them in IndexedDB with a TTL and answers from disk when the network is gone —
 * sub-millisecond rule evaluation, and a linter that still works offline.
 *
 * Three object stores keep the kinds apart: `schemas`, `responses`, and
 * `icons`. Every record carries `storedAt` and `expiresAt`, so expiry is a
 * filter rather than a delete-on-read race, and `pruneExpired` can reclaim
 * storage in one transaction. A capacity bound evicts the oldest entries first
 * so a long session cannot fill the origin's quota.
 *
 * IndexedDB is unavailable in private-browsing modes and in Node; the cache
 * falls back to an equally asynchronous in-memory backend with the same API, so
 * callers never branch on the environment. The DOM types are declared
 * structurally here because the package compiles without the DOM lib.
 */
export const CACHE_STORES = ['schemas', 'responses', 'icons'] as const;

export type CacheStore = (typeof CACHE_STORES)[number];

/** Bumping this runs `onupgradeneeded`; stores are created idempotently. */
export const CACHE_DB_VERSION = 1;

export const DEFAULT_CACHE_TTL_MS = 24 * 60 * 60 * 1000;

export const DEFAULT_MAX_ENTRIES = 500;

export interface CacheRecord<T> {
  key: string;
  value: T;
  storedAt: number;
  expiresAt: number;
}

interface IdbRequestLike<T> {
  readonly result: T;
  onsuccess: (() => void) | null;
  onerror: (() => void) | null;
  readonly error?: unknown;
}

interface IdbObjectStoreLike {
  get(key: string): IdbRequestLike<unknown>;
  put(value: unknown): IdbRequestLike<unknown>;
  delete(key: string): IdbRequestLike<unknown>;
  clear(): IdbRequestLike<unknown>;
  getAll(): IdbRequestLike<unknown[]>;
  count(): IdbRequestLike<number>;
}

interface IdbTransactionLike {
  objectStore(name: string): IdbObjectStoreLike;
  oncomplete: (() => void) | null;
  onerror: (() => void) | null;
  onabort: (() => void) | null;
}

interface IdbDatabaseLike {
  readonly objectStoreNames: { contains(name: string): boolean };
  createObjectStore(name: string, options?: { keyPath?: string }): unknown;
  transaction(names: string[], mode: 'readonly' | 'readwrite'): IdbTransactionLike;
  close(): void;
}

interface IdbOpenRequestLike {
  readonly result: IdbDatabaseLike;
  onupgradeneeded: (() => void) | null;
  onsuccess: (() => void) | null;
  onerror: (() => void) | null;
  readonly error: unknown;
}

/** The subset of `IDBFactory` the cache uses. */
export interface IdbFactoryLike {
  open(name: string, version?: number): IdbOpenRequestLike;
}

export interface IndexedDbCacheOptions {
  /** Defaults to `globalThis.indexedDB`; pass `null` to force the memory backend. */
  factory?: IdbFactoryLike | null;
  dbName?: string;
  version?: number;
  ttlMs?: number;
  maxEntries?: number;
  now?: () => number;
}

export interface CacheSetOptions {
  /** Overrides the cache-wide TTL for one entry (0 means "never expires"). */
  ttlMs?: number;
}

export type CacheBackend = 'indexeddb' | 'memory';

export interface CacheStats {
  backend: CacheBackend;
  entries: Record<CacheStore, number>;
  expired: Record<CacheStore, number>;
  /** Why the memory fallback was chosen, when it was. */
  fallbackReason?: string;
}

function requestResult<T>(request: IdbRequestLike<T>): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('IndexedDB request failed.'));
  });
}

function transactionDone(transaction: IdbTransactionLike): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(new Error('IndexedDB transaction failed.'));
    transaction.onabort = () => reject(new Error('IndexedDB transaction aborted.'));
  });
}

/** A promise-based IndexedDB client with TTL, pruning, and a memory fallback. */
export class IndexedDbSchemaCache {
  private readonly dbName: string;
  private readonly version: number;
  private readonly ttlMs: number;
  private readonly maxEntries: number;
  private readonly now: () => number;
  private readonly factory: IdbFactoryLike | null;

  private db: IdbDatabaseLike | null = null;
  private memory: Map<CacheStore, Map<string, CacheRecord<unknown>>> | null = null;
  private fallbackReason: string | undefined;
  private opening: Promise<CacheBackend> | null = null;

  constructor(options: IndexedDbCacheOptions = {}) {
    this.dbName = options.dbName ?? 'stellar-toml-lint';
    this.version = options.version ?? CACHE_DB_VERSION;
    this.ttlMs = options.ttlMs ?? DEFAULT_CACHE_TTL_MS;
    this.maxEntries = options.maxEntries ?? DEFAULT_MAX_ENTRIES;
    this.now = options.now ?? Date.now;
    this.factory =
      options.factory !== undefined
        ? options.factory
        : ((globalThis as unknown as { indexedDB?: IdbFactoryLike }).indexedDB ?? null);
  }

  get backend(): CacheBackend {
    return this.memory !== null ? 'memory' : 'indexeddb';
  }

  /** Opens the database once; concurrent callers share the same promise. */
  async open(): Promise<CacheBackend> {
    if (this.memory !== null) return 'memory';
    if (this.db !== null) return 'indexeddb';
    this.opening ??= this.openDatabase();
    return this.opening;
  }

  private useMemory(reason: string): CacheBackend {
    this.fallbackReason = reason;
    this.memory = new Map(
      CACHE_STORES.map((store) => [store, new Map<string, CacheRecord<unknown>>()]),
    );
    this.db = null;
    return 'memory';
  }

  private async openDatabase(): Promise<CacheBackend> {
    const factory = this.factory;
    if (factory === null) return this.useMemory('IndexedDB is not available in this runtime.');

    try {
      const request = factory.open(this.dbName, this.version);
      const database = await new Promise<IdbDatabaseLike>((resolve, reject) => {
        request.onupgradeneeded = () => {
          // Idempotent: an upgrade from any earlier version recreates only the
          // stores that are missing, so a future version can add one without a
          // migration ladder.
          const db = request.result;
          for (const store of CACHE_STORES) {
            if (!db.objectStoreNames.contains(store)) {
              db.createObjectStore(store, { keyPath: 'key' });
            }
          }
        };
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error ?? new Error('IndexedDB open failed.'));
      });

      this.db = database;
      return 'indexeddb';
    } catch (error) {
      // Private browsing, disabled storage, or a corrupt database: the cache is
      // an optimisation, never a hard dependency, so degrade instead of throw.
      return this.useMemory(error instanceof Error ? error.message : String(error));
    }
  }

  private memoryStore(store: CacheStore): Map<string, CacheRecord<unknown>> {
    const map = this.memory?.get(store);
    if (map === undefined) throw new Error('Cache is not open.');
    return map;
  }

  private isExpired(record: CacheRecord<unknown>, at = this.now()): boolean {
    return record.expiresAt !== 0 && record.expiresAt <= at;
  }

  async get<T>(store: CacheStore, key: string): Promise<T | undefined> {
    const backend = await this.open();
    const record =
      backend === 'memory'
        ? this.memoryStore(store).get(key)
        : ((await requestResult(
            this.db!.transaction([store], 'readonly').objectStore(store).get(key),
          )) as CacheRecord<T> | undefined);

    if (record === undefined) return undefined;
    if (this.isExpired(record)) {
      await this.delete(store, key);
      return undefined;
    }
    return record.value as T;
  }

  async has(store: CacheStore, key: string): Promise<boolean> {
    return (await this.get(store, key)) !== undefined;
  }

  async set<T>(
    store: CacheStore,
    key: string,
    value: T,
    options: CacheSetOptions = {},
  ): Promise<void> {
    const backend = await this.open();
    const at = this.now();
    const ttl = options.ttlMs ?? this.ttlMs;
    const record: CacheRecord<T> = {
      key,
      value,
      storedAt: at,
      expiresAt: ttl <= 0 ? 0 : at + ttl,
    };

    if (backend === 'memory') {
      this.memoryStore(store).set(key, record as CacheRecord<unknown>);
    } else {
      const transaction = this.db!.transaction([store], 'readwrite');
      transaction.objectStore(store).put(record);
      await transactionDone(transaction);
    }

    await this.prune(store);
  }

  async delete(store: CacheStore, key: string): Promise<boolean> {
    const backend = await this.open();
    if (backend === 'memory') return this.memoryStore(store).delete(key);

    const transaction = this.db!.transaction([store], 'readwrite');
    transaction.objectStore(store).delete(key);
    await transactionDone(transaction);
    return true;
  }

  async clear(store?: CacheStore): Promise<void> {
    const backend = await this.open();
    const stores = store === undefined ? CACHE_STORES : [store];

    if (backend === 'memory') {
      for (const name of stores) this.memoryStore(name).clear();
      return;
    }
    const transaction = this.db!.transaction([...stores], 'readwrite');
    for (const name of stores) transaction.objectStore(name).clear();
    await transactionDone(transaction);
  }

  /** Reads every live record in a store, newest first. */
  async entries<T>(store: CacheStore): Promise<CacheRecord<T>[]> {
    const backend = await this.open();
    let records: CacheRecord<T>[];
    if (backend === 'memory') {
      records = [...this.memoryStore(store).values()] as CacheRecord<T>[];
    } else {
      records = (await requestResult(
        this.db!.transaction([store], 'readonly').objectStore(store).getAll(),
      )) as CacheRecord<T>[];
    }
    return records
      .filter((record) => !this.isExpired(record))
      .sort((a, b) => b.storedAt - a.storedAt);
  }

  /**
   * Structured local query over cached values — the offline path. The predicate
   * runs in the host, so callers can filter a schema by `SEP` number or an icon
   * by domain without a network round trip.
   */
  async query<T>(
    store: CacheStore,
    predicate: (value: T, record: CacheRecord<T>) => boolean,
  ): Promise<CacheRecord<T>[]> {
    const records = await this.entries<T>(store);
    return records.filter((record) => predicate(record.value, record));
  }

  /** Removes expired records and returns how many were dropped. */
  async pruneExpired(): Promise<number> {
    const backend = await this.open();
    let removed = 0;
    const at = this.now();

    for (const store of CACHE_STORES) {
      if (backend === 'memory') {
        const map = this.memoryStore(store);
        for (const [key, record] of map) {
          if (this.isExpired(record, at)) {
            map.delete(key);
            removed++;
          }
        }
        continue;
      }

      const records = (await requestResult(
        this.db!.transaction([store], 'readonly').objectStore(store).getAll(),
      )) as CacheRecord<unknown>[];
      const expired = records.filter((record) => this.isExpired(record, at));
      if (expired.length === 0) continue;

      const transaction = this.db!.transaction([store], 'readwrite');
      for (const record of expired) transaction.objectStore(store).delete(record.key);
      await transactionDone(transaction);
      removed += expired.length;
    }

    return removed;
  }

  async size(store?: CacheStore): Promise<number> {
    const stores = store === undefined ? CACHE_STORES : [store];
    let total = 0;
    for (const name of stores) {
      await this.open();
      total += this.memory !== null ? this.memoryStore(name).size : await this.count(name);
    }
    return total;
  }

  private async count(store: CacheStore): Promise<number> {
    return requestResult(this.db!.transaction([store], 'readonly').objectStore(store).count());
  }

  async stats(): Promise<CacheStats> {
    await this.open();
    const entries = {} as Record<CacheStore, number>;
    const expired = {} as Record<CacheStore, number>;
    const at = this.now();

    for (const store of CACHE_STORES) {
      const records =
        this.memory !== null
          ? ([...this.memoryStore(store).values()] as CacheRecord<unknown>[])
          : ((await requestResult(
              this.db!.transaction([store], 'readonly').objectStore(store).getAll(),
            )) as CacheRecord<unknown>[]);
      expired[store] = records.filter((record) => this.isExpired(record, at)).length;
      entries[store] = records.length - expired[store]!;
    }

    return {
      backend: this.backend,
      entries,
      expired,
      ...(this.fallbackReason === undefined ? {} : { fallbackReason: this.fallbackReason }),
    };
  }

  async close(): Promise<void> {
    this.db?.close();
    this.db = null;
    this.memory = null;
    this.opening = null;
  }

  /** Expiry sweep plus oldest-first eviction above `maxEntries`. */
  private async prune(store: CacheStore): Promise<void> {
    const records = await this.entries(store);
    const excess = records.length - this.maxEntries;
    if (excess <= 0) {
      const expired = await this.expiredKeys(store);
      for (const key of expired) await this.delete(store, key);
      return;
    }
    // `entries` is newest first, so the tail is the oldest entries.
    for (const record of records.slice(records.length - excess)) {
      await this.delete(store, record.key);
    }
  }

  private async expiredKeys(store: CacheStore): Promise<string[]> {
    const backend = await this.open();
    const at = this.now();
    if (backend === 'memory') {
      return [...this.memoryStore(store).values()]
        .filter((record) => this.isExpired(record, at))
        .map((record) => record.key);
    }
    const records = (await requestResult(
      this.db!.transaction([store], 'readonly').objectStore(store).getAll(),
    )) as CacheRecord<unknown>[];
    return records.filter((record) => this.isExpired(record, at)).map((record) => record.key);
  }
}
