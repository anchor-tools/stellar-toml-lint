import { describe, expect, it } from 'vitest';
import { indexedDB } from 'fake-indexeddb';
import { IndexedDbSchemaCache, type IdbFactoryLike } from '../src/wasm/indexedDbCache.js';

const factory = indexedDB as unknown as IdbFactoryLike;
let databaseCounter = 0;

function freshDatabase(): string {
  return `stellar-toml-lint-test-${databaseCounter++}`;
}

/** A controllable clock, so TTL tests never sleep. */
function clock(start = 1_000): { now: () => number; advance: (ms: number) => void } {
  let time = start;
  return {
    now: () => time,
    advance: (ms) => {
      time += ms;
    },
  };
}

describe('IndexedDbSchemaCache — memory fallback', () => {
  it('serves reads and writes when IndexedDB is unavailable', async () => {
    const cache = new IndexedDbSchemaCache({ factory: null });

    expect(await cache.open()).toBe('memory');
    await cache.set('schemas', 'sep-1', { sep: 1 });
    expect(await cache.get('schemas', 'sep-1')).toEqual({ sep: 1 });
    expect(await cache.has('schemas', 'sep-1')).toBe(true);

    const stats = await cache.stats();
    expect(stats.backend).toBe('memory');
    expect(stats.entries.schemas).toBe(1);
    expect(stats.fallbackReason).toMatch(/not available/);
  });

  it('expires entries after the TTL and prunes them on demand', async () => {
    const time = clock();
    const cache = new IndexedDbSchemaCache({ factory: null, ttlMs: 100, now: time.now });

    await cache.set('schemas', 'sep-1', { sep: 1 });
    await cache.set('responses', 'anchor.example', { ok: true });
    time.advance(50);
    await cache.set('schemas', 'sep-24', { sep: 24 }, { ttlMs: 1_000 });

    expect(await cache.get('schemas', 'sep-1')).toEqual({ sep: 1 });

    time.advance(60);
    expect(await cache.get('schemas', 'sep-1')).toBeUndefined();
    expect(await cache.get('responses', 'anchor.example')).toBeUndefined();
    expect(await cache.get('schemas', 'sep-24')).toEqual({ sep: 24 });

    await cache.set('icons', 'icon.example', 'png', { ttlMs: 1_000 });
    await cache.set('responses', 'stale-a', true, { ttlMs: 1 });
    await cache.set('responses', 'stale-b', true, { ttlMs: 1 });
    time.advance(2);

    expect(await cache.pruneExpired()).toBe(2);
    expect(await cache.size()).toBe(2);
  });

  it('treats ttlMs 0 as "never expires"', async () => {
    const time = clock();
    const cache = new IndexedDbSchemaCache({ factory: null, ttlMs: 0, now: time.now });
    await cache.set('schemas', 'permanent', { sep: 1 });

    time.advance(365 * 24 * 60 * 60 * 1000);
    expect(await cache.get('schemas', 'permanent')).toEqual({ sep: 1 });
    expect(await cache.pruneExpired()).toBe(0);
  });

  it('answers structured offline queries', async () => {
    const cache = new IndexedDbSchemaCache({ factory: null, ttlMs: 1_000, now: () => 1_000 });
    await cache.set('schemas', 'sep-1', { sep: 1, title: 'toml' });
    await cache.set('schemas', 'sep-24', { sep: 24, title: 'interactive' });
    await cache.set('icons', 'anchor.example', { svg: '<svg/>' });

    const sep24 = await cache.query<{ sep: number }>('schemas', (value) => value.sep === 24);
    expect(sep24).toHaveLength(1);
    expect(sep24[0]?.key).toBe('sep-24');
    expect(sep24[0]?.value).toEqual({ sep: 24, title: 'interactive' });
  });

  it('evicts the oldest entries above the capacity bound', async () => {
    const time = clock();
    const cache = new IndexedDbSchemaCache({
      factory: null,
      ttlMs: 1_000,
      maxEntries: 2,
      now: time.now,
    });

    await cache.set('schemas', 'first', 1);
    time.advance(1);
    await cache.set('schemas', 'second', 2);
    time.advance(1);
    await cache.set('schemas', 'third', 3);

    expect(await cache.size('schemas')).toBe(2);
    expect(await cache.get('schemas', 'first')).toBeUndefined();
    expect(await cache.get('schemas', 'third')).toBe(3);
  });

  it('clears one store or all of them', async () => {
    const cache = new IndexedDbSchemaCache({ factory: null });
    await cache.set('schemas', 'a', 1);
    await cache.set('responses', 'b', 2);

    await cache.clear('schemas');
    expect(await cache.size('schemas')).toBe(0);
    expect(await cache.size('responses')).toBe(1);

    await cache.clear();
    expect(await cache.size()).toBe(0);
  });
});

describe('IndexedDbSchemaCache — IndexedDB backend', () => {
  it('stores, retrieves and deletes through real transactions', async () => {
    const cache = new IndexedDbSchemaCache({ factory, dbName: freshDatabase(), ttlMs: 1_000 });

    expect(await cache.open()).toBe('indexeddb');
    await cache.set('schemas', 'sep-38', { sep: 38 });
    expect(await cache.get('schemas', 'sep-38')).toEqual({ sep: 38 });

    expect(await cache.delete('schemas', 'sep-38')).toBe(true);
    expect(await cache.get('schemas', 'sep-38')).toBeUndefined();

    await cache.set('icons', 'a.example', 'svg');
    expect((await cache.stats()).entries.icons).toBe(1);
    await cache.close();
  });

  it('persists across sessions and survives a version upgrade', async () => {
    const dbName = freshDatabase();
    const first = new IndexedDbSchemaCache({ factory, dbName, ttlMs: 0 });
    await first.set('schemas', 'sep-1', { sep: 1 });
    await first.close();

    const upgraded = new IndexedDbSchemaCache({
      factory,
      dbName,
      version: 2,
      ttlMs: 0,
    });
    expect(await upgraded.open()).toBe('indexeddb');
    expect(await upgraded.get('schemas', 'sep-1')).toEqual({ sep: 1 });
    await upgraded.set('responses', 'after-upgrade', true);
    expect(await upgraded.get('responses', 'after-upgrade')).toBe(true);
    await upgraded.close();
  });

  it('expires and prunes records in the object stores', async () => {
    const time = clock();
    const cache = new IndexedDbSchemaCache({
      factory,
      dbName: freshDatabase(),
      ttlMs: 100,
      now: time.now,
    });

    await cache.set('schemas', 'old', { sep: 1 });
    await cache.set('icons', 'old-icon', 'svg');
    time.advance(101);
    // Writing to a store prunes that store automatically, so only the icon is
    // left for the explicit sweep.
    await cache.set('schemas', 'new', { sep: 24 }, { ttlMs: 1_000 });

    expect(await cache.pruneExpired()).toBe(1);
    expect(await cache.get('schemas', 'new')).toEqual({ sep: 24 });

    const stats = await cache.stats();
    expect(stats.entries.schemas).toBe(1);
    expect(stats.entries.icons).toBe(0);
    await cache.close();
  });

  it('falls back to memory when opening the database fails', async () => {
    const broken: IdbFactoryLike = {
      open: () => {
        throw new Error('SecurityError: storage is disabled');
      },
    };
    const cache = new IndexedDbSchemaCache({ factory: broken });

    expect(await cache.open()).toBe('memory');
    await cache.set('schemas', 'sep-1', { sep: 1 });
    expect(await cache.get('schemas', 'sep-1')).toEqual({ sep: 1 });
  });
});
