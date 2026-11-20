import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createAssetCacheFetch, isCacheableAssetUrl } from '../src/gitops/ciAssetCache.js';

let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'stl-asset-cache-'));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

interface Call {
  url: string;
  method: string;
}

function fakeFetch(
  respond: (url: string, method: string) => Response = () =>
    new Response('PNGDATA', { status: 200, headers: { 'content-type': 'image/png' } }),
): { fetch: typeof fetch; calls: Call[] } {
  const calls: Call[] = [];
  const impl = async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    const url = input instanceof Request ? input.url : String(input);
    const method = (
      init?.method ?? (input instanceof Request ? input.method : 'GET')
    ).toUpperCase();
    calls.push({ url, method });
    return respond(url, method);
  };
  return { fetch: impl as typeof fetch, calls };
}

describe('isCacheableAssetUrl', () => {
  it.each([
    'https://example.com/logo.png',
    'https://example.com/a/b/Logo.JPEG',
    'https://example.com/icon.svg',
    'https://example.com/favicon.ico',
    'https://example.com/schemas/sep1.json',
    'https://example.com/sep1.schema.json',
    'https://ipfs.io/ipfs/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi',
    'https://bafy.ipfs.dweb.link/logo',
    'http://example.com/logo.webp',
  ])('caches %s', (url) => {
    expect(isCacheableAssetUrl(url)).toBe(true);
  });

  it.each([
    'https://horizon.stellar.org/accounts/G',
    'https://example.com/.well-known/stellar.toml',
    'https://example.com/data.json',
    'https://example.com/logo.png?v=2',
    'https://user:pw@example.com/logo.png',
    'ftp://example.com/logo.png',
    'not a url',
  ])('does not cache %s', (url) => {
    expect(isCacheableAssetUrl(url)).toBe(false);
  });
});

describe('createAssetCacheFetch', () => {
  it('serves a fresh hit from disk without touching the network', async () => {
    const base = fakeFetch();
    const cached = createAssetCacheFetch(base.fetch, dir);
    const first = await cached('https://example.com/logo.png');
    expect(await first.text()).toBe('PNGDATA');
    expect(first.headers.get('x-stellar-toml-lint-cache')).toBeNull();

    const second = await cached(new URL('https://example.com/logo.png'));
    expect(base.calls).toHaveLength(1);
    expect(second.status).toBe(200);
    expect(second.url).toBe('https://example.com/logo.png');
    expect(second.headers.get('content-type')).toBe('image/png');
    expect(second.headers.get('x-stellar-toml-lint-cache')).toBe('hit');
    expect(await second.text()).toBe('PNGDATA');
  });

  it('caches HEAD separately and without a body', async () => {
    const base = fakeFetch(
      (_, method) => new Response(method === 'HEAD' ? null : 'x', { status: 200 }),
    );
    const cached = createAssetCacheFetch(base.fetch, dir);
    await cached('https://example.com/logo.png', { method: 'head' });
    const hit = await cached(new Request('https://example.com/logo.png', { method: 'HEAD' }));
    expect(base.calls.map((c) => c.method)).toEqual(['HEAD']);
    expect(hit.body).toBeNull();
    await cached('https://example.com/logo.png');
    expect(base.calls.map((c) => c.method)).toEqual(['HEAD', 'GET']);
  });

  it('refetches once the entry is older than the TTL', async () => {
    let now = 1_000;
    const base = fakeFetch();
    const cached = createAssetCacheFetch(base.fetch, dir, { ttlMs: 100, now: () => now });
    await cached('https://example.com/logo.png');
    now += 99;
    await cached('https://example.com/logo.png');
    expect(base.calls).toHaveLength(1);
    now += 1;
    await cached('https://example.com/logo.png');
    expect(base.calls).toHaveLength(2);
  });

  it('passes through requests that must not be cached', async () => {
    const base = fakeFetch();
    const cached = createAssetCacheFetch(base.fetch, dir);
    await cached('https://horizon.stellar.org/');
    await cached('https://horizon.stellar.org/');
    await cached('https://example.com/logo.png', { method: 'POST' });
    await cached('https://example.com/logo.png', { method: 'GET', body: null, headers: {} });
    await cached(new Request('https://example.com/logo.png', { method: 'PUT', body: 'x' }));
    await cached(new Request('https://example.com/logo.png'), { method: 'PATCH', body: 'x' });
    expect(base.calls).toHaveLength(6);
    expect(await readdir(dir)).toHaveLength(1);
  });

  it('does not store failures, redirects, or oversized bodies', async () => {
    const responses: Record<string, () => Response> = {
      'https://example.com/404.png': () => new Response('no', { status: 404 }),
      'https://example.com/redirect.png': () => {
        const response = new Response('x', { status: 200 });
        Object.defineProperty(response, 'redirected', { value: true });
        return response;
      },
      'https://example.com/declared.png': () =>
        new Response('x', { status: 200, headers: { 'content-length': String(6 * 1024 * 1024) } }),
      'https://example.com/huge.png': () => new Response(new Uint8Array(5 * 1024 * 1024 + 1)),
    };
    const base = fakeFetch((url) => (responses[url] as () => Response)());
    const cached = createAssetCacheFetch(base.fetch, dir);
    for (const url of Object.keys(responses)) {
      await cached(url);
      await cached(url);
    }
    expect(base.calls).toHaveLength(8);
    expect(await readdir(dir)).toEqual([]);
  });

  it('caches 204 responses without a body', async () => {
    const base = fakeFetch(() => new Response(null, { status: 204 }));
    const cached = createAssetCacheFetch(base.fetch, dir);
    await cached('https://example.com/empty.png');
    const hit = await cached('https://example.com/empty.png');
    expect(base.calls).toHaveLength(1);
    expect(hit.status).toBe(204);
    expect(hit.body).toBeNull();
  });

  it('ignores corrupt entries and drops cookies from stored headers', async () => {
    const base = fakeFetch(
      () => new Response('img', { status: 200, headers: { 'set-cookie': 'a=b', etag: '"1"' } }),
    );
    const cached = createAssetCacheFetch(base.fetch, dir);
    await cached('https://example.com/logo.png');
    const [entry] = await readdir(dir);
    await writeFile(join(dir, entry as string), '{corrupt');
    await cached('https://example.com/logo.png');
    expect(base.calls).toHaveLength(2);
    const hit = await cached('https://example.com/logo.png');
    expect(base.calls).toHaveLength(2);
    expect(hit.headers.get('set-cookie')).toBeNull();
    expect(hit.headers.get('etag')).toBe('"1"');
  });

  it('falls back to the network response when the cache cannot be written', async () => {
    const blocked = join(dir, 'file');
    await writeFile(blocked, 'not a directory');
    const base = fakeFetch();
    const cached = createAssetCacheFetch(base.fetch, join(blocked, 'cache'));
    const response = await cached('https://example.com/logo.png');
    expect(await response.text()).toBe('PNGDATA');
  });
});
