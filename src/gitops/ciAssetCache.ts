/**
 * An on-disk cache for remote assets fetched during network checks.
 *
 * In CI, the slow part of `--check-network` is usually not Horizon but the
 * static assets a `stellar.toml` points at: currency logos, JSON schemas, and
 * IPFS gateway content. They rarely change, so caching them in a directory the
 * workflow persists with `actions/cache` keeps a warm run well under 30 seconds.
 *
 * Only immutable-ish assets are cached. Anything that reflects live state —
 * Horizon, SEP endpoints, TOML files themselves — always goes to the network,
 * so caching can never mask a regression in what the linter is meant to check.
 */

import { createHash } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

/** Environment variable that enables the cache from the CLI. */
export const ASSET_CACHE_ENV = 'STELLAR_TOML_LINT_ASSET_CACHE';

const DAY_MS = 24 * 60 * 60 * 1000;
const MAX_BODY_BYTES = 5 * 1024 * 1024;
const ASSET_EXTENSION = /\.(?:png|jpe?g|gif|svg|webp|avif|ico|bmp|schema\.json)$/i;

export interface AssetCacheOptions {
  /** How long an entry stays fresh. Default 24 hours. */
  ttlMs?: number;
  /** Clock, for tests. */
  now?: () => number;
}

interface CacheEntry {
  url: string;
  method: string;
  status: number;
  statusText: string;
  headers: [string, string][];
  /** Base64 body; empty for HEAD. */
  body: string;
  storedAt: number;
}

/** Whether `url` names an asset whose response is safe to reuse across runs. */
export function isCacheableAssetUrl(url: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return false;
  // Credentials or a query string can make a response caller-specific.
  if (parsed.username !== '' || parsed.password !== '' || parsed.search !== '') return false;
  const path = parsed.pathname.toLowerCase();
  if (path.startsWith('/ipfs/') || parsed.hostname.includes('.ipfs.')) return true;
  if (path.includes('/schemas/') && path.endsWith('.json')) return true;
  return ASSET_EXTENSION.test(path);
}

function requestOf(
  input: Parameters<typeof fetch>[0],
  init?: RequestInit,
): { url: string; method: string; hasBody: boolean } {
  if (input instanceof Request) {
    return {
      url: input.url,
      method: (init?.method ?? input.method).toUpperCase(),
      hasBody: (init?.body !== undefined && init.body !== null) || input.body !== null,
    };
  }
  return {
    url: input instanceof URL ? input.href : String(input),
    method: (init?.method ?? 'GET').toUpperCase(),
    hasBody: init?.body !== undefined && init.body !== null,
  };
}

function keyFor(method: string, url: string): string {
  return createHash('sha256').update(`${method} ${url}`).digest('hex');
}

/** Statuses whose responses must not carry a body. */
function bodiless(status: number, method: string): boolean {
  return method === 'HEAD' || status === 204 || status === 205 || status === 304;
}

function toResponse(entry: CacheEntry): Response {
  const body = bodiless(entry.status, entry.method) ? null : Buffer.from(entry.body, 'base64');
  const response = new Response(body, {
    status: entry.status,
    statusText: entry.statusText,
    headers: [...entry.headers, ['x-stellar-toml-lint-cache', 'hit']],
  });
  // Synthetic responses have an empty url; checks that report redirects read it.
  Object.defineProperty(response, 'url', { value: entry.url });
  return response;
}

/**
 * Wraps `base` so cacheable GET/HEAD requests are served from `dir` while
 * fresh, and successful responses are written back. Cache I/O failures fall
 * through to the network: a broken cache must never fail a lint run.
 */
export function createAssetCacheFetch(
  base: typeof fetch,
  dir: string,
  options: AssetCacheOptions = {},
): typeof fetch {
  const ttl = options.ttlMs ?? DAY_MS;
  const now = options.now ?? Date.now;

  const cached = async (
    input: Parameters<typeof fetch>[0],
    init?: RequestInit,
  ): Promise<Response> => {
    const { url, method, hasBody } = requestOf(input, init);
    if ((method !== 'GET' && method !== 'HEAD') || hasBody || !isCacheableAssetUrl(url)) {
      return base(input, init);
    }

    const file = join(dir, `${keyFor(method, url)}.json`);
    try {
      const entry = JSON.parse(await readFile(file, 'utf8')) as CacheEntry;
      if (entry.url === url && now() - entry.storedAt < ttl) return toResponse(entry);
    } catch {
      // Missing or corrupt entry: fetch below.
    }

    const response = await base(input, init);
    if (!response.ok || response.redirected) return response;

    try {
      const declared = Number(response.headers.get('content-length') ?? '0');
      if (declared > MAX_BODY_BYTES) return response;
      const bytes = bodiless(response.status, method)
        ? Buffer.alloc(0)
        : Buffer.from(await response.clone().arrayBuffer());
      if (bytes.byteLength > MAX_BODY_BYTES) return response;
      const entry: CacheEntry = {
        url,
        method,
        status: response.status,
        statusText: response.statusText,
        headers: [...response.headers.entries()].filter(
          ([name]) =>
            name !== 'set-cookie' && name !== 'content-encoding' && name !== 'content-length',
        ),
        body: bytes.toString('base64'),
        storedAt: now(),
      };
      await mkdir(dir, { recursive: true });
      // Write-then-rename so a parallel reader never sees a torn entry.
      const temp = `${file}.${process.pid}.tmp`;
      await writeFile(temp, JSON.stringify(entry));
      await rename(temp, file);
    } catch {
      // Caching is best-effort.
    }
    return response;
  };

  return cached as typeof fetch;
}
