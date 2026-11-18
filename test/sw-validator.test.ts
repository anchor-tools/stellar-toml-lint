import { describe, expect, it } from 'vitest';
import {
  ServiceWorkerOfflineValidator,
  isVersionedCacheName,
  parseCacheNames,
  parseManifest,
  parseServiceWorker,
  simulateOfflineLint,
  validateOfflinePwa,
} from '../src/wasm/swValidator.js';

const manifest = {
  name: 'Stellar TOML Lint',
  short_name: 'TOML Lint',
  start_url: '/',
  display: 'standalone',
  theme_color: '#0b1c2c',
  icons: [
    { src: '/icons/icon-192.png', sizes: '192x192', type: 'image/png' },
    { src: '/icons/icon-512.png', sizes: '512x512', type: 'image/png' },
  ],
};

const serviceWorker = `
const CACHE = 'linter-v3';
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE).then((cache) =>
      cache.addAll([
        '/',
        '/linter.js',
        '/linter.wasm',
        '/schemas/sep1.json',
        '/manifest.json',
      ]),
    ),
  );
});
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((key) => key !== CACHE).map((key) => caches.delete(key))),
    ),
  );
});
self.addEventListener('fetch', (event) => {
  event.respondWith(caches.match(event.request).then((hit) => hit || fetch(event.request)));
});
`;

describe('service worker parsing', () => {
  it('extracts cache names, including versioned literal caches', () => {
    expect(parseCacheNames(`caches.open('a-v1'); caches.open(\`b-\${BUILD}\`)`)).toEqual([
      'a-v1',
      'b-${BUILD}',
    ]);
  });

  it('recognises versioned cache names', () => {
    expect(isVersionedCacheName('linter-v3')).toBe(true);
    expect(isVersionedCacheName('linter-${BUILD}')).toBe(true);
    expect(isVersionedCacheName('linter-3f9a2c1d')).toBe(true);
    expect(isVersionedCacheName('linter-assets')).toBe(false);
  });

  it('reads precache lists, install/activate handlers and delete logic', () => {
    const analysis = parseServiceWorker(serviceWorker);
    expect(analysis.precachedUrls).toContain('/linter.wasm');
    expect(analysis.hasInstallHandler).toBe(true);
    expect(analysis.hasActivateHandler).toBe(true);
    expect(analysis.deletesOldCaches).toBe(true);
    expect(analysis.versionedCaches).toEqual(['linter-v3']);
    expect(analysis.strategies).toContain('cache-first');
  });

  it('reads Workbox precache objects', () => {
    const analysis = parseServiceWorker(
      `precacheAndRoute([{url: '/app.js', revision: '1'}, {url: '/app.wasm'}]);`,
    );
    expect(analysis.precachedUrls).toEqual(['/app.js', '/app.wasm']);
  });
});

describe('manifest parsing', () => {
  it('keeps optional fields and icons', () => {
    const parsed = parseManifest(JSON.stringify(manifest));
    expect(parsed.parsed).toBe(true);
    expect(parsed.startUrl).toBe('/');
    expect(parsed.icons).toHaveLength(2);
  });

  it('reports invalid JSON instead of throwing', () => {
    const parsed = parseManifest('{ nope');
    expect(parsed.parsed).toBe(false);
    expect(parsed.error).toBeDefined();
  });
});

describe('ServiceWorkerOfflineValidator', () => {
  it('accepts a versioned, fully precached app', () => {
    const result = validateOfflinePwa(serviceWorker, JSON.stringify(manifest));
    expect(result.ok).toBe(true);
    expect(result.findings).toEqual([]);
  });

  it('flags critical assets that are not precached', () => {
    const result = new ServiceWorkerOfflineValidator(
      `const CACHE = 'linter-v1';
self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE).then((c) => c.addAll(['/', '/linter.js'])));
});`,
      JSON.stringify(manifest),
    ).validate({ criticalAssets: ['/linter.wasm', '/schemas/sep1.json'] });
    const missing = result.findings.filter((finding) => finding.code === 'pwa/missing-precache');
    expect(missing).toHaveLength(2);
    expect(result.ok).toBe(false);
  });

  it('requires cache invalidation on new deploys', () => {
    const result = validateOfflinePwa(
      `caches.open('linter-assets').then((c) => c.addAll(['/', '/app.js', '/app.wasm']));`,
      JSON.stringify(manifest),
    );
    expect(result.findings.some((finding) => finding.code === 'pwa/unversioned-cache')).toBe(true);
    expect(result.findings.some((finding) => finding.code === 'pwa/no-cache-invalidation')).toBe(
      true,
    );
  });

  it('warns on missing icon sizes and required manifest fields', () => {
    const result = validateOfflinePwa(
      serviceWorker,
      JSON.stringify({ name: 'Lint', icons: [] }),
    );
    expect(result.findings.some((finding) => finding.code === 'pwa/missing-manifest-field')).toBe(
      true,
    );
    expect(result.findings.filter((finding) => finding.code === 'pwa/missing-icon-size')).toHaveLength(
      2,
    );
  });

  it('fails a manifest that is not JSON', () => {
    const result = validateOfflinePwa(serviceWorker, 'not json');
    expect(result.findings[0]?.code).toBe('pwa/invalid-manifest');
    expect(result.ok).toBe(false);
  });
});

describe('offline linting', () => {
  it('lints a stellar.toml with no network access', async () => {
    const result = await simulateOfflineLint(
      `[[CURRENCIES]]\ncode = "usd"\nissuer = "not-an-account"\n`,
    );
    expect(result.counts.error).toBeGreaterThan(0);
    expect(Array.isArray(result.diagnostics)).toBe(true);
  });
});
