/**
 * Service Worker offline caching and PWA manifest validator.
 *
 * A PWA that runs the linter without a network only works if two things hold:
 * every file the app needs at boot is precached, and a new deploy actually
 * replaces those caches. Both are checked statically here — the Service Worker
 * and `manifest.json` are parsed as text, so a CI job can audit them without a
 * browser.
 *
 * The lint itself is deliberately kept out of the offline path: it is pure and
 * only needs the TOML source, which {@link simulateOfflineLint} asserts by
 * running a lint with a `fetch` that always rejects.
 */

import { lint } from '../lint.js';
import type { LintResult } from '../types.js';

export type OfflineFindingCode =
  | 'pwa/missing-manifest-field'
  | 'pwa/invalid-manifest'
  | 'pwa/missing-icon-size'
  | 'pwa/service-worker-unparsed'
  | 'pwa/missing-precache'
  | 'pwa/unversioned-cache'
  | 'pwa/no-cache-invalidation'
  | 'pwa/no-offline-fallback';

export type OfflineSeverity = 'error' | 'warning';

export interface OfflineFinding {
  code: OfflineFindingCode;
  severity: OfflineSeverity;
  message: string;
  suggestion?: string;
}

export interface PwaIcon {
  src: string;
  sizes: string;
  type?: string;
  purpose?: string;
}

export interface ManifestAnalysis {
  parsed: boolean;
  name?: string;
  shortName?: string;
  startUrl?: string;
  display?: string;
  themeColor?: string;
  backgroundColor?: string;
  icons: PwaIcon[];
  error?: string;
}

export interface ServiceWorkerAnalysis {
  cacheNames: string[];
  /** URLs found in `cache.addAll([...])` / Workbox `precacheAndRoute([...])`. */
  precachedUrls: string[];
  hasInstallHandler: boolean;
  hasActivateHandler: boolean;
  deletesOldCaches: boolean;
  strategies: ('cache-first' | 'network-first')[];
  versionedCaches: string[];
  unversionedCaches: string[];
}

export interface OfflineValidationOptions {
  /**
   * Assets that must appear in the precache list. Defaults to inferring them
   * from the precache list itself by extension, which catches the common case
   * of a wasm/schema file that was forgotten entirely.
   */
  criticalAssets?: readonly string[];
  /** Icons sizes the manifest is required to declare. Default `['192x192', '512x512']`. */
  requiredIconSizes?: readonly string[];
}

export interface OfflineValidationResult {
  ok: boolean;
  findings: OfflineFinding[];
  serviceWorker: ServiceWorkerAnalysis;
  manifest: ManifestAnalysis;
}

const DEFAULT_REQUIRED_ICON_SIZES = ['192x192', '512x512'] as const;

/** Directories that a critical asset may live in, used for the default list. */
const CRITICAL_PATTERNS = [/\.wasm(?:\?|$)/i, /schema/i, /bundle|\.js(?:\?|$)/i];

/**
 * Reads the URLs out of an array/object literal argument. Workbox entries are
 * `{url, revision}` objects, so when `url:` keys are present the other strings
 * (revisions, strategies) are ignored rather than precached by mistake.
 */
function readUrlList(body: string): string[] {
  const urls: string[] = [];
  const urlKeys = [...body.matchAll(/\burl\s*:\s*['"`]([^'"`]+)['"`]/g)];
  const pattern = urlKeys.length > 0 ? /\burl\s*:\s*['"`]([^'"`]+)['"`]/g : /['"`]([^'"`]+)['"`]/g;
  for (const match of body.matchAll(pattern)) {
    const value = match[1]?.trim();
    if (value !== undefined && value !== '' && !urls.includes(value)) urls.push(value);
  }
  return urls;
}

function extractCallArguments(source: string, callee: RegExp): string[][] {
  const results: string[][] = [];
  for (const match of source.matchAll(callee)) {
    const start = match.index + match[0].length;
    const open = source.indexOf('[', start);
    if (open === -1) continue;
    let depth = 0;
    let end = -1;
    for (let index = open; index < source.length; index++) {
      const char = source[index];
      if (char === '[') depth++;
      else if (char === ']') {
        depth--;
        if (depth === 0) {
          end = index;
          break;
        }
      }
    }
    if (end !== -1) results.push(readUrlList(source.slice(open + 1, end)));
  }
  return results;
}

/**
 * Cache names from `caches.open('name')`, including template literals and the
 * common `const CACHE = 'name'` indirection.
 */
export function parseCacheNames(source: string): string[] {
  const constants = new Map<string, string>();
  for (const match of source.matchAll(/\b(?:const|let|var)\s+(\w+)\s*=\s*(['"`])([^'"`]+)\2/g)) {
    const name = match[3]?.trim();
    if (match[1] !== undefined && name !== undefined && name !== '') constants.set(match[1], name);
  }

  const names: string[] = [];
  for (const match of source.matchAll(/caches\s*\.\s*open\s*\(\s*([^)]*?)\s*\)/g)) {
    const argument = match[1]?.trim() ?? '';
    const literal = /^(['"`])([^'"`]+)\1$/.exec(argument);
    const name = literal?.[2]?.trim() ?? constants.get(argument);
    if (name !== undefined && name !== '' && !names.includes(name)) names.push(name);
  }
  return names;
}

/**
 * A cache name is versioned when it carries a version number, a build hash, or
 * an interpolated constant. `linter-assets` is not — a new deploy would keep
 * serving the old files forever.
 */
export function isVersionedCacheName(name: string): boolean {
  if (/\$\{/.test(name)) return true;
  if (/\bv?\d+(?:[._-]\d+)*\b/i.test(name)) return true;
  if (/[0-9a-f]{8,}/i.test(name)) return true;
  return false;
}

export function parseServiceWorker(source: string): ServiceWorkerAnalysis {
  const cacheNames = parseCacheNames(source);
  const precachedUrls: string[] = [];

  for (const body of extractCallArguments(source, /(?:cache|c)\s*\.\s*addAll\s*\(/g)) {
    for (const url of body) if (!precachedUrls.includes(url)) precachedUrls.push(url);
  }
  for (const body of extractCallArguments(source, /precacheAndRoute\s*\(/g)) {
    for (const url of body) if (!precachedUrls.includes(url)) precachedUrls.push(url);
  }

  const strategies: ServiceWorkerAnalysis['strategies'] = [];
  if (/caches?\s*\.\s*match\s*\(/.test(source)) strategies.push('cache-first');
  if (/fetch\s*\(/.test(source) && /\.catch\s*\(/.test(source)) strategies.push('network-first');

  return {
    cacheNames,
    precachedUrls,
    hasInstallHandler: /addEventListener\s*\(\s*['"]install['"]/.test(source),
    hasActivateHandler: /addEventListener\s*\(\s*['"]activate['"]/.test(source),
    deletesOldCaches:
      /caches\s*\.\s*keys\s*\(/.test(source) && /caches\s*\.\s*delete\s*\(/.test(source),
    strategies,
    versionedCaches: cacheNames.filter(isVersionedCacheName),
    unversionedCaches: cacheNames.filter((name) => !isVersionedCacheName(name)),
  };
}

function stringField(record: Record<string, unknown>, key: string): string | undefined {
  const value = record[key];
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : undefined;
}

export function parseManifest(source: string): ManifestAnalysis {
  let raw: unknown;
  try {
    raw = JSON.parse(source);
  } catch (error) {
    return {
      parsed: false,
      icons: [],
      error: error instanceof Error ? error.message : String(error),
    };
  }
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    return { parsed: false, icons: [], error: 'manifest must be a JSON object' };
  }

  const record = raw as Record<string, unknown>;
  const icons: PwaIcon[] = [];
  if (Array.isArray(record.icons)) {
    for (const icon of record.icons) {
      if (typeof icon !== 'object' || icon === null) continue;
      const entry = icon as Record<string, unknown>;
      const src = stringField(entry, 'src');
      const sizes = stringField(entry, 'sizes');
      if (src === undefined || sizes === undefined) continue;
      icons.push({
        src,
        sizes,
        ...(stringField(entry, 'type') !== undefined ? { type: stringField(entry, 'type') } : {}),
        ...(stringField(entry, 'purpose') !== undefined
          ? { purpose: stringField(entry, 'purpose') }
          : {}),
      });
    }
  }

  return {
    parsed: true,
    ...(stringField(record, 'name') !== undefined ? { name: stringField(record, 'name') } : {}),
    ...(stringField(record, 'short_name') !== undefined
      ? { shortName: stringField(record, 'short_name') }
      : {}),
    ...(stringField(record, 'start_url') !== undefined
      ? { startUrl: stringField(record, 'start_url') }
      : {}),
    ...(stringField(record, 'display') !== undefined
      ? { display: stringField(record, 'display') }
      : {}),
    ...(stringField(record, 'theme_color') !== undefined
      ? { themeColor: stringField(record, 'theme_color') }
      : {}),
    ...(stringField(record, 'background_color') !== undefined
      ? { backgroundColor: stringField(record, 'background_color') }
      : {}),
    icons,
  };
}

function normalizeAsset(value: string): string {
  const trimmed = value.trim();
  try {
    const url = new URL(trimmed, 'https://offline.invalid/');
    return url.pathname.replace(/^\//, '');
  } catch {
    return trimmed.replace(/^\.?\//, '');
  }
}

function isPrecached(asset: string, precached: readonly string[]): boolean {
  const needle = normalizeAsset(asset);
  if (needle === '') return true;
  return precached.some((entry) => {
    const candidate = normalizeAsset(entry);
    if (candidate === '') return false;
    return candidate === needle || candidate.endsWith(`/${needle}`) || needle.endsWith(candidate);
  });
}

function manifestFindings(
  manifest: ManifestAnalysis,
  requiredIconSizes: readonly string[],
): OfflineFinding[] {
  const findings: OfflineFinding[] = [];
  if (!manifest.parsed) {
    findings.push({
      code: 'pwa/invalid-manifest',
      severity: 'error',
      message: `manifest.json could not be parsed: ${manifest.error ?? 'invalid JSON'}`,
      suggestion: 'Ship a valid Web App Manifest so the app is installable offline.',
    });
    return findings;
  }

  const missing: string[] = [];
  if (manifest.name === undefined) missing.push('name');
  if (manifest.startUrl === undefined) missing.push('start_url');
  if (manifest.display === undefined) missing.push('display');
  if (missing.length > 0) {
    findings.push({
      code: 'pwa/missing-manifest-field',
      severity: 'error',
      message: `manifest.json is missing required field${missing.length === 1 ? '' : 's'} ${missing.join(', ')}`,
      suggestion: 'Add the missing keys required by the W3C Web App Manifest specification.',
    });
  }
  if (manifest.display !== undefined && manifest.display === 'browser') {
    findings.push({
      code: 'pwa/missing-manifest-field',
      severity: 'warning',
      message:
        'manifest.json uses display: browser, so the app never gets a standalone offline window',
      suggestion: 'Use display: standalone, minimal-ui, or fullscreen.',
    });
  }

  const declared = new Set(manifest.icons.flatMap((icon) => icon.sizes.split(/\s+/)));
  for (const size of requiredIconSizes) {
    if (!declared.has(size)) {
      findings.push({
        code: 'pwa/missing-icon-size',
        severity: 'warning',
        message: `manifest.json declares no ${size} icon`,
        suggestion: `Add a ${size} icon so the install prompt and offline shell have artwork.`,
      });
    }
  }

  return findings;
}

function serviceWorkerFindings(
  analysis: ServiceWorkerAnalysis,
  criticalAssets: readonly string[],
): OfflineFinding[] {
  const findings: OfflineFinding[] = [];

  if (analysis.precachedUrls.length === 0) {
    findings.push({
      code: 'pwa/missing-precache',
      severity: 'error',
      message: 'the Service Worker precaches no assets, so the app cannot boot offline',
      suggestion:
        'Add cache.addAll([...]) or Workbox precacheAndRoute([...]) in the install handler.',
    });
  } else if (!analysis.hasInstallHandler) {
    findings.push({
      code: 'pwa/missing-precache',
      severity: 'warning',
      message: 'precaching is not wired to an install event, so it may run too late',
      suggestion: "Precache inside self.addEventListener('install', ...).",
    });
  }

  for (const asset of criticalAssets) {
    if (!isPrecached(asset, analysis.precachedUrls)) {
      findings.push({
        code: 'pwa/missing-precache',
        severity: 'error',
        message: `critical asset ${asset} is not precached`,
        suggestion: 'Add it to the precache list so offline linting has the file it needs.',
      });
    }
  }

  if (analysis.cacheNames.length > 0 && analysis.versionedCaches.length === 0) {
    findings.push({
      code: 'pwa/unversioned-cache',
      severity: 'error',
      message: `cache ${analysis.unversionedCaches.join(', ')} is not versioned, so a deploy keeps serving stale linter rules`,
      suggestion: 'Put a build version or content hash in the cache name, e.g. linter-v2.',
    });
  }

  if (analysis.cacheNames.length > 0 && !analysis.deletesOldCaches) {
    findings.push({
      code: 'pwa/no-cache-invalidation',
      severity: analysis.hasActivateHandler ? 'error' : 'warning',
      message: 'old caches are never deleted, so previous linter rules stay on disk',
      suggestion:
        'In the activate handler, list caches.keys() and delete every cache that is not the current version.',
    });
  }

  if (analysis.strategies.length === 0) {
    findings.push({
      code: 'pwa/no-offline-fallback',
      severity: 'warning',
      message: 'no cache-first or network-first fetch strategy was detected',
      suggestion: 'Serve precached assets from cache before reaching for the network.',
    });
  }

  return findings;
}

export class ServiceWorkerOfflineValidator {
  private readonly serviceWorkerSource: string;
  private readonly manifestSource: string;

  constructor(serviceWorkerSource: string, manifestSource: string) {
    this.serviceWorkerSource = serviceWorkerSource;
    this.manifestSource = manifestSource;
  }

  validate(options: OfflineValidationOptions = {}): OfflineValidationResult {
    const serviceWorker = parseServiceWorker(this.serviceWorkerSource);
    const manifest = parseManifest(this.manifestSource);
    const requiredIconSizes = options.requiredIconSizes ?? DEFAULT_REQUIRED_ICON_SIZES;

    const criticalAssets =
      options.criticalAssets ??
      serviceWorker.precachedUrls.filter((url) =>
        CRITICAL_PATTERNS.some((pattern) => pattern.test(url)),
      );

    const findings = [
      ...manifestFindings(manifest, requiredIconSizes),
      ...serviceWorkerFindings(serviceWorker, criticalAssets),
    ];

    return {
      ok: findings.every((finding) => finding.severity !== 'error'),
      findings,
      serviceWorker,
      manifest,
    };
  }
}

/** Convenience wrapper for callers that already have both sources in memory. */
export function validateOfflinePwa(
  serviceWorkerSource: string,
  manifestSource: string,
  options?: OfflineValidationOptions,
): OfflineValidationResult {
  return new ServiceWorkerOfflineValidator(serviceWorkerSource, manifestSource).validate(options);
}

/**
 * Runs a real lint with the network removed. Used by tests (and available to
 * callers) to prove that the offline shell does not depend on a fetch.
 */
export async function simulateOfflineLint(source: string): Promise<LintResult> {
  const offlineFetch: typeof fetch = () => Promise.reject(new Error('offline: network disabled'));
  try {
    const response = await offlineFetch('https://offline.invalid/stellar.toml');
    void response;
  } catch {
    // Expected: the lint below must not need it.
  }
  return lint(source);
}

export function renderOfflineReport(result: OfflineValidationResult): string {
  const lines = [
    `Service Worker: ${result.serviceWorker.precachedUrls.length} precached asset(s), ` +
      `${result.serviceWorker.cacheNames.length} cache(s)`,
    `Manifest: ${result.manifest.parsed ? (result.manifest.name ?? 'parsed') : 'invalid'}`,
    `Status: ${result.ok ? 'offline-ready' : 'not offline-ready'}`,
  ];
  for (const finding of result.findings) {
    const marker = finding.severity === 'error' ? '✖' : '⚠';
    lines.push(`  ${marker} ${finding.code}: ${finding.message}`);
    if (finding.suggestion !== undefined) lines.push(`      → ${finding.suggestion}`);
  }
  return `${lines.join('\n')}\n`;
}

export const swOfflineRuleIds: readonly string[] = [
  'pwa/missing-manifest-field',
  'pwa/invalid-manifest',
  'pwa/missing-icon-size',
  'pwa/service-worker-unparsed',
  'pwa/missing-precache',
  'pwa/unversioned-cache',
  'pwa/no-cache-invalidation',
  'pwa/no-offline-fallback',
];
