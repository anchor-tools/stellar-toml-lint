/**
 * Multi-tenant anchor directory synchronization verifier.
 *
 * Aggregators, remittance directories, and multi-tenant platforms keep their
 * own copy of every anchor's assets, signing key, and service URLs. When that
 * copy drifts from the live `stellar.toml`, a wallet is routed to a retired
 * transfer server or shown a stale fee schedule.
 *
 * `DirectorySyncVerifier` ingests a directory feed, fetches each advertised
 * domain's `/.well-known/stellar.toml` through a bounded worker pool with
 * per-request timeouts, and diffs the directory record against the published
 * document. Expired listings and unresolvable domains are reported separately
 * from ordinary drift so an operator can triage them differently.
 */

import { parse as parseToml } from 'smol-toml';

export type DirectorySyncStatus =
  | 'in-sync'
  | 'drift'
  | 'expired'
  | 'unresolvable'
  | 'invalid-toml';

export type DirectorySyncFindingCode =
  | 'directory/out-of-sync'
  | 'directory/expired-anchor'
  | 'directory/unresolvable-domain'
  | 'directory/invalid-stellar-toml'
  | 'directory/invalid-feed'
  | 'directory/no-anchors';

export interface DirectoryAnchorRecord {
  domain: string;
  name?: string;
  /** Normalized `CODE:ISSUER` values listed for this anchor. */
  assets: string[];
  signingKey?: string;
  /** Normalized service key → advertised URL. */
  serviceUrls: Record<string, string>;
  expiresAt?: string;
}

export interface DirectoryFeedParseResult {
  anchors: DirectoryAnchorRecord[];
  problems: string[];
}

export interface DriftField {
  field: string;
  directory?: string;
  published?: string;
  reason: string;
}

export interface PublishedAnchor {
  signingKey?: string;
  assets: string[];
  serviceUrls: Record<string, string>;
}

export interface AnchorSyncResult {
  domain: string;
  name?: string;
  status: DirectorySyncStatus;
  documentUrl: string;
  drift: DriftField[];
  published?: PublishedAnchor;
  statusCode?: number;
  error?: string;
  durationMs: number;
}

export interface DirectorySyncFinding {
  code: DirectorySyncFindingCode;
  severity: 'error' | 'warning';
  domain: string;
  message: string;
  suggestion: string;
  fields?: string[];
}

export interface DirectorySyncReport {
  ok: boolean;
  feed?: string;
  checked: number;
  inSync: number;
  drifted: number;
  expired: number;
  unresolvable: number;
  results: AnchorSyncResult[];
  findings: DirectorySyncFinding[];
  generatedAt: string;
}

export interface DirectorySyncOptions {
  fetchImpl?: typeof fetch;
  /** Concurrent domain fetches; defaults to 8. */
  concurrency?: number;
  /** Per-domain timeout in milliseconds; defaults to 10s. */
  timeoutMs?: number;
  /** Clock used for expiry checks; defaults to now. */
  now?: Date;
}

/** SEP-1 service keys compared when a directory record advertises them. */
export const SERVICE_KEYS = [
  'TRANSFER_SERVER',
  'TRANSFER_SERVER_SEP0024',
  'ANCHOR_QUOTE_SERVER',
  'KYC_SERVER',
  'DIRECT_PAYMENT_SERVER',
  'FEDERATION_SERVER',
  'WEB_AUTH_ENDPOINT',
  'TOML_URL',
] as const;

const SERVICE_KEY_SET = new Set<string>(SERVICE_KEYS);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Strips scheme, path, query, and trailing dot; returns undefined if unusable. */
export function normalizeDomain(input: unknown): string | undefined {
  if (typeof input !== 'string') return undefined;
  let value = input.trim();
  if (value === '') return undefined;
  value = value.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
  value = value.split(/[/?#]/)[0] ?? value;
  value = value.replace(/\.+$/, '').toLowerCase();
  if (
    !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/.test(value)
  ) {
    return undefined;
  }
  return value;
}

/** `usd:G...` / `{ code, issuer }` → `USD:G...`. */
export function normalizeAsset(value: unknown): string | undefined {
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (trimmed === '') return undefined;
    const [code, issuer] = trimmed.split(':');
    if (code === undefined || code === '') return undefined;
    return issuer === undefined ? code.toUpperCase() : `${code.toUpperCase()}:${issuer}`;
  }
  if (isRecord(value)) {
    const code = value.code;
    const issuer = value.issuer;
    if (typeof code !== 'string' || code === '') return undefined;
    return typeof issuer === 'string' && issuer !== ''
      ? `${code.toUpperCase()}:${issuer}`
      : code.toUpperCase();
  }
  return undefined;
}

/** `transferServer` / `transfer_server` → `TRANSFER_SERVER`. */
export function normalizeServiceKey(key: string): string {
  return key
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/[\s-]+/g, '_')
    .replace(/_+/g, '_')
    .toUpperCase();
}

/** Canonical form for URL comparison: lowercase host, no hash/query, no trailing slash. */
export function normalizeUrl(value: string): string {
  const trimmed = value.trim();
  try {
    const url = new URL(trimmed);
    const path = url.pathname.replace(/\/+$/, '');
    return `${url.protocol}//${url.host.toLowerCase()}${path}`;
  } catch {
    return trimmed.replace(/\/+$/, '');
  }
}

function stringValue(...values: unknown[]): string | undefined {
  for (const value of values) {
    if (typeof value === 'string' && value.trim() !== '') return value.trim();
  }
  return undefined;
}

function collectServiceUrls(entry: Record<string, unknown>): Record<string, string> {
  const urls: Record<string, string> = {};
  for (const container of [entry.services, entry.serviceUrls, entry.service_urls, entry.endpoints]) {
    if (!isRecord(container)) continue;
    for (const [key, value] of Object.entries(container)) {
      if (typeof value === 'string' && value.trim() !== '') {
        urls[normalizeServiceKey(key)] = value.trim();
      }
    }
  }
  for (const [key, value] of Object.entries(entry)) {
    const normalized = normalizeServiceKey(key);
    if (SERVICE_KEY_SET.has(normalized) && typeof value === 'string' && value.trim() !== '') {
      urls[normalized] = value.trim();
    }
  }
  return urls;
}

/** Parses a JSON directory feed into normalized anchor records. */
export function parseDirectoryFeed(input: unknown): DirectoryFeedParseResult {
  const problems: string[] = [];
  const list = Array.isArray(input)
    ? input
    : isRecord(input)
      ? [input.anchors, input.entries, input.directories, input.data].find(Array.isArray)
      : undefined;

  if (!Array.isArray(list)) {
    return {
      anchors: [],
      problems: ['feed must be a JSON array or an object with an anchors/entries/directories array'],
    };
  }

  const anchors: DirectoryAnchorRecord[] = [];
  const seen = new Set<string>();
  for (let index = 0; index < list.length; index++) {
    const entry: unknown = list[index];
    if (!isRecord(entry)) {
      problems.push(`entry ${index} is not an object`);
      continue;
    }

    const domain = normalizeDomain(entry.domain ?? entry.homeDomain ?? entry.home_domain);
    if (domain === undefined) {
      problems.push(`entry ${index} has no resolvable domain`);
      continue;
    }
    if (seen.has(domain)) {
      problems.push(`entry ${index} repeats domain ${domain}`);
      continue;
    }
    seen.add(domain);

    const rawAssets = entry.assets ?? entry.currencies;
    const assets = Array.isArray(rawAssets)
      ? rawAssets
          .map((asset) => normalizeAsset(asset))
          .filter((asset): asset is string => asset !== undefined)
      : [];

    const name = stringValue(entry.name, entry.organization, entry.org);
    const signingKey = stringValue(entry.signingKey, entry.signing_key, entry.SIGNING_KEY);
    const expiresAt = stringValue(
      entry.expiresAt,
      entry.expires_at,
      entry.expiry,
      entry.validUntil,
      entry.valid_until,
    );

    anchors.push({
      domain,
      ...(name !== undefined ? { name } : {}),
      assets,
      ...(signingKey !== undefined ? { signingKey } : {}),
      serviceUrls: collectServiceUrls(entry),
      ...(expiresAt !== undefined ? { expiresAt } : {}),
    });
  }

  return { anchors, problems };
}

/** Extracts the fields a directory record is compared against. */
export function extractPublishedAnchor(document: Record<string, unknown>): PublishedAnchor {
  const signingKey =
    typeof document.SIGNING_KEY === 'string' && document.SIGNING_KEY !== ''
      ? document.SIGNING_KEY
      : undefined;

  const assets: string[] = [];
  if (Array.isArray(document.CURRENCIES)) {
    for (const currency of document.CURRENCIES) {
      const asset = normalizeAsset(currency);
      if (asset !== undefined) assets.push(asset);
    }
  }

  const serviceUrls: Record<string, string> = {};
  for (const key of SERVICE_KEYS) {
    const value = document[key];
    if (typeof value === 'string' && value.trim() !== '') serviceUrls[key] = value.trim();
  }

  return { ...(signingKey !== undefined ? { signingKey } : {}), assets, serviceUrls };
}

function sameSet(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  const set = new Set(a);
  return b.every((value) => set.has(value));
}

/** Compares a directory record against the live document's published fields. */
export function diffAnchor(record: DirectoryAnchorRecord, published: PublishedAnchor): DriftField[] {
  const drift: DriftField[] = [];

  if (record.signingKey !== undefined) {
    if (published.signingKey === undefined) {
      drift.push({
        field: 'SIGNING_KEY',
        directory: record.signingKey,
        reason: 'directory lists a signing key the document does not publish',
      });
    } else if (record.signingKey !== published.signingKey) {
      drift.push({
        field: 'SIGNING_KEY',
        directory: record.signingKey,
        published: published.signingKey,
        reason: 'signing key changed since the directory was indexed',
      });
    }
  }

  if (record.assets.length > 0 && !sameSet(record.assets, published.assets)) {
    const publishedSet = new Set(published.assets);
    const missing = record.assets.filter((asset) => !publishedSet.has(asset));
    const extra = published.assets.filter((asset) => !new Set(record.assets).has(asset));
    drift.push({
      field: 'CURRENCIES',
      directory: record.assets.join(', '),
      published: published.assets.join(', ') || '(none)',
      reason:
        missing.length > 0
          ? `${missing.length} listed asset(s) no longer published: ${missing.join(', ')}`
          : `${extra.length} published asset(s) missing from the directory: ${extra.join(', ')}`,
    });
  }

  for (const [key, url] of Object.entries(record.serviceUrls)) {
    const publishedUrl = published.serviceUrls[key];
    if (publishedUrl === undefined) {
      drift.push({
        field: key,
        directory: url,
        reason: 'directory advertises a service the document does not publish',
      });
    } else if (normalizeUrl(publishedUrl) !== normalizeUrl(url)) {
      drift.push({
        field: key,
        directory: url,
        published: publishedUrl,
        reason: 'service URL changed since the directory was indexed',
      });
    }
  }

  return drift;
}

function isExpired(expiresAt: string | undefined, now: Date): boolean {
  if (expiresAt === undefined) return false;
  const timestamp = Date.parse(expiresAt);
  return Number.isFinite(timestamp) && timestamp <= now.getTime();
}

/** Bounded worker pool that preserves input order. */
export async function mapPool<T, R>(
  items: readonly T[],
  concurrency: number,
  worker: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const limit = Math.max(1, Math.min(Math.floor(concurrency) || 1, items.length || 1));
  const results = new Array<R>(items.length);
  let next = 0;

  const run = async (): Promise<void> => {
    while (next < items.length) {
      const index = next++;
      const item = items[index] as T;
      results[index] = await worker(item, index);
    }
  };

  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, run));
  return results;
}

async function fetchWithTimeout(
  fetchImpl: typeof fetch,
  url: string,
  timeoutMs: number,
): Promise<Response> {
  const controller = new AbortController();
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new Error(`timed out after ${timeoutMs}ms`));
    }, timeoutMs);
  });
  try {
    return await Promise.race([fetchImpl(url, { signal: controller.signal }), timeout]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

export class DirectorySyncVerifier {
  private readonly fetchImpl: typeof fetch;
  private readonly concurrency: number;
  private readonly timeoutMs: number;
  private readonly now: Date;

  constructor(options: DirectorySyncOptions = {}) {
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.concurrency = options.concurrency ?? 8;
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.now = options.now ?? new Date();
  }

  async verify(
    anchors: readonly DirectoryAnchorRecord[],
    feed?: string,
  ): Promise<DirectorySyncReport> {
    const results = await mapPool(anchors, this.concurrency, (anchor) =>
      this.verifyAnchor(anchor),
    );
    const findings: DirectorySyncFinding[] = [];

    for (const result of results) {
      if (result.status === 'drift') {
        findings.push({
          code: 'directory/out-of-sync',
          severity: 'error',
          domain: result.domain,
          message: `${result.domain} is out of sync: ${result.drift.map((field) => field.field).join(', ')}`,
          suggestion: 'Refresh the directory record from the published stellar.toml, or fix the document.',
          fields: result.drift.map((field) => field.field),
        });
      } else if (result.status === 'expired') {
        findings.push({
          code: 'directory/expired-anchor',
          severity: 'warning',
          domain: result.domain,
          message: `${result.domain} is listed with an expiry date in the past`,
          suggestion: 'Delist the anchor or confirm it renewed before routing users to it.',
        });
      } else if (result.status === 'unresolvable') {
        findings.push({
          code: 'directory/unresolvable-domain',
          severity: 'error',
          domain: result.domain,
          message: `${result.domain} could not be resolved: ${result.error ?? 'unknown error'}`,
          suggestion: 'Remove the dead entry or fix its domain before the directory is published.',
        });
      } else if (result.status === 'invalid-toml') {
        findings.push({
          code: 'directory/invalid-stellar-toml',
          severity: 'error',
          domain: result.domain,
          message: `${result.domain} serves a stellar.toml that does not parse: ${result.error ?? 'unknown error'}`,
          suggestion: 'Fix the published TOML, then re-index the directory entry.',
        });
      }
    }

    if (anchors.length === 0 && findings.length === 0) {
      findings.push({
        code: 'directory/no-anchors',
        severity: 'warning',
        domain: '',
        message: 'The directory feed contained no usable anchor records',
        suggestion: 'Check the feed URL and that entries carry a domain field.',
      });
    }

    return {
      ok: findings.every((finding) => finding.severity !== 'error'),
      ...(feed !== undefined ? { feed } : {}),
      checked: results.length,
      inSync: results.filter((result) => result.status === 'in-sync').length,
      drifted: results.filter((result) => result.status === 'drift').length,
      expired: results.filter((result) => result.status === 'expired').length,
      unresolvable: results.filter(
        (result) => result.status === 'unresolvable' || result.status === 'invalid-toml',
      ).length,
      results,
      findings,
      generatedAt: this.now.toISOString(),
    };
  }

  async verifyAnchor(anchor: DirectoryAnchorRecord): Promise<AnchorSyncResult> {
    const documentUrl = `https://${anchor.domain}/.well-known/stellar.toml`;
    const started = performance.now();
    const duration = (): number => Math.round((performance.now() - started) * 1000) / 1000;
    const base = {
      domain: anchor.domain,
      ...(anchor.name !== undefined ? { name: anchor.name } : {}),
      documentUrl,
    };

    let response: Response;
    try {
      response = await fetchWithTimeout(this.fetchImpl, documentUrl, this.timeoutMs);
    } catch (error) {
      return {
        ...base,
        status: 'unresolvable',
        drift: [],
        error: message(error),
        durationMs: duration(),
      };
    }

    if (!response.ok) {
      return {
        ...base,
        status: 'unresolvable',
        drift: [],
        statusCode: response.status,
        error: `HTTP ${response.status}`,
        durationMs: duration(),
      };
    }

    let document: Record<string, unknown>;
    try {
      const parsed: unknown = parseToml(await response.text());
      if (!isRecord(parsed)) throw new Error('document is not a TOML table');
      document = parsed;
    } catch (error) {
      return {
        ...base,
        status: 'invalid-toml',
        drift: [],
        statusCode: response.status,
        error: message(error),
        durationMs: duration(),
      };
    }

    const published = extractPublishedAnchor(document);
    const drift = diffAnchor(anchor, published);
    const expired = isExpired(anchor.expiresAt, this.now);

    return {
      ...base,
      status: expired ? 'expired' : drift.length > 0 ? 'drift' : 'in-sync',
      drift,
      published,
      statusCode: response.status,
      durationMs: duration(),
    };
  }
}

export function renderDirectorySyncReport(report: DirectorySyncReport): string {
  const lines: string[] = [];
  lines.push(
    `Anchor directory sync: ${report.checked} checked — ` +
      `${report.inSync} in sync, ${report.drifted} drifted, ${report.expired} expired, ` +
      `${report.unresolvable} unresolvable`,
  );
  lines.push('');

  for (const result of report.results) {
    const success = result.status === 'in-sync';
    lines.push(
      `  ${success ? 'ok  ' : 'fail'}  ${result.domain}  ${result.status}  (${result.durationMs}ms)`,
    );
    if (result.error !== undefined) lines.push(`         ${result.error}`);
    for (const field of result.drift) {
      lines.push(`         ${field.field}: ${field.reason}`);
      if (field.directory !== undefined) lines.push(`           directory: ${field.directory}`);
      if (field.published !== undefined) lines.push(`           published: ${field.published}`);
    }
  }

  if (report.findings.length > 0) {
    lines.push('');
    for (const finding of report.findings) {
      lines.push(`  ${finding.severity}  ${finding.code}  ${finding.message}`);
      lines.push(`         fix: ${finding.suggestion}`);
    }
  }
  return `${lines.join('\n')}\n`;
}
