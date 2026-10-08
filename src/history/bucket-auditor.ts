import { sha256 } from '@noble/hashes/sha2';
import { bytesToHex } from '@noble/hashes/utils';
import { cereal, xdr } from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';
import { specUrl } from '../spec.js';
import { archiveBase, readJson } from './publish-validator.js';

/**
 * History archive bucket integrity auditor (issue #87).
 *
 * A History Archive State (HAS) declares the bucket files a validator
 * publishes, and each bucket file is named `bucket-<sha256>.xdr.gz` in a
 * content-addressed `bucket/xx/yy/zz/` tree. `history/archive-lagging` and the
 * HAS metadata check validate the state file itself, but never open a bucket:
 * a truncated upload or a bit-rotted object that keeps its name passes both
 * while still crashing (or silently corrupting) every node that catches up
 * from that archive.
 *
 * Under opt-in `--check-network --verify-buckets` this module downloads a
 * sample of the `currentBuckets` the HAS declares, decompresses the gzip
 * stream, recomputes the SHA-256 of the decompressed bytes, and confirms the
 * whole buffer decodes as a stream of XDR `BucketEntry` values. Like its
 * siblings it degrades to silence when an archive is unreachable: the audit
 * only reports what it actually observed.
 */

export const BUCKET_DOWNLOAD_FAILED_RULE = 'history/bucket-download-failed';
export const BUCKET_HASH_MISMATCH_RULE = 'history/bucket-hash-mismatch';
export const BUCKET_XDR_CORRUPTED_RULE = 'history/bucket-xdr-corrupted';

export const BUCKET_DOWNLOAD_FAILED = BUCKET_DOWNLOAD_FAILED_RULE;
export const BUCKET_HASH_MISMATCH = BUCKET_HASH_MISMATCH_RULE;
export const BUCKET_XDR_CORRUPTED = BUCKET_XDR_CORRUPTED_RULE;

/** How many bucket files to open per archive, spread across the HAS levels. */
export const DEFAULT_BUCKET_SAMPLE_COUNT = 1;

/** Refuse to decompress more than this, so a crafted bucket cannot exhaust memory. */
export const DEFAULT_MAX_BUCKET_BYTES = 64 * 1024 * 1024;

export interface BucketAuditorOptions {
  rules?: RuleOverrides;
  /** Number of declared buckets to sample per archive. Defaults to 1. */
  sampleCount?: number;
  /** Upper bound on the decompressed bucket size in bytes. */
  maxBytes?: number;
}

/** One `bucket-<hash>.xdr.gz` a HAS points at. */
export interface BucketReference {
  /** File name as published, e.g. `bucket-<64 hex>.xdr.gz`. */
  name: string;
  /** Expected SHA-256 of the decompressed stream, when it can be derived. */
  hash?: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : undefined;
}

function severityFor(
  rule: string,
  fallback: Severity,
  rules: RuleOverrides | undefined,
): Severity | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' || override === 'info'
    ? override
    : fallback;
}

/**
 * The SHA-256 a bucket file name encodes, or `undefined` when the name does not
 * follow the `bucket-<64 hex>.xdr.gz` convention.
 */
export function bucketHashFromName(name: string): string | undefined {
  const base = name.split(/[\\/]/).pop() ?? name;
  const match = /^bucket-([0-9a-f]{64})\.xdr\.gz$/i.exec(base);
  return match?.[1]?.toLowerCase();
}

/** The content-addressed archive path for a bucket name. */
export function bucketPathFor(name: string, hash?: string): string {
  const base = name.split(/[\\/]/).pop() ?? name;
  const digest = hash ?? bucketHashFromName(base);
  if (digest === undefined) return `bucket/${base}`;
  return `bucket/${digest.slice(0, 2)}/${digest.slice(2, 4)}/${digest.slice(4, 6)}/${base}`;
}

/**
 * Every `currentBuckets` file a HAS declares, in level order. Entries are the
 * standard `{ curr, snap, next }` objects, but a bare string (or an explicit
 * `hash`) is accepted so a looser publisher is still audited.
 */
export function bucketReferences(has: unknown): BucketReference[] {
  if (!isRecord(has) || !Array.isArray(has.currentBuckets)) return [];
  const references: BucketReference[] = [];
  const seen = new Set<string>();
  for (const entry of has.currentBuckets) {
    let name: string | undefined;
    let hash: string | undefined;
    if (typeof entry === 'string') {
      name = stringValue(entry);
    } else if (isRecord(entry)) {
      name = stringValue(entry.curr) ?? stringValue(entry.snap) ?? stringValue(entry.name);
      hash = stringValue(entry.hash) ?? stringValue(entry.bucketHash);
    }
    if (name === undefined) continue;
    const base = name.split(/[\\/]/).pop() ?? name;
    if (seen.has(base)) continue;
    seen.add(base);
    const derived = hash ?? bucketHashFromName(base);
    references.push({ name: base, ...(derived === undefined ? {} : { hash: derived }) });
  }
  return references;
}

/** Spread `count` samples across `items`, in order. */
export function sampleBuckets<T>(items: readonly T[], count: number): T[] {
  if (count <= 0 || items.length === 0) return [];
  if (count >= items.length) return [...items];
  const step = items.length / count;
  const sampled: T[] = [];
  for (let index = 0; index < count; index++) {
    const item = items[Math.floor(index * step)];
    if (item !== undefined) sampled.push(item);
  }
  return sampled;
}

/** True when `bytes` decodes start to finish as a stream of `BucketEntry`. */
export function isBucketEntryStream(bytes: Buffer): boolean {
  if (bytes.length === 0) return false;
  try {
    const reader = new cereal.XdrReader(bytes);
    let entries = 0;
    while (!reader.eof) {
      // The published types still describe `read` as taking a Buffer, but the
      // runtime consumes the cursor `fromXDR` builds internally.
      xdr.BucketEntry.read(reader as unknown as Buffer);
      entries++;
    }
    return entries > 0;
  } catch {
    return false;
  }
}

/**
 * Gunzips a bucket stream, falling back to the raw bytes for archives that mirror
 * a bucket uncompressed. Loaded lazily so the browser bundle's closure keeps
 * every `node:` built-in behind a dynamic import.
 */
async function decompress(bytes: Buffer): Promise<Buffer | undefined> {
  if (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) {
    try {
      const { gunzipSync } = await import('node:zlib');
      return gunzipSync(bytes);
    } catch {
      return undefined;
    }
  }
  // Some archives mirror buckets uncompressed; accept the raw bytes then.
  return bytes;
}

interface ReportContext {
  path: string;
  rules: RuleOverrides | undefined;
  diagnostics: Diagnostic[];
}

function report(
  context: ReportContext,
  rule: string,
  fallback: Severity,
  message: string,
  suggestion: string,
  reference?: BucketReference,
): void {
  const severity = severityFor(rule, fallback, context.rules);
  if (severity === undefined) return;
  context.diagnostics.push({
    rule,
    severity,
    category: 'validators',
    message: reference === undefined ? message : `${message} (${reference.name})`,
    path: context.path,
    helpUri: specUrl('validator-information'),
    suggestion,
  });
}

/**
 * Audits one declared bucket: download, decompress, verify the SHA-256, and
 * decode the XDR entry stream. Returns the diagnostics it produced.
 */
export async function auditBucketFile(
  baseUrl: string,
  reference: BucketReference,
  fetchImpl: typeof fetch,
  options: BucketAuditorOptions = {},
  path = 'HISTORY',
): Promise<Diagnostic[]> {
  const context: ReportContext = { path, rules: options.rules, diagnostics: [] };
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BUCKET_BYTES;
  const url = new URL(bucketPathFor(reference.name, reference.hash), baseUrl).toString();

  let response: Response;
  try {
    response = await fetchImpl(url);
  } catch {
    report(
      context,
      BUCKET_DOWNLOAD_FAILED_RULE,
      'error',
      'declared bucket file could not be downloaded',
      'Re-publish the bucket from a node synced to the canonical chain, or fix the archive host.',
      reference,
    );
    return context.diagnostics;
  }
  if (!response.ok) {
    report(
      context,
      BUCKET_DOWNLOAD_FAILED_RULE,
      'error',
      `declared bucket file returned HTTP ${response.status}`,
      'Re-publish the bucket from a node synced to the canonical chain, or fix the archive host.',
      reference,
    );
    return context.diagnostics;
  }

  let raw: Buffer;
  try {
    raw = Buffer.from(await response.arrayBuffer());
  } catch {
    report(
      context,
      BUCKET_DOWNLOAD_FAILED_RULE,
      'error',
      'declared bucket file could not be read',
      'Re-publish the bucket from a node synced to the canonical chain, or fix the archive host.',
      reference,
    );
    return context.diagnostics;
  }

  const bytes = await decompress(raw);
  if (bytes === undefined || bytes.length > maxBytes) {
    report(
      context,
      BUCKET_XDR_CORRUPTED_RULE,
      'error',
      'declared bucket is not a readable gzip stream',
      'Re-publish the bucket; a truncated or re-compressed upload cannot be decompressed by a catchup.',
      reference,
    );
    return context.diagnostics;
  }

  if (reference.hash !== undefined) {
    const actual = bytesToHex(sha256(bytes));
    if (actual !== reference.hash) {
      report(
        context,
        BUCKET_HASH_MISMATCH_RULE,
        'error',
        `bucket content hash ${actual} does not match the ${reference.hash} in its file name`,
        'The published bucket was altered after it was named; re-publish the unmodified bucket.',
        reference,
      );
      // The hash already failed; a decode of tampered bytes says nothing new.
      return context.diagnostics;
    }
  }

  if (!isBucketEntryStream(bytes)) {
    report(
      context,
      BUCKET_XDR_CORRUPTED_RULE,
      'error',
      'declared bucket does not contain a valid XDR BucketEntry stream',
      'Re-publish the bucket from a node synced to the canonical chain; caught-up nodes will fail to decode it.',
      reference,
    );
  }
  return context.diagnostics;
}

function validatorHistories(doc: Record<string, unknown>): string[] {
  const list = Array.isArray(doc.VALIDATORS) ? doc.VALIDATORS : [];
  const histories: string[] = [];
  for (const entry of list) {
    if (!isRecord(entry)) continue;
    const history = stringValue(entry.HISTORY);
    if (history !== undefined) histories.push(history);
  }
  return histories;
}

/**
 * Downloads and verifies a sample of every declared archive's `currentBuckets`.
 *
 * `history/bucket-download-failed` errors when a declared bucket cannot be
 * fetched, `history/bucket-hash-mismatch` when the decompressed content hash
 * disagrees with the name, and `history/bucket-xdr-corrupted` when the gzip
 * stream cannot be read or the bytes are not a valid XDR `BucketEntry` stream.
 */
export async function checkBucketIntegrity(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: BucketAuditorOptions = {},
): Promise<Diagnostic[]> {
  const histories = validatorHistories(doc);
  if (histories.length === 0) return [];

  const sampleCount = Math.max(0, options.sampleCount ?? DEFAULT_BUCKET_SAMPLE_COUNT);
  const diagnostics: Diagnostic[] = [];

  for (let index = 0; index < histories.length; index++) {
    const history = histories[index];
    if (history === undefined) continue;
    const baseUrl = archiveBase(history);
    if (baseUrl === undefined) continue;
    const path = `VALIDATORS[${index}].HISTORY`;

    const hasBody = await readJson(
      new URL('.well-known/stellar-history.json', baseUrl).toString(),
      fetchImpl,
    );
    const references = bucketReferences(hasBody);
    if (references.length === 0) continue; // nothing declared; stay silent

    for (const reference of sampleBuckets(references, sampleCount)) {
      diagnostics.push(...(await auditBucketFile(baseUrl, reference, fetchImpl, options, path)));
    }
  }
  return diagnostics;
}

export const checkBucketAudit = checkBucketIntegrity;
export const checkBucketHashes = checkBucketIntegrity;
export const verifyBuckets = checkBucketIntegrity;

/** Rules registered so `--list-rules`, `--off`, and SARIF know the ids. */
export const bucketAuditorRules: Rule[] = [
  {
    id: BUCKET_DOWNLOAD_FAILED_RULE,
    category: 'validators',
    severity: 'error',
    description: 'Bucket files declared in a HAS must be downloadable from the archive',
    run() {},
  },
  {
    id: BUCKET_HASH_MISMATCH_RULE,
    category: 'validators',
    severity: 'error',
    description: 'Bucket content hashes must match the SHA-256 encoded in the file name',
    run() {},
  },
  {
    id: BUCKET_XDR_CORRUPTED_RULE,
    category: 'validators',
    severity: 'error',
    description: 'Bucket files must contain a valid XDR BucketEntry stream',
    run() {},
  },
];

export const bucketAuditorRuleIds: readonly string[] = bucketAuditorRules.map((rule) => rule.id);
