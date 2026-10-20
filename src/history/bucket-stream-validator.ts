import { cereal, xdr } from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';
import { specUrl } from '../spec.js';
import { bucketPathFor, bucketReferences, type BucketReference } from './bucket-auditor.js';
import { archiveBase, readJson } from './publish-validator.js';

/**
 * Archival bucket compression integrity and corrupted XDR stream check
 * (issue #315).
 *
 * History archives store ledger state as gzip-compressed XDR bucket files.
 * Object storage fails quietly: a multipart upload that was cut short, or a
 * bit flipped at rest, leaves an object that keeps its name and its HTTP 200
 * but is no longer a gzip stream a catchup can read — and stellar-core finds
 * out only when it is halfway through applying it.
 *
 * Under opt-in `--check-network --verify-buckets` this module picks a random
 * sample of the buckets each archive's History Archive State declares and,
 * without downloading whole buckets where it can avoid it:
 *
 * 1. fetches the head of the file with an HTTP `Range` request and validates
 *    the gzip member header — magic bytes, compression method, reserved flags,
 *    the optional `FEXTRA`/`FNAME`/`FCOMMENT` fields, and the `FHCRC` header
 *    checksum when one is present;
 * 2. when the whole file fits under a size bound, downloads the rest,
 *    inflates the deflate body, and compares the CRC32 and length in the
 *    gzip trailer against the decompressed bytes; otherwise inflates just the
 *    prefix with a sync flush, which still catches a corrupt deflate stream;
 * 3. decodes the leading `BucketEntry` records — stellar-core writes them
 *    with XDR record marking (a 4-byte length with the high bit set before
 *    each entry), and a raw unmarked stream is accepted too — and, for a
 *    fully downloaded bucket, confirms the stream does not stop mid-record.
 *
 * A damaged gzip header, deflate stream, or trailer emits
 * `history/corrupted-bucket-gzip-stream`; a stream that decompresses but
 * whose XDR records are cut short or undecodable emits
 * `history/truncated-bucket-xdr`. Download failures are left to
 * `history/bucket-download-failed`, which runs under the same flag, and an
 * archive whose HAS cannot be read stays silent.
 */

export const CORRUPTED_BUCKET_GZIP_STREAM_RULE = 'history/corrupted-bucket-gzip-stream';
export const TRUNCATED_BUCKET_XDR_RULE = 'history/truncated-bucket-xdr';
export const HISTORY_CORRUPTED_BUCKET_GZIP_STREAM = CORRUPTED_BUCKET_GZIP_STREAM_RULE;
export const HISTORY_TRUNCATED_BUCKET_XDR = TRUNCATED_BUCKET_XDR_RULE;

/** How many buckets to open per archive. */
export const DEFAULT_BUCKET_STREAM_SAMPLE_COUNT = 2;

/** How many bytes of each bucket the first ranged request asks for. */
export const DEFAULT_BUCKET_RANGE_BYTES = 64 * 1024;

/**
 * Buckets up to this size are downloaded whole so the gzip trailer's CRC32 can
 * be checked; larger ones are validated from their prefix only.
 */
export const DEFAULT_FULL_VERIFY_MAX_BYTES = 8 * 1024 * 1024;

/** How many leading `BucketEntry` records to decode from a prefix. */
export const DEFAULT_LEADING_ENTRIES = 16;

/** The hash stellar-core gives an empty bucket, which is never published. */
const EMPTY_BUCKET_HASH = '0'.repeat(64);

const GZIP_HEADER_BYTES = 10;
const GZIP_TRAILER_BYTES = 8;
const FHCRC = 0x02;
const FEXTRA = 0x04;
const FNAME = 0x08;
const FCOMMENT = 0x10;
const FRESERVED = 0xe0;
const XDR_RECORD_LAST_FRAGMENT = 0x8000_0000;

/**
 * No single `BucketEntry` comes near this size, so a record mark claiming more
 * is not a record mark. It matters because an unmarked stream opens with
 * `METAENTRY`, whose discriminant -1 also has the high bit set.
 */
const MAX_RECORD_BYTES = 0x0100_0000;

export interface BucketStreamOptions {
  rules?: RuleOverrides;
  /** Buckets to open per archive. */
  sampleCount?: number;
  /** Bytes requested by the first ranged request. */
  rangeBytes?: number;
  /** Largest bucket downloaded whole for the CRC32 check. */
  fullVerifyMaxBytes?: number;
  /** Leading records to decode from a prefix. */
  leadingEntries?: number;
  /** Random source for sampling; injectable so tests are deterministic. */
  random?: () => number;
}

/** A parsed gzip member header, or why it is not one. */
export type GzipHeaderResult =
  | { ok: true; headerLength: number; flags: number; mtime: number; name?: string }
  | { ok: false; reason: string };

/** What the integrity pipeline found for one bucket. */
export type BucketStreamVerdict =
  | { status: 'ok'; entries: number; crcVerified: boolean }
  | { status: 'corrupted-gzip'; reason: string }
  | { status: 'truncated-xdr'; reason: string }
  /** The bucket could not be fetched; reported by the bucket auditor instead. */
  | { status: 'unavailable' };

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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

let crcTable: Uint32Array | undefined;

/** CRC-32 (ISO-HDLC, the polynomial gzip uses) of `bytes`. */
export function crc32(bytes: Uint8Array, seed = 0): number {
  if (crcTable === undefined) {
    crcTable = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb8_8320 ^ (c >>> 1) : c >>> 1;
      crcTable[n] = c >>> 0;
    }
  }
  let crc = ~seed >>> 0;
  for (const byte of bytes) crc = (crcTable[(crc ^ byte) & 0xff] as number) ^ (crc >>> 8);
  return ~crc >>> 0;
}

function hex(byte: number | undefined): string {
  return (byte ?? 0).toString(16).padStart(2, '0');
}

/** Index of the next NUL at or after `from`, or -1. */
function nulAfter(bytes: Uint8Array, from: number): number {
  for (let index = from; index < bytes.length; index++) if (bytes[index] === 0) return index;
  return -1;
}

/**
 * Validates an RFC 1952 gzip member header and returns where the deflate body
 * starts. `bytes` may be just the head of the file.
 */
export function parseGzipHeader(bytes: Uint8Array): GzipHeaderResult {
  if (bytes.length < GZIP_HEADER_BYTES) {
    return {
      ok: false,
      reason: `only ${bytes.length} bytes, shorter than the 10-byte gzip header`,
    };
  }
  if (bytes[0] !== 0x1f || bytes[1] !== 0x8b) {
    return {
      ok: false,
      reason: `missing gzip magic bytes 1f 8b (found ${hex(bytes[0])} ${hex(bytes[1])})`,
    };
  }
  if (bytes[2] !== 8) {
    return { ok: false, reason: `unsupported compression method ${bytes[2]} (gzip requires 8)` };
  }
  const flags = bytes[3] as number;
  if ((flags & FRESERVED) !== 0) {
    return { ok: false, reason: `reserved gzip header flag bits set (0x${hex(flags)})` };
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const mtime = view.getUint32(4, true);

  let offset = GZIP_HEADER_BYTES;
  const truncated = { ok: false as const, reason: 'gzip header is cut short' };
  if (flags & FEXTRA) {
    if (offset + 2 > bytes.length) return truncated;
    offset += 2 + view.getUint16(offset, true);
    if (offset > bytes.length) return truncated;
  }
  let name: string | undefined;
  if (flags & FNAME) {
    const end = nulAfter(bytes, offset);
    if (end < 0) return truncated;
    name = new TextDecoder('latin1').decode(bytes.subarray(offset, end));
    offset = end + 1;
  }
  if (flags & FCOMMENT) {
    const end = nulAfter(bytes, offset);
    if (end < 0) return truncated;
    offset = end + 1;
  }
  if (flags & FHCRC) {
    if (offset + 2 > bytes.length) return truncated;
    const expected = view.getUint16(offset, true);
    const actual = crc32(bytes.subarray(0, offset)) & 0xffff;
    if (expected !== actual) {
      return {
        ok: false,
        reason: `gzip header CRC16 0x${expected.toString(16)} does not match 0x${actual.toString(16)}`,
      };
    }
    offset += 2;
  }
  return { ok: true, headerLength: offset, flags, mtime, ...(name === undefined ? {} : { name }) };
}

/** Loaded lazily so browser bundles never pull in `node:zlib`. */
// The return type is inferred: a static `node:` type import would put the
// built-in in the browser graph's import scan.
async function zlib() {
  return import('node:zlib');
}

/**
 * Verifies a complete single-member gzip file: header, deflate body, and the
 * trailer's CRC32 and ISIZE against the decompressed bytes.
 */
export async function verifyGzipMember(
  file: Uint8Array,
): Promise<{ ok: true; data: Buffer } | { ok: false; reason: string }> {
  const header = parseGzipHeader(file);
  if (!header.ok) return header;
  if (file.length < header.headerLength + GZIP_TRAILER_BYTES) {
    return { ok: false, reason: 'gzip stream ends before its 8-byte trailer' };
  }
  const { inflateRawSync } = await zlib();
  let data: Buffer;
  try {
    data = inflateRawSync(file.subarray(header.headerLength, file.length - GZIP_TRAILER_BYTES));
  } catch (error) {
    return {
      ok: false,
      reason: `deflate stream is corrupt or truncated (${error instanceof Error ? error.message : String(error)})`,
    };
  }
  const trailer = new DataView(
    file.buffer,
    file.byteOffset + file.length - GZIP_TRAILER_BYTES,
    GZIP_TRAILER_BYTES,
  );
  const expectedCrc = trailer.getUint32(0, true);
  const expectedSize = trailer.getUint32(4, true);
  const actualCrc = crc32(data);
  if (expectedCrc !== actualCrc) {
    return {
      ok: false,
      reason: `CRC32 0x${actualCrc.toString(16).padStart(8, '0')} of the decompressed stream does not match the trailer's 0x${expectedCrc.toString(16).padStart(8, '0')}`,
    };
  }
  if (expectedSize !== data.length % 2 ** 32) {
    return {
      ok: false,
      reason: `decompressed ${data.length} bytes but the gzip trailer declares ${expectedSize}`,
    };
  }
  return { ok: true, data };
}

/**
 * Inflates as much of a gzip prefix as is available. A sync flush returns the
 * bytes decoded so far instead of failing on the missing tail, while a corrupt
 * block still throws.
 */
export async function inflatePrefix(
  prefix: Uint8Array,
  headerLength: number,
): Promise<{ ok: true; data: Buffer } | { ok: false; reason: string }> {
  const { inflateRawSync, constants } = await zlib();
  try {
    return {
      ok: true,
      data: inflateRawSync(prefix.subarray(headerLength), {
        finishFlush: constants.Z_SYNC_FLUSH,
      }),
    };
  } catch (error) {
    return {
      ok: false,
      reason: `deflate stream is corrupt (${error instanceof Error ? error.message : String(error)})`,
    };
  }
}

/**
 * Decodes the leading `BucketEntry` records of a decompressed stream.
 *
 * `complete` says whether `bytes` is the whole stream: if it is, a record cut
 * short is a truncation; if it is only a prefix, decoding just stops at the
 * boundary.
 */
export function decodeLeadingBucketEntries(
  bytes: Uint8Array,
  options: { complete: boolean; limit?: number },
): { ok: true; entries: number } | { ok: false; reason: string } {
  const limit = options.complete ? Infinity : (options.limit ?? DEFAULT_LEADING_ENTRIES);
  const buffer = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (buffer.length === 0) {
    return { ok: false, reason: 'bucket decompresses to zero bytes' };
  }

  const first = buffer.length >= 4 ? buffer.readUInt32BE(0) : 0;
  const recordMarked =
    (first & XDR_RECORD_LAST_FRAGMENT) !== 0 &&
    (first & ~XDR_RECORD_LAST_FRAGMENT) <= MAX_RECORD_BYTES;
  if (!recordMarked) return decodeUnmarkedEntries(buffer, options.complete, limit);

  let offset = 0;
  let entries = 0;
  while (offset < buffer.length && entries < limit) {
    if (offset + 4 > buffer.length) {
      if (!options.complete) break;
      return {
        ok: false,
        reason: `stream ends inside the record header of entry ${entries + 1} (${buffer.length - offset} of 4 bytes)`,
      };
    }
    const mark = buffer.readUInt32BE(offset);
    if ((mark & XDR_RECORD_LAST_FRAGMENT) === 0) {
      return {
        ok: false,
        reason: `entry ${entries + 1} at offset ${offset} has no XDR record mark`,
      };
    }
    const length = mark & ~XDR_RECORD_LAST_FRAGMENT;
    const start = offset + 4;
    if (start + length > buffer.length) {
      if (!options.complete) break;
      return {
        ok: false,
        reason: `entry ${entries + 1} declares ${length} bytes but only ${buffer.length - start} remain`,
      };
    }
    try {
      xdr.BucketEntry.fromXDR(buffer.subarray(start, start + length));
    } catch (error) {
      return {
        ok: false,
        reason: `entry ${entries + 1} does not decode as a BucketEntry (${error instanceof Error ? error.message : String(error)})`,
      };
    }
    offset = start + length;
    entries++;
  }

  if (entries === 0) {
    return { ok: false, reason: 'no complete BucketEntry record in the decompressed bytes read' };
  }
  return { ok: true, entries };
}

/**
 * Some mirrors strip the record marks and store entries back to back. With no
 * lengths to go by, each entry is found by decoding it from a cursor.
 */
function decodeUnmarkedEntries(
  buffer: Buffer,
  complete: boolean,
  limit: number,
): { ok: true; entries: number } | { ok: false; reason: string } {
  const reader = new cereal.XdrReader(buffer);
  // The cursor is not part of the published types, but it is the only way to
  // tell how far a successful read got.
  const position = (): number => (reader as unknown as { _index: number })._index;
  let entries = 0;
  while (!reader.eof && entries < limit) {
    const offset = position();
    try {
      xdr.BucketEntry.read(reader as unknown as Buffer);
    } catch {
      if (!complete && entries > 0) break;
      return {
        ok: false,
        reason: `entry ${entries + 1} at offset ${offset} does not decode as a complete BucketEntry`,
      };
    }
    entries++;
  }
  if (entries === 0) {
    return { ok: false, reason: 'no complete BucketEntry record in the decompressed bytes read' };
  }
  return { ok: true, entries };
}

/** Reads at most `limit` bytes of a body, cancelling the rest. */
async function readLimited(
  response: Response,
  limit: number,
): Promise<{ bytes: Buffer; exhausted: boolean }> {
  if (response.body === null) return { bytes: Buffer.alloc(0), exhausted: true };
  const reader = response.body.getReader();
  const chunks: Buffer[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) return { bytes: Buffer.concat(chunks), exhausted: true };
    chunks.push(Buffer.from(value));
    size += value.length;
    if (size > limit) {
      await reader.cancel().catch(() => undefined);
      return { bytes: Buffer.concat(chunks).subarray(0, limit), exhausted: false };
    }
  }
}

/** A ranged read: the bytes, and whether they are the whole file. */
interface RangeRead {
  bytes: Buffer;
  complete: boolean;
  total?: number;
}

async function fetchRange(
  url: string,
  start: number,
  end: number,
  fetchImpl: typeof fetch,
): Promise<RangeRead | 'empty' | undefined> {
  let response: Response;
  try {
    response = await fetchImpl(url, { headers: { Range: `bytes=${start}-${end}` } });
  } catch {
    return undefined;
  }
  // 416 on a request starting at byte 0 means there is no byte 0.
  if (response.status === 416 && start === 0) return 'empty';
  if (!response.ok) return undefined;

  const wanted = end - start + 1;
  if (response.status === 206) {
    const range = /bytes\s+(\d+)-(\d+)\/(\d+|\*)/i.exec(
      response.headers.get('content-range') ?? '',
    );
    const { bytes } = await readLimited(response, wanted);
    const total = range?.[3] !== undefined && range[3] !== '*' ? Number(range[3]) : undefined;
    const last = range?.[2] !== undefined ? Number(range[2]) : start + bytes.length - 1;
    return {
      bytes,
      complete: total !== undefined && last + 1 >= total,
      ...(total === undefined ? {} : { total }),
    };
  }

  // The server ignored the Range header and is sending the whole object.
  if (start !== 0) return undefined;
  const { bytes, exhausted } = await readLimited(response, wanted);
  return { bytes, complete: exhausted, ...(exhausted ? { total: bytes.length } : {}) };
}

/**
 * Runs the full pipeline against one bucket: ranged header read, gzip and
 * CRC32 verification, and leading XDR record decoding.
 */
export async function validateBucketStream(
  url: string,
  fetchImpl: typeof fetch,
  options: BucketStreamOptions = {},
): Promise<BucketStreamVerdict> {
  const rangeBytes = Math.max(GZIP_HEADER_BYTES, options.rangeBytes ?? DEFAULT_BUCKET_RANGE_BYTES);
  const fullVerifyMaxBytes = options.fullVerifyMaxBytes ?? DEFAULT_FULL_VERIFY_MAX_BYTES;

  const head = await fetchRange(url, 0, rangeBytes - 1, fetchImpl);
  if (head === undefined) return { status: 'unavailable' };
  if (head === 'empty') return { status: 'corrupted-gzip', reason: 'bucket file is empty' };

  const header = parseGzipHeader(head.bytes);
  if (!header.ok) return { status: 'corrupted-gzip', reason: header.reason };

  let whole: Buffer | undefined = head.complete ? head.bytes : undefined;
  if (whole === undefined && head.total !== undefined && head.total <= fullVerifyMaxBytes) {
    const rest = await fetchRange(url, head.bytes.length, head.total - 1, fetchImpl);
    if (rest !== undefined && rest !== 'empty') {
      whole = Buffer.concat([head.bytes, rest.bytes]);
      if (whole.length !== head.total) {
        return {
          status: 'corrupted-gzip',
          reason: `archive served ${whole.length} bytes of a ${head.total}-byte bucket`,
        };
      }
    }
  }

  if (whole !== undefined) {
    const member = await verifyGzipMember(whole);
    if (!member.ok) return { status: 'corrupted-gzip', reason: member.reason };
    const decoded = decodeLeadingBucketEntries(member.data, { complete: true });
    if (!decoded.ok) return { status: 'truncated-xdr', reason: decoded.reason };
    return { status: 'ok', entries: decoded.entries, crcVerified: true };
  }

  const prefix = await inflatePrefix(head.bytes, header.headerLength);
  if (!prefix.ok) return { status: 'corrupted-gzip', reason: prefix.reason };
  const decoded = decodeLeadingBucketEntries(prefix.data, {
    complete: false,
    limit: options.leadingEntries ?? DEFAULT_LEADING_ENTRIES,
  });
  if (!decoded.ok) return { status: 'truncated-xdr', reason: decoded.reason };
  return { status: 'ok', entries: decoded.entries, crcVerified: false };
}

/** `count` distinct items chosen at random, in their original order. */
export function sampleRandomBuckets<T>(
  items: readonly T[],
  count: number,
  random: () => number = Math.random,
): T[] {
  if (count <= 0) return [];
  if (count >= items.length) return [...items];
  const indices = items.map((_, index) => index);
  for (let index = indices.length - 1; index > 0; index--) {
    const swap = Math.floor(random() * (index + 1));
    [indices[index], indices[swap]] = [indices[swap] as number, indices[index] as number];
  }
  return indices
    .slice(0, count)
    .sort((a, b) => a - b)
    .map((index) => items[index] as T);
}

/**
 * stellar-core's HAS names each bucket by its bare hex hash, while looser
 * publishers write the file name; both resolve to `bucket-<hash>.xdr.gz`.
 */
export function normalizeBucketReference(reference: BucketReference): BucketReference {
  if (/^[0-9a-f]{64}$/i.test(reference.name)) {
    const hash = reference.name.toLowerCase();
    return { name: `bucket-${hash}.xdr.gz`, hash };
  }
  return reference;
}

function validatorHistories(doc: Record<string, unknown>): { index: number; history: string }[] {
  const list = Array.isArray(doc.VALIDATORS) ? doc.VALIDATORS : [];
  const histories: { index: number; history: string }[] = [];
  list.forEach((entry, index) => {
    if (!isRecord(entry)) return;
    const history = entry.HISTORY;
    if (typeof history === 'string' && history.trim() !== '') {
      histories.push({ index, history: history.trim() });
    }
  });
  return histories;
}

function diagnosticFor(
  verdict: BucketStreamVerdict,
  reference: BucketReference,
  path: string,
  rules: RuleOverrides | undefined,
): Diagnostic[] {
  if (verdict.status === 'corrupted-gzip') {
    const severity = severityFor(CORRUPTED_BUCKET_GZIP_STREAM_RULE, 'error', rules);
    if (severity === undefined) return [];
    return [
      {
        rule: CORRUPTED_BUCKET_GZIP_STREAM_RULE,
        severity,
        category: 'validators',
        message: `${path} bucket ${reference.name} is not a valid gzip stream: ${verdict.reason}`,
        path,
        helpUri: specUrl('validator-information'),
        suggestion:
          'Re-upload the bucket from the publishing node; a truncated multipart upload or bit-rotted object crashes every catchup that reaches it.',
      },
    ];
  }
  if (verdict.status === 'truncated-xdr') {
    const severity = severityFor(TRUNCATED_BUCKET_XDR_RULE, 'error', rules);
    if (severity === undefined) return [];
    return [
      {
        rule: TRUNCATED_BUCKET_XDR_RULE,
        severity,
        category: 'validators',
        message: `${path} bucket ${reference.name} decompresses but its XDR stream is broken: ${verdict.reason}`,
        path,
        helpUri: specUrl('validator-information'),
        suggestion:
          'Re-publish the bucket from a node synced to the canonical chain; catchup cannot apply a bucket whose BucketEntry records are cut short.',
      },
    ];
  }
  return [];
}

/**
 * The `--check-network --verify-buckets` stream audit: validate the gzip
 * framing and leading XDR records of a random sample of every declared
 * archive's buckets.
 */
export async function checkBucketStreams(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: BucketStreamOptions = {},
): Promise<Diagnostic[]> {
  const diagnostics: Diagnostic[] = [];
  const sampleCount = Math.max(0, options.sampleCount ?? DEFAULT_BUCKET_STREAM_SAMPLE_COUNT);

  for (const { index, history } of validatorHistories(doc)) {
    const baseUrl = archiveBase(history);
    if (baseUrl === undefined) continue;
    const path = `VALIDATORS[${index}].HISTORY`;

    const has = await readJson(
      new URL('.well-known/stellar-history.json', baseUrl).toString(),
      fetchImpl,
    );
    const references = bucketReferences(has)
      .map(normalizeBucketReference)
      .filter((reference) => reference.hash !== EMPTY_BUCKET_HASH);
    for (const reference of sampleRandomBuckets(references, sampleCount, options.random)) {
      const url = new URL(bucketPathFor(reference.name, reference.hash), baseUrl).toString();
      const verdict = await validateBucketStream(url, fetchImpl, options);
      diagnostics.push(...diagnosticFor(verdict, reference, path, options.rules));
    }
  }
  return diagnostics;
}

export const verifyBucketStreams = checkBucketStreams;
export const auditBucketStreams = checkBucketStreams;

/** Rules registered so `--list-rules`, `--off`, and SARIF know the ids. */
export const bucketStreamRules: Rule[] = [
  {
    id: CORRUPTED_BUCKET_GZIP_STREAM_RULE,
    category: 'validators',
    severity: 'error',
    description:
      'Archive bucket files must be intact gzip streams with a valid header, deflate body, and CRC32',
    run() {},
  },
  {
    id: TRUNCATED_BUCKET_XDR_RULE,
    category: 'validators',
    severity: 'error',
    description: 'Archive bucket files must decompress to complete XDR BucketEntry records',
    run() {},
  },
];

export const bucketStreamRuleIds: readonly string[] = bucketStreamRules.map((rule) => rule.id);
