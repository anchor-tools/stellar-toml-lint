import { gzipSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2';
import { bytesToHex } from '@noble/hashes/utils';
import { xdr } from '@stellar/stellar-base';
import {
  checkBucketStreams,
  crc32,
  CORRUPTED_BUCKET_GZIP_STREAM_RULE,
  decodeLeadingBucketEntries,
  parseGzipHeader,
  sampleRandomBuckets,
  TRUNCATED_BUCKET_XDR_RULE,
  validateBucketStream,
} from '../../src/history/bucket-stream-validator.js';

const ARCHIVE = 'https://history.example/archive/';
const HAS_PATH = '/archive/.well-known/stellar-history.json';

function entry(ledgerVersion: number): Buffer {
  return Buffer.from(
    xdr.BucketEntry.metaentry(
      new xdr.BucketMetadata({ ledgerVersion, ext: new xdr.BucketMetadataExt(0) }),
    ).toXDR(),
  );
}

/** A bucket stream the way stellar-core writes it: one XDR record mark per entry. */
function recordMarked(count: number): Buffer {
  return Buffer.concat(
    Array.from({ length: count }, (_, index) => {
      const body = entry(20 + (index % 5));
      const mark = Buffer.alloc(4);
      mark.writeUInt32BE((0x8000_0000 | body.length) >>> 0);
      return Buffer.concat([mark, body]);
    }),
  );
}

function nameFor(stream: Buffer): string {
  return `bucket-${bytesToHex(sha256(stream))}.xdr.gz`;
}

function pathFor(name: string): string {
  const hash = name.slice('bucket-'.length, 'bucket-'.length + 64);
  return `/archive/bucket/${hash.slice(0, 2)}/${hash.slice(2, 4)}/${hash.slice(4, 6)}/${name}`;
}

function urlFor(name: string): string {
  return `https://history.example${pathFor(name)}`;
}

/**
 * A fake archive serving `buckets` (name → gzip bytes) with real Range
 * semantics, unless `ignoreRange` makes it answer every request with 200.
 */
function archive(
  buckets: Record<string, Buffer>,
  options: { ignoreRange?: boolean } = {},
): { fetchImpl: typeof fetch; ranges: string[] } {
  const ranges: string[] = [];
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input));
    if (url.pathname === HAS_PATH) {
      return Response.json({
        currentLedger: 1023,
        currentBuckets: [
          // stellar-core writes bare hashes; the first bucket uses the file-name form.
          ...Object.keys(buckets).map((name, index) => {
            const curr = index === 0 ? name : name.slice('bucket-'.length, -'.xdr.gz'.length);
            return { curr, snap: curr };
          }),
          { curr: '0'.repeat(64) },
        ],
      });
    }
    const name = Object.keys(buckets).find((candidate) => url.pathname === pathFor(candidate));
    if (name === undefined) return new Response('missing', { status: 404 });
    const file = buckets[name] as Buffer;
    const range = new Headers(init?.headers).get('range');
    if (range !== null) ranges.push(range);
    const match = /bytes=(\d+)-(\d+)/.exec(range ?? '');
    if (options.ignoreRange || match === null)
      return new Response(new Uint8Array(file), { status: 200 });
    const start = Number(match[1]);
    if (start >= file.length) return new Response(null, { status: 416 });
    const end = Math.min(Number(match[2]), file.length - 1);
    return new Response(new Uint8Array(file.subarray(start, end + 1)), {
      status: 206,
      headers: { 'Content-Range': `bytes ${start}-${end}/${file.length}` },
    });
  }) as typeof fetch;
  return { fetchImpl, ranges };
}

const doc = { VALIDATORS: [{ HISTORY: ARCHIVE }] };

describe('parseGzipHeader', () => {
  it('accepts a zlib-produced header and walks optional fields', () => {
    expect(parseGzipHeader(gzipSync(Buffer.from('x')))).toMatchObject({
      ok: true,
      headerLength: 10,
    });

    // FNAME + FHCRC, with a correct header CRC16.
    const head = Buffer.concat([
      Buffer.from([0x1f, 0x8b, 8, 0x08 | 0x02, 0, 0, 0, 0, 0, 3]),
      Buffer.from('bucket.xdr\0', 'latin1'),
    ]);
    const hcrc = Buffer.alloc(2);
    hcrc.writeUInt16LE(crc32(head) & 0xffff);
    expect(parseGzipHeader(Buffer.concat([head, hcrc]))).toMatchObject({
      ok: true,
      headerLength: head.length + 2,
      name: 'bucket.xdr',
    });
    hcrc[0] = (hcrc[0] as number) ^ 0xff;
    expect(parseGzipHeader(Buffer.concat([head, hcrc]))).toMatchObject({ ok: false });
  });

  it('rejects bad magic bytes, methods, reserved flags, and short input', () => {
    const good = gzipSync(Buffer.from('x'));
    expect(parseGzipHeader(Buffer.from([0x50, 0x4b, ...good.subarray(2)]))).toMatchObject({
      ok: false,
      reason: expect.stringContaining('magic'),
    });
    const method = Buffer.from(good);
    method[2] = 7;
    expect(parseGzipHeader(method).ok).toBe(false);
    const reserved = Buffer.from(good);
    reserved[3] = 0x80;
    expect(parseGzipHeader(reserved).ok).toBe(false);
    expect(parseGzipHeader(good.subarray(0, 4)).ok).toBe(false);
  });
});

describe('crc32', () => {
  it('matches the standard check value', () => {
    expect(crc32(Buffer.from('123456789'))).toBe(0xcbf4_3926);
  });
});

describe('decodeLeadingBucketEntries', () => {
  it('decodes record-marked and unmarked streams', () => {
    expect(decodeLeadingBucketEntries(recordMarked(3), { complete: true })).toEqual({
      ok: true,
      entries: 3,
    });
    const raw = Buffer.concat([entry(21), entry(22)]);
    expect(decodeLeadingBucketEntries(raw, { complete: true })).toEqual({ ok: true, entries: 2 });
  });

  it('treats a cut record as truncation only when the stream is complete', () => {
    const cut = recordMarked(3).subarray(0, -5);
    expect(decodeLeadingBucketEntries(cut, { complete: true })).toMatchObject({ ok: false });
    expect(decodeLeadingBucketEntries(cut, { complete: false })).toEqual({ ok: true, entries: 2 });
  });
});

describe('validateBucketStream', () => {
  it('passes a valid bucket stream and verifies its CRC32', async () => {
    const stream = recordMarked(4);
    const name = nameFor(stream);
    const { fetchImpl } = archive({ [name]: gzipSync(stream) });
    expect(await validateBucketStream(urlFor(name), fetchImpl)).toEqual({
      status: 'ok',
      entries: 4,
      crcVerified: true,
    });
  });

  it('validates a large bucket from its prefix without downloading it', async () => {
    const stream = recordMarked(4000);
    const name = nameFor(stream);
    const { fetchImpl, ranges } = archive({ [name]: gzipSync(stream, { level: 0 }) });
    const verdict = await validateBucketStream(urlFor(name), fetchImpl, {
      rangeBytes: 4096,
      fullVerifyMaxBytes: 8192,
    });
    expect(verdict).toMatchObject({ status: 'ok', crcVerified: false });
    expect(ranges).toEqual(['bytes=0-4095']);
  });

  it('downloads the remainder of a mid-sized bucket to check its trailer', async () => {
    const stream = recordMarked(400);
    const name = nameFor(stream);
    const { fetchImpl, ranges } = archive({ [name]: gzipSync(stream, { level: 0 }) });
    const verdict = await validateBucketStream(urlFor(name), fetchImpl, { rangeBytes: 1024 });
    expect(verdict).toMatchObject({ status: 'ok', entries: 400, crcVerified: true });
    expect(ranges).toHaveLength(2);
  });

  it('works when the archive ignores Range and sends the whole object', async () => {
    const stream = recordMarked(2);
    const name = nameFor(stream);
    const { fetchImpl } = archive({ [name]: gzipSync(stream) }, { ignoreRange: true });
    expect(await validateBucketStream(urlFor(name), fetchImpl)).toMatchObject({
      status: 'ok',
      crcVerified: true,
    });
  });
});

describe('checkBucketStreams', () => {
  it('passes valid bucket streams and skips the empty bucket', async () => {
    const a = recordMarked(3);
    const b = recordMarked(5);
    const { fetchImpl } = archive({ [nameFor(a)]: gzipSync(a), [nameFor(b)]: gzipSync(b) });
    expect(await checkBucketStreams(doc, fetchImpl, { sampleCount: 5 })).toEqual([]);
  });

  it('flags a corrupted gzip header', async () => {
    const stream = recordMarked(3);
    const file = gzipSync(stream);
    file[0] = 0x00;
    file[1] = 0x00;
    const { fetchImpl } = archive({ [nameFor(stream)]: file });
    const diagnostics = await checkBucketStreams(doc, fetchImpl);
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      rule: CORRUPTED_BUCKET_GZIP_STREAM_RULE,
      severity: 'error',
      path: 'VALIDATORS[0].HISTORY',
    });
    expect(diagnostics[0]?.message).toContain('magic');
  });

  it('flags a CRC32 mismatch in the gzip trailer', async () => {
    const stream = recordMarked(3);
    const file = gzipSync(stream);
    file[file.length - 8] = (file[file.length - 8] as number) ^ 0xff;
    const { fetchImpl } = archive({ [nameFor(stream)]: file });
    const diagnostics = await checkBucketStreams(doc, fetchImpl);
    expect(diagnostics.map((d) => d.rule)).toEqual([CORRUPTED_BUCKET_GZIP_STREAM_RULE]);
    expect(diagnostics[0]?.message).toContain('CRC32');
  });

  it('flags a truncated multipart upload as a corrupted gzip stream', async () => {
    const stream = recordMarked(50);
    const whole = gzipSync(stream);
    const file = Buffer.from(whole.subarray(0, Math.floor(whole.length / 2)));
    const { fetchImpl } = archive({ [nameFor(stream)]: file });
    const diagnostics = await checkBucketStreams(doc, fetchImpl);
    expect(diagnostics.map((d) => d.rule)).toEqual([CORRUPTED_BUCKET_GZIP_STREAM_RULE]);
  });

  it('flags a stream whose XDR records are cut short', async () => {
    const stream = recordMarked(3);
    const cut = stream.subarray(0, stream.length - 3);
    const { fetchImpl } = archive({ [nameFor(stream)]: gzipSync(cut) });
    const diagnostics = await checkBucketStreams(doc, fetchImpl);
    expect(diagnostics.map((d) => d.rule)).toEqual([TRUNCATED_BUCKET_XDR_RULE]);
    expect(diagnostics[0]?.message).toContain('entry 3');
  });

  it('stays silent when the archive is down, and honours --off', async () => {
    const offline = (async () => new Response('down', { status: 503 })) as typeof fetch;
    expect(await checkBucketStreams(doc, offline)).toEqual([]);

    const stream = recordMarked(3);
    const file = gzipSync(stream);
    file[0] = 0;
    const { fetchImpl } = archive({ [nameFor(stream)]: file });
    expect(
      await checkBucketStreams(doc, fetchImpl, {
        rules: { [CORRUPTED_BUCKET_GZIP_STREAM_RULE]: 'off' },
      }),
    ).toEqual([]);
  });
});

describe('sampleRandomBuckets', () => {
  it('picks distinct items in their original order', () => {
    const picks = sampleRandomBuckets(['a', 'b', 'c', 'd', 'e'], 3, () => 0.5);
    expect(new Set(picks).size).toBe(3);
    expect([...picks].sort()).toEqual(picks);
    expect(sampleRandomBuckets(['a'], 5)).toEqual(['a']);
  });
});
