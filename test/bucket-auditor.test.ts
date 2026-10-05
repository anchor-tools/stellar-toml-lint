import { gzipSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2';
import { bytesToHex } from '@noble/hashes/utils';
import { xdr } from '@stellar/stellar-base';
import {
  auditBucketFile,
  bucketHashFromName,
  bucketPathFor,
  bucketReferences,
  BUCKET_DOWNLOAD_FAILED_RULE,
  BUCKET_HASH_MISMATCH_RULE,
  BUCKET_XDR_CORRUPTED_RULE,
  checkBucketIntegrity,
  isBucketEntryStream,
  sampleBuckets,
} from '../src/history/bucket-auditor.js';

const ARCHIVE = 'https://history.example/archive/';
const HAS_PATH = '/archive/.well-known/stellar-history.json';

/** A minimal, well-formed XDR `BucketEntry` stream. */
function bucketStream(ledgerVersion = 22): Buffer {
  const entry = xdr.BucketEntry.metaentry(
    new xdr.BucketMetadata({
      ledgerVersion,
      ext: new xdr.BucketMetadataExt(0),
    }),
  );
  return Buffer.from(entry.toXDR());
}

function hex(bytes: Buffer): string {
  return bytesToHex(sha256(bytes));
}

function bucketName(bytes: Buffer): string {
  return `bucket-${hex(bytes)}.xdr.gz`;
}

interface Fixture {
  fetch: typeof fetch;
  calls: string[];
}

/** Routes the HAS document and the bucket files a test declares. */
function fixture(has: unknown, buckets: Record<string, Uint8Array | Error>): Fixture {
  const calls: string[] = [];
  const fetchImpl = (async (input: Parameters<typeof fetch>[0]) => {
    const url = new URL(String(input));
    const key = `${url.origin}${url.pathname}`;
    calls.push(key);
    if (url.pathname === HAS_PATH) {
      return new Response(JSON.stringify(has), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }
    const match = buckets[key];
    if (match instanceof Error) throw match;
    if (match === undefined) return new Response('not found', { status: 404 });
    return new Response(Buffer.from(match), { status: 200 });
  }) as typeof fetch;
  return { fetch: fetchImpl, calls };
}

function hasFor(...names: string[]): Record<string, unknown> {
  return {
    version: 1,
    server: ARCHIVE.replace(/\/$/, ''),
    currentLedger: 1000,
    currentBuckets: names.map((name) => ({ curr: name, snap: '', next: { state: 0 } })),
  };
}

const DOC = { VALIDATORS: [{ HOST: 'core.example:11625', HISTORY: ARCHIVE }] };

describe('bucketHashFromName', () => {
  it('reads the SHA-256 a bucket file name encodes', () => {
    const digest = 'ab'.repeat(32);
    expect(bucketHashFromName(`bucket-${digest}.xdr.gz`)).toBe(digest);
    expect(bucketHashFromName(`bucket/ab/cd/ef/bucket-${digest}.xdr.gz`)).toBe(digest);
  });

  it('is undefined for names that are not content-addressed', () => {
    expect(bucketHashFromName('bucket.xdr.gz')).toBeUndefined();
    expect(bucketHashFromName('bucket-xyz.xdr.gz')).toBeUndefined();
  });
});

describe('bucketPathFor', () => {
  it('places the bucket under the first three pairs of its hash', () => {
    const digest = 'abcdef0123456789'.repeat(4);
    expect(bucketPathFor(`bucket-${digest}.xdr.gz`)).toBe(
      `bucket/ab/cd/ef/bucket-${digest}.xdr.gz`,
    );
  });
});

describe('bucketReferences', () => {
  it('collects and dedupes the HAS currentBuckets', () => {
    const digest = 'ab'.repeat(32);
    const refs = bucketReferences({
      currentBuckets: [
        { curr: `bucket-${digest}.xdr.gz`, snap: '' },
        { curr: `bucket-${digest}.xdr.gz`, snap: '' },
      ],
    });
    expect(refs).toEqual([{ name: `bucket-${digest}.xdr.gz`, hash: digest }]);
  });

  it('is empty when no buckets are declared', () => {
    expect(bucketReferences({ currentBuckets: [] })).toEqual([]);
    expect(bucketReferences({})).toEqual([]);
    expect(bucketReferences('nope')).toEqual([]);
  });
});

describe('sampleBuckets', () => {
  it('spreads samples across the list', () => {
    expect(sampleBuckets([1, 2, 3, 4], 2)).toEqual([1, 3]);
    expect(sampleBuckets([1, 2], 5)).toEqual([1, 2]);
    expect(sampleBuckets([1, 2], 0)).toEqual([]);
  });
});

describe('isBucketEntryStream', () => {
  it('accepts a decodable BucketEntry stream', () => {
    expect(isBucketEntryStream(bucketStream())).toBe(true);
  });

  it('rejects garbage and empty buffers', () => {
    expect(isBucketEntryStream(Buffer.from([0xff, 0x00, 0x01]))).toBe(false);
    expect(isBucketEntryStream(Buffer.alloc(0))).toBe(false);
  });
});

describe('checkBucketIntegrity', () => {
  it('passes a bucket whose content hash and XDR stream are intact', async () => {
    const bytes = bucketStream();
    const name = bucketName(bytes);
    const { fetch: fetchImpl } = fixture(hasFor(name), {
      [`${ARCHIVE}bucket/${name.slice(7, 9)}/${name.slice(9, 11)}/${name.slice(11, 13)}/${name}`]:
        gzipSync(bytes),
    });
    expect(await checkBucketIntegrity(DOC, fetchImpl)).toEqual([]);
  });

  it('errors with history/bucket-hash-mismatch when the content was altered', async () => {
    const original = bucketStream(22);
    const tampered = bucketStream(23);
    const name = bucketName(original);
    const { fetch: fetchImpl } = fixture(hasFor(name), {
      [`${ARCHIVE}bucket/${name.slice(7, 9)}/${name.slice(9, 11)}/${name.slice(11, 13)}/${name}`]:
        gzipSync(tampered),
    });
    const diagnostics = await checkBucketIntegrity(DOC, fetchImpl);
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      rule: BUCKET_HASH_MISMATCH_RULE,
      severity: 'error',
      path: 'VALIDATORS[0].HISTORY',
    });
  });

  it('errors with history/bucket-xdr-corrupted when the stream does not decode', async () => {
    const garbage = Buffer.from('this is not xdr');
    const name = bucketName(garbage);
    const { fetch: fetchImpl } = fixture(hasFor(name), {
      [`${ARCHIVE}bucket/${name.slice(7, 9)}/${name.slice(9, 11)}/${name.slice(11, 13)}/${name}`]:
        gzipSync(garbage),
    });
    const diagnostics = await checkBucketIntegrity(DOC, fetchImpl);
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      rule: BUCKET_XDR_CORRUPTED_RULE,
      severity: 'error',
    });
  });

  it('errors with history/bucket-download-failed when a bucket is missing', async () => {
    const bytes = bucketStream();
    const name = bucketName(bytes);
    const { fetch: fetchImpl } = fixture(hasFor(name), {});
    const diagnostics = await checkBucketIntegrity(DOC, fetchImpl);
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      rule: BUCKET_DOWNLOAD_FAILED_RULE,
      severity: 'error',
    });
  });

  it('reports a decompression failure as history/bucket-xdr-corrupted', async () => {
    const bytes = gzipSync(bucketStream());
    const name = bucketName(bucketStream());
    const { fetch: fetchImpl } = fixture(hasFor(name), {
      [`${ARCHIVE}bucket/${name.slice(7, 9)}/${name.slice(9, 11)}/${name.slice(11, 13)}/${name}`]:
        bytes.subarray(0, 5),
    });
    const diagnostics = await checkBucketIntegrity(DOC, fetchImpl);
    expect(diagnostics[0]).toMatchObject({ rule: BUCKET_XDR_CORRUPTED_RULE });
  });

  it('degrades to silence when the HAS cannot be fetched', async () => {
    const diagnostics = await checkBucketIntegrity(DOC, async () => {
      throw new Error('offline');
    });
    expect(diagnostics).toEqual([]);
  });

  it('honours rule overrides', async () => {
    const bytes = bucketStream();
    const name = bucketName(bytes);
    const { fetch: fetchImpl } = fixture(hasFor(name), {});
    const diagnostics = await checkBucketIntegrity(DOC, fetchImpl, {
      rules: { [BUCKET_DOWNLOAD_FAILED_RULE]: 'off' },
    });
    expect(diagnostics).toEqual([]);
  });
});

describe('auditBucketFile', () => {
  it('returns no diagnostics for an intact bucket', async () => {
    const bytes = bucketStream();
    const name = bucketName(bytes);
    const path = bucketPathFor(name);
    const { fetch: fetchImpl } = fixture({}, { [`${ARCHIVE}${path}`]: gzipSync(bytes) });
    const diagnostics = await auditBucketFile(
      ARCHIVE,
      { name, hash: hex(bytes) },
      fetchImpl,
      {},
      'VALIDATORS[0].HISTORY',
    );
    expect(diagnostics).toEqual([]);
  });
});
