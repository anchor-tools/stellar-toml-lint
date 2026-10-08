import { afterEach, describe, expect, it } from 'vitest';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Diagnostic } from '../../src/types.js';
import {
  DEFAULT_TTL_HOURS,
  diffSnapshots,
  parseSnapshot,
  readCatalog,
  renderMarkdown,
  renderReport,
  renderSnapshot,
  runCorpus,
  snapshotFor,
  type CorpusEntry,
  type Fetcher,
  type Snapshot,
} from './harness.js';

const ENTRY: CorpusEntry = {
  name: 'example-com',
  url: 'https://example.com/.well-known/stellar.toml',
};

const BODY = 'NETWORK_PASSPHRASE = "Test SDF Network ; September 2015"\n';
const OTHER_BODY = `${BODY}DOCUMENTATION = "https://example.com/docs"\n`;

const TTL_MS = DEFAULT_TTL_HOURS * 3_600_000;

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

interface Workspace {
  catalogPath: string;
  snapshotsDir: string;
  cacheDir: string;
  diffDir: string;
}

async function workspace(entries: CorpusEntry[] = [ENTRY]): Promise<Workspace> {
  const root = await mkdtemp(join(tmpdir(), 'stellar-toml-lint-corpus-'));
  roots.push(root);
  const corpus = join(root, 'corpus');
  await mkdir(corpus, { recursive: true });
  const catalogPath = join(corpus, 'corpus.json');
  await writeFile(catalogPath, `${JSON.stringify(entries, null, 2)}\n`, 'utf8');
  return {
    catalogPath,
    snapshotsDir: join(corpus, 'snapshots'),
    cacheDir: join(corpus, '.cache'),
    diffDir: join(corpus, '.diff'),
  };
}

/** A fetcher that counts its calls and returns one canned body (or one error). */
function serve(
  body: string,
  options: { fail?: string } = {},
): {
  fetcher: Fetcher;
  counter: { calls: number };
} {
  const counter = { calls: 0 };
  const fetcher: Fetcher = async () => {
    counter.calls += 1;
    return options.fail === undefined ? { ok: true, body } : { ok: false, error: options.fail };
  };
  return { fetcher, counter };
}

async function exists(path: string): Promise<boolean> {
  try {
    await readFile(path, 'utf8');
    return true;
  } catch {
    return false;
  }
}

function diagnostic(rule: string, over: Partial<Diagnostic> = {}): Diagnostic {
  return {
    rule,
    severity: 'error',
    category: 'general',
    message: `${rule} went wrong`,
    helpUri: `https://example.com/rules/${rule}`,
    ...over,
  };
}

function snapshot(over: Partial<Snapshot> = {}): Snapshot {
  return {
    url: ENTRY.url,
    domain: 'example.com',
    sourceSha256: 'a'.repeat(64),
    ok: false,
    counts: { error: 1, warning: 0, info: 0 },
    diagnostics: [],
    ...over,
  };
}

describe('readCatalog', () => {
  it('parses entries and keeps the note', () => {
    const entries = readCatalog(
      `${JSON.stringify([{ name: 'example-com', url: 'https://example.com/stellar.toml', note: 'why' }])}`,
    );
    expect(entries).toEqual([
      { name: 'example-com', url: 'https://example.com/stellar.toml', note: 'why' },
    ]);
  });

  it('drops an absent note instead of writing undefined', () => {
    const entries = readCatalog(`${JSON.stringify([{ name: 'a', url: 'https://a.com/x.toml' }])}`);
    expect(entries[0]).toEqual({ name: 'a', url: 'https://a.com/x.toml' });
    expect('note' in (entries[0] ?? {})).toBe(false);
  });

  it.each([
    ['not JSON', 'nope'],
    ['a non-array', '{}'],
    ['a missing name', JSON.stringify([{ url: 'https://a.com/x.toml' }])],
    ['an unsafe name', JSON.stringify([{ name: 'UPPER/Case', url: 'https://a.com/x.toml' }])],
    [
      'a duplicate name',
      JSON.stringify([
        { name: 'a', url: 'https://a.com/x.toml' },
        { name: 'a', url: 'https://b.com/x.toml' },
      ]),
    ],
    ['a non-https url', JSON.stringify([{ name: 'a', url: 'http://a.com/x.toml' }])],
    ['a non-object entry', JSON.stringify(['a'])],
  ])('rejects %s', (_label, text) => {
    expect(() => readCatalog(text)).toThrow();
  });
});

describe('snapshotFor', () => {
  it('records where the bytes came from and what they said', () => {
    const result = snapshotFor(ENTRY, BODY);
    expect(result.url).toBe(ENTRY.url);
    expect(result.domain).toBe('example.com');
    expect(result.sourceSha256).toHaveLength(64);
    expect(typeof result.ok).toBe('boolean');
    expect(result.counts).toEqual({
      error: result.diagnostics.filter((d) => d.severity === 'error').length,
      warning: result.diagnostics.filter((d) => d.severity === 'warning').length,
      info: result.diagnostics.filter((d) => d.severity === 'info').length,
    });
    expect(Array.isArray(result.diagnostics)).toBe(true);
  });

  it('is byte-for-byte reproducible', () => {
    expect(renderSnapshot(snapshotFor(ENTRY, BODY))).toBe(renderSnapshot(snapshotFor(ENTRY, BODY)));
  });

  it('changes identity when the source bytes change', () => {
    expect(snapshotFor(ENTRY, BODY).sourceSha256).not.toBe(
      snapshotFor(ENTRY, OTHER_BODY).sourceSha256,
    );
  });
});

describe('renderSnapshot / parseSnapshot', () => {
  it('round-trips', () => {
    const original = snapshotFor(ENTRY, BODY);
    expect(parseSnapshot(renderSnapshot(original))).toEqual(original);
  });

  it('ignores junk', () => {
    expect(parseSnapshot('not json')).toBeUndefined();
    expect(parseSnapshot('{}')).toBeUndefined();
    expect(parseSnapshot('{"url":1}')).toBeUndefined();
  });
});

describe('diffSnapshots', () => {
  it('is empty when the two snapshots agree', () => {
    const before = snapshot({ diagnostics: [diagnostic('general/https-endpoints')] });
    const after = snapshot({ diagnostics: [diagnostic('general/https-endpoints')] });
    expect(diffSnapshots(before, after)).toEqual([]);
  });

  it('lists everything for an entry with no snapshot yet', () => {
    const lines = diffSnapshots(
      undefined,
      snapshot({ diagnostics: [diagnostic('network/passphrase')] }),
    );
    expect(lines[0]).toContain('no committed snapshot');
    expect(lines[1]).toContain('+ network/passphrase');
  });

  it('pairs diagnostics by rule and place so a change reads as a change', () => {
    const before = snapshot({
      diagnostics: [diagnostic('network/passphrase', { message: 'old' })],
    });
    const after = snapshot({ diagnostics: [diagnostic('network/passphrase', { message: 'new' })] });
    const lines = diffSnapshots(before, after);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain('~ network/passphrase');
    expect(lines[0]).toContain('"old" -> "new"');
  });

  it('separates additions from removals', () => {
    const before = snapshot({ diagnostics: [diagnostic('validators/host')] });
    const after = snapshot({
      diagnostics: [diagnostic('documentation/present', { severity: 'warning' })],
    });
    const lines = diffSnapshots(before, after);
    expect(lines.some((line) => line.startsWith('  + documentation/present'))).toBe(true);
    expect(lines.some((line) => line.startsWith('  - validators/host'))).toBe(true);
  });

  it('says who changed, when the verdict flipped, and by how much', () => {
    const before = snapshot({
      ok: true,
      sourceSha256: 'a'.repeat(64),
      counts: { error: 0, warning: 1, info: 0 },
    });
    const after = snapshot({
      ok: false,
      sourceSha256: 'b'.repeat(64),
      counts: { error: 2, warning: 1, info: 0 },
    });
    const text = diffSnapshots(before, after).join('\n');
    expect(text).toContain('source changed');
    expect(text).toContain('verdict changed: ok=true -> ok=false');
    expect(text).toContain('counts: error 0 -> 2');
  });
});

describe('runCorpus', () => {
  it('flags an entry with no snapshot without writing one', async () => {
    const dir = await workspace();
    const { fetcher } = serve(BODY);

    const report = await runCorpus({ ...dir, fetcher });

    expect(report.outcomes).toHaveLength(1);
    expect(report.outcomes[0]?.status).toBe('missing');
    expect(report.needsReview).toBe(true);
    expect(await exists(join(dir.snapshotsDir, 'example-com.json'))).toBe(false);
    expect(await exists(join(dir.diffDir, 'example-com.expected.json'))).toBe(true);
    expect(report.changed).toBe(1);
  });

  it('writes snapshots with --update and does not ask for review', async () => {
    const dir = await workspace();
    const { fetcher } = serve(BODY);

    const report = await runCorpus({ ...dir, fetcher, update: true });

    expect(report.outcomes[0]?.status).toBe('created');
    expect(report.needsReview).toBe(false);
    expect(report.created).toBe(1);
    expect(await exists(join(dir.snapshotsDir, 'example-com.json'))).toBe(true);
  });

  it('reaches a clean second run from the cache, without refetching', async () => {
    const dir = await workspace();
    const { fetcher, counter } = serve(BODY);
    await runCorpus({ ...dir, fetcher, update: true });

    const report = await runCorpus({ ...dir, fetcher });

    expect(report.outcomes[0]?.status).toBe('matched');
    expect(report.outcomes[0]?.source).toBe('cache');
    expect(report.needsReview).toBe(false);
    expect(counter.calls).toBe(1);
  });

  it('detects an edited file and reports the change', async () => {
    const dir = await workspace();
    await runCorpus({ ...dir, fetcher: serve(BODY).fetcher, update: true });

    const report = await runCorpus({
      ...dir,
      fetcher: serve(OTHER_BODY).fetcher,
      refresh: true,
    });

    expect(report.outcomes[0]?.status).toBe('changed');
    expect(report.needsReview).toBe(true);
    expect(report.outcomes[0]?.diff.join('\n')).toContain('source changed');
    expect(await readFile(join(dir.diffDir, 'example-com.actual.json'), 'utf8')).toContain(
      'DOCUMENTATION',
    );
  });

  it('stays clean after --update accepts a change', async () => {
    const dir = await workspace();
    await runCorpus({ ...dir, fetcher: serve(BODY).fetcher, update: true });
    await runCorpus({
      ...dir,
      fetcher: serve(OTHER_BODY).fetcher,
      refresh: true,
      update: true,
    });

    const report = await runCorpus({
      ...dir,
      fetcher: serve(OTHER_BODY).fetcher,
      refresh: true,
    });

    expect(report.outcomes[0]?.status).toBe('matched');
    expect(report.needsReview).toBe(false);
    expect(report.updated).toBe(0);
  });

  it('reports an unreachable host without failing the run', async () => {
    const dir = await workspace();
    const { fetcher } = serve(BODY, { fail: 'HTTP 404' });
    const report = await runCorpus({ ...dir, fetcher });

    expect(report.outcomes[0]?.status).toBe('unreachable');
    expect(report.outcomes[0]?.detail).toBe('HTTP 404');
    expect(report.unreachable).toBe(1);
    expect(report.needsReview).toBe(false);
  });

  it('falls back to a stale cache when the host stops answering', async () => {
    const dir = await workspace();
    const start = 1_700_000_000_000;
    await runCorpus({ ...dir, fetcher: serve(BODY).fetcher, update: true, now: () => start });

    const report = await runCorpus({
      ...dir,
      fetcher: serve(BODY, { fail: 'getaddrinfo ENOTFOUND' }).fetcher,
      now: () => start + TTL_MS + 60_000,
    });

    expect(report.outcomes[0]?.status).toBe('matched');
    expect(report.outcomes[0]?.source).toBe('cache');
    expect(report.needsReview).toBe(false);
  });

  it('refreshes the cache when told to', async () => {
    const dir = await workspace();
    await runCorpus({ ...dir, fetcher: serve(BODY).fetcher, update: true });

    const { fetcher, counter } = serve(OTHER_BODY);
    const report = await runCorpus({ ...dir, fetcher, refresh: true, update: true });

    expect(counter.calls).toBe(1);
    expect(report.updated).toBe(1);
  });

  it('works offline from the cache, at any age', async () => {
    const dir = await workspace();
    const start = 1_700_000_000_000;
    await runCorpus({ ...dir, fetcher: serve(BODY).fetcher, update: true, now: () => start });

    const { fetcher, counter } = serve(BODY, { fail: 'should not be called' });
    const report = await runCorpus({
      ...dir,
      fetcher,
      offline: true,
      now: () => start + TTL_MS * 10,
    });

    expect(report.outcomes[0]?.status).toBe('matched');
    expect(report.outcomes[0]?.source).toBe('cache');
    expect(counter.calls).toBe(0);
  });

  it('explains an offline miss instead of failing', async () => {
    const dir = await workspace();
    const { fetcher } = serve(BODY);
    const report = await runCorpus({ ...dir, fetcher, offline: true });

    expect(report.outcomes[0]?.status).toBe('unreachable');
    expect(report.outcomes[0]?.detail).toContain('offline');
    expect(report.needsReview).toBe(false);
  });

  it('filters to one entry and rejects an unknown name', async () => {
    const dir = await workspace([
      ENTRY,
      { name: 'other-org', url: 'https://other.org/.well-known/stellar.toml' },
    ]);
    const { fetcher } = serve(BODY);

    const report = await runCorpus({ ...dir, fetcher, filter: ['other-org'], update: true });

    expect(report.outcomes.map((o) => o.entry.name)).toEqual(['other-org']);
    await expect(runCorpus({ ...dir, fetcher, filter: ['nope'] })).rejects.toThrow(
      'unknown corpus entry',
    );
  });

  it('clears diff artifacts from an earlier run', async () => {
    const dir = await workspace();
    await runCorpus({ ...dir, fetcher: serve(BODY).fetcher, update: true });
    await runCorpus({ ...dir, fetcher: serve(OTHER_BODY).fetcher, refresh: true });
    expect(await readdir(dir.diffDir)).not.toEqual([]);

    await runCorpus({ ...dir, fetcher: serve(BODY).fetcher, refresh: true });
    expect(await readdir(dir.diffDir)).toEqual([]);
  });

  it('flags an unreadable committed snapshot instead of pretending it is new', async () => {
    const dir = await workspace();
    await runCorpus({ ...dir, fetcher: serve(BODY).fetcher, update: true });
    await writeFile(join(dir.snapshotsDir, 'example-com.json'), '{ broken', 'utf8');

    const report = await runCorpus({ ...dir, fetcher: serve(BODY).fetcher, refresh: true });

    expect(report.outcomes[0]?.status).toBe('changed');
    expect(report.outcomes[0]?.diff[0]).toContain('unreadable');
  });
});

describe('report rendering', () => {
  it('gives one line per entry and the diff underneath', async () => {
    const dir = await workspace();
    const report = await runCorpus({
      ...dir,
      fetcher: serve(OTHER_BODY).fetcher,
      update: true,
    });
    const text = renderReport(report);

    expect(text).toContain('created');
    expect(text).toContain('example-com');
    expect(text).toContain('1 entries: 0 matched, 0 changed, 1 created, 0 updated, 0 unreachable');
    expect(text).toContain('example-com (https://example.com/.well-known/stellar.toml)');
    expect(text).toContain('no committed snapshot');
    expect(text.endsWith('\n')).toBe(true);
  });

  it('renders markdown for the Actions step summary', async () => {
    const dir = await workspace();
    const { fetcher } = serve(BODY, { fail: 'HTTP 503' });
    const report = await runCorpus({ ...dir, fetcher });
    const text = renderMarkdown(report);

    expect(text).toContain('## Corpus run');
    expect(text).toContain('| example-com | unreachable | — | — | HTTP 503 |');
    expect(text).toContain('No behavioural changes');
  });
});
