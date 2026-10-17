import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import JSZip from 'jszip';

import { validateZip } from '../../src/browser/zip-validator.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string): string => readFileSync(join(here, '..', 'fixtures', name), 'utf8');

const valid = fixture('valid.toml');
const broken = fixture('broken.toml');

async function buildZip(files: Record<string, string>): Promise<Uint8Array> {
  const zip = new JSZip();
  for (const [path, content] of Object.entries(files)) {
    zip.file(path, content);
  }
  return zip.generateAsync({ type: 'uint8array' });
}

describe('validateZip', () => {
  it('extracts every .toml, ignores other entries, and lints each file', async () => {
    const buffer = await buildZip({
      'tenant-a/stellar.toml': valid,
      'tenant-b/stellar.toml': broken,
      'README.md': '# not a toml',
      'nested/deep/tenant-c.toml': valid,
    });

    const summary = await validateZip(buffer);

    expect(summary.totalFiles).toBe(3);
    expect(summary.passed).toBe(2);
    expect(summary.failed).toBe(1);
    expect(summary.passRate).toBe(67);

    const byPath = Object.fromEntries(summary.results.map((r) => [r.path, r.result]));
    expect(byPath['tenant-a/stellar.toml']?.ok).toBe(true);
    expect(byPath['nested/deep/tenant-c.toml']?.ok).toBe(true);
    expect(byPath['tenant-b/stellar.toml']?.ok).toBe(false);
  });

  it('reports aggregate counts and common error patterns', async () => {
    const buffer = await buildZip({
      'a.toml': valid,
      'b.toml': broken,
      'c.toml': broken,
    });

    const summary = await validateZip(buffer);

    expect(summary.totalErrors).toBeGreaterThan(0);
    expect(summary.totalFiles).toBe(3);
    expect(summary.passed).toBe(1);
    expect(summary.failed).toBe(2);

    const rules = summary.commonErrors.map((entry) => entry.rule);
    // broken.toml triggers insecure-http-url and several other errors.
    expect(rules).toContain('general/insecure-http-url');
    const insecure = summary.commonErrors.find(
      (entry) => entry.rule === 'general/insecure-http-url',
    );
    expect(insecure?.count).toBeGreaterThanOrEqual(2);
    expect(insecure?.files).toHaveLength(2);
  });

  it('returns an empty summary for an archive without TOML files', async () => {
    const buffer = await buildZip({ 'README.md': 'hello', 'data.json': '{}' });
    const summary = await validateZip(buffer);

    expect(summary.totalFiles).toBe(0);
    expect(summary.passed).toBe(0);
    expect(summary.failed).toBe(0);
    expect(summary.passRate).toBe(0);
    expect(summary.commonErrors).toEqual([]);
    expect(summary.results).toEqual([]);
  });

  it('honours the concurrency option and still produces correct results', async () => {
    const buffer = await buildZip({
      'one.toml': valid,
      'two.toml': broken,
      'three.toml': valid,
    });

    const serial = await validateZip(buffer, { concurrency: 1 });
    const parallel = await validateZip(buffer, { concurrency: 8 });

    expect(serial.totalFiles).toBe(parallel.totalFiles);
    expect(serial.passed).toBe(parallel.passed);
    expect(serial.failed).toBe(parallel.failed);
    expect(serial.commonErrors).toEqual(parallel.commonErrors);
  });
});
