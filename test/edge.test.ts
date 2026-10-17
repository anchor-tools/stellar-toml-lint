import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { vi } from 'vitest';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { webcrypto } from 'node:crypto';
import { lint } from '../src/lint.js';
import { lintEdge } from '../src/edge.js';

const here = dirname(fileURLToPath(import.meta.url));
const rootDir = join(here, '..');

const valid = readFileSync(join(rootDir, 'test', 'fixtures', 'valid.toml'), 'utf8');
const broken = 'VERSION="two"\nSIGNING_KEY="nope"\n';
const warnings = readFileSync(join(rootDir, 'test', 'fixtures', 'warnings-only.toml'), 'utf8');

async function sha256Hex(input: string): Promise<string> {
  const digest = await webcrypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  const bytes = new Uint8Array(digest);
  let hex = '';
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0');
  return hex;
}

describe('lintEdge', () => {
  it('matches the Node entry point on the same source', async () => {
    const edge = await lintEdge(valid);
    expect(edge).toEqual(lint(valid));
    expect(edge.ok).toBe(true);
    expect(edge.counts.error).toBe(0);

    const edgeBroken = await lintEdge(broken);
    expect(edgeBroken).toEqual(lint(broken));
    expect(edgeBroken.ok).toBe(false);
    expect(edgeBroken.counts.error).toBeGreaterThan(0);
  });

  it('forwards strict mode and rule overrides', async () => {
    const relaxed = await lintEdge(warnings);
    const strict = await lintEdge(warnings, { strict: true });
    expect(strict.ok).toBe(lint(warnings, { strict: true }).ok);
    expect(relaxed.ok).toBe(lint(warnings).ok);
  });

  it('aborts with a content-digest error when the digest does not match', async () => {
    const result = await lintEdge(broken, {
      expectedContentDigest: '0000000000000000000000000000000000000000000000000000000000000000',
    });

    expect(result.ok).toBe(false);
    expect(result.diagnostics).toHaveLength(1);
    expect(result.diagnostics[0]!.rule).toBe('edge/content-digest-mismatch');
    expect(result.diagnostics[0]!.severity).toBe('error');
    expect(result.counts.error).toBe(1);
  });

  it('lints normally when the digest matches', async () => {
    const actual = await sha256Hex(valid);
    const result = await lintEdge(valid, { expectedContentDigest: actual });

    expect(result.ok).toBe(true);
    expect(result.diagnostics).toEqual(lint(valid).diagnostics);
  });

  it('produces an empty report for a clean file', async () => {
    const result = await lintEdge(valid);
    expect(result.ok).toBe(true);
    expect(result.diagnostics).toEqual([]);
  });
});

describe('edge without the Node `process` global', () => {
  it('lints when `process` is absent, as on edge runtimes', async () => {
    vi.stubGlobal('process', { env: {} });
    vi.resetModules();
    const { lintEdge: edgeLint } = await import('../src/edge.js');

    const result = await edgeLint(valid);
    expect(result.ok).toBe(true);
    expect(result.counts.error).toBe(0);
    expect(result.diagnostics).toEqual(lint(valid).diagnostics);
  });

  it('computes the content digest with `crypto.subtle` without `process`', async () => {
    vi.stubGlobal('process', { env: {} });
    vi.resetModules();
    const { lintEdge: edgeLint } = await import('../src/edge.js');

    const actual = await sha256Hex(valid);
    const result = await edgeLint(valid, { expectedContentDigest: actual });
    expect(result.ok).toBe(true);

    const mismatched = await edgeLint(valid, {
      expectedContentDigest: '0000000000000000000000000000000000000000000000000000000000000000',
    });
    expect(mismatched.ok).toBe(false);
    expect(mismatched.diagnostics[0]!.rule).toBe('edge/content-digest-mismatch');
  });
});

describe('edge module boundary', () => {
  it('imports no Node built-ins', () => {
    const source = readFileSync(join(rootDir, 'src', 'edge.ts'), 'utf8');
    expect(source).not.toMatch(/(?:^|\n)\s*import[^;\n]*from\s+['"]node:/);
    expect(source).not.toMatch(/require\(['"]node:/);
  });
});
