/**
 * The editor artifacts a page actually loads.
 *
 * `src/editor/` is tested as code by the two per-editor suites; this file tests
 * it as a package — that the subpaths exist and resolve, that the built
 * bundles are browser ESM without Node built-ins, and that each one sits inside
 * the gzip budget the issue sets. The numbers come from `dist/editor/`, so the
 * gate is the build's own measurement rather than a figure in a README.
 */
import { describe, expect, it } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const distDir = join(root, 'dist', 'editor');

const BUNDLES = ['monaco.bundle.js', 'codemirror.bundle.js'] as const;

const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as {
  exports: Record<string, { types?: string; import?: string }>;
  files: string[];
};

const sizes = JSON.parse(readFileSync(join(distDir, 'sizes.json'), 'utf8')) as {
  budgetBytes: number;
  ok: boolean;
  artifacts: { file: string; bytes: number; gzipBytes: number }[];
};

describe('editor bundle packaging', () => {
  it('publishes each editor subpath with its own typings', () => {
    for (const subpath of ['./editor/monaco', './editor/codemirror']) {
      const entry = pkg.exports[subpath];
      expect(entry?.import).toContain('dist/editor/');
      expect(entry?.types).toContain('dist/editor/');
      // The tests run against the built artifact, so these should exist.
      expect(existsSync(join(root, entry?.import ?? ''))).toBe(true);
      expect(existsSync(join(root, entry?.types ?? ''))).toBe(true);
    }
  });

  it('publishes the directory the bundles are built into', () => {
    expect(pkg.files).toContain('dist');
  });

  it('holds every bundle inside the 150KB gzip budget', () => {
    expect(sizes.budgetBytes).toBe(150 * 1024);
    expect(sizes.ok).toBe(true);
    expect(sizes.artifacts.map((artifact) => artifact.file)).toEqual(
      BUNDLES.map((name) => `dist/editor/${name}`),
    );
    for (const artifact of sizes.artifacts) {
      expect(artifact.gzipBytes).toBeGreaterThan(0);
      expect(artifact.gzipBytes).toBeLessThanOrEqual(sizes.budgetBytes);
    }
  });

  it('emits browser ESM with no Node built-ins', () => {
    for (const name of BUNDLES) {
      const code = readFileSync(join(distDir, name), 'utf8');
      expect(code).toMatch(/\bexport\s*[{*]/);
      expect(code).not.toMatch(/['"]node:/);
      expect(code).not.toMatch(/\brequire\s*\(/);
      // Everything the bundle needs is inside it: nothing left to resolve.
      expect(code).not.toMatch(/\bimport\s*[({]?\s*['"][^'"]+['"]/);
      expect(existsSync(join(distDir, `${name}.map`))).toBe(true);
    }
  });

  it('leaves the linter core out of both bundles', () => {
    // The core pulls in @stellar/stellar-base for checksums; the language
    // bundles are supposed to cost a fraction of what that alone does.
    const coreGzipFloor = 100 * 1024;
    for (const artifact of sizes.artifacts) {
      expect(artifact.gzipBytes).toBeLessThan(coreGzipFloor);
    }
  });
});
