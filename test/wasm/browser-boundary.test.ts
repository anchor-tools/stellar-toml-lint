import { describe, expect, it } from 'vitest';
import {
  BrowserBoundaryVerifier,
  extractBundleSpecifiers,
  isNodeBuiltin,
  renderBrowserBoundaryReport,
} from '../../src/wasm/browserBoundaryVerifier.js';

const CLEAN = `import { lint } from './lint.js'; export const run = (s) => lint(s);`;

describe('BrowserBoundaryVerifier', () => {
  it('accepts a browser-clean bundle', () => {
    const verifier = new BrowserBoundaryVerifier();
    const report = verifier.verify([{ path: 'dist/browser/index.js', source: CLEAN }]);
    expect(report.ok).toBe(true);
    expect(report.findings).toEqual([]);
    expect(renderBrowserBoundaryReport(report)).toContain('clean');
  });

  it('errors on node: imports and bare Node built-ins', () => {
    const verifier = new BrowserBoundaryVerifier();
    const findings = verifier.checkSource(
      'index.js',
      `import fs from 'node:fs';\nimport path from 'path';\nimport x from './x.js';`,
    );
    expect(findings.filter((f) => f.code === 'browser/node-builtin')).toHaveLength(2);
    expect(findings[0]?.message).toContain('node:fs');
  });

  it('detects Node-only globals and require()', () => {
    const verifier = new BrowserBoundaryVerifier();
    const codes = verifier
      .checkSource('index.js', `const cwd = process.cwd(); const r = require('./x');`)
      .map((f) => f.code);
    expect(codes).toEqual(['browser/node-global', 'browser/node-global']);
  });

  it('warns when crypto is used without Web Crypto', () => {
    const verifier = new BrowserBoundaryVerifier();
    expect(
      verifier.checkSource('index.js', `const c = crypto.createHash('sha256');`)[0]?.code,
    ).toBe('browser/crypto-polyfill');
    expect(
      verifier.checkSource(
        'index.js',
        `const d = await globalThis.crypto.subtle.digest('SHA-256', b);`,
      ),
    ).toEqual([]);
  });

  it('fails bundles above the size budget and missing artifacts', () => {
    const verifier = new BrowserBoundaryVerifier({ maxBundleBytes: 10 });
    const report = verifier.verify([{ path: 'index.js', source: CLEAN }]);
    expect(report.ok).toBe(false);
    expect(report.findings.map((f) => f.code)).toContain('browser/bundle-too-large');

    const missing = new BrowserBoundaryVerifier({ requiredFiles: ['index.js'] }).verify([]);
    expect(missing.ok).toBe(false);
  });

  it('requires declared artifacts', () => {
    const verifier = new BrowserBoundaryVerifier({ requiredFiles: ['worker.js'] });
    const report = verifier.verify([{ path: 'index.js', source: CLEAN }]);
    expect(report.findings[0]?.code).toBe('browser/missing-artifact');
  });
});

describe('bundle specifier helpers', () => {
  it('classifies Node built-ins', () => {
    expect(isNodeBuiltin('node:fs')).toBe(true);
    expect(isNodeBuiltin('fs/promises')).toBe(true);
    expect(isNodeBuiltin('node:test')).toBe(false);
    expect(isNodeBuiltin('./lint.js')).toBe(false);
  });

  it('extracts static, dynamic, and require specifiers', () => {
    const specifiers = extractBundleSpecifiers(
      `import a from 'a';\nconst b = await import('node:fs');\nrequire('c');`,
    );
    expect(specifiers.map((s) => s.specifier)).toEqual(['a', 'node:fs', 'c']);
  });
});
