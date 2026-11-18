import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import {
  DenoCompatibilityVerifier,
  buildDenoManifest,
  extractSpecifiers,
  permissionFlags,
} from '../src/wasm/denoVerifier.js';

const CLEAN_MOD = `export * from './index.js';\nexport { lint } from './lint.ts';\n`;

describe('extractSpecifiers', () => {
  it('finds static, side-effect and dynamic imports with line numbers', () => {
    const source = [
      "import { lint } from './lint.js';",
      "import './polyfill.js';",
      "const schema = await import('./schema.ts');",
      "export * from './types.js';",
    ].join('\n');

    const specifiers = extractSpecifiers('mod.ts', source);
    expect(specifiers.map((entry) => entry.specifier)).toEqual([
      './lint.js',
      './polyfill.js',
      './schema.ts',
      './types.js',
    ]);
    expect(specifiers[2]).toMatchObject({ path: 'mod.ts', line: 3 });
  });
});

describe('DenoCompatibilityVerifier', () => {
  it('accepts a mod.ts that re-exports explicit relative modules', () => {
    const verifier = new DenoCompatibilityVerifier();
    const report = verifier.verify([{ path: 'mod.ts', source: CLEAN_MOD }]);

    expect(report.ok).toBe(true);
    expect(report.findings).toEqual([]);
    expect(report.entryPoint).toMatchObject({ path: 'mod.ts', clean: true });
  });

  it('flags extension-less relative imports and bare specifiers', () => {
    const verifier = new DenoCompatibilityVerifier();
    const report = verifier.verify([
      {
        path: 'mod.ts',
        source: "export * from './lint';\nexport { parse } from 'smol-toml';\n",
      },
    ]);

    expect(report.ok).toBe(false);
    // The imports are reported once for the module, once for the entry point.
    expect(report.findings.map((finding) => finding.kind)).toEqual([
      'missing-extension',
      'bare-specifier',
      'missing-extension',
      'bare-specifier',
    ]);
    expect(report.entryPoint.clean).toBe(false);
  });

  it('allows a bare specifier that is mapped for the runtime', () => {
    const verifier = new DenoCompatibilityVerifier({ allowedBareSpecifiers: ['smol-toml'] });
    const report = verifier.verify([
      { path: 'src/parse.ts', source: "export { parse } from 'smol-toml';\n" },
    ]);

    expect(report.ok).toBe(true);
    expect(report.findings.filter((finding) => finding.severity === 'error')).toEqual([]);
  });

  it('treats Node built-ins as warnings by default and can be strict', () => {
    const source = "import { readFile } from 'node:fs/promises';\nexport const x = readFile;\n";
    const warn = new DenoCompatibilityVerifier().verify([{ path: 'io.ts', source }]);
    expect(warn.ok).toBe(true);
    expect(warn.findings[0]).toMatchObject({ kind: 'node-builtin', severity: 'warning' });

    const strict = new DenoCompatibilityVerifier({ nodeBuiltins: 'error' }).verify([
      { path: 'io.ts', source },
    ]);
    expect(strict.ok).toBe(false);

    const allowed = new DenoCompatibilityVerifier({ nodeBuiltins: 'allow' }).verify([
      { path: 'io.ts', source },
    ]);
    expect(allowed.findings.filter((finding) => finding.kind === 'node-builtin')).toEqual([]);
  });

  it('rejects CommonJS globals', () => {
    const report = new DenoCompatibilityVerifier().verify([
      {
        path: 'legacy.ts',
        source: "const fs = require('fs');\nmodule.exports = { fs };\nconsole.log(__dirname);\n",
      },
    ]);

    const kinds = report.findings.filter((finding) => finding.kind === 'commonjs');
    expect(kinds.map((finding) => finding.message)).toEqual([
      "CommonJS require() does not exist under Deno's ESM runtime.",
      "CommonJS module.exports does not exist under Deno's ESM runtime.",
      "__dirname does not exist under Deno's ESM runtime.",
    ]);
  });

  it('warns when the suite depends on vitest', () => {
    const report = new DenoCompatibilityVerifier().verify([
      {
        path: 'test/lint.test.ts',
        source: "import { describe } from 'vitest';\n",
      },
    ]);

    expect(report.findings.some((finding) => finding.kind === 'test-runner')).toBe(true);
    expect(report.ok).toBe(false); // vitest is a bare specifier too
  });

  it('maps the run to the narrowest permission flags', () => {
    const verifier = new DenoCompatibilityVerifier({
      usage: {
        paths: ['stellar.toml', '.stellartomlrc.json'],
        domains: ['example.com'],
        env: ['NO_COLOR'],
      },
    });
    const report = verifier.verify([{ path: 'mod.ts', source: CLEAN_MOD }]);

    expect(report.permissionFlags).toEqual([
      '--allow-read=stellar.toml,.stellartomlrc.json',
      '--allow-net=example.com',
      '--allow-env=NO_COLOR',
    ]);
    expect(report.permissions).toEqual([
      { permission: 'read', value: 'stellar.toml' },
      { permission: 'read', value: '.stellartomlrc.json' },
      { permission: 'net', value: 'example.com' },
      { permission: 'env', value: 'NO_COLOR' },
    ]);
    expect(report.ok).toBe(true);
  });

  it('rejects a wildcard permission as over-broad', () => {
    const verifier = new DenoCompatibilityVerifier({ usage: { paths: ['*'] } });
    const report = verifier.verify([{ path: 'mod.ts', source: CLEAN_MOD }]);

    expect(report.ok).toBe(false);
    expect(report.findings[0]).toMatchObject({ kind: 'over-broad-permission', severity: 'error' });
  });

  it('warns when there is no mod.ts to publish', () => {
    const report = new DenoCompatibilityVerifier().verify([
      { path: 'src/index.ts', source: "export * from './lint.js';\n" },
    ]);

    expect(report.ok).toBe(true);
    expect(report.entryPoint.clean).toBe(false);
    expect(report.entryPoint.findings[0]?.severity).toBe('warning');
  });

  it("checks the package's own entry point for Deno-safe imports", async () => {
    const source = await readFile('src/index.ts', 'utf8');
    const report = new DenoCompatibilityVerifier({ nodeBuiltins: 'allow' }).verify([
      { path: 'src/index.ts', source },
    ]);

    expect(report.findings.filter((finding) => finding.severity === 'error')).toEqual([]);
    expect(report.imports.length).toBeGreaterThan(10);
    expect(report.imports.every((entry) => entry.specifier.endsWith('.js'))).toBe(true);
  });
});

describe('permissionFlags / buildDenoManifest', () => {
  it('emits nothing when nothing is needed', () => {
    expect(permissionFlags({})).toEqual([]);
    expect(permissionFlags({ paths: [], domains: [] })).toEqual([]);
  });

  it('builds a JSR manifest that points at the checked entry point', () => {
    expect(
      buildDenoManifest({ name: '@anchor-tools/stellar-toml-lint', version: '0.1.0' }),
    ).toEqual({
      name: '@anchor-tools/stellar-toml-lint',
      version: '0.1.0',
      exports: { '.': './mod.ts' },
      nodeModulesDir: false,
    });
  });
});
