/* eslint-disable no-console */
import { execFileSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

import { nodeShimPlugin } from './build-browser.js';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const outDir = join(root, 'dist', 'monaco');
const packageDir = join(root, 'packages', 'monaco');

mkdirSync(outDir, { recursive: true });

const banner = {
  js: 'var self = typeof window !== "undefined" ? window : typeof globalThis !== "undefined" ? globalThis : this;',
};

/**
 * Builds the two ESM entry points the package exports:
 *
 * - `dist/monaco/index.js` — setup helper and marker/hover mappers.
 * - `dist/monaco/worker.js` — lint + hover worker a page can point a `Worker` at.
 */
async function buildMonaco() {
  await build({
    entryPoints: [join(packageDir, 'src', 'index.ts')],
    outfile: join(outDir, 'index.js'),
    bundle: true,
    format: 'esm',
    platform: 'browser',
    target: 'es2022',
    minify: true,
    sourcemap: true,
    banner,
  });

  await build({
    entryPoints: [join(packageDir, 'src', 'worker.ts')],
    outfile: join(outDir, 'worker.js'),
    bundle: true,
    format: 'iife',
    platform: 'browser',
    target: 'es2022',
    minify: true,
    sourcemap: true,
    banner,
    plugins: [nodeShimPlugin],
  });

  execFileSync(
    process.platform === 'win32' ? 'tsc.cmd' : 'tsc',
    ['-p', join(packageDir, 'tsconfig.json')],
    { cwd: root, stdio: 'inherit' },
  );

  console.log('Monaco bundles generated in dist/monaco/:');
  console.log('  - index.js (ESM helper)');
  console.log('  - worker.js (lint + hover worker)');
  console.log('  - index.d.ts / types.d.ts (TypeScript definitions)');
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  buildMonaco().catch((error) => {
    console.error('Monaco build failed:', error);
    process.exit(1);
  });
}

export { buildMonaco };
