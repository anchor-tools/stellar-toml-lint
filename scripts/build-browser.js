/* eslint-disable no-console, no-undef */
import { build } from 'esbuild';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const rootDir = join(__dirname, '..');
const outDir = join(rootDir, 'dist', 'browser');

mkdirSync(outDir, { recursive: true });

/**
 * Plugin to shim Node built-ins like `node:tls` so that the browser bundle
 * remains fully hermetic without pulling in Node runtime APIs.
 */
const nodeShimPlugin = {
  name: 'node-builtins-shim',
  setup(build) {
    build.onResolve({ filter: /^node:tls$/ }, (args) => ({
      path: args.path,
      namespace: 'node-shim',
    }));
    build.onLoad({ filter: /.*/, namespace: 'node-shim' }, () => ({
      contents: `
        export function connect() {
          throw new Error('TLS audit is not supported in browser environments.');
        }
        export default { connect };
      `,
      loader: 'js',
    }));
  },
};

const banner = {
  js: 'var self = typeof window !== "undefined" ? window : typeof globalThis !== "undefined" ? globalThis : this;',
};

async function buildBrowser() {
  console.log('Building browser and worker bundles...');

  // 1. Minified ESM bundle
  await build({
    entryPoints: [join(rootDir, 'src', 'browser.ts')],
    outfile: join(outDir, 'stellar-toml-lint.esm.min.js'),
    bundle: true,
    format: 'esm',
    platform: 'browser',
    target: 'es2022',
    minify: true,
    sourcemap: true,
    banner,
    plugins: [nodeShimPlugin],
  });

  // Alias dist/browser/index.js to the ESM bundle for standard module bundlers
  await build({
    entryPoints: [join(rootDir, 'src', 'browser.ts')],
    outfile: join(outDir, 'index.js'),
    bundle: true,
    format: 'esm',
    platform: 'browser',
    target: 'es2022',
    minify: true,
    sourcemap: true,
    banner,
    plugins: [nodeShimPlugin],
  });

  // 2. Minified UMD / IIFE bundle for <script> tags
  await build({
    entryPoints: [join(rootDir, 'src', 'browser.ts')],
    outfile: join(outDir, 'stellar-toml-lint.umd.min.js'),
    bundle: true,
    format: 'iife',
    globalName: 'stellarTomlLint',
    platform: 'browser',
    target: 'es2022',
    minify: true,
    sourcemap: true,
    banner,
    plugins: [nodeShimPlugin],
  });

  await build({
    entryPoints: [join(rootDir, 'src', 'browser.ts')],
    outfile: join(outDir, 'index.umd.js'),
    bundle: true,
    format: 'iife',
    globalName: 'stellarTomlLint',
    platform: 'browser',
    target: 'es2022',
    minify: true,
    sourcemap: true,
    banner,
    plugins: [nodeShimPlugin],
  });

  // 3. Web Worker bundle
  await build({
    entryPoints: [join(rootDir, 'src', 'worker.ts')],
    outfile: join(outDir, 'stellar-toml-lint.worker.min.js'),
    bundle: true,
    format: 'iife',
    platform: 'browser',
    target: 'es2022',
    minify: true,
    sourcemap: true,
    banner,
    plugins: [nodeShimPlugin],
  });

  await build({
    entryPoints: [join(rootDir, 'src', 'worker.ts')],
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

  // 4. Typings re-export
  writeFileSync(
    join(outDir, 'index.d.ts'),
    "export * from '../browser.js';\nexport { default } from '../browser.js';\n",
  );
  writeFileSync(
    join(outDir, 'worker.d.ts'),
    "export * from '../worker.js';\nexport { default } from '../worker.js';\n",
  );

  console.log('Browser bundles successfully generated in dist/browser/:');
  console.log('  - stellar-toml-lint.esm.min.js & index.js (ESM)');
  console.log('  - stellar-toml-lint.umd.min.js & index.umd.js (UMD/IIFE)');
  console.log('  - stellar-toml-lint.worker.min.js & worker.js (Web Worker)');
}

buildBrowser().catch((error) => {
  console.error('Browser build failed:', error);
  process.exit(1);
});
