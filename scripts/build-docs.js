import { build } from 'esbuild';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { nodeShimPlugin } from './build-browser.js';

const rootDir = join(dirname(fileURLToPath(import.meta.url)), '..');

await build({
  entryPoints: [join(rootDir, 'src', 'docs-browser.ts')],
  outfile: join(rootDir, 'docs', 'stellar-toml-lint.browser.js'),
  bundle: true,
  format: 'iife',
  globalName: 'stellarTomlLint',
  platform: 'browser',
  target: 'es2022',
  minify: true,
  plugins: [nodeShimPlugin],
});
