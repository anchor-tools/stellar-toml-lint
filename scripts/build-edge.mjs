/* eslint-disable no-console, no-undef */
import { build } from 'esbuild';
import { nodeShimPlugin } from './build-browser.js';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const rootDir = join(__dirname, '..');

async function buildEdge() {
  console.log('Building edge bundle...');

  // Node built-ins are replaced by throwing shims (reused from the browser
  // build): the bundle loads in edge runtimes, and nothing in the `lint`
  // path ever calls them.
  await build({
    entryPoints: [join(rootDir, 'src', 'edge.ts')],
    outfile: join(rootDir, 'dist', 'edge.js'),
    bundle: true,
    format: 'esm',
    platform: 'neutral',
    mainFields: ['browser', 'module', 'main'],
    target: 'es2022',
    sourcemap: true,
    plugins: [nodeShimPlugin],
    banner: {
      js: 'var self = typeof window !== "undefined" ? window : globalThis;',
    },
  });

  console.log('Edge bundle successfully generated in dist/edge.js');
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  buildEdge().catch((error) => {
    console.error('Edge build failed:', error);
    process.exit(1);
  });
}

export { buildEdge };
