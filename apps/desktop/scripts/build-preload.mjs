/**
 * Bundles the preload script to CommonJS.
 *
 * A preload running in a sandboxed renderer is loaded in a restricted context
 * that has `require` but no ESM loader, so the preload cannot be an ES module
 * however the rest of the app is written — and it cannot import from sibling
 * `.js` files either, because there is no module graph to resolve them in. So
 * it is bundled: one self-contained `.cjs` with `electron` left external, which
 * is the only module the sandboxed context provides.
 */
import { build } from 'esbuild';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

await build({
  entryPoints: [join(root, 'src', 'preload.ts')],
  outfile: join(root, 'out', 'preload.cjs'),
  bundle: true,
  platform: 'node',
  format: 'cjs',
  target: 'node20',
  sourcemap: true,
  // Provided by the sandboxed preload context itself.
  external: ['electron'],
});
