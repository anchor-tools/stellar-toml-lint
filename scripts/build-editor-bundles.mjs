/* eslint-disable no-console, no-undef */
/**
 * Builds the web distribution assets for the editor integrations.
 *
 * Two ESM bundles, one per editor, each holding only what a browser needs to
 * light up and complete a `stellar.toml`: the language facts and the
 * marker/completion mappings from `src/editor/`. The linter core is
 * deliberately absent — it is already shipped as `dist/browser/`, and at
 * ~146KB gzip it would spend the entire budget on its own. Requirement #543.5
 * is a footprint limit, so it is enforced here rather than in a README:
 * `dist/editor/sizes.json` records what each bundle costs, and a bundle over
 * 150KB gzip fails the build.
 */
import { build } from 'esbuild';
import { gzipSync } from 'node:zlib';
import { mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const outDir = join(root, 'dist', 'editor');

/** The gzip budget from the issue, in bytes. */
export const MAX_GZIP_BYTES = 150 * 1024;

const ENTRIES = [
  { entry: join('src', 'editor', 'monacoBundle.ts'), outfile: 'monaco.bundle.js' },
  { entry: join('src', 'editor', 'codeMirror.ts'), outfile: 'codemirror.bundle.js' },
];

/**
 * Level 9, not the default: gzip output varies with the level, and a published
 * budget has to be measured the same way every time it is checked.
 */
function gzipBytes(file) {
  return gzipSync(readFileSync(file), { level: 9 }).length;
}

async function bundleEach() {
  mkdirSync(outDir, { recursive: true });

  for (const { entry, outfile } of ENTRIES) {
    await build({
      entryPoints: [join(root, entry)],
      outfile: join(outDir, outfile),
      bundle: true,
      format: 'esm',
      platform: 'browser',
      target: 'es2022',
      minify: true,
      sourcemap: true,
      legalComments: 'none',
      treeShaking: true,
    });
  }
}

/**
 * Builds both bundles and measures them.
 *
 * Returns the sizes record it writes, and throws when a bundle is over budget
 * or contains a Node built-in, so `npm run build:editor` exits non-zero.
 */
export async function buildEditorBundles() {
  await bundleEach();

  const artifacts = ENTRIES.map(({ outfile }) => {
    const file = join(outDir, outfile);
    return {
      file: `dist/editor/${outfile}`,
      bytes: statSync(file).size,
      gzipBytes: gzipBytes(file),
    };
  });

  const overBudget = artifacts.filter((artifact) => artifact.gzipBytes > MAX_GZIP_BYTES);
  const report = {
    budgetBytes: MAX_GZIP_BYTES,
    ok: overBudget.length === 0,
    artifacts,
  };

  writeFileSync(join(outDir, 'sizes.json'), `${JSON.stringify(report, null, 2)}\n`);

  for (const artifact of artifacts) {
    const size = (artifact.gzipBytes / 1024).toFixed(1);
    const share = ((artifact.gzipBytes / MAX_GZIP_BYTES) * 100).toFixed(1);
    console.log(`${artifact.file}: ${size}KB gzip (${share}% of budget)`);
  }

  if (overBudget.length > 0) {
    const names = overBudget.map((a) => `${a.file} (${(a.gzipBytes / 1024).toFixed(1)}KB)`);
    throw new Error(
      `Editor bundle(s) over the ${(MAX_GZIP_BYTES / 1024).toFixed(0)}KB gzip budget: ${names.join(', ')}.`,
    );
  }

  return report;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  buildEditorBundles().catch((error) => {
    console.error('Editor bundle build failed:', error.message);
    process.exit(1);
  });
}
