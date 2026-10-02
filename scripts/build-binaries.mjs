#!/usr/bin/env node
/** Build one self-contained CLI binary for a release target. */
import process from 'node:process';
import { existsSync } from 'node:fs';
import { mkdir, rm } from 'node:fs/promises';
import { basename, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';

const targets = {
  'node20-linux-x64': 'stellar-toml-lint-linux-x64',
  'node20-linuxstatic-x64': 'stellar-toml-lint-linux-x64-musl',
  'node20-linux-arm64': 'stellar-toml-lint-linux-arm64',
  'node20-macos-x64': 'stellar-toml-lint-macos-x64',
  'node20-macos-arm64': 'stellar-toml-lint-macos-arm64',
  'node20-win-x64': 'stellar-toml-lint-windows-x64.exe',
};

const args = process.argv.slice(2);
const target = args[args.indexOf('--target') + 1];

if (target === undefined || !(target in targets)) {
  process.stderr.write(
    `Usage: npm run build:binaries -- --target <target>\n\nTargets:\n${Object.keys(targets)
      .map((item) => `  ${item}`)
      .join('\n')}\n`,
  );
  process.exit(2);
}

const releaseDir = resolve('release');
const bundle = resolve('dist', 'standalone', 'cli.cjs');
const output = resolve(releaseDir, targets[target]);

execFileSync(process.platform === 'win32' ? 'npm.cmd' : 'npm', ['run', 'build'], {
  stdio: 'inherit',
});
await mkdir(releaseDir, { recursive: true });
await rm(resolve('dist', 'standalone'), { recursive: true, force: true });
const npx = process.platform === 'win32' ? 'npx.cmd' : 'npx';
execFileSync(
  npx,
  [
    '--yes',
    'esbuild@0.25.0',
    resolve('dist', 'cli.js'),
    '--bundle',
    '--platform=node',
    '--format=cjs',
    '--target=node20',
    '--banner:js=#!/usr/bin/env node',
    `--outfile=${bundle}`,
  ],
  { stdio: 'inherit' },
);

execFileSync(
  npx,
  ['--yes', '@yao-pkg/pkg@5.16.1', bundle, '--targets', target, '--output', output],
  { stdio: 'inherit' },
);
if (!existsSync(output)) throw new Error(`pkg did not produce ${basename(output)}`);
process.stdout.write(`Built ${output}\n`);
