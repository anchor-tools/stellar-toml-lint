/* eslint-disable no-console, no-undef */
/**
 * Builds and verifies the `stellar-toml` tree-sitter grammar (#539).
 *
 *   node scripts/build-tree-sitter-grammar.mjs
 *
 * Three steps, run in order:
 *
 *   1. `tree-sitter generate` — regenerates `src/parser.c`, `src/grammar.json`
 *      and `src/node-types.json`, failing on grammar conflicts or errors.
 *   2. `tree-sitter test` — replays `test/corpus/*.txt`, which covers a
 *      production anchor, a compliant anchor, contract/muxed-account shapes and
 *      the near-misses that must *not* become SEP-1 nodes.
 *   3. `tree-sitter build --wasm` — only when a WASM toolchain is reachable.
 *      The artefact lands in `dist/wasm/`, which is gitignored: this repository
 *      ships the grammar as source plus this script, never as a compiled binary.
 *
 * Why the WASM half ships as source + script + docs rather than as a checked-in
 * `.wasm` or an npm dependency:
 *
 *   - The root "Malware and supply-chain check" CI job audits `package-lock.json`
 *     and rejects install/lifecycle scripts and non-registry `resolved` URLs.
 *     `tree-sitter-cli` is an npm package whose postinstall downloads a native
 *     binary, so adding it (or `web-tree-sitter`) as a dependency would either
 *     fail that job or require widening its allowlist — and adding a dependency
 *     to the grammar directory would need a nested lockfile, which is worse.
 *   - A committed `.wasm` is an unreviewable binary blob that would have to be
 *     rebuilt on every grammar change anyway.
 *
 * Consequently the CLI is looked up, not installed: `TREE_SITTER_CLI=<path>`
 * wins, otherwise `tree-sitter` from `PATH`. If neither is present the script
 * prints what is missing and exits 0, so nothing that depends on it (CI, a
 * pre-commit hook) breaks on a machine without the toolchain. The repo's own
 * grammar invariants that *can* be checked without the CLI are enforced by
 * `test/tree-sitter-grammar.test.ts`, which runs in the normal vitest suite.
 *
 * WASM toolchain detection, in order: emscripten (`emcc` on `PATH`), a running
 * Docker daemon, and — opt-in with `TREE_SITTER_ALLOW_WASI_SDK=1` — the wasi-sdk
 * toolchain that tree-sitter >= 0.25 downloads into `~/.cache/tree-sitter` on
 * first use (~180 MB, network required). `TREE_SITTER_SKIP_WASM=1` skips step 3
 * entirely.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const grammarDir = join(root, 'grammars', 'tree-sitter-stellar-toml');
const wasmOutput = join(root, 'dist', 'wasm', 'tree-sitter-stellar_toml.wasm');

/** Runs `command` and reports whether it is usable on this machine. */
function canRun(command, args) {
  const result = spawnSync(command, args, { encoding: 'utf8' });
  return !result.error && result.status === 0;
}

/**
 * Resolves the tree-sitter CLI: an explicit `TREE_SITTER_CLI` path, or the
 * `tree-sitter` executable on `PATH`. Returns `null`, plus the reason a caller
 * can print, when neither works.
 */
function resolveCli() {
  const configured = process.env.TREE_SITTER_CLI;
  const command = configured === undefined || configured === '' ? 'tree-sitter' : configured;

  if (configured !== undefined && configured !== '' && !existsSync(configured)) {
    return {
      command: null,
      reason: `TREE_SITTER_CLI points at ${configured}, which does not exist`,
    };
  }

  if (!canRun(command, ['--version'])) {
    const hint =
      configured === undefined
        ? 'install the tree-sitter CLI or set TREE_SITTER_CLI=<path>'
        : `TREE_SITTER_CLI=${configured} is not a working tree-sitter CLI`;
    return { command: null, reason: `no usable tree-sitter CLI (${hint})` };
  }

  const version =
    spawnSync(command, ['--version'], { encoding: 'utf8' }).stdout?.trim() ?? 'unknown';
  return { command, reason: null, version };
}

/** Which WASM backend, if any, can produce a `.wasm` right now. */
function detectWasmToolchain() {
  if (process.env.TREE_SITTER_SKIP_WASM === '1') {
    return { kind: null, reason: 'TREE_SITTER_SKIP_WASM=1' };
  }
  if (canRun('emcc', ['-v'])) {
    return { kind: 'emscripten', reason: null };
  }
  if (canRun('docker', ['info'])) {
    return { kind: 'docker', reason: null };
  }
  if (process.env.TREE_SITTER_ALLOW_WASI_SDK === '1') {
    return { kind: 'cli-wasi-sdk', reason: null };
  }
  return {
    kind: null,
    reason:
      'neither emscripten (`emcc`) nor a running Docker daemon was found; ' +
      're-run with TREE_SITTER_ALLOW_WASI_SDK=1 to let the CLI download its own wasi-sdk',
  };
}

/** Runs one CLI step in the grammar directory; returns its exit status. */
function run(cli, args) {
  console.log(`$ ${cli} ${args.join(' ')}  (in ${grammarDir.replace(`${root}/`, '')})`);
  const result = spawnSync(cli, args, { cwd: grammarDir, stdio: 'inherit' });
  if (result.error) {
    console.error(`  failed to spawn: ${result.error.message}`);
    return 1;
  }
  return result.status ?? 1;
}

function main() {
  const cli = resolveCli();
  if (cli.command === null) {
    console.log(`tree-sitter grammar: SKIPPED — ${cli.reason}.`);
    console.log('  The checked-in src/parser.c is the source of truth; regenerate it once the CLI');
    console.log(
      '  is available. Grammar invariants are covered by test/tree-sitter-grammar.test.ts.',
    );
    return 0;
  }

  console.log(`tree-sitter grammar build (${cli.version})`);

  const generate = run(cli.command, ['generate']);
  if (generate !== 0) {
    console.error('generate FAILED — fix the grammar before running the corpus tests.');
    return generate;
  }

  const test = run(cli.command, ['test']);
  if (test !== 0) {
    console.error('corpus tests FAILED — regenerate expectations with `tree-sitter test -u`');
    console.error('only if the new tree is the intended one.');
    return test;
  }

  const toolchain = detectWasmToolchain();
  if (toolchain.kind === null) {
    console.log(`wasm: SKIPPED — ${toolchain.reason}.`);
    console.log('  The grammar ships as source; nothing in CI or in this repository needs the');
    console.log('  compiled module, and no .wasm is ever committed.');
    return 0;
  }

  if (toolchain.kind === 'cli-wasi-sdk') {
    console.log('wasm: no emcc/docker found — using the CLI built-in wasi-sdk toolchain,');
    console.log('  which may download ~180 MB into ~/.cache/tree-sitter on first use.');
  } else {
    console.log(`wasm: building with ${toolchain.kind}.`);
  }

  mkdirSync(dirname(wasmOutput), { recursive: true });
  const build = run(cli.command, ['build', '--wasm', '-o', wasmOutput]);
  if (build !== 0) {
    console.error('wasm build FAILED.');
    return build;
  }
  console.log(`wasm: wrote ${wasmOutput.replace(`${root}/`, '')} (gitignored build artefact).`);
  return 0;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.exitCode = main();
}

export { detectWasmToolchain, grammarDir, main, resolveCli, wasmOutput };
