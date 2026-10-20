import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'smol-toml';

const here = dirname(fileURLToPath(import.meta.url));
const ZED_DIR = join(here, '..', '..', 'integrations', 'zed');
const read = (relative: string): string => readFileSync(join(ZED_DIR, relative), 'utf8');

/**
 * The extension is a Rust crate built to `wasm32-wasip1`. A machine without a
 * Rust toolchain (most CI runners) cannot build it, so that one test is gated;
 * every structural check still runs everywhere.
 */
function wasmTargetAvailable(): boolean {
  const rustup = spawnSync('rustup', ['target', 'list', '--installed'], { encoding: 'utf8' });
  if (rustup.status !== 0) return false;
  return (rustup.stdout ?? '')
    .split('\n')
    .map((line) => line.trim())
    .some((target) => target.startsWith('wasm32-wasip1'));
}

const canBuild = wasmTargetAvailable();

describe('Zed extension manifest', () => {
  it('declares the extension identity and schema', () => {
    const manifest = parse(read('extension.toml')) as Record<string, unknown>;

    expect(manifest.id).toBe('stellar-toml');
    expect(manifest.name).toBe('Stellar TOML');
    expect(manifest.schema_version).toBe(1);
    expect(String(manifest.repository)).toContain('anchor-tools/stellar-toml-lint');
  });

  it('registers the language server for the stellar-toml language', () => {
    const manifest = parse(read('extension.toml')) as Record<string, any>;
    const server = manifest.language_servers?.['stellar-toml-lint'];

    expect(server).toBeDefined();
    expect(server.name).toContain('Stellar TOML');
    expect(server.languages).toContain('stellar-toml');
  });

  it('pins a tree-sitter grammar for the language', () => {
    const manifest = parse(read('extension.toml')) as Record<string, any>;
    const grammar = manifest.grammars?.['stellar-toml'];

    expect(grammar).toBeDefined();
    expect(String(grammar.repository)).toContain('tree-sitter-toml');
    expect(grammar.rev).toBeTruthy();
  });
});

describe('Zed language definition', () => {
  const config = parse(read('languages/stellar-toml/config.toml')) as Record<string, any>;

  it('names the language and points at the declared grammar', () => {
    expect(config.name).toBe('Stellar TOML');
    expect(config.grammar).toBe('stellar-toml');
  });

  it('activates for stellar.toml files', () => {
    expect(config.path_suffixes).toEqual(expect.arrayContaining(['stellar.toml']));
  });

  it('ships non-empty highlight and fold queries', () => {
    for (const query of ['highlights.scm', 'folds.scm', 'brackets.scm', 'indents.scm']) {
      const contents = read(`languages/stellar-toml/${query}`).trim();
      expect(contents.length, query).toBeGreaterThan(0);
      expect(contents, query).toContain('@');
    }
  });

  it('highlights keys, tables, and comments', () => {
    const highlights = read('languages/stellar-toml/highlights.scm');

    expect(highlights).toContain('@comment');
    expect(highlights).toContain('@property');
    expect(highlights).toContain('@type');
  });
});

describe('Zed extension crate', () => {
  it('has a Cargo manifest built as a WebAssembly cdylib', () => {
    const cargo = parse(read('Cargo.toml')) as Record<string, any>;

    expect(cargo.package.name).toBe('stellar-toml-zed');
    expect(cargo.lib?.['crate-type']).toContain('cdylib');
    expect(cargo.dependencies?.zed_extension_api).toBeTruthy();
  });

  it('implements zed::Extension and registers it', () => {
    const source = read('src/lib.rs');

    expect(source).toContain('impl zed::Extension for');
    expect(source).toContain('fn language_server_command');
    expect(source).toContain('zed::register_extension!');
    expect(source).toContain('--lsp');
  });

  it('references every file Zed loads', () => {
    for (const file of [
      'extension.toml',
      'Cargo.toml',
      'src/lib.rs',
      'languages/stellar-toml/config.toml',
      'languages/stellar-toml/highlights.scm',
    ]) {
      expect(existsSync(join(ZED_DIR, file)), file).toBe(true);
    }
  });
});

describe('Zed extension build', () => {
  it.skipIf(!canBuild)(
    'compiles to the wasm32-wasip1 target',
    () => {
      const result = spawnSync('cargo', ['build', '--release', '--target', 'wasm32-wasip1'], {
        cwd: ZED_DIR,
        encoding: 'utf8',
      });

      expect(result.status, result.stderr).toBe(0);
      expect(
        existsSync(join(ZED_DIR, 'target', 'wasm32-wasip1', 'release', 'stellar_toml_zed.wasm')),
      ).toBe(true);
    },
    120_000,
  );
});
