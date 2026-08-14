import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const read = (...parts: string[]): string => readFileSync(join(root, ...parts), 'utf8');

const pkg = JSON.parse(read('package.json'));

describe('package metadata', () => {
  it('keeps the CLI version in step with package.json', () => {
    // The CLI cannot import package.json at runtime without shipping it, so the
    // version is duplicated as a constant. This test is what keeps them honest.
    const cli = read('src', 'cli.ts');
    const declared = /const VERSION = '([^']+)'/.exec(cli)?.[1];
    expect(declared).toBe(pkg.version);
  });

  it('declares the two runtime dependencies and no more', () => {
    // This tool runs inside other people's CI, so dependency growth is a
    // deliberate decision rather than an accident.
    expect(Object.keys(pkg.dependencies).sort()).toEqual(['@stellar/stellar-base', 'smol-toml']);
  });

  it('publishes the built output and the license', () => {
    expect(pkg.files).toContain('dist');
    expect(pkg.files).toContain('LICENSE');
    expect(pkg.license).toBe('Apache-2.0');
  });

  it('exposes the bin entry the README documents', () => {
    expect(pkg.bin['stellar-toml-lint']).toBe('./dist/cli.js');
  });

  it('requires a Node version that supports the APIs used', () => {
    // `fetch` and `node:test`-era ESM behaviour assume 20+.
    expect(pkg.engines.node).toBe('>=20');
  });
});

describe('FUNDING.json', () => {
  const funding = JSON.parse(read('FUNDING.json'));

  it('is shaped the way the Drips oracle expects', () => {
    expect(typeof funding.drips.ethereum.ownedBy).toBe('string');
    expect(funding.drips.ethereum.ownedBy).toMatch(/^0x[0-9a-fA-F]{40}$/);
  });
});
