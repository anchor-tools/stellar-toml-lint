import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const formulaPath = join(
  import.meta.dirname ?? '.',
  '..',
  'packaging',
  'homebrew',
  'stellar-toml-lint.rb',
);

describe('Homebrew formula', () => {
  it('exists at the expected path', () => {
    const content = readFileSync(formulaPath, 'utf8');
    expect(content.length).toBeGreaterThan(0);
  });

  it('defines the StellarTomlLint class', () => {
    const content = readFileSync(formulaPath, 'utf8');
    expect(content).toContain('class StellarTomlLint < Formula');
  });

  it('includes a test block verifying stellar-toml-lint --version', () => {
    const content = readFileSync(formulaPath, 'utf8');
    expect(content).toMatch(/stellar-toml-lint.*--version/);
  });

  it('declares the node dependency', () => {
    const content = readFileSync(formulaPath, 'utf8');
    expect(content).toContain('depends_on "node"');
  });
});
