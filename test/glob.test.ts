import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { expandGlob, hasMagic } from '../src/glob.js';

/**
 * A tree with every shape a pattern has to handle: files at the root, one
 * level down, two levels down, and a hidden directory nothing should wander
 * into by accident.
 */
let root = '';

beforeAll(async () => {
  root = await mkdtemp(join(tmpdir(), 'stellar-toml-lint-glob-'));
  await mkdir(join(root, 'sub'), { recursive: true });
  await mkdir(join(root, 'deep', 'nested'), { recursive: true });
  await mkdir(join(root, '.cache'), { recursive: true });

  await writeFile(join(root, 'stellar.toml'), 'VERSION="2.7.0"\n');
  await writeFile(join(root, 'sub', 'one.toml'), 'VERSION="2.7.0"\n');
  await writeFile(join(root, 'sub', 'two.toml'), 'VERSION="2.7.0"\n');
  await writeFile(join(root, 'deep', 'nested', 'three.toml'), 'VERSION="2.7.0"\n');
  await writeFile(join(root, '.cache', 'skip.toml'), 'VERSION="2.7.0"\n');
});

afterAll(async () => {
  await rm(root, { recursive: true, force: true });
});

describe('hasMagic', () => {
  it('recognises the characters that make an argument a pattern', () => {
    expect(hasMagic('configs/*.toml')).toBe(true);
    expect(hasMagic('configs/**')).toBe(true);
    expect(hasMagic('file?.toml')).toBe(true);
    expect(hasMagic('report[0-9].toml')).toBe(true);
  });

  it('leaves ordinary paths alone', () => {
    expect(hasMagic('public/.well-known/stellar.toml')).toBe(false);
    expect(hasMagic('./stellar.toml')).toBe(false);
    expect(hasMagic('-')).toBe(false);
    // A backslash is a path separator for a Windows user, not magic on its own.
    expect(hasMagic('configs\\stellar.toml')).toBe(false);
  });

  it('reads a Windows-authored pattern as a pattern', () => {
    expect(hasMagic('configs\\*.toml')).toBe(true);
  });
});

describe('expandGlob', () => {
  it('matches a single directory level', async () => {
    await expect(expandGlob(join(root, 'sub', '*.toml'))).resolves.toEqual([
      join(root, 'sub', 'one.toml'),
      join(root, 'sub', 'two.toml'),
    ]);
  });

  it('spans directories with the globstar, including zero levels', async () => {
    await expect(expandGlob(join(root, '**', '*.toml'))).resolves.toEqual([
      join(root, 'deep', 'nested', 'three.toml'),
      join(root, 'stellar.toml'),
      join(root, 'sub', 'one.toml'),
      join(root, 'sub', 'two.toml'),
    ]);
  });

  it('treats a trailing globstar as "everything underneath"', async () => {
    await expect(expandGlob(join(root, 'sub', '**'))).resolves.toEqual([
      join(root, 'sub', 'one.toml'),
      join(root, 'sub', 'two.toml'),
    ]);
  });

  it('matches a single character with ? and a set with [...]', async () => {
    await expect(expandGlob(join(root, 'sub', 't?o.toml'))).resolves.toEqual([
      join(root, 'sub', 'two.toml'),
    ]);
    await expect(expandGlob(join(root, 'sub', '[ot]ne.toml'))).resolves.toEqual([
      join(root, 'sub', 'one.toml'),
    ]);
  });

  it('never walks into hidden directories on its own', async () => {
    const matches = await expandGlob(join(root, '**', '*.toml'));
    expect(matches).not.toContain(join(root, '.cache', 'skip.toml'));

    // Naming the dot directory is how a caller asks for it.
    await expect(expandGlob(join(root, '.cache', '*.toml'))).resolves.toEqual([
      join(root, '.cache', 'skip.toml'),
    ]);
  });

  it('returns nothing for a pattern that matches nothing', async () => {
    await expect(expandGlob(join(root, 'no-such-dir', '*.toml'))).resolves.toEqual([]);
    await expect(expandGlob(join(root, 'sub', 'missing*.toml'))).resolves.toEqual([]);
  });

  it('passes a path without magic through unchanged', async () => {
    await expect(expandGlob(join(root, 'stellar.toml'))).resolves.toEqual([
      join(root, 'stellar.toml'),
    ]);
  });

  it('returns directories never, since they cannot be linted', async () => {
    const matches = await expandGlob(join(root, '*'));
    expect(matches).toEqual([join(root, 'stellar.toml')]);
  });

  it('never lists the same file twice', async () => {
    const matches = await expandGlob(join(root, '**', '**', '*.toml'));
    expect(new Set(matches).size).toBe(matches.length);
  });
});
