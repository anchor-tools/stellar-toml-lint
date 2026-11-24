import { afterAll, describe, expect, it } from 'vitest';
import { execFile, spawn } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const run = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, '..', 'dist', 'cli.js');

const temps: string[] = [];

afterAll(async () => {
  await Promise.all(temps.map((dir) => rm(dir, { recursive: true, force: true })));
});

async function workspace(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'sort-keys-'));
  temps.push(dir);
  return dir;
}

interface Run {
  code: number;
  stdout: string;
  stderr: string;
}

/** Runs the built CLI, capturing the exit code instead of throwing. */
async function cli(args: string[], input?: string): Promise<Run> {
  if (input !== undefined) return cliStdin(args, input);
  try {
    const { stdout, stderr } = await run('node', [CLI, ...args], {
      env: { ...process.env, NO_COLOR: '1' },
    });
    return { code: 0, stdout, stderr };
  } catch (error) {
    const e = error as { code?: number; stdout?: string; stderr?: string };
    return { code: e.code ?? 1, stdout: e.stdout ?? '', stderr: e.stderr ?? '' };
  }
}

/**
 * `execFile({ input })` never closes the child's stdin here, so any command that
 * reads `-` hangs; `test/config.test.ts` spawns for the same reason.
 */
function cliStdin(args: string[], input: string): Promise<Run> {
  return new Promise((resolvePromise) => {
    const child = spawn('node', [CLI, ...args], { env: { ...process.env, NO_COLOR: '1' } });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });
    child.on('close', (code) => resolvePromise({ code: code ?? 1, stdout, stderr }));
    child.stdin.end(input);
  });
}

/** A currency block written newest-first, with a comment on each key. */
const SCRAMBLED = [
  '# Example anchor.',
  'VERSION = "2.7.0"',
  '',
  '[[CURRENCIES]]',
  '# what it is called',
  'name = "US Dollar"',
  '# the issuing account',
  'issuer = "GABC"',
  'code = "USDC"',
  '',
  '[[CURRENCIES]]',
  'code = "ALPHA"',
  'issuer = "GDEF"',
  '',
].join('\n');

describe('cli --sort-keys', () => {
  it('rewrites a file into canonical order', async () => {
    const dir = await workspace();
    const file = join(dir, 'stellar.toml');
    await writeFile(file, SCRAMBLED);

    const { code, stdout } = await cli(['--sort-keys', file]);

    expect(code).toBe(0);
    expect(stdout).toContain('stellar.toml: sorted');
    expect(await readFile(file, 'utf8')).toBe(
      [
        '# Example anchor.',
        'VERSION = "2.7.0"',
        '',
        '[[CURRENCIES]]',
        'code = "ALPHA"',
        'issuer = "GDEF"',
        '',
        '[[CURRENCIES]]',
        'code = "USDC"',
        '# the issuing account',
        'issuer = "GABC"',
        '# what it is called',
        'name = "US Dollar"',
        '',
      ].join('\n'),
    );
  });

  it('prints a diff and leaves the file alone under --dry-run', async () => {
    const dir = await workspace();
    const file = join(dir, 'stellar.toml');
    await writeFile(file, SCRAMBLED);

    const { code, stdout } = await cli(['--sort-keys', '--dry-run', file]);

    expect(code).toBe(1);
    // The paths arrive as typed, so an absolute input keeps its own spelling
    // rather than picking up git's `a/` prefix and reading `a//tmp/...`.
    expect(stdout.startsWith(`--- ${file}\n+++ ${file}\n`)).toBe(true);
    expect(stdout).toContain('@@');
    expect(stdout).toContain('-name = "US Dollar"');
    expect(stdout).toContain('+code = "USDC"');
    expect(await readFile(file, 'utf8')).toBe(SCRAMBLED);
  });

  it('exits 0 and says so when the file is already canonical', async () => {
    const dir = await workspace();
    const file = join(dir, 'stellar.toml');
    await writeFile(file, SCRAMBLED);

    expect((await cli(['--sort-keys', '--dry-run', file])).code).toBe(1);
    await cli(['--sort-keys', file]);

    const twice = await cli(['--sort-keys', '--dry-run', file]);
    expect(twice.code).toBe(0);
    expect(twice.stdout).toContain('All files are in canonical key order.');
  });

  it('colours the preview only when asked', async () => {
    const dir = await workspace();
    const file = join(dir, 'stellar.toml');
    await writeFile(file, SCRAMBLED);

    const plain = await cli(['--sort-keys', '--dry-run', file]);
    const colored = await cli(['--sort-keys', '--dry-run', '--color', file]);

    expect(plain.stdout).not.toContain('\x1b[');
    expect(colored.stdout).toContain('\x1b[31m-');
    expect(colored.stdout).toContain('\x1b[32m+');
  });

  it('sorts stdin and writes the file to stdout', async () => {
    const { code, stdout } = await cli(['--sort-keys', '-'], SCRAMBLED);

    expect(code).toBe(0);
    expect(stdout.indexOf('code = "ALPHA"')).toBeLessThan(stdout.indexOf('code = "USDC"'));
    expect(stdout).toContain('# the issuing account\nissuer = "GABC"');
  });

  it('sorts every file it is given, including a glob', async () => {
    const dir = await workspace();
    await writeFile(join(dir, 'a.toml'), SCRAMBLED);
    await writeFile(join(dir, 'b.toml'), SCRAMBLED);

    const { code, stdout } = await cli(['--sort-keys', join(dir, '*.toml')]);

    expect(code).toBe(0);
    expect(stdout).toContain('a.toml: sorted');
    expect(stdout).toContain('b.toml: sorted');
  });

  it('reports a file it cannot parse and changes nothing', async () => {
    const dir = await workspace();
    const file = join(dir, 'stellar.toml');
    const broken = '[[CURRENCIES]]\nissuer = "GDEF"\ncode = "ALPHA"\nname = "unterminated\n';
    await writeFile(file, broken);

    const { code, stderr } = await cli(['--sort-keys', file]);

    expect(code).toBe(1);
    expect(stderr).toContain('file does not parse');
    expect(await readFile(file, 'utf8')).toBe(broken);
  });

  it('keeps a sorted file lint-clean', async () => {
    const dir = await workspace();
    const file = join(dir, 'stellar.toml');
    const source = await readFile(join(here, 'fixtures', 'valid.toml'), 'utf8');
    await writeFile(file, source);

    // Sorting must not manufacture or hide a diagnostic, so the same file is
    // checked before and after the reorder rather than trusting the diff.
    const before = await cli([file]);
    await cli(['--sort-keys', file]);
    const after = await cli([file]);

    expect(before.code).toBe(0);
    expect(after.code).toBe(0);
    expect(after.stdout).toContain('No SEP-1 issues found');
  });

  it('rejects --dry-run on its own', async () => {
    const { code, stderr } = await cli(['--dry-run']);

    expect(code).toBe(2);
    expect(stderr).toContain('nothing to preview');
  });

  it('rejects --sort-keys with --domain', async () => {
    const { code, stderr } = await cli(['--sort-keys', '--domain', 'example.com']);

    expect(code).toBe(2);
    expect(stderr).toContain('cannot be combined with --domain');
  });

  it('documents the flag in --help', async () => {
    const { stdout } = await cli(['--help']);

    expect(stdout).toContain('--sort-keys');
    expect(stdout).toContain('--dry-run');
  });
});
