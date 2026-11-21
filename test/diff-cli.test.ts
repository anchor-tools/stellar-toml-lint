import { afterAll, describe, expect, it } from 'vitest';
import { execFile, spawn } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { sortCanonical } from '../src/cst/canonicalSortCodemod.js';
import type { SemanticDiff } from '../src/cst/semanticDiffer.js';

const run = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, '..', 'dist', 'cli.js');
const fixture = (name: string): string => join(here, 'fixtures', 'diff', name);

const temps: string[] = [];

afterAll(async () => {
  await Promise.all(temps.map((dir) => rm(dir, { recursive: true, force: true })));
});

async function workspace(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'semantic-diff-'));
  temps.push(dir);
  return dir;
}

interface Run {
  code: number;
  stdout: string;
  stderr: string;
}

/** Runs the built CLI, capturing the exit code instead of throwing. */
async function cli(args: string[], input?: string, env?: NodeJS.ProcessEnv): Promise<Run> {
  if (input !== undefined) return cliStdin(args, input, env);
  try {
    const { stdout, stderr } = await run('node', [CLI, ...args], {
      env: { ...process.env, NO_COLOR: '1', ...env },
    });
    return { code: 0, stdout, stderr };
  } catch (error) {
    const e = error as { code?: number; stdout?: string; stderr?: string };
    return { code: e.code ?? 1, stdout: e.stdout ?? '', stderr: e.stderr ?? '' };
  }
}

/**
 * `execFile({ input })` never closes the child's stdin here, so a command that
 * reads `-` hangs; `test/config.test.ts` spawns for the same reason.
 */
function cliStdin(args: string[], input: string, env?: NodeJS.ProcessEnv): Promise<Run> {
  return new Promise((resolvePromise) => {
    const child = spawn('node', [CLI, ...args], {
      env: { ...process.env, NO_COLOR: '1', ...env },
    });
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

const LIVE = (): string => fixture('live.toml');
const CANDIDATE = (): string => fixture('candidate.toml');

describe('stellar-toml-lint diff', () => {
  it('exits 0 and prints an empty diff for identical files', async () => {
    const { code, stdout } = await cli(['diff', LIVE(), LIVE()]);

    expect(code).toBe(0);
    expect(stdout).toContain('No semantic changes');
    expect(stdout).not.toContain('## Changes');
  });

  it('exits 1 when the candidate breaks a client', async () => {
    const { code, stdout } = await cli(['diff', LIVE(), CANDIDATE()]);

    expect(code).toBe(1);
    expect(stdout).toContain('BREAKING: 6 breaking changes');
    expect(stdout).toContain('~ `SIGNING_KEY` BREAKING');
    expect(stdout).toContain('+ `CURRENCIES[EURX]`');
  });

  it('counts only what the other direction breaks', async () => {
    const { stdout } = await cli(['diff', CANDIDATE(), LIVE()]);

    // Deploying the live file over the candidate unlists EURX, rotates the signing
    // key, moves the USDX issuer back and rewrites a validator host. It also
    // re-adds SEP-38 and SEP-3, but publishing something a client never had breaks
    // nobody — so the tag sits on four changes, not the six the other way round.
    expect(stdout).toContain('BREAKING: 4 breaking changes');
    expect(stdout).toContain('+ `ANCHOR_QUOTE_SERVER`');
    expect(stdout).not.toContain('+ `ANCHOR_QUOTE_SERVER` BREAKING');
  });

  it('ignores a canonical re-sort of the same document', async () => {
    // The pairing the issue is about: `--sort-keys` moves lines, `diff` has to
    // notice that nothing changed.
    const dir = await workspace();
    const resorted = join(dir, 'resorted.toml');
    const original = await readFile(LIVE(), 'utf8');
    await writeFile(resorted, sortCanonical(original).output, 'utf8');

    const { code, stdout } = await cli(['diff', LIVE(), resorted]);

    expect(code).toBe(0);
    expect(stdout).toContain('No semantic changes');
  });

  it('writes a machine-readable changelog with --json', async () => {
    const { code, stdout } = await cli(['diff', LIVE(), CANDIDATE(), '--json']);
    const report = JSON.parse(stdout) as SemanticDiff;

    expect(code).toBe(1);
    expect(report.source.input).toBe(LIVE());
    expect(report.target.fields).toBe(15);
    expect(report.breaking).toBe(6);
    expect(
      report.changes.find((change) => change.path === 'CURRENCIES[USDX].issuer'),
    ).toMatchObject({ breaking: true, kind: 'modified' });
  });

  it('takes one side from stdin', async () => {
    const live = await readFile(LIVE(), 'utf8');
    const { code, stdout } = await cli(['diff', '-', CANDIDATE()], live);

    expect(code).toBe(1);
    expect(stdout).toContain('**source:** `-`');
    expect(stdout).toContain('BREAKING: 6 breaking changes');
  });

  it('refuses to read both sides from stdin', async () => {
    const { code, stderr } = await cli(['diff', '-', '-'], '');

    expect(code).toBe(2);
    expect(stderr).toContain('Only one side of a diff can come from stdin');
  });

  it('exits 2 when a side does not parse', async () => {
    const dir = await workspace();
    const broken = join(dir, 'broken.toml');
    await writeFile(broken, '[[CURRENCIES]]\ncode = "USD"\nname = "unterminated\n', 'utf8');

    const { code, stdout } = await cli(['diff', LIVE(), broken]);

    expect(code).toBe(2);
    expect(stdout).toContain('did not parse');
    expect(stdout).toContain('Invalid TOML');
  });

  it('exits 2 on a side that cannot be read', async () => {
    const missing = resolve(await workspace(), 'nowhere.toml');
    const { code, stderr } = await cli(['diff', LIVE(), missing]);

    expect(code).toBe(2);
    expect(stderr).toContain('Could not find');
  });

  it('reports usage rather than linting the word diff', async () => {
    const { code, stderr } = await cli(['diff', LIVE()]);

    expect(code).toBe(2);
    expect(stderr).toContain('Usage: stellar-toml-lint diff <source> <target> [--json]');
  });

  it('rejects an unknown flag', async () => {
    const { code, stderr } = await cli(['diff', LIVE(), CANDIDATE(), '--strict']);

    expect(code).toBe(2);
    expect(stderr).toContain('Unknown option --strict for diff');
  });

  it('colourises the markers when a colour is asked for', async () => {
    const { stdout } = await cli(['diff', LIVE(), CANDIDATE()], undefined, {
      NO_COLOR: '',
      FORCE_COLOR: '1',
    });

    expect(stdout).toContain('\x1b[31m-\x1b[39m');
    expect(stdout).toContain('\x1b[32m+\x1b[39m');
  });
});
