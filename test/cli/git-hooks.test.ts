import { afterEach, describe, expect, it } from 'vitest';
import { execFile, spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { promisify } from 'node:util';
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, delimiter, dirname, join } from 'node:path';
import {
  BACKUP_SUFFIX,
  DEFAULT_COMMAND,
  HOOK_MARKER,
  findGitDir,
  installHook,
  isHookName,
  renderHookScript,
  uninstallHook,
} from '../../src/cli/git-hooks.js';

const exec = promisify(execFile);

/**
 * Git for Windows ships the `sh` it uses for hooks, but does not necessarily
 * put it on PATH. Resolve that copy before falling back to a bare name.
 */
const SH =
  process.platform === 'win32'
    ? (['bin', 'usr\\bin']
        .map((dir) => join(process.env.ProgramFiles ?? 'C:\\Program Files', 'Git', dir, 'sh.exe'))
        .find((candidate) => existsSync(candidate)) ?? 'sh')
    : 'sh';

const ZERO = '0000000000000000000000000000000000000000';

/** Directories to delete once a test finishes, however it finished. */
const scratch: string[] = [];

afterEach(async () => {
  await Promise.all(scratch.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function scratchDir(prefix: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), prefix));
  scratch.push(dir);
  return dir;
}

async function git(cwd: string, args: string[]): Promise<string> {
  const { stdout } = await exec('git', args, { cwd });
  return stdout.trim();
}

/** A throwaway repository with an identity configured, so commits work in CI. */
async function makeRepo(): Promise<string> {
  const dir = await scratchDir('stl-hooks-');
  await git(dir, ['init', '-q']);
  await git(dir, ['config', 'user.email', 'hooks@example.com']);
  await git(dir, ['config', 'user.name', 'Hook Test']);
  await git(dir, ['config', 'commit.gpgsign', 'false']);
  return dir;
}

/** Writes an executable `sh` stub that exits with `code`. */
async function stubLinter(dir: string, name: string, body: string): Promise<string> {
  const path = join(dir, name);
  await writeFile(path, `#!/bin/sh\n${body}\n`, { mode: 0o755 });
  await chmod(path, 0o755);
  return path;
}

/**
 * Points the hook at the stub by bare name, with its directory on PATH.
 *
 * The generated hook deliberately leaves `$LINTER` unquoted so callers can bake
 * in commands with arguments (the default is `npx --yes ...`). Passing an
 * absolute path containing spaces therefore splits it; a PATH lookup avoids
 * that without changing the script's documented contract.
 */
function linterEnv(stub: string): Record<string, string> {
  return {
    STELLAR_TOML_LINT: basename(stub),
    PATH: `${dirname(stub)}${delimiter}${process.env.PATH ?? ''}`,
  };
}

/** Runs a hook exactly as git would: `/bin/sh <hook>` with the refs on stdin. */
function runHook(
  hookPath: string,
  cwd: string,
  options: { stdin?: string; env?: Record<string, string> } = {},
): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(SH, [hookPath], {
      cwd,
      env: { ...process.env, ...options.env },
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk: Buffer) => (stdout += chunk.toString()));
    child.stderr.on('data', (chunk: Buffer) => (stderr += chunk.toString()));
    child.on('close', (code) => resolve({ code: code ?? 0, stdout, stderr }));
    child.stdin.end(options.stdin ?? '');
  });
}

describe('isHookName', () => {
  it('accepts the two hooks the installer writes', () => {
    expect(isHookName('pre-commit')).toBe(true);
    expect(isHookName('pre-push')).toBe(true);
  });

  it('rejects anything else', () => {
    expect(isHookName('commit-msg')).toBe(false);
    expect(isHookName('pre-receive')).toBe(false);
    expect(isHookName('')).toBe(false);
  });
});

describe('renderHookScript', () => {
  it('marks the script as managed and runs the documented default command', () => {
    const script = renderHookScript('pre-push');
    expect(script.startsWith('#!/bin/sh\n')).toBe(true);
    expect(script).toContain(HOOK_MARKER);
    expect(script).toContain(DEFAULT_COMMAND);
    // The command must be overridable at hook time, so a team can pin a version.
    expect(script).toContain('${STELLAR_TOML_LINT:-');
  });

  it('bakes in a custom command when one is given', () => {
    const script = renderHookScript('pre-push', {
      command: './node_modules/.bin/stellar-toml-lint',
    });
    expect(script).toContain('./node_modules/.bin/stellar-toml-lint');
    expect(script).not.toContain(DEFAULT_COMMAND);
  });

  it('lints only the pushed commit range and aborts on findings', () => {
    const script = renderHookScript('pre-push');
    expect(script).toContain('--not --remotes');
    expect(script).toContain('$remote_sha..$local_sha');
    expect(script).toContain('stellar\\.toml$');
    expect(script).toContain('exit 1');
    expect(script).toContain('--no-verify');
  });

  it('lints staged blobs rather than the working tree for pre-commit', () => {
    const script = renderHookScript('pre-commit');
    expect(script).toContain('--cached');
    expect(script).toContain('git show ":$file"');
    expect(script).not.toContain('--not --remotes');
  });
});

describe('findGitDir', () => {
  it('finds the repository root from a nested subdirectory', async () => {
    const repo = await makeRepo();
    const nested = join(repo, 'apps', 'anchor');
    await mkdir(nested, { recursive: true });
    expect(await findGitDir(nested)).toBe(join(repo, '.git'));
  });

  it('returns undefined when no ancestor holds a .git directory', async () => {
    const outside = await scratchDir('stl-nogit-');
    expect(await findGitDir(outside)).toBeUndefined();
  });
});

describe('installHook', () => {
  it('is a no-op for a repository it cannot find', async () => {
    const outside = await scratchDir('stl-nogit-');
    await expect(installHook('pre-push', { cwd: outside })).rejects.toThrow(/Not inside a Git/);
  });

  it('writes an executable hook that git will run', async () => {
    const repo = await makeRepo();
    const result = await installHook('pre-commit', { cwd: repo });

    expect(result.path).toBe(join(repo, '.git', 'hooks', 'pre-commit'));
    if (process.platform !== 'win32') {
      const mode = (await stat(result.path)).mode;
      expect(mode & 0o111).not.toBe(0);
    }

    const body = await readFile(result.path, 'utf8');
    expect(body).toContain(HOOK_MARKER);
  });

  it('refreshes its own hook without leaving backups behind', async () => {
    const repo = await makeRepo();
    await installHook('pre-push', { cwd: repo, command: 'first' });
    const second = await installHook('pre-push', { cwd: repo, command: 'second' });

    expect(second.backedUp).toBeUndefined();
    const body = await readFile(second.path, 'utf8');
    expect(body).toContain('second');
    expect(body).not.toContain('first');
  });

  it('preserves a foreign hook instead of overwriting it', async () => {
    const repo = await makeRepo();
    const hooks = join(repo, '.git', 'hooks');
    await mkdir(hooks, { recursive: true });
    const target = join(hooks, 'pre-push');
    await writeFile(target, '#!/bin/sh\necho hand-written\n');

    const result = await installHook('pre-push', { cwd: repo });

    expect(result.backedUp).toBe(`${target}${BACKUP_SUFFIX}`);
    expect(await readFile(result.backedUp as string, 'utf8')).toContain('hand-written');
    expect(await readFile(target, 'utf8')).toContain(HOOK_MARKER);
  });

  it('keeps the original backup across a second install of a foreign hook', async () => {
    const repo = await makeRepo();
    const hooks = join(repo, '.git', 'hooks');
    await mkdir(hooks, { recursive: true });
    await writeFile(join(hooks, 'pre-push'), '#!/bin/sh\necho original\n');

    await installHook('pre-push', { cwd: repo });
    await installHook('pre-push', { cwd: repo });

    const backup = await readFile(join(hooks, `pre-push${BACKUP_SUFFIX}`), 'utf8');
    expect(backup).toContain('original');
  });
});

describe('uninstallHook', () => {
  it('reports when there is nothing to remove', async () => {
    const repo = await makeRepo();
    const result = await uninstallHook('pre-commit', { cwd: repo });
    expect(result.present).toBe(false);
    expect(result.removed).toBe(false);
  });

  it('removes a managed hook and restores the one it replaced', async () => {
    const repo = await makeRepo();
    const hooks = join(repo, '.git', 'hooks');
    await mkdir(hooks, { recursive: true });
    const target = join(hooks, 'pre-push');
    await writeFile(target, '#!/bin/sh\necho mine\n');

    await installHook('pre-push', { cwd: repo });
    const result = await uninstallHook('pre-push', { cwd: repo });

    expect(result.removed).toBe(true);
    expect(result.restored).toBe(target);
    expect(await readFile(target, 'utf8')).toContain('mine');
  });

  it('leaves a foreign hook alone', async () => {
    const repo = await makeRepo();
    const hooks = join(repo, '.git', 'hooks');
    await mkdir(hooks, { recursive: true });
    const target = join(hooks, 'pre-commit');
    await writeFile(target, '#!/bin/sh\necho not ours\n');

    const result = await uninstallHook('pre-commit', { cwd: repo });

    expect(result.present).toBe(true);
    expect(result.removed).toBe(false);
    expect(await readFile(target, 'utf8')).toContain('not ours');
  });
});

describe('pre-commit hook execution', () => {
  it('fails the commit when the staged stellar.toml has findings', async () => {
    const repo = await makeRepo();
    await mkdir(join(repo, '.well-known'), { recursive: true });
    await writeFile(join(repo, '.well-known', 'stellar.toml'), 'VERSION = "1.0.0"\n');
    await git(repo, ['add', '.well-known/stellar.toml']);

    const stub = await stubLinter(repo, 'fail.sh', 'exit 1');
    const { path } = await installHook('pre-commit', { cwd: repo });
    const run = await runHook(path, repo, { env: linterEnv(stub) });

    expect(run.code).toBe(1);
    expect(run.stderr).toContain('commit aborted');
  });

  it('passes a clean staged file', async () => {
    const repo = await makeRepo();
    await mkdir(join(repo, '.well-known'), { recursive: true });
    await writeFile(join(repo, '.well-known', 'stellar.toml'), 'VERSION = "1.0.0"\n');
    await git(repo, ['add', '.well-known/stellar.toml']);

    const stub = await stubLinter(repo, 'ok.sh', 'exit 0');
    const { path } = await installHook('pre-commit', { cwd: repo });
    const run = await runHook(path, repo, { env: linterEnv(stub) });

    expect(run.code).toBe(0);
  });

  it('does not run the linter when no stellar.toml is staged', async () => {
    const repo = await makeRepo();
    await writeFile(join(repo, 'README.md'), '# hi\n');
    await git(repo, ['add', 'README.md']);

    const sentinel = join(repo, 'called');
    const stub = await stubLinter(repo, 'record.sh', `echo called > ${sentinel}\nexit 1`);
    const { path } = await installHook('pre-commit', { cwd: repo });
    const run = await runHook(path, repo, { env: linterEnv(stub) });

    expect(run.code).toBe(0);
    await expect(stat(sentinel)).rejects.toThrow();
  });
});

describe('pre-push hook execution', () => {
  async function repoWithAnchorFile(): Promise<{ repo: string; sha: string }> {
    const repo = await makeRepo();
    await writeFile(join(repo, 'stellar.toml'), 'VERSION = "1.0.0"\n');
    await git(repo, ['add', 'stellar.toml']);
    await git(repo, ['commit', '-q', '-m', 'add anchor file']);
    const sha = await git(repo, ['rev-parse', 'HEAD']);
    return { repo, sha };
  }

  it('aborts the push when a pushed stellar.toml fails', async () => {
    const { repo, sha } = await repoWithAnchorFile();
    const stub = await stubLinter(repo, 'fail.sh', 'exit 1');
    const { path } = await installHook('pre-push', { cwd: repo });

    const run = await runHook(path, repo, {
      stdin: `refs/heads/main ${sha} refs/heads/main ${ZERO}\n`,
      env: linterEnv(stub),
    });

    expect(run.code).toBe(1);
    expect(run.stderr).toContain('push aborted');
  });

  it('allows the push when the range is clean', async () => {
    const { repo, sha } = await repoWithAnchorFile();
    const stub = await stubLinter(repo, 'ok.sh', 'exit 0');
    const { path } = await installHook('pre-push', { cwd: repo });

    const run = await runHook(path, repo, {
      stdin: `refs/heads/main ${sha} refs/heads/main ${ZERO}\n`,
      env: linterEnv(stub),
    });

    expect(run.code).toBe(0);
  });

  it('skips the linter when the pushed range touches no stellar.toml', async () => {
    const repo = await makeRepo();
    await writeFile(join(repo, 'README.md'), '# hi\n');
    await git(repo, ['add', 'README.md']);
    await git(repo, ['commit', '-q', '-m', 'docs only']);
    const sha = await git(repo, ['rev-parse', 'HEAD']);

    const sentinel = join(repo, 'called');
    const stub = await stubLinter(repo, 'record.sh', `echo called > ${sentinel}\nexit 1`);
    const { path } = await installHook('pre-push', { cwd: repo });

    const run = await runHook(path, repo, {
      stdin: `refs/heads/main ${sha} refs/heads/main ${ZERO}\n`,
      env: linterEnv(stub),
    });

    expect(run.code).toBe(0);
    expect(run.stderr).toContain('no stellar.toml');
    await expect(stat(sentinel)).rejects.toThrow();
  });

  it('ignores a deleted branch ref', async () => {
    const { repo } = await repoWithAnchorFile();
    const sentinel = join(repo, 'called');
    const stub = await stubLinter(repo, 'record.sh', `echo called > ${sentinel}\nexit 1`);
    const { path } = await installHook('pre-push', { cwd: repo });

    const run = await runHook(path, repo, {
      stdin: `(delete) ${ZERO} refs/heads/old ${ZERO}\n`,
      env: linterEnv(stub),
    });

    expect(run.code).toBe(0);
    await expect(stat(sentinel)).rejects.toThrow();
  });
});
