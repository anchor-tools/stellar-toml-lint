import { afterAll, describe, expect, it } from 'vitest';
import { execFile, spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { loadConfig } from '../src/config.js';

const run = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, '..', 'dist', 'cli.js');

const temps: string[] = [];

afterAll(async () => {
  await Promise.all(temps.map((dir) => rm(dir, { recursive: true, force: true })));
});

async function tempDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'stellartoml-config-'));
  temps.push(dir);
  return dir;
}

/** The valid fixture minus its VERSION line: general/version is its only finding. */
function versionOnlyToml(): string {
  return readFileSync(join(here, 'fixtures', 'valid.toml'), 'utf8').replace(
    /^VERSION="[^"]*"$/m,
    '',
  );
}

async function writeFixture(dir: string, name: string): Promise<string> {
  const path = join(dir, 'stellar.toml');
  await writeFile(path, await readFile(join(here, 'fixtures', name), 'utf8'));
  return path;
}

async function writeConfig(dir: string, value: unknown): Promise<void> {
  const body = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  await writeFile(join(dir, '.stellartomlrc.json'), body);
}

/** Runs the built CLI, capturing the exit code instead of throwing. */
async function cli(
  args: string[],
  cwd?: string,
): Promise<{ code: number; stdout: string; stderr: string }> {
  try {
    const { stdout, stderr } = await run('node', [CLI, ...args], {
      env: { ...process.env, NO_COLOR: '1' },
      ...(cwd === undefined ? {} : { cwd }),
    });
    return { code: 0, stdout, stderr };
  } catch (error) {
    const e = error as { code?: number; stdout?: string; stderr?: string };
    return { code: e.code ?? 1, stdout: e.stdout ?? '', stderr: e.stderr ?? '' };
  }
}

/** Runs the built CLI linting stdin, so config discovery starts at `cwd`. */
function cliStdin(
  cwd: string,
  input: string,
): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn('node', [CLI, '-'], {
      cwd,
      env: { ...process.env, NO_COLOR: '1' },
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });
    child.on('close', (code) => resolve({ code: code ?? 1, stdout, stderr }));
    child.stdin.end(input);
  });
}

describe('loadConfig', () => {
  it('returns an empty config when no file exists above the directory', async () => {
    const nested = join(await tempDir(), 'public', '.well-known');
    await mkdir(nested, { recursive: true });

    expect(await loadConfig(nested)).toEqual({ rules: {}, strict: false });
  });

  it('reads rules, strict, and maxWarnings from the nearest file', async () => {
    const dir = await tempDir();
    await writeConfig(dir, {
      rules: { 'general/version': 'off', 'general/unknown-field': 'error' },
      strict: true,
      maxWarnings: 5,
    });

    const config = await loadConfig(dir);
    expect(config.rules).toEqual({ 'general/version': 'off', 'general/unknown-field': 'error' });
    expect(config.strict).toBe(true);
    expect(config.maxWarnings).toBe(5);
  });

  it('discovers the file by walking up from a nested directory', async () => {
    const dir = await tempDir();
    await writeConfig(dir, { strict: true });
    const nested = join(dir, 'public', '.well-known');
    await mkdir(nested, { recursive: true });

    expect((await loadConfig(nested)).strict).toBe(true);
  });

  it('rejects malformed JSON with a clear message', async () => {
    const dir = await tempDir();
    await writeConfig(dir, '{ "strict": true,, }');

    const error = await loadConfig(dir).then(
      () => undefined,
      (e: Error) => e,
    );
    expect(error).toBeInstanceOf(Error);
    expect(error?.message).toMatch(/Malformed JSON/);
    expect(error?.message).toContain(join(dir, '.stellartomlrc.json'));
  });

  it('rejects an unknown rule id and suggests the closest match', async () => {
    const dir = await tempDir();
    await writeConfig(dir, { rules: { 'general/versionz': 'off' } });

    const error = await loadConfig(dir).then(
      () => undefined,
      (e: Error) => e,
    );
    expect(error?.message).toContain('Unknown rule "general/versionz"');
    expect(error?.message).toMatch(/Did you mean: .*general\/version/);
  });

  it('rejects an invalid severity', async () => {
    const dir = await tempDir();
    await writeConfig(dir, { rules: { 'general/version': 'fatal' } });

    await expect(loadConfig(dir)).rejects.toThrow(/severity/);
  });

  it('rejects unknown top-level fields', async () => {
    const dir = await tempDir();
    await writeConfig(dir, { maxwarning: 3 });

    await expect(loadConfig(dir)).rejects.toThrow(/unknown field/);
  });
});

describe('cli with a config file', () => {
  it('honours a discovered config without any flags', async () => {
    const plain = await tempDir();
    await writeFile(join(plain, 'stellar.toml'), versionOnlyToml());
    const before = await cli([join(plain, 'stellar.toml')]);
    expect(before.code).toBe(0);
    expect(before.stdout).toContain('general/version');

    const configured = await tempDir();
    await writeFile(join(configured, 'stellar.toml'), versionOnlyToml());
    await writeConfig(configured, { rules: { 'general/version': 'off' } });

    const after = await cli([join(configured, 'stellar.toml')]);
    expect(after.code).toBe(0);
    expect(after.stdout).toContain('No SEP-1 issues found');
    expect(after.stdout).not.toContain('general/version');
  });

  it('lets a CLI flag override the config file', async () => {
    const dir = await tempDir();
    await writeFile(join(dir, 'stellar.toml'), versionOnlyToml());
    await writeConfig(dir, { rules: { 'general/version': 'off' } });

    // The config switches the rule off; --error must switch it back on and
    // raise it, which a warning-only file then fails on.
    const result = await cli([join(dir, 'stellar.toml'), '--error', 'general/version']);
    expect(result.code).toBe(1);
    expect(result.stdout).toContain('general/version');
  });

  it('applies strict from the config file', async () => {
    const plain = await tempDir();
    const plainFile = await writeFixture(plain, 'warnings-only.toml');
    expect((await cli([plainFile])).code).toBe(0);

    const dir = await tempDir();
    const file = await writeFixture(dir, 'warnings-only.toml');
    await writeConfig(dir, { strict: true });

    expect((await cli([file])).code).toBe(1);
  });

  it('applies maxWarnings from the config, and --max-warnings wins', async () => {
    const dir = await tempDir();
    const file = await writeFixture(dir, 'warnings-only.toml');
    await writeConfig(dir, { maxWarnings: 0 });

    expect((await cli([file])).code).toBe(1);
    expect((await cli([file, '--max-warnings', '99'])).code).toBe(0);
  });

  it('exits 2 when the config is malformed', async () => {
    const dir = await tempDir();
    const file = await writeFixture(dir, 'warnings-only.toml');
    await writeConfig(dir, '{ "strict": true');

    const result = await cli([file]);
    expect(result.code).toBe(2);
    expect(result.stderr).toContain('Malformed JSON');
  });

  it('exits 2 when the config names an unknown rule', async () => {
    const dir = await tempDir();
    const file = await writeFixture(dir, 'warnings-only.toml');
    await writeConfig(dir, { rules: { 'general/versionz': 'off' } });

    const result = await cli([file]);
    expect(result.code).toBe(2);
    expect(result.stderr).toContain('Unknown rule "general/versionz"');
    expect(result.stderr).toMatch(/Did you mean: .*general\/version/);
  });

  it('discovers config from the current directory when linting stdin', async () => {
    const dir = await tempDir();
    await writeConfig(dir, { rules: { 'general/version': 'off' } });

    const result = await cliStdin(dir, versionOnlyToml());
    expect(result.code).toBe(0);
    expect(result.stdout).toContain('No SEP-1 issues found');
    expect(result.stdout).not.toContain('general/version');
  });
});
