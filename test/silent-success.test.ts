import { describe, expect, it } from 'vitest';
import { execFile, spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const run = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, '..', 'dist', 'cli.js');
const fixture = (name: string): string => join(here, 'fixtures', name);
const VALID_SOURCE = readFileSync(fixture('valid.toml'), 'utf8');

/** Runs the built CLI, capturing the exit code instead of throwing. */
async function cli(
  args: string[],
  input?: string,
): Promise<{ code: number; stdout: string; stderr: string }> {
  if (input !== undefined) {
    return new Promise((resolve) => {
      const child = spawn('node', [CLI, ...args], {
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
      child.on('close', (code) => resolve({ code: code ?? 0, stdout, stderr }));
      child.stdin.end(input);
    });
  }
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

// These exercise the built artifact, so they depend on `npm run build`.
describe('cli --silent-success', () => {
  it('writes nothing to stdout on a clean run and exits 0', async () => {
    const { code, stdout, stderr } = await cli([fixture('valid.toml'), '--silent-success']);

    expect(code).toBe(0);
    expect(stdout).toBe('');
    expect(stderr).toBe('');
  });

  // Spawns the built CLI once per reporter (6 processes); CI runners and
  // loaded machines regularly exceed the 5s default.
  it('is silent on a clean run in every reporter, not just text', async () => {
    for (const format of ['text', 'summary', 'json', 'sarif', 'junit', 'markdown']) {
      const { code, stdout } = await cli([fixture('valid.toml'), '--silent-success', '-f', format]);
      expect(code, format).toBe(0);
      expect(stdout, format).toBe('');
    }
  }, 30_000);

  it('still prints errors and exits 1 on a broken file', async () => {
    const { code, stdout } = await cli([fixture('broken.toml'), '--silent-success']);

    expect(code).toBe(1);
    expect(stdout).toContain('error');
    expect(stdout).toContain('broken.toml');
  });

  it('still prints warnings, which are diagnostics too', async () => {
    // warnings-only.toml has no errors, so the run passes; the warning is still
    // a diagnostic and must not be swallowed by the silent-success flag.
    const { code, stdout } = await cli([fixture('warnings-only.toml'), '--silent-success']);

    expect(code).toBe(0);
    expect(stdout).toContain('warning');
  });

  it('keeps the count line silent only when there is nothing to count', async () => {
    const clean = await cli([fixture('valid.toml'), '--silent-success', '--count']);
    expect(clean.code).toBe(0);
    expect(clean.stdout).toBe('');

    const broken = await cli([fixture('broken.toml'), '--silent-success', '--count']);
    expect(broken.code).toBe(1);
    expect(broken.stdout.trim()).toMatch(/^\d+ problems \(\d+ errors, \d+ warnings\)$/);
  });

  it('skips only the clean files in a multi-file run', async () => {
    const { code, stdout } = await cli([
      fixture('valid.toml'),
      fixture('broken.toml'),
      '--silent-success',
    ]);

    expect(code).toBe(1);
    // The broken file reports as usual; the clean one contributes no output.
    expect(stdout).toContain('broken.toml');
    expect(stdout).not.toContain('valid.toml');
  });

  it('accepts --quiet-success as an alias', async () => {
    const { code, stdout } = await cli([fixture('valid.toml'), '--quiet-success']);
    expect(code).toBe(0);
    expect(stdout).toBe('');
  });

  it('reads stdin and stays silent when the document has no diagnostics', async () => {
    const { code, stdout } = await cli(['-', '--silent-success'], VALID_SOURCE);
    expect(code).toBe(0);
    expect(stdout).toBe('');
  });

  it('documents the flag in --help and the completion scripts', async () => {
    const help = await cli(['--help']);
    expect(help.stdout).toContain('--silent-success');

    for (const shell of ['bash', 'zsh', 'fish']) {
      const { stdout } = await cli(['--completion', shell]);
      expect(stdout, shell).toContain('silent-success');
    }
  });
});
