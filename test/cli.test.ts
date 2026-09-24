import { describe, expect, it } from 'vitest';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { XMLValidator } from 'fast-xml-parser';

const run = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, '..', 'dist', 'cli.js');
const fixture = (name: string): string => join(here, 'fixtures', name);

/** Runs the built CLI, capturing the exit code instead of throwing. */
async function cli(
  args: string[],
  input?: string,
): Promise<{ code: number; stdout: string; stderr: string }> {
  try {
    const { stdout, stderr } = await run('node', [CLI, ...args], {
      env: { ...process.env, NO_COLOR: '1' },
      ...(input !== undefined ? {} : {}),
    });
    return { code: 0, stdout, stderr };
  } catch (error) {
    const e = error as { code?: number; stdout?: string; stderr?: string };
    return { code: e.code ?? 1, stdout: e.stdout ?? '', stderr: e.stderr ?? '' };
  }
}

// These exercise the built artifact, so they depend on `npm run build`.
describe('cli', () => {
  it('exits 0 on a valid file', async () => {
    const { code, stdout } = await cli([fixture('valid.toml')]);
    expect(code).toBe(0);
    expect(stdout).toContain('No SEP-1 issues found');
  });

  it('exits 1 on a broken file', async () => {
    const { code, stdout } = await cli([fixture('broken.toml')]);
    expect(code).toBe(1);
    expect(stdout).toContain('error');
  });

  it('exits 2 when the file does not exist', async () => {
    const { code, stderr } = await cli(['./definitely-not-here.toml']);
    expect(code).toBe(2);
    expect(stderr).toContain('Could not find');
  });

  it('exits 2 on an unknown option', async () => {
    const { code, stderr } = await cli(['--nonsense']);
    expect(code).toBe(2);
    expect(stderr).toContain('Unknown option');
  });

  it('rejects an unknown rule id and suggests alternatives', async () => {
    const { code, stderr } = await cli(['--off', 'general/versionz']);
    expect(code).toBe(2);
    expect(stderr).toContain('Unknown rule');
  });

  it('prints usage for --help', async () => {
    const { code, stdout } = await cli(['--help']);
    expect(code).toBe(0);
    expect(stdout).toContain('USAGE');
    expect(stdout).toContain('EXIT CODES');
    expect(stdout).toContain('--check-contracts');
    expect(stdout).toContain('--soroban-rpc');
    expect(stdout).toContain('checkstyle');
  });

  it('prints the version', async () => {
    const { code, stdout } = await cli(['--version']);
    expect(code).toBe(0);
    expect(stdout.trim()).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it('lists every rule', async () => {
    const { code, stdout } = await cli(['--list-rules']);
    expect(code).toBe(0);
    expect(stdout).toContain('currencies/issuance-exclusive');
    expect(stdout).toContain('currencies/regulated-missing-auth-required-flag');
    expect(stdout).toContain('currencies/regulated-missing-auth-revocable-flag');
    expect(stdout).toContain('soroban/contract-ttl-expiring-soon');
    expect(stdout).toContain('soroban/contract-expired');
    expect(stdout).toMatch(/^\d+ rules/);
  });

  it('accepts severity overrides on the network-bound rules', async () => {
    const accepted = await cli([
      fixture('valid.toml'),
      '--off',
      'soroban/contract-expired',
      '--error',
      'currencies/regulated-missing-auth-revocable-flag',
    ]);
    expect(accepted.code).toBe(0);
  });

  it('rejects --soroban-rpc without a value', async () => {
    const { code, stderr } = await cli(['--check-contracts', '--soroban-rpc']);
    expect(code).toBe(2);
    expect(stderr).toContain('expects a value');
  });

  it('emits parseable JSON', async () => {
    const { stdout } = await cli([fixture('broken.toml'), '-f', 'json']);
    expect(() => JSON.parse(stdout)).not.toThrow();
  });

  it('emits parseable SARIF', async () => {
    const { stdout } = await cli([fixture('broken.toml'), '-f', 'sarif']);
    expect(JSON.parse(stdout).version).toBe('2.1.0');
  });

  it('emits parseable JUnit XML', async () => {
    const { stdout } = await cli([fixture('broken.toml'), '-f', 'junit']);
    expect(XMLValidator.validate(stdout)).toBe(true);
    expect(stdout).toContain('<testsuites');
    expect(stdout).toContain('<failure');
  });

  it('emits parseable Checkstyle XML', async () => {
    const { stdout, code } = await cli([fixture('broken.toml'), '-f', 'checkstyle']);
    expect(XMLValidator.validate(stdout)).toBe(true);
    expect(stdout).toContain('<checkstyle');
    expect(stdout).toContain('<file name=');
    expect(stdout).toContain('severity="error"');
    expect(stdout).toContain('source="');
    // The format flag never changes the verdict: broken file still exits 1.
    expect(code).toBe(1);
  });

  it('honours --off', async () => {
    const { stdout } = await cli([
      fixture('broken.toml'),
      '-f',
      'json',
      '--off',
      'general/version',
    ]);
    const rules = JSON.parse(stdout).diagnostics.map((d: { rule: string }) => d.rule);
    expect(rules).not.toContain('general/version');
  });

  it('fails a warning-only file under --strict', async () => {
    const clean = await cli([fixture('valid.toml'), '--strict']);
    expect(clean.code).toBe(0);

    // display_decimals warning only — no errors.
    const warned = await cli([fixture('warnings-only.toml')]);
    expect(warned.code).toBe(0);

    const strict = await cli([fixture('warnings-only.toml'), '--strict']);
    expect(strict.code).toBe(1);
  });

  it('honours --max-warnings', async () => {
    const under = await cli([fixture('warnings-only.toml'), '--max-warnings', '99']);
    expect(under.code).toBe(0);

    const over = await cli([fixture('warnings-only.toml'), '--max-warnings', '0']);
    expect(over.code).toBe(1);
  });

  it('shows only errors under --quiet', async () => {
    const { stdout } = await cli([fixture('broken.toml'), '--quiet', '-f', 'json']);
    const severities = JSON.parse(stdout).diagnostics.map((d: { severity: string }) => d.severity);
    expect(new Set(severities)).toEqual(new Set(['error']));
  });
});
