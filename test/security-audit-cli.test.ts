import { afterAll, describe, expect, it } from 'vitest';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { StrKey } from '@stellar/stellar-base';

const run = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, '..', 'dist', 'cli.js');
const dir = await mkdtemp(join(tmpdir(), 'stellar-security-cli-'));

afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

async function cli(args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
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

describe('security audit CLI integration', () => {
  it('documents the new flags and subcommand', async () => {
    const { stdout } = await cli(['--help']);
    expect(stdout).toContain('--audit-dns-takeover');
    expect(stdout).toContain('--audit-secrets');
    expect(stdout).toContain('--audit-ssrf');
    expect(stdout).toContain('refactor <file>');
  });

  it('lists and accepts the new rule ids', async () => {
    const listed = await cli(['--list-rules']);
    expect(listed.stdout).toContain('security/dns-takeover-cname');
    expect(listed.stdout).toContain('security/secret-stellar-seed');
    expect(listed.stdout).toContain('security/ssrf-private-ip');

    const fixture = join(here, 'fixtures', 'valid.toml');
    expect((await cli([fixture, '--off', 'security/secret-stellar-seed'])).code).toBe(0);
  });

  it('halts with exit 1 and masked output on a leaked seed', async () => {
    const seed = StrKey.encodeEd25519SecretSeed(Buffer.alloc(32, 9));
    const file = join(dir, 'leak.toml');
    await writeFile(file, `VERSION = "2"\nSIGNING_KEY = "${seed}"\n`, 'utf8');
    const { code, stdout, stderr } = await cli([file, '--audit-secrets', '-f', 'json']);
    expect(code).toBe(1);
    expect(stdout).toBe('');
    expect(stderr).toContain('CREDENTIALS DETECTED');
    expect(stderr).toContain('...');
    expect(stderr).not.toContain(seed);
  });

  it('deduplicates assets through the refactor subcommand', async () => {
    const file = join(dir, 'dup.toml');
    await writeFile(
      file,
      [
        '[[CURRENCIES]]',
        'code = "USD"',
        'issuer = "GABC"',
        'name = "Dollar"',
        '',
        '[[CURRENCIES]]',
        'code = "USD"',
        'issuer = "GABC"',
        'display_decimals = 2',
        '',
      ].join('\n'),
      'utf8',
    );
    const { code, stdout, stderr } = await cli(['refactor', file]);
    expect(code).toBe(0);
    expect(stdout).toContain('-[[CURRENCIES]]');
    expect(stderr).toContain('Duplicates removed: 1');
    expect(stderr).toContain('Validation: passed');
  });

  it('rejects a refactor invocation without a file', async () => {
    const { code, stderr } = await cli(['refactor']);
    expect(code).toBe(2);
    expect(stderr).toContain('Usage:');
  });
});
