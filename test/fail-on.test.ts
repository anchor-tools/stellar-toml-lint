import { describe, expect, it } from 'vitest';
import { execFile } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const run = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, '..', 'dist', 'cli.js');
const fixture = (name: string): string => join(here, 'fixtures', name);

/** Runs the built CLI, capturing the exit code instead of throwing. */
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

const WARNINGS_ONLY = fixture('warnings-only.toml');
const BROKEN = fixture('broken.toml');
const VALID = fixture('valid.toml');

// These exercise the built artifact, so they depend on `npm run build`.
describe('--fail-on', () => {
  it('exits 1 on a warnings-only file at the warning threshold', async () => {
    expect((await cli([WARNINGS_ONLY, '--fail-on', 'warning'])).code).toBe(1);
  });

  it('exits 0 on a warnings-only file at the error threshold', async () => {
    expect((await cli([WARNINGS_ONLY, '--fail-on', 'error'])).code).toBe(0);
  });

  it('exits 1 on a warnings-only file at the info threshold', async () => {
    expect((await cli([WARNINGS_ONLY, '--fail-on', 'info'])).code).toBe(1);
  });

  it('fails on errors at every threshold', async () => {
    for (const severity of ['error', 'warning', 'info']) {
      expect((await cli([BROKEN, '--fail-on', severity])).code).toBe(1);
    }
  });

  it('passes a clean file at every threshold', async () => {
    for (const severity of ['error', 'warning', 'info']) {
      expect((await cli([VALID, '--fail-on', severity])).code).toBe(0);
    }
  });

  it('lets an info-only file pass at the error threshold and fail at info', async () => {
    // Written to a temp directory: test/fixtures is swept by the glob tests,
    // and a new fixture there would change the file counts they assert.
    const dir = await mkdtemp(join(tmpdir(), 'stellar-toml-lint-fail-on-'));
    const file = join(dir, 'stellar.toml');
    await writeFile(
      file,
      [
        'VERSION="2.7.0"',
        'NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"',
        // general/unknown-field, severity info.
        'SUPPORT_SERVER="https://api.example.com/support"',
        '',
        '[DOCUMENTATION]',
        'ORG_NAME="Example Anchor Ltd"',
        'ORG_URL="https://example.com"',
        'ORG_DESCRIPTION="A minimal but valid info file."',
        'ORG_LOGO="https://example.com/logo.png"',
        'ORG_OFFICIAL_EMAIL="partners@example.com"',
        '',
        '[[CURRENCIES]]',
        'code="USDX"',
        'issuer="GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY"',
        'display_decimals=2',
        'is_unlimited=true',
        '',
      ].join('\n'),
    );

    try {
      expect((await cli([file, '--fail-on', 'error'])).code).toBe(0);
      expect((await cli([file, '--fail-on', 'warning'])).code).toBe(0);
      expect((await cli([file, '--fail-on', 'info'])).code).toBe(1);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('takes precedence over --strict', async () => {
    // --strict alone fails this file; the explicit threshold says errors only.
    expect((await cli([WARNINGS_ONLY, '--strict'])).code).toBe(1);
    expect((await cli([WARNINGS_ONLY, '--strict', '--fail-on', 'error'])).code).toBe(0);
    expect((await cli([WARNINGS_ONLY, '--fail-on', 'warning', '--strict'])).code).toBe(1);
  });

  it('combines with --max-warnings rather than replacing it', async () => {
    expect((await cli([WARNINGS_ONLY, '--fail-on', 'error', '--max-warnings', '0'])).code).toBe(1);
    expect((await cli([WARNINGS_ONLY, '--fail-on', 'error', '--max-warnings', '99'])).code).toBe(0);
  });

  it('rejects an unknown severity', async () => {
    const { code, stderr } = await cli([VALID, '--fail-on', 'fatal']);
    expect(code).toBe(2);
    expect(stderr).toContain('Unknown --fail-on severity');
    expect(stderr).toContain('Expected error, warning, or info');
  });

  it('rejects --fail-on without a value', async () => {
    const { code, stderr } = await cli([VALID, '--fail-on']);
    expect(code).toBe(2);
    expect(stderr).toContain('expects a value');
  });

  it('documents the flag in --help', async () => {
    const { stdout } = await cli(['--help']);
    expect(stdout).toContain('--fail-on');
    expect(stdout).toContain('a --fail-on threshold met');
  });
});
