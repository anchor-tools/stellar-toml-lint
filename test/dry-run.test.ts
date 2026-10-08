import { describe, expect, it } from 'vitest';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';

const run = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, '..', 'dist', 'cli.js');

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

describe('--dry-run and --fix CLI flags', () => {
  it('prints unified diff and leaves file on disk unchanged when run with --fix --dry-run', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'stellar-dryrun-'));
    const testFile = join(tempDir, 'stellar.toml');

    const originalContent = `# Stellar TOML with fixable violations
VERSION = "2.0.0"
NETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"
TRANSFER_SERVER = "https://example.com/sep24/"

[DOCUMENTATION]
ORG_NAME = "Example Org"
ORG_URL = "https://example.com"
ORG_PHONE_NUMBER = "(415) 555-2671"
ORG_KEYBASE = "https://keybase.io/stellar"
`;

    try {
      writeFileSync(testFile, originalContent, 'utf8');

      const { code, stdout, stderr } = await cli([testFile, '--fix', '--dry-run']);

      expect(code).toBe(0);
      expect(stderr).toBe('');

      // Unified diff output
      expect(stdout).toContain(`--- a/${testFile}`);
      expect(stdout).toContain(`+++ b/${testFile}`);
      expect(stdout).toContain('-TRANSFER_SERVER = "https://example.com/sep24/"');
      expect(stdout).toContain('+TRANSFER_SERVER = "https://example.com/sep24"');
      expect(stdout).toContain('-ORG_PHONE_NUMBER = "(415) 555-2671"');
      expect(stdout).toContain('+ORG_PHONE_NUMBER = "+4155552671"');
      expect(stdout).toContain('-ORG_KEYBASE = "https://keybase.io/stellar"');
      expect(stdout).toContain('+ORG_KEYBASE = "stellar"');

      // Crucial requirement: file on disk remains completely unchanged
      const contentOnDisk = readFileSync(testFile, 'utf8');
      expect(contentOnDisk).toBe(originalContent);
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('modifies file on disk when run with --fix without --dry-run', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'stellar-fix-'));
    const testFile = join(tempDir, 'stellar.toml');

    const originalContent = `VERSION = "2.0.0"
NETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"
TRANSFER_SERVER = "https://example.com/sep24/"
`;

    try {
      writeFileSync(testFile, originalContent, 'utf8');

      const { code } = await cli([testFile, '--fix']);

      expect(code).toBe(0);

      // File on disk must now be updated with the fix applied
      const updatedContent = readFileSync(testFile, 'utf8');
      expect(updatedContent).not.toBe(originalContent);
      expect(updatedContent).toContain('TRANSFER_SERVER = "https://example.com/sep24"');
      expect(updatedContent).not.toContain('https://example.com/sep24/');
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('emits no diff and exits 0 when --fix --dry-run is run on an already clean file', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'stellar-clean-'));
    const testFile = join(tempDir, 'stellar.toml');

    const cleanContent = `VERSION = "2.0.0"
NETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"
TRANSFER_SERVER = "https://example.com/sep24"
`;

    try {
      writeFileSync(testFile, cleanContent, 'utf8');

      const { code, stdout } = await cli([testFile, '--fix', '--dry-run']);

      expect(code).toBe(0);
      expect(stdout).toBe('');
      expect(readFileSync(testFile, 'utf8')).toBe(cleanContent);
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('leaves file on disk unchanged when run with --migrate --dry-run', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'stellar-migrate-'));
    const testFile = join(tempDir, 'stellar.toml');

    const legacyContent = `VERSION = "2.0.0"
NETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"
FEDERATION_SERVER = "https://api.example.com/federation"

[DOCUMENTATION]
ORG_NAME = "Example Org"
ORG_URL = "https://example.com"
`;

    try {
      writeFileSync(testFile, legacyContent, 'utf8');

      const { stdout } = await cli([testFile, '--migrate', 'sep41', '--dry-run']);

      expect(stdout).toContain(`--- a/${testFile}`);
      expect(stdout).toContain(`+++ b/${testFile}`);

      // File on disk remains unchanged
      expect(readFileSync(testFile, 'utf8')).toBe(legacyContent);
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('documents --dry-run and --fix in --help', async () => {
    const { code, stdout } = await cli(['--help']);
    expect(code).toBe(0);
    expect(stdout).toContain('--dry-run');
    expect(stdout).toContain('--fix');
  });
});
