import { describe, expect, it } from 'vitest';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { XMLValidator } from 'fast-xml-parser';

const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, '..', 'dist', 'cli.js');
const fixture = (name: string): string => join(here, 'fixtures', name);

/** Runs the built CLI, capturing the exit code instead of throwing. */
function cli(
  args: string[],
  input?: string,
): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn('node', [CLI, ...args], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, NO_COLOR: '1' },
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => (stdout += chunk));
    child.stderr.on('data', (chunk) => (stderr += chunk));
    child.on('close', (code) => resolve({ code: code ?? 1, stdout, stderr }));
    if (input !== undefined) child.stdin.write(input);
    child.stdin.end();
  });
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

  it('serves network checks from --mock-fixtures', async () => {
    const { code, stdout } = await cli([
      fixture('network/offline-anchor.toml'),
      '--check-network',
      '--mock-fixtures',
      fixture('network'),
      '-f',
      'json',
    ]);

    expect(code).toBe(0);
    const rules = JSON.parse(stdout).diagnostics.map((d: { rule: string }) => d.rule);
    expect(rules.filter((rule: string) => rule.startsWith('network/'))).toEqual([]);
  });

  it('rejects a --mock-fixtures directory that does not exist', async () => {
    const { code, stderr } = await cli([
      fixture('network/offline-anchor.toml'),
      '--check-network',
      '--mock-fixtures',
      './definitely-not-here',
    ]);
    expect(code).toBe(2);
    expect(stderr).toContain('--mock-fixtures directory');
  });
});

describe('cli --json-schema', () => {
  it('exits 0 and emits a JSON schema to stdout', async () => {
    const { code, stdout } = await cli(['--json-schema']);
    expect(code).toBe(0);

    const schema = JSON.parse(stdout) as Record<string, unknown>;
    expect(schema.$schema).toBe('https://json-schema.org/draft/2020-12/schema');
    expect(schema.type).toBe('object');

    const properties = schema.properties as Record<string, unknown>;
    for (const section of ['DOCUMENTATION', 'PRINCIPALS', 'CURRENCIES', 'VALIDATORS']) {
      expect(properties[section], `missing ${section}`).toBeDefined();
    }
  });
});

// ── globs and the multi-file summary ───────────────────────────────────────

describe('glob patterns and multi-file summaries', () => {
  /** Windows prints paths with backslashes; the assertions read either way. */
  const forward = (s: string): string => s.replace(/\\/g, '/');

  it('expands a quoted glob to every file it matches', async () => {
    const { code, stdout } = await cli([fixture('tenants/*/stellar.toml')]);
    const out = forward(stdout);

    expect(code).toBe(0);
    expect(out).toContain('tenants/acme/stellar.toml');
    expect(out).toContain('tenants/globex/stellar.toml');
    expect(out).toContain('Checked 2 files: 2 passed, 0 failed (0 errors, 0 warnings)');
  });

  it('expands a recursive glob across directories', async () => {
    const { stdout } = await cli([fixture('**/*.toml')]);
    expect(stdout).toMatch(/Checked \d+ files: \d+ passed, 1 failed/);
  });

  it('exits 1 when one file fails and the others pass', async () => {
    const { code, stdout } = await cli([fixture('*.toml')]);

    expect(code).toBe(1);
    expect(stdout).toContain('Checked 3 files: 2 passed, 1 failed');
    // Per-file reporting is still there — the summary only appends to it.
    expect(stdout).toContain('broken.toml');
    expect(stdout).toContain('No SEP-1 issues found');
  });

  it('exits 0 when every file passes', async () => {
    const { code, stdout } = await cli([fixture('tenants/*/*.toml')]);

    expect(code).toBe(0);
    expect(stdout).toContain('Checked 2 files: 2 passed, 0 failed');
  });

  it('keeps single-file output free of the summary', async () => {
    const { stdout } = await cli([fixture('valid.toml')]);
    expect(stdout).not.toContain('Checked');
  });

  it('keeps machine-readable formats machine-readable', async () => {
    const { stdout } = await cli([fixture('tenants/*/*.toml'), '-f', 'json']);

    // The summary belongs to the text reporter; prose appended to JSON, SARIF,
    // or XML would break the parser it exists for.
    expect(stdout).not.toContain('Checked');
    expect(stdout).not.toContain('passed');
  });

  it('exits 2 with a clear message when a glob matches nothing', async () => {
    const { code, stderr } = await cli([fixture('no-such-*.toml')]);

    expect(code).toBe(2);
    expect(stderr).toContain('No files matched');
    expect(stderr).toContain('no-such-*.toml');
    expect(stderr).toContain('quote the pattern');
  });
});

describe('cli --completion', () => {
  it('prints a bash completion script and exits 0', async () => {
    const { code, stdout } = await cli(['--completion', 'bash']);
    expect(code).toBe(0);
    expect(stdout).toContain('complete -F _stellar_toml_lint');
    expect(stdout).toContain('--check-contracts');
  });

  it('prints a zsh completion script and exits 0', async () => {
    const { code, stdout } = await cli(['--completion', 'zsh']);
    expect(code).toBe(0);
    expect(stdout).toContain('#compdef stellar-toml-lint');
  });

  it('exits 2 for an unsupported shell', async () => {
    const { code, stderr } = await cli(['--completion', 'unknown']);
    expect(code).toBe(2);
    expect(stderr).toContain('Unknown shell');
  });

  it('exits 2 when --completion has no value', async () => {
    const { code, stderr } = await cli(['--completion']);
    expect(code).toBe(2);
    expect(stderr).toContain('expects a value');
  });
});

describe('cli -f markdown', () => {
  it('emits a step-summary table for a broken file and still exits 1', async () => {
    const { code, stdout } = await cli([fixture('broken.toml'), '-f', 'markdown']);
    expect(code).toBe(1);
    expect(stdout).toContain('### ❌ Failed');
    expect(stdout).toContain('| Location | Severity | Rule | Message |');
    expect(stdout).toContain('<details>');
  });

  it('emits a green pass header for a clean file', async () => {
    const { code, stdout } = await cli([fixture('valid.toml'), '-f', 'markdown']);
    expect(code).toBe(0);
    expect(stdout).toContain('No SEP-1 issues found');
  });
});
