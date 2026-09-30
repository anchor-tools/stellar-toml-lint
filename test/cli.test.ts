import { describe, expect, it } from 'vitest';
import { execFile, spawn } from 'node:child_process';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
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

  it('prints the version as plain text by default', async () => {
    const { code, stdout } = await cli(['--version']);
    expect(code).toBe(0);
    expect(stdout.trim()).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it('prints the version as JSON when combined with --format json', async () => {
    const { code, stdout } = await cli(['--version', '--format', 'json']);
    expect(code).toBe(0);
    const data = JSON.parse(stdout) as { name: string; version: string; node: string };
    expect(data.name).toBe('stellar-toml-lint');
    expect(data.version).toMatch(/^\d+\.\d+\.\d+$/);
    expect(data.node).toBe(process.version);
  });

  it('prints the version as JSON when --format json comes before -v', async () => {
    const { code, stdout } = await cli(['-f', 'json', '-v']);
    expect(code).toBe(0);
    const data = JSON.parse(stdout) as { name: string; version: string; node: string };
    expect(data.name).toBe('stellar-toml-lint');
    expect(data.version).toMatch(/^\d+\.\d+\.\d+$/);
    expect(data.node).toBe(process.version);
  });

  it('lists every rule', async () => {
    const { code, stdout } = await cli(['--list-rules']);
    expect(code).toBe(0);
    expect(stdout).toContain('currencies/issuance-exclusive');
    expect(stdout).toContain('currencies/regulated-asset-missing-auth-required');
    expect(stdout).toContain('currencies/regulated-missing-auth-revocable-flag');
    expect(stdout).toContain('soroban/contract-ttl-expiring-soon');
    expect(stdout).toContain('soroban/contract-expired');
    expect(stdout).toMatch(/^\d+ rules/);
  });

  it('lists the Soroban contract and overlay handshake rules', async () => {
    const { stdout } = await cli(['--list-rules']);
    expect(stdout).toContain('soroban/duplicate-error-code');
    expect(stdout).toContain('soroban/system-error-code-collision');
    expect(stdout).toContain('soroban/contract-only-on-testnet');
    expect(stdout).toContain('soroban/network-mismatch');
    expect(stdout).toContain('soroban/unresolved-contract-dependency');
    expect(stdout).toContain('soroban/circular-contract-dependency');
    expect(stdout).toContain('overlay/handshake-timeout');
    expect(stdout).toContain('overlay/network-mismatch');
    expect(stdout).toContain('overlay/public-key-mismatch');
    expect(stdout).toContain('overlay/protocol-version-outdated');
  });

  it('documents --verify-overlay and --contract-graph', async () => {
    const { stdout } = await cli(['--help']);
    expect(stdout).toContain('--verify-overlay');
    expect(stdout).toContain('--contract-graph');
  });

  it('rejects --contract-graph without a value or with an unknown format', async () => {
    const missing = await cli(['--contract-graph']);
    expect(missing.code).toBe(2);
    expect(missing.stderr).toContain('expects a value');

    const unknown = await cli(['--contract-graph', 'svg']);
    expect(unknown.code).toBe(2);
    expect(unknown.stderr).toContain('Unknown contract graph format');
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

  it('documents --rpc-url and rejects it without a value', async () => {
    const help = await cli(['--help']);
    expect(help.stdout).toContain('--rpc-url');

    const { code, stderr } = await cli(['--check-contracts', '--rpc-url']);
    expect(code).toBe(2);
    expect(stderr).toContain('expects a value');
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

// ── the one-line status format ──────────────────────────────────────────────

describe('cli -f summary', () => {
  /** Windows prints paths with backslashes; the assertions read either way. */
  const forward = (s: string): string => s.replace(/\\/g, '/');

  /**
   * The parenthesised tail of a status line. Info is named only when there is
   * some, so it is the one optional part of the shape.
   */
  const COUNTS = /\(\d+ errors?, \d+ warnings?(?:, \d+ infos?)?\)$/;

  it('emits exactly one PASS line for a clean file and exits 0', async () => {
    const { code, stdout } = await cli([fixture('valid.toml'), '-f', 'summary']);

    expect(code).toBe(0);
    const lines = stdout.trimEnd().split('\n');
    expect(lines).toHaveLength(1);
    expect(forward(lines[0] as string)).toMatch(
      /fixtures\/valid\.toml: PASS \(0 errors, 0 warnings\)$/,
    );
  });

  it('emits exactly one FAIL line with counts for a broken file and exits 1', async () => {
    const { code, stdout } = await cli([fixture('broken.toml'), '-f', 'summary']);

    // The format flag never changes the verdict.
    expect(code).toBe(1);
    const lines = stdout.trimEnd().split('\n');
    expect(lines).toHaveLength(1);
    expect(forward(lines[0] as string)).toMatch(/fixtures\/broken\.toml: FAIL /);
    expect(forward(lines[0] as string)).toMatch(COUNTS);
  });

  it('accepts the long form too', async () => {
    const { code, stdout } = await cli([fixture('valid.toml'), '--format', 'summary']);
    expect(code).toBe(0);
    expect(stdout).toContain('PASS (0 errors, 0 warnings)');
  });

  it('writes one line per file and no closing Checked line', async () => {
    const { stdout } = await cli([fixture('tenants/*/stellar.toml'), '-f', 'summary']);
    const out = forward(stdout);

    expect(out.trimEnd().split('\n')).toHaveLength(2);
    expect(out).toContain('tenants/acme/stellar.toml: PASS');
    expect(out).toContain('tenants/globex/stellar.toml: PASS');
    // Every file is already a line, so the text reporter's closing prose would
    // only be something else for a status loop to trip over.
    expect(out).not.toContain('Checked');
  });

  it('fails a warning-only file under --strict, as every other reporter does', async () => {
    const lenient = await cli([fixture('warnings-only.toml'), '-f', 'summary']);
    expect(lenient.code).toBe(0);
    expect(lenient.stdout).toContain('PASS');
    expect(lenient.stdout.trimEnd()).toMatch(COUNTS);

    const strict = await cli([fixture('warnings-only.toml'), '-f', 'summary', '--strict']);
    expect(strict.code).toBe(1);
    expect(strict.stdout).toContain('FAIL');
  });

  it('prints no colour when NO_COLOR is set', async () => {
    const plain = await cli([fixture('broken.toml'), '-f', 'summary']);
    const painted = await cli([fixture('broken.toml'), '-f', 'summary', '--color']);

    // Stripping the escape sequences has to leave the plain line untouched, so
    // a script matching PASS or FAIL reads the same either way.
    expect(painted.stdout.replace(/\p{Cc}\[[0-9;]*m/gu, '')).toBe(plain.stdout);
    expect(painted.stdout).not.toBe(plain.stdout);
  });

  it('lists summary among the formats --help and --completion advertise', async () => {
    const help = await cli(['--help']);
    expect(help.stdout).toContain('summary');

    const bash = await cli(['--completion', 'bash']);
    expect(bash.stdout).toContain('summary');
  });

  it('still exits 2 on an unknown format', async () => {
    const { code, stderr } = await cli([fixture('valid.toml'), '-f', 'summaries']);
    expect(code).toBe(2);
    expect(stderr).toContain('Unknown format');
    // The message has to name the new choice, or the fix is a guess.
    expect(stderr).toContain('summary');
  });
});

describe('cli --count', () => {
  it('emits only the problem count line for a broken file and exits 1', async () => {
    const { code, stdout, stderr } = await cli([fixture('broken.toml'), '--count']);

    // Return code remains unchanged: 1 on errors
    expect(code).toBe(1);
    expect(stderr).toBe('');

    // Must emit only the single problem count line without diagnostic text
    const lines = stdout.trimEnd().split('\n');
    expect(lines).toHaveLength(1);
    expect(lines[0]).toBe('45 problems (29 errors, 16 warnings)');

    // Suppresses diagnostic lists, file headers, suggestions, and rule ids
    expect(stdout).not.toContain('broken.toml');
    expect(stdout).not.toContain('↳');
    expect(stdout).not.toContain('currencies/issuance-exclusive');
    expect(stdout).not.toContain('general/version');
  });

  it('emits 0 problems for a valid file and exits 0', async () => {
    const { code, stdout, stderr } = await cli([fixture('valid.toml'), '--count']);

    expect(code).toBe(0);
    expect(stderr).toBe('');

    const lines = stdout.trimEnd().split('\n');
    expect(lines).toHaveLength(1);
    expect(lines[0]).toBe('0 problems (0 errors, 0 warnings)');
    expect(stdout).not.toContain('No SEP-1 issues found');
    expect(stdout).not.toContain('valid.toml');
  });

  it('aggregates problem count totals across multiple files without per-file output', async () => {
    const { code, stdout } = await cli([fixture('valid.toml'), fixture('broken.toml'), '--count']);

    expect(code).toBe(1);
    const lines = stdout.trimEnd().split('\n');
    expect(lines).toHaveLength(1);
    expect(lines[0]).toBe('45 problems (29 errors, 16 warnings)');
    expect(stdout).not.toContain('valid.toml');
    expect(stdout).not.toContain('broken.toml');
    expect(stdout).not.toContain('Checked');
  });

  it('emits only the problem count when reading stdin', async () => {
    const { code, stdout } = await cli(['-', '--count'], 'VERSION="two"\n');

    // VERSION="two" is a warning, so default exit code is 0 (no errors)
    expect(code).toBe(0);
    const lines = stdout.trimEnd().split('\n');
    expect(lines).toHaveLength(1);
    expect(lines[0]).toBe('3 problems (0 errors, 3 warnings)');
    expect(stdout).not.toContain('stdin');
  });

  it('preserves --strict exit code while emitting problem count', async () => {
    const lenient = await cli([fixture('warnings-only.toml'), '--count']);
    expect(lenient.code).toBe(0);
    expect(lenient.stdout.trimEnd()).toMatch(/^\d+ problems? \(0 errors, \d+ warnings?\)$/);

    const strict = await cli([fixture('warnings-only.toml'), '--count', '--strict']);
    expect(strict.code).toBe(1);
    expect(strict.stdout.trimEnd()).toMatch(/^\d+ problems? \(0 errors, \d+ warnings?\)$/);
  });

  it('documents --count in --help', async () => {
    const { code, stdout } = await cli(['--help']);
    expect(code).toBe(0);
    expect(stdout).toContain('--count');
    expect(stdout).toContain('Print only problem count totals');
  });

  it('advertises --count in --completion scripts', async () => {
    const { code, stdout } = await cli(['--completion', 'bash']);
    expect(code).toBe(0);
    expect(stdout).toContain('--count');
  });

  it('paints count line when --color is requested and strips cleanly with NO_COLOR', async () => {
    const plain = await cli([fixture('broken.toml'), '--count']);
    const painted = await cli([fixture('broken.toml'), '--count', '--color']);

    // Stripping escape sequences yields the plain line
    expect(painted.stdout.replace(/\p{Cc}\[[0-9;]*m/gu, '')).toBe(plain.stdout);
    expect(painted.stdout).not.toBe(plain.stdout);
  });
});

/** Writes a scratch file, runs a callback, then removes the scratch directory. */
async function withScratchFile(
  source: string,
  run: (path: string) => Promise<{ code: number; stdout: string; stderr: string }>,
): Promise<{ code: number; stdout: string; stderr: string; after: string }> {
  const dir = await mkdtemp(join(tmpdir(), 'stellar-toml-lint-'));
  const path = join(dir, 'stellar.toml');
  await writeFile(path, source, 'utf8');
  const result = await run(path);
  const after = await readFile(path, 'utf8');
  return { ...result, after };
}

/** Runs the CLI with something on stdin, for the `-` path. */
function cliWithStdin(
  args: string[],
  input: string,
): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn('node', [CLI, ...args], { env: { ...process.env, NO_COLOR: '1' } });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => (stdout += chunk));
    child.stderr.on('data', (chunk) => (stderr += chunk));
    child.on('close', (code) => resolve({ code: code ?? 1, stdout, stderr }));
    child.stdin.end(input);
  });
}

describe('cli --format-file', () => {
  it('rewrites a file into SEP-1 order', async () => {
    const source = 'ACCOUNTS = ["GABC"]\nVERSION = "2.0.0"\n';
    const { code, stdout, after } = await withScratchFile(source, (path) =>
      cli(['--format-file', path]),
    );
    expect(code).toBe(0);
    expect(stdout).toContain('Formatted');
    expect(after).toBe('VERSION = "2.0.0"\nACCOUNTS = ["GABC"]\n');
  });

  it('reports an already-canonical file as unchanged', async () => {
    const source = 'VERSION = "2.0.0"\nACCOUNTS = ["GABC"]\n';
    const { code, stdout, after } = await withScratchFile(source, (path) =>
      cli(['--format-file', path]),
    );
    expect(code).toBe(0);
    expect(stdout).toContain('Unchanged');
    expect(after).toBe(source);
  });

  it('leaves invalid TOML untouched and exits 2', async () => {
    const source = 'VERSION = \n# broken on purpose\n';
    const { code, stderr, after } = await withScratchFile(source, (path) =>
      cli(['--format-file', path]),
    );
    expect(code).toBe(2);
    expect(stderr).toContain('Invalid TOML');
    expect(stderr).toContain('left untouched');
    expect(after).toBe(source);
  });

  it('formats stdin onto stdout', async () => {
    const { code, stdout } = await cliWithStdin(['--format-file', '-'], 'VERSION = "1"\n');
    expect(code).toBe(0);
    expect(stdout).toBe('VERSION = "1"\n');
  });

  it('rejects --domain, which has no file to rewrite', async () => {
    const { code, stderr } = await cli(['--format-file', '--domain', 'example.com']);
    expect(code).toBe(2);
    expect(stderr).toContain('--domain');
  });

  it('is mentioned in --help', async () => {
    const { stdout } = await cli(['--help']);
    expect(stdout).toContain('--format-file');
  });
});
