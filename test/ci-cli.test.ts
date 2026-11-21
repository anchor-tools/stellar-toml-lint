import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { parseDocument } from 'yaml';
import { validateWorkflow } from '../src/gitops/ciWorkflowGenerator.js';
import { validateSarif } from '../src/gitops/ciSarif.js';
import {
  PUBLIC_NETWORK_PASSPHRASE,
  TESTNET_NETWORK_PASSPHRASE,
} from '../src/gitops/ciEnvironments.js';

const run = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, '..', 'dist', 'cli.js');
const VALID = join(here, 'fixtures', 'valid.toml');

let cwd: string;
beforeEach(async () => {
  cwd = await mkdtemp(join(tmpdir(), 'stl-ci-cli-'));
});
afterEach(async () => {
  await rm(cwd, { recursive: true, force: true });
});

async function cli(
  args: string[],
  env: NodeJS.ProcessEnv = {},
): Promise<{ code: number; stdout: string; stderr: string }> {
  try {
    const { stdout, stderr } = await run('node', [CLI, ...args], {
      cwd,
      env: { ...process.env, NO_COLOR: '1', GITHUB_OUTPUT: '', ...env },
    });
    return { code: 0, stdout, stderr };
  } catch (error) {
    const failure = error as { code?: number; stdout?: string; stderr?: string };
    return { code: failure.code ?? 1, stdout: failure.stdout ?? '', stderr: failure.stderr ?? '' };
  }
}

async function tenant(env: string, passphrase: string): Promise<string> {
  const source = (await readFile(VALID, 'utf8')).replace(PUBLIC_NETWORK_PASSPHRASE, passphrase);
  const file = `environments/${env}/stellar.toml`;
  await mkdir(join(cwd, dirname(file)), { recursive: true });
  await writeFile(join(cwd, file), source);
  return file;
}

// Every case spawns the built CLI; allow for loaded runners.
describe('init-ci', { timeout: 30_000 }, () => {
  it('writes a valid workflow for the requested matrix and refuses to overwrite it', async () => {
    const first = await cli(['init-ci', '--matrix', 'testnet,public']);
    expect(first).toMatchObject({ code: 0, stderr: '' });
    expect(first.stdout).toContain('Wrote .github/workflows/stellar-toml-lint-matrix.yml');
    expect(first.stdout).toContain('testnet: environments/testnet/stellar.toml');

    const yaml = await readFile(
      join(cwd, '.github/workflows/stellar-toml-lint-matrix.yml'),
      'utf8',
    );
    const doc = parseDocument(yaml);
    expect(doc.errors).toEqual([]);
    const workflow = doc.toJS();
    expect(validateWorkflow(workflow)).toEqual([]);
    expect(workflow.jobs.validate.strategy.matrix.environment).toEqual(['testnet', 'public']);

    const again = await cli(['init-ci']);
    expect(again.code).toBe(1);
    expect(again.stderr).toContain('already exists; pass --force to overwrite');

    const forced = await cli(['init-ci', '--matrix', 'dev', '--force']);
    expect(forced.code).toBe(0);
    const rewritten = await readFile(
      join(cwd, '.github/workflows/stellar-toml-lint-matrix.yml'),
      'utf8',
    );
    expect(rewritten).toContain('- development');
  });

  it('prints to stdout with every option applied', async () => {
    const { code, stdout } = await cli([
      'init-ci',
      '--matrix',
      'staging,prod',
      '--node',
      '22, 24',
      '--file-pattern',
      'tenants/{environment}.toml',
      '--file',
      'prod=public/.well-known/stellar.toml',
      '-o',
      '.github/workflows/anchors.yml',
      '--check-network',
      '--strict',
      '--no-sarif',
      '--no-pr-comment',
      '--no-cache',
      '--stdout',
    ]);
    expect(code).toBe(0);
    const workflow = parseDocument(stdout).toJS();
    expect(validateWorkflow(workflow)).toEqual([]);
    expect(workflow.jobs.validate.strategy.matrix).toEqual({
      environment: ['staging', 'public'],
      node: ['22', '24'],
      include: [
        { environment: 'staging', file: 'tenants/staging.toml', 'check-network': true },
        { environment: 'public', file: 'public/.well-known/stellar.toml', 'check-network': true },
      ],
    });
    expect(workflow.on.push.paths).toContain('.github/workflows/anchors.yml');
    expect(Object.keys(workflow.jobs)).toEqual(['validate']);
    expect(stdout).not.toContain('actions/cache@');
    expect(stdout).toContain('STRICT: "true"');
    await expect(readdir(cwd)).resolves.toEqual([]);

    const offline = await cli(['init-ci', '--no-check-network', '--stdout']);
    expect(parseDocument(offline.stdout).toJS().jobs.validate.strategy.matrix.include).toEqual([
      { environment: 'testnet', file: 'environments/testnet/stellar.toml', 'check-network': false },
      { environment: 'public', file: 'environments/public/stellar.toml', 'check-network': false },
    ]);
  });

  it.each([
    [['--matrix', 'moon'], 'Unknown environment "moon"'],
    [['--matrix'], '--matrix expects a value.'],
    [['--file', 'nonsense'], '--file expects <environment>=<path>'],
    [['--file', 'moon=x.toml'], '--file expects <environment>=<path>'],
    [['--file', 'staging=x.toml'], '--file names "staging", which is not in --matrix'],
    [['--node', '16'], 'requires Node.js 20 or newer'],
    [['--file-pattern', '../{environment}.toml'], 'Unsafe file'],
    [['--bogus'], 'Unknown option "--bogus" for init-ci'],
  ])('exits 2 on bad usage %#', async (args, error) => {
    const result = await cli(['init-ci', ...args]);
    expect(result.code).toBe(2);
    expect(result.stderr).toContain(error);
  });

  it('reports filesystem errors with exit code 2', async () => {
    await writeFile(join(cwd, '.github'), 'not a directory');
    const result = await cli(['init-ci']);
    expect(result.code).toBe(2);
    expect(result.stderr).not.toBe('');
  });

  it('prints help', async () => {
    const result = await cli(['init-ci', '--help']);
    expect(result.code).toBe(0);
    expect(result.stdout).toContain('init-ci OPTIONS');
    expect(result.stdout).toContain('STELLAR_TOML_LINT_ASSET_CACHE');
  });
});

describe('ci-report and ci-scorecard', { timeout: 30_000 }, () => {
  it('runs a full matrix cell and aggregates the PR comment', async () => {
    const testnet = await tenant('testnet', PUBLIC_NETWORK_PASSPHRASE);
    const production = await tenant('public', PUBLIC_NETWORK_PASSPHRASE);
    const output = join(cwd, 'github-output');
    await writeFile(output, '');

    for (const [env, file] of [
      ['testnet', testnet],
      ['public', production],
    ] as const) {
      const lint = await cli([file, '--format', 'json']);
      await writeFile(join(cwd, `lint-${env}.json`), lint.stdout);
      const report = await cli(
        [
          'ci-report',
          '--environment',
          env,
          '--file',
          file,
          '--node',
          '20',
          '--lint-json',
          `lint-${env}.json`,
          '--lint-exit-code',
          String(lint.code),
          '--out-dir',
          `artifacts/stellar-toml-lint-${env}`,
          '--check-network',
          '--strict',
        ],
        { GITHUB_OUTPUT: output },
      );
      expect(report.code).toBe(0);
      expect(report.stdout).toContain('### ');
    }

    expect(await readFile(output, 'utf8')).toBe('ok=false\nok=true\n');
    const artifacts = join(cwd, 'artifacts/stellar-toml-lint-testnet');
    expect((await readdir(artifacts)).sort()).toEqual([
      'testnet.json',
      'testnet.md',
      'testnet.sarif',
    ]);
    const sarif = JSON.parse(await readFile(join(artifacts, 'testnet.sarif'), 'utf8'));
    expect(validateSarif(sarif)).toEqual([]);
    expect(sarif.runs[0].automationDetails.id).toBe('stellar-toml-lint/testnet/');
    expect(sarif.runs[0].results.map((r: { ruleId: string }) => r.ruleId)).toContain(
      'ci/network-passphrase-mismatch',
    );
    // Unrelated JSON in an artifact is skipped.
    await writeFile(join(cwd, 'artifacts', 'other.json'), '{"x":1}');
    await writeFile(join(cwd, 'artifacts', 'broken.json'), '{');

    const printed = await cli(['ci-scorecard', '--input', 'artifacts']);
    expect(printed.code).toBe(0);
    expect(printed.stdout).toContain('**❌ 1 of 2 environments failed**');
    expect(printed.stdout).toContain('| Testnet |');

    const written = await cli([
      'ci-scorecard',
      '--input',
      'artifacts',
      '--output',
      'scorecard.md',
      '--run-url',
      'https://github.com/o/r/actions/runs/7',
      '--commit',
      'abcdef0123456789',
    ]);
    expect(written).toMatchObject({ code: 0, stdout: '' });
    const comment = await readFile(join(cwd, 'scorecard.md'), 'utf8');
    expect(comment.startsWith('<!-- stellar-toml-lint:ci-scorecard -->')).toBe(true);
    expect(comment).toContain('[workflow run](https://github.com/o/r/actions/runs/7)');
    // Spawns the CLI eight times; allow for slow CI runners.
  }, 90_000);

  it('records missing inputs as an errored report instead of crashing', async () => {
    const result = await cli([
      'ci-report',
      '--environment',
      'testnet',
      '--file',
      'missing.toml',
      '--lint-json',
      'missing.json',
      '--lint-exit-code',
      '2',
    ]);
    expect(result.code).toBe(0);
    expect(result.stdout).toContain('💥 errored');
    const report = JSON.parse(await readFile(join(cwd, 'reports/testnet.json'), 'utf8'));
    expect(report.error).toBe('linter produced no output (exit code 2)');
  });

  it('flags an unreadable tenant file even when lint output exists', async () => {
    await writeFile(join(cwd, 'lint.json'), '{"diagnostics":[]}');
    const result = await cli([
      'ci-report',
      '--environment',
      'public',
      '--file',
      'gone.toml',
      '--lint-json',
      'lint.json',
    ]);
    expect(result.code).toBe(0);
    const report = JSON.parse(await readFile(join(cwd, 'reports/public.json'), 'utf8'));
    expect(report).toMatchObject({ ok: false, error: 'could not read gone.toml' });
  });

  it('passes a clean tenant on its own network', async () => {
    const file = await tenant('testnet', TESTNET_NETWORK_PASSPHRASE);
    const source = await readFile(join(cwd, file), 'utf8');
    await writeFile(
      join(cwd, file),
      source.replace('HORIZON_URL="https://horizon.example.com"', ''),
    );
    const lint = await cli([file, '--format', 'json']);
    await writeFile(join(cwd, 'lint.json'), lint.stdout);
    const result = await cli([
      'ci-report',
      '--environment',
      'test',
      '--file',
      file,
      '--lint-json',
      'lint.json',
      '--lint-exit-code',
      String(lint.code),
    ]);
    expect(result.stdout).toContain('network isolation ✅ isolated');
  });

  it.each([
    [['ci-report'], 'Usage: stellar-toml-lint ci-report'],
    [['ci-report', '--environment', 'moon', '--file', 'x'], 'Unknown environment "moon"'],
    [['ci-report', '--lint-exit-code', '-1'], '--lint-exit-code expects a value.'],
    [['ci-report', '--lint-exit-code', 'x'], '--lint-exit-code expects a non-negative integer'],
    [['ci-report', '--nope'], 'Unknown option "--nope" for ci-report'],
    [['ci-scorecard'], 'Usage: stellar-toml-lint ci-scorecard'],
    [['ci-scorecard', '--nope'], 'Unknown option "--nope" for ci-scorecard'],
    [['ci-scorecard', '--input', 'does-not-exist'], 'Could not find'],
  ])('exits 2 on bad usage %#', async (args, error) => {
    const result = await cli(args);
    expect(result.code).toBe(2);
    expect(result.stderr).toContain(error);
  });

  it('exits 2 when the output directory cannot be created', async () => {
    await writeFile(join(cwd, 'blocked'), 'file');
    const result = await cli([
      'ci-report',
      '--environment',
      'public',
      '--file',
      'x.toml',
      '--out-dir',
      'blocked/reports',
    ]);
    expect(result.code).toBe(2);
  });
});
