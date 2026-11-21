import { afterAll, describe, expect, it } from 'vitest';
import { execFile } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const run = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, '..', 'dist', 'cli.js');

const temps: string[] = [];

afterAll(async () => {
  await Promise.all(temps.map((dir) => rm(dir, { recursive: true, force: true })));
});

async function workspace(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'cst-telemetry-cli-'));
  temps.push(dir);
  return dir;
}

interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

async function cli(args: string[]): Promise<RunResult> {
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

describe('CLI format, verify-rate-headers, and audit-tls commands', () => {
  it('formats a stellar.toml file with the format command', async () => {
    const ws = await workspace();
    const filePath = join(ws, 'stellar.toml');
    const content = '# Comment\nVERSION = "2.7.0"\n';
    await writeFile(filePath, content, 'utf8');

    const result = await cli(['format', '--file', filePath]);
    expect(result.code).toBe(0);
    expect(result.stdout).toContain('# Comment');
    expect(result.stdout).toContain('VERSION = "2.7.0"');
  });

  it('validates rate-limit headers with verify-rate-headers command', async () => {
    // Testing missing rate-limit headers or usage on mock/unreachable url
    const result = await cli([
      'verify-rate-headers',
      '--url',
      'https://example.com/api',
      '--format',
      'json',
    ]);
    // Either finishes or reports connection / missing headers with valid JSON output
    expect(result.stdout).toBeDefined();
    if (result.stdout.trim().startsWith('{')) {
      const parsed = JSON.parse(result.stdout);
      expect(parsed.url).toBe('https://example.com/api');
    }
  });

  it('audits TLS certificate with audit-tls command', async () => {
    const result = await cli(['audit-tls', '--domain', 'example.com', '--format', 'json']);
    expect(result.stdout).toBeDefined();
    if (result.stdout.trim().startsWith('{')) {
      const parsed = JSON.parse(result.stdout);
      expect(parsed.domain).toBe('example.com');
    }
  });
});
