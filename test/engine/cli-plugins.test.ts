import { afterAll, describe, expect, it } from 'vitest';
import { execFile } from 'node:child_process';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const run = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, '..', '..', 'dist', 'cli.js');

const temps: string[] = [];

afterAll(async () => {
  await Promise.all(temps.map((dir) => rm(dir, { recursive: true, force: true })));
});

async function workspace(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'cli-plugins-'));
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

describe('CLI --plugin and --rules-dir', () => {
  it('loads external plugin and reports custom diagnostic', async () => {
    const ws = await workspace();
    const tomlPath = join(ws, 'stellar.toml');
    const pluginPath = join(ws, 'plugin.mjs');

    await writeFile(
      tomlPath,
      'VERSION = "2.7.0"\nNETWORK_PASSPHRASE = "Test SDF Network ; September 2015"\n',
      'utf8',
    );

    await writeFile(
      pluginPath,
      `
export default {
  name: 'my-cli-plugin',
  rules: [
    {
      id: 'no-test-network',
      severity: 'error',
      createVisitor(ctx) {
        return {
          visitKeyValue(entry, key, val) {
            if (key === 'NETWORK_PASSPHRASE') {
              ctx.report({ message: 'Passphrase check from custom plugin' });
            }
          }
        };
      }
    }
  ]
};
`,
      'utf8',
    );

    const result = await cli(['--plugin', pluginPath, tomlPath]);
    expect(result.code).toBe(1);
    expect(result.stdout + result.stderr).toContain('Passphrase check from custom plugin');
  });

  it('loads rules from directory via --rules-dir', async () => {
    const ws = await workspace();
    const tomlPath = join(ws, 'stellar.toml');
    const rulesDir = join(ws, 'rules');
    await mkdir(rulesDir, { recursive: true });

    await writeFile(tomlPath, 'VERSION = "2.7.0"\n', 'utf8');

    await writeFile(
      join(rulesDir, 'custom.mjs'),
      `
export default {
  name: 'dir-plugin',
  rules: [
    {
      id: 'version-notice',
      severity: 'warning',
      createVisitor(ctx) {
        return {
          visitKeyValue(entry, key) {
            if (key === 'VERSION') {
              ctx.report({ message: 'Version notice from rules-dir' });
            }
          }
        };
      }
    }
  ]
};
`,
      'utf8',
    );

    const result = await cli(['--rules-dir', rulesDir, tomlPath]);
    expect(result.code).toBe(0); // Warning does not fail unless --strict
    expect(result.stdout + result.stderr).toContain('Version notice from rules-dir');
  });
});
