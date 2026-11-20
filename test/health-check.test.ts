import { describe, expect, it, beforeAll, afterAll } from 'vitest';
import * as http from 'node:http';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const run = promisify(execFile);
const here = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(here, '..', 'dist', 'cli.js');

async function cli(args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  try {
    const { stdout, stderr } = await run('node', [CLI, ...args], {
      env: { ...process.env, NO_COLOR: '1' },
    });
    return { code: 0, stdout, stderr };
  } catch (error) {
    const e = error as any;
    return { code: e.code ?? 1, stdout: e.stdout ?? '', stderr: e.stderr ?? '' };
  }
}

describe('Health Check', () => {
  let server: http.Server;
  let serverUrl: string;
  let tomlPath: string;

  beforeAll(async () => {
    server = http.createServer((req, res) => {
      if (req.method === 'HEAD' || req.method === 'GET') {
        if (req.url === '/auth') {
          res.writeHead(200);
          res.end();
        } else if (req.url === '/broken') {
          res.writeHead(500);
          res.end();
        } else {
          res.writeHead(404);
          res.end();
        }
      }
    });

    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address() as any;
        serverUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    const tomlContent = `
WEB_AUTH_ENDPOINT="${serverUrl}/auth"
KYC_SERVER="${serverUrl}/broken"
`;
    tomlPath = path.join(here, 'fixtures', 'health.toml');
    await fs.writeFile(tomlPath, tomlContent);
  });

  afterAll(async () => {
    server.close();
    try {
      await fs.unlink(tomlPath);
    } catch {
      /* ignore */
    }
  });

  it('prints the latency matrix and sets exit code 1 for broken endpoints', async () => {
    const { code, stdout } = await cli([tomlPath, '--health-check']);

    expect(stdout).toContain('Endpoint Health:');
    expect(stdout).toContain('WEB_AUTH_ENDPOINT');
    expect(stdout).toContain('KYC_SERVER');

    // Auth should be 200 GOOD
    expect(stdout).toMatch(/200\s+\d+ms\s+(GOOD|FAIR)/);
    // Broken should be 500 FAIL
    expect(stdout).toMatch(/500\s+\d+ms\s+FAIL/);

    expect(code).toBe(1); // Because it failed
  });
});
