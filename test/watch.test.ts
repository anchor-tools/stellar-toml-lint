import { describe, expect, it, beforeAll, afterAll } from 'vitest';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as path from 'node:path';
import * as fs from 'node:fs/promises';

const here = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(here, '..', 'dist', 'cli.js');

describe('Watch mode', () => {
  const watchFixture = path.join(here, 'fixtures', 'watch.toml');

  beforeAll(async () => {
    await fs.writeFile(watchFixture, 'VERSION="2.0.0"\n');
  });

  afterAll(async () => {
    try {
      await fs.unlink(watchFixture);
    } catch {
      /* ignore */
    }
  });

  it('runs indefinitely when --watch is provided and re-evaluates', async () => {
    const child = spawn('node', [CLI, watchFixture, '--watch'], {
      env: { ...process.env, NO_COLOR: '1' },
    });

    const exited = await new Promise<boolean>((resolve) => {
      child.on('exit', () => resolve(true));
      // If it doesn't exit after 1.5s, it is successfully watching
      setTimeout(() => resolve(false), 1500);
    });

    child.kill('SIGKILL');
    expect(exited).toBe(false);
  });

  it('runs indefinitely when -w is provided and re-evaluates', async () => {
    const child = spawn('node', [CLI, watchFixture, '-w'], {
      env: { ...process.env, NO_COLOR: '1' },
    });

    const exited = await new Promise<boolean>((resolve) => {
      child.on('exit', () => resolve(true));
      setTimeout(() => resolve(false), 1500);
    });

    child.kill('SIGKILL');
    expect(exited).toBe(false);
  });

  it('re-evaluates when the watched file is modified', async () => {
    const child = spawn('node', [CLI, watchFixture, '--watch'], {
      env: { ...process.env, NO_COLOR: '1' },
    });

    let outputCount = 0;
    const success = await new Promise<boolean>((resolve) => {
      child.stdout.on('data', (data: Buffer) => {
        const chunk = data.toString();
        if (chunk.includes('watch.toml')) {
          outputCount++;
          if (outputCount === 1) {
            // First evaluation occurred; modify the file to trigger a reload.
            setTimeout(async () => {
              await fs.writeFile(watchFixture, 'VERSION="3.0.0"\\n');
            }, 100);
          } else if (outputCount === 2) {
            // Second evaluation occurred.
            resolve(true);
          }
        }
      });
      setTimeout(() => resolve(false), 4000);
    });

    child.kill('SIGKILL');
    expect(success).toBe(true);
  });
});
