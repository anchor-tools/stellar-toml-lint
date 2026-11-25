import { describe, expect, it, beforeAll, afterAll } from 'vitest';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as os from 'node:os';
import * as path from 'node:path';
import * as fs from 'node:fs/promises';

const here = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(here, '..', 'dist', 'cli.js');

describe('Watch mode', () => {
  // Each run gets its own file: the suite is collected twice (test/ and the
  // tests/ symlink), and two workers sharing one fixture would rewrite or
  // delete it under each other's watcher.
  let watchDir = '';
  let watchFixture = '';

  beforeAll(async () => {
    watchDir = await fs.mkdtemp(path.join(os.tmpdir(), 'stellar-toml-lint-watch-'));
    watchFixture = path.join(watchDir, 'watch.toml');
    await fs.writeFile(watchFixture, 'VERSION="2.0.0"\n');
  });

  afterAll(async () => {
    await fs.rm(watchDir, { recursive: true, force: true });
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
    let rewrites: NodeJS.Timeout | undefined;
    const success = await new Promise<boolean>((resolve) => {
      child.stdout.on('data', (data: Buffer) => {
        const chunk = data.toString();
        if (chunk.includes('watch.toml')) {
          outputCount++;
          if (outputCount === 1) {
            // First evaluation occurred. The watcher is armed only after it,
            // so keep modifying the file until a reload is observed rather
            // than betting on a single write landing after the watcher.
            let version = 3;
            rewrites = setInterval(() => {
              void fs.writeFile(watchFixture, `VERSION="${version++}.0.0"\n`);
            }, 250);
          } else if (outputCount === 2) {
            // Second evaluation occurred.
            resolve(true);
          }
        }
      });
      setTimeout(() => resolve(false), 15000);
    });

    clearInterval(rewrites);
    child.kill('SIGKILL');
    expect(success).toBe(true);
  });
});
