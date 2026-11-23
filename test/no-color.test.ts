import { describe, expect, it } from 'vitest';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const run = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, '..', 'dist', 'cli.js');
const BROKEN = join(here, 'fixtures', 'broken.toml');

/** Matches the start of any ANSI escape sequence. */
// eslint-disable-next-line no-control-regex
const ANSI = /\u001b\[/g;

// These exercise the built artifact, so they depend on `npm run build`.
describe('NO_COLOR compliance', () => {
  /**
   * Runs the CLI with a controlled colour environment, so the caller's own
   * NO_COLOR/FORCE_COLOR cannot leak into the result.
   */
  async function cli(
    args: string[],
    env: Record<string, string> = {},
  ): Promise<{ code: number; stdout: string; stderr: string }> {
    const merged: NodeJS.ProcessEnv = { ...process.env };
    delete merged.NO_COLOR;
    delete merged.FORCE_COLOR;
    Object.assign(merged, env);

    try {
      const { stdout, stderr } = await run('node', [CLI, ...args], { env: merged });
      return { code: 0, stdout, stderr };
    } catch (error) {
      const e = error as { code?: number; stdout?: string; stderr?: string };
      return { code: e.code ?? 1, stdout: e.stdout ?? '', stderr: e.stderr ?? '' };
    }
  }

  const ansiCount = (output: string): number => output.match(ANSI)?.length ?? 0;

  it('emits colour when FORCE_COLOR asks for it', async () => {
    const { stdout } = await cli([BROKEN], { FORCE_COLOR: '1' });
    expect(ansiCount(stdout)).toBeGreaterThan(0);
  });

  it('emits no ANSI sequences at all when NO_COLOR is set', async () => {
    const { code, stdout } = await cli([BROKEN], { NO_COLOR: '1' });
    expect(code).toBe(1);
    expect(ansiCount(stdout)).toBe(0);
  });

  it('lets NO_COLOR win over FORCE_COLOR', async () => {
    const { stdout } = await cli([BROKEN], { NO_COLOR: '1', FORCE_COLOR: '1' });
    expect(ansiCount(stdout)).toBe(0);
  });

  it.each(['0', 'false', 'anything'])('disables colour for NO_COLOR=%s', async (value) => {
    const { stdout } = await cli([BROKEN], { NO_COLOR: value, FORCE_COLOR: '1' });
    expect(ansiCount(stdout)).toBe(0);
  });

  it('treats an empty NO_COLOR as unset', async () => {
    const { stdout } = await cli([BROKEN], { NO_COLOR: '', FORCE_COLOR: '1' });
    expect(ansiCount(stdout)).toBeGreaterThan(0);
  });

  it('lets an explicit --color override NO_COLOR', async () => {
    const { stdout } = await cli([BROKEN, '--color'], { NO_COLOR: '1' });
    expect(ansiCount(stdout)).toBeGreaterThan(0);
  });

  it('lets an explicit --no-color win over FORCE_COLOR', async () => {
    const { stdout } = await cli([BROKEN, '--no-color'], { FORCE_COLOR: '1' });
    expect(ansiCount(stdout)).toBe(0);
  });
});
