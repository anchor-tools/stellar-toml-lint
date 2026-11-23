import { describe, expect, it } from 'vitest';
import { EventEmitter } from 'node:events';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  createDashboardState,
  matchingEntries,
  reduceDashboard,
  renderDashboard,
  runDashboard,
  selectedEntry,
  supportsDashboard,
  type DashboardState,
  type DashboardStreams,
} from '../src/ui/dashboard.js';
import type { Diagnostic, LintResult, Severity } from '../src/types.js';

const run = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, '..', 'dist', 'cli.js');
const fixture = (name: string): string => join(here, 'fixtures', name);

function diagnostic(rule: string, severity: Severity, extra: Partial<Diagnostic> = {}): Diagnostic {
  return { rule, severity, category: 'general', message: `${rule} is wrong`, ...extra };
}

function result(counts: Partial<Record<Severity, number>>, diagnostics: Diagnostic[]): LintResult {
  const full: Record<Severity, number> = {
    error: counts.error ?? 0,
    warning: counts.warning ?? 0,
    info: counts.info ?? 0,
  };
  return { diagnostics, ok: full.error === 0, counts: full };
}

const sample: { name: string; result: LintResult }[] = [
  {
    name: 'a.toml',
    result: result({ error: 1, warning: 1 }, [
      diagnostic('currencies/missing-issuer', 'error', {
        position: { line: 12, column: 3 },
        suggestion: 'Add an issuer for each currency.',
        helpUri: 'https://example.test/sep-1',
      }),
      diagnostic('general/email', 'warning', { position: { line: 30, column: 1 } }),
    ]),
  },
  {
    name: 'b.toml',
    result: result({ error: 1 }, [
      diagnostic('currencies/issuance-exclusive', 'error', { position: { line: 4, column: 1 } }),
    ]),
  },
];

/**
 * Sends keystrokes one at a time. An escape sequence is sent whole: splitting
 * it into characters would turn an arrow key into three no-ops, which is how
 * the first version of this test passed while the arrows did nothing.
 */
function press(
  keys: string,
  state: DashboardState,
  context?: Parameters<typeof reduceDashboard>[2],
): DashboardState {
  const sequence = keys.startsWith('\x1b') ? [keys] : [...keys];
  return sequence.reduce((acc, key) => reduceDashboard(acc, key, context ?? {}), state);
}

function stripAnsi(text: string): string {
  // eslint-disable-next-line no-control-regex
  return text.replace(/\x1b\[[0-9;]*m/g, '');
}

// ── state and navigation ───────────────────────────────────────────────────

describe('dashboard state', () => {
  it('flattens the run into one list, keeping the file each finding came from', () => {
    const state = createDashboardState(sample);

    expect(state.entries).toHaveLength(3);
    expect(state.entries.map((entry) => entry.file)).toEqual(['a.toml', 'a.toml', 'b.toml']);
    expect(state.cursor).toBe(0);
    expect(state.quit).toBe(false);
  });

  it('moves with both j/k and the arrow sequences, and stops at the ends', () => {
    const start = createDashboardState(sample);

    expect(selectedEntry(press('j', start))?.diagnostic.rule).toBe('general/email');
    expect(selectedEntry(press('\x1b[B', start))?.diagnostic.rule).toBe('general/email');
    expect(selectedEntry(press('jj', start))?.diagnostic.rule).toBe(
      'currencies/issuance-exclusive',
    );
    expect(selectedEntry(press('jjjjjj', start))?.diagnostic.rule).toBe(
      'currencies/issuance-exclusive',
    );
    expect(press('kkk', start).cursor).toBe(0);
    expect(selectedEntry(press('\x1b[A', start))?.diagnostic.rule).toBe(
      'currencies/missing-issuer',
    );
  });

  it('cycles the severity filter and resets the cursor with it', () => {
    const filtered = press('s', press('jj', createDashboardState(sample)));

    expect(filtered.filter).toBe('error');
    expect(filtered.cursor).toBe(0);
    expect(matchingEntries(filtered)).toHaveLength(2);

    const warnings = press('ss', createDashboardState(sample));
    expect(warnings.filter).toBe('warning');
    expect(matchingEntries(warnings).map((entry) => entry.diagnostic.rule)).toEqual([
      'general/email',
    ]);

    expect(press('sss', createDashboardState(sample)).filter).toBe('all');
  });

  it('searches rule names without leaving the list navigable', () => {
    const typing = press('/missing', createDashboardState(sample));

    expect(typing.searching).toBe(true);
    expect(typing.search).toBe('missing');
    expect(matchingEntries(typing).map((entry) => entry.diagnostic.rule)).toEqual([
      'currencies/missing-issuer',
    ]);

    // Backspace edits, Enter leaves the bar but keeps the term.
    expect(press('\x7f', typing).search).toBe('missin');
    const done = press('\r', typing);
    expect(done.searching).toBe(false);
    expect(done.search).toBe('missing');

    // Escape is also a way out.
    expect(press('\x1b', typing).searching).toBe(false);
  });

  it('treats keys as search input while the bar is open, q included', () => {
    const typing = press('/q', createDashboardState(sample));

    expect(typing.quit).toBe(false);
    expect(typing.search).toBe('q');
  });

  it('matches the search case-insensitively', () => {
    const upper = press('/MISSING', createDashboardState(sample));

    expect(matchingEntries(upper)).toHaveLength(1);
  });

  it('toggles the details panel and quits on q or Ctrl-C', () => {
    const opened = reduceDashboard(createDashboardState(sample), '\r');
    expect(opened.expanded).toBe(true);
    expect(reduceDashboard(opened, '\r').expanded).toBe(false);

    expect(reduceDashboard(createDashboardState(sample), 'q').quit).toBe(true);
    expect(reduceDashboard(createDashboardState(sample), '\x03').quit).toBe(true);
  });

  it('reports what f can and cannot do', () => {
    const state = createDashboardState(sample);

    // No fix engine is wired up yet, and the dashboard says so rather than
    // pretending something happened.
    expect(reduceDashboard(state, 'f').status).toContain('#9');

    const withEngine = reduceDashboard(state, 'f', {
      autofix: (entry) => `Fixed ${entry.diagnostic.rule}`,
    });
    expect(withEngine.status).toBe('Fixed currencies/missing-issuer');

    const narrowed = [...'ss'].reduce((acc, key) => reduceDashboard(acc, key), state);
    expect(reduceDashboard({ ...narrowed, entries: [] }, 'f').status).toBe(
      'Nothing selected to fix.',
    );
  });
});

// ── rendering ──────────────────────────────────────────────────────────────

describe('dashboard rendering', () => {
  it('draws a frame with the counts, the findings and the key hints', () => {
    const frame = renderDashboard(createDashboardState(sample), { width: 80, height: 20 });

    expect(frame).toContain('2 errors · 1 warnings · 0 info');
    expect(frame).toContain('currencies/missing-issuer');
    expect(frame).toContain('line 12');
    expect(frame).toContain('j/k ↑↓ move');
    expect(frame).toContain('q quit');
    expect(frame.split('\n').at(-1)?.startsWith('└')).toBe(true);
  });

  it('marks the highlighted row and only that row', () => {
    const state = press('j', createDashboardState(sample));
    const lines = renderDashboard(state, { width: 80 }).split('\n');
    const marked = lines.filter((line) => line.includes('▸'));

    expect(marked).toHaveLength(1);
    expect(marked[0]).toContain('general/email');
  });

  it('shows the details panel with the suggestion and the spec link when expanded', () => {
    const state = reduceDashboard(createDashboardState(sample), '\r');
    const frame = renderDashboard(state, { width: 100, height: 20 });

    expect(frame).toContain('Add an issuer for each currency.');
    expect(frame).toContain('https://example.test/sep-1');
    expect(frame).toContain('a.toml:12');
  });

  it('says so when the filter matches nothing', () => {
    const empty = { ...createDashboardState(sample), search: 'nope' };

    expect(renderDashboard(empty, { width: 80 })).toContain('No findings match this filter.');
  });

  it('never overflows the rows it was given, and says how many are hidden', () => {
    const many = createDashboardState([
      {
        name: 'big.toml',
        result: result(
          { error: 30 },
          Array.from({ length: 30 }, (_, index) => diagnostic(`rule/${index}`, 'error')),
        ),
      },
    ]);

    const lines = renderDashboard(many, { width: 80, height: 12 }).split('\n');

    expect(lines.length).toBeLessThanOrEqual(12);
    expect(lines.join('\n')).toContain('more (filter or search to narrow)');
  });

  it('keeps every row the same width, colour codes excluded', () => {
    const state = reduceDashboard(createDashboardState(sample), '\r');
    const plain = renderDashboard(state, { width: 80, height: 24 }).split('\n');
    const coloured = renderDashboard(state, { width: 80, height: 24, color: true }).split('\n');

    for (const lines of [plain, coloured]) {
      const widths = new Set(lines.map((line) => stripAnsi(line).length));
      expect(widths.size).toBe(1);
    }
  });

  it('adds no escape codes unless colour was asked for', () => {
    const state = createDashboardState(sample);

    expect(renderDashboard(state, { color: false })).not.toContain('\x1b[');
    expect(renderDashboard(state, { color: true })).toContain('\x1b[');
  });

  it('truncates a long rule name instead of breaking the frame', () => {
    const long = createDashboardState([
      {
        name: 'x.toml',
        result: result({ error: 1 }, [diagnostic(`currencies/${'x'.repeat(120)}`, 'error')]),
      },
    ]);

    const frame = renderDashboard(long, { width: 60 });
    expect(frame).toContain('…');
    expect(
      stripAnsi(frame)
        .split('\n')
        .every((line) => line.length === 60),
    ).toBe(true);
  });
});

// ── the TTY loop and the fallback ──────────────────────────────────────────

describe('dashboard loop', () => {
  function fakeStreams(writes: string[]): DashboardStreams {
    const input = new EventEmitter() as unknown as DashboardStreams['stdin'];
    Object.assign(input, {
      isRaw: false,
      setRawMode: (mode: boolean) => {
        (input as { isRaw: boolean }).isRaw = mode;
      },
      resume: () => {},
      pause: () => {},
      setEncoding: () => {},
    });

    const output = {
      isTTY: true,
      columns: 90,
      rows: 24,
      write: (chunk: string) => {
        writes.push(chunk);
        return true;
      },
    } as unknown as DashboardStreams['stdout'];

    return { stdin: input, stdout: output };
  }

  it('draws a frame, follows the keystrokes and stops on q', async () => {
    const writes: string[] = [];
    const streams = fakeStreams(writes);

    const pending = runDashboard(sample, streams, { color: false });
    // The first frame is drawn before any input arrives.
    await new Promise((resolve) => setTimeout(resolve, 0));
    streams.stdin.emit('data', 'j');
    streams.stdin.emit('data', 'q');

    const { state, lines } = await pending;

    expect(state.quit).toBe(true);
    expect(state.cursor).toBe(1);
    expect(lines.length).toBeGreaterThanOrEqual(2);
    expect(writes.some((chunk) => chunk.includes('\x1b[2J'))).toBe(true);
    expect(writes.join('')).toContain('general/email');
  });

  it('leaves raw mode as it found it', async () => {
    const writes: string[] = [];
    const streams = fakeStreams(writes);

    const pending = runDashboard(sample, streams);
    await new Promise((resolve) => setTimeout(resolve, 0));
    streams.stdin.emit('data', 'q');
    await pending;

    expect((streams.stdin as { isRaw?: boolean }).isRaw).toBe(false);
  });

  it('can open already filtered, which is what --quiet asks for', async () => {
    const writes: string[] = [];
    const streams = fakeStreams(writes);

    const pending = runDashboard(sample, streams, { filter: 'error' });
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(writes.join('')).toContain('filter: errors only');
    streams.stdin.emit('data', 'q');
    const { state } = await pending;

    expect(state.filter).toBe('error');
    expect(matchingEntries(state)).toHaveLength(2);
  });

  it('only claims to support a real terminal', () => {
    expect(supportsDashboard({ isTTY: true })).toBe(true);
    expect(supportsDashboard({ isTTY: false })).toBe(false);
    expect(supportsDashboard({})).toBe(false);
  });
});

// ── the CLI ────────────────────────────────────────────────────────────────

async function cli(args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
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
describe('cli --interactive', () => {
  it('falls back to the text report when stdout is not a terminal', async () => {
    const plain = await cli([fixture('broken.toml')]);
    const interactive = await cli([fixture('broken.toml'), '--interactive']);

    expect(interactive.code).toBe(1);
    // Piped output must be byte-identical to the non-interactive run: a frame
    // of box drawing in a CI log would be a regression.
    expect(interactive.stdout).toBe(plain.stdout);
    expect(interactive.stdout).not.toContain('\x1b[');
    expect(interactive.stdout).not.toContain('┌');
  });

  it('accepts -i as the short form', async () => {
    const { code, stdout } = await cli([fixture('valid.toml'), '-i']);

    expect(code).toBe(0);
    expect(stdout).toContain('No SEP-1 issues found');
  });

  it('refuses to combine the dashboard with another format', async () => {
    const { code, stderr } = await cli([fixture('broken.toml'), '--interactive', '-f', 'json']);

    expect(code).toBe(2);
    expect(stderr).toContain('--interactive draws its own view');
    expect(stderr).toContain('drop --format json');
  });

  it('lists the flag in --help', async () => {
    const { stdout } = await cli(['--help']);

    expect(stdout).toContain('-i, --interactive');
  });
});
