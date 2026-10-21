import { describe, expect, it } from 'vitest';
import { renderSplitDiff } from '../../src/reporters/split-diff.js';

/** Built from String.fromCharCode so this file stays as regex-clean as the source. */
const ESC = String.fromCharCode(27);
const RED = `${ESC}[31m`;
const GREEN = `${ESC}[32m`;
const RESET = `${ESC}[0m`;

const BASE = ['ORG_NAME = "Old"', 'KEEP = 1'].join('\n');
const TARGET = ['ORG_NAME = "New"', 'KEEP = 1'].join('\n');

describe('renderSplitDiff', () => {
  it('labels the two columns and keeps the line numbers aligned', () => {
    const lines = renderSplitDiff(BASE, TARGET, {
      color: false,
      width: 80,
      base: 'old.toml',
      target: 'new.toml',
    }).split('\n');

    expect(lines[0]).toBe('--- old.toml');
    expect(lines[1]).toBe('+++ new.toml');
  });

  it('marks removals and additions and keeps unchanged rows unmarked', () => {
    const out = renderSplitDiff(BASE, TARGET, { color: false, width: 80 });

    expect(out).toContain('-ORG_NAME = "Old"');
    expect(out).toContain('+ORG_NAME = "New"');
    expect(out).not.toContain('-KEEP');
    expect(out).not.toContain('+KEEP');
    expect(out.split('KEEP = 1').length - 1).toBeGreaterThanOrEqual(2);
    expect(out).toContain('1 insertions(+), 1 deletions(-), 1 unchanged');
    expect(out.endsWith('\n')).toBe(true);
  });

  it('paints only the words that changed', () => {
    const out = renderSplitDiff(
      ['ORG_NAME = "Old"', 'KEEP = 1'].join('\n'),
      ['ORG_NAME = "Renamed"', 'KEEP = 1'].join('\n'),
      { color: true, width: 80 },
    );

    expect(out).toContain(`${RED}"Old"${RESET}`);
    expect(out).toContain(`${GREEN}"Renamed"${RESET}`);
    expect(out).toContain('-');
    expect(out).toContain('+');
    // The shared words stay unpainted; only the marker and the changed word
    // carry colour.
    expect(out).not.toContain(`${RED}ORG_NAME`);
    expect(out).not.toContain(`${GREEN}ORG_NAME`);
  });

  it('folds long runs of unchanged lines and counts what it folded', () => {
    const common = Array.from({ length: 10 }, (_, index) => `L${index + 1}`);
    const out = renderSplitDiff([...common, 'OLD'].join('\n'), [...common, 'NEW'].join('\n'), {
      color: false,
      width: 80,
    });

    expect(out).toContain('... 4 unchanged lines ...');
    expect(out).toContain('1 insertions(+), 1 deletions(-), 10 unchanged');
    expect(out).toContain('-OLD');
    expect(out).toContain('+NEW');
    // Context survives on both sides of the fold...
    expect(out).toContain('L3');
    expect(out).toContain('L8');
    // ...and the folded middle does not.
    expect(out).not.toContain('L5');
  });

  it('never exceeds the requested width, wrapping long lines instead', () => {
    const out = renderSplitDiff(`${'X'.repeat(200)}\n`, `${'Y'.repeat(200)}\n`, {
      color: false,
      width: 40,
    });

    for (const line of out.split('\n')) {
      expect(line.length).toBeLessThanOrEqual(40);
    }
    expect(out.split('\n').length).toBeGreaterThan(14);
  });

  it('normalizes CRLF line endings', () => {
    const out = renderSplitDiff('A\r\nB\r\n', 'A\r\nC\r\n', { color: false, width: 80 });

    expect(out).not.toContain('\r');
    expect(out).toContain('-B');
    expect(out).toContain('+C');
  });

  it('reports zero churn for identical inputs', () => {
    const same = 'A\nB\nC\n';

    const out = renderSplitDiff(same, same, { color: false, width: 80 });

    expect(out).toContain('0 insertions(+), 0 deletions(-), 3 unchanged');
    expect(out).not.toContain('\u001b');
  });
});
