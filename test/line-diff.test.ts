import { describe, expect, it } from 'vitest';
import { diffLines, formatUnifiedDiff, toLines } from '../src/line-diff.js';

/** Compact form for asserting on a diff: `'+text'`, `'-text'`, `' text'`. */
function ops(before: string, after: string): string[] {
  return diffLines(before, after).map(
    (line) => `${line.op === 'added' ? '+' : line.op === 'removed' ? '-' : ' '}${line.text}`,
  );
}

describe('toLines', () => {
  it('drops the empty final element a trailing newline produces', () => {
    expect(toLines('a\nb\n')).toEqual(['a', 'b']);
    expect(toLines('a\nb')).toEqual(['a', 'b']);
    expect(toLines('')).toEqual([]);
    expect(toLines('\n')).toEqual(['']);
  });
});

describe('diffLines', () => {
  it('returns nothing for identical texts', () => {
    expect(diffLines('a\nb\n', 'a\nb\n')).toEqual([]);
  });

  it('reports a two-line swap as a deletion, the survivor, then the insertion', () => {
    expect(ops('a = 1\nb = 2\n', 'b = 2\na = 1\n')).toEqual(['-a = 1', ' b = 2', '+a = 1']);
  });

  it('keeps unmodified neighbours as context', () => {
    expect(ops('top\na = 1\nb = 2\nbottom\n', 'top\nb = 2\na = 1\nbottom\n')).toEqual([
      ' top',
      '-a = 1',
      ' b = 2',
      '+a = 1',
      ' bottom',
    ]);
  });

  it('handles a pure addition and a pure removal', () => {
    expect(ops('', 'x\n')).toEqual(['+x']);
    expect(ops('x\n', '')).toEqual(['-x']);
  });

  it('numbers each side and zeroes the side a one-sided change lacks', () => {
    const lines = diffLines('a\nb\nc\n', 'a\nc\n');
    expect(lines).toEqual([
      { op: 'context', text: 'a', oldLine: 1, newLine: 1 },
      { op: 'removed', text: 'b', oldLine: 2, newLine: 0 },
      { op: 'context', text: 'c', oldLine: 3, newLine: 2 },
    ]);
  });

  it('diffes text with no trailing newline', () => {
    expect(ops('a\nb', 'a\nc')).toEqual([' a', '-b', '+c']);
  });
});

describe('formatUnifiedDiff', () => {
  it('is empty when there is nothing to show', () => {
    expect(formatUnifiedDiff('stellar.toml', 'a\n', 'a\n')).toBe('');
  });

  it('drops the git prefix for a path that is already absolute', () => {
    // `a//tmp/stellar.toml` is neither a git header nor a path anyone can paste
    // back into a shell, and the CLI hands us what the user typed.
    expect(
      formatUnifiedDiff('/tmp/stellar.toml', 'a = 1\n', 'b = 2\n').split('\n').slice(0, 2),
    ).toEqual(['--- /tmp/stellar.toml', '+++ /tmp/stellar.toml']);
  });

  it('treats Windows drive and UNC paths as absolute too', () => {
    for (const path of [
      'C:\\Users\\runner\\stellar.toml',
      'D:/anchor/stellar.toml',
      '\\\\fileserver\\share\\stellar.toml',
    ]) {
      expect(formatUnifiedDiff(path, 'a = 1\n', 'b = 2\n').split('\n').slice(0, 2)).toEqual([
        `--- ${path}`,
        `+++ ${path}`,
      ]);
    }
  });

  it('writes git headers and a hunk range', () => {
    expect(formatUnifiedDiff('stellar.toml', 'a = 1\nb = 2\n', 'b = 2\na = 1\n')).toBe(
      [
        '--- a/stellar.toml',
        '+++ b/stellar.toml',
        '@@ -1,2 +1,2 @@',
        '-a = 1',
        ' b = 2',
        '+a = 1',
        '',
      ].join('\n'),
    );
  });

  it('splits changes that are further apart than the context window', () => {
    const before = Array.from({ length: 20 }, (_, index) => `k${index} = ${index}`).join('\n');
    const after = before.replace('k0 = 0', 'k0 = 9').replace('k19 = 19', 'k19 = 9');
    const diff = formatUnifiedDiff('f.toml', before, after);
    expect(diff.match(/^@@/gm)).toHaveLength(2);
  });

  it('keeps one hunk when the gap fits inside the context', () => {
    const before = Array.from({ length: 9 }, (_, index) => `k${index} = ${index}`).join('\n');
    const after = before.replace('k1 = 1', 'k1 = 9').replace('k7 = 7', 'k7 = 9');
    expect(formatUnifiedDiff('f.toml', before, after).match(/^@@/gm)).toHaveLength(1);
  });

  it('trims context to the window it was given', () => {
    const diff = formatUnifiedDiff('f.toml', 'a\nb\nc\nd\ne\n', 'a\nb\nX\nd\ne\n', {
      context: 1,
    });
    // Line 1 is two steps from the change, so it must not appear at all.
    expect(diff.split('\n')).toEqual([
      '--- a/f.toml',
      '+++ b/f.toml',
      '@@ -2,3 +2,3 @@',
      ' b',
      '-c',
      '+X',
      ' d',
      '',
    ]);
    expect(formatUnifiedDiff('f.toml', 'a\nb\nc\nd\ne\n', 'a\nb\nX\nd\ne\n')).toContain(' a');
  });

  it('colours only the changed lines, and only when asked', () => {
    const plain = formatUnifiedDiff('f.toml', 'a = 1\n', 'b = 2\n');
    const colored = formatUnifiedDiff('f.toml', 'a = 1\n', 'b = 2\n', { color: true });
    expect(plain).not.toContain('\x1b[');
    expect(colored).toContain('\x1b[31m-a = 1\x1b[39m');
    expect(colored).toContain('\x1b[32m+b = 2\x1b[39m');
    expect(colored.split('\n')[0]).toBe('\x1b[1m--- a/f.toml\x1b[22m');
    expect(colored).toContain('\x1b[36m@@ -1,1 +1,1 @@\x1b[39m');
  });

  it('agrees with diffLines about what changed', () => {
    const before = 'ORG_NAME="x"\nORG_URL="y"\n';
    const after = 'ORG_URL="y"\nORG_NAME="x"\n';
    const body = formatUnifiedDiff('f.toml', before, after).split('\n').slice(3, -1);
    expect(body).toEqual(ops(before, after));
  });
});
