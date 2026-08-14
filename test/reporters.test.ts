import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { lint } from '../src/lint.js';
import { formatGithub, formatJson, formatSarif, formatText } from '../src/reporters.js';

const here = dirname(fileURLToPath(import.meta.url));
/** A file that produces zero diagnostics, for the empty-output cases. */
const CLEAN = readFileSync(join(here, 'fixtures', 'valid.toml'), 'utf8');

const BROKEN = 'VERSION="two"\nSIGNING_KEY="nope"\n';

describe('formatText', () => {
  it('says so when there is nothing to report', () => {
    const output = formatText(lint(CLEAN), { filename: 'a.toml' });
    expect(output).toContain('No SEP-1 issues found');
  });

  it('emits an editor-clickable line:column prefix', () => {
    const output = formatText(lint(BROKEN), { filename: 'stellar.toml' });
    expect(output).toMatch(/\d+:\d+\s+error/);
    expect(output).toContain('stellar.toml');
  });

  it('summarises the counts', () => {
    const result = lint(BROKEN);
    const output = formatText(result, { color: false });
    expect(output).toContain(`${result.counts.error} error`);
  });

  it('omits colour codes unless asked', () => {
    // eslint-disable-next-line no-control-regex
    const ansi = /\[/;
    expect(ansi.test(formatText(lint(BROKEN), { color: false }))).toBe(false);
    expect(ansi.test(formatText(lint(BROKEN), { color: true }))).toBe(true);
  });
});

describe('formatJson', () => {
  it('round-trips through JSON.parse', () => {
    const parsed = JSON.parse(formatJson(lint(BROKEN), 'stellar.toml'));
    expect(parsed.file).toBe('stellar.toml');
    expect(parsed.ok).toBe(false);
    expect(Array.isArray(parsed.diagnostics)).toBe(true);
    expect(parsed.counts.error).toBeGreaterThan(0);
  });
});

describe('formatSarif', () => {
  const sarif = JSON.parse(formatSarif(lint(BROKEN), 'stellar.toml', '0.1.0'));

  it('declares SARIF 2.1.0', () => {
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs).toHaveLength(1);
  });

  it('names the driver and its rules', () => {
    expect(sarif.runs[0].tool.driver.name).toBe('stellar-toml-lint');
    expect(sarif.runs[0].tool.driver.rules.length).toBeGreaterThan(0);
  });

  it('maps every result to a declared rule index', () => {
    const rules = sarif.runs[0].tool.driver.rules;
    for (const result of sarif.runs[0].results) {
      expect(rules[result.ruleIndex].id).toBe(result.ruleId);
    }
  });

  it('uses SARIF level names and 1-based positions', () => {
    for (const result of sarif.runs[0].results) {
      expect(['error', 'warning', 'note']).toContain(result.level);
      const region = result.locations[0].physicalLocation.region;
      expect(region.startLine).toBeGreaterThanOrEqual(1);
      expect(region.startColumn).toBeGreaterThanOrEqual(1);
    }
  });
});

describe('formatGithub', () => {
  it('emits workflow commands with file and line', () => {
    const output = formatGithub(lint(BROKEN), 'stellar.toml');
    expect(output).toMatch(/^::(error|warning|notice) file=stellar\.toml,line=\d+/m);
  });

  it('escapes newlines and reserved characters in titles', () => {
    const output = formatGithub(lint(BROKEN), 'stellar.toml');
    for (const line of output.trim().split('\n')) {
      // Everything before `::<message>` must not contain a raw newline.
      expect(line.split('::')[1]).not.toContain('\n');
    }
  });

  it('produces nothing for a clean file', () => {
    expect(formatGithub(lint(CLEAN), 'a.toml')).toBe('');
  });
});

describe('column alignment', () => {
  it('widens the location column to fit path-only diagnostics', () => {
    // Rules about an absent key have no line number and fall back to a dotted
    // path, which is wider than "12:1". A fixed pad misaligned everything after.
    const output = formatText(lint('VERSION="two"\n'), { color: false });

    // The severity keyword starts a fixed distance in on every row.
    const columns = output
      .split('\n')
      .map((line) => /\b(error|warning|info)\b {2}/.exec(line)?.index)
      .filter((index): index is number => index !== undefined);

    expect(columns.length).toBeGreaterThan(1);
    expect(new Set(columns).size).toBe(1);
  });
});
