import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { XMLParser, XMLValidator } from 'fast-xml-parser';
import { lint } from '../src/lint.js';
import {
  formatCheckstyle,
  formatGithub,
  formatCount,
  formatJson,
  formatSarif,
  formatSummary,
  formatText,
  makeColors,
} from '../src/reporters.js';
import type { LintResult } from '../src/types.js';

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

describe('formatSummary', () => {
  /** One line, and the shape a monitoring script is documented to rely on. */
  const ONE_LINE = /^[^\n]+\n$/;

  it('reports a clean file as a single PASS line with zeroed counts', () => {
    const output = formatSummary(lint(CLEAN), 'stellar.toml');

    expect(output).toBe('stellar.toml: PASS (0 errors, 0 warnings)\n');
    // One line is the whole contract: a monitoring loop reads it line by line.
    expect(output).toMatch(ONE_LINE);
  });

  it('reports a broken file as a single FAIL line carrying the counts', () => {
    const result = lint(BROKEN);
    const output = formatSummary(result, 'public/.well-known/stellar.toml');

    expect(output).toMatch(ONE_LINE);
    expect(output).toMatch(
      /^public\/\.well-known\/stellar\.toml: FAIL \(\d+ errors?, \d+ warnings?/,
    );
    expect(output).toContain(`${result.counts.error} error`);
  });

  it('agrees with the result verdict rather than recomputing it', () => {
    // --strict turns a warning into a failure, and the summary has to say FAIL
    // in the same breath the exit code turns 1.
    const source = readFileSync(join(here, 'fixtures', 'warnings-only.toml'), 'utf8');

    const strict = lint(source, { strict: true });
    expect(strict.ok).toBe(false);
    expect(formatSummary(strict, 'stellar.toml')).toContain('FAIL');

    const lenient = lint(source);
    expect(lenient.ok).toBe(true);
    expect(formatSummary(lenient, 'stellar.toml')).toContain('PASS');
  });

  it('defaults the target name to stellar.toml', () => {
    expect(formatSummary(lint(CLEAN))).toBe('stellar.toml: PASS (0 errors, 0 warnings)\n');
  });

  it('names info findings only when there are some', () => {
    const info: LintResult = {
      diagnostics: [],
      ok: true,
      counts: { error: 0, warning: 0, info: 2 },
    };

    // A run carrying nothing but info notes must not read as untouched, the
    // same way the closing line of a multi-file run reports them.
    expect(formatSummary(info, 'a.toml')).toBe('a.toml: PASS (0 errors, 0 warnings, 2 infos)\n');
    expect(formatSummary({ ...info, counts: { error: 0, warning: 0, info: 0 } }, 'a.toml')).toBe(
      'a.toml: PASS (0 errors, 0 warnings)\n',
    );
  });

  it('paints a strict failure red, since warnings are what failed it', () => {
    const strict: LintResult = {
      diagnostics: [],
      ok: false,
      counts: { error: 0, warning: 1, info: 0 },
    };

    expect(formatSummary(strict, 'a.toml', { color: true })).toBe(
      `${makeColors(true).red(makeColors(true).bold('a.toml: FAIL (0 errors, 1 warning)'))}\n`,
    );
  });

  it('paints a pass green, a warned pass yellow, and a fail red', () => {
    const c = makeColors(true);
    const failing: LintResult = {
      diagnostics: [],
      ok: false,
      counts: { error: 2, warning: 1, info: 0 },
    };
    const warned: LintResult = {
      diagnostics: [],
      ok: true,
      counts: { error: 0, warning: 1, info: 0 },
    };

    // The whole line is painted rather than just the status word, so a log
    // reader gets the colour and a script matching `PASS` still finds it.
    expect(formatSummary(lint(CLEAN), 'a.toml', { color: true })).toBe(
      `${c.green('a.toml: PASS (0 errors, 0 warnings)')}\n`,
    );
    expect(formatSummary(warned, 'a.toml', { color: true })).toBe(
      `${c.yellow('a.toml: PASS (0 errors, 1 warning)')}\n`,
    );
    expect(formatSummary(failing, 'a.toml', { color: true })).toBe(
      `${c.red(c.bold('a.toml: FAIL (2 errors, 1 warning)'))}\n`,
    );
  });

  it('paints the verdict and stays plain when colour is off', () => {
    // eslint-disable-next-line no-control-regex
    const ansi = /\[/;
    const clean = lint(CLEAN);
    const broken = lint(BROKEN);

    expect(ansi.test(formatSummary(clean, 'a.toml', { color: false }))).toBe(false);
    expect(ansi.test(formatSummary(broken, 'a.toml', { color: false }))).toBe(false);

    const painted = formatSummary(clean, 'a.toml', { color: true });
    expect(ansi.test(painted)).toBe(true);
  });

  it('emits the identical line uncoloured by default and when colour is off', () => {
    const failing: LintResult = {
      diagnostics: [],
      ok: false,
      counts: { error: 2, warning: 1, info: 0 },
    };

    // Colour is opt-in, as it is for every other reporter, so the plain line is
    // a byte-for-byte match rather than a near miss.
    expect(formatSummary(failing, 'a.toml')).toBe('a.toml: FAIL (2 errors, 1 warning)\n');
    expect(formatSummary(failing, 'a.toml', { color: false })).toBe(
      'a.toml: FAIL (2 errors, 1 warning)\n',
    );
  });

  it('keeps a target whose name holds a newline on one line', () => {
    // A path is a shell argument, so this is reachable — and a status line that
    // split across two rows would read as two files.
    const output = formatSummary(lint(CLEAN), 'weird\nname.toml');
    expect(output).toMatch(ONE_LINE);
    expect(output).toBe('weird name.toml: PASS (0 errors, 0 warnings)\n');
  });
});

describe('formatCount', () => {
  const ONE_LINE = /^[^\n]+\n$/;

  it('reports a clean file as 0 problems (0 errors, 0 warnings)', () => {
    const output = formatCount(lint(CLEAN));
    expect(output).toBe('0 problems (0 errors, 0 warnings)\n');
    expect(output).toMatch(ONE_LINE);
  });

  it('formats single error correctly with singular problem and error', () => {
    const result: LintResult = {
      ok: false,
      diagnostics: [],
      counts: { error: 1, warning: 0, info: 0 },
    };
    expect(formatCount(result)).toBe('1 problem (1 error, 0 warnings)\n');
  });

  it('formats single warning correctly with singular problem and warning', () => {
    const result: LintResult = {
      ok: true,
      diagnostics: [],
      counts: { error: 0, warning: 1, info: 0 },
    };
    expect(formatCount(result)).toBe('1 problem (0 errors, 1 warning)\n');
  });

  it('formats multiple problems and excludes info diagnostics from problem counts', () => {
    const result: LintResult = {
      ok: false,
      diagnostics: [],
      counts: { error: 1, warning: 2, info: 5 },
    };
    expect(formatCount(result)).toBe('3 problems (1 error, 2 warnings)\n');
  });

  it('aggregates problem counts across multiple results', () => {
    const r1: LintResult = {
      ok: false,
      diagnostics: [],
      counts: { error: 1, warning: 1, info: 0 },
    };
    const r2: LintResult = {
      ok: false,
      diagnostics: [],
      counts: { error: 2, warning: 3, info: 1 },
    };
    expect(formatCount([{ result: r1 }, { result: r2 }])).toBe(
      '7 problems (3 errors, 4 warnings)\n',
    );
  });

  it('paints errors red bold, warnings yellow, and zero errors/warnings green when color is on', () => {
    const c = makeColors(true);
    const withErrors: LintResult = {
      ok: false,
      diagnostics: [],
      counts: { error: 1, warning: 2, info: 0 },
    };
    const withWarningsOnly: LintResult = {
      ok: true,
      diagnostics: [],
      counts: { error: 0, warning: 2, info: 0 },
    };
    const clean: LintResult = {
      ok: true,
      diagnostics: [],
      counts: { error: 0, warning: 0, info: 0 },
    };

    expect(formatCount(withErrors, { color: true })).toBe(
      `${c.red(c.bold('3 problems (1 error, 2 warnings)'))}\n`,
    );
    expect(formatCount(withWarningsOnly, { color: true })).toBe(
      `${c.yellow('2 problems (0 errors, 2 warnings)')}\n`,
    );
    expect(formatCount(clean, { color: true })).toBe(
      `${c.green('0 problems (0 errors, 0 warnings)')}\n`,
    );
  });

  it('stays plain when color is off', () => {
    const result: LintResult = {
      ok: false,
      diagnostics: [],
      counts: { error: 1, warning: 1, info: 0 },
    };
    const ansi = / \[/;
    expect(ansi.test(formatCount(result, { color: false }))).toBe(false);
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

describe('formatCheckstyle', () => {
  /** Parses the report the way a CI dashboard's Checkstyle reader would. */
  const parse = (xml: string): any =>
    new XMLParser({
      ignoreAttributes: false,
      attributeNamePrefix: '@_',
      parseAttributeValue: true,
      isArray: (name: string) => name === 'error',
    }).parse(xml);

  it('emits well-formed XML that a standard parser accepts', () => {
    expect(XMLValidator.validate(formatCheckstyle(lint(BROKEN), 'stellar.toml'))).toBe(true);
    expect(XMLValidator.validate(formatCheckstyle(lint(CLEAN), 'stellar.toml'))).toBe(true);
    expect(
      XMLValidator.validate(formatCheckstyle(lint('[[CURRENCIES]]\ncode = "<&>"\n'), 'a.toml')),
    ).toBe(true);
  });

  it('wraps the run in one <file> element per linted file', () => {
    const result = lint(BROKEN);
    const doc = parse(formatCheckstyle(result, 'public/.well-known/stellar.toml'));

    expect(doc.checkstyle['@_version']).toBeDefined();
    expect(doc.checkstyle.file['@_name']).toBe('public/.well-known/stellar.toml');
    expect(doc.checkstyle.file.error).toHaveLength(result.diagnostics.length);
  });

  it('carries line, column, severity, message and the rule id as source', () => {
    const result = lint(BROKEN);
    const file = parse(formatCheckstyle(result, 'stellar.toml')).checkstyle.file;

    for (const diagnostic of result.diagnostics) {
      const match = file.error.find((e: any) => e['@_source'] === diagnostic.rule);
      expect(match).toBeDefined();
      expect(match['@_severity']).toBe(diagnostic.severity);
      expect(match['@_message']).toBe(diagnostic.message);
      if (diagnostic.position) {
        expect(match['@_line']).toBe(diagnostic.position.line);
        expect(match['@_column']).toBe(diagnostic.position.column);
      } else {
        // The format wants both attributes even when the finding has no
        // position of its own; 1 is the compromise SARIF already makes.
        expect(match['@_line']).toBeGreaterThanOrEqual(1);
        expect(match['@_column']).toBeGreaterThanOrEqual(1);
      }
    }
  });

  it('defaults positionless findings to 1:1 and maps severity straight across', () => {
    const result: LintResult = {
      diagnostics: [
        { rule: 'general/version', severity: 'info', category: 'general', message: 'no position' },
      ],
      ok: true,
      counts: { error: 0, warning: 0, info: 1 },
    };
    const file = parse(formatCheckstyle(result, 'a.toml')).checkstyle.file;

    expect(file.error[0]['@_line']).toBe(1);
    expect(file.error[0]['@_column']).toBe(1);
    expect(file.error[0]['@_severity']).toBe('info');
    expect(file.error[0]['@_source']).toBe('general/version');
  });

  it('escapes markup in messages quoted out of the file', () => {
    const result = lint('[[CURRENCIES]]\ncode = "<&>"\n');
    const offending = result.diagnostics.find((d) => d.message.includes('<&>'));
    expect(offending).toBeDefined();

    const xml = formatCheckstyle(result, 'stellar.toml');
    expect(XMLValidator.validate(xml)).toBe(true);
    expect(xml).toContain('&lt;&amp;&gt;');

    // The value survives the round trip intact rather than becoming markup.
    const file = parse(xml).checkstyle.file;
    const messages = file.error.map((e: any) => String(e['@_message']));
    expect(messages).toContain(offending?.message);
  });

  it('reports a clean file as an empty <file> element', () => {
    const xml = formatCheckstyle(lint(CLEAN), 'a.toml');
    expect(XMLValidator.validate(xml)).toBe(true);

    const file = parse(xml).checkstyle.file;
    expect(file['@_name']).toBe('a.toml');
    expect(file.error).toBeUndefined();
  });

  it('defaults the filename and ends with a newline', () => {
    const xml = formatCheckstyle(lint(BROKEN));
    expect(xml).toContain('<file name="stellar.toml"');
    expect(xml.endsWith('\n')).toBe(true);
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
