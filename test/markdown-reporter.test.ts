import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { lint } from '../src/lint.js';
import { formatMarkdown } from '../src/reporters.js';
import type { LintResult } from '../src/types.js';

const here = dirname(fileURLToPath(import.meta.url));
/** A file that produces zero diagnostics, so the run reports a clean pass. */
const CLEAN = readFileSync(join(here, 'fixtures', 'valid.toml'), 'utf8');

const BROKEN = 'VERSION="two"\nSIGNING_KEY="nope"\n';

describe('formatMarkdown', () => {
  it('reports a clean file as a green pass header', () => {
    const output = formatMarkdown(lint(CLEAN), 'stellar.toml');
    expect(output.trim()).toBe('### ✅ stellar.toml: No SEP-1 issues found');
    expect(output.endsWith('\n')).toBe(true);
  });

  it('reports a failed run as a red header with the counts', () => {
    const result = lint(BROKEN);
    const output = formatMarkdown(result, 'public/.well-known/stellar.toml');

    expect(output).toContain('### ❌ Failed: public/.well-known/stellar.toml');
    expect(output).toContain(`${result.counts.error} error`);
    expect(output).toContain(`${result.counts.warning} warning`);
  });

  it('renders one table row per diagnostic', () => {
    const result = lint(BROKEN);
    const output = formatMarkdown(result, 'stellar.toml');

    expect(output).toContain('| Location | Severity | Rule | Message |');
    expect(output).toContain('| --- | --- | --- | --- |');

    for (const diagnostic of result.diagnostics) {
      expect(output).toContain(`| ${diagnostic.severity} | ${diagnostic.rule} |`);
    }
  });

  it('folds suggestions and spec links into collapsible details', () => {
    const result = lint(BROKEN);
    const output = formatMarkdown(result, 'stellar.toml');

    expect(output).toContain('<details>');
    expect(output).toContain('</details>');

    const withSuggestion = result.diagnostics.find((d) => d.suggestion);
    expect(withSuggestion).toBeDefined();
    expect(output).toContain(withSuggestion?.suggestion as string);

    const withHelp = result.diagnostics.find((d) => d.helpUri);
    expect(withHelp).toBeDefined();
    expect(output).toContain(withHelp?.helpUri as string);
  });

  it('escapes markdown table syntax out of quoted values', () => {
    const result: LintResult = {
      diagnostics: [
        {
          rule: 'currencies/pipe',
          severity: 'error',
          category: 'currencies',
          message: 'CURRENCIES[0].code is "USD|X" <script>',
          position: { line: 3, column: 1 },
          suggestion: 'Use a plain asset code a|b',
        },
      ],
      ok: false,
      counts: { error: 1, warning: 0, info: 0 },
    };

    const output = formatMarkdown(result, 'stellar.toml');

    // The pipe and angle brackets must not survive as markup.
    expect(output).not.toContain('USD|X');
    expect(output).not.toContain('<script>');
    expect(output).toContain('USD\\|X');
    expect(output).toContain('&lt;script&gt;');
    expect(output).toContain('a\\|b');

    // Every table row still has exactly the four columns it started with.
    const rows = output.split('\n').filter((line) => line.startsWith('| '));
    for (const row of rows) {
      expect(row.match(/(?<!\\)\|/g)?.length).toBe(5);
    }
  });

  it('marks a warnings-only run as passed with no errors', () => {
    const result: LintResult = {
      diagnostics: [
        { rule: 'documentation/x', severity: 'warning', category: 'documentation', message: 'w' },
      ],
      ok: true,
      counts: { error: 0, warning: 1, info: 0 },
    };

    const output = formatMarkdown(result, 'stellar.toml');
    expect(output).toContain('### ✅ Passed: stellar.toml');
  });

  it('defaults the filename and ends with a newline', () => {
    const output = formatMarkdown(lint(BROKEN));
    expect(output).toContain('### ❌ Failed: stellar.toml');
    expect(output.endsWith('\n')).toBe(true);
  });
});
