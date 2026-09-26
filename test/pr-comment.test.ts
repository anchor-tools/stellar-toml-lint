import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parse as parseYaml } from 'yaml';

import {
  breakingChanges,
  formatPrComment,
  PR_COMMENT_MARKER,
} from '../src/reporters/pr-comment.js';
import type { Diagnostic, LintResult, Severity } from '../src/types.js';

function createResult(
  counts: Partial<Record<Severity, number>>,
  diagnostics: Diagnostic[] = [],
): LintResult {
  const full: Record<Severity, number> = {
    error: counts.error ?? 0,
    warning: counts.warning ?? 0,
    info: counts.info ?? 0,
  };
  return { diagnostics, ok: full.error === 0, counts: full };
}

function createDiagnostic(
  rule: string,
  severity: Severity,
  extra: Partial<Diagnostic> = {},
): Diagnostic {
  return { rule, severity, category: 'general', message: `${rule} is not valid`, ...extra };
}

const passing: LintResult = createResult({ error: 0, warning: 0, info: 0 });
const failing: LintResult = createResult({ error: 2, warning: 1 }, [
  createDiagnostic('currencies/missing-issuer', 'error', {
    position: { line: 15, column: 1 },
    suggestion: 'Add the issuer account ID.',
    helpUri: 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0001.md',
  }),
  createDiagnostic('general/deprecated-field', 'warning', {
    path: 'AUTH_SERVER',
    message: 'AUTH_SERVER is deprecated because the SEP-3 Compliance Protocol is deprecated',
    suggestion: 'Replace AUTH_SERVER with WEB_AUTH_ENDPOINT.',
  }),
  createDiagnostic('general/unknown-field', 'info', { path: 'SOMETHING_NEW' }),
]);

describe('pr-comment reporter: status and badges', () => {
  it('reports Pass for a clean run with exit code 0', () => {
    const md = formatPrComment(passing);
    expect(md).toContain('Pass');
    expect(md).not.toContain('Fail');
    expect(md).toContain('| `0` |');
  });

  it('reports Fail with the linter exit code for a failing run', () => {
    const md = formatPrComment(failing);
    expect(md).toContain('Fail');
    expect(md).toContain('| `1` |');
    expect(md).toContain('2'); // error count
  });

  it('renders status and Wallet Readiness as shields.io badge images', () => {
    const md = formatPrComment(failing);
    expect(md).toMatch(/!\[Fail\]\(https:\/\/img\.shields\.io\/badge\//);
    expect(md).toMatch(/!\[Wallet Readiness [^\\n]*\]\(https:\/\/img\.shields\.io\/badge\//);
  });

  it('computes the readiness score from the lint counts (same formula as the badge generator)', () => {
    // 2 errors + 1 warning = 100 - (2*10 + 1*3) = 77 → grade C
    const md = formatPrComment(failing);
    expect(md).toContain('Wallet Readiness 77/100 (C)');
    expect(md).toMatch(/Wallet%20Readiness-77.*C.*-yellow/);
  });

  it('shows a perfect score for a clean run', () => {
    const md = formatPrComment(passing);
    expect(md).toContain('Wallet Readiness 100/100 (A)');
  });

  it('honours an explicit exit code option', () => {
    const md = formatPrComment(passing, { exitCode: 2 });
    expect(md).toContain('| `2` |');
  });
});

describe('pr-comment reporter: GitHub-flavored Markdown structure', () => {
  it('starts with the marker comment the posting script keys on', () => {
    const md = formatPrComment(failing);
    expect(md.startsWith(PR_COMMENT_MARKER)).toBe(true);
    expect(md.split('\n', 1)[0]).toBe('<!-- stellar-toml-lint-report -->');
  });

  it('wraps detailed suggestions in a collapsible <details> block', () => {
    const md = formatPrComment(failing);
    expect(md).toContain('<details>');
    expect(md).toMatch(/<summary>[^\\n]*Diagnostics &amp; suggestions \(3\)<\/summary>/);
    expect(md).toContain('</details>');
    expect(md).toContain('Suggestion: Add the issuer account ID.');
    expect(md).toContain('Spec: <https://github.com/stellar/stellar-protocol');
  });

  it('keeps a clean run outside the details block, with no details at all', () => {
    const md = formatPrComment(passing);
    expect(md).not.toContain('<details>');
    expect(md).toContain('No SEP-1 findings');
  });

  it('escapes values sourced from the linted file', () => {
    const md = formatPrComment(
      createResult({ error: 1 }, [
        createDiagnostic('general/unknown-field', 'error', {
          message: 'EVIL <script>alert(1)</script> | pipe | rule',
          path: 'A|B<C>',
        }),
      ]),
    );
    // Prose positions escape markup characters with backslashes (the same
    // convention as the step-summary reporter), so nothing survives as markup.
    expect(md).not.toContain('EVIL <script>');
    expect(md).toContain('\\<script\\>');
    expect(md).toContain('A\\|B\\<C\\>');
  });

  it('keeps underscores literal inside code spans', () => {
    const md = formatPrComment(failing);
    expect(md).toContain('`AUTH_SERVER`');
    expect(md).not.toContain('AUTH\\_SERVER`');
  });

  it('is deterministic: no timestamps, same input → same output', () => {
    expect(formatPrComment(failing)).toBe(formatPrComment(failing));
    expect(formatPrComment(failing)).not.toMatch(/\d{4}-\d{2}-\d{2}/);
  });

  it('fits inside a PR comment body (GitHub hard-caps at 65,536 characters)', () => {
    const many = Array.from({ length: 300 }, (_, i) =>
      createDiagnostic(`general/unknown-field`, 'info', {
        message: `Finding number ${i} with a moderately long message to bulk the body out.`,
        position: { line: i + 1, column: 1 },
      }),
    );
    const md = formatPrComment(createResult({ error: 0, info: 300 }, many));
    expect(md.length).toBeLessThan(65_536);
    expect(md).toContain('…and');
  });
});

describe('pr-comment reporter: breaking changes', () => {
  it('lists deprecated fields in their own section', () => {
    const md = formatPrComment(failing);
    expect(md).toContain('Breaking changes (1)');
    expect(md).toContain('`AUTH_SERVER`');
    // Prose text keeps underscores escaped so GitHub cannot italicise them.
    expect(md).toContain('Fix: Replace AUTH\\_SERVER with WEB\\_AUTH\\_ENDPOINT.');
  });

  it('omits the section when nothing deprecated was found', () => {
    const md = formatPrComment(passing);
    expect(md).not.toContain('Breaking changes');
  });

  it('exposes the heuristic as a queryable helper', () => {
    const deprecated = createDiagnostic('general/deprecated-field', 'warning', {
      message:
        'DEPOSIT_SERVER is deprecated because the legacy SEP-6 deposit server field was replaced',
    });
    const plain = createDiagnostic('general/unknown-field', 'info');
    expect(breakingChanges([plain, deprecated])).toEqual([deprecated]);
  });
});

describe('action.yml pr-comment wiring', () => {
  const action = parseYaml(readFileSync('action.yml', 'utf8')) as {
    inputs: Record<string, { default?: string; required?: boolean }>;
    runs: { steps: { id?: string; uses?: string; if?: string }[] };
  };

  it('declares a pr-comment input defaulting to false', () => {
    const input = action.inputs['pr-comment'];
    expect(input).toBeDefined();
    expect(input?.default).toBe('false');
    expect(input?.required).toBe(false);
  });

  it('posts the comment with actions/github-script only in pull-request contexts', () => {
    const step = action.runs.steps.find((s) => s.id === 'pr-comment');
    expect(step).toBeDefined();
    expect(step?.uses).toContain('actions/github-script@');
    expect(step?.if).toContain("inputs.pr-comment == 'true'");
    expect(step?.if).toContain("github.event_name == 'pull_request'");
  });
});
