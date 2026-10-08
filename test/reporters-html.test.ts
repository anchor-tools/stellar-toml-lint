import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { lint } from '../src/lint.js';
import { formatHtml } from '../src/reporters.js';
import type { Diagnostic, LintResult } from '../src/types.js';

const here = dirname(fileURLToPath(import.meta.url));
/** A file that produces zero diagnostics, for the clean-report case. */
const CLEAN = readFileSync(join(here, 'fixtures', 'valid.toml'), 'utf8');

const BROKEN = 'VERSION="two"\nSIGNING_KEY="nope"\n';

/** An asset code we know the rules quote back at us, markup characters and all. */
const MARKUP = '[[CURRENCIES]]\ncode = "<&>"\n';

/** A payload a hostile stellar.toml might try to smuggle into the report. */
const EVIL = '<script>alert("xss")</script>';

function broken(): LintResult {
  return lint(BROKEN);
}

/** Mirrors the reporter's escaping so assertions compare like with like. */
function escape(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

describe('formatHtml', () => {
  it('emits a complete HTML document with a doctype and title', () => {
    const html = formatHtml(broken(), 'public/.well-known/stellar.toml');

    expect(html.startsWith('<!DOCTYPE html>')).toBe(true);
    expect(html).toMatch(/<html lang="en">/);
    expect(html).toContain('<title>');
    expect(html).toContain('public/.well-known/stellar.toml');
    expect(html).toContain('SEP-1 audit:');
    expect(html.trimEnd().endsWith('</html>')).toBe(true);
  });

  it('stamps the report with a timestamp and a Pass/Fail badge', () => {
    const failed = formatHtml(broken(), 'stellar.toml');
    expect(failed).toContain('class="verdict verdict-fail">Fail<');
    expect(failed).toMatch(/<time datetime="\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);

    const passed = formatHtml(lint(CLEAN), 'stellar.toml');
    expect(passed).toContain('class="verdict verdict-pass">Pass<');
  });

  it('lists every diagnostic message, rule, and severity', () => {
    const result = broken();
    const html = formatHtml(result, 'stellar.toml');

    expect(result.diagnostics.length).toBeGreaterThan(0);
    for (const d of result.diagnostics) {
      expect(html).toContain(escape(d.message));
      expect(html).toContain(escape(d.rule));
      expect(html).toContain(`data-severity="${d.severity}"`);
    }
    expect(html).toContain('class="pill pill-error"');
  });

  it('shows the Wallet Readiness grade and score bar', () => {
    const html = formatHtml(broken(), 'stellar.toml');

    expect(html).toContain('Wallet Readiness');
    expect(html).toMatch(/class="grade grade-[a-f]"/);
    expect(html).toMatch(/class="meter-fill grade-[a-f]" style="width: \d+%;"/);
    expect(html).toMatch(/\d+ \/ 100/);
  });

  it('offers All / Errors / Warnings / Info severity filters', () => {
    const html = formatHtml(broken(), 'stellar.toml');

    for (const [severity, label] of [
      ['all', 'All'],
      ['error', 'Errors'],
      ['warning', 'Warnings'],
      ['info', 'Info'],
    ]) {
      expect(html).toContain(`data-severity="${severity}"`);
      expect(html).toContain(`>${label} <span class="count">`);
    }
  });

  it('renders suggestions as expandable blocks with a code frame', () => {
    const result = broken();
    const html = formatHtml(result, 'stellar.toml');

    expect(html).toContain('<details class="more">');
    expect(html).toContain('<pre class="frame"><code>');
    // The frame carries the line:column coordinates the rule reported.
    expect(html).toMatch(/stellar\.toml:\d+:\d+/);
    const withSuggestion = result.diagnostics.find((d) => d.suggestion !== undefined)?.suggestion;
    if (withSuggestion !== undefined) expect(html).toContain(escape(withSuggestion));
  });

  it('pulls in nothing from the network', () => {
    const html = formatHtml(broken(), 'stellar.toml');

    // No external script, stylesheet, or font: the only <script> is inline.
    expect(html).not.toMatch(/<script[^>]+\bsrc\s*=/i);
    expect(html).not.toMatch(/<link[^>]+\brel\s*=\s*["']?stylesheet/i);
    expect(html).not.toMatch(/@import/i);
    expect(html).not.toMatch(/<link[^>]+\bhref\s*=/i);
  });

  it('says so on a clean file instead of showing an empty table', () => {
    const html = formatHtml(lint(CLEAN), 'stellar.toml');
    expect(html).toContain('No SEP-1 issues found.');
    expect(html).toContain('verdict-pass');
  });

  it('escapes every user-controlled string to prevent XSS', () => {
    const diagnostic: Diagnostic = {
      rule: `file/${EVIL}`,
      severity: 'error',
      category: 'file',
      message: `Diagnostic message ${EVIL}`,
      path: `PATH.${EVIL}`,
      position: { line: 3, column: 7 },
      helpUri: 'javascript:alert(1)',
      suggestion: `Suggestion ${EVIL}`,
    };
    const result: LintResult = {
      diagnostics: [diagnostic],
      ok: false,
      counts: { error: 1, warning: 0, info: 0 },
    };

    const html = formatHtml(result, EVIL);

    // The raw payload never appears anywhere in the document.
    expect(html).not.toContain('<script>alert("xss")</script>alert');
    expect(html).not.toContain('<script>alert');
    expect(html).not.toContain('javascript:alert');

    // ...but its escaped form does, in the title, body, and code frame.
    expect(html).toContain('&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;');
    expect(html).toContain('Diagnostic message &lt;script&gt;');
    expect(html).toContain('Suggestion &lt;script&gt;');
  });

  it('escapes markup that real rules quote back at us', () => {
    const html = formatHtml(lint(MARKUP), 'stellar.toml');
    expect(html).not.toContain('<&>');
    expect(html).toContain('&lt;&amp;&gt;');
  });
});
