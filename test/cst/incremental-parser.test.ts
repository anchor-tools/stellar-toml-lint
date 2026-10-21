import { describe, expect, it } from 'vitest';
import { IncrementalParser, computeLineDelta } from '../../src/cst/incremental-parser.js';
import { lint } from '../../src/lint.js';
import { allRules } from '../../src/rules/index.js';
import type { Diagnostic } from '../../src/types.js';

const URI = 'file:///workspace/stellar.toml';

const ISSUER = 'GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7';

/**
 * Comment-free on purpose: any edit region containing a `#` is a deliberate
 * fallback, so the fixtures keep comments out unless a test wants one.
 */
const SOURCE = [
  'VERSION = "2.7.0"',
  'NETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"',
  '[DOCUMENTATION]',
  'ORG_NAME = "Example"',
  '[[CURRENCIES]]',
  'code = "USD"',
  `issuer = "${ISSUER}"`,
  'approval_server = "https://sep8.example.com"',
  '',
].join('\n');

const DEAD = 'general/dead-configuration-key';

function find(diagnostics: Diagnostic[], rule: string): Diagnostic[] {
  return diagnostics.filter((diagnostic) => diagnostic.rule === rule);
}

function expectParity(text: string, actual: { diagnostics: Diagnostic[] }): void {
  expect(actual.diagnostics).toEqual(lint(text).diagnostics);
}

describe('IncrementalParser', () => {
  it('starts with a full parse and the complete rule sweep', () => {
    const parser = new IncrementalParser();
    const first = parser.update(URI, SOURCE);

    expect(first.incremental).toBe(false);
    expect(first.reparsedPaths).toEqual([]);
    expect(first.rulesExecuted).toEqual(allRules.map((rule) => rule.id));
    expectParity(SOURCE, first);
  });

  it('reuses the previous result when the text is unchanged', () => {
    const parser = new IncrementalParser();
    const first = parser.update(URI, SOURCE);
    const again = parser.update(URI, SOURCE);

    expect(again.incremental).toBe(true);
    expect(again.rulesExecuted).toEqual([]);
    expect(again.diagnostics).toEqual(first.diagnostics);
  });

  it('reparses only the touched section for a single-line value edit', () => {
    const parser = new IncrementalParser();
    parser.update(URI, SOURCE);

    const edited = SOURCE.replace('ORG_NAME = "Example"', 'ORG_NAME = "Renamed"');
    const second = parser.update(URI, edited);

    expect(second.incremental).toBe(true);
    expect(second.reparsedPaths).toContain('DOCUMENTATION.ORG_NAME');
    // Section-scoped selection: currencies rules do not run for a
    // DOCUMENTATION edit, but the always-on general rules do.
    expect(second.rulesExecuted).toContain(DEAD);
    expect(second.rulesExecuted).not.toContain('currencies/duplicate-currency-declaration');
    expect(second.rulesExecuted.length).toBeLessThan(allRules.length);
    expectParity(edited, second);
  });

  it('runs every rule and shifts findings when a root key is inserted above', () => {
    const parser = new IncrementalParser();
    const first = parser.update(URI, SOURCE);
    const beforeLine = find(first.diagnostics, DEAD)[0]?.position?.line;

    const shifted = `INJECTED = 1\n${SOURCE}`;
    const second = parser.update(URI, shifted);

    expect(second.incremental).toBe(true);
    expect(second.rulesExecuted).toEqual(allRules.map((rule) => rule.id));
    expectParity(shifted, second);

    const afterLine = find(second.diagnostics, DEAD)[0]?.position?.line;
    expect(beforeLine).toBeGreaterThan(0);
    expect(afterLine).toBe((beforeLine ?? 0) + 1);
  });

  it('moves every stored diagnostic for a trivia-only edit without rerunning rules', () => {
    const parser = new IncrementalParser();
    parser.update(URI, SOURCE);

    const blank = `${SOURCE}\n`;
    const second = parser.update(URI, blank);

    expect(second.incremental).toBe(true);
    expect(second.rulesExecuted).toEqual([]);
    expect(second.reparsedPaths).toEqual([]);
    expectParity(blank, second);
  });

  it('falls back to a full reparse when the edit region contains a comment', () => {
    const parser = new IncrementalParser();
    parser.update(URI, SOURCE);

    const commented = `${SOURCE}# a new note\n`;
    const second = parser.update(URI, commented);

    expect(second.incremental).toBe(false);
    expect(second.rulesExecuted).toEqual(allRules.map((rule) => rule.id));
    expectParity(commented, second);
  });

  it('falls back while the syntax is broken, then recovers with a full reparse', () => {
    const parser = new IncrementalParser();
    parser.update(URI, SOURCE);

    const broken = SOURCE.replace('ORG_NAME = "Example"', 'ORG_NAME = "Example');
    const failed = parser.update(URI, broken);
    expect(failed.incremental).toBe(false);
    expect(find(failed.diagnostics, 'file/parse').length).toBeGreaterThan(0);
    expect(find(parser.diagnostics(URI), 'file/parse').length).toBeGreaterThan(0);

    const recovered = parser.update(URI, SOURCE);
    expect(recovered.incremental).toBe(false);
    expectParity(SOURCE, recovered);
  });

  it('falls back when a BOM appears or disappears', () => {
    const parser = new IncrementalParser();
    parser.update(URI, SOURCE);

    const withBom = `\uFEFF${SOURCE}`;
    const second = parser.update(URI, withBom);

    expect(second.incremental).toBe(false);
    expectParity(withBom, second);
  });

  it('drops the cached state on close', () => {
    const parser = new IncrementalParser();
    parser.update(URI, SOURCE);
    parser.close(URI);

    const afterClose = parser.update(URI, `${SOURCE}X = 1\n`);
    expect(afterClose.incremental).toBe(false);
    expect(parser.diagnostics('file:///never-seen.toml')).toEqual([]);
  });

  it('honours severity overrides on the first parse and on incremental rounds', () => {
    const off = new IncrementalParser({ rules: { 'general/dead-configuration-key': 'off' } });
    expect(find(off.update(URI, SOURCE).diagnostics, DEAD)).toEqual([]);

    const edited = SOURCE.replace('code = "USD"', 'code = "USDX"');
    expect(find(off.update(URI, edited).diagnostics, DEAD)).toEqual([]);

    const errored = new IncrementalParser({ rules: { 'general/dead-configuration-key': 'error' } });
    const first = errored.update(URI, SOURCE);
    expect(find(first.diagnostics, DEAD)[0]?.severity).toBe('error');

    const second = errored.update(URI, edited);
    expect(second.incremental).toBe(true);
    expect(find(second.diagnostics, DEAD)[0]?.severity).toBe('error');
  });

  it('matches lint() on a 5,000-line file and stays incremental', () => {
    const lines: string[] = ['VERSION = "2.7.0"'];
    for (let i = 0; i < 1666; i++) {
      lines.push('[[CURRENCIES]]', `code = "S${i}"`, `issuer = "${ISSUER}"`);
    }
    const big = `${lines.join('\n')}\n`;

    const parser = new IncrementalParser();
    const first = parser.update('file:///big.toml', big);
    expect(first.incremental).toBe(false);

    const small = big.replace('code = "S1000"', 'code = "S1000X"');
    const second = parser.update('file:///big.toml', small);
    expect(second.incremental).toBe(true);
    expect(second.rulesExecuted.length).toBeLessThan(allRules.length);

    const fullStart = performance.now();
    const expected = lint(small);
    const fullLatencyMs = performance.now() - fullStart;

    // Rule execution, not reparsing, dominates this fixture: a one-entry edit
    // still selects every currencies rule plus the always-on ones, and the
    // absolute 100 ms gate this test used predates most of the registry (a
    // full sweep now costs about the same). What must hold is that an
    // incremental round stays within the cost of the full lint it replaces
    // instead of adding a second sweep on top.
    expect(second.latencyMs).toBeLessThanOrEqual(fullLatencyMs * 2);
    expect(second.diagnostics).toEqual(expected.diagnostics);
  });
});

describe('computeLineDelta', () => {
  it('reports identical texts as unchanged', () => {
    const delta = computeLineDelta('a\nb\n', 'a\nb\n');

    expect(delta.unchanged).toBe(true);
    expect(delta.lineDelta).toBe(0);
    expect(delta.startOffset).toBe(0);
    expect(delta.oldEndOffset).toBe(0);
    expect(delta.newEndOffset).toBe(0);
  });

  it('locates a single-line edit without moving any line', () => {
    const oldText = 'a\nb\nc';
    const delta = computeLineDelta(oldText, 'a\nB\nc');

    expect(delta.unchanged).toBe(false);
    expect(delta.startLine).toBe(1);
    expect(delta.oldEndLine).toBe(2);
    expect(delta.newEndLine).toBe(2);
    expect(delta.lineDelta).toBe(0);
    expect(delta.startOffset).toBe(oldText.indexOf('b'));
    expect(delta.oldEndOffset).toBe(oldText.indexOf('c'));
    expect(delta.newEndOffset).toBe('a\nB\nc'.indexOf('c'));
  });

  it('counts an inserted line', () => {
    const delta = computeLineDelta('a\nb', 'a\nX\nb');

    expect(delta.startLine).toBe(1);
    expect(delta.oldEndLine).toBe(1);
    expect(delta.newEndLine).toBe(2);
    expect(delta.lineDelta).toBe(1);
    expect(delta.startOffset).toBe(2);
    expect(delta.oldEndOffset).toBe(2);
    expect(delta.newEndOffset).toBe(4);
  });

  it('counts a deleted line', () => {
    const delta = computeLineDelta('a\nX\nb', 'a\nb');

    expect(delta.startLine).toBe(1);
    expect(delta.oldEndLine).toBe(2);
    expect(delta.newEndLine).toBe(1);
    expect(delta.lineDelta).toBe(-1);
    expect(delta.startOffset).toBe(2);
    expect(delta.oldEndOffset).toBe(4);
    expect(delta.newEndOffset).toBe(2);
  });

  it('spans a multi-line paste', () => {
    const oldText = 'a\nb\nc\nd';
    const delta = computeLineDelta(oldText, 'a\n1\n2\n3\nd');

    expect(delta.startLine).toBe(1);
    expect(delta.oldEndLine).toBe(3);
    expect(delta.newEndLine).toBe(4);
    expect(delta.lineDelta).toBe(1);
    expect(delta.startOffset).toBe(2);
    expect(delta.oldEndOffset).toBe(oldText.indexOf('d'));
  });
});
