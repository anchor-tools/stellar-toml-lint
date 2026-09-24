import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { XMLParser, XMLValidator } from 'fast-xml-parser';
import { lint } from '../src/lint.js';
import { formatJunit } from '../src/reporters.js';
import type { LintResult } from '../src/types.js';

const here = dirname(fileURLToPath(import.meta.url));
/** A file that produces zero diagnostics, for the empty-suite case. */
const CLEAN = readFileSync(join(here, 'fixtures', 'valid.toml'), 'utf8');

const BROKEN = 'VERSION="two"\nSIGNING_KEY="nope"\n';

/** An asset code we know the rules quote back at us, markup characters and all. */
const MARKUP = '[[CURRENCIES]]\ncode = "<&>"\n';

/**
 * Parses the reporter's output the way a CI dashboard would.
 *
 * `isArray` is what makes one-element suites predictable: without it a
 * `testcase` child collapses into a bare object and every assertion below would
 * have to branch on the number of findings.
 */
function parseXml(xml: string): any {
  return new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: '@_',
    parseAttributeValue: true,
    isArray: (name: string) => name === 'testcase',
  }).parse(xml);
}

function suiteOf(result: LintResult, filename = 'stellar.toml'): any {
  const doc = parseXml(formatJunit(result, filename));
  return { doc, suite: doc.testsuites.testsuite };
}

describe('formatJunit', () => {
  it('emits well-formed XML that a standard parser accepts', () => {
    expect(XMLValidator.validate(formatJunit(lint(BROKEN), 'stellar.toml'))).toBe(true);
    expect(XMLValidator.validate(formatJunit(lint(CLEAN), 'stellar.toml'))).toBe(true);
    expect(XMLValidator.validate(formatJunit(lint(MARKUP), 'stellar.toml'))).toBe(true);
  });

  it('names the suites and counts the diagnostics', () => {
    const result = lint(BROKEN);
    const { doc, suite } = suiteOf(result, 'public/.well-known/stellar.toml');

    expect(doc.testsuites['@_name']).toBe('stellar-toml-lint');
    expect(doc.testsuites['@_tests']).toBe(result.diagnostics.length);
    expect(doc.testsuites['@_failures']).toBe(result.counts.error);
    expect(doc.testsuites['@_errors']).toBe(result.counts.warning + result.counts.info);

    // The file itself is the suite, so dashboards show it by name.
    expect(suite['@_name']).toBe('public/.well-known/stellar.toml');
    expect(suite['@_tests']).toBe(result.diagnostics.length);
    expect(suite['@_skipped']).toBe(0);
  });

  it('emits one testcase per diagnostic, named after its rule', () => {
    const result = lint(BROKEN);
    const { suite } = suiteOf(result);

    expect(suite.testcase).toHaveLength(result.diagnostics.length);
    const names = suite.testcase.map((c: any) => c['@_name']);
    for (const diagnostic of result.diagnostics) {
      expect(names).toContain(diagnostic.rule);
    }
  });

  it('records error-severity findings as failures and the rest as errors', () => {
    // Exit code 1 is driven by errors alone, so a dashboard counting failures
    // has to agree with it — warnings stay visible without claiming a failure.
    const result = lint(BROKEN);
    expect(result.counts.warning).toBeGreaterThan(0);
    const { suite } = suiteOf(result);

    const withFailure = suite.testcase.filter((c: any) => c.failure !== undefined);
    const withError = suite.testcase.filter((c: any) => c.error !== undefined);

    expect(withFailure).toHaveLength(result.counts.error);
    expect(withError).toHaveLength(result.counts.warning + result.counts.info);
    expect(withFailure.length + withError.length).toBe(result.diagnostics.length);
  });

  it('carries the message, suggestion, help link and position', () => {
    const result = lint(BROKEN);
    const { suite } = suiteOf(result, 'stellar.toml');
    const errors = suite.testcase.filter((c: any) => c.failure !== undefined);

    for (const testcase of errors) {
      const diagnostic = result.diagnostics.find((d) => d.rule === testcase['@_name']);
      expect(diagnostic).toBeDefined();

      // The body is exactly the message plus whatever extra guidance exists:
      // an exact match is what catches stray separators leaking between the
      // lines of the element.
      const expected = [diagnostic?.message, diagnostic?.suggestion, diagnostic?.helpUri]
        .filter((part): part is string => part !== undefined)
        .join('\n');

      expect(testcase.failure['@_type']).toBe('error');
      expect(testcase.failure['@_message']).toBe(diagnostic?.message);
      expect(testcase.failure['#text']).toBe(expected);
      if (diagnostic?.helpUri) expect(testcase.failure['#text']).toContain(diagnostic.helpUri);
      if (diagnostic?.position) expect(testcase['@_line']).toBe(diagnostic.position.line);
      expect(testcase['@_file']).toBe('stellar.toml');
    }
  });

  it('escapes markup in values quoted out of the file', () => {
    const result = lint(MARKUP);
    const offending = result.diagnostics.find((d) => d.message.includes('<&>'));
    expect(offending).toBeDefined();

    const xml = formatJunit(result, 'stellar.toml');
    expect(XMLValidator.validate(xml)).toBe(true);
    // The value survives the round trip intact rather than becoming markup.
    expect(xml).toContain('&lt;&amp;&gt;');
    expect(
      parseXml(xml).testsuites.testsuite.testcase.map((c: any) => c.failure ?? c.error),
    ).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ '@_message': offending?.message, '#text': expect.any(String) }),
      ]),
    );
  });

  it('drops characters XML 1.0 cannot carry, keeping the rest intact', () => {
    // A single stray control byte makes a parser reject the whole document, so
    // it is replaced rather than trusted not to appear. Astral characters are
    // a code point like any other and have to survive that pass.
    const result: LintResult = {
      diagnostics: [
        {
          rule: 'file/encoding',
          severity: 'error',
          category: 'file',
          message: 'value contains a NUL:\u0000 and an emoji: \u{1F525}',
        },
      ],
      ok: false,
      counts: { error: 1, warning: 0, info: 0 },
    };

    const xml = formatJunit(result, 'a.toml');
    expect(XMLValidator.validate(xml)).toBe(true);
    expect(xml).not.toContain('\u0000');
    expect(xml).toContain('\uFFFD');
    expect(xml).toContain('\u{1F525}');
  });

  it('reports a clean file as an empty suite', () => {
    const { doc, suite } = suiteOf(lint(CLEAN), 'a.toml');

    expect(doc.testsuites['@_tests']).toBe(0);
    expect(doc.testsuites['@_failures']).toBe(0);
    expect(doc.testsuites['@_errors']).toBe(0);
    expect(suite.testcase).toBeUndefined();
    expect(XMLValidator.validate(formatJunit(lint(CLEAN), 'a.toml'))).toBe(true);
  });

  it('defaults the filename, like the other reporters', () => {
    expect(formatJunit(lint(BROKEN))).toContain('<testsuite name="stellar.toml"');
  });
});
