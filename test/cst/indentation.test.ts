import { describe, expect, it } from 'vitest';

import {
  auditIndentation,
  detectIndentation,
  indentUnit,
  isIndentStyle,
  normalizeIndentation,
} from '../../src/cst/indentation.js';
import { parseCst } from '../../src/cst/parser.js';
import { parse } from 'smol-toml';

/** Two-space indented document with a nested table and an array. */
const CLEAN = [
  'VERSION = "2.7.0"',
  'ACCOUNTS = [',
  '  "GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS",',
  '  "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5",',
  ']',
  '',
  '[DOCUMENTATION]',
  '  ORG_NAME = "Example"',
  '',
].join('\n');

/** Tab-indented equivalent of {@link CLEAN}, at depth one. */
const TABBED = CLEAN.replace(/^ {2}/gm, '\t');

/** The same keys, but some lines use tabs and others use spaces. */
const MIXED = [
  'NETWORK_PASSPHRASE = "Test SDF Network ; September 2015"',
  '',
  '[[CURRENCIES]]',
  '\tcode = "USDC"',
  '    issuer = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"',
  '',
].join('\n');

describe('detectIndentation', () => {
  it('recognises an all-spaces file as 2-space', () => {
    const report = detectIndentation(CLEAN);
    expect(report.mixed).toBe(false);
    expect(report.style).toBe('2');
    expect(report.tabLines).toBe(0);
    expect(report.spaceLines).toBeGreaterThan(0);
  });

  it('recognises an all-tabs file as tabs', () => {
    const report = detectIndentation(TABBED);
    expect(report.mixed).toBe(false);
    expect(report.style).toBe('tabs');
    expect(report.spaceLines).toBe(0);
  });

  it('flags a file that mixes tabs and spaces', () => {
    const report = detectIndentation(MIXED);
    expect(report.mixed).toBe(true);
    expect(report.style).toBe('mixed');
    expect(report.tabLines).toBeGreaterThan(0);
    expect(report.spaceLines).toBeGreaterThan(0);
  });

  it('does not count a tab embedded inside a multi-line string', () => {
    const source = ['ORG_DESCRIPTION = """', '\tcontent is not indentation', '"""', ''].join('\n');
    const report = detectIndentation(source);
    expect(report.tabLines).toBe(0);
    expect(report.spaceLines).toBe(0);
  });
});

describe('auditIndentation', () => {
  it('reports style/mixed-indentation for a mixed file', () => {
    const findings = auditIndentation(MIXED);
    expect(findings.some((f) => f.rule === 'style/mixed-indentation')).toBe(true);
  });

  it('reports style/misaligned-table-key when siblings disagree', () => {
    const findings = auditIndentation(MIXED);
    const misaligned = findings.find((f) => f.rule === 'style/misaligned-table-key');
    expect(misaligned).toBeDefined();
    expect(misaligned?.position.line).toBe(5);
  });

  it('stays silent on a consistently indented file', () => {
    expect(auditIndentation(CLEAN)).toEqual([]);
    expect(auditIndentation(TABBED)).toEqual([]);
  });
});

describe('normalizeIndentation', () => {
  it('normalizes mixed indentation into clean 2-space style', () => {
    const { output, changed } = normalizeIndentation(MIXED, '2');
    expect(changed).toBe(true);
    expect(output).toBe(
      [
        'NETWORK_PASSPHRASE = "Test SDF Network ; September 2015"',
        '',
        '[[CURRENCIES]]',
        '  code = "USDC"',
        '  issuer = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"',
        '',
      ].join('\n'),
    );
  });

  it('normalizes tabs to 4 spaces', () => {
    const { output } = normalizeIndentation(TABBED, '4');
    expect(output).toContain('\n    ORG_NAME = "Example"');
    expect(output).not.toContain('\t');
  });

  it('normalizes spaces to tabs', () => {
    const { output } = normalizeIndentation(CLEAN, 'tabs');
    expect(output).toContain('\n\tORG_NAME = "Example"');
  });

  it('leaves an already-clean file byte-for-byte unchanged', () => {
    const { output, changed } = normalizeIndentation(CLEAN, '2');
    expect(changed).toBe(false);
    expect(output).toBe(CLEAN);
  });

  it('is idempotent', () => {
    const once = normalizeIndentation(MIXED, '2').output;
    const twice = normalizeIndentation(once, '2');
    expect(twice.changed).toBe(false);
    expect(twice.output).toBe(once);
  });

  it('round-trips: normalization does not change the parsed document', () => {
    const { output } = normalizeIndentation(MIXED, '2');
    expect(parseCst(output).errors).toEqual([]);
    expect(parse(output)).toEqual(parse(MIXED));
  });

  it('keeps multi-line string contents untouched', () => {
    const source = [
      'ORG_DESCRIPTION = """',
      '\tkeep this tab',
      '"""',
      '',
      '\tORG_NAME = "X"',
      '',
    ].join('\n');
    const { output } = normalizeIndentation(source, '2');
    expect(output).toContain('"""\n\tkeep this tab\n"""');
    expect(output).toContain('\n  ORG_NAME = "X"');
  });

  it('defaults to the file’s dominant style', () => {
    const { output } = normalizeIndentation(MIXED.replace(/\t/g, '  '));
    expect(output).toContain('\n  code = "USDC"');
  });

  it('preserves entry structure through a round-trip', () => {
    const before = parseCst(MIXED).entries.map((e) => e.kind);
    const after = parseCst(normalizeIndentation(MIXED, '2').output).entries.map((e) => e.kind);
    expect(after).toEqual(before);
  });
});

describe('helpers', () => {
  it('indentUnit maps a style to its whitespace', () => {
    expect(indentUnit('2')).toBe('  ');
    expect(indentUnit('4')).toBe('    ');
    expect(indentUnit('tabs')).toBe('\t');
  });

  it('isIndentStyle accepts only the three documented values', () => {
    expect(isIndentStyle('2')).toBe(true);
    expect(isIndentStyle('4')).toBe(true);
    expect(isIndentStyle('tabs')).toBe(true);
    expect(isIndentStyle('3')).toBe(false);
    expect(isIndentStyle('spaces')).toBe(false);
  });
});
