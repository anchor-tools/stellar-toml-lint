import { describe, expect, it } from 'vitest';
import { lint } from '../src/lint.js';
import { allRules } from '../src/rules/index.js';
import type { LintResult } from '../src/types.js';

function find(result: LintResult, rule: string) {
  return result.diagnostics.filter((diagnostic) => diagnostic.rule === rule);
}

const MIXED = [
  'NETWORK_PASSPHRASE = "Test SDF Network ; September 2015"',
  '',
  '[[CURRENCIES]]',
  '\tcode = "USDC"',
  '    issuer = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"',
  '',
].join('\n');

const CLEAN = ['[DOCUMENTATION]', '  ORG_NAME = "Example"', ''].join('\n');

describe('style/mixed-indentation', () => {
  it('warns when a file mixes tabs and spaces', () => {
    const diagnostics = find(lint(MIXED), 'style/mixed-indentation');
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      severity: 'warning',
      category: 'style',
      rule: 'style/mixed-indentation',
    });
  });

  it('stays silent on a consistently indented file', () => {
    expect(find(lint(CLEAN), 'style/mixed-indentation')).toEqual([]);
  });

  it('can be silenced with --off', () => {
    const result = lint(MIXED, { rules: { 'style/mixed-indentation': 'off' } });
    expect(find(result, 'style/mixed-indentation')).toEqual([]);
  });
});

describe('style/misaligned-table-key', () => {
  it('warns when sibling keys in a table disagree on indentation', () => {
    const diagnostics = find(lint(MIXED), 'style/misaligned-table-key');
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      severity: 'warning',
      category: 'style',
      rule: 'style/misaligned-table-key',
    });
    expect(diagnostics[0]?.position?.line).toBe(5);
  });

  it('stays silent when every sibling lines up', () => {
    expect(find(lint(CLEAN), 'style/misaligned-table-key')).toEqual([]);
  });
});

describe('style rules registration', () => {
  it('registers both rules so --list-rules and --off know them', () => {
    const ids = allRules.map((rule) => rule.id);
    expect(ids).toContain('style/mixed-indentation');
    expect(ids).toContain('style/misaligned-table-key');
  });

  it('never attaches a fix — reindenting is a whole-file rewrite', () => {
    for (const diagnostic of lint(MIXED).diagnostics) {
      if (diagnostic.rule.startsWith('style/')) {
        expect(diagnostic.fix).toBeUndefined();
      }
    }
  });
});
