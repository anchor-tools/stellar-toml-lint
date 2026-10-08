import { describe, expect, it } from 'vitest';
import { lint } from '../src/lint.js';
import { applyFixes } from '../src/fix.js';
import type { LintResult } from '../src/types.js';

function find(result: LintResult, rule: string) {
  return result.diagnostics.filter((diagnostic) => diagnostic.rule === rule);
}

describe('general/untrimmed-string-value', () => {
  it('passes when string values have no leading or trailing whitespace', () => {
    const source = [
      'VERSION="2.7.0"',
      'NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"',
      'ORG_NAME="Example Anchor"',
      '[[CURRENCIES]]',
      'code="USD"',
      'issuer="GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS"',
    ].join('\n');

    const result = lint(source);
    expect(find(result, 'general/untrimmed-string-value')).toEqual([]);
  });

  it('asserts general/untrimmed-string-value on leading or trailing whitespace', () => {
    const source = 'ORG_NAME=" Example Anchor "';
    const result = lint(source);
    const diagnostics = find(result, 'general/untrimmed-string-value');

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      severity: 'warning',
      rule: 'general/untrimmed-string-value',
      path: 'ORG_NAME',
    });
    expect(diagnostics[0]?.message).toContain('ORG_NAME');
  });

  it('autofixes string values by trimming whitespace', () => {
    const source = 'ORG_NAME=" Example Anchor "';
    const result = lint(source);
    const fixed = applyFixes(source, result.diagnostics);

    expect(fixed).toBe('ORG_NAME="Example Anchor"');
  });
});
