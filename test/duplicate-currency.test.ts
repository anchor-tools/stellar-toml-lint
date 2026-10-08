import { describe, expect, it } from 'vitest';
import { lint } from '../src/lint.js';
import type { LintResult } from '../src/types.js';

function find(result: LintResult, rule: string) {
  return result.diagnostics.filter((diagnostic) => diagnostic.rule === rule);
}

const ACCOUNT_A = 'GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS';
const ACCOUNT_B = 'GC7T6T56DX23PT7Q6WGCTIJT5O6TP6SJ47RP73JCA3ISLVCCVMGHNSDI';

describe('currencies/duplicate-currency-declaration', () => {
  it('passes when currencies are distinct', () => {
    const source = [
      '[[CURRENCIES]]',
      'code="USD"',
      `issuer="${ACCOUNT_A}"`,
      'is_unlimited=true',
      '',
      '[[CURRENCIES]]',
      'code="EUR"',
      `issuer="${ACCOUNT_A}"`,
      'is_unlimited=true',
      '',
      '[[CURRENCIES]]',
      'code="USD"',
      `issuer="${ACCOUNT_B}"`,
      'is_unlimited=true',
    ].join('\n');

    const result = lint(source);
    expect(find(result, 'currencies/duplicate-currency-declaration')).toEqual([]);
  });

  it('asserts currencies/duplicate-currency-declaration on duplicate code and issuer', () => {
    const entry = `[[CURRENCIES]]\ncode="USD"\nissuer="${ACCOUNT_A}"\nis_unlimited=true`;
    const source = `${entry}\n\n${entry}`;

    const result = lint(source);
    const diagnostics = find(result, 'currencies/duplicate-currency-declaration');

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      severity: 'error',
      path: 'CURRENCIES[1]',
      rule: 'currencies/duplicate-currency-declaration',
    });
    expect(diagnostics[0]?.message).toContain('duplicates');
  });

  it('asserts currencies/duplicate-currency-declaration on duplicate native asset declarations', () => {
    const source = ['[[CURRENCIES]]', 'code="native"', '', '[[CURRENCIES]]', 'code="native"'].join(
      '\n',
    );

    const result = lint(source);
    const diagnostics = find(result, 'currencies/duplicate-currency-declaration');

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.path).toBe('CURRENCIES[1]');
  });
});
