import { describe, expect, it } from 'vitest';
import { lint } from '../src/lint.js';
import type { LintResult } from '../src/types.js';

function find(result: LintResult, rule: string) {
  return result.diagnostics.filter((diagnostic) => diagnostic.rule === rule);
}

function currency(code: string): string {
  return `[[CURRENCIES]]\ncode="${code}"\nissuer="GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS"\nis_unlimited=true`;
}

describe('Stellar asset code format', () => {
  it.each(['USD', 'USDC', 'BTC123456789'])('accepts %s', (code) => {
    const result = lint(currency(code));

    expect(find(result, 'currencies/invalid-asset-code-format')).toEqual([]);
    expect(find(result, 'currencies/asset-code-too-long')).toEqual([]);
  });

  it('rejects non-alphanumeric codes', () => {
    const result = lint(currency('USDT_V2'));
    const [diagnostic] = find(result, 'currencies/invalid-asset-code-format');

    expect(diagnostic).toMatchObject({
      severity: 'error',
      path: 'CURRENCIES[0].code',
    });
    expect(diagnostic?.message).toContain('USDT_V2');
  });

  it('rejects codes longer than 12 characters', () => {
    const result = lint(currency('TOOLONGASSETCODE123'));
    const [diagnostic] = find(result, 'currencies/asset-code-too-long');

    expect(diagnostic).toMatchObject({
      severity: 'error',
      path: 'CURRENCIES[0].code',
    });
  });

  it('accepts the native XLM asset', () => {
    const result = lint('[[CURRENCIES]]\ncode="XLM"');

    expect(find(result, 'currencies/invalid-asset-code-format')).toEqual([]);
    expect(find(result, 'currencies/asset-code-too-long')).toEqual([]);
  });
});
