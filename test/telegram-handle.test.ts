import { describe, expect, it } from 'vitest';
import { lint } from '../src/lint.js';
import { telegramHandleProblem } from '../src/rules/telegram-handle.js';

const RULE = 'general/invalid-telegram-handle';

function docSource(handle: string): string {
  return ['[DOCUMENTATION]', 'ORG_NAME="Example Anchor"', `ORG_TELEGRAM="${handle}"`, ''].join('\n');
}

function handleDiagnostics(handle: string) {
  return lint(docSource(handle)).diagnostics.filter((d) => d.rule === RULE);
}

describe('general/invalid-telegram-handle', () => {
  it.each([
    'example_anchor',
    '@example_anchor',
    'https://t.me/example_anchor',
    't.me/example_anchor',
    'https://telegram.me/example_anchor',
  ])('accepts %s', (handle) => {
    expect(handleDiagnostics(handle)).toEqual([]);
  });

  it('flags a handle shorter than 5 characters', () => {
    const [diagnostic] = handleDiagnostics('abc');
    expect(diagnostic?.rule).toBe(RULE);
    expect(diagnostic?.severity).toBe('warning');
    expect(diagnostic?.path).toBe('DOCUMENTATION.ORG_TELEGRAM');
    expect(diagnostic?.message).toContain("shorter than Telegram's 5-character limit");
  });

  it.each([
    ['a'.repeat(33), '32-character limit'],
    ['invalid-handle!', 'characters Telegram does not allow'],
  ])('flags %s', (handle, reason) => {
    expect(handleDiagnostics(handle)[0]?.message).toContain(reason);
  });

  it.each([
    'https://example.com/example_anchor',
    'http://invalid-site.org/example_anchor',
  ])('flags the non-profile URL %s', (url) => {
    expect(handleDiagnostics(url)).toHaveLength(1);
  });

  it('flags an empty value', () => {
    const [diagnostic] = handleDiagnostics('');
    expect(diagnostic?.message).toContain('is empty');
  });

  it('stays silent when ORG_TELEGRAM is absent', () => {
    expect(lint('[DOCUMENTATION]\nORG_NAME="Example Anchor"\n').diagnostics).not.toContainEqual(
      expect.objectContaining({ rule: RULE }),
    );
  });
});

describe('telegramHandleProblem', () => {
  it('accepts a valid username and unwraps a profile URL to the same handle', () => {
    expect(telegramHandleProblem('example_anchor')).toBeUndefined();
    expect(telegramHandleProblem('https://t.me/example_anchor')).toBeUndefined();
  });

  it('reports the reason rather than normalizing a bad value', () => {
    expect(telegramHandleProblem('abc')).toBe("is shorter than Telegram's 5-character limit");
    expect(telegramHandleProblem('https://example.com/anchor')).toBe(
      'must be a https://t.me/<handle> profile URL or Telegram handle',
    );
  });
});
