import { describe, expect, it } from 'vitest';
import { lint } from '../src/lint.js';
import { twitterHandleProblem } from '../src/rules/twitter-handle.js';

const RULE = 'general/invalid-twitter-handle';

function docSource(handle: string): string {
  return ['[DOCUMENTATION]', 'ORG_NAME="Example Anchor"', `ORG_TWITTER="${handle}"`, ''].join('\n');
}

function handleDiagnostics(handle: string) {
  return lint(docSource(handle)).diagnostics.filter((d) => d.rule === RULE);
}

describe('general/invalid-twitter-handle', () => {
  it.each(['stellarorg', 'StellarOrg', 'stellar_org', 'a'.repeat(15)])(
    'accepts the bare handle %s',
    (handle) => {
      expect(handleDiagnostics(handle)).toEqual([]);
    },
  );

  it('flags a leading @ and offers the bare handle as a fix', () => {
    const [diagnostic] = handleDiagnostics('@stellarorg');
    expect(diagnostic?.rule).toBe(RULE);
    expect(diagnostic?.severity).toBe('warning');
    expect(diagnostic?.path).toBe('DOCUMENTATION.ORG_TWITTER');
    expect(diagnostic?.message).toBe('DOCUMENTATION.ORG_TWITTER must not include a leading @');
    expect(diagnostic?.suggestion).toBe('Use the bare handle, e.g. "stellarorg".');
    expect(diagnostic?.fix).toEqual({ value: 'stellarorg' });
  });

  it.each([
    'https://x.com/stellarorg',
    'https://twitter.com/stellarorg',
    'https://www.twitter.com/stellarorg/',
    'https://mobile.twitter.com/stellarorg',
  ])('flags the profile URL %s and offers the extracted handle', (url) => {
    const [diagnostic] = handleDiagnostics(url);
    expect(diagnostic?.rule).toBe(RULE);
    expect(diagnostic?.severity).toBe('warning');
    expect(diagnostic?.message).toBe('DOCUMENTATION.ORG_TWITTER must be a bare handle, not a URL');
    expect(diagnostic?.suggestion).toBe('Use the bare handle, e.g. "stellarorg".');
    expect(diagnostic?.fix).toEqual({ value: 'stellarorg' });
  });

  it.each([
    ['waytoolonghandle', '15-character limit'],
    ['bad-handle', 'characters Twitter/X does not allow'],
    ['handle.name', 'characters Twitter/X does not allow'],
    ['', 'is empty'],
  ])('flags %s', (handle, reason) => {
    const [diagnostic] = handleDiagnostics(handle);
    expect(diagnostic?.rule).toBe(RULE);
    expect(diagnostic?.message).toContain(reason);
    expect(diagnostic?.suggestion).toBeTruthy();
  });

  it.each([
    'https://example.com/stellarorg',
    'http://twitter.com/stellarorg',
    'https://x.com/stellarorg/status/1234567890',
    'twitter.com/stellarorg',
  ])('flags the non-profile URL %s', (url) => {
    expect(handleDiagnostics(url)).toHaveLength(1);
  });

  it('never offers a fix that would still be flagged', () => {
    // The @ unwraps, but the handle underneath is longer than 15 characters.
    const [diagnostic] = handleDiagnostics('@waytoolonghandle');
    expect(diagnostic?.message).toContain('leading @');
    expect(diagnostic?.fix).toBeUndefined();
  });

  it('stays silent when ORG_TWITTER is absent', () => {
    expect(lint('[DOCUMENTATION]\nORG_NAME="Example Anchor"\n').diagnostics).not.toContainEqual(
      expect.objectContaining({ rule: RULE }),
    );
  });

  it('does not touch ORG_GITHUB, which has its own rule', () => {
    const source = '[DOCUMENTATION]\nORG_GITHUB="https://github.com/stellar"\n';
    const ruleIds = lint(source).diagnostics.map((d) => d.rule);
    expect(ruleIds).not.toContain(RULE);
  });
});

describe('twitterHandleProblem', () => {
  it('accepts a bare handle', () => {
    expect(twitterHandleProblem('stellarorg')).toBeUndefined();
    expect(twitterHandleProblem('stellar_org')).toBeUndefined();
  });

  it('reports the reason rather than normalizing a bad value', () => {
    expect(twitterHandleProblem('@stellarorg')).toBe('must not include a leading @');
    expect(twitterHandleProblem('https://x.com/stellarorg')).toBe(
      'must be a bare handle, not a URL',
    );
    expect(twitterHandleProblem('a'.repeat(16))).toBe(
      "is longer than Twitter/X's 15-character limit",
    );
    expect(twitterHandleProblem('')).toBe('is empty');
  });
});
