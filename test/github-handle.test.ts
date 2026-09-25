import { describe, expect, it } from 'vitest';
import { lint } from '../src/lint.js';
import { githubHandleProblem } from '../src/rules/github-handle.js';

const RULE = 'general/invalid-github-handle';

function docSource(handle: string): string {
  return ['[DOCUMENTATION]', 'ORG_NAME="Example Anchor"', `ORG_GITHUB="${handle}"`, ''].join('\n');
}

function handleDiagnostics(handle: string) {
  return lint(docSource(handle)).diagnostics.filter((d) => d.rule === RULE);
}

describe('general/invalid-github-handle', () => {
  it.each(['stellar', 'https://github.com/stellar', 'https://github.com/stellar/'])(
    'accepts %s',
    (handle) => {
      expect(handleDiagnostics(handle)).toEqual([]);
    },
  );

  it('flags a handle wrapped in hyphens', () => {
    const [diagnostic] = handleDiagnostics('-invalid-');
    expect(diagnostic?.rule).toBe(RULE);
    expect(diagnostic?.severity).toBe('warning');
    expect(diagnostic?.path).toBe('DOCUMENTATION.ORG_GITHUB');
    expect(diagnostic?.message).toBe(
      'DOCUMENTATION.ORG_GITHUB must not start or end with a hyphen',
    );
  });

  it.each([
    ['in--valid', 'consecutive hyphens'],
    ['@stellar', 'characters GitHub does not allow'],
    ['a'.repeat(40), '39-character limit'],
  ])('flags %s', (handle, reason) => {
    expect(handleDiagnostics(handle)[0]?.message).toContain(reason);
  });

  it.each([
    'https://gitlab.com/stellar',
    'http://github.com/stellar',
    'https://github.com/stellar/stellar-toml-lint',
    'github.com/stellar',
  ])('flags the non-profile URL %s', (url) => {
    expect(handleDiagnostics(url)).toHaveLength(1);
  });

  it('flags an empty value', () => {
    const [diagnostic] = handleDiagnostics('');
    expect(diagnostic?.message).toContain('is empty');
  });

  it('stays silent when ORG_GITHUB is absent', () => {
    expect(lint('[DOCUMENTATION]\nORG_NAME="Example Anchor"\n').diagnostics).not.toContainEqual(
      expect.objectContaining({ rule: RULE }),
    );
  });

  it('does not touch ORG_TWITTER, which has its own rule for the bare handle', () => {
    const source = '[DOCUMENTATION]\nORG_TWITTER="https://twitter.com/exampleanchor"\n';
    const rules = lint(source).diagnostics.map((d) => d.rule);
    expect(rules).toContain('general/invalid-twitter-handle');
    expect(rules).not.toContain(RULE);
  });
});

describe('githubHandleProblem', () => {
  it('accepts a username and unwraps a profile URL to the same handle', () => {
    expect(githubHandleProblem('stellar')).toBeUndefined();
    expect(githubHandleProblem('https://github.com/stellar')).toBeUndefined();
  });

  it('reports the reason rather than normalizing a bad value', () => {
    expect(githubHandleProblem('-invalid-')).toBe('must not start or end with a hyphen');
    expect(githubHandleProblem('https://github.com/stellar/repo')).toBe(
      'must be a github.com profile URL, not a repository',
    );
  });
});
