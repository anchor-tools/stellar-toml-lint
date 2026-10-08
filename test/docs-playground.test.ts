import { describe, expect, it } from 'vitest';
import { SAMPLES, hashForSource, sourceFromHash } from '../docs/playground.js';
import { lint } from '../src/lint.js';

describe('documentation playground samples', () => {
  it('offers the four named client-side templates', () => {
    expect(Object.keys(SAMPLES)).toEqual([
      'Minimal Issuer',
      'SEP-24 Anchor',
      'Validator Node',
      'Broken TOML',
    ]);
  });

  it.each(['Minimal Issuer', 'SEP-24 Anchor', 'Validator Node'] as const)(
    '%s has no lint errors',
    (name) => {
      expect(lint(SAMPLES[name] ?? '').counts.error).toBe(0);
    },
  );

  it('makes Broken TOML produce positioned rule diagnostics', () => {
    const result = lint(SAMPLES['Broken TOML']);
    expect(result.counts.error).toBeGreaterThan(0);
    expect(result.diagnostics.every((diagnostic) => diagnostic.rule.length > 0)).toBe(true);
    expect(result.diagnostics.some((diagnostic) => diagnostic.position?.line !== undefined)).toBe(
      true,
    );
    expect(result.diagnostics.some((diagnostic) => diagnostic.suggestion)).toBe(true);
  });
});

describe('playground hash state', () => {
  it('round-trips TOML without putting it outside the hash', () => {
    const source = 'ORG_NAME="Northstar & Company"\n[DOCUMENTATION]';
    const hash = hashForSource(source);
    expect(hash.startsWith('#toml=')).toBe(true);
    expect(sourceFromHash(hash)).toBe(source);
  });

  it('ignores absent and malformed state', () => {
    expect(sourceFromHash('')).toBeUndefined();
    expect(sourceFromHash('#toml=%E0%A4%A')).toBeUndefined();
  });
});
