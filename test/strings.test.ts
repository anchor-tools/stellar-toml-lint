import { describe, expect, it } from 'vitest';
import { trimTrailingSlashes } from '../src/strings.js';

describe('trimTrailingSlashes', () => {
  it('removes only trailing slashes', () => {
    expect(trimTrailingSlashes('https://a.example/sep6///')).toBe('https://a.example/sep6');
    expect(trimTrailingSlashes('https://a.example/sep6')).toBe('https://a.example/sep6');
    expect(trimTrailingSlashes('a//b/')).toBe('a//b');
    expect(trimTrailingSlashes('////')).toBe('');
    expect(trimTrailingSlashes('')).toBe('');
  });

  it('stays linear on many non-trailing slashes (no ReDoS)', () => {
    const hostile = `a${'/'.repeat(200_000)}b`;
    const start = performance.now();
    expect(trimTrailingSlashes(hostile)).toBe(hostile);
    expect(performance.now() - start).toBeLessThan(100);
  });
});
