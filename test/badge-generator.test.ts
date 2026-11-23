import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { lint } from '../src/lint.js';
import { generateBadgeSvg, generateShieldsEndpoint } from '../src/generators/badge.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string): string => readFileSync(join(here, 'fixtures', name), 'utf8');

describe('badge generator', () => {
  describe('clean TOML', () => {
    const result = lint(fixture('valid.toml'), { domain: 'example.com' });

    it('produces a green Shields.io endpoint', () => {
      const endpoint = generateShieldsEndpoint(result);
      expect(endpoint.schemaVersion).toBe(1);
      expect(endpoint.label).toBe('stellar.toml');
      expect(endpoint.message).toBe('100%');
      expect(endpoint.color).toBe('brightgreen');
    });

    it('produces a valid SVG string', () => {
      const svg = generateBadgeSvg(result);
      expect(svg).toContain('<svg');
      expect(svg).toContain('stellar.toml');
      expect(svg).toContain('100%');
    });
  });

  describe('TOML with errors', () => {
    const result = lint(fixture('broken.toml'));

    it('produces a red badge with error count', () => {
      const endpoint = generateShieldsEndpoint(result);
      expect(endpoint.color).toBe('red');
      expect(endpoint.message).toMatch(/error/);
    });

    it('produces SVG with error info', () => {
      const svg = generateBadgeSvg(result);
      expect(svg).toContain('<svg');
      expect(svg).toContain('error');
    });
  });
});
