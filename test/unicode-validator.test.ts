import { describe, expect, it } from 'vitest';
import {
  UnicodeLocalizationValidator,
  unicodeRuleIds,
  validateUnicode,
} from '../src/cst/unicodeValidator.js';

const ids = (doc: unknown): string[] => validateUnicode(doc).map((d) => d.rule);

describe('UnicodeLocalizationValidator', () => {
  it('registers its rule ids', () => {
    expect(unicodeRuleIds).toEqual([
      'unicode/bidi-override',
      'unicode/invisible-character',
      'unicode/homoglyph-spoofing',
      'unicode/invalid-language-tag',
    ]);
  });

  it('is silent on clean multilingual text', () => {
    const doc = {
      DOCUMENTATION: { ORG_NAME: 'Café Ünïcode 東京 Москва', ORG_DESCRIPTION: 'Привет' },
      CURRENCIES: [{ code: 'USDC', desc: 'Dólar estadounidense' }],
      ORG_URL: 'https://example.com',
    };
    expect(ids(doc)).toEqual([]);
  });

  it('errors immediately on bidi overrides', () => {
    for (const ch of ['‮', '‭', '⁦']) {
      const d = validateUnicode({ DOCUMENTATION: { ORG_NAME: `ab${ch}cd` } });
      expect(d).toHaveLength(1);
      expect(d[0]).toMatchObject({ rule: 'unicode/bidi-override', severity: 'error' });
      expect(d[0]?.path).toBe('DOCUMENTATION.ORG_NAME');
    }
  });

  it('detects bidi characters in keys and nested arrays', () => {
    expect(ids({ 'A‮B': 'x' })).toEqual(['unicode/bidi-override']);
    expect(ids({ CURRENCIES: [{ desc: 'a‮b' }] })).toEqual(['unicode/bidi-override']);
  });

  it('warns on zero-width characters', () => {
    expect(ids({ ORG_NAME: 'Acme​Corp' })).toEqual(['unicode/invisible-character']);
    expect(ids({ ORG_NAME: 'Acme﻿' })).toEqual(['unicode/invisible-character']);
  });

  it('detects homoglyphs in domains and asset codes only', () => {
    expect(ids({ ORG_URL: 'https://exаmple.com' })).toEqual(['unicode/homoglyph-spoofing']);
    expect(ids({ CURRENCIES: [{ code: 'USDС' }] })).toEqual(['unicode/homoglyph-spoofing']);
    expect(ids({ ORG_NAME: 'Аcme' })).toEqual([]);
  });

  it('validates language tags', () => {
    for (const ok of ['en', 'es', 'fr', 'pt-BR', 'zh-Hant-TW']) {
      expect(ids({ lang: ok })).toEqual([]);
    }
    for (const bad of ['english', 'EN', 'pt_BR', 'e']) {
      expect(ids({ lang: bad })).toEqual(['unicode/invalid-language-tag']);
    }
  });

  it('honours rule overrides', () => {
    const doc = { ORG_NAME: 'a‮b', lang: 'xx_YY' };
    const d = new UnicodeLocalizationValidator({
      rules: { 'unicode/bidi-override': 'off', 'unicode/invalid-language-tag': 'error' },
    }).validate(doc);
    expect(d.map((x) => [x.rule, x.severity])).toEqual([['unicode/invalid-language-tag', 'error']]);
  });
});
