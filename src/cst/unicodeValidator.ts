/**
 * Unicode security and localization validator.
 *
 * Runs under opt-in `--audit-unicode-security`.
 *
 * Follows Unicode Technical Report #36 (Security Considerations): bidirectional
 * override characters (Trojan Source), invisible formatting characters, and
 * mixed-script confusables can make a URL or an asset code read as something
 * other than what a wallet will actually resolve.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isString } from '../predicates.js';

const BIDI_RULE = 'unicode/bidi-override';
const INVISIBLE_RULE = 'unicode/invisible-character';
const HOMOGLYPH_RULE = 'unicode/homoglyph-spoofing';
const LANGUAGE_TAG_RULE = 'unicode/invalid-language-tag';

const SPEC = 'https://www.unicode.org/reports/tr36/';

/** Embeddings, overrides, isolates and marks that reorder displayed text. */
const BIDI_CONTROLS = /[؜‎‏‪-‮⁦-⁩]/u;
/** Zero-width and other invisible formatting characters. */
const INVISIBLE = /[­͏᠎​-‍⁠-⁤﻿]/u;

/** Cyrillic and Greek letters that render identically to a Latin letter. */
const CONFUSABLE = /[Ͱ-ϿЀ-ӿ]/u;
const LATIN = /[A-Za-z]/u;

/** Keys whose values are identifiers, so mixed scripts are never legitimate. */
const IDENTIFIER_KEYS = new Set([
  'code',
  'ORG_URL',
  'ORG_DBA',
  'HORIZON_URL',
  'TRANSFER_SERVER',
  'TRANSFER_SERVER_SEP0024',
  'KYC_SERVER',
  'WEB_AUTH_ENDPOINT',
  'ANCHOR_QUOTE_SERVER',
  'FEDERATION_SERVER',
  'AUTH_SERVER',
]);

/** BCP 47 subset used by SEP-1 localization: `en`, `es`, `pt-BR`, `zh-Hant-TW`. */
const LANGUAGE_TAG = /^[a-z]{2,3}(-[A-Z][a-z]{3})?(-([A-Z]{2}|\d{3}))?$/u;
const LANGUAGE_KEYS = new Set(['lang', 'language', 'locale', 'languages', 'locales']);

export interface UnicodeValidatorOptions {
  rules?: RuleOverrides;
}

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules?: RuleOverrides,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

function codePoint(ch: string): string {
  return `U+${ch.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}`;
}

/** Scans every key and string value of a parsed stellar.toml. */
export class UnicodeLocalizationValidator {
  constructor(private readonly options: UnicodeValidatorOptions = {}) {}

  validate(doc: unknown): Diagnostic[] {
    const out: Diagnostic[] = [];
    this.walk(doc, '', '', out);
    return out;
  }

  private emit(
    out: Diagnostic[],
    rule: string,
    fallback: 'error' | 'warning',
    message: string,
    path: string,
    suggestion: string,
  ): void {
    const severity = severityFor(rule, fallback, this.options.rules);
    if (severity === undefined) return;
    out.push({
      rule,
      severity,
      category: 'general',
      message,
      ...(path === '' ? {} : { path }),
      helpUri: SPEC,
      suggestion,
    });
  }

  private walk(value: unknown, path: string, key: string, out: Diagnostic[]): void {
    if (isString(value)) {
      this.checkString(value, path, key, out);
    } else if (Array.isArray(value)) {
      value.forEach((item, i) => this.walk(item, `${path}[${i}]`, key, out));
    } else if (typeof value === 'object' && value !== null) {
      for (const [k, v] of Object.entries(value)) {
        this.checkString(k, path === '' ? k : `${path}.${k}`, '', out, true);
        this.walk(v, path === '' ? k : `${path}.${k}`, k, out);
      }
    }
  }

  private checkString(
    text: string,
    path: string,
    key: string,
    out: Diagnostic[],
    isKey = false,
  ): void {
    for (const ch of text) {
      if (BIDI_CONTROLS.test(ch)) {
        this.emit(
          out,
          BIDI_RULE,
          'error',
          `${isKey ? 'Key' : 'Value'} contains bidirectional control character ${codePoint(ch)}`,
          path,
          'Remove it; bidirectional overrides can make text display differently from how it is stored (Trojan Source).',
        );
        break;
      }
    }
    for (const ch of text) {
      if (INVISIBLE.test(ch)) {
        this.emit(
          out,
          INVISIBLE_RULE,
          'warning',
          `${isKey ? 'Key' : 'Value'} contains invisible character ${codePoint(ch)}`,
          path,
          'Remove zero-width and invisible formatting characters.',
        );
        break;
      }
    }
    if (isKey) return;

    if (IDENTIFIER_KEYS.has(key) && CONFUSABLE.test(text)) {
      this.emit(
        out,
        HOMOGLYPH_RULE,
        'error',
        `"${key}" value mixes Cyrillic or Greek characters ${LATIN.test(text) ? 'with Latin ones ' : ''}in an identifier`,
        path,
        'Use plain ASCII (or punycode for internationalized domains) so the value cannot be spoofed.',
      );
    }

    if (LANGUAGE_KEYS.has(key.toLowerCase())) {
      if (!LANGUAGE_TAG.test(text)) {
        this.emit(
          out,
          LANGUAGE_TAG_RULE,
          'warning',
          `Language tag "${text}" is not a valid BCP 47 tag such as en, es, fr or pt-BR`,
          path,
          'Use a lowercase language code with an optional uppercase region, e.g. pt-BR.',
        );
      }
    }
  }
}

/** Convenience wrapper used by the CLI. */
export function validateUnicode(doc: unknown, options: UnicodeValidatorOptions = {}): Diagnostic[] {
  return new UnicodeLocalizationValidator(options).validate(doc);
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const unicodeRules: Rule[] = [
  {
    id: BIDI_RULE,
    category: 'general',
    severity: 'error',
    description: 'Strings must not contain bidirectional override or isolate characters',
    run() {},
  },
  {
    id: INVISIBLE_RULE,
    category: 'general',
    severity: 'warning',
    description: 'Strings must not contain zero-width or invisible formatting characters',
    run() {},
  },
  {
    id: HOMOGLYPH_RULE,
    category: 'general',
    severity: 'error',
    description: 'Domains and asset codes must not mix Cyrillic or Greek homoglyphs',
    run() {},
  },
  {
    id: LANGUAGE_TAG_RULE,
    category: 'general',
    severity: 'warning',
    description: 'Localized metadata must use well-formed language tags',
    run() {},
  },
];

export const unicodeRuleIds: readonly string[] = unicodeRules.map((rule) => rule.id);
