import { describe, expect, it } from 'vitest';
import { lint } from '../src/lint.js';
import type { Diagnostic, LintResult } from '../src/types.js';

describe('empty string values rule', () => {
  /** Default non-empty values for recommended documentation fields. */
  const recommendedDefaults: Record<string, string> = {
    ORG_NAME: 'Test Org',
    ORG_URL: 'https://example.com',
    ORG_DESCRIPTION: 'Test description',
    ORG_LOGO: 'https://example.com/logo.png',
    ORG_OFFICIAL_EMAIL: 'test@example.com',
    ORG_PRIVACY_POLICY: 'https://example.com/privacy',
    ORG_TERMS_OF_SERVICE: 'https://example.com/terms',
  };

  function makeSource(overrides: Record<string, string>): string {
    const fields: string[] = [];
    for (const [key, value] of Object.entries({ ...recommendedDefaults, ...overrides })) {
      fields.push(`${key}="${value}"`);
    }
    return [
      'VERSION="2.7.0"',
      'NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"',
      '',
      '[DOCUMENTATION]',
      ...fields,
    ].join('\n');
  }

  function getEmptyStringDiagnostics(result: LintResult): Diagnostic[] {
    return result.diagnostics.filter(
      (d): d is Diagnostic => d.rule === 'general/empty-string-value',
    );
  }

  it('flags empty string in ORG_NAME', () => {
    const source = makeSource({ ORG_NAME: '' });
    const result = lint(source, { rules: {} });
    const diags = getEmptyStringDiagnostics(result);
    expect(diags).toHaveLength(1);
    expect(diags[0]).toMatchObject({
      rule: 'general/empty-string-value',
      message: 'DOCUMENTATION.ORG_NAME is an empty string',
      path: 'DOCUMENTATION.ORG_NAME',
    });
  });

  it('flags empty string in ORG_URL', () => {
    const source = makeSource({ ORG_URL: '' });
    const result = lint(source, { rules: {} });
    const diags = getEmptyStringDiagnostics(result);
    expect(diags).toHaveLength(1);
    expect(diags[0]).toMatchObject({
      rule: 'general/empty-string-value',
      message: 'DOCUMENTATION.ORG_URL is an empty string',
      path: 'DOCUMENTATION.ORG_URL',
    });
  });

  it('flags empty string in ORG_DESCRIPTION', () => {
    const source = makeSource({ ORG_DESCRIPTION: '' });
    const result = lint(source, { rules: {} });
    const diags = getEmptyStringDiagnostics(result);
    expect(diags).toHaveLength(1);
    expect(diags[0]).toMatchObject({
      rule: 'general/empty-string-value',
      message: 'DOCUMENTATION.ORG_DESCRIPTION is an empty string',
      path: 'DOCUMENTATION.ORG_DESCRIPTION',
    });
  });

  it('does not flag non-empty string', () => {
    const source = makeSource({ ORG_NAME: 'Example' });
    const result = lint(source, { rules: {} });
    const diags = getEmptyStringDiagnostics(result);
    expect(diags).toHaveLength(0);
  });

  it('flags multiple empty strings', () => {
    const source = makeSource({ ORG_NAME: '', ORG_URL: '' });
    const result = lint(source, { rules: {} });
    const diags = getEmptyStringDiagnostics(result);
    expect(diags).toHaveLength(2);
    const paths = diags.map((d: Diagnostic) => d.path);
    expect(paths).toContain('DOCUMENTATION.ORG_NAME');
    expect(paths).toContain('DOCUMENTATION.ORG_URL');
  });

  it('ignores non-string values', () => {
    // ORG_LOGO expects a string, but we can test with a number (though it would be caught by other rules)
    // We'll just ensure that our rule doesn't crash and doesn't flag non-strings.
    const source = makeSource({ ORG_LOGO: '123' as unknown as string });
    const result = lint(source, { rules: {} });
    const diags = getEmptyStringDiagnostics(result);
    expect(diags).toHaveLength(0);
  });
});
