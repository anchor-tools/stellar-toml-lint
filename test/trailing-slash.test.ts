import { describe, expect, it } from 'vitest';
import { lint } from '../src/lint.js';
import type { LintResult } from '../src/types.js';

const RULE = 'general/trailing-slash-in-endpoint';

function find(result: LintResult, rule: string) {
  return result.diagnostics.filter((d) => d.rule === rule);
}

describe('general/trailing-slash-in-endpoint', () => {
  it('passes on endpoints without a trailing slash', () => {
    const result = lint(
      [
        'VERSION="2.7.0"',
        'NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"',
        'WEB_AUTH_ENDPOINT="https://anchor.com/auth"',
        'TRANSFER_SERVER="https://anchor.com/sep6"',
        'TRANSFER_SERVER_SEP0024="https://anchor.com/sep24"',
        'KYC_SERVER="https://anchor.com/kyc"',
        'ANCHOR_QUOTE_SERVER="https://anchor.com/sep38"',
        'DIRECT_PAYMENT_SERVER="https://anchor.com/sep31"',
        '',
      ].join('\n'),
    );
    expect(find(result, RULE)).toEqual([]);
  });

  it('flags WEB_AUTH_ENDPOINT with a trailing slash', () => {
    const result = lint('WEB_AUTH_ENDPOINT="https://anchor.com/auth/"');
    const [d] = find(result, RULE);

    expect(d).toBeDefined();
    expect(d?.severity).toBe('warning');
    expect(d?.rule).toBe(RULE);
    expect(d?.path).toBe('WEB_AUTH_ENDPOINT');
    expect(d?.message).toContain('trailing slash');
  });

  it.each([
    'WEB_AUTH_ENDPOINT',
    'TRANSFER_SERVER',
    'TRANSFER_SERVER_SEP0024',
    'KYC_SERVER',
    'ANCHOR_QUOTE_SERVER',
    'DIRECT_PAYMENT_SERVER',
  ])('flags %s when it ends with a slash', (field) => {
    const result = lint(`${field}="https://anchor.com/service/"`);
    const [d] = find(result, RULE);

    expect(d?.severity).toBe('warning');
    expect(d?.path).toBe(field);
  });

  it('suggests the URL without the trailing slash', () => {
    const result = lint('TRANSFER_SERVER="https://anchor.com/sep6/"');
    const [d] = find(result, RULE);

    expect(d?.suggestion).toContain('https://anchor.com/sep6');
    expect(d?.suggestion).not.toContain('sep6/');
  });

  it('flags multiple offending endpoints in one file', () => {
    const result = lint(
      ['WEB_AUTH_ENDPOINT="https://anchor.com/auth/"', 'KYC_SERVER="https://anchor.com/kyc/"'].join(
        '\n',
      ),
    );
    expect(find(result, RULE)).toHaveLength(2);
  });

  it('stays silent when the field is missing', () => {
    const result = lint('VERSION="2.7.0"');
    expect(find(result, RULE)).toEqual([]);
  });

  it('stays silent on a non-string value', () => {
    const result = lint('WEB_AUTH_ENDPOINT=42');
    expect(find(result, RULE)).toEqual([]);
  });

  it('can be disabled with --off', () => {
    const result = lint('WEB_AUTH_ENDPOINT="https://anchor.com/auth/"', {
      rules: { [RULE]: 'off' },
    });
    expect(find(result, RULE)).toEqual([]);
  });

  it('does not fire on the valid fixture', async () => {
    const { readFileSync } = await import('node:fs');
    const { fileURLToPath } = await import('node:url');
    const { dirname, join } = await import('node:path');
    const here = dirname(fileURLToPath(import.meta.url));
    const source = readFileSync(join(here, 'fixtures', 'valid.toml'), 'utf8');
    expect(find(lint(source), RULE)).toEqual([]);
  });

  it('fires on the broken fixture via TRANSFER_SERVER_SEP0024', async () => {
    const { readFileSync } = await import('node:fs');
    const { fileURLToPath } = await import('node:url');
    const { dirname, join } = await import('node:path');
    const here = dirname(fileURLToPath(import.meta.url));
    const source = readFileSync(join(here, 'fixtures', 'broken.toml'), 'utf8');
    const [d] = find(lint(source), RULE);
    expect(d?.path).toBe('TRANSFER_SERVER_SEP0024');
  });
});
