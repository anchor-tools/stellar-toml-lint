import { describe, expect, it } from 'vitest';
import { parseSuppressions } from '../src/comments.js';
import { lint } from '../src/lint.js';
import { formatJson } from '../src/reporters.js';
import type { LintResult } from '../src/types.js';

const BASE = [
  'VERSION="2.7.0"',
  'NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"',
];

const DOCS = [
  '[DOCUMENTATION]',
  'ORG_NAME="Example"',
  'ORG_URL="https://example.com"',
  'ORG_DESCRIPTION="Example"',
  'ORG_LOGO="https://example.com/logo.png"',
  'ORG_OFFICIAL_EMAIL="ops@example.com"',
];

/** A valid file, to which callers prepend or append lines under test. */
function doc(...extra: string[]): string {
  return [...BASE, ...extra, ...DOCS].join('\n');
}

function rules(result: LintResult): string[] {
  return result.diagnostics.map((d) => d.rule);
}

/** A checksum-valid account id written entirely in lowercase: two rules fire. */
const LOWERCASE_KEY = 'gcm5ycqpfw4icbppskacx56ztgg6kz7a53jguwwafrzw462yfik4bzs';

describe('parseSuppressions', () => {
  it('records disable-line on its own line and disable-next-line on the next', () => {
    const map = parseSuppressions(
      [
        'a = 1 # stellar-toml-lint-disable-line rule/a',
        '# stellar-toml-lint-disable-next-line rule/b',
        'b = 2',
      ].join('\n'),
    );

    expect(map.get(1)).toEqual(new Set(['rule/a']));
    expect(map.get(3)).toEqual(new Set(['rule/b']));
    expect(map.has(2)).toBe(false);
  });
});

describe('in-source suppressions', () => {
  it('disables a specific rule on the next line', () => {
    const pragma = '# stellar-toml-lint-disable-next-line general/https-endpoints';

    const unsuppressed = lint(doc('TRANSFER_SERVER="http://api.example.com/sep6"'));
    expect(rules(unsuppressed)).toContain('general/https-endpoints');

    const suppressed = lint(doc(pragma, 'TRANSFER_SERVER="http://api.example.com/sep6"'));
    expect(rules(suppressed)).not.toContain('general/https-endpoints');
  });

  it('disables multiple comma-separated rules on the next line', () => {
    const source = doc(
      '# stellar-toml-lint-disable-next-line general/signing-keys, general/lowercase-public-key',
      `SIGNING_KEY="${LOWERCASE_KEY}"`,
    );

    const unsuppressed = lint(doc(`SIGNING_KEY="${LOWERCASE_KEY}"`));
    expect(rules(unsuppressed)).toEqual(
      expect.arrayContaining(['general/signing-keys', 'general/lowercase-public-key']),
    );

    expect(rules(lint(source))).toEqual([]);
  });

  it('suppresses a block until it is re-enabled', () => {
    const source = doc(
      '# stellar-toml-lint-disable general/https-endpoints',
      'TRANSFER_SERVER="http://api.example.com/sep6"',
      '# stellar-toml-lint-enable general/https-endpoints',
      'TRANSFER_SERVER_SEP0024="http://api.example.com/sep24"',
    );

    const found = lint(source).diagnostics.filter((d) => d.rule === 'general/https-endpoints');
    expect(found).toHaveLength(1);
    expect(found[0]?.message).toContain('TRANSFER_SERVER_SEP0024');
  });

  it('still reports unsuppressed diagnostics on other lines', () => {
    const source = doc(
      '# stellar-toml-lint-disable-next-line general/https-endpoints',
      'TRANSFER_SERVER="http://api.example.com/sep6"',
      'KYC_SERVER="http://api.example.com/kyc"',
    );

    const found = lint(source).diagnostics.filter((d) => d.rule === 'general/https-endpoints');
    expect(found).toHaveLength(1);
    expect(found[0]?.message).toContain('KYC_SERVER');
  });

  it('suppresses every diagnostic on a line with the * wildcard', () => {
    const source = doc('# stellar-toml-lint-disable-next-line *', `SIGNING_KEY="${LOWERCASE_KEY}"`);

    const result = lint(source);
    expect(rules(result)).toEqual([]);
    // Nothing left to fail the run: suppressed findings never reach the counts.
    expect(result.ok).toBe(true);
    expect(result.counts).toEqual({ error: 0, warning: 0, info: 0 });
  });

  it('suppresses rules on the same line via a trailing disable-line comment', () => {
    const source = doc(
      `SIGNING_KEY="${LOWERCASE_KEY}" # stellar-toml-lint-disable-line general/signing-keys, general/lowercase-public-key`,
    );

    expect(rules(lint(source))).toEqual([]);
  });

  it('keeps suppressed diagnostics out of reporter output', () => {
    const source = doc(
      '# stellar-toml-lint-disable-next-line general/https-endpoints',
      'TRANSFER_SERVER="http://api.example.com/sep6"',
    );

    expect(formatJson(lint(source), 'stellar.toml')).not.toContain('general/https-endpoints');
  });
});
