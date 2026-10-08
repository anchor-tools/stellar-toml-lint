import { describe, expect, it } from 'vitest';
import { fix } from '../src/fix.js';
import { lint } from '../src/lint.js';
import type { Diagnostic } from '../src/types.js';

/**
 * `--fix` applies only the mechanically safe rewrites to the raw source. Each
 * test lints the input the way the CLI would, then fixes the diagnostics and
 * asserts on the rewritten text, the edit metadata, and idempotency.
 */

describe('fix', () => {
  describe('general/trailing-slash-in-endpoint', () => {
    it('drops the trailing slash from an endpoint', () => {
      const source = 'TRANSFER_SERVER="https://anchor.com/sep6/"';
      const fixed = fix(source, lint(source).diagnostics);

      expect(fixed.edits).toHaveLength(1);
      expect(fixed.edits[0]).toMatchObject({
        rule: 'general/trailing-slash-in-endpoint',
        path: 'TRANSFER_SERVER',
        old: 'https://anchor.com/sep6/',
        replacement: 'https://anchor.com/sep6',
      });
      expect(fixed.source).toBe('TRANSFER_SERVER="https://anchor.com/sep6"');
    });

    it('fixes every offending endpoint in one file', () => {
      const source = [
        'WEB_AUTH_ENDPOINT="https://anchor.com/auth/"',
        'KYC_SERVER="https://anchor.com/kyc/"',
      ].join('\n');
      const fixed = fix(source, lint(source).diagnostics);

      expect(fixed.edits).toHaveLength(2);
      expect(fixed.source).toBe(
        'WEB_AUTH_ENDPOINT="https://anchor.com/auth"\nKYC_SERVER="https://anchor.com/kyc"',
      );
    });

    it('expands a bare trailing-slash value', () => {
      const source = "TRANSFER_SERVER='https://anchor.com/sep6/'";
      const fixed = fix(source, lint(source).diagnostics);

      expect(fixed.source).toBe("TRANSFER_SERVER='https://anchor.com/sep6'");
    });
  });

  describe('network/passphrase', () => {
    it('normalises stray whitespace around the separator', () => {
      const source = 'NETWORK_PASSPHRASE="Public Global Stellar Network  ;  September 2015"';
      const fixed = fix(source, lint(source).diagnostics);

      expect(fixed.edits).toHaveLength(1);
      expect(fixed.edits[0]).toMatchObject({
        rule: 'network/passphrase',
        path: 'NETWORK_PASSPHRASE',
        replacement: 'Public Global Stellar Network ; September 2015',
      });
      expect(fixed.source).toBe(
        'NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"',
      );
    });

    it('trims leading and trailing whitespace', () => {
      const source = 'NETWORK_PASSPHRASE="  Public Global Stellar Network ; September 2015  "';
      const fixed = fix(source, lint(source).diagnostics);

      expect(fixed.source).toBe(
        'NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"',
      );
    });

    it('never rewrites an unrecognised passphrase', () => {
      const source = 'NETWORK_PASSPHRASE="Some made up network"';
      const fixed = fix(source, lint(source).diagnostics);

      expect(fixed.edits).toEqual([]);
      expect(fixed.source).toBe(source);
    });

    it('leaves a missing NETWORK_PASSPHRASE alone', () => {
      const source = 'VERSION="2.7.0"';
      const fixed = fix(source, lint(source).diagnostics);

      expect(fixed.edits).toEqual([]);
      expect(fixed.source).toBe(source);
    });
  });

  describe('documentation/social-handles', () => {
    it('strips a leading @ from a handle', () => {
      const source = '[DOCUMENTATION]\nORG_TWITTER="@stellarOrg"\n';
      const fixed = fix(source, lint(source).diagnostics);

      expect(fixed.edits).toHaveLength(1);
      expect(fixed.edits[0]).toMatchObject({
        rule: 'documentation/social-handles',
        path: 'DOCUMENTATION.ORG_TWITTER',
        old: '@stellarOrg',
        replacement: 'stellarOrg',
      });
      expect(fixed.source).toBe('[DOCUMENTATION]\nORG_TWITTER="stellarOrg"\n');
    });

    it('replaces a URL-valued handle with the bare handle', () => {
      const source = '[DOCUMENTATION]\nORG_KEYBASE="https://keybase.io/stellarOrg"\n';
      const fixed = fix(source, lint(source).diagnostics);

      expect(fixed.edits).toHaveLength(1);
      expect(fixed.edits[0]).toMatchObject({
        rule: 'documentation/social-handles',
        path: 'DOCUMENTATION.ORG_KEYBASE',
        old: 'https://keybase.io/stellarOrg',
        replacement: 'stellarOrg',
      });
      expect(fixed.source).toBe('[DOCUMENTATION]\nORG_KEYBASE="stellarOrg"\n');
    });

    it('strips a trailing slash from a handle URL before unwrapping', () => {
      const source = '[DOCUMENTATION]\nORG_TWITTER="https://twitter.com/stellarOrg/"\n';
      const fixed = fix(source, lint(source).diagnostics);

      expect(fixed.source).toBe('[DOCUMENTATION]\nORG_TWITTER="stellarOrg"\n');
    });

    it('does not touch already-bare handles', () => {
      const source = '[DOCUMENTATION]\nORG_TWITTER="stellarOrg"\n';
      const result = lint(source);

      expect(result.diagnostics.filter((d) => d.rule === 'documentation/social-handles')).toEqual(
        [],
      );
      expect(fix(source, result.diagnostics).edits).toEqual([]);
    });
  });

  describe('principals/social-handles', () => {
    it('rewrites a principal social handle to a bare handle', () => {
      const source = '[[PRINCIPALS]]\ntwitter="@crypto_jane"\n';
      const fixed = fix(source, lint(source).diagnostics);

      expect(fixed.edits).toHaveLength(1);
      expect(fixed.edits[0]).toMatchObject({
        rule: 'principals/social-handles',
        path: 'PRINCIPALS[0].twitter',
        old: '@crypto_jane',
        replacement: 'crypto_jane',
      });
      expect(fixed.source).toBe('[[PRINCIPALS]]\ntwitter="crypto_jane"\n');
    });

    it('unwraps a principal handle URL', () => {
      const source = '[[PRINCIPALS]]\nkeybase="https://keybase.io/crypto_jane"\n';
      const fixed = fix(source, lint(source).diagnostics);

      expect(fixed.source).toBe('[[PRINCIPALS]]\nkeybase="crypto_jane"\n');
    });
  });

  describe('editing behaviour', () => {
    it('preserves comments and unrelated formatting', () => {
      const source = [
        'VERSION = "2.7.0"                       # spec version',
        'NETWORK_PASSPHRASE = "Public Global Stellar Network ;  September 2015"   # mainnet',
        'TRANSFER_SERVER = "https://anchor.com/sep6/"   # service root',
        '',
        '[DOCUMENTATION]',
        '  ORG_NAME = "Anchor"',
        '  ORG_TWITTER = "@anchor_org"   # twitter, no leading @ needed',
        '  ORG_KEYBASE = "https://keybase.io/anchor"',
        '',
      ].join('\n');
      const fixed = fix(source, lint(source).diagnostics);

      expect(fixed.edits).toHaveLength(4);
      expect(fixed.source).toBe(
        [
          'VERSION = "2.7.0"                       # spec version',
          'NETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"   # mainnet',
          'TRANSFER_SERVER = "https://anchor.com/sep6"   # service root',
          '',
          '[DOCUMENTATION]',
          '  ORG_NAME = "Anchor"',
          '  ORG_TWITTER = "anchor_org"   # twitter, no leading @ needed',
          '  ORG_KEYBASE = "anchor"',
          '',
        ].join('\n'),
      );
    });

    it('is idempotent for the fixed cases', () => {
      const source = [
        'NETWORK_PASSPHRASE="Public Global Stellar Network  ;  September 2015"',
        'TRANSFER_SERVER="https://anchor.com/sep6/"',
        '[DOCUMENTATION]',
        'ORG_TWITTER="@stellarOrg"',
      ].join('\n');
      const first = fix(source, lint(source).diagnostics);
      const second = fix(first.source, lint(first.source).diagnostics);

      expect(first.edits.length).toBeGreaterThan(0);
      expect(second.edits).toEqual([]);
      expect(second.source).toBe(first.source);
    });

    it('writes nothing when there is nothing to fix', () => {
      const source = [
        'VERSION="2.7.0"',
        'NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"',
        'TRANSFER_SERVER="https://anchor.com/sep6"',
        '[DOCUMENTATION]',
        'ORG_TWITTER="stellarOrg"',
      ].join('\n');
      const fixed = fix(source, lint(source).diagnostics);

      expect(fixed.edits).toEqual([]);
      expect(fixed.source).toBe(source);
    });

    it('ignores diagnostics whose value is already the fix value', () => {
      const stale: Diagnostic = {
        rule: 'general/trailing-slash-in-endpoint',
        severity: 'warning',
        category: 'general',
        path: 'TRANSFER_SERVER',
        message: 'has a trailing slash',
        fix: { value: 'https://anchor.com/sep6' },
      };
      const fixed = fix('TRANSFER_SERVER="https://anchor.com/sep6"', [stale]);

      expect(fixed.edits).toEqual([]);
      expect(fixed.source).toBe('TRANSFER_SERVER="https://anchor.com/sep6"');
    });

    it('skips a diagnostic with no fix', () => {
      const source = 'NETWORK_PASSPHRASE="Some made up network"';
      const fixed = fix(source, lint(source).diagnostics);

      expect(fixed.edits).toEqual([]);
    });

    it('skips a fixable diagnostic with no resolvable span', () => {
      const missing: Diagnostic = {
        rule: 'documentation/social-handles',
        severity: 'warning',
        category: 'documentation',
        path: 'DOCUMENTATION.ORG_TWITTER',
        message: 'should not include a leading @',
        fix: { value: 'stellarOrg' },
      };
      const source = '[DOCUMENTATION]\nORG_NAME="Anchor"\n';
      const fixed = fix(source, [missing]);

      expect(fixed.edits).toEqual([]);
      expect(fixed.source).toBe(source);
    });

    it('does not corrupt an inline table the index cannot pin down', () => {
      // SourceIndex cannot see inside inline tables, so the diagnostics resolve
      // to the DOCUMENTATION key position; the fixer must refuse rather than
      // rewrite the table header. The value is left as the human wrote it.
      const source = 'DOCUMENTATION = { ORG_TWITTER = "@x" }';
      const fixed = fix(source, lint(source).diagnostics);

      expect(fixed.edits).toEqual([]);
      expect(fixed.source).toBe(source);
    });
  });
});
