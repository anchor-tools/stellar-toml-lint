import { describe, expect, it } from 'vitest';
import { lint } from '../src/lint.js';

const PASSPHRASE = 'Public Global Stellar Network ; September 2015';

const ruleIds = (result: { diagnostics: { rule: string }[] }): string[] =>
  result.diagnostics.map((d) => d.rule);

describe('network passphrase validation', () => {
  describe('general/network-passphrase-typo', () => {
    it('passes for the canonical Public passphrase', () => {
      const toml = `NETWORK_PASSPHRASE="${PASSPHRASE}"\n`;
      const result = lint(toml);
      expect(ruleIds(result)).not.toContain('general/network-passphrase-typo');
      expect(ruleIds(result)).not.toContain('general/unrecognized-network-passphrase');
    });

    it('passes for the canonical Testnet passphrase', () => {
      const toml = 'NETWORK_PASSPHRASE="Test SDF Network ; September 2015"\n';
      const result = lint(toml);
      expect(ruleIds(result)).not.toContain('general/network-passphrase-typo');
      expect(ruleIds(result)).not.toContain('general/unrecognized-network-passphrase');
    });

    it('passes for the canonical Futurenet passphrase', () => {
      const toml = 'NETWORK_PASSPHRASE="Test SDF Future Network ; October 2022"\n';
      const result = lint(toml);
      expect(ruleIds(result)).not.toContain('general/network-passphrase-typo');
      expect(ruleIds(result)).not.toContain('general/unrecognized-network-passphrase');
    });

    it('detects a single-character typo in the Public passphrase', () => {
      const toml = 'NETWORK_PASSPHRASE="Public Globl Stellar Network ; September 2015"\n';
      const result = lint(toml);
      expect(ruleIds(result)).toContain('general/network-passphrase-typo');
      const d = result.diagnostics.find((x) => x.rule === 'general/network-passphrase-typo');
      expect(d?.severity).toBe('error');
      expect(d?.message).toContain('likely typo');
      expect(d?.message).toContain('edit distance');
    });

    it('detects a missing semicolon as a typo', () => {
      const toml = 'NETWORK_PASSPHRASE="Public Global Stellar Network September 2015"\n';
      const result = lint(toml);
      expect(ruleIds(result)).toContain('general/network-passphrase-typo');
    });

    it('does not double-report when whitespace normalization already catches it', () => {
      // Extra space before semicolon: known to network/passphrase
      const toml = 'NETWORK_PASSPHRASE="Public Global Stellar Network  ; September 2015"\n';
      const result = lint(toml);
      const typoResults = result.diagnostics.filter(
        (d) => d.rule === 'general/network-passphrase-typo',
      );
      expect(typoResults.length).toBeLessThanOrEqual(1);
    });
  });

  describe('general/unrecognized-network-passphrase', () => {
    it('warns on a completely unknown passphrase', () => {
      const toml = 'NETWORK_PASSPHRASE="My Custom Network ; January 2024"\n';
      const result = lint(toml);
      expect(ruleIds(result)).toContain('general/unrecognized-network-passphrase');
      const d = result.diagnostics.find(
        (x) => x.rule === 'general/unrecognized-network-passphrase',
      );
      expect(d?.severity).toBe('warning');
      expect(d?.message).toContain('does not match any known Stellar network');
    });

    it('does not fire when the passphrase is a known one', () => {
      const toml = `NETWORK_PASSPHRASE="${PASSPHRASE}"\n`;
      const result = lint(toml);
      expect(ruleIds(result)).not.toContain('general/unrecognized-network-passphrase');
    });

    it('does not fire when the passphrase is close to a known one (typo rule handles it)', () => {
      const toml = 'NETWORK_PASSPHRASE="Public Globl Stellar Network ; September 2015"\n';
      const result = lint(toml);
      const unrecognized = result.diagnostics.filter(
        (d) => d.rule === 'general/unrecognized-network-passphrase',
      );
      expect(unrecognized).toHaveLength(0);
    });
  });
});
