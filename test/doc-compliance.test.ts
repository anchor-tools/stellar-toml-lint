import { describe, expect, it } from 'vitest';
import { lint } from '../src/lint.js';
import { checkDocCompliance } from '../src/rules/doc-compliance.js';

const GOOD_TOML = [
  'VERSION="2.7.0"',
  'NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"',
  '',
  '[DOCUMENTATION]',
  'ORG_NAME="Example"',
  'ORG_URL="https://example.com"',
  'ORG_DESCRIPTION="Example"',
  'ORG_LOGO="https://example.com/logo.png"',
  'ORG_OFFICIAL_EMAIL="ops@example.com"',
  'ORG_PRIVACY_POLICY="https://example.com/privacy"',
  'ORG_TERMS_OF_SERVICE="https://example.com/terms"',
].join('\n');

const ruleIds = (result: { diagnostics: { rule: string }[] }): string[] =>
  result.diagnostics.map((d) => d.rule);

describe('doc-compliance rules', () => {
  describe('presence checks (offline)', () => {
    it('passes when both legal URLs are present', () => {
      const result = lint(GOOD_TOML);
      expect(ruleIds(result)).not.toContain('documentation/missing-privacy-policy');
      expect(ruleIds(result)).not.toContain('documentation/missing-terms-of-service');
    });

    it('warns when ORG_PRIVACY_POLICY is missing', () => {
      const toml = GOOD_TOML.replace('\nORG_PRIVACY_POLICY="https://example.com/privacy"', '');
      const result = lint(toml);
      expect(ruleIds(result)).toContain('documentation/missing-privacy-policy');
      const d = result.diagnostics.find((x) => x.rule === 'documentation/missing-privacy-policy');
      expect(d?.severity).toBe('info');
    });

    it('warns when ORG_TERMS_OF_SERVICE is missing', () => {
      const toml = GOOD_TOML.replace('\nORG_TERMS_OF_SERVICE="https://example.com/terms"', '');
      const result = lint(toml);
      expect(ruleIds(result)).toContain('documentation/missing-terms-of-service');
      const d = result.diagnostics.find((x) => x.rule === 'documentation/missing-terms-of-service');
      expect(d?.severity).toBe('info');
    });

    it('warns when both legal URLs are missing', () => {
      const toml = GOOD_TOML.replace(
        '\nORG_PRIVACY_POLICY="https://example.com/privacy"',
        '',
      ).replace('\nORG_TERMS_OF_SERVICE="https://example.com/terms"', '');
      const result = lint(toml);
      expect(ruleIds(result)).toContain('documentation/missing-privacy-policy');
      expect(ruleIds(result)).toContain('documentation/missing-terms-of-service');
    });

    it('does not report when no DOCUMENTATION table exists', () => {
      const toml = 'VERSION="2.7.0"\n';
      const result = lint(toml);
      expect(ruleIds(result)).not.toContain('documentation/missing-privacy-policy');
      expect(ruleIds(result)).not.toContain('documentation/missing-terms-of-service');
    });

    it('does not report when ORG_URL is absent', () => {
      const toml = ['VERSION="2.7.0"', '[DOCUMENTATION]', 'ORG_NAME="Example"'].join('\n');
      const result = lint(toml);
      expect(ruleIds(result)).not.toContain('documentation/missing-privacy-policy');
      expect(ruleIds(result)).not.toContain('documentation/missing-terms-of-service');
    });
  });

  describe('reachability checks (checkDocCompliance)', () => {
    it('passes when both URLs respond HTTP 200', async () => {
      const doc = {
        DOCUMENTATION: {
          ORG_PRIVACY_POLICY: 'https://example.com/privacy',
          ORG_TERMS_OF_SERVICE: 'https://example.com/terms',
        },
      };

      const impl = (async () => new Response(null, { status: 200 })) as unknown as typeof fetch;

      const diagnostics = await checkDocCompliance(doc, impl);
      expect(diagnostics).toHaveLength(0);
    });

    it('reports ORG_PRIVACY_POLICY as unreachable when it returns 404', async () => {
      const doc = {
        DOCUMENTATION: {
          ORG_PRIVACY_POLICY: 'https://example.com/privacy',
          ORG_TERMS_OF_SERVICE: 'https://example.com/terms',
        },
      };

      const impl = (async (url: string | URL) => {
        const target = String(url);
        if (target.includes('privacy')) return new Response(null, { status: 404 });
        return new Response(null, { status: 200 });
      }) as unknown as typeof fetch;

      const diagnostics = await checkDocCompliance(doc, impl);
      expect(diagnostics.length).toBeGreaterThan(0);
      const d = diagnostics.find((x) => x.rule === 'documentation/legal-url-unreachable');
      expect(d?.severity).toBe('error');
      expect(d?.message).toContain('HTTP 404');
      expect(d?.path).toBe('DOCUMENTATION.ORG_PRIVACY_POLICY');
    });

    it('reports ORG_TERMS_OF_SERVICE as unreachable when it returns 500', async () => {
      const doc = {
        DOCUMENTATION: {
          ORG_PRIVACY_POLICY: 'https://example.com/privacy',
          ORG_TERMS_OF_SERVICE: 'https://example.com/terms',
        },
      };

      const impl = (async (url: string | URL) => {
        const target = String(url);
        if (target.includes('terms')) return new Response(null, { status: 500 });
        return new Response(null, { status: 200 });
      }) as unknown as typeof fetch;

      const diagnostics = await checkDocCompliance(doc, impl);
      const d = diagnostics.find((x) => x.rule === 'documentation/legal-url-unreachable');
      expect(d?.severity).toBe('error');
      expect(d?.message).toContain('HTTP 500');
      expect(d?.path).toBe('DOCUMENTATION.ORG_TERMS_OF_SERVICE');
    });

    it('reports unreachable URLs when fetch throws', async () => {
      const doc = {
        DOCUMENTATION: {
          ORG_PRIVACY_POLICY: 'https://example.com/privacy',
          ORG_TERMS_OF_SERVICE: 'https://example.com/terms',
        },
      };

      const impl = (async () => {
        throw new Error('connect ETIMEDOUT');
      }) as unknown as typeof fetch;

      const diagnostics = await checkDocCompliance(doc, impl);
      expect(diagnostics.length).toBe(2);
      expect(diagnostics.every((d) => d.rule === 'documentation/legal-url-unreachable')).toBe(true);
      expect(diagnostics.every((d) => d.severity === 'error')).toBe(true);
    });

    it('skips non-https URLs', async () => {
      const doc = {
        DOCUMENTATION: {
          ORG_PRIVACY_POLICY: 'http://example.com/privacy',
          ORG_TERMS_OF_SERVICE: 'http://example.com/terms',
        },
      };

      const impl = (async () => new Response(null, { status: 200 })) as unknown as typeof fetch;

      const diagnostics = await checkDocCompliance(doc, impl);
      expect(diagnostics).toHaveLength(0);
    });
  });
});
