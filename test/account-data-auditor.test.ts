import { describe, expect, it, vi, beforeEach } from 'vitest';
import {
  auditAccountData,
  auditTomlAccountData,
  accountDataAuditorRules,
  HASH_MISMATCH_RULE,
  MISSING_PROOF_RULE,
} from '../src/security/account-data-auditor.js';

describe('Account data auditor', () => {
  const mockFetch = vi.fn();

  beforeEach(() => {
    mockFetch.mockReset();
  });

  describe('auditAccountData', () => {
    it('passes when stellar_toml_hash matches and org_domain matches', async () => {
      const tomlContent = 'NETWORK_PASSPHRASE="Test SDF Network ; September 2015"\n';
      const { createHash } = await import('node:crypto');
      const expectedHash = createHash('sha256').update(tomlContent, 'utf8').digest('hex');

      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          data: {
            stellar_toml_hash: Buffer.from(expectedHash).toString('base64'),
            org_domain: Buffer.from('example.com').toString('base64'),
          },
        }),
      });

      const diagnostics = await auditAccountData(
        'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF',
        tomlContent,
        'https://horizon-testnet.stellar.org',
        'example.com',
        mockFetch,
      );

      expect(diagnostics).toEqual([]);
    });

    it('reports security/on-chain-toml-hash-mismatch when hash differs', async () => {
      const tomlContent = 'NETWORK_PASSPHRASE="Test SDF Network ; September 2015"\n';
      const { createHash } = await import('node:crypto');
      const wrongHash = createHash('sha256').update('different content', 'utf8').digest('hex');

      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          data: {
            stellar_toml_hash: Buffer.from(wrongHash).toString('base64'),
            org_domain: Buffer.from('example.com').toString('base64'),
          },
        }),
      });

      const diagnostics = await auditAccountData(
        'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF',
        tomlContent,
        'https://horizon-testnet.stellar.org',
        'example.com',
        mockFetch,
      );

      expect(diagnostics).toContainEqual(
        expect.objectContaining({
          rule: HASH_MISMATCH_RULE,
          severity: 'error',
        }),
      );
      expect(diagnostics[0]?.message).toContain('stellar_toml_hash');
    });

    it('reports security/on-chain-toml-hash-mismatch when org_domain differs', async () => {
      const tomlContent = 'NETWORK_PASSPHRASE="Test SDF Network ; September 2015"\n';
      const { createHash } = await import('node:crypto');
      const expectedHash = createHash('sha256').update(tomlContent, 'utf8').digest('hex');

      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          data: {
            stellar_toml_hash: Buffer.from(expectedHash).toString('base64'),
            org_domain: Buffer.from('wrong-domain.com').toString('base64'),
          },
        }),
      });

      const diagnostics = await auditAccountData(
        'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF',
        tomlContent,
        'https://horizon-testnet.stellar.org',
        'example.com',
        mockFetch,
      );

      expect(diagnostics).toContainEqual(
        expect.objectContaining({
          rule: HASH_MISMATCH_RULE,
          severity: 'error',
        }),
      );
      expect(diagnostics[0]?.message).toContain('org_domain');
    });

    it('reports security/missing-on-chain-verification-proof when stellar_toml_hash is missing', async () => {
      const tomlContent = 'NETWORK_PASSPHRASE="Test SDF Network ; September 2015"\n';

      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          data: {
            org_domain: Buffer.from('example.com').toString('base64'),
          },
        }),
      });

      const diagnostics = await auditAccountData(
        'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF',
        tomlContent,
        'https://horizon-testnet.stellar.org',
        'example.com',
        mockFetch,
      );

      expect(diagnostics).toContainEqual(
        expect.objectContaining({
          rule: MISSING_PROOF_RULE,
          severity: 'warning',
        }),
      );
      expect(diagnostics[0]?.message).toContain('stellar_toml_hash');
    });

    it('reports security/missing-on-chain-verification-proof when org_domain is missing', async () => {
      const tomlContent = 'NETWORK_PASSPHRASE="Test SDF Network ; September 2015"\n';
      const { createHash } = await import('node:crypto');
      const expectedHash = createHash('sha256').update(tomlContent, 'utf8').digest('hex');

      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          data: {
            stellar_toml_hash: Buffer.from(expectedHash).toString('base64'),
          },
        }),
      });

      const diagnostics = await auditAccountData(
        'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF',
        tomlContent,
        'https://horizon-testnet.stellar.org',
        'example.com',
        mockFetch,
      );

      expect(diagnostics).toContainEqual(
        expect.objectContaining({
          rule: MISSING_PROOF_RULE,
          severity: 'warning',
        }),
      );
      expect(diagnostics[0]?.message).toContain('org_domain');
    });

    it('reports warning when account cannot be fetched from Horizon', async () => {
      const tomlContent = 'NETWORK_PASSPHRASE="Test SDF Network ; September 2015"\n';

      mockFetch.mockResolvedValue({
        ok: false,
        status: 404,
      });

      const diagnostics = await auditAccountData(
        'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF',
        tomlContent,
        'https://horizon-testnet.stellar.org',
        'example.com',
        mockFetch,
      );

      expect(diagnostics).toContainEqual(
        expect.objectContaining({
          rule: MISSING_PROOF_RULE,
          severity: 'warning',
        }),
      );
    });
  });

  describe('auditTomlAccountData', () => {
    it('audits SIGNING_KEY and ACCOUNTS entries', async () => {
      const tomlContent = 'NETWORK_PASSPHRASE="Test SDF Network ; September 2015"\nSIGNING_KEY="GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"\nACCOUNTS=["GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBZU"]\n';
      const { createHash } = await import('node:crypto');
      const expectedHash = createHash('sha256').update(tomlContent, 'utf8').digest('hex');

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({
            data: {
              stellar_toml_hash: Buffer.from(expectedHash).toString('base64'),
              org_domain: Buffer.from('example.com').toString('base64'),
            },
          }),
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({
            data: {
              stellar_toml_hash: Buffer.from(expectedHash).toString('base64'),
              org_domain: Buffer.from('example.com').toString('base64'),
            },
          }),
        });

      const doc = {
        NETWORK_PASSPHRASE: 'Test SDF Network ; September 2015',
        SIGNING_KEY: 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF',
        ACCOUNTS: ['GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBZU'],
      };

      const diagnostics = await auditTomlAccountData(doc, tomlContent, mockFetch);
      expect(diagnostics).toEqual([]);
    });

    it('skips invalid account entries', async () => {
      const tomlContent = 'NETWORK_PASSPHRASE="Test SDF Network ; September 2015"\n';
      const doc = {
        NETWORK_PASSPHRASE: 'Test SDF Network ; September 2015',
        SIGNING_KEY: 123, // invalid
        ACCOUNTS: ['GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBZU', 456], // mixed
      };

      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          data: {
            stellar_toml_hash: Buffer.from('abc').toString('base64'),
            org_domain: Buffer.from('example.com').toString('base64'),
          },
        }),
      });

      const diagnostics = await auditTomlAccountData(doc, tomlContent, mockFetch);
      // Only the valid account should be checked
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });
  });

  describe('accountDataAuditorRules', () => {
    it('registers expected rules', () => {
      const ruleIds = accountDataAuditorRules.map((r) => r.id);
      expect(ruleIds).toContain(HASH_MISMATCH_RULE);
      expect(ruleIds).toContain(MISSING_PROOF_RULE);
    });
  });
});