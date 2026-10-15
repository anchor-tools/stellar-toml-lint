import { describe, expect, it, vi, beforeEach } from 'vitest';
import {
  buildSyntheticSep8Transaction,
  isValidTransactionXdr,
  verifySep8Webhook,
  sep8WebhookRules,
  WEBHOOK_UNRESPONSIVE_RULE,
  INVALID_WEBHOOK_RESPONSE_RULE,
  INVALID_CO_SIGNED_TX_RULE,
  IDEMPOTENCY_VIOLATION_RULE,
  WEBHOOK_LATENCY_RULE,
} from '../src/sep8/webhookCoordinator.js';
import { xdr } from '@stellar/stellar-base';

describe('SEP-8 webhook coordinator', () => {
  describe('buildSyntheticSep8Transaction', () => {
    it('builds a valid transaction envelope', () => {
      const result = buildSyntheticSep8Transaction(
        'USDC',
        'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN',
        'Test SDF Network ; September 2015',
      );

      expect(result.txXdr).toBeDefined();
      expect(result.sourcePublicKey).toBeDefined();
      expect(result.destPublicKey).toBeDefined();
      expect(result.txHash).toBeInstanceOf(Buffer);
      expect(result.txHash.length).toBe(32);
    });

    it('builds a valid native asset transaction', () => {
      const result = buildSyntheticSep8Transaction('XLM', undefined, 'Test SDF Network ; September 2015');
      expect(isValidTransactionXdr(result.txXdr)).toBe(true);
    });

    it('uses provided source and destination keypairs', () => {
      const { Keypair } = require('@stellar/stellar-base');
      const source = Keypair.random();
      const dest = Keypair.random();

      const result = buildSyntheticSep8Transaction(
        'USDC',
        'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN',
        'Test SDF Network ; September 2015',
        source,
        dest,
      );

      expect(result.sourcePublicKey).toBe(source.publicKey());
      expect(result.destPublicKey).toBe(dest.publicKey());
    });
  });

  describe('isValidTransactionXdr', () => {
    it('returns true for valid transaction XDR', () => {
      const result = buildSyntheticSep8Transaction(
        'USDC',
        'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN',
        'Test SDF Network ; September 2015',
      );
      expect(isValidTransactionXdr(result.txXdr)).toBe(true);
    });

    it('returns false for invalid XDR', () => {
      expect(isValidTransactionXdr('invalid')).toBe(false);
      expect(isValidTransactionXdr('')).toBe(false);
      expect(isValidTransactionXdr('AAAAAA==')).toBe(false);
    });
  });

  describe('verifySep8Webhook', () => {
    const mockFetch = vi.fn();

    beforeEach(() => {
      mockFetch.mockReset();
    });

    it('reports sep8/webhook-unresponsive when server is unreachable', async () => {
      mockFetch.mockRejectedValue(new Error('Network error'));

      const doc = {
        NETWORK_PASSPHRASE: 'Test SDF Network ; September 2015',
        CURRENCIES: [
          {
            code: 'USDC',
            issuer: 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN',
            approval_server: 'https://approval.example.com',
          },
        ],
      };

      const diagnostics = await verifySep8Webhook(doc, mockFetch);
      expect(diagnostics).toContainEqual(
        expect.objectContaining({
          rule: WEBHOOK_UNRESPONSIVE_RULE,
          severity: 'error',
        }),
      );
    });

    it('reports sep8/invalid-webhook-response when server returns non-JSON', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => { throw new Error('Not JSON'); },
      });

      const doc = {
        NETWORK_PASSPHRASE: 'Test SDF Network ; September 2015',
        CURRENCIES: [
          {
            code: 'USDC',
            issuer: 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN',
            approval_server: 'https://approval.example.com',
          },
        ],
      };

      const diagnostics = await verifySep8Webhook(doc, mockFetch);
      expect(diagnostics).toContainEqual(
        expect.objectContaining({
          rule: INVALID_WEBHOOK_RESPONSE_RULE,
          severity: 'error',
        }),
      );
    });

    it('reports sep8/invalid-webhook-response when status is invalid', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ status: 'invalid_status' }),
      });

      const doc = {
        NETWORK_PASSPHRASE: 'Test SDF Network ; September 2015',
        CURRENCIES: [
          {
            code: 'USDC',
            issuer: 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN',
            approval_server: 'https://approval.example.com',
          },
        ],
      };

      const diagnostics = await verifySep8Webhook(doc, mockFetch);
      expect(diagnostics).toContainEqual(
        expect.objectContaining({
          rule: INVALID_WEBHOOK_RESPONSE_RULE,
          severity: 'error',
        }),
      );
    });

    it('reports sep8/invalid-co-signed-transaction when revised tx is invalid', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ status: 'revised', tx: 'invalid-xdr' }),
      });

      const doc = {
        NETWORK_PASSPHRASE: 'Test SDF Network ; September 2015',
        CURRENCIES: [
          {
            code: 'USDC',
            issuer: 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN',
            approval_server: 'https://approval.example.com',
          },
        ],
      };

      const diagnostics = await verifySep8Webhook(doc, mockFetch);
      expect(diagnostics).toContainEqual(
        expect.objectContaining({
          rule: INVALID_CO_SIGNED_TX_RULE,
          severity: 'error',
        }),
      );
    });

    it('skips currencies without approval_server', async () => {
      const doc = {
        NETWORK_PASSPHRASE: 'Test SDF Network ; September 2015',
        CURRENCIES: [
          { code: 'USDC', issuer: 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN' },
        ],
      };

      const diagnostics = await verifySep8Webhook(doc, mockFetch);
      expect(diagnostics).toEqual([]);
    });
  });

  describe('sep8WebhookRules', () => {
    it('registers expected rules', () => {
      const ruleIds = sep8WebhookRules.map((r) => r.id);
      expect(ruleIds).toContain(WEBHOOK_UNRESPONSIVE_RULE);
      expect(ruleIds).toContain(INVALID_WEBHOOK_RESPONSE_RULE);
      expect(ruleIds).toContain(INVALID_CO_SIGNED_TX_RULE);
      expect(ruleIds).toContain(IDEMPOTENCY_VIOLATION_RULE);
      expect(ruleIds).toContain(WEBHOOK_LATENCY_RULE);
    });
  });
});