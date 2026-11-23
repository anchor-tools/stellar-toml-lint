import { describe, expect, it } from 'vitest';
import {
  ConsumerProtectionVerifier,
  auditConsumerProtection,
  consumerProtectionRuleIds,
  renderScorecard,
} from '../../src/protocols/consumerProtectionVerifier.js';

const COMPLIANT = {
  DOCUMENTATION: {
    ORG_LEGAL: {
      ORG_COMPLAINTS_EMAIL: 'complaints@example.com',
      ORG_DISPUTE_RESOLUTION_URL: 'https://example.com/disputes',
      ORG_JURISDICTION: 'EU',
      ORG_LICENSES: ['MiCA-123'],
    },
  },
};

const ok = (body = 'terms'): typeof fetch =>
  (async () => new Response(body, { status: 200 })) as unknown as typeof fetch;

describe('ConsumerProtectionVerifier', () => {
  it('registers rule ids', () => {
    expect(consumerProtectionRuleIds).toEqual([
      'consumerprotection/missing-field',
      'consumerprotection/invalid-field',
      'consumerprotection/dispute-url-unreachable',
    ]);
  });

  it('passes a compliant file with a 100% scorecard', async () => {
    const r = await auditConsumerProtection(COMPLIANT, ok(), { checkReachability: true });
    expect(r.diagnostics).toEqual([]);
    expect(r.scorecard).toMatchObject({ passed: 4, total: 4, score: 100 });
    expect(renderScorecard(r.scorecard)).toContain('100%');
  });

  it('reports every missing field in an incomplete section', async () => {
    const r = await auditConsumerProtection({ DOCUMENTATION: { ORG_LEGAL: {} } });
    expect(r.diagnostics.map((d) => d.rule)).toEqual(
      Array(4).fill('consumerprotection/missing-field'),
    );
    expect(r.scorecard.score).toBe(0);
  });

  it('accepts fields placed directly in DOCUMENTATION or the root', async () => {
    const r = await auditConsumerProtection({
      ORG_COMPLAINTS_EMAIL: 'a@example.com',
      DOCUMENTATION: {
        ORG_DISPUTE_RESOLUTION_URL: 'https://example.com/d',
        ORG_JURISDICTION: 'US-NY',
        ORG_LICENSES: 'BitLicense',
      },
    });
    expect(r.diagnostics).toEqual([]);
  });

  it('flags malformed values', async () => {
    const r = await auditConsumerProtection({
      DOCUMENTATION: {
        ORG_LEGAL: {
          ORG_COMPLAINTS_EMAIL: 'nope',
          ORG_DISPUTE_RESOLUTION_URL: 'http://example.com',
          ORG_JURISDICTION: '',
          ORG_LICENSES: [],
        },
      },
    });
    expect(r.diagnostics.map((d) => d.rule)).toEqual(
      Array(4).fill('consumerprotection/invalid-field'),
    );
  });

  it('does not touch the network without checkReachability', async () => {
    const fetchImpl = (async () => {
      throw new Error('should not be called');
    }) as unknown as typeof fetch;
    const r = await new ConsumerProtectionVerifier(fetchImpl).verify(COMPLIANT);
    expect(r.diagnostics).toEqual([]);
  });

  it('flags non-200, empty and unreachable dispute URLs', async () => {
    const run = (f: typeof fetch) =>
      auditConsumerProtection(COMPLIANT, f, { checkReachability: true });
    const notFound = (async () => new Response('x', { status: 404 })) as unknown as typeof fetch;
    const failing = (async () => {
      throw new Error('boom');
    }) as unknown as typeof fetch;
    for (const f of [notFound, ok('  '), failing]) {
      const r = await run(f);
      expect(r.diagnostics.map((d) => d.rule)).toEqual([
        'consumerprotection/dispute-url-unreachable',
      ]);
      expect(r.scorecard.passed).toBe(3);
    }
  });

  it('honours rule overrides', async () => {
    const r = await auditConsumerProtection({}, fetch, {
      rules: { 'consumerprotection/missing-field': 'off' },
    });
    expect(r.diagnostics).toEqual([]);
  });
});
