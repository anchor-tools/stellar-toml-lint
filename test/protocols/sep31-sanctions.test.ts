import { describe, expect, it } from 'vitest';
import {
  SANCTIONS_RULE_IDS,
  analyzeSanctionsCompliance,
  sep31SanctionsRules,
  sep31SanctionsRuleIds,
  verifySanctionsCompliance,
} from '../../src/protocols/sep31Sanctions.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function compliantDoc(): Record<string, unknown> {
  return {
    DOCUMENTATION: {
      ORG_NAME: 'Compliant Anchor Inc.',
      ORG_OFFICIAL_EMAIL: 'compliance@example.com',
      ORG_LICENSES: 'MTL-2024-001',
    },
    DIRECT_PAYMENT_SERVER: 'https://sep31.example.com',
  };
}

function fullInfoResponse(): unknown {
  return {
    receive: {
      'USD:GCUSTOMER': {
        transaction_statuses: {
          pending_customer_info_update: {
            description: 'Please update your KYC information.',
          },
          pending_transaction_info_update: {
            description: 'Additional transaction information required.',
          },
          blocked: {
            description:
              'Transaction blocked due to sanctions screening. Contact compliance@example.com or visit https://example.com/dispute to resolve.',
          },
        },
      },
    },
  };
}

function mockFetch(info: unknown, status = 200): typeof fetch {
  return (async () =>
    new Response(JSON.stringify(info), {
      status,
      headers: { 'content-type': 'application/json' },
    })) as unknown as typeof fetch;
}

// ---------------------------------------------------------------------------

describe('analyzeSanctionsCompliance — static document checks', () => {
  it('passes a fully compliant document with all required fields', () => {
    const report = analyzeSanctionsCompliance(compliantDoc(), fullInfoResponse());
    expect(report.ok).toBe(true);
    expect(report.hasLicensesField).toBe(true);
    expect(report.hasContactField).toBe(true);
  });

  it('warns when ORG_LICENSES is absent', () => {
    const doc = compliantDoc();
    (doc.DOCUMENTATION as Record<string, unknown>).ORG_LICENSES = undefined;
    const report = analyzeSanctionsCompliance(doc, fullInfoResponse());
    const rules = report.diagnostics.map((d) => d.rule);
    expect(rules).toContain(SANCTIONS_RULE_IDS.licensesAbsent);
    expect(report.hasLicensesField).toBe(false);
  });

  it('warns when ORG_OFFICIAL_EMAIL is absent', () => {
    const doc = compliantDoc();
    (doc.DOCUMENTATION as Record<string, unknown>).ORG_OFFICIAL_EMAIL = undefined;
    const report = analyzeSanctionsCompliance(doc, fullInfoResponse());
    const rules = report.diagnostics.map((d) => d.rule);
    expect(rules).toContain(SANCTIONS_RULE_IDS.contactAbsent);
    expect(report.hasContactField).toBe(false);
  });

  it('warns when DOCUMENTATION table is entirely absent', () => {
    const report = analyzeSanctionsCompliance({}, fullInfoResponse());
    const rules = report.diagnostics.map((d) => d.rule);
    expect(rules).toContain(SANCTIONS_RULE_IDS.licensesAbsent);
    expect(rules).toContain(SANCTIONS_RULE_IDS.contactAbsent);
  });

  it('suppresses a static warning when the rule is turned off', () => {
    const doc = compliantDoc();
    (doc.DOCUMENTATION as Record<string, unknown>).ORG_LICENSES = undefined;
    const report = analyzeSanctionsCompliance(doc, fullInfoResponse(), {
      rules: { [SANCTIONS_RULE_IDS.licensesAbsent]: 'off' },
    });
    expect(report.diagnostics.map((d) => d.rule)).not.toContain(SANCTIONS_RULE_IDS.licensesAbsent);
  });
});

describe('analyzeSanctionsCompliance — dynamic /info checks', () => {
  it('passes when /info declares all required hold statuses with dispute reference', () => {
    const report = analyzeSanctionsCompliance(compliantDoc(), fullInfoResponse());
    expect(report.ok).toBe(true);
    expect(report.corridors).toHaveLength(1);
    expect(report.corridors[0]?.hasBlockedStatus).toBe(true);
    expect(report.corridors[0]?.hasDisputeContact).toBe(true);
  });

  it('errors when "blocked" status is missing from /info', () => {
    const info = {
      receive: {
        'USD:GCUSTOMER': {
          transaction_statuses: {
            pending_customer_info_update: { description: 'update kyc' },
          },
        },
      },
    };
    const report = analyzeSanctionsCompliance(compliantDoc(), info);
    expect(report.ok).toBe(false);
    expect(report.diagnostics.map((d) => d.rule)).toContain(SANCTIONS_RULE_IDS.blockedStatusAbsent);
  });

  it('warns when "blocked" is present but has no dispute contact', () => {
    const info = {
      receive: {
        'USD:GCUSTOMER': {
          transaction_statuses: {
            pending_customer_info_update: { description: 'x' },
            pending_transaction_info_update: { description: 'x' },
            blocked: { description: 'Transaction blocked.' },
          },
        },
      },
    };
    const report = analyzeSanctionsCompliance(compliantDoc(), info);
    const rules = report.diagnostics.map((d) => d.rule);
    expect(rules).toContain(SANCTIONS_RULE_IDS.disputeContactAbsent);
    expect(rules).not.toContain(SANCTIONS_RULE_IDS.blockedStatusAbsent);
  });

  it('warns when "pending_customer_info_update" is absent', () => {
    const info = {
      receive: {
        'USD:GCUSTOMER': {
          transaction_statuses: {
            blocked: { description: 'contact compliance@example.com' },
          },
        },
      },
    };
    const report = analyzeSanctionsCompliance(compliantDoc(), info);
    expect(report.diagnostics.map((d) => d.rule)).toContain(SANCTIONS_RULE_IDS.pendingStatusAbsent);
  });

  it('reports per-corridor compliance entries', () => {
    const info = {
      receive: {
        'EUR:GCUSTOMER': {
          transaction_statuses: {
            blocked: { description: 'contact@example.com' },
            pending_customer_info_update: { description: 'x' },
            pending_transaction_info_update: { description: 'x' },
          },
        },
        'USD:GCUSTOMER': {
          transaction_statuses: {
            pending_customer_info_update: { description: 'x' },
          },
        },
      },
    };
    const report = analyzeSanctionsCompliance(compliantDoc(), info);
    expect(report.corridors).toHaveLength(2);
    const eur = report.corridors.find((c) => c.asset === 'EUR:GCUSTOMER');
    const usd = report.corridors.find((c) => c.asset === 'USD:GCUSTOMER');
    expect(eur?.hasBlockedStatus).toBe(true);
    expect(usd?.hasBlockedStatus).toBe(false);
  });

  it('handles a /info body with no receive map gracefully', () => {
    const report = analyzeSanctionsCompliance(compliantDoc(), { not_receive: {} });
    expect(report.corridors).toHaveLength(0);
    // Static checks still run
    expect(report.hasLicensesField).toBe(true);
  });

  it('handles a /info body that is not an object', () => {
    const report = analyzeSanctionsCompliance(compliantDoc(), null);
    expect(report.corridors).toHaveLength(0);
  });
});

describe('verifySanctionsCompliance — network path', () => {
  it('fetches /info and validates a compliant anchor', async () => {
    const report = await verifySanctionsCompliance(compliantDoc(), {
      fetchImpl: mockFetch(fullInfoResponse()),
    });
    expect(report.ok).toBe(true);
    expect(report.corridors).toHaveLength(1);
  });

  it('reports infoUnavailable when /info returns a non-200 status', async () => {
    const report = await verifySanctionsCompliance(compliantDoc(), {
      fetchImpl: mockFetch({}, 503),
    });
    const rules = report.diagnostics.map((d) => d.rule);
    expect(rules).toContain(SANCTIONS_RULE_IDS.infoUnavailable);
  });

  it('reports infoUnavailable when the fetch throws', async () => {
    const failingFetch = (async () => {
      throw new Error('connection refused');
    }) as unknown as typeof fetch;
    const report = await verifySanctionsCompliance(compliantDoc(), {
      fetchImpl: failingFetch,
    });
    expect(report.diagnostics.map((d) => d.rule)).toContain(SANCTIONS_RULE_IDS.infoUnavailable);
  });

  it('returns a report with only static checks when DIRECT_PAYMENT_SERVER is absent', async () => {
    const doc = { DOCUMENTATION: { ORG_LICENSES: 'MTL-001', ORG_OFFICIAL_EMAIL: 'a@b.com' } };
    const report = await verifySanctionsCompliance(doc);
    expect(report.corridors).toHaveLength(0);
    expect(report.hasLicensesField).toBe(true);
  });

  it('returns a report with only static checks when DIRECT_PAYMENT_SERVER is not a URL', async () => {
    const doc = {
      DOCUMENTATION: { ORG_LICENSES: 'MTL-001', ORG_OFFICIAL_EMAIL: 'a@b.com' },
      DIRECT_PAYMENT_SERVER: 'not-a-url',
    };
    const report = await verifySanctionsCompliance(doc);
    expect(report.corridors).toHaveLength(0);
  });
});

describe('sep31SanctionsRules', () => {
  it('registers all expected rule ids', () => {
    const ids = sep31SanctionsRules.map((r) => r.id);
    for (const ruleId of Object.values(SANCTIONS_RULE_IDS)) {
      expect(ids).toContain(ruleId);
    }
  });

  it('exports sep31SanctionsRuleIds matching the rule list', () => {
    expect(sep31SanctionsRuleIds).toEqual(sep31SanctionsRules.map((r) => r.id));
  });
});
