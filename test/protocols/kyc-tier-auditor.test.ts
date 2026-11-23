import { describe, expect, it } from 'vitest';
import {
  KycTierStateMachineAuditor,
  auditKycStateMachines,
  extractCustomerTypes,
  kycTierRuleIds,
  observationFromCustomer,
  renderKycDiagram,
  type KycModel,
} from '../../src/protocols/kycTierAuditor.js';

const auditor = new KycTierStateMachineAuditor();
const rules = (m: KycModel): string[] => auditor.audit(m).map((d) => d.rule);

const STANDARD: KycModel = {
  type: 'tier1',
  states: {
    NEEDS_INFO: { fields: ['first_name'] },
    PENDING: { more_info_url: 'https://example.com/status' },
    ACCEPTED: {},
    REJECTED: { message: 'declined' },
  },
};

describe('KycTierStateMachineAuditor', () => {
  it('registers rule ids', () => {
    expect(kycTierRuleIds).toHaveLength(5);
  });

  it('accepts the standard SEP-12 machine', () => {
    expect(rules(STANDARD)).toEqual([]);
  });

  it('reports unknown statuses', () => {
    expect(rules({ type: 't', states: { APPROVED: {} } })).toContain(
      'sep12/unknown-customer-status',
    );
  });

  it('requires fields for NEEDS_INFO and a next action for PENDING/REJECTED', () => {
    const d = auditor.audit({
      type: 't',
      states: { NEEDS_INFO: {}, PENDING: {}, REJECTED: {} },
    });
    const missing = d.filter((x) => x.rule === 'sep12/status-missing-next-action');
    expect(missing.map((x) => x.severity)).toEqual(['error', 'warning', 'warning']);
  });

  it('detects circular transitions that never reach a terminal status', () => {
    const model: KycModel = {
      type: 'loop',
      initial: 'NEEDS_INFO',
      states: { NEEDS_INFO: { fields: ['x'] }, PENDING: { message: 'm' } },
      transitions: [
        { from: 'NEEDS_INFO', on: 'submit', to: 'PENDING' },
        { from: 'PENDING', on: 'retry', to: 'NEEDS_INFO' },
      ],
    };
    expect(rules(model).filter((r) => r === 'sep12/circular-status-transition')).toHaveLength(2);
  });

  it('allows a cycle that has an exit', () => {
    const model: KycModel = {
      ...STANDARD,
      initial: 'NEEDS_INFO',
      transitions: [
        { from: 'NEEDS_INFO', on: 'submit', to: 'PENDING' },
        { from: 'PENDING', on: 'request_info', to: 'NEEDS_INFO' },
        { from: 'PENDING', on: 'approve', to: 'ACCEPTED' },
        { from: 'PENDING', on: 'reject', to: 'REJECTED' },
      ],
    };
    expect(rules(model)).toEqual([]);
  });

  it('detects non-deterministic transitions', () => {
    const model: KycModel = {
      ...STANDARD,
      transitions: [
        { from: 'PENDING', on: 'review', to: 'ACCEPTED' },
        { from: 'PENDING', on: 'review', to: 'REJECTED' },
        { from: 'NEEDS_INFO', on: 'submit', to: 'PENDING' },
      ],
    };
    expect(rules(model)).toContain('sep12/nondeterministic-status-transition');
  });

  it('detects orphaned states', () => {
    const model: KycModel = {
      ...STANDARD,
      transitions: [{ from: 'NEEDS_INFO', on: 'submit', to: 'PENDING' }],
    };
    const orphan = auditor.audit(model).filter((d) => d.rule === 'sep12/unreachable-status');
    expect(orphan.map((d) => d.message)).toHaveLength(2);
  });

  it('renders a diagram', () => {
    expect(renderKycDiagram(STANDARD)).toContain('[PENDING] --approve--> [ACCEPTED]');
  });
});

describe('SEP-31 / SEP-12 extraction', () => {
  it('extracts customer types', () => {
    const info = {
      receive: {
        USDC: { sep12: { sender: { types: { a: {}, b: {} } }, receiver: { types: { c: {} } } } },
        XLM: {},
      },
    };
    expect(extractCustomerTypes(info)).toEqual(['a', 'b', 'c']);
    expect(extractCustomerTypes(null)).toEqual([]);
  });

  it('parses customer responses', () => {
    expect(observationFromCustomer({ status: 'NEEDS_INFO', fields: { a: {} } })).toEqual([
      'NEEDS_INFO',
      { fields: ['a'] },
    ]);
    expect(observationFromCustomer({ nope: 1 })).toBeUndefined();
  });

  const json = (b: unknown, status = 200): Response => new Response(JSON.stringify(b), { status });

  it('audits live responses end to end', async () => {
    const fetchImpl = (async (url: string) => {
      if (url.endsWith('/info')) {
        return json({ receive: { USDC: { sep12: { sender: { types: { tier1: {} } } } } } });
      }
      return json({ status: 'NEEDS_INFO' });
    }) as unknown as typeof fetch;
    const r = await auditKycStateMachines(
      { KYC_SERVER: 'https://k.example.com', DIRECT_PAYMENT_SERVER: 'https://d.example.com/' },
      fetchImpl,
    );
    expect(r.models).toHaveLength(1);
    expect(r.diagnostics.map((d) => d.rule)).toEqual(['sep12/status-missing-next-action']);
  });

  it('is silent without servers or when responses need auth', async () => {
    expect((await auditKycStateMachines({})).diagnostics).toEqual([]);
    const denied = (async () => json({}, 401)) as unknown as typeof fetch;
    const r = await auditKycStateMachines(
      { KYC_SERVER: 'https://k', DIRECT_PAYMENT_SERVER: 'https://d' },
      denied,
    );
    expect(r.models).toEqual([]);
  });
});
