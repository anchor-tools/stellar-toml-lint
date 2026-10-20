import { describe, expect, it } from 'vitest';
import { auditEmailDns, SECURITY_MISSING_DMARC_RULE } from '../../src/security/dmarc-auditor.js';

describe('auditEmailDns', () => {
  it('accepts a strict SPF policy and enforcing DMARC record', async () => {
    const result = await auditEmailDns(
      { DOMAIN: 'anchor.example' },
      {
        resolveTxt: async (hostname) =>
          hostname.startsWith('_dmarc.')
            ? [['v=DMARC1; p=reject']]
            : [['v=spf1 include:mail.example -all']],
      },
    );

    expect(result).toEqual([]);
  });

  it('reports a missing DMARC record', async () => {
    const result = await auditEmailDns(
      { DOMAIN: 'anchor.example' },
      {
        resolveTxt: async (hostname) => (hostname.startsWith('_dmarc.') ? [] : [['v=spf1 -all']]),
      },
    );

    expect(result.map(({ rule }) => rule)).toContain(SECURITY_MISSING_DMARC_RULE);
  });

  it('uses the official email domain for SPF and DMARC lookups', async () => {
    const queried: string[] = [];
    await auditEmailDns(
      {
        DOMAIN: 'stellar.toml.example',
        DOCUMENTATION: { ORG_OFFICIAL_EMAIL: 'security@mail.example' },
      },
      {
        resolveTxt: async (hostname) => {
          queried.push(hostname);
          return [['v=spf1 -all']];
        },
      },
    );

    expect(queried).toContain('mail.example');
    expect(queried).toContain('_dmarc.mail.example');
  });
});
