import { describe, expect, it } from 'vitest';
import {
  auditOriginExposure,
  ORIGIN_IP_EXPOSED_RULE,
} from '../../src/security/origin-leak-detector.js';

const document = {
  DOCUMENTATION: { ORG_URL: 'https://anchor.example' },
  TRANSFER_SERVER: 'https://api.anchor.example',
};

describe('origin IP exposure auditor', () => {
  it('does not flag a shielded origin', async () => {
    const diagnostics = await auditOriginExposure(document, {
      resolve: async (host) => ({
        addresses: host === 'api.anchor.example' ? ['192.0.2.1'] : [],
        mailHosts: [],
        textRecords: [],
      }),
      probe: async () => false,
    });
    expect(diagnostics).toEqual([]);
  });

  it('warns when an MX-record IP serves the anchor file directly', async () => {
    const diagnostics = await auditOriginExposure(document, {
      resolve: async (host) => ({
        addresses:
          host === 'api.anchor.example'
            ? ['8.8.8.8']
            : host === 'mail.anchor.example'
              ? ['8.8.4.8']
              : [],
        mailHosts: host === 'anchor.example' ? ['mail.anchor.example'] : [],
        textRecords: [],
      }),
      probe: async (ip) => ip === '8.8.4.8',
    });
    expect(diagnostics.map(({ rule, severity }) => [rule, severity])).toEqual([
      [ORIGIN_IP_EXPOSED_RULE, 'warning'],
    ]);
  });
});
