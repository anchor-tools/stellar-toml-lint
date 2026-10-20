import { describe, expect, it } from 'vitest';
import {
  auditTlsForwardSecrecy,
  SECURITY_LACKS_FORWARD_SECRECY_RULE,
  SECURITY_SESSION_RESUMPTION_RULE,
} from '../../src/security/tls-pfs-auditor.js';

describe('auditTlsForwardSecrecy', () => {
  it('accepts ephemeral ECDHE key exchange', async () => {
    const result = await auditTlsForwardSecrecy(
      { DOMAIN: 'anchor.example' },
      {
        probe: async () => ({
          cipher: 'ECDHE-RSA-AES128-GCM-SHA256',
          protocol: 'TLSv1.2',
          ephemeral: true,
          sessionReused: false,
        }),
      },
    );

    expect(result).toEqual([]);
  });

  it('reports static RSA key exchange', async () => {
    const result = await auditTlsForwardSecrecy(
      { DOMAIN: 'anchor.example' },
      {
        probe: async () => ({
          cipher: 'AES128-GCM-SHA256',
          protocol: 'TLSv1.2',
          ephemeral: false,
          sessionReused: false,
        }),
      },
    );

    expect(result.map(({ rule }) => rule)).toContain(SECURITY_LACKS_FORWARD_SECRECY_RULE);
  });

  it('warns when the server resumes a TLS session', async () => {
    const result = await auditTlsForwardSecrecy(
      { DOMAIN: 'anchor.example' },
      {
        probe: async () => ({
          cipher: 'TLS_AES_128_GCM_SHA256',
          protocol: 'TLSv1.3',
          ephemeral: true,
          sessionReused: true,
        }),
      },
    );

    expect(result.map(({ rule }) => rule)).toContain(SECURITY_SESSION_RESUMPTION_RULE);
  });

  it('passes the configured observation window to the probe', async () => {
    let observationWindow = 0;
    await auditTlsForwardSecrecy(
      { DOMAIN: 'anchor.example' },
      {
        sessionObservationWindowMs: 600_000,
        probe: async (_hostname, windowMs) => {
          observationWindow = windowMs;
          return {
            cipher: 'TLS_AES_128_GCM_SHA256',
            protocol: 'TLSv1.3',
            ephemeral: true,
            sessionReused: false,
          };
        },
      },
    );

    expect(observationWindow).toBe(600_000);
  });
});
