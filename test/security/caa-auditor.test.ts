import { describe, expect, it } from 'vitest';
import {
  auditCaa,
  isCaaIssuerAuthorized,
  SECURITY_UNAUTHORIZED_CA_RULE,
} from '../../src/security/caa-auditor.js';

describe('auditCaa', () => {
  it('accepts CAA records that authorize the active certificate issuer', async () => {
    const result = await auditCaa(
      { DOMAIN: 'anchor.example' },
      {
        resolveCaa: async () => [{ issue: 'letsencrypt.org', issuewild: 'letsencrypt.org' }],
        certificateIssuer: async () => "C=US, O=Let's Encrypt, CN=R3",
      },
    );

    expect(result).toEqual([]);
  });

  it('reports a certificate issuer not authorized by CAA', async () => {
    const result = await auditCaa(
      { DOMAIN: 'anchor.example' },
      {
        resolveCaa: async () => [{ issue: 'digicert.com', issuewild: 'digicert.com' }],
        certificateIssuer: async () => "O=Let's Encrypt, CN=R3",
      },
    );

    expect(result.map(({ rule }) => rule)).toContain(SECURITY_UNAUTHORIZED_CA_RULE);
  });
});

it('matches common CA issuer names to CAA issuer identifiers', () => {
  expect(isCaaIssuerAuthorized('O=DigiCert Inc', ['digicert.com'])).toBe(true);
});
