import { describe, expect, it } from 'vitest';
import {
  analyzeCtCertificates,
  checkCertificateTransparency,
  SECURITY_MISSING_SCT_TIMESTAMPS,
  SECURITY_UNRECOGNIZED_CA_IN_CT_LOGS,
} from '../src/security/ct-auditor.js';

describe('certificate transparency auditor', () => {
  it('passes a valid certificate issued by a recognized CA', () => {
    const diagnostics = analyzeCtCertificates('anchor.example', [
      { issuer: "C=US, O=Let's Encrypt, CN=R3" },
    ]);

    expect(diagnostics).toEqual([]);
  });

  it('flags an untrusted CA in the CT logs', () => {
    const diagnostics = analyzeCtCertificates('anchor.example', [
      { issuer: 'CN=Rogue Intermediate CA' },
    ]);

    expect(diagnostics.map((d) => d.rule)).toContain(SECURITY_UNRECOGNIZED_CA_IN_CT_LOGS);
  });

  it('warns when there are no CT entries for the domain', () => {
    const diagnostics = analyzeCtCertificates('anchor.example', []);

    expect(diagnostics.map((d) => d.rule)).toContain(SECURITY_MISSING_SCT_TIMESTAMPS);
  });

  it('queries the CT log API and accepts a recognized issuer', async () => {
    const fetchImpl = (async () =>
      new Response(JSON.stringify([{ issuer_name: 'O=DigiCert Inc' }]), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })) as typeof fetch;

    const diagnostics = await checkCertificateTransparency('anchor.example', {
      fetchImpl,
      logUrl: 'https://ct.example',
    });

    expect(diagnostics).toEqual([]);
  });

  it('flags an untrusted CA returned by the CT log API', async () => {
    const fetchImpl = (async () =>
      new Response(JSON.stringify([{ issuer_name: 'CN=Suspicious CA' }]), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })) as typeof fetch;

    const diagnostics = await checkCertificateTransparency('anchor.example', {
      fetchImpl,
      logUrl: 'https://ct.example',
    });

    expect(diagnostics.map((d) => d.rule)).toContain(SECURITY_UNRECOGNIZED_CA_IN_CT_LOGS);
  });

  it('degrades to silence when the CT log is unreachable', async () => {
    const fetchImpl = (async () => {
      throw new Error('ECONNREFUSED');
    }) as unknown as typeof fetch;

    expect(await checkCertificateTransparency('anchor.example', { fetchImpl })).toEqual([]);
  });
});
