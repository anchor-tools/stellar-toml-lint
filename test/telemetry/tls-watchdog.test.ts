import { describe, expect, it } from 'vitest';
import { TlsCertificateWatchdog } from '../../src/telemetry/tlsWatchdog.js';
import type { TlsRawCertInfo } from '../../src/telemetry/tlsWatchdog.js';

describe('TlsCertificateWatchdog', () => {
  const watchdog = new TlsCertificateWatchdog();

  it('audits healthy certificate with > 30 days remaining and valid OCSP stapling', () => {
    const now = new Date('2026-06-01T00:00:00Z');
    const validTo = new Date('2026-09-01T00:00:00Z'); // 92 days remaining

    const certInfo: TlsRawCertInfo = {
      subject: 'CN=anchor.example.com',
      issuer: "CN=Let's Encrypt Authority",
      validFrom: new Date('2026-05-01T00:00:00Z'),
      validTo,
      ocspResponse: Buffer.from([1, 2, 3]),
      certStatus: 'good',
    };

    const result = watchdog.auditCertificate(certInfo, 'anchor.example.com', now);
    expect(result.valid).toBe(true);
    expect(result.isExpired).toBe(false);
    expect(result.isExpiringSoon).toBe(false);
    expect(result.hasOcspStapling).toBe(true);
    expect(result.daysRemaining).toBe(92);
    expect(result.findings.length).toBe(0);
  });

  it('warns when certificate expiration is less than 30 days away', () => {
    const now = new Date('2026-06-01T00:00:00Z');
    const validTo = new Date('2026-06-15T00:00:00Z'); // 14 days remaining

    const certInfo: TlsRawCertInfo = {
      subject: 'CN=anchor.example.com',
      issuer: 'CN=DigiCert Global Root CA',
      validFrom: new Date('2025-06-01T00:00:00Z'),
      validTo,
      ocspResponse: Buffer.from([1, 2, 3]),
      certStatus: 'good',
    };

    const result = watchdog.auditCertificate(certInfo, 'anchor.example.com', now);
    expect(result.isExpiringSoon).toBe(true);
    expect(result.isExpired).toBe(false);
    expect(result.daysRemaining).toBe(14);
    expect(result.findings.some((f) => f.rule === 'tls/cert-expiring-soon')).toBe(true);
  });

  it('flags expired certificate with critical error', () => {
    const now = new Date('2026-06-01T00:00:00Z');
    const validTo = new Date('2026-05-15T00:00:00Z'); // expired 17 days ago

    const certInfo: TlsRawCertInfo = {
      subject: 'CN=anchor.example.com',
      issuer: 'CN=DigiCert Global Root CA',
      validFrom: new Date('2025-05-15T00:00:00Z'),
      validTo,
      ocspResponse: Buffer.from([1, 2, 3]),
    };

    const result = watchdog.auditCertificate(certInfo, 'anchor.example.com', now);
    expect(result.valid).toBe(false);
    expect(result.isExpired).toBe(true);
    expect(result.findings.some((f) => f.rule === 'tls/cert-expired')).toBe(true);
  });

  it('warns when OCSP stapling is missing from handshake', () => {
    const now = new Date('2026-06-01T00:00:00Z');
    const validTo = new Date('2026-10-01T00:00:00Z');

    const certInfo: TlsRawCertInfo = {
      subject: 'CN=anchor.example.com',
      issuer: "CN=Let's Encrypt",
      validFrom: new Date('2026-05-01T00:00:00Z'),
      validTo,
      ocspResponse: null, // No stapling
    };

    const result = watchdog.auditCertificate(certInfo, 'anchor.example.com', now);
    expect(result.hasOcspStapling).toBe(false);
    expect(result.findings.some((f) => f.rule === 'tls/missing-ocsp-stapling')).toBe(true);
  });

  it('flags revoked certificate via OCSP response', () => {
    const now = new Date('2026-06-01T00:00:00Z');
    const validTo = new Date('2026-10-01T00:00:00Z');

    const certInfo: TlsRawCertInfo = {
      subject: 'CN=anchor.example.com',
      issuer: "CN=Let's Encrypt",
      validFrom: new Date('2026-05-01T00:00:00Z'),
      validTo,
      ocspResponse: Buffer.from([1, 2, 3]),
      certStatus: 'revoked',
    };

    const result = watchdog.auditCertificate(certInfo, 'anchor.example.com', now);
    expect(result.valid).toBe(false);
    expect(result.findings.some((f) => f.rule === 'tls/ocsp-revoked')).toBe(true);
  });

  it('audits domain using custom socket probe to prevent hanging', async () => {
    const mockProbe = async (host: string) => ({
      subject: `CN=${host}`,
      issuer: 'CN=Mock Issuer',
      validFrom: '2026-01-01',
      validTo: '2026-12-31',
      ocspResponse: Buffer.from([1, 2]),
      certStatus: 'good' as const,
    });

    const result = await watchdog.auditDomain('anchor.example.com', {
      socketProbe: mockProbe,
    });

    expect(result.domain).toBe('anchor.example.com');
    expect(result.hasOcspStapling).toBe(true);
    expect(result.valid).toBe(true);
  });

  it('renders report in text and JSON formats', () => {
    const certInfo: TlsRawCertInfo = {
      subject: 'CN=anchor.example.com',
      issuer: 'CN=Mock CA',
      validFrom: new Date('2026-01-01T00:00:00Z'),
      validTo: new Date('2026-12-31T00:00:00Z'),
      ocspResponse: Buffer.from([1]),
    };

    const result = watchdog.auditCertificate(
      certInfo,
      'anchor.example.com',
      new Date('2026-06-01T00:00:00Z'),
    );
    const text = watchdog.renderReport(result, 'text');
    expect(text).toContain('TLS Certificate Watchdog Report for anchor.example.com');
    expect(text).toContain('OCSP Stapling:   ENABLED');

    const jsonStr = watchdog.renderReport(result, 'json');
    const parsed = JSON.parse(jsonStr);
    expect(parsed.domain).toBe('anchor.example.com');
    expect(parsed.hasOcspStapling).toBe(true);
  });
});
