import { describe, expect, it } from 'vitest';
import {
  TlsCipherSecurityAuditor,
  auditTlsCiphers,
  hasForwardSecrecy,
  isAeadCipher,
  nodeTlsProbe,
  renderCipherReport,
  tlsCipherRuleIds,
  type HandshakeProbe,
  type HandshakeResult,
  type TlsVersion,
} from '../../src/security/tlsCipherAuditor.js';

const ok = (standard: string): HandshakeResult => ({
  status: 'accepted',
  cipherStandard: standard,
});
const no: HandshakeResult = { status: 'rejected' };

const GCM12 = 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256';
const GCM13 = 'TLS_AES_256_GCM_SHA384';

const server =
  (table: Partial<Record<TlsVersion, HandshakeResult>>): HandshakeProbe =>
  async (_h, _p, v) =>
    table[v] ?? no;

describe('TlsCipherSecurityAuditor', () => {
  it('registers rule ids', () => {
    expect(tlsCipherRuleIds).toContain('tlscipher/legacy-protocol-accepted');
  });

  it('grades a modern TLS 1.2 + 1.3 server A+', async () => {
    const r = await auditTlsCiphers('anchor.example', {
      probe: server({ 'TLSv1.2': ok(GCM12), 'TLSv1.3': ok(GCM13) }),
    });
    expect(r.diagnostics).toEqual([]);
    expect(r.report.grade).toBe('A+');
    expect(renderCipherReport(r.report)).toContain('grade A+');
  });

  it('grades a TLS 1.2 only server A', async () => {
    const r = await auditTlsCiphers('a.example', { probe: server({ 'TLSv1.2': ok(GCM12) }) });
    expect(r.report.grade).toBe('A');
  });

  it('fails a server that accepts TLS 1.0 and 1.1', async () => {
    const r = await auditTlsCiphers('old.example', {
      probe: server({ TLSv1: ok(GCM12), 'TLSv1.1': ok(GCM12), 'TLSv1.2': ok(GCM12) }),
    });
    expect(r.report.grade).toBe('F');
    expect(
      r.diagnostics.filter((d) => d.rule === 'tlscipher/legacy-protocol-accepted'),
    ).toHaveLength(2);
  });

  it('fails when no modern protocol is accepted', async () => {
    const r = await auditTlsCiphers('x.example', { probe: server({}) });
    expect(r.report.grade).toBe('F');
    expect(r.diagnostics[0]?.rule).toBe('tlscipher/no-modern-protocol');
  });

  it('fails weak ciphers such as 3DES and RC4', async () => {
    const r = await auditTlsCiphers('weak.example', {
      probe: server({ 'TLSv1.2': ok('TLS_RSA_WITH_3DES_EDE_CBC_SHA') }),
    });
    expect(r.report.grade).toBe('F');
    expect(r.diagnostics.some((d) => d.rule === 'tlscipher/weak-cipher')).toBe(true);
  });

  it('grades B for CBC without forward secrecy', async () => {
    const r = await auditTlsCiphers('cbc.example', {
      probe: server({ 'TLSv1.2': { status: 'accepted', cipher: 'AES128-SHA256' } }),
    });
    expect(r.report.grade).toBe('B');
    expect(r.diagnostics.map((d) => d.rule).sort()).toEqual([
      'tlscipher/no-forward-secrecy',
      'tlscipher/non-aead-cipher',
    ]);
  });

  it('reports unreachable hosts without a grade', async () => {
    const probe: HandshakeProbe = async () => ({ status: 'error', error: 'ECONNREFUSED' });
    const r = await new TlsCipherSecurityAuditor({ probe }).audit('down.example');
    expect(r.report.grade).toBeNull();
    expect(r.diagnostics[0]?.rule).toBe('tlscipher/unreachable');
  });

  it('honours rule overrides and the port option', async () => {
    const ports: number[] = [];
    const probe: HandshakeProbe = async (_h, port, v) => {
      ports.push(port);
      return v === 'TLSv1' ? ok(GCM12) : v === 'TLSv1.2' ? ok(GCM12) : no;
    };
    const r = await auditTlsCiphers('o.example', {
      probe,
      port: 8443,
      rules: { 'tlscipher/legacy-protocol-accepted': 'off' },
    });
    expect(r.diagnostics).toEqual([]);
    expect(new Set(ports)).toEqual(new Set([8443]));
  });

  it('classifies forward secrecy and AEAD', () => {
    expect(hasForwardSecrecy('TLSv1.3', 'TLS_AES_128_GCM_SHA256')).toBe(true);
    expect(hasForwardSecrecy('TLSv1.2', 'ECDHE-RSA-AES128-GCM-SHA256')).toBe(true);
    expect(hasForwardSecrecy('TLSv1.2', 'AES128-GCM-SHA256')).toBe(false);
    expect(hasForwardSecrecy('TLSv1.2', undefined)).toBe(false);
    expect(isAeadCipher('ECDHE-RSA-CHACHA20-POLY1305')).toBe(true);
    expect(isAeadCipher('ECDHE-RSA-AES256-SHA384')).toBe(false);
  });

  it('tears the socket down and never rejects when the connection is refused', async () => {
    // Port 1 on loopback refuses immediately; no external network is used.
    const result = await nodeTlsProbe(2000)('127.0.0.1', 1, 'TLSv1.2');
    expect(result.status).toBe('error');
  });
});
