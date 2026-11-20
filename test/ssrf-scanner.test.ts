import { describe, expect, it } from 'vitest';
import {
  checkSsrf,
  isBlockedIp,
  normalizeIp,
  renderSsrfReport,
  scanSsrf,
  SECURITY_SSRF_DNS_REBINDING,
  SECURITY_SSRF_PRIVATE_IP,
  ssrfRuleIds,
  type SsrfDnsResolver,
} from '../src/security/ssrfScanner.js';

const DOC = {
  HORIZON_URL: 'https://horizon.anchor.example.com',
  DOCUMENTATION: { ORG_URL: 'https://anchor.example.com' },
};

describe('SSRF scanner', () => {
  it('checks CIDR boundaries, including IPv4-mapped IPv6', () => {
    expect(isBlockedIp('10.0.0.1').blocked).toBe(true);
    expect(isBlockedIp('172.15.0.1').blocked).toBe(false);
    expect(isBlockedIp('172.16.0.1').blocked).toBe(true);
    expect(isBlockedIp('172.31.255.255').blocked).toBe(true);
    expect(isBlockedIp('172.32.0.1').blocked).toBe(false);
    expect(isBlockedIp('192.168.1.1').blocked).toBe(true);
    expect(isBlockedIp('169.254.169.254').reason).toContain('metadata');
    expect(isBlockedIp('127.0.0.1').blocked).toBe(true);
    expect(isBlockedIp('224.0.0.1').blocked).toBe(true);
    expect(isBlockedIp('8.8.8.8').blocked).toBe(false);
    expect(normalizeIp('::ffff:127.0.0.1')).toBe('127.0.0.1');
    expect(normalizeIp('::ffff:7f00:1')).toBe('127.0.0.1');
    expect(isBlockedIp('::ffff:127.0.0.1').blocked).toBe(true);
    expect(isBlockedIp('[::1]').blocked).toBe(true);
    expect(isBlockedIp('fe80::1').blocked).toBe(true);
    expect(isBlockedIp('fc00::1').blocked).toBe(true);
    expect(isBlockedIp('ff02::1').blocked).toBe(true);
    expect(isBlockedIp('2001:4860:4860::8888').blocked).toBe(false);
    expect(isBlockedIp('not-an-ip').blocked).toBe(false);
  });

  it('registers rule ids', () => {
    expect(ssrfRuleIds).toContain(SECURITY_SSRF_PRIVATE_IP);
    expect(ssrfRuleIds).toContain(SECURITY_SSRF_DNS_REBINDING);
  });

  it('passes hostnames that resolve to public addresses', async () => {
    const resolver: SsrfDnsResolver = async () => ['93.184.216.34'];
    const report = await scanSsrf(DOC, { dnsResolver: resolver });
    expect(report.ok).toBe(true);
    expect(report.hostsChecked).toHaveLength(2);
    expect(report.hostsChecked).toEqual(
      expect.arrayContaining(['anchor.example.com', 'horizon.anchor.example.com']),
    );
  });

  it('flags literal private targets without a DNS lookup', async () => {
    let calls = 0;
    const resolver: SsrfDnsResolver = async () => {
      calls++;
      return [];
    };
    const report = await scanSsrf(
      { HORIZON_URL: 'http://169.254.169.254/latest/meta-data' },
      { dnsResolver: resolver },
    );
    expect(report.findings).toHaveLength(1);
    expect(report.findings[0]?.ip).toBe('169.254.169.254');
    expect(report.findings[0]?.reason).toContain('metadata');
    expect(calls).toBe(0);
  });

  it('flags hostnames resolving to private addresses', async () => {
    const resolver: SsrfDnsResolver = async () => ['10.1.2.3'];
    const diagnostics = await checkSsrf(DOC, { dnsResolver: resolver });
    expect(diagnostics[0]).toMatchObject({ rule: SECURITY_SSRF_PRIVATE_IP, severity: 'error' });
    expect(diagnostics[0]?.message).toContain('CRITICAL');
    expect(diagnostics[0]?.suggestion).toContain('RFC 1918');
  });

  it('detects DNS rebinding from public to private', async () => {
    const resolver: SsrfDnsResolver = async (_hostname, attempt) =>
      attempt === 0 ? ['93.184.216.34'] : ['127.0.0.1'];
    const report = await scanSsrf(DOC, { dnsResolver: resolver });
    expect(report.findings.some((finding) => finding.kind === 'rebind')).toBe(true);
    const diagnostics = await checkSsrf(DOC, { dnsResolver: resolver });
    expect(diagnostics.some((d) => d.rule === SECURITY_SSRF_DNS_REBINDING)).toBe(true);
  });

  it('treats consistently private answers as a direct private-IP finding', async () => {
    const resolver: SsrfDnsResolver = async () => ['192.168.5.5'];
    const report = await scanSsrf(DOC, { dnsResolver: resolver });
    expect(report.findings.every((finding) => finding.kind === 'private')).toBe(true);
    expect(report.findings.some((finding) => finding.kind === 'rebind')).toBe(false);
  });

  it('handles IPv4-mapped IPv6 answers from DNS', async () => {
    const resolver: SsrfDnsResolver = async () => ['::ffff:127.0.0.1'];
    const report = await scanSsrf(DOC, { dnsResolver: resolver });
    expect(report.findings[0]?.ip).toBe('127.0.0.1');
  });

  it('survives a slow DNS responder', async () => {
    const slow: SsrfDnsResolver = (_hostname, _attempt, signal) =>
      new Promise((_resolve, reject) => {
        signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
      });
    const report = await scanSsrf(DOC, { dnsResolver: slow, timeoutMs: 10 });
    expect(report.timedOut).toContain('anchor.example.com');
    expect(report.ok).toBe(true);
  });

  it('uses the injected fetch transport for the default resolver', async () => {
    const urls: string[] = [];
    const fetchImpl = (async (input: Parameters<typeof fetch>[0]) => {
      const url = new URL(String(input));
      urls.push(url.toString());
      return new Response(JSON.stringify({ Answer: [{ type: 1, data: '8.8.8.8' }] }), {
        headers: { 'content-type': 'application/dns-json' },
      });
    }) as typeof fetch;
    const report = await scanSsrf(
      { HORIZON_URL: 'https://horizon.example.com' },
      { fetchImpl, resolutionAttempts: 1 },
    );
    expect(urls.some((url) => url.includes('type=A'))).toBe(true);
    expect(report.findings).toEqual([]);
  });

  it('honours --off and renders a report', async () => {
    const resolver: SsrfDnsResolver = async () => ['10.0.0.1'];
    expect(
      await checkSsrf(DOC, { dnsResolver: resolver, rules: { [SECURITY_SSRF_PRIVATE_IP]: 'off' } }),
    ).toEqual([]);

    const report = await scanSsrf(DOC, { dnsResolver: resolver });
    const rendered = renderSsrfReport(report);
    expect(rendered).toContain('[CRITICAL]');
    expect(rendered).toContain('RFC 1918');
    expect(rendered).toContain('Path: HORIZON_URL');
  });

  it('skips documents with no URLs', async () => {
    let calls = 0;
    const resolver: SsrfDnsResolver = async () => {
      calls++;
      return [];
    };
    expect((await scanSsrf({}, { dnsResolver: resolver })).hostsChecked).toEqual([]);
    expect(calls).toBe(0);
  });
});
