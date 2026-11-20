import { describe, expect, it } from 'vitest';
import {
  checkSubdomainTakeover,
  renderTakeoverReport,
  scanSubdomainTakeover,
  SECURITY_DNS_TAKEOVER_CNAME,
  SECURITY_DNS_TAKEOVER_NS,
  SECURITY_DNS_TAKEOVER_TIMEOUT,
  subdomainTakeoverRuleIds,
  TAKEOVER_SIGNATURES,
  type TakeoverDnsRecord,
  type TakeoverDnsResponse,
  type TakeoverDnsResolver,
} from '../src/security/subdomainScanner.js';

function answer(type: TakeoverDnsRecord['type'], ...values: string[]): TakeoverDnsResponse {
  return {
    status: 'NOERROR',
    records: values.map((value) => ({ type, value })),
  };
}

const EMPTY: TakeoverDnsResponse = { status: 'NOERROR', records: [] };
const NXDOMAIN: TakeoverDnsResponse = { status: 'NXDOMAIN', records: [] };

function resolverFor(records: Record<string, TakeoverDnsResponse>): TakeoverDnsResolver {
  return async (domain, type) => records[`${type}:${domain}`] ?? EMPTY;
}

const DOC = {
  DOMAIN: 'anchor.example.com',
  HORIZON_URL: 'https://horizon.anchor.example.com',
  DOCUMENTATION: { ORG_LOGO: 'https://cdn.anchor.example.com/logo.png' },
};

describe('subdomain takeover scanner', () => {
  it('registers stable rule ids', () => {
    expect(subdomainTakeoverRuleIds).toEqual([
      SECURITY_DNS_TAKEOVER_CNAME,
      SECURITY_DNS_TAKEOVER_NS,
      SECURITY_DNS_TAKEOVER_TIMEOUT,
    ]);
  });

  it('maps intact CNAMEs to no findings', async () => {
    const resolver = resolverFor({
      'CNAME:cdn.anchor.example.com': answer('CNAME', 'assets.s3.amazonaws.com'),
      'A:assets.s3.amazonaws.com': answer('A', '192.0.2.10'),
    });
    const report = await scanSubdomainTakeover(DOC, { dnsResolver: resolver });
    expect(report.ok).toBe(true);
    expect(report.findings).toEqual([]);
    expect(report.domainsChecked).toContain('example.com');
    expect(report.domainsChecked).toContain('cdn.anchor.example.com');
  });

  it('flags a dangling S3 CNAME as critical', async () => {
    const resolver = resolverFor({
      'CNAME:cdn.anchor.example.com': answer('CNAME', 'abandoned-bucket.s3.amazonaws.com'),
      'A:abandoned-bucket.s3.amazonaws.com': NXDOMAIN,
      'AAAA:abandoned-bucket.s3.amazonaws.com': NXDOMAIN,
    });
    const diagnostics = await checkSubdomainTakeover(DOC, { dnsResolver: resolver });
    const finding = diagnostics.find((d) => d.rule === SECURITY_DNS_TAKEOVER_CNAME);
    expect(finding).toMatchObject({ severity: 'error', category: 'network' });
    expect(finding?.message).toContain('CRITICAL');
    expect(finding?.message).toContain('AWS S3');
    expect(finding?.suggestion).toContain('bucket');
  });

  it('rates dangling CNAMEs without a known signature as high', async () => {
    const resolver = resolverFor({
      'CNAME:cdn.anchor.example.com': answer('CNAME', 'old-site.unknown-host.example.net'),
      'A:old-site.unknown-host.example.net': NXDOMAIN,
      'AAAA:old-site.unknown-host.example.net': NXDOMAIN,
    });
    const report = await scanSubdomainTakeover(DOC, { dnsResolver: resolver });
    expect(report.findings).toHaveLength(1);
    expect(report.findings[0]?.risk).toBe('high');
    expect(report.findings[0]?.signature).toBeUndefined();
  });

  it('detects dangling NS delegations to known providers', async () => {
    const resolver = resolverFor({
      'NS:anchor.example.com': answer('NS', 'ns-123.awsdns-45.com'),
      'A:ns-123.awsdns-45.com': NXDOMAIN,
    });
    const report = await scanSubdomainTakeover(
      { DOMAIN: 'anchor.example.com' },
      { dnsResolver: resolver },
    );
    const nsFinding = report.findings.find((finding) => finding.recordType === 'NS');
    expect(nsFinding?.risk).toBe('critical');
    expect(nsFinding?.signature?.provider).toContain('Route 53');
  });

  it('does not query when the document has no domains', async () => {
    let calls = 0;
    const resolver: TakeoverDnsResolver = async () => {
      calls++;
      return EMPTY;
    };
    const report = await scanSubdomainTakeover({}, { dnsResolver: resolver });
    expect(report.domainsChecked).toEqual([]);
    expect(calls).toBe(0);
  });

  it('survives a slow DNS responder and reports the timeout', async () => {
    const slow: TakeoverDnsResolver = (_domain, _type, signal) =>
      new Promise((_resolve, reject) => {
        signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
      });
    const report = await scanSubdomainTakeover(DOC, { dnsResolver: slow, timeoutMs: 10 });
    expect(report.timedOut.length).toBeGreaterThan(0);
    expect(report.ok).toBe(true);

    const diagnostics = await checkSubdomainTakeover(DOC, {
      dnsResolver: slow,
      timeoutMs: 10,
    });
    expect(diagnostics.some((d) => d.rule === SECURITY_DNS_TAKEOVER_TIMEOUT)).toBe(true);
  });

  it('honours rule overrides', async () => {
    const resolver = resolverFor({
      'CNAME:cdn.anchor.example.com': answer('CNAME', 'gone.github.io'),
      'A:gone.github.io': NXDOMAIN,
      'AAAA:gone.github.io': NXDOMAIN,
    });
    expect(
      await checkSubdomainTakeover(DOC, {
        dnsResolver: resolver,
        rules: { [SECURITY_DNS_TAKEOVER_CNAME]: 'off' },
      }),
    ).toEqual([]);
  });

  it('uses the injected fetch transport for the default DoH resolver', async () => {
    const urls: string[] = [];
    const fetchImpl = (async (input: Parameters<typeof fetch>[0]) => {
      const url = new URL(String(input));
      urls.push(url.toString());
      const type = url.searchParams.get('type');
      return new Response(
        JSON.stringify({
          Status: 0,
          Answer:
            type === 'CNAME'
              ? [{ type: 5, data: 'live.github.io.' }]
              : [{ type: type === 'AAAA' ? 28 : 1, data: '192.0.2.10' }],
        }),
        { headers: { 'content-type': 'application/dns-json' } },
      );
    }) as typeof fetch;
    const report = await scanSubdomainTakeover({ DOMAIN: 'anchor.example.com' }, { fetchImpl });
    expect(urls.length).toBeGreaterThan(0);
    expect(urls[0]).toContain('type=CNAME');
    expect(report.findings).toEqual([]);
  });

  it('renders risk ratings in the report', () => {
    const rendered = renderTakeoverReport({
      findings: [
        {
          domain: 'cdn.anchor.example.com',
          target: 'gone.s3.amazonaws.com',
          recordType: 'CNAME',
          risk: 'critical',
          message: 'dangling',
          remediation: 'Remove the CNAME',
        },
      ],
      domainsChecked: ['anchor.example.com'],
      timedOut: [],
      ok: false,
    });
    expect(rendered).toContain('1 critical');
    expect(rendered).toContain('[CRITICAL]');
    expect(rendered).toContain('Remove the CNAME');
    expect(TAKEOVER_SIGNATURES.length).toBeGreaterThan(5);
  });
});
