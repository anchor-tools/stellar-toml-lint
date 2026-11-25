import { describe, expect, it } from 'vitest';
import {
  DnsCaaRecordValidator,
  auditDnsCaa,
  caaLookupChain,
  dnsCaaRuleIds,
  isValidIodef,
  issuerOf,
  type CaaRecord,
  type CaaResolver,
} from '../../src/protocols/dnsCaaValidator.js';

const noData = (): Error => Object.assign(new Error('queryCaa ENODATA'), { code: 'ENODATA' });

/** Resolver backed by a zone map; names not in the map have no CAA records. */
const zone =
  (records: Record<string, CaaRecord[]>, log: string[] = []): CaaResolver =>
  async (name) => {
    log.push(name);
    const found = records[name];
    if (found === undefined) throw noData();
    return found;
  };

const GOOD: CaaRecord[] = [
  { critical: 0, issue: 'letsencrypt.org' },
  { critical: 0, issuewild: ';' },
  { critical: 0, iodef: 'mailto:security@example.com' },
];

const rules = (r: { diagnostics: { rule: string }[] }): string[] =>
  r.diagnostics.map((d) => d.rule).sort();

describe('DnsCaaRecordValidator', () => {
  it('registers rule ids', () => {
    expect(dnsCaaRuleIds).toContain('caa/missing-records');
  });

  it('builds the lookup chain up to, but not including, the TLD', () => {
    expect(caaLookupChain('Anchor.Pay.Example.com.')).toEqual([
      'anchor.pay.example.com',
      'pay.example.com',
      'example.com',
    ]);
    expect(caaLookupChain('com')).toEqual([]);
  });

  it('parses issuer values and iodef URLs', () => {
    expect(issuerOf('LetsEncrypt.org; validationmethods=dns-01')).toBe('letsencrypt.org');
    expect(issuerOf(';')).toBe('');
    expect(isValidIodef('mailto:security@example.com')).toBe(true);
    expect(isValidIodef('https://example.com/caa-report')).toBe(true);
    expect(isValidIodef('mailto:nobody')).toBe(false);
    expect(isValidIodef('ftp://example.com')).toBe(false);
    expect(isValidIodef('not a url')).toBe(false);
  });

  it('passes a complete policy', async () => {
    const r = await auditDnsCaa({ domain: 'example.com', resolver: zone({ 'example.com': GOOD }) });
    expect(r.diagnostics).toEqual([]);
    expect(r.relevantName).toBe('example.com');
  });

  it('climbs to the parent zone and stops at the first record set (RFC 8659 §3)', async () => {
    const log: string[] = [];
    const r = await auditDnsCaa({
      domain: 'api.anchor.example.com',
      resolver: zone({ 'example.com': GOOD }, log),
    });
    expect(log).toEqual(['api.anchor.example.com', 'anchor.example.com', 'example.com']);
    expect(r.relevantName).toBe('example.com');
    expect(r.diagnostics).toEqual([]);
  });

  it('judges a CNAME-aliased name by the records the resolver returns for it', async () => {
    // The stub resolver, like a real one, answers for the alias with the target's records.
    const r = await auditDnsCaa({
      domain: 'www.example.com',
      resolver: zone({ 'www.example.com': [{ critical: 0, issue: 'digicert.com' }] }),
    });
    expect(r.relevantName).toBe('www.example.com');
    expect(rules(r)).toEqual(['caa/missing-iodef', 'caa/missing-issuewild']);
  });

  it('warns when no zone has CAA records', async () => {
    const r = await auditDnsCaa({ domain: 'a.example.com', resolver: zone({}) });
    expect(rules(r)).toEqual(['caa/missing-records']);
    expect(r.queried).toEqual(['a.example.com', 'example.com']);
  });

  it('flags overly permissive and unknown CA records', async () => {
    const r = await auditDnsCaa({
      domain: 'example.com',
      resolver: zone({
        'example.com': [
          { critical: 0, issuewild: 'cheap-certs.example' },
          { critical: 0, iodef: 'ftp://example.com' },
        ],
      }),
    });
    expect(rules(r)).toEqual(['caa/invalid-iodef', 'caa/missing-issue', 'caa/unrecognized-ca']);
  });

  it('flags unknown critical tags but ignores unknown non-critical ones', async () => {
    const critical = await auditDnsCaa({
      domain: 'example.com',
      resolver: zone({ 'example.com': [...GOOD, { critical: 128, tbs: 'x' }] }),
    });
    expect(rules(critical)).toEqual(['caa/unknown-critical-tag']);
    const relaxed = await auditDnsCaa({
      domain: 'example.com',
      resolver: zone({ 'example.com': [...GOOD, { critical: 0, tbs: 'x' }] }),
    });
    expect(relaxed.diagnostics).toEqual([]);
  });

  it('reports DNS timeouts instead of rejecting', async () => {
    const r = await new DnsCaaRecordValidator({
      domain: 'example.com',
      resolver: async () => {
        throw Object.assign(new Error('queryCaa ETIMEOUT example.com'), { code: 'ETIMEOUT' });
      },
    }).validate();
    expect(rules(r)).toEqual(['caa/lookup-failed']);
    expect(r.diagnostics[0]?.message).toContain('ETIMEOUT');
  });

  it('honours rule overrides and a custom CA list', async () => {
    const r = await auditDnsCaa({
      domain: 'example.com',
      resolver: zone({ 'example.com': [{ critical: 0, issue: 'internal-ca.example' }] }),
      recognizedCas: ['internal-ca.example'],
      rules: { 'caa/missing-iodef': 'off', 'caa/missing-issuewild': 'error' },
    });
    expect(r.diagnostics.map((d) => [d.rule, d.severity])).toEqual([
      ['caa/missing-issuewild', 'error'],
    ]);
  });
});
