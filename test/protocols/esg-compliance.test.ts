import { generateKeyPairSync, sign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  auditEsgDisclosures,
  esgRuleIds,
  rate,
  renderEsgReport,
  verifyAttestationSignature,
} from '../../src/protocols/esgComplianceVerifier.js';

const NOW = new Date('2026-06-01T00:00:00Z');
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const rawKey = (publicKey.export({ format: 'der', type: 'spki' }) as Buffer).subarray(-32);
const KEY_HEX = rawKey.toString('hex');
const ATTESTATION = Buffer.from('Annual carbon audit 2026');
const SIG = sign(null, ATTESTATION, privateKey);

const esg = (extra: Record<string, unknown> = {}) => ({
  DOCUMENTATION: {
    ORG_ESG: {
      CARBON_ACCOUNTING_METHODOLOGY: 'GHG Protocol Scope 2',
      RENEWABLE_ENERGY_CERTIFICATES: ['REC-1', 'REC-2'],
      PUE: 1.15,
      ATTESTATION_URL: 'https://audit.example.com/att.pdf',
      ATTESTATION_SIGNATURE_URL: 'https://audit.example.com/att.sig',
      ATTESTATION_PUBLIC_KEY: KEY_HEX,
      ATTESTATION_EXPIRES: '2027-01-01',
      ...extra,
    },
  },
});

const server = (sig: Buffer = SIG, data: Buffer = ATTESTATION): typeof fetch =>
  (async (url: string) =>
    url.endsWith('.sig')
      ? new Response(sig.toString('hex'))
      : new Response(data)) as unknown as typeof fetch;

describe('EsgComplianceVerifier', () => {
  it('registers rule ids', () => {
    expect(esgRuleIds).toContain('esg/attestation-signature-invalid');
  });

  it('rates scores', () => {
    expect([95, 80, 60, 30, 0].map(rate)).toEqual([
      'Platinum',
      'Gold',
      'Silver',
      'Bronze',
      'Unrated',
    ]);
  });

  it('is silent without an ORG_ESG section', async () => {
    const r = await auditEsgDisclosures({ DOCUMENTATION: {} });
    expect(r.diagnostics).toEqual([]);
    expect(r.report.rating).toBe('Unrated');
  });

  it('verifies a valid attestation and rates Platinum', async () => {
    const r = await auditEsgDisclosures(esg(), server(), { checkAttestation: true, now: NOW });
    expect(r.diagnostics).toEqual([]);
    expect(r.report).toMatchObject({ score: 100, rating: 'Platinum' });
    expect(renderEsgReport(r.report)).toContain('Platinum (100/100)');
  });

  it('accepts a Stellar G... public key and base64 signature', async () => {
    const { StrKey } = await import('@stellar/stellar-base');
    const g = StrKey.encodeEd25519PublicKey(rawKey);
    expect(await verifyAttestationSignature(ATTESTATION, SIG.toString('base64'), g)).toBe(true);
    expect(await verifyAttestationSignature(ATTESTATION, 'zz', g)).toBe(false);
    expect(await verifyAttestationSignature(ATTESTATION, SIG.toString('hex'), 'bad')).toBe(false);
  });

  it('does not download without checkAttestation', async () => {
    const r = await auditEsgDisclosures(esg(), undefined, { now: NOW });
    expect(r.report.score).toBe(85);
    expect(r.report.criteria[3]?.detail).toContain('not verified');
  });

  it('reports missing fields', async () => {
    const r = await auditEsgDisclosures({ DOCUMENTATION: { ORG_ESG: {} } });
    expect(r.diagnostics.map((d) => d.path)).toEqual([
      'DOCUMENTATION.ORG_ESG.CARBON_ACCOUNTING_METHODOLOGY',
      'DOCUMENTATION.ORG_ESG.RENEWABLE_ENERGY_CERTIFICATES',
      'DOCUMENTATION.ORG_ESG.PUE',
      'DOCUMENTATION.ORG_ESG.ATTESTATION_URL',
    ]);
    expect(r.report.score).toBe(0);
  });

  it('reports malformed fields', async () => {
    const r = await auditEsgDisclosures(
      esg({
        CARBON_ACCOUNTING_METHODOLOGY: '',
        RENEWABLE_ENERGY_CERTIFICATES: [1],
        PUE: 0.5,
        ATTESTATION_URL: 'http://x',
      }),
    );
    expect(r.diagnostics.filter((d) => d.rule === 'esg/invalid-field')).toHaveLength(4);
    const date = await auditEsgDisclosures(esg({ ATTESTATION_EXPIRES: 'soon' }), undefined, {
      now: NOW,
    });
    expect(date.diagnostics[0]?.rule).toBe('esg/invalid-field');
  });

  it('flags an expired attestation as an error and withholds credit', async () => {
    const r = await auditEsgDisclosures(esg({ ATTESTATION_EXPIRES: '2026-01-01' }), server(), {
      checkAttestation: true,
      now: NOW,
    });
    expect(r.diagnostics).toEqual([
      expect.objectContaining({ rule: 'esg/attestation-expired', severity: 'error' }),
    ]);
    expect(r.report.score).toBe(75);
  });

  it('flags a bad signature', async () => {
    const r = await auditEsgDisclosures(esg(), server(SIG, Buffer.from('tampered')), {
      checkAttestation: true,
      now: NOW,
    });
    expect(r.diagnostics.map((d) => d.rule)).toEqual(['esg/attestation-signature-invalid']);
    expect(r.report.rating).toBe('Gold');
  });

  it('flags unreachable attestations and missing signature material', async () => {
    const down = (async () => {
      throw new Error('ENOTFOUND');
    }) as unknown as typeof fetch;
    const r = await auditEsgDisclosures(esg(), down, { checkAttestation: true, now: NOW });
    expect(r.diagnostics.map((d) => d.rule)).toEqual(['esg/attestation-unreachable']);
    const notFound = (async () => new Response('', { status: 404 })) as unknown as typeof fetch;
    const r404 = await auditEsgDisclosures(esg(), notFound, { checkAttestation: true, now: NOW });
    expect(r404.diagnostics[0]?.message).toContain('HTTP 404');
    const noSig = await auditEsgDisclosures(
      esg({ ATTESTATION_SIGNATURE_URL: undefined }),
      server(),
      { checkAttestation: true, now: NOW },
    );
    expect(noSig.diagnostics.map((d) => d.rule)).toEqual(['esg/missing-field']);
  });

  it('scores PUE tiers', async () => {
    const scores = await Promise.all(
      [1.1, 1.3, 1.5, 2.0].map(
        async (pue) =>
          (await auditEsgDisclosures(esg({ PUE: pue }), undefined, { now: NOW })).report.criteria[2]
            ?.points,
      ),
    );
    expect(scores).toEqual([25, 20, 12, 5]);
  });

  it('honours severity overrides', async () => {
    const r = await auditEsgDisclosures({ DOCUMENTATION: { ORG_ESG: {} } }, undefined, {
      rules: { 'esg/missing-field': 'off' },
    });
    expect(r.diagnostics).toEqual([]);
  });
});
