import { describe, expect, it } from 'vitest';
import {
  SecurityTxtValidator,
  crc24,
  isWellFormedArmor,
  parseExpires,
  parseSecurityTxt,
  securityTxtRuleIds,
  verifySecurityTxt,
} from '../../src/protocols/securityTxtValidator.js';

const NOW = new Date('2026-11-19T00:00:00Z');

const GOOD = [
  '# Security contact for example.com',
  'Contact: mailto:security@example.com',
  'Contact: https://example.com/report',
  'Expires: 2027-06-30T23:59:59Z',
  'Encryption: https://example.com/pgp-key.txt',
  'Acknowledgments: https://example.com/hall-of-fame',
  'Policy: https://example.com/disclosure-policy',
  'Preferred-Languages: en, fr',
  '',
].join('\n');

/** Builds a structurally valid armor block (correct CRC-24) around `data`. */
function armor(data: Uint8Array): string {
  const b64 = Buffer.from(data).toString('base64');
  const crc = crc24(data);
  const crcB64 = Buffer.from([crc >> 16, (crc >> 8) & 0xff, crc & 0xff]).toString('base64');
  return [
    '-----BEGIN PGP SIGNATURE-----',
    '',
    b64,
    `=${crcB64}`,
    '-----END PGP SIGNATURE-----',
  ].join('\n');
}

const signed = (body: string, sig: string): string =>
  ['-----BEGIN PGP SIGNED MESSAGE-----', 'Hash: SHA512', '', body, sig, ''].join('\n');

const check = (
  text: string,
  extra: Partial<ConstructorParameters<typeof SecurityTxtValidator>[1]> = {},
) => verifySecurityTxt(fetch, { domain: 'example.com', text, now: NOW, ...extra });

const rules = (r: { diagnostics: { rule: string }[] }): string[] =>
  r.diagnostics.map((d) => d.rule).sort();

describe('parseExpires', () => {
  it('accepts RFC 3339 date-times with an offset', () => {
    expect(parseExpires('2027-01-31T23:59:59Z')?.toISOString()).toBe('2027-01-31T23:59:59.000Z');
    expect(parseExpires('2027-01-31t23:59:59z')?.toISOString()).toBe('2027-01-31T23:59:59.000Z');
    expect(parseExpires('2027-01-31T23:59:59.500+02:00')?.toISOString()).toBe(
      '2027-01-31T21:59:59.500Z',
    );
    expect(parseExpires(' 2028-02-29T00:00:00-05:00 ')?.toISOString()).toBe(
      '2028-02-29T05:00:00.000Z',
    );
  });

  it('rejects dates without a time, offset or seconds, and impossible values', () => {
    for (const bad of [
      '2027-01-31',
      '2027-01-31T23:59:59',
      '2027-01-31T23:59Z',
      '2027-02-30T00:00:00Z',
      '2027-13-01T00:00:00Z',
      '2027-01-01T24:00:00Z',
      '2027-01-01T23:60:00Z',
      '2027-01-01T23:59:60Z',
      '2027-01-01T00:00:00+25:00',
      'Tue, 31 Jan 2027 23:59:59 GMT',
      '',
    ]) {
      expect(parseExpires(bad), bad).toBeUndefined();
    }
  });
});

describe('SecurityTxtValidator', () => {
  it('registers rule ids', () => {
    expect(securityTxtRuleIds).toContain('securitytxt/expired');
  });

  it('passes a complete file', async () => {
    const r = await check(GOOD);
    expect(r.diagnostics).toEqual([]);
    expect(r.expires?.toISOString()).toBe('2027-06-30T23:59:59.000Z');
    expect(r.parsed?.fields.filter((f) => f.name === 'contact')).toHaveLength(2);
  });

  it('fetches /.well-known/security.txt when no text is given', async () => {
    let seen = '';
    const fetchImpl = (async (url: string) => {
      seen = url;
      return new Response(GOOD, { status: 200 });
    }) as unknown as typeof fetch;
    const r = await new SecurityTxtValidator(fetchImpl, {
      domain: 'example.com',
      now: NOW,
    }).validate();
    expect(seen).toBe('https://example.com/.well-known/security.txt');
    expect(r.diagnostics).toEqual([]);
  });

  it('reports a missing file and unreachable hosts', async () => {
    const notFound = (async () => new Response('nope', { status: 404 })) as unknown as typeof fetch;
    expect(rules(await verifySecurityTxt(notFound, { domain: 'example.com' }))).toEqual([
      'securitytxt/unreachable',
    ]);
    const failing = (async () => {
      throw new Error('ECONNREFUSED');
    }) as unknown as typeof fetch;
    const r = await verifySecurityTxt(failing, { domain: 'example.com' });
    expect(r.diagnostics[0]?.message).toContain('ECONNREFUSED');
  });

  it('flags an expired file', async () => {
    const r = await check(GOOD.replace('2027-06-30T23:59:59Z', '2026-11-18T23:59:59Z'));
    expect(rules(r)).toEqual(['securitytxt/expired']);
  });

  it('notes an expiry more than a year away', async () => {
    const r = await check(GOOD.replace('2027-06-30T23:59:59Z', '2028-06-30T23:59:59Z'));
    expect(rules(r)).toEqual(['securitytxt/expires-too-far']);
    expect(r.diagnostics[0]?.severity).toBe('info');
  });

  it('flags an incomplete file', async () => {
    const r = await check('# nothing useful\nPolicy: https://example.com/policy\n');
    expect(rules(r)).toEqual(['securitytxt/missing-contact', 'securitytxt/missing-expires']);
  });

  it('flags malformed fields', async () => {
    const r = await check(
      [
        'Contact: security@example.com',
        'Contact: http://example.com/report',
        'Expires: next year',
        'Expires: 2027-01-01T00:00:00Z',
        'Encryption: http://example.com/key',
        'Preferred-Languages: en; fr',
        'this line is free text',
      ].join('\n'),
    );
    expect(rules(r)).toEqual([
      'securitytxt/invalid-contact',
      'securitytxt/invalid-contact',
      'securitytxt/invalid-field',
      'securitytxt/invalid-field',
      'securitytxt/invalid-field',
      'securitytxt/invalid-field',
      'securitytxt/invalid-field',
      'securitytxt/missing-policy',
    ]);
  });

  it('accepts tel: contacts and openpgp4fpr: encryption URIs', async () => {
    const r = await check(
      GOOD.replace('Contact: https://example.com/report', 'Contact: tel:+1-201-555-0123').replace(
        'https://example.com/pgp-key.txt',
        'openpgp4fpr:5f2de5521c63a801ab59ccb603d49de44b29100f',
      ),
    );
    expect(r.diagnostics).toEqual([]);
  });

  it('parses a cleartext-signed file and checks the armor CRC-24', async () => {
    const sig = armor(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9]));
    expect(isWellFormedArmor(sig)).toBe(true);
    const parsed = parseSecurityTxt(signed(GOOD, sig));
    expect(parsed.signature?.hash).toBe('SHA512');
    expect(parsed.signature?.signedText).toContain('Contact: mailto:security@example.com');
    expect((await check(signed(GOOD, sig))).diagnostics).toEqual([]);

    const tampered = sig.replace(/^=.{4}$/m, '=AAAA');
    expect(isWellFormedArmor(tampered)).toBe(false);
    expect(rules(await check(signed(GOOD, tampered)))).toEqual(['securitytxt/invalid-signature']);
    expect(rules(await check(signed(GOOD, '')))).toEqual(['securitytxt/invalid-signature']);
  });

  it('delegates cryptographic verification to the injected verifier', async () => {
    const sig = armor(new Uint8Array([9, 8, 7]));
    let received = '';
    const ok = await check(signed(GOOD, sig), {
      verifySignature: async (text) => {
        received = text;
        return true;
      },
    });
    expect(ok.diagnostics).toEqual([]);
    expect(received).toContain('Expires: 2027-06-30T23:59:59Z');

    const bad = await check(signed(GOOD, sig), { verifySignature: async () => false });
    expect(rules(bad)).toEqual(['securitytxt/invalid-signature']);
    const throwing = await check(signed(GOOD, sig), {
      verifySignature: async () => {
        throw new Error('no key');
      },
    });
    expect(rules(throwing)).toEqual(['securitytxt/invalid-signature']);
  });

  it('honours rule overrides', async () => {
    const r = await check(GOOD.replace('Policy: https://example.com/disclosure-policy\n', ''), {
      rules: { 'securitytxt/missing-policy': 'warning' },
    });
    expect(r.diagnostics.map((d) => [d.rule, d.severity])).toEqual([
      ['securitytxt/missing-policy', 'warning'],
    ]);
  });
});
