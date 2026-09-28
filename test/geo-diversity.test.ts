import { describe, expect, it } from 'vitest';
import {
  analyzeValidatorGeoDiversity,
  checkGeoDiversity,
  computeDistribution,
  VALIDATORS_HIGH_ASN_CONCENTRATION,
  VALIDATORS_HIGH_GEOGRAPHIC_CONCENTRATION,
} from '../src/validators/geo-diversity.js';

describe('validator geo-diversity', () => {
  it('passes a diverse validator distribution', () => {
    const diagnostics = checkGeoDiversity([
      { host: 'a', asn: 1, country: 'US' },
      { host: 'b', asn: 2, country: 'DE' },
      { host: 'c', asn: 3, country: 'SG' },
      { host: 'd', asn: 4, country: 'BR' },
    ]);

    expect(diagnostics).toEqual([]);
  });

  it('flags a quorum with 80% on the same ASN', () => {
    const diagnostics = checkGeoDiversity([
      { host: 'a', asn: 64500, country: 'US' },
      { host: 'b', asn: 64500, country: 'CA' },
      { host: 'c', asn: 64500, country: 'MX' },
      { host: 'd', asn: 64500, country: 'GB' },
      { host: 'e', asn: 64501, country: 'DE' },
    ]);

    expect(diagnostics.map((d) => d.rule)).toContain(VALIDATORS_HIGH_ASN_CONCENTRATION);
  });

  it('flags excessive geographic concentration separately', () => {
    const diagnostics = checkGeoDiversity([
      { host: 'a', asn: 1, country: 'US' },
      { host: 'b', asn: 2, country: 'US' },
      { host: 'c', asn: 3, country: 'US' },
      { host: 'd', asn: 4, country: 'DE' },
    ]);

    expect(diagnostics.map((d) => d.rule)).toContain(VALIDATORS_HIGH_GEOGRAPHIC_CONCENTRATION);
  });

  it('computes distribution percentages', () => {
    const distribution = computeDistribution(
      [
        { host: 'a', country: 'US' },
        { host: 'b', country: 'US' },
        { host: 'c', country: 'DE' },
        { host: 'd', country: 'SG' },
      ],
      'country',
    );

    expect(distribution[0]).toMatchObject({ value: 'US', count: 2 });
    expect(distribution[0]?.percent).toBeCloseTo(50, 1);
  });

  it('resolves hosts and enriches them with ASN/country data', async () => {
    const entries = await analyzeValidatorGeoDiversity(
      [{ host: 'a.example' }, { host: 'b.example' }],
      {
        resolveHost: async (host) => (host === 'a.example' ? '192.0.2.1' : '192.0.2.2'),
        lookup: (ip) => (ip === '192.0.2.1' ? { asn: 1, country: 'US' } : { asn: 2, country: 'DE' }),
      },
    );

    expect(entries[0]).toMatchObject({ host: 'a.example', ip: '192.0.2.1', asn: 1, country: 'US' });
    expect(entries[1]).toMatchObject({ host: 'b.example', asn: 2, country: 'DE' });
  });
});
