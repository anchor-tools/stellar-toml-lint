import { describe, expect, it } from 'vitest';
import { GeographicDiversityScorer, parseHostPort } from '../../src/overlay/diversityScorer.js';

describe('GeographicDiversityScorer', () => {
  describe('parseHostPort', () => {
    it('parses standard hostname and port', () => {
      expect(parseHostPort('node1.stellar.org:11625')).toEqual({
        hostname: 'node1.stellar.org',
        port: 11625,
      });
    });

    it('parses bare hostname without port', () => {
      expect(parseHostPort('node1.stellar.org')).toEqual({
        hostname: 'node1.stellar.org',
        port: undefined,
      });
    });

    it('parses IPv6 address with brackets and port', () => {
      expect(parseHostPort('[2001:db8::1]:11625')).toEqual({
        hostname: '2001:db8::1',
        port: 11625,
      });
    });
  });

  describe('Diversity Coefficients Calculation', () => {
    const scorer = new GeographicDiversityScorer();

    it('calculates 0 entropy and 0 Simpson index for homogeneous distribution', () => {
      // 4 nodes, all in same ASN
      const metrics = scorer.calculateDiversityMetrics(['AS100', 'AS100', 'AS100', 'AS100']);
      expect(metrics.simpsonIndex).toBe(0);
      expect(metrics.shannonEntropy).toBe(0);
      expect(metrics.normalizedEntropy).toBe(0);
      expect(metrics.uniqueCategories).toBe(1);
      expect(metrics.percentages['AS100']).toBe(100);
    });

    it('calculates maximum diversity for uniform distribution across 4 distinct categories', () => {
      const metrics = scorer.calculateDiversityMetrics(['AS1', 'AS2', 'AS3', 'AS4']);
      // Simpson index = 1 - 4 * (1/4)^2 = 1 - 4*(1/16) = 1 - 0.25 = 0.75
      expect(metrics.simpsonIndex).toBe(0.75);
      // Shannon entropy = -4 * (0.25 * ln(0.25)) = ln(4) ~= 1.3863
      expect(metrics.shannonEntropy).toBeCloseTo(Math.log(4), 3);
      expect(metrics.normalizedEntropy).toBe(1);
      expect(metrics.uniqueCategories).toBe(4);
    });
  });

  describe('score() with stellar.toml', () => {
    it('warns when >= 50% of validator nodes share a single ASN', async () => {
      const toml = `
[[VALIDATORS]]
ALIAS = "node1"
HOST = "node1.example.com:11625"

[[VALIDATORS]]
ALIAS = "node2"
HOST = "node2.example.com:11625"

[[VALIDATORS]]
ALIAS = "node3"
HOST = "node3.example.com:11625"

[[VALIDATORS]]
ALIAS = "node4"
HOST = "node4.example.com:11625"
`;
      // 3 of 4 (75%) share AS16509 (AWS)
      const mockDns = async (h: string) => `192.0.2.${h.slice(4, 5)}`;
      const mockGeo = (ip: string) => {
        if (ip.endsWith('.4')) {
          return {
            asn: 'AS24940',
            asOrg: 'Hetzner',
            cloudProvider: 'Hetzner',
            datacenter: 'hetzner-fsn1',
          };
        }
        return {
          asn: 'AS16509',
          asOrg: 'Amazon.com',
          cloudProvider: 'AWS',
          datacenter: 'aws-us-east-1',
        };
      };

      const scorer = new GeographicDiversityScorer({
        dnsResolver: mockDns,
        geoLookup: mockGeo,
      });

      const report = await scorer.score(toml);
      expect(report.totalValidators).toBe(4);
      expect(report.resolvedValidators).toBe(4);
      expect(report.hasAsnConcentrationRisk).toBe(true);
      expect(report.dominantAsn?.asn).toBe('AS16509');
      expect(report.dominantAsn?.percentage).toBe(75);
      expect(report.hasDatacenterConcentrationRisk).toBe(true);
      expect(report.dominantDatacenter?.datacenter).toBe('aws-us-east-1');
      expect(report.warnings.some((w) => w.includes('Validator centralization risk: 75%'))).toBe(
        true,
      );
      expect(report.warnings.some((w) => w.includes('Datacenter concentration risk: 75%'))).toBe(
        true,
      );
    });

    it('passes without concentration warnings on a geographically diverse validator set', async () => {
      const toml = `
[[VALIDATORS]]
ALIAS = "us-east"
HOST = "aws.example.com:11625"

[[VALIDATORS]]
ALIAS = "eu-central"
HOST = "hetzner.example.com:11625"

[[VALIDATORS]]
ALIAS = "ap-southeast"
HOST = "ovh.example.com:11625"

[[VALIDATORS]]
ALIAS = "sa-east"
HOST = "gcp.example.com:11625"
`;
      const mockDns = async (h: string) => `198.51.100.${h.length}`;
      const mockGeo = (_ip: string, host?: string) => {
        if (host?.includes('aws'))
          return {
            asn: 'AS16509',
            cloudProvider: 'AWS',
            country: 'US',
            datacenter: 'aws-us-east-1',
          };
        if (host?.includes('hetzner'))
          return { asn: 'AS24940', cloudProvider: 'Hetzner', country: 'DE', datacenter: 'fsn1' };
        if (host?.includes('ovh'))
          return { asn: 'AS16276', cloudProvider: 'OVH', country: 'FR', datacenter: 'gra' };
        return { asn: 'AS15169', cloudProvider: 'GCP', country: 'BR', datacenter: 'gcp-sa-east1' };
      };

      const scorer = new GeographicDiversityScorer({
        dnsResolver: mockDns,
        geoLookup: mockGeo,
      });

      const report = await scorer.score(toml);
      expect(report.resolvedValidators).toBe(4);
      expect(report.hasAsnConcentrationRisk).toBe(false);
      expect(report.hasDatacenterConcentrationRisk).toBe(false);
      expect(report.warnings).toHaveLength(0);
      expect(report.asnDiversity.simpsonIndex).toBe(0.75);
      expect(report.countryDiversity.uniqueCategories).toBe(4);
    });

    it('handles unresolvable hostnames gracefully without throwing', async () => {
      const toml = `
[[VALIDATORS]]
ALIAS = "broken"
HOST = "nonexistent.invalid:11625"
`;
      const mockDns = async () => {
        throw new Error('ENOTFOUND');
      };
      const scorer = new GeographicDiversityScorer({ dnsResolver: mockDns });
      const report = await scorer.score(toml);

      expect(report.totalValidators).toBe(1);
      expect(report.resolvedValidators).toBe(0);
      expect(report.validators[0]!.resolved).toBe(false);
      expect(report.warnings).toContain('Could not resolve hostnames for any declared validators.');
    });
  });
});
