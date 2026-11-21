import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { parse as parseToml } from 'smol-toml';
import type { StellarToml } from '../types.js';

export interface ValidatorLocation {
  publicKey?: string;
  alias?: string;
  displayName?: string;
  rawHost: string;
  hostname: string;
  port?: number;
  ip?: string;
  country?: string;
  countryCode?: string;
  region?: string;
  city?: string;
  asn?: string;
  asOrg?: string;
  cloudProvider?: string;
  datacenter?: string;
  resolved: boolean;
  error?: string;
}

export interface DiversityMetrics {
  simpsonIndex: number;
  shannonEntropy: number;
  normalizedEntropy: number;
  uniqueCategories: number;
  distribution: Record<string, number>;
  percentages: Record<string, number>;
}

export interface GeographicDiversityReport {
  totalValidators: number;
  resolvedValidators: number;
  validators: ValidatorLocation[];
  asnDiversity: DiversityMetrics;
  countryDiversity: DiversityMetrics;
  datacenterDiversity: DiversityMetrics;
  dominantAsn?: { asn: string; asOrg?: string; percentage: number };
  dominantDatacenter?: { datacenter: string; provider?: string; percentage: number };
  hasAsnConcentrationRisk: boolean;
  hasDatacenterConcentrationRisk: boolean;
  warnings: string[];
}

export type GeoDnsResolver = (hostname: string) => Promise<string | string[]>;
export type DnsResolver = GeoDnsResolver;
export type GeoLookupResolver = (
  ip: string,
  hostname?: string,
) => Promise<Partial<ValidatorLocation>> | Partial<ValidatorLocation>;

export interface GeographicDiversityScorerOptions {
  dnsResolver?: GeoDnsResolver;
  geoLookup?: GeoLookupResolver;
}

/**
 * Splits a host string like "host:11625" or "[::1]:11625" into hostname and port.
 */
export function parseHostPort(rawHost: string): { hostname: string; port?: number } {
  const trimmed = rawHost.trim();
  if (trimmed.startsWith('[')) {
    const closeBracket = trimmed.indexOf(']');
    if (closeBracket !== -1) {
      const hostname = trimmed.slice(1, closeBracket);
      const rest = trimmed.slice(closeBracket + 1);
      if (rest.startsWith(':')) {
        const port = Number.parseInt(rest.slice(1), 10);
        return { hostname, port: Number.isFinite(port) ? port : undefined };
      }
      return { hostname };
    }
  }

  const parts = trimmed.split(':');
  if (parts.length === 2 && !Number.isNaN(Number(parts[1]))) {
    return { hostname: parts[0]!, port: Number.parseInt(parts[1]!, 10) };
  }

  return { hostname: trimmed };
}

/**
 * Infers cloud provider and ASN metadata from hostname/IP heuristics when no external lookup is provided.
 */
function inferDefaultGeoMetadata(ip: string, hostname: string): Partial<ValidatorLocation> {
  const h = hostname.toLowerCase();

  if (h.includes('aws') || h.includes('amazon') || h.includes('compute.amazonaws.com')) {
    return {
      asn: 'AS16509',
      asOrg: 'Amazon.com, Inc.',
      cloudProvider: 'AWS',
      datacenter: h.includes('us-east-1') ? 'aws-us-east-1' : h.includes('eu-central-1') ? 'aws-eu-central-1' : 'aws-cloud',
      country: 'United States',
      countryCode: 'US',
    };
  }
  if (h.includes('gcp') || h.includes('google') || h.includes('googleusercontent.com')) {
    return {
      asn: 'AS15169',
      asOrg: 'Google LLC',
      cloudProvider: 'GCP',
      datacenter: 'gcp-datacenter',
      country: 'United States',
      countryCode: 'US',
    };
  }
  if (h.includes('azure') || h.includes('microsoft')) {
    return {
      asn: 'AS8075',
      asOrg: 'Microsoft Corporation',
      cloudProvider: 'Azure',
      datacenter: 'azure-datacenter',
      country: 'United States',
      countryCode: 'US',
    };
  }
  if (h.includes('hetzner')) {
    return {
      asn: 'AS24940',
      asOrg: 'Hetzner Online GmbH',
      cloudProvider: 'Hetzner',
      datacenter: 'hetzner-fsn1',
      country: 'Germany',
      countryCode: 'DE',
    };
  }
  if (h.includes('ovh')) {
    return {
      asn: 'AS16276',
      asOrg: 'OVH SAS',
      cloudProvider: 'OVH',
      datacenter: 'ovh-gra',
      country: 'France',
      countryCode: 'FR',
    };
  }
  if (h.includes('digitalocean')) {
    return {
      asn: 'AS14061',
      asOrg: 'DigitalOcean, LLC',
      cloudProvider: 'DigitalOcean',
      datacenter: 'do-nyc3',
      country: 'United States',
      countryCode: 'US',
    };
  }

  // Fallback defaults for testing or unrecognized IPs
  return {
    asn: 'AS-UNKNOWN',
    asOrg: 'Unknown Provider',
    cloudProvider: 'Independent',
    datacenter: 'default-dc',
    country: 'Global',
    countryCode: 'XX',
  };
}

export class GeographicDiversityScorer {
  private readonly dnsResolver?: DnsResolver;
  private readonly geoLookup?: GeoLookupResolver;

  constructor(options: GeographicDiversityScorerOptions = {}) {
    this.dnsResolver = options.dnsResolver;
    this.geoLookup = options.geoLookup;
  }

  /**
   * Resolves a hostname or IP to an IP address.
   */
  public async resolveHost(hostname: string): Promise<string> {
    if (isIP(hostname)) {
      return hostname;
    }

    if (this.dnsResolver) {
      const res = await this.dnsResolver(hostname);
      return Array.isArray(res) ? (res[0] ?? hostname) : res;
    }

    try {
      const res = await lookup(hostname);
      return res.address;
    } catch (err) {
      throw new Error(`DNS lookup failed for ${hostname}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  /**
   * Calculates Simpson's diversity index and Shannon entropy for an array of category keys.
   */
  public calculateDiversityMetrics(categories: string[]): DiversityMetrics {
    const valid = categories.filter((c) => Boolean(c && c.trim().length > 0));
    const total = valid.length;

    if (total === 0) {
      return {
        simpsonIndex: 0,
        shannonEntropy: 0,
        normalizedEntropy: 0,
        uniqueCategories: 0,
        distribution: {},
        percentages: {},
      };
    }

    const distribution: Record<string, number> = {};
    for (const cat of valid) {
      distribution[cat] = (distribution[cat] ?? 0) + 1;
    }

    const uniqueKeys = Object.keys(distribution);
    const uniqueCategories = uniqueKeys.length;
    const percentages: Record<string, number> = {};

    let sumP2 = 0;
    let shannon = 0;

    for (const key of uniqueKeys) {
      const count = distribution[key]!;
      const p = count / total;
      percentages[key] = Math.round(p * 10000) / 100;
      sumP2 += p * p;
      if (p > 0) {
        shannon -= p * Math.log(p);
      }
    }

    // Simpson's Index of Diversity (1 - D)
    const simpsonIndex = Math.round((1 - sumP2) * 10000) / 10000;
    const shannonEntropy = Math.round(shannon * 10000) / 10000;
    const normalizedEntropy =
      uniqueCategories > 1
        ? Math.round((shannon / Math.log(uniqueCategories)) * 10000) / 10000
        : 0;

    return {
      simpsonIndex,
      shannonEntropy,
      normalizedEntropy,
      uniqueCategories,
      distribution,
      percentages,
    };
  }

  /**
   * Scans [[VALIDATORS]] in stellar.toml and computes geographic and ASN diversity.
   */
  public async score(
    input: string | StellarToml | Record<string, unknown>,
  ): Promise<GeographicDiversityReport> {
    let doc: Record<string, unknown> = {};
    if (typeof input === 'string') {
      try {
        doc = parseToml(input) as Record<string, unknown>;
      } catch (err) {
        throw new Error(`Failed to parse TOML: ${err instanceof Error ? err.message : String(err)}`);
      }
    } else if (typeof input === 'object' && input !== null) {
      doc = input as Record<string, unknown>;
    }

    const rawValidators = (doc['VALIDATORS'] ?? doc['validators']) as
      | Array<Record<string, unknown>>
      | undefined;

    const validatorList = Array.isArray(rawValidators) ? rawValidators : [];
    const totalValidators = validatorList.length;

    const locations: ValidatorLocation[] = [];

    for (const val of validatorList) {
      const publicKey = typeof val['PUBLIC_KEY'] === 'string' ? val['PUBLIC_KEY'] : undefined;
      const alias = typeof val['ALIAS'] === 'string' ? val['ALIAS'] : undefined;
      const displayName = typeof val['DISPLAY_NAME'] === 'string' ? val['DISPLAY_NAME'] : undefined;
      const rawHost = typeof val['HOST'] === 'string' ? val['HOST'] : '';

      if (!rawHost) {
        locations.push({
          publicKey,
          alias,
          displayName,
          rawHost: '',
          hostname: '',
          resolved: false,
          error: 'No HOST declared for validator',
        });
        continue;
      }

      const { hostname, port } = parseHostPort(rawHost);

      try {
        const ip = await this.resolveHost(hostname);
        let geo: Partial<ValidatorLocation> = {};

        if (this.geoLookup) {
          geo = await this.geoLookup(ip, hostname);
        } else {
          geo = inferDefaultGeoMetadata(ip, hostname);
        }

        locations.push({
          publicKey,
          alias,
          displayName,
          rawHost,
          hostname,
          port,
          ip,
          country: geo.country,
          countryCode: geo.countryCode,
          region: geo.region,
          city: geo.city,
          asn: geo.asn,
          asOrg: geo.asOrg,
          cloudProvider: geo.cloudProvider,
          datacenter: geo.datacenter ?? geo.cloudProvider,
          resolved: true,
        });
      } catch (err) {
        locations.push({
          publicKey,
          alias,
          displayName,
          rawHost,
          hostname,
          port,
          resolved: false,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }

    const resolved = locations.filter((loc) => loc.resolved);
    const resolvedValidators = resolved.length;

    const asns = resolved.map((loc) => loc.asn).filter((a): a is string => Boolean(a));
    const countries = resolved.map((loc) => loc.country ?? loc.countryCode).filter((c): c is string => Boolean(c));
    const datacenters = resolved
      .map((loc) => loc.datacenter ?? loc.cloudProvider)
      .filter((d): d is string => Boolean(d));

    const asnDiversity = this.calculateDiversityMetrics(asns);
    const countryDiversity = this.calculateDiversityMetrics(countries);
    const datacenterDiversity = this.calculateDiversityMetrics(datacenters);

    const warnings: string[] = [];

    // Check ASN concentration (>= 50%)
    let dominantAsn: { asn: string; asOrg?: string; percentage: number } | undefined;
    let hasAsnConcentrationRisk = false;

    for (const [asn, pct] of Object.entries(asnDiversity.percentages)) {
      if (pct >= 50) {
        hasAsnConcentrationRisk = true;
        const org = resolved.find((r) => r.asn === asn)?.asOrg;
        dominantAsn = { asn, asOrg: org, percentage: pct };
        warnings.push(
          `Validator centralization risk: ${pct}% of validator nodes share a single ASN ${asn}${org ? ` (${org})` : ''}.`,
        );
        break;
      }
    }

    // Check Cloud Datacenter concentration (>= 50%)
    let dominantDatacenter: { datacenter: string; provider?: string; percentage: number } | undefined;
    let hasDatacenterConcentrationRisk = false;

    for (const [dc, pct] of Object.entries(datacenterDiversity.percentages)) {
      if (pct >= 50) {
        hasDatacenterConcentrationRisk = true;
        const provider = resolved.find((r) => (r.datacenter ?? r.cloudProvider) === dc)?.cloudProvider;
        dominantDatacenter = { datacenter: dc, provider, percentage: pct };
        warnings.push(
          `Datacenter concentration risk: ${pct}% of validator nodes share cloud datacenter/provider ${dc}${provider ? ` (${provider})` : ''}.`,
        );
        break;
      }
    }

    if (resolvedValidators === 0 && totalValidators > 0) {
      warnings.push('Could not resolve hostnames for any declared validators.');
    }

    return {
      totalValidators,
      resolvedValidators,
      validators: locations,
      asnDiversity,
      countryDiversity,
      datacenterDiversity,
      dominantAsn,
      dominantDatacenter,
      hasAsnConcentrationRisk,
      hasDatacenterConcentrationRisk,
      warnings,
    };
  }
}
