/**
 * Validator geo-distribution and ASN diversity analysis engine.
 *
 * A healthy, decentralized network avoids single points of infrastructure
 * failure. This module resolves validator hosts to IP addresses, enriches them
 * with ASN and country metadata, and flags quorum sets where more than a third
 * of nodes share a single ASN or country.
 *
 * Network access is opt-in: `analyzeValidatorGeoDiversity` performs the DNS and
 * ASN lookups, while `checkGeoDiversity` is a pure function over already
 * resolved entries so it can be unit-tested offline.
 */

import { lookup as dnsLookup } from 'node:dns/promises';
import { readFile } from 'node:fs/promises';
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';

export const VALIDATORS_HIGH_ASN_CONCENTRATION = 'validators/high-asn-concentration';
export const VALIDATORS_HIGH_GEOGRAPHIC_CONCENTRATION =
  'validators/high-geographic-concentration';

export const HIGH_ASN_CONCENTRATION_RULE = VALIDATORS_HIGH_ASN_CONCENTRATION;
export const HIGH_GEOGRAPHIC_CONCENTRATION_RULE = VALIDATORS_HIGH_GEOGRAPHIC_CONCENTRATION;

/** Default share (percent) above which concentration is flagged. */
export const DEFAULT_CONCENTRATION_THRESHOLD_PERCENT = 33.3;

export interface GeoDiversityEntry {
  host: string;
  ip?: string;
  country?: string;
  asn?: number;
  asnOrg?: string;
}

export interface GeoRecord {
  country?: string;
  asn?: number;
  asnOrg?: string;
}

export type GeoLookup = (ip: string) => GeoRecord | undefined | Promise<GeoRecord | undefined>;
export type HostResolver = (host: string) => Promise<string | undefined>;

export interface GeoDiversityOptions {
  rules?: RuleOverrides;
  /** Percentage threshold above which a bucket is considered concentrated. */
  thresholdPercent?: number;
  lookup?: GeoLookup;
  resolveHost?: HostResolver;
}

export interface GeoDistributionBucket<K extends string | number> {
  value: K;
  count: number;
  percent: number;
  entries: GeoDiversityEntry[];
}

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules: RuleOverrides | undefined,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

/**
 * Load an IP → { asn, country } table from the JSON file named by
 * `ANCHOR_GEO_LOOKUP`. This is how operators plug in an offline MaxMind
 * GeoLite / ASN export without bundling the binary database. Returns
 * `undefined` when unset or unreadable.
 */
export async function loadGeoLookupFromEnv(
  env: Record<string, string | undefined> = process.env,
): Promise<GeoLookup | undefined> {
  const path = env.ANCHOR_GEO_LOOKUP;
  if (!path) return undefined;
  try {
    const table = JSON.parse(await readFile(path, 'utf8')) as Record<string, GeoRecord>;
    return (ip: string) => table[ip];
  } catch {
    return undefined;
  }
}

async function defaultResolveHost(host: string): Promise<string | undefined> {
  try {
    const result = await dnsLookup(host);
    return result.address;
  } catch {
    return undefined;
  }
}

/** Group entries by ASN or country and compute each bucket's share. */
export function computeDistribution<K extends 'asn' | 'country'>(
  entries: readonly GeoDiversityEntry[],
  key: K,
): Array<GeoDistributionBucket<K extends 'asn' ? number : string>> {
  const buckets = new Map<string | number, GeoDiversityEntry[]>();

  for (const entry of entries) {
    const value = entry[key];
    if (value === undefined || value === null) continue;
    const bucket = buckets.get(value) ?? [];
    bucket.push(entry);
    buckets.set(value, bucket);
  }

  const total = entries.filter((entry) => entry[key] !== undefined).length || 1;

  return [...buckets.entries()]
    .map(([value, bucketEntries]) => ({
      value,
      count: bucketEntries.length,
      percent: (bucketEntries.length / total) * 100,
      entries: bucketEntries,
    }))
    .sort((a, b) => b.count - a.count) as Array<
    GeoDistributionBucket<K extends 'asn' ? number : string>
  >;
}

/** Pure concentration check over already-enriched validator entries. */
export function checkGeoDiversity(
  entries: readonly GeoDiversityEntry[],
  options: GeoDiversityOptions = {},
): Diagnostic[] {
  const { rules } = options;
  const threshold = options.thresholdPercent ?? DEFAULT_CONCENTRATION_THRESHOLD_PERCENT;
  const diagnostics: Diagnostic[] = [];

  const asnSeverity = severityFor(VALIDATORS_HIGH_ASN_CONCENTRATION, 'warning', rules);
  if (asnSeverity !== undefined) {
    const top = computeDistribution(entries, 'asn')[0];
    if (top && top.percent > threshold) {
      diagnostics.push({
        rule: VALIDATORS_HIGH_ASN_CONCENTRATION,
        severity: asnSeverity,
        category: 'validators',
        message: `${top.percent.toFixed(1)}% of validators share ASN ${top.value}, which risks a single-provider outage`,
        suggestion:
          'Distribute quorum nodes across multiple autonomous systems and hosting providers.',
      });
    }
  }

  const countrySeverity = severityFor(VALIDATORS_HIGH_GEOGRAPHIC_CONCENTRATION, 'warning', rules);
  if (countrySeverity !== undefined) {
    const top = computeDistribution(entries, 'country')[0];
    if (top && top.percent > threshold) {
      diagnostics.push({
        rule: VALIDATORS_HIGH_GEOGRAPHIC_CONCENTRATION,
        severity: countrySeverity,
        category: 'validators',
        message: `${top.percent.toFixed(1)}% of validators are hosted in ${top.value}, which risks a regional outage`,
        suggestion:
          'Spread quorum nodes across multiple countries and regulatory jurisdictions.',
      });
    }
  }

  return diagnostics;
}

/**
 * Resolve each validator host to an IP and enrich it with ASN/country data.
 * Resolution or lookup failures leave the corresponding fields undefined
 * rather than throwing, so a partially reachable set still yields a report.
 */
export async function analyzeValidatorGeoDiversity(
  validators: readonly (string | { host: string })[],
  options: GeoDiversityOptions = {},
): Promise<GeoDiversityEntry[]> {
  const resolveHost = options.resolveHost ?? defaultResolveHost;
  const lookup = options.lookup;
  const entries: GeoDiversityEntry[] = [];

  for (const validator of validators) {
    const host = typeof validator === 'string' ? validator : validator.host;
    const ip = await resolveHost(host);
    const record = ip !== undefined && lookup !== undefined ? await lookup(ip) : undefined;
    entries.push({
      host,
      ...(ip === undefined ? {} : { ip }),
      ...(record?.country === undefined ? {} : { country: record.country }),
      ...(record?.asn === undefined ? {} : { asn: record.asn }),
      ...(record?.asnOrg === undefined ? {} : { asnOrg: record.asnOrg }),
    });
  }

  return entries;
}

/** Extract validator hosts from a parsed stellar.toml `[[VALIDATORS]]` array. */
export function validatorHostsFromDocument(doc: Record<string, unknown>): string[] {
  const raw = doc.VALIDATORS;
  if (!Array.isArray(raw)) return [];
  const hosts: string[] = [];
  for (const entry of raw) {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) continue;
    const host = (entry as Record<string, unknown>).HOST;
    if (typeof host === 'string' && host.trim() !== '') hosts.push(host.trim());
  }
  return hosts;
}

/**
 * End-to-end helper for the CLI: read validator hosts from a parsed document,
 * enrich them (using the table in `ANCHOR_GEO_LOOKUP` unless one is supplied),
 * and return concentration diagnostics.
 */
export async function checkValidatorDiversityFromDocument(
  doc: Record<string, unknown>,
  options: GeoDiversityOptions = {},
): Promise<Diagnostic[]> {
  const hosts = validatorHostsFromDocument(doc);
  const lookup = options.lookup ?? (await loadGeoLookupFromEnv());
  const entries = await analyzeValidatorGeoDiversity(hosts, options);
  return checkGeoDiversity(entries, {
    ...options,
    ...(lookup === undefined ? {} : { lookup }),
  });
}

/** Reverse lookup performed only when a caller supplies a lookup table. */
export const geoDiversityRules: Rule[] = [
  {
    id: VALIDATORS_HIGH_ASN_CONCENTRATION,
    category: 'validators',
    severity: 'warning',
    description: 'No single ASN should host more than a third of the validator quorum',
    run() {},
  },
  {
    id: VALIDATORS_HIGH_GEOGRAPHIC_CONCENTRATION,
    category: 'validators',
    severity: 'warning',
    description: 'No single country should host more than a third of the validator quorum',
    run() {},
  },
];

export const geoDiversityRuleIds: readonly string[] = geoDiversityRules.map((rule) => rule.id);
