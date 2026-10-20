import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { HTTPS_ENDPOINT_FIELDS } from '../spec.js';
import { hostOf, isString } from '../predicates.js';

export const NETWORK_RPKI_INVALID_ROUTE_RULE = 'network/rpki-invalid-route';
export const NETWORK_UNVERIFIED_BGP_RULE = 'network/unverified-bgp-announcement';
export const DEFAULT_RIPESTAT_URL = 'https://stat.ripe.net/data/';

export interface BgpRoute {
  prefix: string;
  asns: string[];
}

export type AddressResolver = (hostname: string) => Promise<string[] | undefined>;

export interface BgpRouteAuditorOptions {
  rules?: RuleOverrides;
  domain?: string;
  fetchImpl?: typeof fetch;
  resolveAddresses?: AddressResolver;
  ripeStatUrl?: string;
  expectedAsns?: readonly string[];
}

export const bgpRouteDetectorRules: Rule[] = [
  {
    id: NETWORK_RPKI_INVALID_ROUTE_RULE,
    category: 'network',
    severity: 'error',
    description: 'BGP origin ASNs should be authorized by a valid RPKI ROA',
    run() {},
  },
  {
    id: NETWORK_UNVERIFIED_BGP_RULE,
    category: 'network',
    severity: 'warning',
    description: 'Public BGP announcements should have a verifiable RPKI state',
    run() {},
  },
];

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules: RuleOverrides | undefined,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

function targetsOf(doc: Record<string, unknown>, domain?: string): string[] {
  const targets = new Set<string>();
  const domainValue = domain ?? doc.DOMAIN;
  if (typeof domainValue === 'string') {
    try {
      targets.add(
        new URL(domainValue.includes('://') ? domainValue : `https://${domainValue}`).hostname,
      );
    } catch {
      // Invalid document domains are handled by the normal lint rules.
    }
  }
  const documentation = doc.DOCUMENTATION;
  if (
    typeof documentation === 'object' &&
    documentation !== null &&
    !Array.isArray(documentation)
  ) {
    const organizationHost = hostOf((documentation as Record<string, unknown>).ORG_URL);
    if (organizationHost !== undefined) targets.add(organizationHost);
  }
  for (const field of HTTPS_ENDPOINT_FIELDS) {
    const value = doc[field];
    if (!isString(value)) continue;
    const host = hostOf(value);
    if (host !== undefined) targets.add(host);
  }
  return [...targets];
}

const systemAddressResolver: AddressResolver = async (hostname) => {
  const dns = await import('node:dns/promises').catch(() => null);
  if (dns === null) return undefined;
  try {
    const addresses = await dns.lookup(hostname, { all: true });
    return addresses.map(({ address }) => address);
  } catch {
    return undefined;
  }
};

async function getJson(
  fetchImpl: typeof fetch,
  url: URL,
): Promise<Record<string, unknown> | undefined> {
  try {
    const response = await fetchImpl(url, { signal: AbortSignal.timeout(8_000) });
    if (!response.ok) return undefined;
    const body = (await response.json()) as unknown;
    if (typeof body !== 'object' || body === null || Array.isArray(body)) return undefined;
    return body as Record<string, unknown>;
  } catch {
    return undefined;
  }
}

function routeFrom(body: Record<string, unknown>): BgpRoute | undefined {
  const data = body.data;
  if (typeof data !== 'object' || data === null || Array.isArray(data)) return undefined;
  const record = data as Record<string, unknown>;
  if (typeof record.prefix !== 'string' || !Array.isArray(record.asns)) return undefined;
  const asns = record.asns
    .filter((asn): asn is number | string => typeof asn === 'number' || typeof asn === 'string')
    .map((asn) => String(asn).replace(/^AS/i, ''));
  return asns.length > 0 ? { prefix: record.prefix, asns } : undefined;
}

function rpkiStatus(body: Record<string, unknown>): string | undefined {
  const data = body.data;
  if (typeof data !== 'object' || data === null || Array.isArray(data)) return undefined;
  const status = (data as Record<string, unknown>).status;
  return typeof status === 'string' ? status.toLowerCase() : undefined;
}

export async function auditBgpRoutes(
  doc: Record<string, unknown>,
  options: BgpRouteAuditorOptions = {},
): Promise<Diagnostic[]> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const resolveAddresses = options.resolveAddresses ?? systemAddressResolver;
  const baseUrl = options.ripeStatUrl ?? DEFAULT_RIPESTAT_URL;
  const diagnostics: Diagnostic[] = [];
  const seenAddresses = new Set<string>();

  for (const host of targetsOf(doc, options.domain)) {
    const addresses = await resolveAddresses(host);
    if (addresses === undefined) continue;
    for (const address of addresses) {
      if (seenAddresses.has(address)) continue;
      seenAddresses.add(address);
      const networkInfoUrl = new URL('network-info/data.json', baseUrl);
      networkInfoUrl.searchParams.set('resource', address);
      const routeBody = await getJson(fetchImpl, networkInfoUrl);
      if (routeBody === undefined) continue;
      const route = routeFrom(routeBody);
      if (route === undefined) {
        const severity = severityFor(NETWORK_UNVERIFIED_BGP_RULE, 'warning', options.rules);
        if (severity !== undefined) {
          diagnostics.push({
            rule: NETWORK_UNVERIFIED_BGP_RULE,
            severity,
            category: 'network',
            message: `No announcing BGP origin ASN could be verified for ${address} (${host})`,
            suggestion:
              'Check that the host IP is publicly routed and that RIPEstat has current route data.',
          });
        }
        continue;
      }

      for (const asn of route.asns) {
        if (
          options.expectedAsns !== undefined &&
          options.expectedAsns.length > 0 &&
          !options.expectedAsns.some((expected) => expected.replace(/^AS/i, '') === asn)
        ) {
          const severity = severityFor(NETWORK_UNVERIFIED_BGP_RULE, 'warning', options.rules);
          if (severity !== undefined) {
            diagnostics.push({
              rule: NETWORK_UNVERIFIED_BGP_RULE,
              severity,
              category: 'network',
              message: `BGP prefix ${route.prefix} is announced by unexpected AS${asn}; expected ${options.expectedAsns.map((expected) => `AS${expected.replace(/^AS/i, '')}`).join(', ')}`,
              suggestion:
                'Verify the origin ASN with your network provider and update the expected ASN list only for authorized routing changes.',
            });
          }
        }
        const validationUrl = new URL('rpki-validation/data.json', baseUrl);
        validationUrl.searchParams.set('resource', route.prefix);
        validationUrl.searchParams.set('origin', asn);
        const validationBody = await getJson(fetchImpl, validationUrl);
        if (validationBody === undefined) continue;
        const status = rpkiStatus(validationBody);
        if (status === 'invalid') {
          const severity = severityFor(NETWORK_RPKI_INVALID_ROUTE_RULE, 'error', options.rules);
          if (severity !== undefined) {
            diagnostics.push({
              rule: NETWORK_RPKI_INVALID_ROUTE_RULE,
              severity,
              category: 'network',
              message: `BGP prefix ${route.prefix} is announced by AS${asn}, which has an invalid RPKI ROA`,
              suggestion:
                'Correct the route origin or publish a matching Route Origin Authorization.',
            });
          }
        } else if (status !== 'valid') {
          const severity = severityFor(NETWORK_UNVERIFIED_BGP_RULE, 'warning', options.rules);
          if (severity !== undefined) {
            diagnostics.push({
              rule: NETWORK_UNVERIFIED_BGP_RULE,
              severity,
              category: 'network',
              message: `BGP prefix ${route.prefix} announced by AS${asn} has no valid RPKI state (${status ?? 'unknown'})`,
              suggestion:
                'Publish a Route Origin Authorization for the announced prefix and origin ASN.',
            });
          }
        }
      }
    }
  }

  return diagnostics;
}
