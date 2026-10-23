/**
 * Multi-tenant anchor routing and host-header delegation auditor.
 *
 * Large anchor platforms serve several home domains from one cluster, routing
 * on the HTTP `Host` header (or the `X-Forwarded-Host` a terminating proxy
 * adds). A cluster that ignores those headers answers every request with the
 * same tenant's `stellar.toml` — a cross-tenant data leak, because a wallet
 * asking for one anchor's info file receives another anchor's accounts and
 * signing key.
 *
 * Runs under opt-in `--check-network`.
 *
 * The auditor requests the well-known info file once per tenant host with the
 * host headers a real client would send, and compares the identity markers
 * (`DOCUMENTATION.ORG_NAME`, `SIGNING_KEY`, `ACCOUNTS`) in each answer:
 *
 *   - a tenant host answered with another tenant's markers is
 *     `network/tenant-cross-contamination` (error);
 *   - a host override that is ignored, or an `Access-Control-Allow-Origin`
 *     that does not reflect the tenant domain, is `network/invalid-host-routing`
 *     (warning).
 *
 * Every transport failure is silence: an unreachable cluster says nothing
 * about a file defect, and the plain `--check-network` probes already report
 * endpoint liveness.
 */

import { parse } from 'smol-toml';
import type { Diagnostic, Rule, RuleCategory, RuleOverrides, Severity } from '../types.js';
import { isString } from '../predicates.js';

export const TENANT_CROSS_CONTAMINATION_RULE = 'network/tenant-cross-contamination';
export const INVALID_HOST_ROUTING_RULE = 'network/invalid-host-routing';

const SEP1_SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0001.md';
const WELL_KNOWN_PATH = '/.well-known/stellar.toml';
/** A host that cannot be a tenant, used to detect servers that drop `Host`. */
const BOGUS_HOST = 'stellar-toml-lint.invalid';

export interface MultiTenantOptions {
  /** Rule severity overrides. */
  rules?: RuleOverrides;
  /** The home domain the file is served from, e.g. `anchor.example.com`. */
  domain?: string;
  /**
   * Sibling tenant home domains to probe. Without them the audit still checks
   * that the primary host routes and reflects CORS, but cannot prove isolation
   * between two tenants.
   */
  tenantHosts?: readonly string[];
}

interface ProbeResult {
  status: number;
  document: Record<string, unknown> | null;
  accessControlAllowOrigin: string | null;
}

function severityFor(
  rule: string,
  fallback: Severity,
  rules?: RuleOverrides,
): Severity | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override ?? fallback;
}

function report(
  diagnostics: Diagnostic[],
  rule: string,
  fallback: Severity,
  message: string,
  suggestion: string,
  rules?: RuleOverrides,
  extras: Partial<Diagnostic> = {},
): void {
  const severity = severityFor(rule, fallback, rules);
  if (severity === undefined) return;
  diagnostics.push({
    rule,
    severity,
    category: 'network' as RuleCategory,
    message,
    helpUri: SEP1_SPEC,
    suggestion,
    ...extras,
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Normalizes a host or URL to a bare lowercase hostname (port preserved). */
function hostOf(value: string): string | undefined {
  const trimmed = value.trim();
  if (trimmed === '') return undefined;
  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  try {
    return new URL(withScheme).host.toLowerCase();
  } catch {
    return undefined;
  }
}

/** The domain the file is served from, from the flag or `DOCUMENTATION.ORG_URL`. */
function resolveDomain(doc: Record<string, unknown>, domain?: string): string | undefined {
  if (domain !== undefined) {
    const normalized = hostOf(domain);
    if (normalized !== undefined) return normalized;
  }
  const documentation = doc.DOCUMENTATION;
  if (isRecord(documentation) && isString(documentation.ORG_URL)) {
    return hostOf(documentation.ORG_URL);
  }
  return undefined;
}

/** The distinctive values that identify one tenant's info file. */
function identityMarkers(doc: Record<string, unknown> | null): Set<string> {
  const markers = new Set<string>();
  if (doc === null) return markers;

  const documentation = doc.DOCUMENTATION;
  if (isRecord(documentation) && isString(documentation.ORG_NAME)) {
    const name = documentation.ORG_NAME.trim();
    if (name !== '') markers.add(name);
  }
  if (isString(doc.SIGNING_KEY) && doc.SIGNING_KEY !== '') markers.add(doc.SIGNING_KEY);
  if (Array.isArray(doc.ACCOUNTS)) {
    for (const account of doc.ACCOUNTS) {
      if (isString(account) && account !== '') markers.add(account);
    }
  }
  return markers;
}

function overlappingMarkers(a: Set<string>, b: Set<string>): string[] {
  const overlap: string[] = [];
  for (const marker of a) if (b.has(marker)) overlap.push(marker);
  return overlap;
}

function parseToml(text: string): Record<string, unknown> | null {
  try {
    const parsed: unknown = parse(text);
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

async function probe(
  fetchImpl: typeof fetch,
  host: string,
  requestedHost: string,
): Promise<ProbeResult | undefined> {
  try {
    const response = await fetchImpl(`https://${host}${WELL_KNOWN_PATH}`, {
      headers: {
        accept: 'application/toml, text/plain;q=0.9, */*;q=0.1',
        // `Host` is the header a direct client sends; `X-Forwarded-Host` is
        // what a proxy that terminates TLS forwards. Send both: a cluster
        // routing on either one is exercising the isolation contract.
        host: requestedHost,
        'x-forwarded-host': requestedHost,
        origin: `https://${requestedHost}`,
      },
      redirect: 'follow',
    });
    const text = await response.text().catch(() => '');
    return {
      status: response.status,
      document: response.ok ? parseToml(text) : null,
      accessControlAllowOrigin: response.headers.get('access-control-allow-origin'),
    };
  } catch {
    return undefined;
  }
}

/**
 * Audits tenant isolation for one anchor file.
 *
 * Silent when the file does not declare (and the caller does not supply) a
 * domain, because there is no host to route on.
 */
export async function auditMultiTenantRouting(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: MultiTenantOptions = {},
): Promise<Diagnostic[]> {
  const diagnostics: Diagnostic[] = [];
  const domain = resolveDomain(doc, options.domain);
  if (domain === undefined) return diagnostics;

  const selfMarkers = identityMarkers(doc);

  const primary = await probe(fetchImpl, domain, domain);
  if (primary === undefined) return diagnostics;

  // Siblings: whatever the caller declared, minus the primary host itself.
  const siblings = new Set<string>();
  for (const host of options.tenantHosts ?? []) {
    const normalized = hostOf(host);
    if (normalized !== undefined && normalized !== domain) siblings.add(normalized);
  }

  // Learn each sibling's identity from its own well-known file. A sibling that
  // cannot be reached contributes no markers, but its host probe still counts.
  const siblingMarkers = new Map<string, Set<string>>();
  for (const sibling of siblings) {
    const direct = await probe(fetchImpl, sibling, sibling);
    if (direct !== undefined && direct.document !== null) {
      siblingMarkers.set(sibling, identityMarkers(direct.document));
    }
  }

  // 1. The primary response must not contain a sibling's identity.
  const primaryDocumentMarkers = identityMarkers(primary.document);
  for (const [sibling, markers] of siblingMarkers) {
    const leaked = overlappingMarkers(primaryDocumentMarkers, markers);
    if (leaked.length === 0) continue;
    report(
      diagnostics,
      TENANT_CROSS_CONTAMINATION_RULE,
      'error',
      `The stellar.toml served for ${domain} contains data belonging to sibling tenant ${sibling} (${leaked.join(', ')})`,
      'Route each host to its own tenant configuration; a shared cache or default virtual host is leaking another anchor’s details.',
      options.rules,
      { path: 'DOCUMENTATION.ORG_NAME' },
    );
    break;
  }

  // 2. A sibling host must not be answered with this tenant's identity.
  for (const sibling of siblings) {
    const routed = await probe(fetchImpl, domain, sibling);
    if (routed === undefined || routed.document === null) continue;

    const routedMarkers = identityMarkers(routed.document);
    const leaked = overlappingMarkers(routedMarkers, selfMarkers);
    if (leaked.length === 0) continue;

    report(
      diagnostics,
      TENANT_CROSS_CONTAMINATION_RULE,
      'error',
      `A request for tenant ${sibling} was answered with ${domain}’s stellar.toml (${leaked.join(', ')})`,
      'Honour the Host / X-Forwarded-Host header and serve the requested tenant’s configuration.',
      options.rules,
      { path: 'DOCUMENTATION.ORG_NAME' },
    );
    break;
  }

  // 3. A host nobody owns must not receive the primary tenant's file. Only
  // meaningful for a multi-tenant cluster: a single-tenant server answering
  // every Host is normal, and flagging it would make the rule unusable.
  if (siblings.size > 0) {
    const bogus = await probe(fetchImpl, domain, BOGUS_HOST);
    if (bogus !== undefined && bogus.document !== null) {
      const leaked = overlappingMarkers(identityMarkers(bogus.document), selfMarkers);
      if (leaked.length > 0) {
        report(
          diagnostics,
          INVALID_HOST_ROUTING_RULE,
          'warning',
          `The server ignored an unknown Host header and served ${domain}’s stellar.toml to ${BOGUS_HOST}`,
          'Reject requests whose Host header is not a configured tenant instead of falling back to a default vhost.',
          options.rules,
          { path: 'DOCUMENTATION.ORG_URL' },
        );
      }
    }
  }

  // 4. CORS must reflect the tenant that asked. A wildcard is valid but not
  // tenant-specific, so it is not treated as a routing failure.
  const acao = primary.accessControlAllowOrigin;
  if (acao !== null && acao.trim() !== '*' && !acao.toLowerCase().includes(domain)) {
    report(
      diagnostics,
      INVALID_HOST_ROUTING_RULE,
      'warning',
      `Access-Control-Allow-Origin "${acao}" does not reflect the tenant domain ${domain}`,
      'Reflect the requesting tenant origin in Access-Control-Allow-Origin instead of a fixed sibling domain.',
      options.rules,
      { path: 'DOCUMENTATION.ORG_URL' },
    );
  }

  return diagnostics;
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const multiTenantRules: Rule[] = [
  {
    id: TENANT_CROSS_CONTAMINATION_RULE,
    category: 'network',
    severity: 'error',
    description:
      'A tenant host must never be served another tenant’s stellar.toml or identity markers',
    run() {},
  },
  {
    id: INVALID_HOST_ROUTING_RULE,
    category: 'network',
    severity: 'warning',
    description: 'The server must route on Host / X-Forwarded-Host and reflect tenant CORS origins',
    run() {},
  },
];
