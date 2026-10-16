/**
 * Cross-SEP anchor discovery and directory listing compliance validator
 * (issue #397).
 *
 * Wallet clients and aggregators discover anchors through ecosystem
 * directories and registry feeds that reference a `stellar.toml`. When a
 * directory's cached profile drifts from the published file — a renamed
 * organisation, a stale `ORG_URL`, a capability flag for a SEP the anchor no
 * longer serves — discovery breaks quietly: clients route to endpoints that do
 * not exist, or skip an anchor that does.
 *
 * This validator audits that integrity:
 *
 * - it performs a reverse domain lookup against each configured directory
 *   registry (`GET <registry>?search=<domain>`), finding every listing entry
 *   that claims the anchor's domain.
 * - it cross-checks `ORG_NAME`, `ORG_URL`, and `ACCOUNTS` between the
 *   directory entries and the published `stellar.toml`.
 * - it validates advertised SEP-6 / SEP-24 / SEP-31 / SEP-38 capabilities
 *   against the endpoint fields the file actually declares.
 * - it verifies every registry feed is reachable and carries a recognised
 *   JSON schema, degrading to a warning when a registry times out.
 *
 * Registry endpoints are configurable (`directories`), and the transport is
 * injectable, so test suites stay hermetic with recorded feeds.
 */
import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';
import { hostOf, isString } from '../predicates.js';

export const REGISTRY_UNREACHABLE_RULE = 'directory/registry-unreachable';
export const SCHEMA_INVALID_RULE = 'directory/schema-invalid';
export const PROFILE_OUT_OF_SYNC_RULE = 'directory/profile-out-of-sync';
export const CAPABILITY_MISMATCH_RULE = 'directory/capability-mismatch';

const DEFAULT_TIMEOUT_MS = 5_000;

/** One directory registry feed to audit. */
export interface DirectoryRegistry {
  /** Human label used in diagnostics, e.g. `Stellar Expert`. */
  name: string;
  /** Base JSON endpoint; the domain is appended as a `search` query. */
  url: string;
}

/**
 * The registries audited when none are configured.
 *
 * Stellar Expert's SEP-37 address directory is the directory clients have
 * relied on since 2018 and is the one feed whose schema this validator knows
 * without configuration. Additional registries are supplied through
 * `--directory-feed <url>`, so no unverified endpoint is ever contacted.
 */
export const DEFAULT_DIRECTORY_REGISTRIES: readonly DirectoryRegistry[] = [
  { name: 'Stellar Expert', url: 'https://api.stellar.expert/explorer/directory' },
];

/** A directory listing entry, normalized across registry schemas. */
export interface DirectoryEntry {
  address?: string;
  name?: string;
  domain?: string;
  url?: string;
  /** Capability tags, e.g. `anchor`, `sep6`, `sep-24`. */
  tags: string[];
  /** Explicit SEP capability declarations. */
  seps: string[];
}

/** The SEP numbers a `stellar.toml` field advertises, in report order. */
export const TOML_SEP_ENDPOINTS: ReadonlyMap<string, string> = new Map([
  ['6', 'TRANSFER_SERVER'],
  ['24', 'TRANSFER_SERVER_SEP0024'],
  ['31', 'DIRECT_PAYMENT_SERVER'],
  ['38', 'ANCHOR_QUOTE_SERVER'],
]);

export interface AnchorDiscoveryOptions {
  rules?: RuleOverrides;
  fetchImpl?: typeof fetch;
  /** The domain whose directory listings are audited. */
  domain?: string;
  /** Registries to query; defaults to {@link DEFAULT_DIRECTORY_REGISTRIES}. */
  directories?: readonly DirectoryRegistry[];
  /** Per-request timeout in milliseconds. */
  timeoutMs?: number;
}

export const anchorDiscoveryRules: Rule[] = [
  {
    id: REGISTRY_UNREACHABLE_RULE,
    category: 'network',
    severity: 'warning',
    description: 'Configured anchor directory registries must be reachable',
    run() {},
  },
  {
    id: SCHEMA_INVALID_RULE,
    category: 'network',
    severity: 'warning',
    description: 'Directory registry feeds must serve a recognised JSON schema',
    run() {},
  },
  {
    id: PROFILE_OUT_OF_SYNC_RULE,
    category: 'network',
    severity: 'warning',
    description:
      'Directory listing metadata (ORG_NAME, ORG_URL, ACCOUNTS) must match stellar.toml',
    run() {},
  },
  {
    id: CAPABILITY_MISMATCH_RULE,
    category: 'network',
    severity: 'warning',
    description:
      'Advertised SEP capabilities must match the endpoint fields declared in stellar.toml',
    run() {},
  },
];

export const anchorDiscoveryRuleIds: readonly string[] = anchorDiscoveryRules.map((rule) => rule.id);

function severityFor(
  rule: string,
  fallback: Severity,
  rules: RuleOverrides | undefined,
): Severity | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' || override === 'info' ? override : fallback;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Normalizes a display name for comparison: case and punctuation insensitive. */
function normalizeName(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, ' ')
    .trim();
}

/** Normalizes a hostname for comparison: lowercase, no `www.`, no trailing dot. */
function normalizeHost(value: string): string {
  return value.toLowerCase().replace(/^www\./, '').replace(/\.$/, '');
}

/**
 * Matches both bare SEP numbers (`"31"`) and tagged forms (`"sep31"`,
 * `"sep-24"`, `"sep_6"`), which different registries use interchangeably.
 */
const SEP_TAG_PATTERN = /^(?:sep[_-]?)?(\d+)$/i;

/** Extracts SEP numbers from an array of tags or an object of capability flags. */
function sepNumbersOf(values: unknown): string[] {
  const numbers = new Set<string>();
  if (Array.isArray(values)) {
    for (const value of values) {
      if (!isString(value)) continue;
      const match = SEP_TAG_PATTERN.exec(value.trim());
      if (match?.[1] !== undefined) numbers.add(match[1]);
    }
  } else if (isRecord(values)) {
    for (const [key, value] of Object.entries(values)) {
      const match = SEP_TAG_PATTERN.exec(key.trim());
      if (match?.[1] !== undefined && (value === true || value === 'true')) numbers.add(match[1]);
    }
  }
  return [...numbers].sort();
}

/** Normalizes one raw registry record; returns `undefined` for unusable entries. */
function normalizeEntry(raw: unknown): DirectoryEntry | undefined {
  if (!isRecord(raw)) return undefined;
  const tags = Array.isArray(raw.tags) ? raw.tags.filter(isString) : [];
  const seps = [
    ...sepNumbersOf(raw.seps),
    ...sepNumbersOf(raw.capabilities),
    ...sepNumbersOf(raw.tags),
  ];
  const entry: DirectoryEntry = { tags, seps: [...new Set(seps)].sort() };
  if (isString(raw.address)) entry.address = raw.address;
  if (isString(raw.name)) entry.name = raw.name;
  if (isString(raw.domain)) entry.domain = raw.domain;
  if (isString(raw.url)) entry.url = raw.url;
  return entry;
}

/**
 * Reads the records out of the registry response shapes this validator
 * recognises: a Horizon-style `_embedded.records` page (SEP-37), a plain
 * top-level `records` array, or a bare JSON array.
 *
 * Returns `undefined` when the payload is none of those, so the caller can
 * report a schema problem instead of silently treating it as "no entries".
 */
export function parseDirectoryRecords(body: unknown): DirectoryEntry[] | undefined {
  let records: unknown;
  if (Array.isArray(body)) {
    records = body;
  } else if (isRecord(body)) {
    if (isRecord(body._embedded) && Array.isArray(body._embedded.records)) {
      records = body._embedded.records;
    } else if (Array.isArray(body.records)) {
      records = body.records;
    }
  }
  if (!Array.isArray(records)) return undefined;

  const entries: DirectoryEntry[] = [];
  for (const raw of records) {
    const entry = normalizeEntry(raw);
    if (entry !== undefined) entries.push(entry);
  }
  return entries;
}

/** The endpoint fields a `stellar.toml` declares, keyed by SEP number. */
export function declaredSepsOf(doc: Record<string, unknown>): Map<string, string> {
  const declared = new Map<string, string>();
  for (const [sep, field] of TOML_SEP_ENDPOINTS) {
    if (isString(doc[field]) && doc[field] !== '') declared.set(sep, field);
  }
  return declared;
}

/** Every SEP a directory entry advertises. */
export function advertisedSepsOf(entry: DirectoryEntry): string[] {
  return [...new Set(entry.seps)].sort();
}

/** The anchor domain, from `--domain` or `DOCUMENTATION.ORG_URL`. */
export function anchorDomainOf(
  doc: Record<string, unknown>,
  domain?: string,
): string | undefined {
  if (isString(domain) && domain.trim() !== '') {
    const host = hostOf(
      domain.includes('://') ? domain : `https://${domain.split('/')[0] ?? domain}`,
    );
    if (host !== undefined) return normalizeHost(host);
  }
  const documentation = doc.DOCUMENTATION;
  if (isRecord(documentation)) {
    const host = hostOf(documentation.ORG_URL);
    if (host !== undefined) return normalizeHost(host);
  }
  return undefined;
}

interface ReportOptions {
  rule: string;
  fallback: Severity;
  message: string;
  path: string;
  suggestion: string;
  helpUri?: string;
}

/**
 * Audits an anchor's directory listings against its published `stellar.toml`.
 *
 * The class form exists for callers that audit several documents with the same
 * configuration; {@link validateAnchorDiscovery} is the one-shot convenience
 * wrapper the CLI uses.
 */
export class AnchorDiscoveryValidator {
  private readonly options: AnchorDiscoveryOptions;

  constructor(options: AnchorDiscoveryOptions = {}) {
    this.options = options;
  }

  private report(diagnostics: Diagnostic[], options: ReportOptions): void {
    const severity = severityFor(options.rule, options.fallback, this.options.rules);
    if (severity === undefined) return;
    diagnostics.push({
      rule: options.rule,
      severity,
      category: 'network',
      message: options.message,
      path: options.path,
      ...(options.helpUri === undefined ? {} : { helpUri: options.helpUri }),
      suggestion: options.suggestion,
    });
  }

  /**
   * Runs the audit. Returns `[]` — never throws — when the anchor domain is
   * unknown (there is nothing to look up) or when every rule is disabled.
   */
  async validate(doc: Record<string, unknown>): Promise<Diagnostic[]> {
    const domain = anchorDomainOf(doc, this.options.domain);
    if (domain === undefined) return [];

    const enabled = anchorDiscoveryRules.some(
      (rule) => severityFor(rule.id, rule.severity, this.options.rules) !== undefined,
    );
    if (!enabled) return [];

    const directories = this.options.directories ?? DEFAULT_DIRECTORY_REGISTRIES;
    const fetchImpl = this.options.fetchImpl ?? fetch;
    const timeoutMs = this.options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const diagnostics: Diagnostic[] = [];

    for (const registry of directories) {
      await this.auditRegistry(registry, domain, doc, fetchImpl, timeoutMs, diagnostics);
    }

    return diagnostics;
  }

  private async auditRegistry(
    registry: DirectoryRegistry,
    domain: string,
    doc: Record<string, unknown>,
    fetchImpl: typeof fetch,
    timeoutMs: number,
    diagnostics: Diagnostic[],
  ): Promise<void> {
    const url = `${registry.url.replace(/\/+$/, '')}?search=${encodeURIComponent(domain)}&limit=100`;

    let response: Response;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        response = await fetchImpl(url, { signal: controller.signal, redirect: 'follow' });
      } finally {
        clearTimeout(timer);
      }
    } catch (error) {
      this.report(diagnostics, {
        rule: REGISTRY_UNREACHABLE_RULE,
        fallback: 'warning',
        message: `${registry.name} registry at ${registry.url} could not be reached: ${(error as Error).message}`,
        path: 'DOCUMENTATION.ORG_URL',
        suggestion:
          'Confirm the directory endpoint is online, or point --directory-feed at its current URL.',
      });
      return;
    }

    if (!response.ok) {
      this.report(diagnostics, {
        rule: REGISTRY_UNREACHABLE_RULE,
        fallback: 'warning',
        message: `${registry.name} registry at ${registry.url} returned HTTP ${response.status}`,
        path: 'DOCUMENTATION.ORG_URL',
        suggestion: 'Confirm the directory endpoint is online and serves JSON, then re-run.',
      });
      return;
    }

    let body: unknown;
    try {
      body = await response.json();
    } catch {
      this.report(diagnostics, {
        rule: SCHEMA_INVALID_RULE,
        fallback: 'warning',
        message: `${registry.name} registry at ${registry.url} did not return valid JSON`,
        path: 'DOCUMENTATION.ORG_URL',
        suggestion: 'Verify the registry feed is a JSON endpoint, not an HTML page.',
      });
      return;
    }

    const entries = parseDirectoryRecords(body);
    if (entries === undefined) {
      this.report(diagnostics, {
        rule: SCHEMA_INVALID_RULE,
        fallback: 'warning',
        message: `${registry.name} registry response does not match a recognised directory schema (expected records, _embedded.records, or a JSON array)`,
        path: 'DOCUMENTATION.ORG_URL',
        suggestion:
          'Return a SEP-37-compatible directory page, or configure an adapter for this registry.',
      });
      return;
    }

    const matching = entries.filter((entry) => {
      const entryHost = entry.domain !== undefined ? normalizeHost(entry.domain) : undefined;
      return entryHost !== undefined && (entryHost === domain || entryHost.endsWith(`.${domain}`));
    });

    if (matching.length === 0) {
      this.report(diagnostics, {
        rule: PROFILE_OUT_OF_SYNC_RULE,
        fallback: 'warning',
        message: `${registry.name} has no directory entry for ${domain}`,
        path: 'DOCUMENTATION.ORG_URL',
        suggestion: `Register the anchor with ${registry.name} (or remove the directory listing requirement) so wallet clients can discover it.`,
      });
      return;
    }

    this.compareProfile(registry, domain, doc, matching, diagnostics);
    this.compareCapabilities(registry, domain, doc, matching, diagnostics);
  }

  private compareProfile(
    registry: DirectoryRegistry,
    domain: string,
    doc: Record<string, unknown>,
    entries: DirectoryEntry[],
    diagnostics: Diagnostic[],
  ): void {
    const documentation = isRecord(doc.DOCUMENTATION) ? doc.DOCUMENTATION : {};
    const orgName = isString(documentation.ORG_NAME) ? documentation.ORG_NAME : undefined;
    const orgUrl = isString(documentation.ORG_URL) ? documentation.ORG_URL : undefined;
    const orgHost = hostOf(orgUrl);
    const accounts = Array.isArray(doc.ACCOUNTS) ? doc.ACCOUNTS.filter(isString) : [];

    // The directory entry a wallet would match against: the first name/url pair.
    for (const entry of entries) {
      if (entry.name !== undefined && orgName !== undefined) {
        if (normalizeName(entry.name) !== normalizeName(orgName)) {
          this.report(diagnostics, {
            rule: PROFILE_OUT_OF_SYNC_RULE,
            fallback: 'warning',
            message: `${registry.name} lists "${entry.name}" for ${domain}, but stellar.toml DOCUMENTATION.ORG_NAME is "${orgName}"`,
            path: 'DOCUMENTATION.ORG_NAME',
            suggestion: `Update the ${registry.name} listing or the stellar.toml so both advertise the same organisation name.`,
          });
        }
      }

      if (entry.url !== undefined && orgHost !== undefined) {
        const entryHost = hostOf(entry.url);
        if (entryHost !== undefined && normalizeHost(entryHost) !== normalizeHost(orgHost)) {
          this.report(diagnostics, {
            rule: PROFILE_OUT_OF_SYNC_RULE,
            fallback: 'warning',
            message: `${registry.name} lists URL ${entry.url} for ${domain}, out of sync with stellar.toml DOCUMENTATION.ORG_URL ${orgUrl}`,
            path: 'DOCUMENTATION.ORG_URL',
            suggestion: `Update the ${registry.name} listing URL to the canonical ORG_URL host.`,
          });
        }
      }
    }

    if (accounts.length === 0) return;
    const directoryAddresses = entries
      .map((entry) => entry.address)
      .filter((address): address is string => address !== undefined);
    if (directoryAddresses.length === 0) return;

    const declared = new Set(accounts);
    if (directoryAddresses.some((address) => declared.has(address))) return;

    this.report(diagnostics, {
      rule: PROFILE_OUT_OF_SYNC_RULE,
      fallback: 'warning',
      message: `${registry.name} lists account${directoryAddresses.length === 1 ? '' : 's'} ${directoryAddresses.join(', ')} for ${domain}, but none appear in stellar.toml ACCOUNTS`,
      path: 'ACCOUNTS',
      suggestion:
        'Add the operational account the directory lists to ACCOUNTS, or update the directory entry to the accounts the file declares.',
    });
  }

  private compareCapabilities(
    registry: DirectoryRegistry,
    domain: string,
    doc: Record<string, unknown>,
    entries: DirectoryEntry[],
    diagnostics: Diagnostic[],
  ): void {
    const declared = declaredSepsOf(doc);
    const advertised = new Set<string>();
    for (const entry of entries) {
      for (const sep of advertisedSepsOf(entry)) advertised.add(sep);
    }
    // A registry that publishes no SEP metadata cannot contradict the file.
    if (advertised.size === 0) return;

    for (const [sep, field] of declared) {
      if (advertised.has(sep)) continue;
      this.report(diagnostics, {
        rule: CAPABILITY_MISMATCH_RULE,
        fallback: 'warning',
        message: `${registry.name} does not advertise SEP-${sep} for ${domain}, but stellar.toml declares ${field}`,
        path: field,
        suggestion: `Add the SEP-${sep} capability to the ${registry.name} listing so clients route SEP-${sep} requests here.`,
      });
    }

    for (const sep of [...advertised].sort()) {
      if (declared.has(sep)) continue;
      const field = TOML_SEP_ENDPOINTS.get(sep);
      this.report(diagnostics, {
        rule: CAPABILITY_MISMATCH_RULE,
        fallback: 'warning',
        message: `${registry.name} advertises SEP-${sep} for ${domain}, but stellar.toml does not declare ${field ?? `a SEP-${sep} endpoint`}`,
        path: 'DOCUMENTATION.ORG_URL',
        suggestion: `Remove the stale SEP-${sep} capability from the ${registry.name} listing, or publish the endpoint in stellar.toml.`,
      });
    }
  }
}

/** One-shot convenience wrapper around {@link AnchorDiscoveryValidator}. */
export async function validateAnchorDiscovery(
  doc: Record<string, unknown>,
  options: AnchorDiscoveryOptions = {},
): Promise<Diagnostic[]> {
  return new AnchorDiscoveryValidator(options).validate(doc);
}
