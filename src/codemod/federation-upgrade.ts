/**
 * Codemod for legacy federation declarations.
 *
 * SEP-2 asks wallets to append `q` and `type` query parameters themselves when
 * they call a federation server. Older `stellar.toml` files instead bake a
 * lookup template into `FEDERATION_SERVER` — an `http://` scheme, a trailing
 * slash, or a `?q={q}&type={type}` placeholder pair — which the SEP-2 client
 * cannot append to without producing a malformed URL. This module rewrites
 * those declarations to the canonical HTTPS endpoint and records which lookup
 * directions the legacy declaration actually advertised, so the migration
 * preserves reverse-lookup support rather than silently dropping it.
 *
 * The transform is line-based, like `migrate.ts`: only the value token of the
 * `FEDERATION_SERVER` assignment changes, so comments, ordering, and every
 * unrelated byte survive the rewrite.
 */

import type { Diagnostic, RuleCategory, Severity } from '../types.js';
import { generateDiff } from './migrate.js';

export const FEDERATION_UPGRADE_APPLIED_RULE = 'codemod/federation-upgrade-applied';
export const FEDERATION_UPGRADE_SKIPPED_RULE = 'codemod/federation-upgrade-skipped';
export const FEDERATION_SERVER_INVALID_RULE = 'codemod/federation-server-invalid';
export const FEDERATION_SERVER_UNREACHABLE_RULE = 'codemod/federation-server-unreachable';

const SEP2_SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0002.md';
const DEFAULT_FEDERATION_PATH = '/federation';
/** A well-known address used only to perform a forward-lookup reachability probe. */
const PROBE_FORWARD_ADDRESS = 'lint-probe*example.com';
/** A well-formed account id is not required: SEP-2 answers 404 for unknown ids. */
const PROBE_REVERSE_ACCOUNT = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF';

/** Which SEP-2 lookup directions a declaration advertises. */
export interface FederationLookupFlags {
  /** `type=name`: address to account id. */
  forward: boolean;
  /** `type=id`: account id to addresses. */
  reverse: boolean;
}

export interface FederationUpgradeOptions {
  /** Probe the rewritten endpoint under `--check-network`. */
  checkNetwork?: boolean;
  /** Transport used by the reachability probe. */
  fetchImpl?: typeof fetch;
  /** Path shown in the unified diff headers. */
  filePath?: string;
  /** Rule severity overrides, keyed by rule id. */
  rules?: Record<string, Severity | 'off'>;
}

export interface FederationUpgradeResult {
  /** The rewritten document (equal to the input when nothing matched). */
  source: string;
  /** Unified diff preview between the input and {@link source}. */
  diff: string;
  /** True when the rewrite produced a different document. */
  changed: boolean;
  /**
   * True when the rewrite is safe to write back. The federation transform has
   * no conflict case, so this mirrors {@link changed}; it exists so a caller
   * can share one shape with `migrate.ts`.
   */
  applied: boolean;
  /** Canonical endpoint the migration produced, when the file declared one. */
  federationServer?: string;
  /** Lookup directions preserved from the legacy declaration. */
  lookups: FederationLookupFlags;
  diagnostics: Diagnostic[];
}

function severityFor(
  rule: string,
  fallback: Severity,
  rules?: Record<string, Severity | 'off'>,
): Severity | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override ?? fallback;
}

function push(
  diagnostics: Diagnostic[],
  rule: string,
  fallback: Severity,
  message: string,
  suggestion: string,
  rules?: Record<string, Severity | 'off'>,
  extras: Partial<Diagnostic> = {},
): void {
  const severity = severityFor(rule, fallback, rules);
  if (severity === undefined) return;
  diagnostics.push({
    rule,
    severity,
    category: 'codemod' as RuleCategory,
    message,
    helpUri: SEP2_SPEC,
    suggestion,
    ...extras,
  });
}

/**
 * Reads the `type` values a legacy declaration embedded in its query string or
 * placeholder template. A declaration that named neither lookup direction
 * predates the distinction and is assumed to support both.
 */
export function legacyLookupFlags(raw: string): FederationLookupFlags {
  const lower = raw.toLowerCase();
  const mentionsName = /\btype\s*=\s*['"]?name\b/.test(lower);
  const mentionsId = /\btype\s*=\s*['"]?id\b/.test(lower);
  if (mentionsName && mentionsId) return { forward: true, reverse: true };
  if (mentionsName) return { forward: true, reverse: false };
  if (mentionsId) return { forward: false, reverse: true };
  return { forward: true, reverse: true };
}

/**
 * Strips the lookup template out of a legacy federation URL.
 *
 * Handles the placeholder spellings seen in the wild — `{q}`, `<q>`, `%s`, and
 * a literal `q=`/`type=` query pair — as well as fragments and credentials. The
 * result is a base URL a SEP-2 client can append `?q=…&type=…` to.
 */
export function canonicalFederationServer(raw: string): string | undefined {
  const trimmed = raw.trim();
  if (trimmed === '') return undefined;

  // `http://` is the common legacy scheme; SEP-2 requires TLS.
  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  // Strip the placeholder template, any real query string, and any fragment.
  const withoutTemplate = withScheme
    .replace(/\?[^#]*$/, '')
    .replace(/#.*$/, '')
    .replace(/\{[^}]*\}/g, '')
    .replace(/<[^>]*>/g, '')
    .replace(/%s/g, '');

  let url: URL;
  try {
    url = new URL(withoutTemplate);
  } catch {
    return undefined;
  }
  if (url.hostname === '') return undefined;

  url.protocol = 'https:';
  url.search = '';
  url.hash = '';

  let pathname = url.pathname.replace(/\/+$/, '');
  if (pathname === '') pathname = DEFAULT_FEDERATION_PATH;
  url.pathname = pathname;

  return url.toString().replace(/\/$/, '');
}

/** Rewrites only the value token of the `FEDERATION_SERVER` assignment. */
function rewriteDeclaration(source: string, value: string): string {
  const lines = source.split('\n');
  let changed = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line === undefined) continue;
    const match = line.match(/^(\s*FEDERATION_SERVER\s*=\s*)((['"])(.*?)\3)(\s*(?:#.*)?)$/);
    if (!match) continue;
    const prefix = match[1] ?? '';
    const suffix = match[5] ?? '';
    const quote = match[3] ?? '"';
    lines[i] = `${prefix}${quote}${value}${quote}${suffix}`;
    changed = true;
    break;
  }

  return changed ? lines.join('\n') : source;
}

function declaredFederationServer(source: string): string | undefined {
  const match = source.match(/^\s*FEDERATION_SERVER\s*=\s*(['"])(.*?)\1\s*(?:#.*)?$/m);
  return match?.[2];
}

/** Issues one SEP-2 lookup; true when the endpoint answered below 5xx. */
async function probeFederation(
  endpoint: string,
  query: string,
  fetchImpl: typeof fetch,
): Promise<boolean> {
  try {
    const response = await fetchImpl(`${endpoint}?${query}`, {
      headers: { accept: 'application/json' },
      redirect: 'follow',
    });
    // Any HTTP answer proves the endpoint is listening: SEP-2 answers 404 for
    // an unknown account, which is a healthy server, not an outage.
    return response.status < 500;
  } catch {
    return false;
  }
}

async function checkReachability(
  endpoint: string,
  lookups: FederationLookupFlags,
  fetchImpl: typeof fetch,
): Promise<string | undefined> {
  // Probe both directions even when the first one answers: the point of the
  // check is which lookups the preserved declaration still reaches, so the run
  // must not short-circuit on the forward lookup and skip reverse.
  const probes: string[] = [];
  if (lookups.forward) {
    probes.push(`q=${encodeURIComponent(PROBE_FORWARD_ADDRESS)}&type=name`);
  }
  if (lookups.reverse) {
    probes.push(`q=${encodeURIComponent(PROBE_REVERSE_ACCOUNT)}&type=id`);
  }
  if (probes.length === 0) return undefined;

  const reachable = await Promise.all(
    probes.map((query) => probeFederation(endpoint, query, fetchImpl)),
  );
  return reachable.some(Boolean) ? undefined : `No SEP-2 lookup answered at ${endpoint}`;
}

/**
 * Rewrites a legacy federation declaration into its canonical SEP-2 form and
 * reports what it did. The returned `diff` is always safe to print first: the
 * caller decides whether to write `source` back to disk.
 */
export async function upgradeFederationDeclaration(
  source: string,
  options: FederationUpgradeOptions = {},
): Promise<FederationUpgradeResult> {
  const diagnostics: Diagnostic[] = [];
  const raw = declaredFederationServer(source);

  if (raw === undefined) {
    push(
      diagnostics,
      FEDERATION_UPGRADE_SKIPPED_RULE,
      'info',
      'No FEDERATION_SERVER declaration to upgrade',
      'Add FEDERATION_SERVER = "https://your-anchor.example.com/federation" if the anchor runs a SEP-2 server.',
      options.rules,
    );
    return {
      source,
      diff: generateDiff(source, source, options.filePath ?? 'stellar.toml'),
      changed: false,
      applied: false,
      lookups: { forward: true, reverse: true },
      diagnostics,
    };
  }

  const lookups = legacyLookupFlags(raw);
  const canonical = canonicalFederationServer(raw);

  if (canonical === undefined) {
    push(
      diagnostics,
      FEDERATION_SERVER_INVALID_RULE,
      'error',
      `FEDERATION_SERVER "${raw}" is not a usable SEP-2 endpoint`,
      'Use an absolute https:// URL, e.g. "https://anchor.example.com/federation".',
      options.rules,
      { path: 'FEDERATION_SERVER' },
    );
    return {
      source,
      diff: generateDiff(source, source, options.filePath ?? 'stellar.toml'),
      changed: false,
      applied: false,
      lookups,
      diagnostics,
    };
  }

  const migrated = rewriteDeclaration(source, canonical);
  const changed = migrated !== source;

  if (changed) {
    push(
      diagnostics,
      FEDERATION_UPGRADE_APPLIED_RULE,
      'info',
      `FEDERATION_SERVER normalized to ${canonical}`,
      'Clients append q and type themselves, so the declaration must not embed a lookup template.',
      options.rules,
      { path: 'FEDERATION_SERVER' },
    );
  } else {
    push(
      diagnostics,
      FEDERATION_UPGRADE_SKIPPED_RULE,
      'info',
      'FEDERATION_SERVER already uses the canonical SEP-2 form',
      'Nothing to migrate.',
      options.rules,
    );
  }

  if (options.checkNetwork === true) {
    const unreachable = await checkReachability(canonical, lookups, options.fetchImpl ?? fetch);
    if (unreachable !== undefined) {
      push(
        diagnostics,
        FEDERATION_SERVER_UNREACHABLE_RULE,
        'warning',
        unreachable,
        'Confirm the federation server is deployed and answers SEP-2 name and id lookups.',
        options.rules,
        { path: 'FEDERATION_SERVER' },
      );
    }
  }

  return {
    source: migrated,
    diff: generateDiff(source, migrated, options.filePath ?? 'stellar.toml'),
    changed,
    applied: changed,
    federationServer: canonical,
    lookups,
    diagnostics,
  };
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const federationUpgradeRules = [
  {
    id: FEDERATION_UPGRADE_APPLIED_RULE,
    category: 'codemod' as RuleCategory,
    severity: 'info' as Severity,
    description: 'Legacy FEDERATION_SERVER declarations can be rewritten to canonical SEP-2 form',
  },
  {
    id: FEDERATION_UPGRADE_SKIPPED_RULE,
    category: 'codemod' as RuleCategory,
    severity: 'info' as Severity,
    description: 'Reports that a federation upgrade was a no-op',
  },
  {
    id: FEDERATION_SERVER_INVALID_RULE,
    category: 'codemod' as RuleCategory,
    severity: 'error' as Severity,
    description: 'FEDERATION_SERVER must be an absolute https:// SEP-2 endpoint',
  },
  {
    id: FEDERATION_SERVER_UNREACHABLE_RULE,
    category: 'codemod' as RuleCategory,
    severity: 'warning' as Severity,
    description: 'The migrated federation endpoint should answer SEP-2 lookups',
  },
] as const;
