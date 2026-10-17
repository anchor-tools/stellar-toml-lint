/**
 * Cross-SEP asset issuer federation lookup and reverse lookup consistency
 * auditor.
 *
 * SEP-2 federation servers map human-readable Stellar addresses
 * (`alice*anchor.com`) to account IDs, and reverse federation maps an account
 * ID back to an address. If the federation server answers with accounts that
 * conflict with the asset issuers or signing keys the file declares, user
 * payments are misrouted — the wallet trusts the file, the federated lookup
 * says something else, and nobody notices until funds land in the wrong place.
 *
 * Runs under opt-in `--check-network`. Two lookups are made against the
 * declared `FEDERATION_SERVER`, and their answers are cross-checked against
 * each other and against `SIGNING_KEY`/`ACCOUNTS`:
 *
 * - forward: `?type=name&q=deposit*<domain>` (or a caller-supplied probe name)
 * - reverse: `?type=id&q=<SIGNING_KEY>`
 *
 * A lookup that cannot be performed at all — an unreachable server, a non-200
 * answer, a body that is not a federation record — is reported under the same
 * rule the corresponding inconsistency would be, so a server that answers
 * nothing is never read as a pass. The rules are registered so `--list-rules`
 * and `--off`/`--warn`/`--error` know their ids.
 */
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { hostOf, isAccountId, isHttpsUrl, isString } from '../predicates.js';
import { adaptiveFetch } from '../network/adaptive-client.js';

export const FEDERATION_FORWARD_RESOLUTION_FAILED = 'federation/forward-resolution-failed';
export const FEDERATION_REVERSE_LOOKUP_MISMATCH = 'federation/reverse-lookup-mismatch';

/** Naming the SEP-2 rules a maintainer should re-read after a finding. */
const FEDERATION_SPEC =
  'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0002.md';

export interface FederationAuditOptions {
  rules?: RuleOverrides;
  /** The domain serving the file, when the caller already knows it. */
  domain?: string;
  /**
   * The forward name to resolve. Defaults to `deposit*<domain>`, the address a
   * deposit flow would type; a caller can point the audit at a real account.
   */
  probeName?: string;
}

/** The subset of a SEP-2 federation record this audit understands. */
interface FederationRecord {
  stellar_address?: string;
  account_id: string;
}

/** The result of one federation query: a record, or why there is none. */
type LookupOutcome = { ok: true; record: FederationRecord } | { ok: false; detail: string };

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules?: RuleOverrides,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Normalises a domain that may arrive bare (`example.com`) or as a URL. */
function normalizeDomain(value: unknown): string | undefined {
  if (!isString(value) || value.trim() === '') return undefined;
  const raw = value.trim();
  return hostOf(raw.includes('://') ? raw : `https://${raw}`)?.replace(/\.$/, '');
}

/**
 * The anchor's domain, from the caller, the file's `DOMAIN`, or the host of
 * `DOCUMENTATION.ORG_URL` — the same precedence the DNSSEC audit uses.
 */
function documentDomain(
  doc: Record<string, unknown>,
  explicit: string | undefined,
): string | undefined {
  const fromOption = normalizeDomain(explicit);
  if (fromOption !== undefined) return fromOption;

  const direct = normalizeDomain(doc.DOMAIN);
  if (direct !== undefined) return direct;

  const documentation = doc.DOCUMENTATION;
  if (isRecord(documentation)) {
    return normalizeDomain(documentation.ORG_URL);
  }
  return undefined;
}

/** The domain part of `alice*example.com` / `alice@example.com`. */
export function addressDomain(address: string): string | undefined {
  const at = address.search(/[*@]/);
  if (at < 0) return undefined;
  const host = address
    .slice(at + 1)
    .trim()
    .toLowerCase();
  return host === '' ? undefined : host.replace(/\.$/, '');
}

/**
 * GETs one federation URL and reads the record out of the answer.
 *
 * Never throws: a transport failure, a non-200 status, a body that is not JSON
 * or JSON that is not a federation record all come back as `ok: false` with a
 * phrase the caller can put in a message.
 */
export async function lookupFederationRecord(
  url: string,
  fetchImpl: typeof fetch = adaptiveFetch,
): Promise<LookupOutcome> {
  let response: Response;
  try {
    response = await fetchImpl(url, { redirect: 'follow' });
  } catch (error) {
    return { ok: false, detail: `could not be reached: ${errorMessage(error)}` };
  }

  if (!response.ok) return { ok: false, detail: `returned HTTP ${response.status}` };

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    return { ok: false, detail: 'did not return valid JSON' };
  }

  if (!isRecord(body)) return { ok: false, detail: 'did not return a JSON object' };

  const account = body.account_id;
  if (!isAccountId(account)) {
    return { ok: false, detail: 'did not return a valid account_id' };
  }

  const address = body.stellar_address;
  return {
    ok: true,
    record: {
      account_id: account as string,
      ...(isString(address) ? { stellar_address: address } : {}),
    },
  };
}

/** The URL of one federation query, with the value percent-encoded. */
export function federationLookupUrl(server: string, type: 'name' | 'id', value: string): string {
  return `${server.replace(/\/+$/, '')}?type=${type}&q=${encodeURIComponent(value)}`;
}

function finding(
  rule: string,
  fallback: 'error' | 'warning',
  message: string,
  suggestion: string,
  rules: RuleOverrides | undefined,
): Diagnostic[] {
  const severity = severityFor(rule, fallback, rules);
  if (severity === undefined) return [];
  return [
    {
      rule,
      severity,
      category: 'network',
      message,
      path: 'FEDERATION_SERVER',
      helpUri: FEDERATION_SPEC,
      suggestion,
    },
  ];
}

/**
 * Audits the file's `FEDERATION_SERVER` for forward/reverse consistency.
 *
 * Silent unless the file declares both an `https://` federation server and a
 * valid `SIGNING_KEY`; a malformed server or key is already reported offline by
 * `general/https-endpoints` and `general/signing-keys`, and a run that has
 * nothing to cross-check should not open a socket.
 */
export async function checkFederationBidirectional(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = adaptiveFetch,
  options: FederationAuditOptions = {},
): Promise<Diagnostic[]> {
  const server = doc.FEDERATION_SERVER;
  if (!isString(server) || !isHttpsUrl(server)) return [];

  const signingKey = isAccountId(doc.SIGNING_KEY) ? (doc.SIGNING_KEY as string) : undefined;
  if (signingKey === undefined) return [];

  // `SIGNING_KEY` is authoritative; `ACCOUNTS` entries are the other accounts
  // the anchor says it controls, so a federated answer from any of them is not
  // a conflict with the file.
  const authorized = new Set<string>([signingKey]);
  if (Array.isArray(doc.ACCOUNTS)) {
    for (const account of doc.ACCOUNTS) if (isAccountId(account)) authorized.add(account);
  }

  const domain = documentDomain(doc, options.domain);
  const diagnostics: Diagnostic[] = [];

  // Forward: does the anchor's own deposit address resolve, and to an account
  // the file authorises?
  let forward: FederationRecord | undefined;
  if (domain !== undefined) {
    const name = options.probeName ?? `deposit*${domain}`;
    const outcome = await lookupFederationRecord(
      federationLookupUrl(server, 'name', name),
      fetchImpl,
    );
    if (!outcome.ok) {
      diagnostics.push(
        ...finding(
          FEDERATION_FORWARD_RESOLUTION_FAILED,
          'error',
          `Forward federation lookup for "${name}" ${outcome.detail}`,
          'Publish a federation record for the deposit address, or point FEDERATION_SERVER at the live SEP-2 service.',
          options.rules,
        ),
      );
    } else {
      forward = outcome.record;
      if (!authorized.has(forward.account_id)) {
        diagnostics.push(
          ...finding(
            FEDERATION_FORWARD_RESOLUTION_FAILED,
            'error',
            `Forward federation lookup for "${name}" resolved to ${forward.account_id}, which is neither SIGNING_KEY nor an ACCOUNTS entry`,
            'Return an account the file declares, or add the federated account to ACCOUNTS.',
            options.rules,
          ),
        );
      }
    }
  }

  // Reverse: does the signing key resolve back to this anchor, and to the same
  // account the forward lookup returned?
  const reverse = await lookupFederationRecord(
    federationLookupUrl(server, 'id', signingKey),
    fetchImpl,
  );

  if (!reverse.ok) {
    diagnostics.push(
      ...finding(
        FEDERATION_REVERSE_LOOKUP_MISMATCH,
        'error',
        `Reverse federation lookup for ${signingKey} ${reverse.detail}`,
        'Publish a reverse federation record mapping SIGNING_KEY back to this anchor.',
        options.rules,
      ),
    );
    return diagnostics;
  }

  if (!authorized.has(reverse.record.account_id)) {
    diagnostics.push(
      ...finding(
        FEDERATION_REVERSE_LOOKUP_MISMATCH,
        'error',
        `Reverse federation lookup for ${signingKey} returned account ${reverse.record.account_id}, which does not match the queried key`,
        'Make the federation server map the queried account back to itself, so a payment cannot be misrouted.',
        options.rules,
      ),
    );
  }

  if (forward !== undefined && forward.account_id !== reverse.record.account_id) {
    diagnostics.push(
      ...finding(
        FEDERATION_REVERSE_LOOKUP_MISMATCH,
        'error',
        `Forward federation lookup returned ${forward.account_id} but reverse lookup returned ${reverse.record.account_id}`,
        'Reconcile the forward and reverse records at the federation server so both directions agree.',
        options.rules,
      ),
    );
  }

  const address = reverse.record.stellar_address;
  const addressHost = address === undefined ? undefined : addressDomain(address);
  if (domain !== undefined && addressHost !== undefined && addressHost !== domain) {
    diagnostics.push(
      ...finding(
        FEDERATION_REVERSE_LOOKUP_MISMATCH,
        'error',
        `Reverse federation lookup for ${signingKey} returned "${address}", a foreign domain rather than ${domain}`,
        'The reverse record must resolve to an address on the domain that serves this stellar.toml.',
        options.rules,
      ),
    );
  }

  return diagnostics;
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const federationBidirectionalRules: Rule[] = [
  {
    id: FEDERATION_FORWARD_RESOLUTION_FAILED,
    category: 'network',
    severity: 'error',
    description: 'FEDERATION_SERVER must resolve a forward name lookup to an authorised account',
    run() {},
  },
  {
    id: FEDERATION_REVERSE_LOOKUP_MISMATCH,
    category: 'network',
    severity: 'error',
    description:
      'FEDERATION_SERVER reverse lookups must agree with SIGNING_KEY and the forward lookup',
    run() {},
  },
];

/** Rule ids emitted by {@link checkFederationBidirectional}. */
export const federationBidirectionalRuleIds: readonly string[] = federationBidirectionalRules.map(
  (rule) => rule.id,
);
