/**
 * Horizon Account Data Entry Auditor.
 *
 * Fetches account data dictionary from Horizon for the SIGNING_KEY account.
 * Decodes base64-encoded data values.
 * Verifies stellar_toml_hash entry matches the SHA-256 hash of the live stellar.toml.
 * Verifies org_domain entry matches the serving home domain.
 * Emits security/on-chain-toml-hash-mismatch (error).
 * Emits security/missing-on-chain-verification-proof (warning).
 *
 * Runs under opt-in --check-network.
 */

import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';
import { isString } from '../predicates.js';
import { horizonUrlFor } from '../network-checks.js';

// node:crypto is dynamically imported to avoid bundling in browser builds
async function getCreateHash(): Promise<(algorithm: string) => { update: (data: string | Uint8Array, encoding?: string) => { digest: (encoding?: 'hex' | 'base64' | 'utf8') => string | Uint8Array } }> {
  const { createHash } = await import('node:crypto');
  return createHash as unknown as (algorithm: string) => { update: (data: string | Uint8Array, encoding?: string) => { digest: (encoding?: 'hex' | 'base64' | 'utf8') => string | Uint8Array } };
}

export const HASH_MISMATCH_RULE = 'security/on-chain-toml-hash-mismatch';
export const MISSING_PROOF_RULE = 'security/missing-on-chain-verification-proof';

export interface AccountDataAuditorOptions {
  rules?: RuleOverrides;
  /** The file path that named the account, attached to every diagnostic. */
  path?: string;
  /** Horizon endpoint, overriding the one derived from the passphrase. */
  horizonUrl?: string;
  /** Network passphrase, used to derive the Horizon endpoint when unset. */
  networkPassphrase?: string;
  /** The domain the stellar.toml is served from (for org_domain verification). */
  domain?: string;
}

/** Horizon account data entry */
interface HorizonAccountData {
  [key: string]: string; // base64-encoded values
}

/** Decoded account data entry */
interface DecodedAccountData {
  [key: string]: string; // decoded string values
}

/**
 * Fetches account data from Horizon.
 */
async function fetchAccountData(
  accountId: string,
  horizonUrl: string,
  fetchImpl: typeof fetch,
): Promise<HorizonAccountData | undefined> {
  try {
    const response = await fetchImpl(`${horizonUrl}/accounts/${encodeURIComponent(accountId)}`);
    if (!response.ok) return undefined;
    const body = (await response.json()) as Record<string, unknown>;
    const data = body.data;
    if (typeof data !== 'object' || data === null || Array.isArray(data)) return undefined;
    const result: HorizonAccountData = {};
    for (const [key, value] of Object.entries(data)) {
      if (isString(value)) result[key] = value;
    }
    return result;
  } catch {
    return undefined;
  }
}

/**
 * Decodes base64 account data values to strings.
 */
function decodeAccountData(data: HorizonAccountData): DecodedAccountData {
  const result: DecodedAccountData = {};
  for (const [key, b64] of Object.entries(data)) {
    try {
      result[key] = Buffer.from(b64, 'base64').toString('utf8');
    } catch {
      // Skip entries that aren't valid base64/utf8
    }
  }
  return result;
}

/**
 * Computes SHA-256 hash of stellar.toml content.
 */
async function computeTomlHash(tomlContent: string): Promise<string> {
  const createHash = await getCreateHash();
  const result = createHash('sha256').update(tomlContent, 'utf8').digest('hex');
  return result as string;
}

/**
 * Audits a single account's data entries for verification proofs.
 */
export async function auditAccountData(
  accountId: string,
  tomlContent: string,
  horizonUrl: string,
  domain: string | undefined,
  fetchImpl: typeof fetch,
  options: AccountDataAuditorOptions = {},
): Promise<Diagnostic[]> {
  const diagnostics: Diagnostic[] = [];
  const finding = (rule: string, fallback: 'error' | 'warning', detail: string, suggestion?: string): Diagnostic[] => {
    const severity = severityFor(rule, fallback, options.rules);
    if (severity === undefined) return [];
    return [
      {
        rule,
        severity,
        category: 'network',
        message: `Account ${accountId} ${detail}`,
        ...(options.path !== undefined ? { path: options.path } : {}),
        ...(suggestion !== undefined ? { suggestion } : {}),
      },
    ];
  };

  const rawData = await fetchAccountData(accountId, horizonUrl, fetchImpl);
  if (rawData === undefined) {
    return finding(
      MISSING_PROOF_RULE,
      'warning',
      'could not be fetched from Horizon (account may not exist or network error)',
      'Ensure the account exists on the network and Horizon is reachable.',
    );
  }

  const decoded = decodeAccountData(rawData);
  const tomlHash = await computeTomlHash(tomlContent);
  let hasStellarTomlHash = false;
  let hasOrgDomain = false;

  // Check stellar_toml_hash
  if (decoded.stellar_toml_hash !== undefined) {
    hasStellarTomlHash = true;
    if (decoded.stellar_toml_hash !== tomlHash) {
      diagnostics.push(
        ...finding(
          HASH_MISMATCH_RULE,
          'error',
          `stellar_toml_hash (${decoded.stellar_toml_hash}) does not match the computed SHA-256 of the live stellar.toml (${tomlHash})`,
          'Update the on-chain stellar_toml_hash data entry to match the current stellar.toml content.',
        ),
      );
    }
  }

  // Check org_domain
  if (decoded.org_domain !== undefined) {
    hasOrgDomain = true;
    if (domain && decoded.org_domain !== domain) {
      diagnostics.push(
        ...finding(
          HASH_MISMATCH_RULE,
          'error',
          `org_domain (${decoded.org_domain}) does not match the serving domain (${domain})`,
          `Update the on-chain org_domain data entry to match the serving domain (${domain}).`,
        ),
      );
    }
  }

  // Warn if missing verification proofs
  if (!hasStellarTomlHash) {
    diagnostics.push(
      ...finding(
        MISSING_PROOF_RULE,
        'warning',
        'has no stellar_toml_hash data entry on-chain',
        'Add a stellar_toml_hash data entry to the account with the SHA-256 hash of the stellar.toml file.',
      ),
    );
  }

  if (!hasOrgDomain) {
    diagnostics.push(
      ...finding(
        MISSING_PROOF_RULE,
        'warning',
        'has no org_domain data entry on-chain',
        'Add an org_domain data entry to the account with the home domain serving the stellar.toml.',
      ),
    );
  }

  return diagnostics;
}

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules?: RuleOverrides,
): Severity | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

/**
 * Audits account data entries for SIGNING_KEY and ACCOUNTS declared in the file.
 */
export async function auditTomlAccountData(
  doc: Record<string, unknown>,
  tomlContent: string,
  fetchImpl: typeof fetch,
  options: AccountDataAuditorOptions = {},
): Promise<Diagnostic[]> {
  const diagnostics: Diagnostic[] = [];
  const passphrase =
    typeof doc.NETWORK_PASSPHRASE === 'string' ? doc.NETWORK_PASSPHRASE : undefined;
  const horizonUrl = options.horizonUrl ?? horizonUrlFor(passphrase);
  const domain = options.domain;

  const accountsToCheck: { id: string; path: string }[] = [];

  if (isString(doc.SIGNING_KEY)) {
    accountsToCheck.push({ id: doc.SIGNING_KEY, path: 'SIGNING_KEY' });
  }

  if (Array.isArray(doc.ACCOUNTS)) {
    doc.ACCOUNTS.forEach((acc, index) => {
      if (isString(acc)) {
        accountsToCheck.push({ id: acc, path: `ACCOUNTS[${index}]` });
      }
    });
  }

  for (const acc of accountsToCheck) {
    diagnostics.push(
      ...(await auditAccountData(
        acc.id,
        tomlContent,
        horizonUrl,
        domain,
        fetchImpl,
        { ...options, path: acc.path },
      )),
    );
  }

  return diagnostics;
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const accountDataAuditorRules: Rule[] = [
  {
    id: HASH_MISMATCH_RULE,
    category: 'network',
    severity: 'error',
    description: 'On-chain stellar.toml hash or org_domain does not match the live file or domain',
    run() {},
  },
  {
    id: MISSING_PROOF_RULE,
    category: 'network',
    severity: 'warning',
    description: 'Account is missing on-chain verification proofs (stellar_toml_hash or org_domain)',
    run() {},
  },
];

/** Rule ids emitted by {@link auditTomlAccountData}. */
export const accountDataAuditorRuleIds: readonly string[] = accountDataAuditorRules.map((rule) => rule.id);