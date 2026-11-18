/**
 * Reverse federation lookup and memo routing consistency verifier.
 *
 * SEP-2 resolves both directions: `type=name&q=user*domain` gives the account,
 * and `type=id&q=G...` (or `M...`) gives the address back. If the reverse lookup
 * names a different user, or the memo an exchange requires is missing, a wallet
 * sending to the returned address can misroute funds.
 *
 * `ReverseFederationVerifier` queries the server declared in
 * `FEDERATION_SERVER` with the accounts the anchor already publishes
 * (`ACCOUNTS` and currency issuers), checks the forward → reverse → forward
 * round trip for each, validates every memo against Stellar Core's rules, and
 * reports the discrepancies a payment flow would hit.
 */

import { StrKey } from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isHttpsUrl, isString } from '../predicates.js';

const NO_SERVER_RULE = 'federation/reverse-missing-server';
const UNREACHABLE_RULE = 'federation/reverse-unreachable';
const MISMATCH_RULE = 'federation/reverse-mismatch';
const INVALID_SCHEMA_RULE = 'federation/invalid-response';
const MEMO_RULE = 'federation/invalid-memo';
const MISSING_MEMO_RULE = 'federation/memo-missing';

const SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0002.md';

export type MemoType = 'text' | 'id' | 'hash';

export interface FederationRecord {
  stellar_address: string;
  account_id: string;
  memo_type?: string;
  memo?: string;
}

export interface MemoProblem {
  code: 'memo/invalid-type' | 'memo/invalid-value' | 'memo/missing';
  message: string;
}

export interface ReverseCheck {
  accountId: string;
  /** Forward lookup result for the address, when the server returned one. */
  forward?: FederationRecord;
  /** SEP-2 schema problems in the forward response. */
  schemaProblems?: string[];
  /** Reverse lookup result for `accountId`. */
  reverse?: FederationRecord;
  /** Forward lookup of the address the reverse lookup returned. */
  roundTrip?: FederationRecord;
  consistent: boolean;
  memoProblems: MemoProblem[];
  error?: string;
}

export interface ReverseFederationReport {
  ok: boolean;
  server?: string;
  checks: ReverseCheck[];
  findings: { code: string; severity: 'error' | 'warning'; message: string; suggestion: string }[];
}

export interface ReverseFederationOptions {
  rules?: RuleOverrides;
  /** Additional addresses to check, e.g. from a wallet config. */
  accounts?: string[];
}

const MEMO_TYPES = new Set<MemoType>(['text', 'id', 'hash']);
const HASH_PATTERN = /^[0-9a-f]{64}$/i;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Validates a SEP-2 record shape and its memo against Stellar Core rules. */
export function validateFederationRecord(body: unknown): {
  record?: FederationRecord;
  problems: string[];
} {
  if (!isRecord(body)) return { problems: ['response is not a JSON object'] };
  const problems: string[] = [];

  if (!isString(body.stellar_address) || !body.stellar_address.includes('*')) {
    problems.push('stellar_address is missing or not "user*domain"');
  }
  if (
    !isString(body.account_id) ||
    !(
      StrKey.isValidEd25519PublicKey(body.account_id) ||
      StrKey.isValidMed25519PublicKey(body.account_id)
    )
  ) {
    problems.push('account_id is not a valid Stellar public or muxed account');
  }
  if (body.memo_type !== undefined && !isString(body.memo_type)) {
    problems.push('memo_type must be a string');
  }
  if (body.memo !== undefined && !isString(body.memo)) {
    problems.push('memo must be a string');
  }
  if (problems.length > 0) return { problems };

  const record: FederationRecord = {
    stellar_address: body.stellar_address as string,
    account_id: body.account_id as string,
  };
  if (isString(body.memo_type)) record.memo_type = body.memo_type;
  if (isString(body.memo)) record.memo = body.memo;
  return { record, problems };
}

/** Memo rules from Stellar Core: text ≤ 28 bytes, id uint64, hash 32 bytes hex. */
export function validateMemo(
  memoType: string | undefined,
  memo: string | undefined,
): MemoProblem[] {
  if (memoType === undefined && memo === undefined) return [];
  if (memoType === undefined) {
    return [{ code: 'memo/invalid-type', message: 'memo is present without a memo_type' }];
  }
  if (!MEMO_TYPES.has(memoType as MemoType)) {
    return [
      {
        code: 'memo/invalid-type',
        message: `memo_type "${memoType}" is not one of text, id, or hash`,
      },
    ];
  }
  if (memo === undefined) {
    return [
      { code: 'memo/missing', message: `memo_type "${memoType}" is set but memo is missing` },
    ];
  }

  switch (memoType as MemoType) {
    case 'text':
      if (new TextEncoder().encode(memo).length > 28) {
        return [{ code: 'memo/invalid-value', message: 'text memo exceeds 28 bytes' }];
      }
      return [];
    case 'id':
      if (!/^\d+$/.test(memo) || BigInt(memo) > 18446744073709551615n) {
        return [
          { code: 'memo/invalid-value', message: 'id memo must be an unsigned 64-bit integer' },
        ];
      }
      return [];
    case 'hash':
      if (!HASH_PATTERN.test(memo)) {
        return [{ code: 'memo/invalid-value', message: 'hash memo must be 32 bytes of hex' }];
      }
      return [];
  }
}

/** Accounts an anchor publishes: ACCOUNTS plus every currency issuer. */
export function collectAnchorAccounts(doc: Record<string, unknown>): string[] {
  const accounts = new Set<string>();
  if (Array.isArray(doc.ACCOUNTS)) {
    for (const account of doc.ACCOUNTS) {
      if (isString(account) && StrKey.isValidEd25519PublicKey(account)) accounts.add(account);
    }
  }
  if (Array.isArray(doc.CURRENCIES)) {
    for (const currency of doc.CURRENCIES) {
      if (!isRecord(currency) || !isString(currency.issuer)) continue;
      if (StrKey.isValidEd25519PublicKey(currency.issuer)) accounts.add(currency.issuer);
    }
  }
  return [...accounts];
}

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules?: RuleOverrides,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

export class ReverseFederationVerifier {
  private readonly fetchImpl: typeof fetch;
  private readonly options: ReverseFederationOptions;

  constructor(fetchImpl: typeof fetch = fetch, options: ReverseFederationOptions = {}) {
    this.fetchImpl = fetchImpl;
    this.options = options;
  }

  async verify(doc: Record<string, unknown>): Promise<ReverseFederationReport> {
    const server = doc.FEDERATION_SERVER;
    if (!isString(server) || !isHttpsUrl(server)) {
      return {
        ok: false,
        checks: [],
        findings: [
          {
            code: NO_SERVER_RULE,
            severity: 'error',
            message: 'FEDERATION_SERVER is missing or not an https URL',
            suggestion: 'Declare `FEDERATION_SERVER` before relying on reverse resolution.',
          },
        ],
      };
    }

    const accounts = new Set([...collectAnchorAccounts(doc), ...(this.options.accounts ?? [])]);
    const checks: ReverseCheck[] = [];
    const findings: ReverseFederationReport['findings'] = [];

    for (const accountId of accounts) {
      const check = await this.checkAccount(server, accountId);
      checks.push(check);

      if (check.schemaProblems !== undefined && check.schemaProblems.length > 0) {
        this.push(
          findings,
          INVALID_SCHEMA_RULE,
          'error',
          `Federation lookup for ${accountId} is not a valid SEP-2 record: ${check.schemaProblems.join('; ')}`,
          'Return stellar_address and account_id together in every federation record.',
        );
      }
      if (check.error !== undefined) {
        this.push(
          findings,
          UNREACHABLE_RULE,
          'error',
          `Reverse lookup for ${accountId} failed: ${check.error}`,
          'Confirm the federation server responds to type=id.',
        );
        continue;
      }
      if (check.reverse === undefined) continue;

      if (!check.consistent) {
        this.push(
          findings,
          MISMATCH_RULE,
          'error',
          check.roundTrip === undefined
            ? `Reverse lookup for ${accountId} returned ${check.reverse.stellar_address}, which does not resolve back`
            : `Reverse lookup for ${accountId} returned ${check.reverse.stellar_address}, but forward lookup names ${check.roundTrip.account_id}`,
          'Make name→account and account→name agree, or omit the reverse mapping.',
        );
      }
      if (check.memoProblems.length > 0) {
        for (const problem of check.memoProblems) {
          this.push(
            findings,
            problem.code === 'memo/missing' ? MISSING_MEMO_RULE : MEMO_RULE,
            'error',
            `${accountId} via ${check.reverse.stellar_address}: ${problem.message}`,
            'Return memo_type and memo together, following Stellar Core memo limits.',
          );
        }
      }
    }

    return { ok: findings.every((f) => f.severity !== 'error'), server, checks, findings };
  }

  private push(
    findings: ReverseFederationReport['findings'],
    code: string,
    fallback: 'error' | 'warning',
    message: string,
    suggestion: string,
  ): void {
    const severity = severityFor(code, fallback, this.options.rules);
    if (severity !== undefined) findings.push({ code, severity, message, suggestion });
  }

  private async checkAccount(server: string, accountId: string): Promise<ReverseCheck> {
    const check: ReverseCheck = { accountId, consistent: false, memoProblems: [] };

    const forward = await this.resolve(server, 'id', accountId);
    if (forward.error !== undefined) {
      check.error = forward.error;
      return check;
    }
    if (forward.record === undefined) {
      check.schemaProblems = forward.problems;
      check.error = forward.problems.join('; ') || 'no record';
      return check;
    }
    check.forward = forward.record;
    check.memoProblems = validateMemo(forward.record.memo_type, forward.record.memo);

    const reverse = await this.resolve(server, 'name', forward.record.stellar_address);
    if (reverse.error !== undefined) {
      check.error = reverse.error;
      return check;
    }
    if (reverse.record === undefined) {
      check.schemaProblems = [...(check.schemaProblems ?? []), ...reverse.problems];
      check.error = reverse.problems.join('; ') || 'no record';
      return check;
    }
    check.reverse = reverse.record;

    const roundTrip = await this.resolve(server, 'id', reverse.record.account_id);
    if (roundTrip.record !== undefined) {
      check.roundTrip = roundTrip.record;
      check.consistent =
        roundTrip.record.account_id === forward.record.account_id &&
        reverse.record.account_id === forward.record.account_id;
    }
    return check;
  }

  private async resolve(
    server: string,
    type: 'id' | 'name',
    query: string,
  ): Promise<{ record?: FederationRecord; problems: string[]; error?: string }> {
    const url = new URL(server);
    url.searchParams.set('type', type);
    url.searchParams.set('q', query);
    try {
      const response = await this.fetchImpl(url.toString(), {
        headers: { accept: 'application/json' },
      });
      if (response.status === 404) return { problems: ['not found'] };
      if (!response.ok) return { problems: [], error: `HTTP ${response.status}` };
      const body = (await response.json()) as unknown;
      if (isRecord(body) && isString(body.detail) && !('account_id' in body)) {
        return { problems: [body.detail] };
      }
      return validateFederationRecord(body);
    } catch (error) {
      return { problems: [], error: error instanceof Error ? error.message : String(error) };
    }
  }
}

/** Diagnostics for the lint pipeline (`--verify-federation-sync`). */
export async function verifyFederationSync(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: ReverseFederationOptions = {},
): Promise<{ diagnostics: Diagnostic[]; report: ReverseFederationReport }> {
  const report = await new ReverseFederationVerifier(fetchImpl, options).verify(doc);
  const diagnostics: Diagnostic[] = report.findings.map((finding) => ({
    rule: finding.code,
    severity: finding.severity,
    category: 'network',
    message: finding.message,
    path: 'FEDERATION_SERVER',
    helpUri: SPEC,
    suggestion: finding.suggestion,
  }));
  return { diagnostics, report };
}

export function renderReverseFederationReport(report: ReverseFederationReport): string {
  const lines: string[] = [];
  lines.push(`Reverse federation consistency: ${report.ok ? 'clean' : 'issues found'}`);
  if (report.server !== undefined) lines.push(`  server: ${report.server}`);
  for (const check of report.checks) {
    const address =
      check.reverse?.stellar_address ?? check.forward?.stellar_address ?? 'unresolved';
    lines.push(
      `  ${check.consistent ? 'ok  ' : 'fail'}  ${check.accountId}  <->  ${address}` +
        (check.memoProblems.length > 0 ? `  (${check.memoProblems.length} memo issue(s))` : ''),
    );
  }
  for (const finding of report.findings) {
    lines.push(`  ${finding.severity}  ${finding.code}  ${finding.message}`);
    lines.push(`         fix: ${finding.suggestion}`);
  }
  if (report.checks.length === 0) {
    lines.push('  No ACCOUNTS or currency issuers to reverse-resolve.');
  }
  return `${lines.join('\n')}\n`;
}

export const reverseFederationRules: Rule[] = [
  {
    id: NO_SERVER_RULE,
    category: 'network',
    severity: 'error',
    description: 'Reverse federation requires an https FEDERATION_SERVER',
    run() {},
  },
  {
    id: UNREACHABLE_RULE,
    category: 'network',
    severity: 'error',
    description: 'Federation lookups must complete for published anchor accounts',
    run() {},
  },
  {
    id: MISMATCH_RULE,
    category: 'network',
    severity: 'error',
    description: 'Forward and reverse federation lookups must agree',
    run() {},
  },
  {
    id: INVALID_SCHEMA_RULE,
    category: 'network',
    severity: 'error',
    description: 'Federation responses must match the SEP-2 record schema',
    run() {},
  },
  {
    id: MEMO_RULE,
    category: 'network',
    severity: 'error',
    description: 'Federation memos must follow Stellar Core text/id/hash limits',
    run() {},
  },
  {
    id: MISSING_MEMO_RULE,
    category: 'network',
    severity: 'error',
    description: 'A declared memo_type must include its memo value',
    run() {},
  },
];

export const reverseFederationRuleIds: readonly string[] = reverseFederationRules.map(
  (rule) => rule.id,
);
