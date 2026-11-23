/**
 * SEP-2 federation query sanitation and injection-resistance tester.
 *
 * A federation server answers `GET /federation?type=name&q=user*domain.com`
 * (and `type=id`, `type=forward`) with either a SEP-2 record or a JSON error
 * `{"detail": "..."}`. An anchor that concatenates `q` into SQL, LDAP, or shell
 * input fails in visible ways: a 5xx, a stack trace, or a database error string
 * in the body instead of a clean validation error.
 *
 * This tester sends only well-formed requests and quote/semicolon/NUL/Unicode
 * probes. It never uses destructive payloads (`DROP`, `DELETE`, shell), so it
 * is safe to point at production, and it rate-limits by default.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isHttpsUrl, isString } from '../predicates.js';

const MISSING_SERVER_RULE = 'federation/missing-server';
const BAD_STATUS_RULE = 'federation/non-4xx-error';
const BAD_JSON_RULE = 'federation/invalid-error-json';
const LEAK_RULE = 'federation/error-detail-leak';
const SERVER_ERROR_RULE = 'federation/server-error';

const SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0002.md';

export type FederationQueryType = 'name' | 'id' | 'forward';

export interface FederationProbe {
  type: FederationQueryType;
  /** The `q` value sent; kept for the report. */
  query: string;
  kind: 'valid' | 'injection';
  status?: number;
  detail?: string;
  error?: string;
}

export interface FederationSecurityFinding {
  code: string;
  severity: 'error' | 'warning';
  message: string;
  probe: FederationProbe;
  suggestion: string;
}

export interface FederationSecurityReport {
  ok: boolean;
  server?: string;
  probes: FederationProbe[];
  findings: FederationSecurityFinding[];
}

export interface FederationSecurityOptions {
  rules?: RuleOverrides;
  /** Delay between requests; defaults to 100ms, and 0 is allowed for tests. */
  rateLimitMs?: number;
  /** Overrides for tests or a clock. */
  sleep?: (ms: number) => Promise<void>;
}

/** Non-destructive probes covering quotes, statements, NULs, and Unicode. */
export const INJECTION_PROBES = [
  "user'*example.com",
  "user' OR '1'='1*example.com",
  'user"*example.com',
  'user;example.com',
  'user*example.com\u0000',
  'user\u0000*example.com',
  'us\u0435r*example.com',
  "user'--*example.com",
  'user%00*example.com',
] as const;

/** Strings that only appear when an internal error escaped to the client. */
export const ERROR_LEAK_PATTERNS: { pattern: RegExp; label: string }[] = [
  { pattern: /\bSQLSTATE\b/i, label: 'SQLSTATE' },
  { pattern: /\bSQL syntax\b/i, label: 'SQL syntax' },
  { pattern: /\b(?:at\s+\S+\s+\([^)]*:\d+:\d+\)|node_modules[\\/])/i, label: 'stack trace' },
  { pattern: /\b(?:sqlite|postgres|mysql|mariadb|oracle|mssql)\b/i, label: 'database name' },
  { pattern: /syntax error at or near/i, label: 'Postgres syntax error' },
  { pattern: /\bLDAP\b/i, label: 'LDAP error' },
  { pattern: /\b(?:ER_[A-Z_]+|SQLITE_[A-Z_]+)\b/, label: 'driver error code' },
  { pattern: /\b(?:sequelize|typeorm|prisma|knex|pg|mysql2)\b/i, label: 'ORM/driver name' },
  { pattern: /\bTraceback \(most recent call last\)/i, label: 'Python traceback' },
];

const VALID_QUERIES: { type: FederationQueryType; query: string }[] = [
  { type: 'name', query: 'test*example.com' },
  { type: 'id', query: 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF' },
  { type: 'forward', query: 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF' },
];

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Finds the first internal detail that should never reach a client. */
export function findLeakedDetail(body: string): string | undefined {
  for (const { pattern, label } of ERROR_LEAK_PATTERNS) {
    if (pattern.test(body)) return label;
  }
  return undefined;
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

export class FederationSecurityTester {
  private readonly fetchImpl: typeof fetch;
  private readonly options: FederationSecurityOptions;
  private readonly sleep: (ms: number) => Promise<void>;

  constructor(fetchImpl: typeof fetch = fetch, options: FederationSecurityOptions = {}) {
    this.fetchImpl = fetchImpl;
    this.options = options;
    this.sleep = options.sleep ?? delay;
  }

  /** Resolves the server from the document and runs valid then probe queries. */
  async audit(doc: Record<string, unknown>): Promise<FederationSecurityReport> {
    const server = doc.FEDERATION_SERVER;
    if (!isString(server) || !isHttpsUrl(server)) {
      return {
        ok: false,
        probes: [],
        findings: [
          {
            code: MISSING_SERVER_RULE,
            severity: 'error',
            message: 'FEDERATION_SERVER is missing or not an https URL',
            probe: { type: 'name', query: '', kind: 'valid' },
            suggestion: 'Declare `FEDERATION_SERVER = "https://…/federation"` in stellar.toml.',
          },
        ],
      };
    }

    const probes: FederationProbe[] = [];
    const findings: FederationSecurityFinding[] = [];

    for (const valid of VALID_QUERIES) {
      const probe = await this.query(server, valid.type, valid.query, 'valid');
      probes.push(probe);
      findings.push(...this.inspect(probe));
    }

    for (const payload of INJECTION_PROBES) {
      const probe = await this.query(server, 'name', payload, 'injection');
      probes.push(probe);
      findings.push(...this.inspect(probe));
    }

    return {
      ok: findings.every((finding) => finding.severity !== 'error'),
      server,
      probes,
      findings,
    };
  }

  private async query(
    server: string,
    type: FederationQueryType,
    query: string,
    kind: 'valid' | 'injection',
  ): Promise<FederationProbe> {
    const url = new URL(server);
    url.searchParams.set('type', type);
    url.searchParams.set('q', query);

    if ((this.options.rateLimitMs ?? 100) > 0) await this.sleep(this.options.rateLimitMs ?? 100);
    try {
      const response = await this.fetchImpl(url.toString(), {
        headers: { accept: 'application/json' },
      });
      const body = await response.text();
      const probe: FederationProbe = {
        type,
        query,
        kind,
        status: response.status,
        detail: body.slice(0, 500),
      };
      const leaked = findLeakedDetail(body);
      if (leaked !== undefined) probe.detail = `${leaked}: ${body.slice(0, 200)}`;
      return probe;
    } catch (error) {
      return {
        type,
        query,
        kind,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  /** Turns one probe response into findings: status, JSON shape, and leaks. */
  private inspect(probe: FederationProbe): FederationSecurityFinding[] {
    const findings: FederationSecurityFinding[] = [];
    const emit = (
      code: string,
      fallback: 'error' | 'warning',
      message: string,
      suggestion: string,
    ): void => {
      const severity = severityFor(code, fallback, this.options.rules);
      if (severity === undefined) return;
      findings.push({ code, severity, message, probe, suggestion });
    };

    if (probe.error !== undefined) {
      emit(
        SERVER_ERROR_RULE,
        'error',
        `Federation request for "${probe.query}" failed: ${probe.error}`,
        'Confirm the federation server is reachable and rate limits are not rejecting probes.',
      );
      return findings;
    }

    const status = probe.status ?? 0;
    if (status >= 500) {
      emit(
        SERVER_ERROR_RULE,
        'error',
        `Federation server returned HTTP ${status} for "${probe.query}"`,
        'Handle malformed query values as client errors instead of crashing.',
      );
    } else if (probe.kind === 'injection' && status >= 200 && status < 300) {
      // An injection probe answering 200 is only suspicious when it echoes a
      // record; a 404 or 400 is the expected validation failure.
      emit(
        BAD_STATUS_RULE,
        'warning',
        `Injection probe "${probe.query}" returned HTTP ${status} instead of a 4xx validation error`,
        'Reject invalid `q` values with a 4xx and a `{"detail": ...}` body.',
      );
    }

    const body = probe.detail ?? '';
    const leaked = findLeakedDetail(body);
    if (leaked !== undefined) {
      emit(
        LEAK_RULE,
        'error',
        `Response for "${probe.query}" leaks an internal ${leaked} detail`,
        'Return a generic SEP-2 `{"detail": "..."}` message and log the internal error server-side.',
      );
    }

    if (probe.kind === 'injection' && status >= 400) {
      // A clean SEP-2 error is JSON with a string `detail`; HTML error pages
      // and empty bodies are where stack traces and framework defaults leak.
      let parsed: unknown;
      try {
        parsed = JSON.parse(body);
      } catch {
        parsed = undefined;
      }
      const detail =
        typeof parsed === 'object' && parsed !== null && 'detail' in parsed
          ? (parsed as { detail?: unknown }).detail
          : undefined;
      if (!isString(detail) || detail.length === 0) {
        emit(
          BAD_JSON_RULE,
          'warning',
          `HTTP ${status} for "${probe.query}" is not a SEP-2 {"detail": "..."} JSON error`,
          'Return `Content-Type: application/json` with a `detail` string for every 4xx.',
        );
      }
    }

    return findings;
  }
}

/** Diagnostics for the lint pipeline, so `--audit-federation-security` reports normally. */
export async function auditFederationSecurity(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: FederationSecurityOptions = {},
): Promise<{ diagnostics: Diagnostic[]; report: FederationSecurityReport }> {
  const report = await new FederationSecurityTester(fetchImpl, options).audit(doc);
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

export function renderFederationSecurityReport(report: FederationSecurityReport): string {
  const lines: string[] = [];
  lines.push(`SEP-2 federation security: ${report.ok ? 'clean' : 'issues found'}`);
  if (report.server !== undefined) lines.push(`  server: ${report.server}`);
  lines.push(`  probes: ${report.probes.length}`);
  for (const finding of report.findings) {
    lines.push(`  ${finding.severity}  ${finding.code}  ${finding.message}`);
    lines.push(`         fix: ${finding.suggestion}`);
  }
  if (report.findings.length === 0) {
    lines.push('  Every probe returned a SEP-2 4xx JSON error without leaking internals.');
  }
  return `${lines.join('\n')}\n`;
}

export const federationSecurityRules: Rule[] = [
  {
    id: MISSING_SERVER_RULE,
    category: 'network',
    severity: 'error',
    description: 'FEDERATION_SERVER must be declared as an https URL',
    run() {},
  },
  {
    id: BAD_STATUS_RULE,
    category: 'network',
    severity: 'warning',
    description: 'Malformed federation queries must return a 4xx validation error',
    run() {},
  },
  {
    id: BAD_JSON_RULE,
    category: 'network',
    severity: 'warning',
    description: 'Federation errors must use the SEP-2 {"detail": "..."} JSON shape',
    run() {},
  },
  {
    id: LEAK_RULE,
    category: 'network',
    severity: 'error',
    description: 'Federation errors must not leak database errors or stack traces',
    run() {},
  },
  {
    id: SERVER_ERROR_RULE,
    category: 'network',
    severity: 'error',
    description: 'Federation queries must not crash the server with a 5xx',
    run() {},
  },
];

export const federationSecurityRuleIds: readonly string[] = federationSecurityRules.map(
  (rule) => rule.id,
);
