/**
 * CORS wildcard and credential-exposure auditor.
 *
 * SEP-1 requires `/.well-known/stellar.toml` to answer with
 * `Access-Control-Allow-Origin: *` so any web wallet can read the file. On an
 * authenticated endpoint the same wildcard is a defect: combined with
 * `Access-Control-Allow-Credentials: true` it is rejected by every browser
 * today, and an endpoint that echoes back whatever `Origin` it was handed has
 * no whitelist at all, so any page on any site can read a logged-in user's
 * SEP-10 / SEP-12 / SEP-24 session responses.
 *
 * The auditor sends the three requests a browser would send — an `OPTIONS`
 * preflight, an actual request from a wallet origin, and an actual request from
 * an origin that could only ever appear in a whitelist by mistake — and reads
 * nothing but response headers. It never sends credentials, so it is safe to
 * point at production.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isHttpsUrl, isString } from '../predicates.js';
import { errorMessage, fetchWithTimeout } from '../protocols/verifierSupport.js';
import { specUrl } from '../spec.js';

const OWASP_CORS_URL = 'https://cheatsheetseries.owasp.org/cheatsheets/CORS_Cheat_Sheet.html';

const PUBLIC_WILDCARD_RULE = 'cors/public-endpoint-missing-wildcard';
const WILDCARD_CREDENTIALS_RULE = 'cors/wildcard-origin-with-credentials';
const ORIGIN_ECHO_RULE = 'cors/unlisted-origin-echoed';
const PREFLIGHT_RULE = 'cors/preflight-not-allowed';
const UNREACHABLE_RULE = 'cors/endpoint-unreachable';

/** A wallet origin that no anchor whitelist should ever contain. */
export const REQUESTING_ORIGIN = 'https://wallet.example.org';

/** A second unrelated origin, used to test whether the server validates `Origin`. */
export const UNLISTED_ORIGIN = 'https://cors-probe.invalid';

/** The role a CORS policy has to satisfy; SEP-1 and the SEPs differ per endpoint. */
export type CorsEndpointRole = 'public' | 'authenticated' | 'interactive';

interface CorsTarget {
  /** SEP-1 field the URL came from, reported as the diagnostic path. */
  field: string;
  url: string;
  role: CorsEndpointRole;
}

export interface CorsObservation {
  field: string;
  url: string;
  role: CorsEndpointRole;
  probe: 'preflight' | 'actual' | 'unlisted-origin';
  origin: string;
  status?: number;
  allowOrigin: string | null;
  allowMethods: string | null;
  allowCredentials: boolean;
  error?: string;
}

export interface CorsFinding {
  code: string;
  severity: 'error' | 'warning';
  message: string;
  field: string;
  url: string;
  suggestion: string;
}

export interface CorsAuditReport {
  ok: boolean;
  /** The origin the `stellar.toml` probe was served from, when one was resolvable. */
  origin?: string;
  observations: CorsObservation[];
  findings: CorsFinding[];
}

export interface CorsAuditOptions {
  rules?: RuleOverrides;
  /** Domain the file is served from; used for the public `/.well-known/stellar.toml` probe. */
  domain?: string;
  /** Per-request timeout in milliseconds. */
  timeoutMs?: number;
}

function includesToken(value: string | null, token: string): boolean {
  return (value ?? '')
    .split(',')
    .some((entry) => entry.trim().toLowerCase() === token.toLowerCase());
}

/** Resolves the effective severity for a rule, or `undefined` when it is turned off. */
function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules?: RuleOverrides,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

/**
 * The origin `/.well-known/stellar.toml` is served from.
 *
 * `--domain` wins because the operator knows the host they deployed to; the
 * file's own `ORG_URL` and then the first declared endpoint are fallbacks, so a
 * local file still gets its public CORS policy checked.
 */
function documentOrigin(
  doc: Record<string, unknown>,
  options: CorsAuditOptions,
): string | undefined {
  const candidates: unknown[] = [];
  if (options.domain !== undefined) {
    candidates.push(options.domain.includes('://') ? options.domain : `https://${options.domain}`);
  }
  const documentation = doc.DOCUMENTATION;
  if (
    typeof documentation === 'object' &&
    documentation !== null &&
    !Array.isArray(documentation)
  ) {
    candidates.push((documentation as Record<string, unknown>).ORG_URL);
  }
  for (const field of ['WEB_AUTH_ENDPOINT', 'FEDERATION_SERVER', 'ANCHOR_QUOTE_SERVER']) {
    candidates.push(doc[field]);
  }
  for (const candidate of candidates) {
    if (!isString(candidate) || !isHttpsUrl(candidate)) continue;
    try {
      return new URL(candidate).origin;
    } catch {
      // Try the next candidate.
    }
  }
  return undefined;
}

/** Every endpoint whose CORS policy SEP-1 and the anchor SEPs put under scrutiny. */
export function corsTargets(
  doc: Record<string, unknown>,
  options: CorsAuditOptions = {},
): CorsTarget[] {
  const targets: CorsTarget[] = [];
  const origin = documentOrigin(doc, options);
  if (origin !== undefined) {
    targets.push({
      field: 'DOCUMENTATION.ORG_URL',
      url: `${origin}/.well-known/stellar.toml`,
      role: 'public',
    });
  }

  // SEP-38 `/info` reads and the info file are unauthenticated by specification.
  if (isString(doc.ANCHOR_QUOTE_SERVER) && isHttpsUrl(doc.ANCHOR_QUOTE_SERVER)) {
    targets.push({ field: 'ANCHOR_QUOTE_SERVER', url: doc.ANCHOR_QUOTE_SERVER, role: 'public' });
  }

  for (const field of ['WEB_AUTH_ENDPOINT', 'KYC_SERVER', 'FEDERATION_SERVER'] as const) {
    const value = doc[field];
    if (isString(value) && isHttpsUrl(value)) {
      targets.push({ field, url: value, role: 'authenticated' });
    }
  }

  for (const field of [
    'TRANSFER_SERVER',
    'TRANSFER_SERVER_SEP0024',
    'DIRECT_PAYMENT_SERVER',
  ] as const) {
    const value = doc[field];
    if (isString(value) && isHttpsUrl(value)) {
      targets.push({ field, url: value, role: 'interactive' });
    }
  }

  if (Array.isArray(doc.CURRENCIES)) {
    doc.CURRENCIES.forEach((entry, index) => {
      if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) return;
      const approvalServer = (entry as Record<string, unknown>).approval_server;
      if (isString(approvalServer) && isHttpsUrl(approvalServer)) {
        targets.push({
          field: `CURRENCIES[${index}].approval_server`,
          url: approvalServer,
          role: 'interactive',
        });
      }
    });
  }

  return targets;
}

export class CorsSecurityAuditor {
  private readonly fetchImpl: typeof fetch;
  private readonly options: CorsAuditOptions;

  constructor(fetchImpl: typeof fetch = fetch, options: CorsAuditOptions = {}) {
    this.fetchImpl = fetchImpl;
    this.options = options;
  }

  /** Runs the three browser-shaped requests against every declared endpoint. */
  async audit(doc: Record<string, unknown>): Promise<CorsAuditReport> {
    const observations: CorsObservation[] = [];
    const findings: CorsFinding[] = [];
    const origin = documentOrigin(doc, this.options);

    for (const target of corsTargets(doc, this.options)) {
      const probed: CorsObservation[] = [
        await this.request(target, 'preflight', REQUESTING_ORIGIN, {
          method: 'OPTIONS',
          headers: {
            Origin: REQUESTING_ORIGIN,
            'Access-Control-Request-Method': 'POST',
            'Access-Control-Request-Headers': 'authorization, content-type',
          },
        }),
        await this.request(target, 'actual', REQUESTING_ORIGIN, {
          headers: { Origin: REQUESTING_ORIGIN },
        }),
        await this.request(target, 'unlisted-origin', UNLISTED_ORIGIN, {
          headers: { Origin: UNLISTED_ORIGIN },
        }),
      ];
      observations.push(...probed);
      findings.push(...this.inspect(target, probed));
    }

    return {
      ok: findings.every((finding) => finding.severity !== 'error'),
      ...(origin === undefined ? {} : { origin }),
      observations,
      findings,
    };
  }

  private async request(
    target: CorsTarget,
    probe: CorsObservation['probe'],
    origin: string,
    init: RequestInit,
  ): Promise<CorsObservation> {
    const base: Omit<
      CorsObservation,
      'status' | 'allowOrigin' | 'allowMethods' | 'allowCredentials'
    > = {
      field: target.field,
      url: target.url,
      role: target.role,
      probe,
      origin,
    };
    try {
      const response = await fetchWithTimeout(
        this.fetchImpl,
        target.url,
        init,
        this.options.timeoutMs,
      );
      return {
        ...base,
        status: response.status,
        allowOrigin: response.headers.get('access-control-allow-origin'),
        allowMethods: response.headers.get('access-control-allow-methods'),
        allowCredentials:
          response.headers.get('access-control-allow-credentials')?.trim().toLowerCase() === 'true',
      };
    } catch (error) {
      return {
        ...base,
        allowOrigin: null,
        allowMethods: null,
        allowCredentials: false,
        error: errorMessage(error),
      };
    }
  }

  private inspect(target: CorsTarget, probed: CorsObservation[]): CorsFinding[] {
    const findings: CorsFinding[] = [];
    const emit = (
      code: string,
      fallback: 'error' | 'warning',
      message: string,
      suggestion: string,
    ) => {
      const severity = severityFor(code, fallback, this.options.rules);
      if (severity === undefined) return;
      findings.push({ code, severity, message, field: target.field, url: target.url, suggestion });
    };

    const unreachable = probed.filter((observation) => observation.error !== undefined);
    if (unreachable.length === probed.length) {
      emit(
        UNREACHABLE_RULE,
        'warning',
        `${target.field} could not be probed for CORS policy: ${unreachable[0]?.error}`,
        'Confirm the endpoint is reachable over https; the auditor cannot read headers from a host it cannot connect to.',
      );
      return findings;
    }

    const preflight = probed.find((observation) => observation.probe === 'preflight');
    const actual = probed.find((observation) => observation.probe === 'actual');
    const echoed = probed.find((observation) => observation.probe === 'unlisted-origin');

    if (
      preflight !== undefined &&
      preflight.error === undefined &&
      (preflight.allowOrigin === null ||
        (preflight.allowOrigin !== '*' && preflight.allowOrigin !== REQUESTING_ORIGIN) ||
        !['GET', 'POST', 'OPTIONS'].every((method) =>
          includesToken(preflight.allowMethods, method),
        ))
    ) {
      emit(
        PREFLIGHT_RULE,
        'warning',
        `${target.field} did not answer the OPTIONS pre-flight with a matching origin and GET, POST, OPTIONS methods${
          preflight.status === undefined ? '' : ` (HTTP ${preflight.status})`
        }`,
        'Respond to OPTIONS with Access-Control-Allow-Origin, -Methods and -Headers before the wallet sends the real request.',
      );
    }

    if (target.role === 'public' && actual !== undefined && actual.error === undefined) {
      if (actual.allowOrigin !== '*') {
        emit(
          PUBLIC_WILDCARD_RULE,
          'error',
          `${target.field} is a public endpoint but served Access-Control-Allow-Origin: ${
            actual.allowOrigin ?? '(absent)'
          } instead of *`,
          'SEP-1 requires the stellar.toml and SEP-38 quote reads to allow every origin so any wallet can fetch them.',
        );
      }
    }

    if (target.role !== 'public' && actual !== undefined && actual.error === undefined) {
      if (actual.allowOrigin === '*' && actual.allowCredentials) {
        emit(
          WILDCARD_CREDENTIALS_RULE,
          'error',
          `${target.field} combines Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true`,
          'A wildcard origin must never be paired with credentials — pick the wallet origins that may send cookies and list them.',
        );
      }
    }

    if (
      target.role !== 'public' &&
      echoed !== undefined &&
      echoed.error === undefined &&
      echoed.allowOrigin === UNLISTED_ORIGIN
    ) {
      emit(
        ORIGIN_ECHO_RULE,
        'error',
        `${target.field} echoed the unlisted origin ${UNLISTED_ORIGIN}${
          echoed.allowCredentials ? ' with Access-Control-Allow-Credentials: true' : ''
        }, so it accepts any Origin header without checking a whitelist`,
        'Validate Origin against an explicit list of wallet partners and refuse the header when it is not on the list.',
      );
    }

    return findings;
  }
}

/** Diagnostics for the lint pipeline, so `--audit-cors` reports like the other audits. */
export async function auditCors(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: CorsAuditOptions = {},
): Promise<{ diagnostics: Diagnostic[]; report: CorsAuditReport }> {
  const report = await new CorsSecurityAuditor(fetchImpl, options).audit(doc);
  const diagnostics: Diagnostic[] = report.findings.map((finding) => ({
    rule: finding.code,
    severity: finding.severity,
    category: 'network',
    message: finding.message,
    path: finding.field,
    helpUri:
      finding.code === PUBLIC_WILDCARD_RULE ? specUrl('general-information') : OWASP_CORS_URL,
    suggestion: finding.suggestion,
  }));
  return { diagnostics, report };
}

export function renderCorsReport(report: CorsAuditReport): string {
  const lines: string[] = [];
  lines.push(`CORS policy audit: ${report.ok ? 'clean' : 'issues found'}`);
  if (report.origin !== undefined) lines.push(`  served from: ${report.origin}`);
  lines.push(`  probes: ${report.observations.length}`);
  for (const observation of report.observations) {
    const headers =
      observation.error !== undefined
        ? `unreachable: ${observation.error}`
        : `ACAO=${observation.allowOrigin ?? '(absent)'} credentials=${
            observation.allowCredentials ? 'true' : 'false'
          } status=${observation.status ?? '-'}`;
    lines.push(`  ${observation.field} [${observation.probe}/${observation.role}]  ${headers}`);
  }
  for (const finding of report.findings) {
    lines.push(`  ${finding.severity}  ${finding.code}  ${finding.message}`);
    lines.push(`         fix: ${finding.suggestion}`);
  }
  if (report.findings.length === 0) {
    lines.push('  Every probed endpoint kept its CORS policy within OWASP guidance.');
  }
  return `${lines.join('\n')}\n`;
}

/** Registered so `--list-rules`, completions and `--off`/`--warn`/`--error` know these ids. */
export const corsSecurityRules: Rule[] = [
  {
    id: PUBLIC_WILDCARD_RULE,
    category: 'network',
    severity: 'error',
    description: 'Public stellar.toml and SEP-38 reads must allow every origin',
    run() {},
  },
  {
    id: WILDCARD_CREDENTIALS_RULE,
    category: 'network',
    severity: 'error',
    description:
      'Authenticated endpoints must not pair a wildcard CORS origin with credentialed requests',
    run() {},
  },
  {
    id: ORIGIN_ECHO_RULE,
    category: 'network',
    severity: 'error',
    description: 'CORS endpoints must validate Origin against a whitelist instead of echoing it',
    run() {},
  },
  {
    id: PREFLIGHT_RULE,
    category: 'network',
    severity: 'warning',
    description: 'Endpoints must answer the OPTIONS pre-flight with matching origin and methods',
    run() {},
  },
  {
    id: UNREACHABLE_RULE,
    category: 'network',
    severity: 'warning',
    description: 'CORS audit could not reach a declared endpoint over https',
    run() {},
  },
];

export const corsSecurityRuleIds: readonly string[] = corsSecurityRules.map((rule) => rule.id);
