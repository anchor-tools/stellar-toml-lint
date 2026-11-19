/**
 * HTTP error taxonomy and RFC 7807 Problem Details verifier.
 *
 * Wallets can only show a user how to recover from a failed request when the
 * anchor answers with machine-readable errors: either RFC 7807 Problem Details
 * (`application/problem+json` with `type`, `title`, `status`, `detail`,
 * `instance`) or the SEP error shape `{"error": "..."}`. HTML error pages,
 * plain strings and — worst of all — stack traces or credentials leaking into
 * the body are reported.
 *
 * `Rfc7807ErrorValidator` sends deliberately invalid, read-only `GET`
 * requests (missing parameters, bogus account ids, malformed asset codes,
 * unknown ids and paths) to every declared SEP endpoint. Every probe is
 * constructed so that no compliant server could act on it: nothing is
 * created, updated or deleted.
 */
import { StrKey } from '@stellar/stellar-base';

/** Standardized classification of an error response. */
export type ErrorCategory =
  | 'client-input'
  | 'authentication'
  | 'authorization'
  | 'not-found'
  | 'conflict'
  | 'rate-limited'
  | 'server'
  | 'unexpected-success'
  | 'other';

/** How the body was shaped. */
export type ErrorFormat =
  'rfc7807' | 'sep-error' | 'json-unstructured' | 'html' | 'plain-text' | 'empty';

export type LeakKind =
  | 'stellar-secret-seed'
  | 'private-key'
  | 'database-credentials'
  | 'cloud-credentials'
  | 'stack-trace'
  | 'sql-error'
  | 'internal-path'
  | 'debug-page';

export interface Leak {
  kind: LeakKind;
  severity: 'error' | 'warning';
  /** Redacted excerpt of what matched. */
  excerpt: string;
}

export interface ErrorFinding {
  code: string;
  severity: 'error' | 'warning';
  message: string;
}

export interface ErrorResponse {
  status: number;
  contentType: string;
  body: string;
}

export interface ErrorClassification {
  status: number;
  category: ErrorCategory;
  format: ErrorFormat;
  findings: ErrorFinding[];
  leaks: Leak[];
}

export interface ErrorProbe {
  field: string;
  description: string;
  path: string;
}

export interface ErrorProbeResult extends ErrorProbe {
  url: string;
  classification?: ErrorClassification;
  error?: string;
}

export interface ErrorTaxonomyReport {
  ok: boolean;
  results: ErrorProbeResult[];
  /** Count of responses per category. */
  categories: Partial<Record<ErrorCategory, number>>;
  criticalLeaks: number;
}

/** Maps an HTTP status to the taxonomy. */
export function categorizeStatus(status: number): ErrorCategory {
  if (status >= 200 && status < 400) return 'unexpected-success';
  if (status === 400 || status === 422) return 'client-input';
  if (status === 401) return 'authentication';
  if (status === 403) return 'authorization';
  if (status === 404 || status === 410) return 'not-found';
  if (status === 409) return 'conflict';
  if (status === 429) return 'rate-limited';
  if (status >= 500 && status < 600) return 'server';
  return 'other';
}

interface LeakPattern {
  kind: LeakKind;
  severity: 'error' | 'warning';
  pattern: RegExp;
  /** Optional extra check to cut false positives. */
  confirm?: (match: string) => boolean;
}

const LEAK_PATTERNS: readonly LeakPattern[] = [
  {
    kind: 'stellar-secret-seed',
    severity: 'error',
    pattern: /\bS[A-Z2-7]{55}\b/g,
    confirm: (m) => StrKey.isValidEd25519SecretSeed(m),
  },
  {
    kind: 'private-key',
    severity: 'error',
    pattern: /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----/g,
  },
  {
    kind: 'database-credentials',
    severity: 'error',
    pattern:
      /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|mssql):\/\/[^\s:@/"']+:[^\s@/"']+@[^\s"']+/gi,
  },
  {
    kind: 'cloud-credentials',
    severity: 'error',
    pattern:
      /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\baws_secret_access_key\b|\bxox[bap]-[0-9A-Za-z-]{10,}/g,
  },
  {
    kind: 'stack-trace',
    severity: 'error',
    pattern:
      /\n\s+at [\w$.<>]+ \(?[^\s)]+:\d+:\d+\)?|Traceback \(most recent call last\)|\bat [\w$.]+\([\w]+\.java:\d+\)|Exception in thread "|panic: .*\n\s*goroutine \d+|\.rb:\d+:in `/g,
  },
  {
    kind: 'sql-error',
    severity: 'warning',
    pattern:
      /\bSQLSTATE\[|syntax error at or near|\bORA-\d{5}\b|You have an error in your SQL syntax|\bduplicate key value violates\b/gi,
  },
  {
    kind: 'internal-path',
    severity: 'warning',
    pattern:
      /(?:\/home\/[\w.-]+|\/var\/www|\/usr\/src\/app|\/opt\/[\w.-]+\/|[A-Z]:\\(?:Users|inetpub)\\)[^\s"'<]*/g,
  },
  {
    kind: 'debug-page',
    severity: 'error',
    pattern:
      /Werkzeug Debugger|DEBUG = True|Whoops! There was an error|<title>Action Controller: Exception caught<\/title>|Laravel\s+\|\s+Ignition/gi,
  },
];

function redact(text: string): string {
  const flat = text.replace(/\s+/g, ' ').trim();
  if (flat.length <= 12) return `${flat.slice(0, 2)}…`;
  return `${flat.slice(0, 8)}…${flat.slice(-4)}`;
}

/** Scans `body` for leaked secrets, credentials and internal details. */
export function detectLeaks(body: string): Leak[] {
  const leaks: Leak[] = [];
  const seen = new Set<string>();
  for (const { kind, severity, pattern, confirm } of LEAK_PATTERNS) {
    pattern.lastIndex = 0;
    for (const match of body.matchAll(pattern)) {
      const text = match[0];
      if (confirm !== undefined && !confirm(text)) continue;
      const key = `${kind}:${text}`;
      if (seen.has(key)) continue;
      seen.add(key);
      leaks.push({ kind, severity, excerpt: redact(text) });
    }
  }
  return leaks;
}

function mediaType(contentType: string): string {
  return (contentType.split(';')[0] ?? '').trim().toLowerCase();
}

/** Classifies one error response and validates its body. */
export function classifyErrorResponse(response: ErrorResponse): ErrorClassification {
  const { status, body } = response;
  const type = mediaType(response.contentType);
  const findings: ErrorFinding[] = [];
  const category = categorizeStatus(status);
  let format: ErrorFormat;

  let json: unknown;
  let jsonOk = false;
  if (body.trim() !== '') {
    try {
      json = JSON.parse(body);
      jsonOk = true;
    } catch {
      jsonOk = false;
    }
  }

  if (body.trim() === '') {
    format = 'empty';
  } else if (jsonOk && json !== null && typeof json === 'object' && !Array.isArray(json)) {
    const obj = json as Record<string, unknown>;
    const problemKeys = ['type', 'title', 'status', 'detail', 'instance'];
    const looksLikeProblem =
      type === 'application/problem+json' || problemKeys.filter((k) => k in obj).length >= 2;
    if (looksLikeProblem) {
      format = 'rfc7807';
      validateProblem(obj, status, type, findings);
    } else if (typeof obj.error === 'string') {
      format = 'sep-error';
      if (obj.error.trim() === '') {
        findings.push({
          code: 'errors/empty-error-message',
          severity: 'warning',
          message: 'SEP error body has an empty "error" string',
        });
      }
    } else {
      format = 'json-unstructured';
      findings.push({
        code: 'errors/unstructured-json',
        severity: 'warning',
        message:
          'JSON error body is neither RFC 7807 Problem Details nor a SEP {"error": "..."} object',
      });
    }
    if (
      type !== 'application/json' &&
      type !== 'application/problem+json' &&
      !type.endsWith('+json')
    ) {
      findings.push({
        code: 'errors/wrong-content-type',
        severity: 'warning',
        message: `JSON error body is served as "${type || '(none)'}" instead of application/problem+json or application/json`,
      });
    }
  } else if (type === 'text/html' || /^\s*<(!doctype|html)/i.test(body)) {
    format = 'html';
    findings.push({
      code: 'errors/html-error-page',
      severity: 'error',
      message: 'Error is an HTML page; wallets cannot parse it',
    });
  } else {
    format = 'plain-text';
    findings.push({
      code: 'errors/plain-text-error',
      severity: 'error',
      message: 'Error is a plain-text string instead of JSON',
    });
  }

  if (format === 'empty' && status >= 400) {
    findings.push({
      code: 'errors/empty-body',
      severity: 'warning',
      message: `HTTP ${status} carries no body, so wallets get no explanation`,
    });
  }
  if (category === 'unexpected-success') {
    findings.push({
      code: 'errors/accepted-invalid-request',
      severity: 'warning',
      message: `Invalid request was answered with HTTP ${status} instead of a 4xx error`,
    });
  }
  if (category === 'server') {
    findings.push({
      code: 'errors/server-error-on-invalid-input',
      severity: 'warning',
      message: `Invalid input caused HTTP ${status}; input validation should reject it with a 4xx`,
    });
  }

  const leaks = detectLeaks(body);
  for (const leak of leaks) {
    findings.push({
      code: `errors/leak-${leak.kind}`,
      severity: leak.severity,
      message:
        leak.severity === 'error'
          ? `CRITICAL: error response exposes ${leak.kind.replace(/-/g, ' ')} (${leak.excerpt})`
          : `Error response exposes ${leak.kind.replace(/-/g, ' ')} (${leak.excerpt})`,
    });
  }

  return { status, category, format, findings, leaks };
}

function validateProblem(
  obj: Record<string, unknown>,
  status: number,
  type: string,
  findings: ErrorFinding[],
): void {
  if (type !== 'application/problem+json') {
    findings.push({
      code: 'errors/problem-content-type',
      severity: 'warning',
      message: `Problem Details should be served as application/problem+json, not "${type || '(none)'}"`,
    });
  }
  for (const key of ['type', 'title', 'detail', 'instance'] as const) {
    if (key in obj && typeof obj[key] !== 'string') {
      findings.push({
        code: 'errors/problem-invalid-member',
        severity: 'error',
        message: `Problem Details member "${key}" must be a string`,
      });
    }
  }
  if ('type' in obj && typeof obj.type === 'string') {
    try {
      new URL(obj.type, 'https://placeholder.invalid/');
    } catch {
      findings.push({
        code: 'errors/problem-invalid-type-uri',
        severity: 'error',
        message: `Problem Details "type" is not a URI reference: ${obj.type}`,
      });
    }
  }
  if ('status' in obj) {
    if (typeof obj.status !== 'number' || !Number.isInteger(obj.status)) {
      findings.push({
        code: 'errors/problem-invalid-member',
        severity: 'error',
        message: 'Problem Details member "status" must be an integer',
      });
    } else if (obj.status !== status) {
      findings.push({
        code: 'errors/problem-status-mismatch',
        severity: 'warning',
        message: `Problem Details "status" ${obj.status} does not match HTTP status ${status}`,
      });
    }
  }
  if (typeof obj.title !== 'string' || obj.title.trim() === '') {
    findings.push({
      code: 'errors/problem-missing-title',
      severity: 'warning',
      message: 'Problem Details should carry a human-readable "title"',
    });
  }
  if (typeof obj.detail !== 'string' || obj.detail.trim() === '') {
    findings.push({
      code: 'errors/problem-missing-detail',
      severity: 'warning',
      message: 'Problem Details should carry a human-readable "detail"',
    });
  }
}

const BOGUS_ACCOUNT = 'GNOTAVALIDSTELLARACCOUNT';
const BOGUS_ASSET = '%24%24INVALID-ASSET-CODE%24%24';
const BOGUS_ID = '00000000-0000-0000-0000-stellartomllint';

/** Read-only edge-case probes per SEP field. */
export const ERROR_PROBES: Readonly<Record<string, readonly Omit<ErrorProbe, 'field'>[]>> = {
  TRANSFER_SERVER: [
    { description: 'deposit with missing parameters', path: '/deposit' },
    {
      description: 'deposit with invalid account and asset code',
      path: `/deposit?asset_code=${BOGUS_ASSET}&account=${BOGUS_ACCOUNT}`,
    },
    { description: 'unknown transaction id', path: `/transaction?id=${BOGUS_ID}` },
    { description: 'unknown route', path: '/stellar-toml-lint-nonexistent-route' },
  ],
  TRANSFER_SERVER_SEP0024: [
    { description: 'unknown transaction id', path: `/transaction?id=${BOGUS_ID}` },
    {
      description: 'transactions with malformed asset code',
      path: `/transactions?asset_code=${BOGUS_ASSET}`,
    },
    { description: 'unknown route', path: '/stellar-toml-lint-nonexistent-route' },
  ],
  DIRECT_PAYMENT_SERVER: [
    { description: 'unknown transaction id', path: `/transactions/${BOGUS_ID}` },
    { description: 'unknown route', path: '/stellar-toml-lint-nonexistent-route' },
  ],
  ANCHOR_QUOTE_SERVER: [
    { description: 'prices with missing parameters', path: '/prices' },
    {
      description: 'price with malformed asset',
      path: `/price?sell_asset=${BOGUS_ASSET}&buy_asset=${BOGUS_ASSET}&sell_amount=-1&context=sep6`,
    },
  ],
  KYC_SERVER: [
    { description: 'customer with invalid account', path: `/customer?account=${BOGUS_ACCOUNT}` },
  ],
  WEB_AUTH_ENDPOINT: [
    { description: 'challenge for invalid account', path: `?account=${BOGUS_ACCOUNT}` },
  ],
};

export function buildErrorProbes(doc: Record<string, unknown>): (ErrorProbe & { url: string })[] {
  const out: (ErrorProbe & { url: string })[] = [];
  for (const [field, probes] of Object.entries(ERROR_PROBES)) {
    const base = doc[field];
    if (typeof base !== 'string' || !/^https?:\/\//i.test(base)) continue;
    const trimmed = base.replace(/\/+$/, '');
    for (const probe of probes) out.push({ field, ...probe, url: `${trimmed}${probe.path}` });
  }
  return out;
}

export interface Rfc7807ErrorValidatorOptions {
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  /** Bodies are truncated to this many bytes before analysis. */
  maxBodyBytes?: number;
}

export class Rfc7807ErrorValidator {
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;
  private readonly maxBodyBytes: number;

  constructor(options: Rfc7807ErrorValidatorOptions = {}) {
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.maxBodyBytes = options.maxBodyBytes ?? 256 * 1024;
  }

  /** Runs every probe for the endpoints declared in a parsed `stellar.toml`. */
  async audit(doc: Record<string, unknown>): Promise<ErrorTaxonomyReport> {
    const results: ErrorProbeResult[] = [];
    for (const probe of buildErrorProbes(doc)) results.push(await this.run(probe));
    return summarizeTaxonomy(results);
  }

  /** Sends one probe. Never rejects. */
  async run(probe: ErrorProbe & { url: string }): Promise<ErrorProbeResult> {
    try {
      const response = await this.fetchImpl(probe.url, {
        method: 'GET',
        redirect: 'manual',
        headers: { accept: 'application/problem+json, application/json;q=0.9, */*;q=0.1' },
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      const text = await response.text();
      const body = text.length > this.maxBodyBytes ? text.slice(0, this.maxBodyBytes) : text;
      return {
        ...probe,
        classification: classifyErrorResponse({
          status: response.status,
          contentType: response.headers.get('content-type') ?? '',
          body,
        }),
      };
    } catch (error) {
      return { ...probe, error: error instanceof Error ? error.message : String(error) };
    }
  }
}

export function summarizeTaxonomy(results: ErrorProbeResult[]): ErrorTaxonomyReport {
  const categories: Partial<Record<ErrorCategory, number>> = {};
  let criticalLeaks = 0;
  let ok = true;
  for (const result of results) {
    const c = result.classification;
    if (c === undefined) continue;
    categories[c.category] = (categories[c.category] ?? 0) + 1;
    criticalLeaks += c.leaks.filter((l) => l.severity === 'error').length;
    if (c.findings.some((f) => f.severity === 'error')) ok = false;
  }
  return { ok, results, categories, criticalLeaks };
}

export function renderErrorTaxonomyReport(report: ErrorTaxonomyReport): string {
  const out: string[] = ['HTTP error taxonomy audit (RFC 7807 / SEP error schema)'];
  if (report.results.length === 0) {
    out.push('No SEP endpoints declared to probe.');
    return `${out.join('\n')}\n`;
  }
  for (const result of report.results) {
    out.push('');
    out.push(`${result.field} — ${result.description}`);
    out.push(`  GET ${result.url}`);
    if (result.error !== undefined) {
      out.push(`  ! unreachable: ${result.error}`);
      continue;
    }
    const c = result.classification as ErrorClassification;
    out.push(`  HTTP ${c.status} · ${c.category} · ${c.format}`);
    for (const f of c.findings) out.push(`  ${f.severity === 'error' ? '✗' : '!'} ${f.message}`);
    if (c.findings.length === 0) out.push('  ✓ compliant');
  }
  out.push('');
  const cats = Object.entries(report.categories)
    .map(([k, v]) => `${k}: ${v}`)
    .join(', ');
  out.push(`Categories: ${cats || 'none'}`);
  if (report.criticalLeaks > 0) {
    out.push(`✗ ${report.criticalLeaks} critical information leak(s) in error responses`);
  }
  out.push(report.ok ? '✓ Error handling is machine-readable' : '✗ Error handling issues found');
  return `${out.join('\n')}\n`;
}
