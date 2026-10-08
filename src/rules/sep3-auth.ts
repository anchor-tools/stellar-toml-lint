import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isString, isUrl } from '../predicates.js';

const AUTH_SERVER_UNREACHABLE_RULE = 'sep3/auth-server-unreachable';
const MISSING_CORS_HEADERS_RULE = 'sep3/missing-cors-headers';
const SEP3_SPEC_URL =
  'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0003.md';
const PROBE_ORIGIN = 'https://stellar-toml-lint.invalid';
const DEFAULT_TIMEOUT_MS = 10_000;
const VALID_STATUS_CODES = new Set([200, 202, 400, 403, 500]);

interface AuditOptions {
  rules?: RuleOverrides;
  timeoutMs?: number;
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

function finding(
  rule: string,
  message: string,
  suggestion: string,
  rules: RuleOverrides | undefined,
): Diagnostic[] {
  const severity = severityFor(rule, 'error', rules);
  if (severity === undefined) return [];

  return [
    {
      rule,
      severity,
      category: 'network',
      message,
      path: 'AUTH_SERVER',
      helpUri: SEP3_SPEC_URL,
      suggestion,
    },
  ];
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}

function unreachable(detail: string, rules: RuleOverrides | undefined): Diagnostic[] {
  return finding(
    AUTH_SERVER_UNREACHABLE_RULE,
    detail,
    'Confirm AUTH_SERVER points at a live SEP-3 compliance server over HTTPS and is reachable.',
    rules,
  );
}

function hasCorsHeader(response: Response): boolean {
  const origin = response.headers.get('access-control-allow-origin')?.trim();
  return origin === '*' || origin === PROBE_ORIGIN;
}

export async function checkSep3Auth(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: AuditOptions = {},
): Promise<Diagnostic[]> {
  const authServer = doc.AUTH_SERVER;
  if (!isString(authServer) || !isUrl(authServer)) return [];

  let url: URL;
  try {
    url = new URL(authServer);
  } catch {
    return [];
  }

  if (url.protocol !== 'https:') {
    return unreachable(`AUTH_SERVER at ${authServer} is not served over HTTPS`, options.rules);
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs ?? DEFAULT_TIMEOUT_MS);

  let response: Response;
  try {
    response = await fetchImpl(authServer, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        origin: PROBE_ORIGIN,
      },
      body: new URLSearchParams({ data: '', sig: '' }),
      signal: controller.signal,
    });
  } catch (error) {
    return unreachable(
      `Could not reach AUTH_SERVER at ${authServer}: ${errorMessage(error)}`,
      options.rules,
    );
  } finally {
    clearTimeout(timeout);
  }

  if (!VALID_STATUS_CODES.has(response.status)) {
    return unreachable(
      `AUTH_SERVER at ${authServer} returned HTTP ${response.status}, which is not a valid SEP-3 status`,
      options.rules,
    );
  }

  if (!hasCorsHeader(response)) {
    return finding(
      MISSING_CORS_HEADERS_RULE,
      `AUTH_SERVER at ${authServer} did not return a valid Access-Control-Allow-Origin header`,
      'Set Access-Control-Allow-Origin to * or the wallet origin on AUTH_SERVER.',
      options.rules,
    );
  }

  return [];
}

export const sep3Rules: Rule[] = [
  {
    id: AUTH_SERVER_UNREACHABLE_RULE,
    category: 'network',
    severity: 'error',
    description: 'AUTH_SERVER must be reachable over HTTPS and return a valid SEP-3 status',
    run() {},
  },
  {
    id: MISSING_CORS_HEADERS_RULE,
    category: 'network',
    severity: 'error',
    description: 'AUTH_SERVER must return CORS headers for browser clients',
    run() {},
  },
];

export const sep3RuleIds: readonly string[] = sep3Rules.map((rule) => rule.id);
