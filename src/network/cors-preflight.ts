import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isString, isUrl } from '../predicates.js';

const CORS_PREFLIGHT_FAILED = 'network/cors-preflight-failed';
const MISSING_ALLOW_HEADERS = 'network/missing-allow-headers';
const REQUESTING_ORIGIN = 'https://stellar-toml-lint.invalid';

const ENDPOINTS = [
  'WEB_AUTH_ENDPOINT',
  'TRANSFER_SERVER',
  'KYC_SERVER',
  'ANCHOR_QUOTE_SERVER',
] as const;

interface CheckOptions {
  rules?: RuleOverrides;
}

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules: RuleOverrides | undefined,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

function diagnostic(
  rule: string,
  fallback: 'error' | 'warning',
  message: string,
  path: string,
  options: CheckOptions,
): Diagnostic[] {
  const severity = severityFor(rule, fallback, options.rules);
  if (severity === undefined) return [];
  return [{ rule, severity, category: 'network', message, path }];
}

function includesToken(value: string | null, token: string): boolean {
  return (value ?? '')
    .split(',')
    .some((entry) => entry.trim().toLowerCase() === token.toLowerCase());
}

/** Sends browser-shaped OPTIONS requests to each service endpoint in SEP-1. */
export async function checkCorsPreflight(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: CheckOptions = {},
): Promise<Diagnostic[]> {
  const diagnostics: Diagnostic[] = [];

  for (const endpoint of ENDPOINTS) {
    const value = doc[endpoint];
    if (!isString(value) || !isUrl(value)) continue;

    let response: Response;
    try {
      response = await fetchImpl(value, {
        method: 'OPTIONS',
        headers: {
          Origin: REQUESTING_ORIGIN,
          'Access-Control-Request-Method': 'POST',
          'Access-Control-Request-Headers': 'content-type, authorization',
        },
      });
    } catch (error) {
      diagnostics.push(
        ...diagnostic(
          CORS_PREFLIGHT_FAILED,
          'error',
          `Could not send CORS pre-flight request to ${endpoint}: ${error instanceof Error ? error.message : String(error)}`,
          endpoint,
          options,
        ),
      );
      continue;
    }

    const allowOrigin = response.headers.get('access-control-allow-origin');
    const allowMethods = response.headers.get('access-control-allow-methods');
    if (
      !response.ok ||
      (allowOrigin !== '*' && allowOrigin !== REQUESTING_ORIGIN) ||
      !includesToken(allowMethods, 'GET') ||
      !includesToken(allowMethods, 'POST') ||
      !includesToken(allowMethods, 'OPTIONS')
    ) {
      diagnostics.push(
        ...diagnostic(
          CORS_PREFLIGHT_FAILED,
          'error',
          `${endpoint} did not provide a valid CORS pre-flight response${response.ok ? '' : ` (HTTP ${response.status})`}`,
          endpoint,
          options,
        ),
      );
    }

    if (!response.headers.has('access-control-allow-headers')) {
      diagnostics.push(
        ...diagnostic(
          MISSING_ALLOW_HEADERS,
          'warning',
          `${endpoint} is missing the Access-Control-Allow-Headers response header`,
          endpoint,
          options,
        ),
      );
    }
  }

  return diagnostics;
}

export const corsPreflightRules: Rule[] = [
  {
    id: CORS_PREFLIGHT_FAILED,
    category: 'network',
    severity: 'error',
    description:
      'Service endpoints must answer OPTIONS requests with valid CORS origin and methods',
    run() {},
  },
  {
    id: MISSING_ALLOW_HEADERS,
    category: 'network',
    severity: 'warning',
    description:
      'Service endpoints should return Access-Control-Allow-Headers for browser pre-flight requests',
    run() {},
  },
];
