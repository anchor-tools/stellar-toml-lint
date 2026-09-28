/**
 * Horizon API rate-limit resilience and exponential-backoff tester.
 *
 * Runs under the opt-in `--check-network` flag (and is skipped entirely when a
 * hermetic fixture transport is in use).
 *
 * When a Horizon instance is hit by a spike or DDoS event it answers with
 * HTTP 429 and rate-limit metadata. This auditor probes the configured Horizon
 * base URL, inspects `X-RateLimit-Limit` / `X-RateLimit-Remaining` /
 * `X-RateLimit-Reset`, and verifies that 429 responses are reported as RFC 7807
 * problem-details rather than an opaque body.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';

export const NETWORK_MISSING_RATE_LIMIT_HEADERS = 'network/missing-rate-limit-headers';
export const NETWORK_UNSTANDARDIZED_RATE_LIMIT_RESPONSE =
  'network/unstandardized-rate-limit-response';

export const MISSING_RATE_LIMIT_HEADERS_RULE = NETWORK_MISSING_RATE_LIMIT_HEADERS;
export const UNSTANDARDIZED_RATE_LIMIT_RESPONSE_RULE = NETWORK_UNSTANDARDIZED_RATE_LIMIT_RESPONSE;

export const DEFAULT_HORIZON_URL = 'https://horizon.stellar.org';

export const RATE_LIMIT_HEADERS = [
  'x-ratelimit-limit',
  'x-ratelimit-remaining',
  'x-ratelimit-reset',
] as const;

const RFC7807_SPEC = 'https://www.rfc-editor.org/rfc/rfc7807';

export interface RateLimitTesterOptions {
  rules?: RuleOverrides;
  /** Horizon base URL (no trailing slash required). */
  horizonUrl?: string;
  fetchImpl?: typeof fetch;
}

export interface RateLimitProbe {
  url: string;
  status: number;
  headers: Record<string, string>;
  missingHeaders: string[];
  rateLimited: boolean;
  problemDetails: boolean;
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

function normalizeBaseUrl(baseUrl: string | undefined): string {
  const value = (baseUrl ?? DEFAULT_HORIZON_URL).trim();
  return value.endsWith('/') ? value.slice(0, -1) : value;
}

/**
 * Standard exponential backoff with a ceiling, used to verify that callers
 * honour Horizon's `Retry-After` guidance rather than hammering a throttled
 * endpoint.
 */
export function computeBackoffDelayMs(attempt: number, baseMs = 1000, maxMs = 60_000): number {
  const exponent = Math.max(0, attempt - 1);
  return Math.min(baseMs * 2 ** exponent, maxMs);
}

function headerRecord(response: Response): Record<string, string> {
  const headers: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    headers[key.toLowerCase()] = value;
  });
  return headers;
}

function isProblemDetails(contentType: string, body: unknown): boolean {
  if (contentType.includes('application/problem+json')) return true;
  if (typeof body !== 'object' || body === null || Array.isArray(body)) return false;
  const record = body as Record<string, unknown>;
  return typeof record.type === 'string' || typeof record.title === 'string';
}

async function readBody(response: Response): Promise<unknown> {
  try {
    const text = await response.text();
    if (text.trim() === '') return undefined;
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

export async function probeHorizonRateLimit(
  url: string,
  fetchImpl: typeof fetch = fetch,
): Promise<RateLimitProbe> {
  const response = await fetchImpl(url, { headers: { Accept: 'application/json' } });
  const headers = headerRecord(response);
  const missingHeaders = RATE_LIMIT_HEADERS.filter((name) => headers[name] === undefined);
  const rateLimited = response.status === 429;
  const body = rateLimited ? await readBody(response) : undefined;

  return {
    url,
    status: response.status,
    headers,
    missingHeaders: [...missingHeaders],
    rateLimited,
    problemDetails: !rateLimited || isProblemDetails(headers['content-type'] ?? '', body),
  };
}

/**
 * Probe Horizon's root and ledger endpoints and report rate-limit metadata
 * gaps. Network failures degrade to silence so offline runs never fail hard.
 */
export async function checkRateLimitResilience(
  options: RateLimitTesterOptions = {},
): Promise<Diagnostic[]> {
  const { rules } = options;
  const fetchImpl = options.fetchImpl ?? fetch;
  const baseUrl = normalizeBaseUrl(options.horizonUrl);

  const endpoints = [`${baseUrl}/`, `${baseUrl}/ledgers?order=desc&limit=1`];
  const probes: RateLimitProbe[] = [];

  for (const endpoint of endpoints) {
    try {
      probes.push(await probeHorizonRateLimit(endpoint, fetchImpl));
    } catch {
      // Unreachable endpoint: nothing reliable to assert.
    }
  }

  if (probes.length === 0) return [];

  const diagnostics: Diagnostic[] = [];

  const withMissingHeaders = probes.filter((probe) => probe.missingHeaders.length > 0);
  const missingSeverity = severityFor(NETWORK_MISSING_RATE_LIMIT_HEADERS, 'warning', rules);
  if (missingSeverity !== undefined && withMissingHeaders.length > 0) {
    const details = withMissingHeaders
      .map((probe) => `${probe.url} missing ${probe.missingHeaders.join(', ')}`)
      .join('; ');
    diagnostics.push({
      rule: NETWORK_MISSING_RATE_LIMIT_HEADERS,
      severity: missingSeverity,
      category: 'network',
      message: `Horizon does not advertise rate-limit headers (${details})`,
      suggestion:
        'Enable the Horizon rate limiter and expose X-RateLimit-Limit, X-RateLimit-Remaining and X-RateLimit-Reset on every response.',
    });
  }

  const unstandardized = probes.filter((probe) => probe.rateLimited && !probe.problemDetails);
  const unstandardizedSeverity = severityFor(
    NETWORK_UNSTANDARDIZED_RATE_LIMIT_RESPONSE,
    'error',
    rules,
  );
  if (unstandardizedSeverity !== undefined && unstandardized.length > 0) {
    diagnostics.push({
      rule: NETWORK_UNSTANDARDIZED_RATE_LIMIT_RESPONSE,
      severity: unstandardizedSeverity,
      category: 'network',
      message: `Horizon returned HTTP 429 without an RFC 7807 problem-details body (${unstandardized
        .map((probe) => probe.url)
        .join(', ')})`,
      suggestion:
        'Return application/problem+json with type, title and status fields on throttled responses so clients can back off deterministically.',
      helpUri: RFC7807_SPEC,
    });
  }

  return diagnostics;
}

export const rateLimitTesterRules: Rule[] = [
  {
    id: NETWORK_MISSING_RATE_LIMIT_HEADERS,
    category: 'network',
    severity: 'warning',
    description: 'Horizon responses should advertise X-RateLimit-* headers',
    run() {},
  },
  {
    id: NETWORK_UNSTANDARDIZED_RATE_LIMIT_RESPONSE,
    category: 'network',
    severity: 'error',
    description: 'HTTP 429 responses should use RFC 7807 problem-details',
    run() {},
  },
];

export const rateLimitTesterRuleIds: readonly string[] = rateLimitTesterRules.map(
  (rule) => rule.id,
);
