/**
 * Anchor API rate-limit header standard RFC 6585 compliance verifier.
 *
 * Inspects HTTP response headers against IETF RateLimit header specifications
 * (RateLimit-Limit, RateLimit-Remaining, RateLimit-Reset) and legacy X-RateLimit-* headers.
 * Validates Retry-After delta-seconds and HTTP-date formats under HTTP 429 responses.
 */
import type { Diagnostic, Severity } from '../types.js';

export interface RateLimitFinding {
  rule: string;
  severity: Severity;
  message: string;
}

export interface RateLimitComplianceResult {
  url?: string;
  ok: boolean;
  statusCode: number;
  standard: 'ietf' | 'legacy' | 'both' | 'none';
  limit?: number;
  remaining?: number;
  reset?: number | Date;
  retryAfterSeconds?: number;
  retryAfterDate?: Date;
  findings: RateLimitFinding[];
  diagnostics: Diagnostic[];
}

export interface VerifyRateHeadersOptions {
  burstCount?: number;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}

export class RateLimitHeaderVerifier {
  /**
   * Evaluates response headers for RFC 6585 and IETF RateLimit specification compliance.
   */
  public verifyHeaders(
    headers: Headers | Record<string, string | string[] | undefined>,
    statusCode: number = 200,
    url?: string,
  ): RateLimitComplianceResult {
    const getHeader = (name: string): string | undefined => {
      const lower = name.toLowerCase();
      if (typeof (headers as Headers).get === 'function') {
        return (headers as Headers).get(lower) ?? undefined;
      }
      const raw =
        (headers as Record<string, string | string[] | undefined>)[lower] ??
        (headers as Record<string, string | string[] | undefined>)[name];
      if (Array.isArray(raw)) return raw[0];
      return raw ?? undefined;
    };

    const findings: RateLimitFinding[] = [];

    // 1. Extract IETF headers
    const ietfLimitStr = getHeader('ratelimit-limit');
    const ietfRemainingStr = getHeader('ratelimit-remaining');
    const ietfResetStr = getHeader('ratelimit-reset');

    // 2. Extract legacy headers
    const legacyLimitStr = getHeader('x-ratelimit-limit');
    const legacyRemainingStr = getHeader('x-ratelimit-remaining');
    const legacyResetStr = getHeader('x-ratelimit-reset');

    // 3. Extract Retry-After
    const retryAfterStr = getHeader('retry-after');

    const hasIetf =
      ietfLimitStr !== undefined || ietfRemainingStr !== undefined || ietfResetStr !== undefined;
    const hasLegacy =
      legacyLimitStr !== undefined ||
      legacyRemainingStr !== undefined ||
      legacyResetStr !== undefined;

    let standard: 'ietf' | 'legacy' | 'both' | 'none' = 'none';
    if (hasIetf && hasLegacy) standard = 'both';
    else if (hasIetf) standard = 'ietf';
    else if (hasLegacy) standard = 'legacy';

    if (standard === 'legacy') {
      findings.push({
        rule: 'ratelimit/legacy-headers-used',
        severity: 'info',
        message:
          'Endpoint returns legacy X-RateLimit-* headers instead of IETF standard RateLimit-* headers.',
      });
    } else if (standard === 'none') {
      findings.push({
        rule: 'ratelimit/missing-headers',
        severity: statusCode === 429 ? 'error' : 'warning',
        message:
          statusCode === 429
            ? 'HTTP 429 Too Many Requests returned without any RateLimit disclosure headers.'
            : 'Endpoint does not disclose RateLimit headers.',
      });
    }

    // Parse Limit
    let limit: number | undefined;
    const rawLimit = ietfLimitStr ?? legacyLimitStr;
    if (rawLimit !== undefined) {
      // IETF allow window parameter: "100, 100;w=60"
      const match = rawLimit.match(/^\s*(\d+)/);
      if (match) {
        limit = Number(match[1]);
      } else {
        findings.push({
          rule: 'ratelimit/malformed-limit',
          severity: 'error',
          message: `Malformed RateLimit-Limit value: "${rawLimit}". Expected non-negative integer.`,
        });
      }
    }

    // Parse Remaining
    let remaining: number | undefined;
    const rawRemaining = ietfRemainingStr ?? legacyRemainingStr;
    if (rawRemaining !== undefined) {
      const parsed = Number(rawRemaining.trim());
      if (Number.isInteger(parsed) && parsed >= 0) {
        remaining = parsed;
      } else {
        findings.push({
          rule: 'ratelimit/malformed-remaining',
          severity: 'error',
          message: `Malformed RateLimit-Remaining value: "${rawRemaining}". Expected non-negative integer.`,
        });
      }
    }

    // Consistency check between limit and remaining
    if (limit !== undefined && remaining !== undefined && remaining > limit) {
      findings.push({
        rule: 'ratelimit/inconsistent-remaining',
        severity: 'error',
        message: `RateLimit-Remaining (${remaining}) exceeds RateLimit-Limit (${limit}).`,
      });
    }

    // Parse Reset
    let reset: number | Date | undefined;
    const rawReset = ietfResetStr ?? legacyResetStr;
    if (rawReset !== undefined) {
      const resetNum = Number(rawReset.trim());
      if (Number.isFinite(resetNum)) {
        if (resetNum < 0) {
          findings.push({
            rule: 'ratelimit/inconsistent-reset',
            severity: 'error',
            message: `Negative RateLimit-Reset value: "${rawReset}".`,
          });
        } else {
          // If value is large (e.g. epoch timestamp > 1e9), interpret as timestamp
          if (resetNum > 1000000000) {
            reset = new Date(resetNum * 1000);
            if (reset.getTime() < Date.now() - 3600000) {
              findings.push({
                rule: 'ratelimit/inconsistent-reset',
                severity: 'warning',
                message: `RateLimit-Reset timestamp is in the past: ${reset.toISOString()}.`,
              });
            }
          } else {
            reset = resetNum; // delta-seconds
          }
        }
      } else {
        // Try parsing as HTTP-date
        const parsedDate = new Date(rawReset.trim());
        if (!isNaN(parsedDate.getTime())) {
          reset = parsedDate;
        } else {
          findings.push({
            rule: 'ratelimit/malformed-reset',
            severity: 'error',
            message: `Malformed RateLimit-Reset value: "${rawReset}".`,
          });
        }
      }
    }

    // Validate Retry-After under 429
    let retryAfterSeconds: number | undefined;
    let retryAfterDate: Date | undefined;

    if (statusCode === 429) {
      if (!retryAfterStr) {
        findings.push({
          rule: 'ratelimit/missing-retry-after',
          severity: 'error',
          message: 'HTTP 429 response is missing required RFC 6585 Retry-After header.',
        });
      } else {
        const trimmed = retryAfterStr.trim();
        // Check if delta-seconds (integer >= 0)
        if (/^\d+$/.test(trimmed)) {
          retryAfterSeconds = Number(trimmed);
        } else {
          // Check if valid HTTP-date
          const dateVal = new Date(trimmed);
          if (!isNaN(dateVal.getTime())) {
            retryAfterDate = dateVal;
            retryAfterSeconds = Math.max(0, Math.round((dateVal.getTime() - Date.now()) / 1000));
          } else {
            findings.push({
              rule: 'ratelimit/invalid-retry-after',
              severity: 'error',
              message: `Invalid Retry-After header: "${retryAfterStr}". Expected integer delta-seconds or RFC 7231 HTTP-date.`,
            });
          }
        }
      }
    }

    const diagnostics: Diagnostic[] = findings.map((f) => ({
      rule: f.rule,
      category: 'network',
      severity: f.severity,
      message: f.message,
      path: url,
    }));

    const hasError = findings.some((f) => f.severity === 'error');

    return {
      url,
      ok: !hasError,
      statusCode,
      standard,
      limit,
      remaining,
      reset,
      retryAfterSeconds,
      retryAfterDate,
      findings,
      diagnostics,
    };
  }

  /**
   * Sends structured burst probes against a target URL to verify rate-limit behavior.
   */
  public async verifyEndpoint(
    url: string,
    options: VerifyRateHeadersOptions = {},
  ): Promise<RateLimitComplianceResult> {
    const fetchImpl = options.fetchImpl ?? fetch;
    const burstCount = options.burstCount ?? 3;

    let lastResult: RateLimitComplianceResult | undefined;

    for (let i = 0; i < burstCount; i++) {
      const response = await fetchImpl(url, {
        method: 'GET',
        headers: { Accept: 'application/json' },
      });

      lastResult = this.verifyHeaders(response.headers, response.status, url);
      if (response.status === 429) {
        break; // Hit rate limit, examine headers
      }
    }

    return (
      lastResult ?? {
        url,
        ok: false,
        statusCode: 0,
        standard: 'none',
        findings: [
          {
            rule: 'ratelimit/connection-failed',
            severity: 'error',
            message: `Failed to receive response from ${url}`,
          },
        ],
        diagnostics: [],
      }
    );
  }

  /**
   * Formats the compliance result as human-readable text or JSON.
   */
  public renderReport(result: RateLimitComplianceResult, format: 'text' | 'json' = 'text'): string {
    if (format === 'json') {
      return JSON.stringify(result, null, 2);
    }

    const lines: string[] = [];
    lines.push(`Rate Limit Compliance Report for ${result.url ?? 'endpoint'}`);
    lines.push(`  Status Code: ${result.statusCode}`);
    lines.push(`  Standard:    ${result.standard.toUpperCase()}`);
    if (result.limit !== undefined) lines.push(`  Limit:       ${result.limit}`);
    if (result.remaining !== undefined) lines.push(`  Remaining:   ${result.remaining}`);
    if (result.reset !== undefined) {
      lines.push(
        `  Reset:       ${result.reset instanceof Date ? result.reset.toISOString() : `${result.reset}s`}`,
      );
    }
    if (result.retryAfterSeconds !== undefined) {
      lines.push(`  Retry-After: ${result.retryAfterSeconds}s`);
    }

    if (result.findings.length > 0) {
      lines.push('\nFindings:');
      for (const f of result.findings) {
        const tag =
          f.severity === 'error' ? '[ERROR]' : f.severity === 'warning' ? '[WARN]' : '[INFO]';
        lines.push(`  ${tag} ${f.rule}: ${f.message}`);
      }
    } else {
      lines.push('\nAll rate-limit headers comply with IETF standards.');
    }

    return lines.join('\n');
  }
}
