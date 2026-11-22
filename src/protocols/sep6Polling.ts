/**
 * SEP-6 non-interactive transaction polling resilience verifier.
 *
 * Runs under opt-in `--audit-sep6-polling`.
 *
 * A SEP-6 wallet watches a transfer by polling `GET /transaction?id=...` at a
 * fixed cadence. Identical requests must therefore be safe to repeat: the same
 * status and the same payload, a response that a proxy cannot cache into a
 * stale state, and honest rate-limit signals when the anchor needs the client
 * to back off. An anchor that flips between `pending_anchor` and `completed`
 * for one id, omits `Cache-Control: no-store`, or returns 429 without
 * `Retry-After` leaves wallets desynchronised days after the file shipped.
 *
 * The verifier is read-only: it polls an existing transaction id the caller
 * supplies and never creates or mutates a transfer.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isHttpsUrl, isString } from '../predicates.js';
import { fetchWithTimeout, isRecord, severityFor } from './verifierSupport.js';

const INCONSISTENT_RULE = 'sep6/polling-inconsistent-response';
const SERVER_ERROR_RULE = 'sep6/polling-server-error';
const CACHE_RULE = 'sep6/polling-stale-cache-headers';
const RATE_LIMIT_RULE = 'sep6/polling-rate-limit-headers';
const UNKNOWN_STATUS_RULE = 'sep6/polling-unknown-status';
const UNVERIFIABLE_RULE = 'sep6/polling-unverifiable';

const SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0006.md';

/** SEP-6 transaction statuses a wallet may poll for. */
export const SEP6_TRANSACTION_STATUSES = [
  'pending_stellar',
  'pending_external',
  'pending_anchor',
  'pending_user_transfer_start',
  'pending_user_transfer_complete',
  'pending_trust',
  'pending_user',
  'pending_user_kyc',
  'incomplete',
  'no_market',
  'too_small',
  'too_large',
  'completed',
  'refunded',
  'expired',
  'error',
] as const;

/** Client polling cadences simulated by default, in milliseconds. */
export const DEFAULT_POLLING_INTERVALS_MS = [2000, 5000, 10000] as const;

export interface PollingClock {
  monotonicNow(): number;
}

export const systemPollingClock: PollingClock = {
  monotonicNow: () => performance.now(),
};

export interface Sep6PollingOptions {
  rules?: RuleOverrides;
  /** Transfer server base; defaults to `TRANSFER_SERVER`. */
  transferServer?: string;
  /** The transaction id wallets would poll. Without one the audit cannot run. */
  transactionId?: string;
  /** SEP-10 JWT, when the anchor requires authentication. */
  token?: string;
  /** Polling cadences to simulate. Defaults to 2s, 5s and 10s. */
  intervals?: readonly number[];
  /** Identical polls per cadence. Defaults to 2. */
  pollsPerInterval?: number;
  timeoutMs?: number;
  sleep?: (ms: number) => Promise<unknown>;
  clock?: PollingClock;
}

export interface PollRecord {
  intervalMs: number;
  status: number;
  /** Stable checksum of the response body. */
  checksum: string;
  cacheControl?: string;
  rateLimitLimit?: number;
  rateLimitRemaining?: number;
  retryAfter?: string;
  transactionStatus?: string;
  latencyMs?: number;
}

export interface Sep6PollingResult {
  diagnostics: Diagnostic[];
  polls: PollRecord[];
  summary: string;
}

/** JSON with sorted object keys, so field order never fakes a difference. */
export function stableChecksum(value: unknown): string {
  const canonical = (input: unknown): string => {
    if (Array.isArray(input)) return `[${input.map(canonical).join(',')}]`;
    if (isRecord(input)) {
      return `{${Object.keys(input)
        .sort()
        .map((key) => `${JSON.stringify(key)}:${canonical(input[key])}`)
        .join(',')}}`;
    }
    return JSON.stringify(input) ?? 'null';
  };
  return canonical(value);
}

function headerOf(headers: Headers, name: string): string | undefined {
  const value = headers.get(name);
  return value === null ? undefined : value;
}

function integerHeader(headers: Headers, name: string): number | undefined {
  const raw = headerOf(headers, name);
  if (raw === undefined) return undefined;
  const parsed = Number(raw);
  return Number.isInteger(parsed) ? parsed : undefined;
}

/** `Cache-Control` must stop wallets and proxies caching a transaction state. */
export function isUncacheable(cacheControl: string | undefined): boolean {
  if (cacheControl === undefined) return false;
  return /\b(no-store|no-cache|private|max-age\s*=\s*0)\b/i.test(cacheControl);
}

export class Sep6PollingIdempotencyVerifier {
  constructor(
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly options: Sep6PollingOptions = {},
  ) {}

  async verify(doc: Record<string, unknown>): Promise<Sep6PollingResult> {
    const server = this.options.transferServer ?? doc.TRANSFER_SERVER;
    if (!isString(server) || !isHttpsUrl(server)) {
      return { diagnostics: [], polls: [], summary: 'No usable TRANSFER_SERVER to poll.' };
    }
    const transactionId = this.options.transactionId;
    if (!isString(transactionId) || transactionId.length === 0) {
      return {
        diagnostics: this.finding(
          UNVERIFIABLE_RULE,
          'info',
          'SEP-6 polling audit needs a transaction id to repeat GET /transaction requests',
          'TRANSFER_SERVER',
          'Pass --transaction-id <id> with a transfer the anchor already knows about.',
        ),
        polls: [],
        summary: 'No transaction id supplied.',
      };
    }

    const base = server.replace(/\/+$/, '');
    const clock = this.options.clock ?? systemPollingClock;
    const sleep =
      this.options.sleep ?? ((ms: number) => new Promise((resolve) => setTimeout(resolve, ms)));
    const intervals = this.options.intervals ?? DEFAULT_POLLING_INTERVALS_MS;
    const pollsPerInterval = Math.max(1, this.options.pollsPerInterval ?? 2);

    const polls: PollRecord[] = [];
    for (const intervalMs of intervals) {
      if (intervalMs > 0) await sleep(intervalMs);
      for (let poll = 0; poll < pollsPerInterval; poll++) {
        polls.push(await this.poll(base, transactionId, intervalMs, clock));
      }
    }

    if (polls.every((poll) => poll.status === 0)) {
      return {
        diagnostics: this.finding(
          UNVERIFIABLE_RULE,
          'info',
          `TRANSFER_SERVER ${base} did not answer /transaction for "${transactionId}"`,
          'TRANSFER_SERVER',
          'Confirm TRANSFER_SERVER is reachable and the transaction id exists.',
        ),
        polls,
        summary: 'Transaction could not be polled.',
      };
    }

    return {
      diagnostics: this.assess(polls),
      polls,
      summary: `${polls.length} polls across ${intervals.length} cadences for transaction ${transactionId}.`,
    };
  }

  private assess(polls: readonly PollRecord[]): Diagnostic[] {
    const diagnostics: Diagnostic[] = [];

    const answered = polls.filter((poll) => poll.status !== 0);
    const serverErrors = answered.filter((poll) => poll.status >= 500);
    if (serverErrors.length > 0) {
      diagnostics.push(
        ...this.finding(
          SERVER_ERROR_RULE,
          'warning',
          `${serverErrors.length} of ${answered.length} identical GET /transaction polls returned HTTP ${serverErrors[0]?.status}`,
          'TRANSFER_SERVER',
          'Keep GET /transaction idempotent and available: a 5xx during a wallet poll looks like a lost transfer.',
        ),
      );
    }

    const byInterval = new Map<number, PollRecord[]>();
    for (const poll of answered) {
      const group = byInterval.get(poll.intervalMs) ?? [];
      group.push(poll);
      byInterval.set(poll.intervalMs, group);
    }
    // A status change between polls is a transfer progressing, not a bug. What
    // is a bug: the same status carrying different payloads, or a 2xx and a
    // failure for the same id a moment apart.
    const diverged = [...byInterval.values()].find((group) => {
      const hasSuccess = group.some((poll) => poll.status >= 200 && poll.status < 300);
      const hasFailure = group.some((poll) => poll.status < 200 || poll.status >= 300);
      if (hasSuccess && hasFailure) return true;
      const byStatus = new Map<number, Set<string>>();
      for (const poll of group) {
        const checksums = byStatus.get(poll.status) ?? new Set<string>();
        checksums.add(poll.checksum);
        byStatus.set(poll.status, checksums);
      }
      return [...byStatus.values()].some((checksums) => checksums.size > 1);
    });
    if (diverged !== undefined) {
      diagnostics.push(
        ...this.finding(
          INCONSISTENT_RULE,
          'error',
          `Identical GET /transaction polls returned ${new Set(diverged.map((poll) => poll.status)).size} status codes and ${new Set(diverged.map((poll) => poll.checksum)).size} payloads`,
          'TRANSFER_SERVER',
          'Return a stable transaction object for an unchanged transfer state; repeat polls must not desynchronise the wallet.',
        ),
      );
    }

    const cacheable = answered.filter(
      (poll) => poll.status === 200 && !isUncacheable(poll.cacheControl),
    );
    if (cacheable.length > 0) {
      diagnostics.push(
        ...this.finding(
          CACHE_RULE,
          'warning',
          `${cacheable.length} of ${answered.length} transaction responses lack Cache-Control: no-store`,
          'TRANSFER_SERVER',
          'Send Cache-Control: no-store (or no-cache) on GET /transaction so a proxy cannot serve a stale status.',
        ),
      );
    }

    const throttled = answered.filter((poll) => poll.status === 429);
    const missingRetryAfter = throttled.filter((poll) => poll.retryAfter === undefined);
    const invalidLimit = answered.filter(
      (poll) =>
        (poll.rateLimitLimit !== undefined && poll.rateLimitLimit < 0) ||
        (poll.rateLimitRemaining !== undefined &&
          poll.rateLimitLimit !== undefined &&
          poll.rateLimitRemaining > poll.rateLimitLimit),
    );
    const nonDecreasing = answered.some((poll, index) => {
      const previous = answered[index - 1];
      return (
        previous !== undefined &&
        previous.rateLimitRemaining !== undefined &&
        poll.rateLimitRemaining !== undefined &&
        poll.rateLimitRemaining > previous.rateLimitRemaining
      );
    });
    if (missingRetryAfter.length > 0 || invalidLimit.length > 0 || nonDecreasing) {
      diagnostics.push(
        ...this.finding(
          RATE_LIMIT_RULE,
          'warning',
          missingRetryAfter.length > 0
            ? `${missingRetryAfter.length} of ${throttled.length} HTTP 429 responses omitted Retry-After`
            : 'RateLimit-Limit/RateLimit-Remaining headers are inconsistent across identical polls',
          'TRANSFER_SERVER',
          'Advertise RFC 6585 RateLimit-Limit/RateLimit-Remaining and a Retry-After on 429 so wallets back off without abandoning the transfer.',
        ),
      );
    }

    const unknown = answered.filter(
      (poll) =>
        poll.transactionStatus !== undefined &&
        !(SEP6_TRANSACTION_STATUSES as readonly string[]).includes(poll.transactionStatus),
    );
    if (unknown.length > 0) {
      diagnostics.push(
        ...this.finding(
          UNKNOWN_STATUS_RULE,
          'warning',
          `GET /transaction returned the non-SEP-6 status "${unknown[0]?.transactionStatus}"`,
          'TRANSFER_SERVER',
          'Return one of the SEP-6 transaction statuses so wallets can render the transfer correctly.',
        ),
      );
    }

    return diagnostics;
  }

  private async poll(
    base: string,
    transactionId: string,
    intervalMs: number,
    clock: PollingClock,
  ): Promise<PollRecord> {
    const start = clock.monotonicNow();
    const params = new URLSearchParams({ id: transactionId });
    try {
      const response = await fetchWithTimeout(
        this.fetchImpl,
        `${base}/transaction?${params.toString()}`,
        {
          ...(this.options.token === undefined
            ? {}
            : { headers: { authorization: `Bearer ${this.options.token}` } }),
        },
        this.options.timeoutMs,
      );
      const text = await response.text().catch(() => '');
      let body: unknown;
      try {
        body = JSON.parse(text);
      } catch {
        body = text;
      }
      return {
        intervalMs,
        status: response.status,
        checksum: stableChecksum(body),
        ...(headerOf(response.headers, 'cache-control') !== undefined
          ? { cacheControl: headerOf(response.headers, 'cache-control') as string }
          : {}),
        ...(integerHeader(response.headers, 'ratelimit-limit') !== undefined
          ? { rateLimitLimit: integerHeader(response.headers, 'ratelimit-limit') as number }
          : {}),
        ...(integerHeader(response.headers, 'ratelimit-remaining') !== undefined
          ? { rateLimitRemaining: integerHeader(response.headers, 'ratelimit-remaining') as number }
          : {}),
        ...(headerOf(response.headers, 'retry-after') !== undefined
          ? { retryAfter: headerOf(response.headers, 'retry-after') as string }
          : {}),
        ...(isRecord(body) && isString(body.status) ? { transactionStatus: body.status } : {}),
        latencyMs: clock.monotonicNow() - start,
      };
    } catch {
      return {
        intervalMs,
        status: 0,
        checksum: 'unreachable',
        latencyMs: clock.monotonicNow() - start,
      };
    }
  }

  private finding(
    rule: string,
    fallback: 'error' | 'warning' | 'info',
    message: string,
    path: string,
    suggestion: string,
  ): Diagnostic[] {
    const severity = severityFor(rule, fallback, this.options.rules);
    if (severity === undefined) return [];
    return [{ rule, severity, category: 'network', message, path, helpUri: SPEC, suggestion }];
  }
}

export async function auditSep6Polling(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: Sep6PollingOptions = {},
): Promise<Sep6PollingResult> {
  return new Sep6PollingIdempotencyVerifier(fetchImpl, options).verify(doc);
}

const def = (id: string, severity: 'error' | 'warning' | 'info', description: string): Rule => ({
  id,
  category: 'network',
  severity,
  description,
  run() {},
});

export const sep6PollingRules: Rule[] = [
  def(
    INCONSISTENT_RULE,
    'error',
    'Identical SEP-6 GET /transaction polls must return the same status and payload',
  ),
  def(
    SERVER_ERROR_RULE,
    'warning',
    'SEP-6 GET /transaction must stay available while wallets poll',
  ),
  def(CACHE_RULE, 'warning', 'SEP-6 transaction responses must not be cacheable'),
  def(RATE_LIMIT_RULE, 'warning', 'SEP-6 polling must expose consistent rate-limit signals'),
  def(UNKNOWN_STATUS_RULE, 'warning', 'SEP-6 transaction statuses must be from the spec'),
  def(UNVERIFIABLE_RULE, 'info', 'SEP-6 polling resilience should be verifiable'),
];

export const sep6PollingRuleIds: readonly string[] = sep6PollingRules.map((rule) => rule.id);
