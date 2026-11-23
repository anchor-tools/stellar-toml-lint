import { describe, expect, it } from 'vitest';
import {
  SEP6_TRANSACTION_STATUSES,
  Sep6PollingIdempotencyVerifier,
  auditSep6Polling,
  isUncacheable,
  sep6PollingRuleIds,
  stableChecksum,
} from '../../src/protocols/sep6Polling.js';

const DOC = { TRANSFER_SERVER: 'https://transfer.example.com/sep6' };
const TX_ID = 'tx-123';

function jsonResponse(
  body: unknown,
  init: { status?: number; headers?: Record<string, string> } = {},
): Response {
  return new Response(JSON.stringify(body), {
    status: init.status ?? 200,
    headers: { 'content-type': 'application/json', ...(init.headers ?? {}) },
  });
}

/** Scripted transfer server; `reply` is called once per poll. */
function transferServer(
  reply: (poll: number) => Response,
  calls?: { count: number },
): typeof fetch {
  let poll = 0;
  return (async (input: string | URL | Request) => {
    const url = new URL(String(input));
    if (url.pathname.endsWith('/transaction')) {
      if (calls) calls.count++;
      return reply(poll++);
    }
    throw new Error(`unexpected request to ${url}`);
  }) as unknown as typeof fetch;
}

function audit(fetchImpl: typeof fetch, options: Record<string, unknown> = {}) {
  return auditSep6Polling(DOC, fetchImpl, {
    transactionId: TX_ID,
    intervals: [0, 0, 0],
    pollsPerInterval: 2,
    sleep: async () => {},
    ...options,
  });
}

const BODY = { id: TX_ID, status: 'pending_anchor', amount_in: '10.00' };

describe('SEP-6 polling helpers', () => {
  it('registers the polling rule ids', () => {
    expect(sep6PollingRuleIds).toEqual([
      'sep6/polling-inconsistent-response',
      'sep6/polling-server-error',
      'sep6/polling-stale-cache-headers',
      'sep6/polling-rate-limit-headers',
      'sep6/polling-unknown-status',
      'sep6/polling-unverifiable',
    ]);
  });

  it('treats only explicit cache-busting directives as uncacheable', () => {
    expect(isUncacheable('no-store')).toBe(true);
    expect(isUncacheable('private, max-age=0')).toBe(true);
    expect(isUncacheable('public, max-age=60')).toBe(false);
    expect(isUncacheable(undefined)).toBe(false);
  });

  it('builds a key-order-independent checksum', () => {
    expect(stableChecksum({ a: 1, b: [2, { c: 3 }] })).toBe(
      stableChecksum({ b: [2, { c: 3 }], a: 1 }),
    );
    expect(stableChecksum({ a: 1 })).not.toBe(stableChecksum({ a: 2 }));
  });

  it('knows the SEP-6 statuses', () => {
    expect(SEP6_TRANSACTION_STATUSES).toContain('pending_anchor');
    expect(SEP6_TRANSACTION_STATUSES).toContain('completed');
  });
});

describe('Sep6PollingIdempotencyVerifier', () => {
  it('passes a compliant anchor', async () => {
    const calls = { count: 0 };
    const result = await audit(
      transferServer(
        (poll) =>
          jsonResponse(BODY, {
            headers: {
              'cache-control': 'no-store',
              'ratelimit-limit': '10',
              'ratelimit-remaining': String(9 - poll),
            },
          }),
        calls,
      ),
    );
    expect(result.diagnostics).toEqual([]);
    expect(result.polls).toHaveLength(6);
    expect(calls.count).toBe(6);
    expect(result.polls.every((poll) => (poll.latencyMs ?? -1) >= 0)).toBe(true);
  });

  it('errors when one status carries different payloads', async () => {
    const result = await audit(
      transferServer((poll) =>
        jsonResponse(poll % 2 === 0 ? BODY : { ...BODY, amount_in: '99.00' }, {
          headers: { 'cache-control': 'no-store' },
        }),
      ),
    );
    expect(result.diagnostics.map((d) => d.rule)).toContain('sep6/polling-inconsistent-response');
    expect(result.diagnostics[0]?.severity).toBe('error');
  });

  it('flags a transient server failure for an otherwise stable transaction', async () => {
    const result = await audit(
      transferServer((poll) =>
        poll === 1
          ? jsonResponse(
              { error: 'boom' },
              { status: 503, headers: { 'cache-control': 'no-store' } },
            )
          : jsonResponse(BODY, { headers: { 'cache-control': 'no-store' } }),
      ),
    );
    const rules = result.diagnostics.map((d) => d.rule);
    expect(rules).toContain('sep6/polling-server-error');
    expect(rules).toContain('sep6/polling-inconsistent-response');
  });

  it('warns when the transaction response is cacheable', async () => {
    const result = await audit(
      transferServer(() =>
        jsonResponse(BODY, { headers: { 'cache-control': 'public, max-age=60' } }),
      ),
    );
    expect(result.diagnostics.map((d) => d.rule)).toEqual(['sep6/polling-stale-cache-headers']);
  });

  it('warns when a 429 omits Retry-After', async () => {
    const result = await audit(
      transferServer(() =>
        jsonResponse(
          { status: 'pending_anchor' },
          { status: 429, headers: { 'ratelimit-limit': '5' } },
        ),
      ),
    );
    expect(result.diagnostics.map((d) => d.rule)).toEqual(['sep6/polling-rate-limit-headers']);
    expect(result.diagnostics[0]?.message).toContain('Retry-After');
  });

  it('passes a 429 that carries Retry-After', async () => {
    const result = await audit(
      transferServer(() =>
        jsonResponse(
          { status: 'pending_anchor' },
          { status: 429, headers: { 'retry-after': '5', 'ratelimit-limit': '5' } },
        ),
      ),
    );
    expect(result.diagnostics).toEqual([]);
  });

  it('warns on impossible rate-limit values', async () => {
    const result = await audit(
      transferServer(() =>
        jsonResponse(BODY, {
          headers: {
            'cache-control': 'no-store',
            'ratelimit-limit': '5',
            'ratelimit-remaining': '9',
          },
        }),
      ),
    );
    expect(result.diagnostics.map((d) => d.rule)).toEqual(['sep6/polling-rate-limit-headers']);
  });

  it('warns on a non-SEP-6 status', async () => {
    const result = await audit(
      transferServer(() =>
        jsonResponse(
          { ...BODY, status: 'almost_done' },
          { headers: { 'cache-control': 'no-store' } },
        ),
      ),
    );
    expect(result.diagnostics.map((d) => d.rule)).toEqual(['sep6/polling-unknown-status']);
    expect(result.diagnostics[0]?.message).toContain('almost_done');
  });

  it('reports an unreachable anchor once', async () => {
    const result = await audit((async () => {
      throw new Error('offline');
    }) as unknown as typeof fetch);
    expect(result.diagnostics.map((d) => d.rule)).toEqual(['sep6/polling-unverifiable']);
    expect(result.diagnostics[0]?.severity).toBe('info');
  });

  it('requires a transaction id', async () => {
    let called = 0;
    const result = await audit(
      (async () => {
        called++;
        return jsonResponse({});
      }) as unknown as typeof fetch,
      { transactionId: undefined },
    );
    expect(result.diagnostics.map((d) => d.rule)).toEqual(['sep6/polling-unverifiable']);
    expect(called).toBe(0);
  });

  it('stays silent without a usable TRANSFER_SERVER', async () => {
    const result = await auditSep6Polling({ TRANSFER_SERVER: 'http://insecure' }, fetch, {
      transactionId: TX_ID,
    });
    expect(result.diagnostics).toEqual([]);
    expect(result.polls).toEqual([]);
  });

  it('honours severity overrides', async () => {
    const result = await audit(
      transferServer(() => jsonResponse(BODY)),
      { rules: { 'sep6/polling-stale-cache-headers': 'off' } },
    );
    expect(result.diagnostics).toEqual([]);
  });

  it('uses an injected clock for latency measurement', async () => {
    let tick = 0;
    const result = await new Sep6PollingIdempotencyVerifier(
      transferServer(() => jsonResponse(BODY, { headers: { 'cache-control': 'no-store' } })),
      {
        transactionId: TX_ID,
        intervals: [0],
        pollsPerInterval: 1,
        sleep: async () => {},
        clock: {
          monotonicNow: () => {
            const value = tick;
            tick += 3;
            return value;
          },
        },
      },
    ).verify(DOC);
    expect(result.diagnostics).toEqual([]);
    expect(result.polls[0]?.latencyMs).toBe(3);
  });
});
