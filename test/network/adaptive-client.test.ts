import { describe, expect, it, vi } from 'vitest';
import {
  AdaptiveClient,
  CircuitOpenError,
  DEFAULT_CAP_DELAY_MS,
  DEFAULT_FAILURE_THRESHOLD,
  DEFAULT_MAX_ATTEMPTS,
  DEFAULT_RETRY_STATUSES,
  adaptiveFetch,
  createAdaptiveFetch,
  fullJitterDelay,
  isRetryableError,
} from '../../src/network/adaptive-client.js';

/** A `Response` with just enough shape for the client to classify it. */
function reply(status: number, headers: Record<string, string> = {}): Response {
  return new Response(status === 204 ? null : 'body', { status, headers });
}

/**
 * A scripted transport. Each entry is returned (or thrown) in order; the last
 * entry repeats once the script runs out, so "always 503" needs one line.
 */
function scripted(script: Array<Response | Error | (() => Response | Error)>): {
  fetchImpl: typeof fetch;
  calls: string[];
} {
  const calls: string[] = [];
  let index = 0;
  const fetchImpl = (async (input: RequestInfo | URL) => {
    calls.push(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
    const entry = script[Math.min(index++, script.length - 1)];
    const value = typeof entry === 'function' ? entry() : entry;
    if (value instanceof Error) throw value;
    return value as Response;
  }) as typeof fetch;
  return { fetchImpl, calls };
}

/** Collects the sleeps a client asks for without actually waiting. */
function recordingSleep(): { sleep: (ms: number) => Promise<void>; slept: number[] } {
  const slept: number[] = [];
  return {
    slept,
    sleep: (ms: number) => {
      slept.push(ms);
      return Promise.resolve();
    },
  };
}

/** A transport error shaped the way Node's `fetch` reports one. */
function transportError(code: string): Error {
  const error = new TypeError('fetch failed');
  (error as TypeError & { cause?: unknown }).cause = Object.assign(new Error(code), { code });
  return error;
}

describe('fullJitterDelay', () => {
  it('draws from [0, base * 2 ** attempt) as the formula states', () => {
    // random() = 1 - epsilon gives the top of the window; the ceiling itself
    // is exclusive, so assert against the open interval.
    const almostOne = () => 0.999999;
    expect(fullJitterDelay(0, 200, 5_000, almostOne)).toBe(199);
    expect(fullJitterDelay(1, 200, 5_000, almostOne)).toBe(399);
    expect(fullJitterDelay(2, 200, 5_000, almostOne)).toBe(799);
    expect(fullJitterDelay(3, 200, 5_000, almostOne)).toBe(1599);
  });

  it('returns zero on the low end of the draw, which is what "full" jitter means', () => {
    // Decorrelated retries need a real chance of retrying immediately;
    // "equal jitter" variants that floor at base/2 do not have it.
    expect(fullJitterDelay(5, 200, 5_000, () => 0)).toBe(0);
  });

  it('never exceeds the cap however many attempts have elapsed', () => {
    for (const attempt of [4, 8, 16, 64, 1_000]) {
      expect(fullJitterDelay(attempt, 200, 1_000, () => 0.999999)).toBeLessThan(1_000);
    }
  });

  it('is monotonic in the draw for a fixed attempt', () => {
    const low = fullJitterDelay(3, 100, 10_000, () => 0.1);
    const high = fullJitterDelay(3, 100, 10_000, () => 0.9);
    expect(high).toBeGreaterThan(low);
  });
});

describe('isRetryableError', () => {
  it('retries timeouts, resets, refusals, and transient resolver failures', () => {
    expect(isRetryableError(Object.assign(new Error('aborted'), { name: 'AbortError' }))).toBe(
      true,
    );
    expect(isRetryableError(transportError('ECONNRESET'))).toBe(true);
    expect(isRetryableError(transportError('ECONNREFUSED'))).toBe(true);
    expect(isRetryableError(transportError('ETIMEDOUT'))).toBe(true);
    expect(isRetryableError(transportError('EAI_AGAIN'))).toBe(true);
  });

  it('does not retry a name that does not resolve or a certificate that does not validate', () => {
    // These are findings about the endpoint, not weather. Retrying them only
    // makes the report slower while reaching the same conclusion.
    expect(isRetryableError(transportError('ENOTFOUND'))).toBe(false);
    expect(isRetryableError(transportError('CERT_HAS_EXPIRED'))).toBe(false);
    expect(isRetryableError(transportError('ERR_TLS_CERT_ALTNAME_INVALID'))).toBe(false);
    expect(isRetryableError(transportError('DEPTH_ZERO_SELF_SIGNED_CERT'))).toBe(false);
  });

  it('does not retry an open circuit, which would defeat the breaker', () => {
    expect(isRetryableError(new CircuitOpenError('https://a.example', 5, 30_000))).toBe(false);
  });
});

describe('AdaptiveClient retries', () => {
  it('recovers a 503 on the next attempt and returns the 200', async () => {
    const { fetchImpl, calls } = scripted([reply(503), reply(200)]);
    const { sleep, slept } = recordingSleep();
    const client = new AdaptiveClient({ fetchImpl, sleep, random: () => 0.5, baseDelayMs: 200 });

    const response = await client.fetch('https://anchor.example/.well-known/stellar.toml');

    expect(response.status).toBe(200);
    expect(calls).toHaveLength(2);
    // One backoff, drawn from [0, 200) at random() = 0.5.
    expect(slept).toEqual([100]);
  });

  it.each(DEFAULT_RETRY_STATUSES)('retries status %i', async (status) => {
    const { fetchImpl, calls } = scripted([reply(status), reply(200)]);
    const client = new AdaptiveClient({ fetchImpl, sleep: () => Promise.resolve() });

    expect((await client.fetch('https://anchor.example/')).status).toBe(200);
    expect(calls).toHaveLength(2);
  });

  it.each([200, 201, 204, 301, 400, 401, 403, 404, 410, 501])(
    'does not retry status %i',
    async (status) => {
      const { fetchImpl, calls } = scripted([reply(status)]);
      const client = new AdaptiveClient({ fetchImpl, sleep: () => Promise.resolve() });

      expect((await client.fetch('https://anchor.example/')).status).toBe(status);
      expect(calls).toHaveLength(1);
    },
  );

  it('returns the last response rather than throwing when retries run out', async () => {
    // A rule that asked for a 503 must see the 503: the report should say what
    // was observed, not "an internal error occurred".
    const { fetchImpl, calls } = scripted([reply(503)]);
    const client = new AdaptiveClient({ fetchImpl, sleep: () => Promise.resolve() });

    const response = await client.fetch('https://anchor.example/');

    expect(response.status).toBe(503);
    expect(calls).toHaveLength(DEFAULT_MAX_ATTEMPTS);
  });

  it('backs off exponentially across attempts', async () => {
    const { fetchImpl } = scripted([reply(503)]);
    const { sleep, slept } = recordingSleep();
    const client = new AdaptiveClient({
      fetchImpl,
      sleep,
      random: () => 0.999999,
      baseDelayMs: 100,
      capDelayMs: 10_000,
      maxAttempts: 5,
      honorRetryAfter: false,
    });

    await client.fetch('https://anchor.example/');

    expect(slept).toEqual([99, 199, 399, 799]);
  });

  it('retries a transport timeout and succeeds', async () => {
    const { fetchImpl, calls } = scripted([transportError('ETIMEDOUT'), reply(200)]);
    const client = new AdaptiveClient({ fetchImpl, sleep: () => Promise.resolve() });

    expect((await client.fetch('https://anchor.example/')).status).toBe(200);
    expect(calls).toHaveLength(2);
  });

  it('gives up immediately on a permanent transport error', async () => {
    const { fetchImpl, calls } = scripted([transportError('ENOTFOUND')]);
    const client = new AdaptiveClient({ fetchImpl, sleep: () => Promise.resolve() });

    await expect(client.fetch('https://nope.invalid/')).rejects.toThrow('fetch failed');
    expect(calls).toHaveLength(1);
  });

  it('rethrows the last transport error when every attempt threw', async () => {
    const { fetchImpl, calls } = scripted([transportError('ECONNRESET')]);
    const client = new AdaptiveClient({ fetchImpl, sleep: () => Promise.resolve() });

    await expect(client.fetch('https://anchor.example/')).rejects.toThrow('fetch failed');
    expect(calls).toHaveLength(DEFAULT_MAX_ATTEMPTS);
  });

  it('makes exactly one attempt when configured not to retry', async () => {
    const { fetchImpl, calls } = scripted([reply(503)]);
    const client = new AdaptiveClient({
      fetchImpl,
      maxAttempts: 1,
      sleep: () => Promise.resolve(),
    });

    expect((await client.fetch('https://anchor.example/')).status).toBe(503);
    expect(calls).toHaveLength(1);
  });

  it('reports each retry to the observer', async () => {
    const events: Array<{ attempt: number; status?: number; delayMs: number }> = [];
    const { fetchImpl } = scripted([reply(429), reply(503), reply(200)]);
    const client = new AdaptiveClient({
      fetchImpl,
      sleep: () => Promise.resolve(),
      random: () => 0,
      honorRetryAfter: false,
      onRetry: (event) =>
        events.push({
          attempt: event.attempt,
          ...(event.status === undefined ? {} : { status: event.status }),
          delayMs: event.delayMs,
        }),
    });

    await client.fetch('https://anchor.example/');

    expect(events).toEqual([
      { attempt: 0, status: 429, delayMs: 0 },
      { attempt: 1, status: 503, delayMs: 0 },
    ]);
  });

  it('survives an observer that throws', async () => {
    const { fetchImpl } = scripted([reply(503), reply(200)]);
    const client = new AdaptiveClient({
      fetchImpl,
      sleep: () => Promise.resolve(),
      onRetry: () => {
        throw new Error('observer exploded');
      },
    });

    expect((await client.fetch('https://anchor.example/')).status).toBe(200);
  });
});

describe('AdaptiveClient Retry-After', () => {
  it('prefers the delay a rate-limiter states over the jitter draw', async () => {
    const { fetchImpl } = scripted([reply(429, { 'retry-after': '2' }), reply(200)]);
    const { sleep, slept } = recordingSleep();
    const client = new AdaptiveClient({ fetchImpl, sleep, random: () => 0.5, baseDelayMs: 200 });

    await client.fetch('https://cdn.example/');

    expect(slept).toEqual([2_000]);
  });

  it('accepts an HTTP-date Retry-After', async () => {
    const now = Date.UTC(2026, 0, 1, 12, 0, 0);
    const header = new Date(now + 3_000).toUTCString();
    const { fetchImpl } = scripted([reply(503, { 'retry-after': header }), reply(200)]);
    const { sleep, slept } = recordingSleep();
    const client = new AdaptiveClient({ fetchImpl, sleep, now: () => now });

    await client.fetch('https://cdn.example/');

    expect(slept).toEqual([3_000]);
  });

  it('caps a hostile Retry-After so one header cannot hang CI', async () => {
    const { fetchImpl } = scripted([reply(429, { 'retry-after': '86400' }), reply(200)]);
    const { sleep, slept } = recordingSleep();
    const client = new AdaptiveClient({ fetchImpl, sleep, capDelayMs: DEFAULT_CAP_DELAY_MS });

    await client.fetch('https://cdn.example/');

    expect(slept).toEqual([DEFAULT_CAP_DELAY_MS]);
  });

  it('falls back to jitter when Retry-After is unparseable', async () => {
    const { fetchImpl } = scripted([reply(429, { 'retry-after': 'soon-ish' }), reply(200)]);
    const { sleep, slept } = recordingSleep();
    const client = new AdaptiveClient({ fetchImpl, sleep, random: () => 0.5, baseDelayMs: 400 });

    await client.fetch('https://cdn.example/');

    expect(slept).toEqual([200]);
  });

  it('ignores Retry-After entirely when asked to', async () => {
    const { fetchImpl } = scripted([reply(429, { 'retry-after': '30' }), reply(200)]);
    const { sleep, slept } = recordingSleep();
    const client = new AdaptiveClient({
      fetchImpl,
      sleep,
      random: () => 0,
      honorRetryAfter: false,
    });

    await client.fetch('https://cdn.example/');

    expect(slept).toEqual([0]);
  });
});

describe('AdaptiveClient circuit breaker', () => {
  it('trips after the threshold of consecutive failures and fails fast after that', async () => {
    const { fetchImpl, calls } = scripted([transportError('ECONNREFUSED')]);
    const client = new AdaptiveClient({
      fetchImpl,
      sleep: () => Promise.resolve(),
      maxAttempts: 1,
      failureThreshold: DEFAULT_FAILURE_THRESHOLD,
    });

    for (let i = 0; i < DEFAULT_FAILURE_THRESHOLD; i++) {
      await expect(client.fetch('https://down.example/a')).rejects.toThrow('fetch failed');
    }
    expect(calls).toHaveLength(DEFAULT_FAILURE_THRESHOLD);
    expect(client.circuitFor('https://down.example/a').state).toBe('open');

    // The sixth request never reaches the transport.
    await expect(client.fetch('https://down.example/b')).rejects.toThrow(CircuitOpenError);
    expect(calls).toHaveLength(DEFAULT_FAILURE_THRESHOLD);
  });

  it('keys the breaker by origin, so a dead host does not mute a healthy one', async () => {
    const fetchImpl = (async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.startsWith('https://down.example')) throw transportError('ECONNREFUSED');
      return reply(200);
    }) as typeof fetch;
    const client = new AdaptiveClient({
      fetchImpl,
      sleep: () => Promise.resolve(),
      maxAttempts: 1,
      failureThreshold: 2,
    });

    await expect(client.fetch('https://down.example/x')).rejects.toThrow('fetch failed');
    await expect(client.fetch('https://down.example/y')).rejects.toThrow('fetch failed');
    expect(client.circuitFor('https://down.example/').state).toBe('open');

    expect((await client.fetch('https://up.example/x')).status).toBe(200);
    expect(client.circuitFor('https://up.example/').state).toBe('closed');
  });

  it('counts a retry-exhausted run of 503s as one failure, not one per attempt', async () => {
    // Otherwise a single request with four attempts would trip a
    // five-failure breaker almost immediately, and the breaker would be
    // measuring our own retry budget rather than the host's health.
    const { fetchImpl } = scripted([reply(503)]);
    const client = new AdaptiveClient({ fetchImpl, sleep: () => Promise.resolve() });

    await client.fetch('https://flaky.example/');

    expect(client.circuitFor('https://flaky.example/').consecutiveFailures).toBe(1);
  });

  it('resets the count on any definitive answer, including a 404', async () => {
    const { fetchImpl } = scripted([
      transportError('ECONNRESET'),
      transportError('ECONNRESET'),
      reply(404),
    ]);
    const client = new AdaptiveClient({
      fetchImpl,
      sleep: () => Promise.resolve(),
      maxAttempts: 1,
      failureThreshold: 5,
    });

    await expect(client.fetch('https://anchor.example/')).rejects.toThrow();
    await expect(client.fetch('https://anchor.example/')).rejects.toThrow();
    expect(client.circuitFor('https://anchor.example/').consecutiveFailures).toBe(2);

    expect((await client.fetch('https://anchor.example/')).status).toBe(404);
    expect(client.circuitFor('https://anchor.example/').consecutiveFailures).toBe(0);
  });

  it('half-opens after the reset window and closes on a successful probe', async () => {
    let clock = 1_000;
    const { fetchImpl } = scripted([
      transportError('ECONNREFUSED'),
      transportError('ECONNREFUSED'),
      reply(200),
    ]);
    const client = new AdaptiveClient({
      fetchImpl,
      sleep: () => Promise.resolve(),
      now: () => clock,
      maxAttempts: 1,
      failureThreshold: 2,
      resetAfterMs: 30_000,
    });

    await expect(client.fetch('https://down.example/')).rejects.toThrow();
    await expect(client.fetch('https://down.example/')).rejects.toThrow();
    expect(client.circuitFor('https://down.example/').state).toBe('open');

    await expect(client.fetch('https://down.example/')).rejects.toThrow(CircuitOpenError);

    clock += 30_000;
    expect(client.circuitFor('https://down.example/').state).toBe('half-open');

    expect((await client.fetch('https://down.example/')).status).toBe(200);
    expect(client.circuitFor('https://down.example/').state).toBe('closed');
  });

  it('re-opens with a fresh clock when the half-open probe also fails', async () => {
    let clock = 0;
    const { fetchImpl } = scripted([transportError('ECONNREFUSED')]);
    const client = new AdaptiveClient({
      fetchImpl,
      sleep: () => Promise.resolve(),
      now: () => clock,
      maxAttempts: 1,
      failureThreshold: 1,
      resetAfterMs: 10_000,
    });

    await expect(client.fetch('https://down.example/')).rejects.toThrow('fetch failed');
    clock = 10_000;
    await expect(client.fetch('https://down.example/')).rejects.toThrow('fetch failed');

    expect(client.circuitFor('https://down.example/').openedAt).toBe(10_000);
    expect(client.circuitFor('https://down.example/').state).toBe('open');
  });

  it('names the origin and the wait in the CircuitOpenError', async () => {
    const { fetchImpl } = scripted([transportError('ECONNREFUSED')]);
    const client = new AdaptiveClient({
      fetchImpl,
      sleep: () => Promise.resolve(),
      now: () => 0,
      maxAttempts: 1,
      failureThreshold: 1,
      resetAfterMs: 30_000,
    });

    await expect(client.fetch('https://down.example/a')).rejects.toThrow();

    const error = await client.fetch('https://down.example/b').catch((e: unknown) => e);
    expect(error).toBeInstanceOf(CircuitOpenError);
    const circuitError = error as CircuitOpenError;
    expect(circuitError.origin).toBe('https://down.example');
    expect(circuitError.failures).toBe(1);
    expect(circuitError.retryInMs).toBe(30_000);
    expect(circuitError.message).toContain('circuit open for https://down.example');
  });

  it('can be disabled, so a breaker never masks a host under test', async () => {
    const { fetchImpl, calls } = scripted([transportError('ECONNREFUSED')]);
    const client = new AdaptiveClient({
      fetchImpl,
      sleep: () => Promise.resolve(),
      maxAttempts: 1,
      failureThreshold: 0,
    });

    for (let i = 0; i < 10; i++) {
      await expect(client.fetch('https://down.example/')).rejects.toThrow('fetch failed');
    }
    expect(calls).toHaveLength(10);
    expect(client.circuitFor('https://down.example/').state).toBe('closed');
  });

  it('forgets everything on resetCircuits()', async () => {
    const { fetchImpl } = scripted([transportError('ECONNREFUSED')]);
    const client = new AdaptiveClient({
      fetchImpl,
      sleep: () => Promise.resolve(),
      maxAttempts: 1,
      failureThreshold: 1,
    });

    await expect(client.fetch('https://down.example/')).rejects.toThrow();
    expect(client.circuitFor('https://down.example/').state).toBe('open');

    client.resetCircuits();
    expect(client.circuitFor('https://down.example/').state).toBe('closed');
  });

  it('treats an unparseable URL as its own circuit key instead of throwing', async () => {
    const { fetchImpl } = scripted([transportError('ECONNREFUSED')]);
    const client = new AdaptiveClient({
      fetchImpl,
      sleep: () => Promise.resolve(),
      maxAttempts: 1,
      failureThreshold: 1,
    });

    await expect(client.fetch('not-a-url')).rejects.toThrow('fetch failed');
    expect(client.circuitFor('not-a-url').state).toBe('open');
  });
});

describe('AdaptiveClient per-attempt timeout', () => {
  it('aborts an attempt that outlives the deadline and retries it', async () => {
    const seen: Array<AbortSignal | null | undefined> = [];
    let call = 0;
    const fetchImpl = (async (_input: RequestInfo | URL, init?: RequestInit) => {
      seen.push(init?.signal);
      if (call++ === 0) {
        // Resolve only once the deadline has fired, the way a hung socket does.
        return new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () =>
            reject(Object.assign(new Error('aborted'), { name: 'AbortError' })),
          );
        });
      }
      return reply(200);
    }) as typeof fetch;

    const client = new AdaptiveClient({ fetchImpl, sleep: () => Promise.resolve(), timeoutMs: 5 });

    expect((await client.fetch('https://slow.example/')).status).toBe(200);
    expect(seen).toHaveLength(2);
    expect(seen[0]).toBeInstanceOf(AbortSignal);
  });

  it("chains the caller's own signal so cancelling the run cancels the attempt", async () => {
    const controller = new AbortController();
    controller.abort();
    const fetchImpl = (async (_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.signal?.aborted) {
        throw Object.assign(new Error('aborted'), { name: 'AbortError' });
      }
      return reply(200);
    }) as typeof fetch;

    const client = new AdaptiveClient({
      fetchImpl,
      sleep: () => Promise.resolve(),
      maxAttempts: 1,
      timeoutMs: 1_000,
    });

    await expect(
      client.fetch('https://anchor.example/', { signal: controller.signal }),
    ).rejects.toThrow('aborted');
  });

  it('passes the request straight through when the timeout is disabled', async () => {
    const seen: Array<AbortSignal | null | undefined> = [];
    const fetchImpl = (async (_input: RequestInfo | URL, init?: RequestInit) => {
      seen.push(init?.signal);
      return reply(200);
    }) as typeof fetch;
    const client = new AdaptiveClient({ fetchImpl, timeoutMs: 0 });

    await client.fetch('https://anchor.example/');

    expect(seen).toEqual([undefined]);
  });
});

describe('fetch compatibility', () => {
  it('is assignable wherever a bare fetch is, and forwards init unchanged', async () => {
    const seen: RequestInit[] = [];
    const fetchImpl = (async (_input: RequestInfo | URL, init?: RequestInit) => {
      if (init) seen.push(init);
      return reply(200);
    }) as typeof fetch;

    // The shape every rule's `fetchImpl` parameter expects.
    const transport: typeof fetch = createAdaptiveFetch({ fetchImpl, timeoutMs: 0 });
    await transport('https://anchor.example/', { method: 'HEAD', redirect: 'follow' });

    expect(seen[0]?.method).toBe('HEAD');
    expect(seen[0]?.redirect).toBe('follow');
  });

  it('accepts the URL and Request input forms', async () => {
    const { fetchImpl, calls } = scripted([reply(200), reply(200)]);
    const transport = createAdaptiveFetch({ fetchImpl, timeoutMs: 0 });

    await transport(new URL('https://anchor.example/one'));
    await transport(new Request('https://anchor.example/two'));

    expect(calls).toEqual(['https://anchor.example/one', 'https://anchor.example/two']);
  });

  it('exports a shared default transport so one dead host is learned once', () => {
    // The rules import this one; a per-call client would give the breaker
    // nothing to remember across the rules that fan out to the same host.
    expect(typeof adaptiveFetch).toBe('function');
  });
});

describe('rule call sites', () => {
  it('default to the adaptive transport rather than a raw fetch', async () => {
    const { readdirSync, readFileSync } = await import('node:fs');
    const { dirname, join } = await import('node:path');
    const { fileURLToPath } = await import('node:url');

    const rulesDir = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'src', 'rules');
    const files = readdirSync(rulesDir).filter((name) => name.endsWith('.ts'));

    const raw: string[] = [];
    for (const file of files) {
      const source = readFileSync(join(rulesDir, file), 'utf8');
      // A default of `fetch`/`globalThis.fetch` means that call site opted out
      // of retries and the breaker without saying why.
      if (/fetchImpl: typeof fetch = (globalThis\.)?fetch,/.test(source)) raw.push(file);
    }

    expect(raw).toEqual([]);
  });

  it('keeps an injected transport authoritative, so stubs stay hermetic', async () => {
    const { checkOrgUrl } = await import('../../src/rules/org-url-check.js');
    const stub = vi.fn(async () => reply(200));

    await checkOrgUrl({ DOCUMENTATION: { ORG_URL: 'https://example.com' } }, stub as typeof fetch);

    expect(stub).toHaveBeenCalled();
  });
});
