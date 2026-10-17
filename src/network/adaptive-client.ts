/**
 * Adaptive HTTP client: full-jitter retries and a per-origin circuit breaker
 * (issue #381).
 *
 * A full `--check-network` run fans out across dozens of third-party hosts:
 * Horizon, Soroban RPC, every `CURRENCIES[].toml` pointer, every service
 * endpoint, every validator history archive. One raw `fetch` per endpoint makes
 * the report only as reliable as the flakiest host in it — a CDN that
 * rate-limits the third request in a burst, or a load balancer that sheds one
 * connection with a 503, turns into a lint *finding* about the anchor's
 * configuration. That is the worst failure mode this tool has: it tells an
 * operator their file is broken when the network hiccuped.
 *
 * Two mechanisms fix that, and they pull in opposite directions:
 *
 * - **Retries with full jitter** turn a transient failure into a slower
 *   success. The sleep before attempt `n` is
 *   `random(0, min(cap, base * 2 ** n))` — the "full jitter" variant from
 *   AWS's *Exponential Backoff and Jitter*. Decorrelating the sleeps matters
 *   here specifically because a lint run issues its requests in parallel
 *   bursts: undecorrelated backoff would retry all of them at the same instant
 *   and re-trigger the same rate limit.
 * - **A circuit breaker** stops retries from turning one dead host into a
 *   stalled pipeline. After {@link DEFAULT_FAILURE_THRESHOLD} consecutive
 *   failures an origin is tripped open, and every further request to it fails
 *   immediately with {@link CircuitOpenError} instead of spending the whole
 *   retry budget again. Without this, a hosting provider that went down
 *   overnight would multiply its own latency by the number of endpoints the
 *   file names.
 *
 * The breaker is keyed by origin rather than by URL, because the thing that
 * fails is a host, not a path: once `https://anchor.example` has refused five
 * requests, the sixth path on it is not worth the wait.
 *
 * Everything that makes a retry loop untestable — the clock, the sleep, the
 * random draw — is injectable, so {@link createAdaptiveFetch} can be driven
 * deterministically in a test without real delays. Callers that already accept
 * a `fetchImpl` keep working unchanged: the wrapper *is* a `fetch`, so it
 * composes both ways (wrap a stub, or hand the wrapper to a stub-taking
 * function).
 */

/** Status codes that mean "try again", not "your request is wrong". */
export const DEFAULT_RETRY_STATUSES: readonly number[] = [408, 425, 429, 500, 502, 503, 504];

/** Attempts in total, counting the first one. Three retries at most. */
export const DEFAULT_MAX_ATTEMPTS = 4;

/** `base` in `random(0, min(cap, base * 2 ** attempt))`. */
export const DEFAULT_BASE_DELAY_MS = 200;

/** `cap` in the same expression: no single sleep exceeds this. */
export const DEFAULT_CAP_DELAY_MS = 5_000;

/** How long one attempt may run before it is aborted and counted a timeout. */
export const DEFAULT_TIMEOUT_MS = 10_000;

/** Consecutive failures against one origin before its circuit trips open. */
export const DEFAULT_FAILURE_THRESHOLD = 5;

/** How long a tripped circuit stays open before one probe request is allowed. */
export const DEFAULT_RESET_AFTER_MS = 30_000;

/**
 * `cause.code` values that no number of retries will change.
 *
 * A name that does not resolve, or a certificate that does not validate, is a
 * finding about the endpoint — retrying it three times only makes the report
 * slower while reaching the same conclusion. Everything *not* listed here
 * (resets, refusals, timeouts, transient resolver failures) is retried.
 */
const PERMANENT_ERROR_CODES: ReadonlySet<string> = new Set([
  'ENOTFOUND',
  'ERR_INVALID_URL',
  'ERR_TLS_CERT_ALTNAME_INVALID',
  'CERT_HAS_EXPIRED',
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'SELF_SIGNED_CERT_IN_CHAIN',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'ERR_SSL_WRONG_VERSION_NUMBER',
]);

/** Knobs for {@link AdaptiveClient}. Every one has a documented default. */
export interface AdaptiveClientOptions {
  /** The transport to wrap. Defaults to the global `fetch`. */
  fetchImpl?: typeof fetch;
  /** Total attempts including the first. Values below 1 are clamped to 1. */
  maxAttempts?: number;
  /** `base` of the backoff expression, in milliseconds. */
  baseDelayMs?: number;
  /** `cap` of the backoff expression, in milliseconds. */
  capDelayMs?: number;
  /** Per-attempt deadline. `0` disables the timeout. */
  timeoutMs?: number;
  /** Response statuses to retry. Defaults to {@link DEFAULT_RETRY_STATUSES}. */
  retryStatuses?: readonly number[];
  /** Consecutive failures that trip an origin's circuit. `0` disables it. */
  failureThreshold?: number;
  /** How long a tripped circuit stays open before admitting a probe. */
  resetAfterMs?: number;
  /**
   * Honour a `Retry-After` header when the server sends one, capped by
   * `capDelayMs`. A server that states its own backoff knows better than our
   * formula; the cap stops a hostile or mistaken header from hanging CI.
   */
  honorRetryAfter?: boolean;
  /** Source of the jitter draw in `[0, 1)`. Injected by tests. */
  random?: () => number;
  /** Sleep implementation. Injected by tests to avoid real delays. */
  sleep?: (ms: number) => Promise<void>;
  /** Clock used for circuit timing. Injected by tests. */
  now?: () => number;
  /** Called once per attempt. Observability hook; must not throw. */
  onRetry?: (event: RetryEvent) => void;
}

/** What one exhausted attempt did, reported to {@link AdaptiveClientOptions.onRetry}. */
export interface RetryEvent {
  /** The URL the attempt targeted. */
  url: string;
  /** 0-based index of the attempt that just failed. */
  attempt: number;
  /** Attempts the client will make in total. */
  maxAttempts: number;
  /** Milliseconds the client will sleep before the next attempt. */
  delayMs: number;
  /** Status that triggered the retry, when the failure was a response. */
  status?: number;
  /** Error that triggered the retry, when the failure was a transport error. */
  error?: unknown;
}

/**
 * Thrown instead of a request when an origin's circuit is open.
 *
 * A distinct type rather than a generic `Error` so a caller that wants to
 * report "not checked" differently from "checked and failed" can tell them
 * apart. Callers that do not care treat it like any other transport failure,
 * which is why every rule's `catch` already handles it correctly.
 */
export class CircuitOpenError extends Error {
  /** The origin whose circuit is open, e.g. `https://anchor.example`. */
  readonly origin: string;
  /** Consecutive failures recorded against the origin when it tripped. */
  readonly failures: number;
  /** Milliseconds until the circuit admits a probe request. */
  readonly retryInMs: number;

  constructor(origin: string, failures: number, retryInMs: number) {
    super(
      `circuit open for ${origin} after ${failures} consecutive failures; retrying in ${Math.ceil(
        retryInMs / 1000,
      )}s`,
    );
    this.name = 'CircuitOpenError';
    this.origin = origin;
    this.failures = failures;
    this.retryInMs = retryInMs;
  }
}

/** A circuit's three states, in the usual breaker vocabulary. */
export type CircuitState = 'closed' | 'open' | 'half-open';

/** One origin's breaker bookkeeping, as {@link AdaptiveClient.circuitFor} reports it. */
export interface CircuitSnapshot {
  origin: string;
  state: CircuitState;
  consecutiveFailures: number;
  /** When the circuit last tripped, or `undefined` while it is closed. */
  openedAt?: number;
}

interface CircuitRecord {
  consecutiveFailures: number;
  openedAt?: number;
}

/**
 * The full-jitter sleep before a given attempt.
 *
 * `sleep = random(0, min(cap, base * 2 ** attempt))`, where `attempt` is
 * 0-based: the wait before the first *retry* draws from `[0, base)`. Exported
 * because the distribution is the part of this module worth asserting on
 * directly, and because the benchmark suite reuses it.
 */
export function fullJitterDelay(
  attempt: number,
  baseDelayMs: number = DEFAULT_BASE_DELAY_MS,
  capDelayMs: number = DEFAULT_CAP_DELAY_MS,
  random: () => number = Math.random,
): number {
  // 2 ** attempt overflows into Infinity long before it matters; min() with the
  // cap makes that harmless, but clamp the exponent so the arithmetic stays
  // inspectable in a stack trace.
  const exponent = Math.min(Math.max(attempt, 0), 32);
  const ceiling = Math.min(capDelayMs, baseDelayMs * 2 ** exponent);
  if (!(ceiling > 0)) return 0;
  return Math.floor(random() * ceiling);
}

/** `true` when a transport error is worth another attempt. */
export function isRetryableError(error: unknown): boolean {
  if (error instanceof CircuitOpenError) return false;

  // An abort is how the per-attempt timeout surfaces, and a timeout is the
  // canonical transient failure this client exists to absorb.
  if (error instanceof Error && (error.name === 'AbortError' || error.name === 'TimeoutError')) {
    return true;
  }

  const code = errorCode(error);
  if (code !== undefined && PERMANENT_ERROR_CODES.has(code)) return false;

  // `fetch` reports every transport failure as the same opaque
  // `TypeError: fetch failed`, with the real reason on `cause`. Anything that
  // reached us as a transport error and was not ruled out above gets another
  // attempt.
  return error instanceof Error;
}

/** Walks `cause` chains for a `code`, which is where Node hides the real reason. */
function errorCode(error: unknown): string | undefined {
  let current: unknown = error;
  for (let depth = 0; depth < 8 && current instanceof Error; depth++) {
    const code = (current as Error & { code?: unknown }).code;
    if (typeof code === 'string') return code;
    current = (current as Error & { cause?: unknown }).cause;
  }
  return undefined;
}

/** The origin a URL belongs to, or the raw input when it will not parse. */
function originOf(url: string): string {
  try {
    return new URL(url).origin;
  } catch {
    return url;
  }
}

/** The request target as a string, for whichever of `fetch`'s input forms it is. */
function urlOf(input: RequestInfo | URL): string {
  if (typeof input === 'string') return input;
  if (input instanceof URL) return input.href;
  return input.url;
}

/** `Retry-After` in milliseconds — seconds or an HTTP date — or `undefined`. */
function retryAfterMs(response: Response, now: number): number | undefined {
  const header = response.headers?.get?.('retry-after');
  if (header === null || header === undefined || header.trim() === '') return undefined;

  const seconds = Number(header);
  if (Number.isFinite(seconds)) return seconds >= 0 ? seconds * 1000 : undefined;

  const date = Date.parse(header);
  if (Number.isNaN(date)) return undefined;
  const delta = date - now;
  return delta > 0 ? delta : 0;
}

function defaultSleep(ms: number): Promise<void> {
  if (ms <= 0) return Promise.resolve();
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    // Never let a pending backoff keep the CLI process alive past its report.
    if (typeof timer === 'object' && timer !== null && 'unref' in timer) timer.unref();
  });
}

/**
 * A `fetch`-shaped transport with retries, full-jitter backoff, and a
 * per-origin circuit breaker.
 *
 * Instances hold the breaker state, so a long-lived client is what gives the
 * breaker anything to remember. {@link adaptiveFetch} is the process-wide
 * instance the rules use by default; construct your own when you want isolated
 * state (every test does).
 */
export class AdaptiveClient {
  private readonly fetchImpl: typeof fetch;
  private readonly maxAttempts: number;
  private readonly baseDelayMs: number;
  private readonly capDelayMs: number;
  private readonly timeoutMs: number;
  private readonly retryStatuses: ReadonlySet<number>;
  private readonly failureThreshold: number;
  private readonly resetAfterMs: number;
  private readonly honorRetryAfter: boolean;
  private readonly random: () => number;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly now: () => number;
  private readonly onRetry: ((event: RetryEvent) => void) | undefined;
  private readonly circuits = new Map<string, CircuitRecord>();

  constructor(options: AdaptiveClientOptions = {}) {
    this.fetchImpl = options.fetchImpl ?? ((...args) => globalThis.fetch(...args));
    this.maxAttempts = Math.max(1, Math.trunc(options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS));
    this.baseDelayMs = Math.max(0, options.baseDelayMs ?? DEFAULT_BASE_DELAY_MS);
    this.capDelayMs = Math.max(0, options.capDelayMs ?? DEFAULT_CAP_DELAY_MS);
    this.timeoutMs = Math.max(0, options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
    this.retryStatuses = new Set(options.retryStatuses ?? DEFAULT_RETRY_STATUSES);
    this.failureThreshold = Math.max(
      0,
      Math.trunc(options.failureThreshold ?? DEFAULT_FAILURE_THRESHOLD),
    );
    this.resetAfterMs = Math.max(0, options.resetAfterMs ?? DEFAULT_RESET_AFTER_MS);
    this.honorRetryAfter = options.honorRetryAfter ?? true;
    this.random = options.random ?? Math.random;
    this.sleep = options.sleep ?? defaultSleep;
    this.now = options.now ?? Date.now;
    this.onRetry = options.onRetry;

    // Bound up front so `client.fetch` can be passed wherever a bare `fetch`
    // is expected — which is the whole point of the wrapper.
    this.fetch = this.fetch.bind(this);
  }

  /**
   * Performs one logical request, retrying transient failures.
   *
   * Resolves with the last response when the retries are exhausted — a run
   * that ends on a 503 still gets the 503, so the calling rule reports what it
   * observed rather than a synthetic error. Rejects only when every attempt
   * threw, or when the origin's circuit is open.
   */
  async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const url = urlOf(input);
    const origin = originOf(url);

    const open = this.rejectIfOpen(origin);
    if (open !== undefined) throw open;

    let lastResponse: Response | undefined;
    let lastError: unknown;

    for (let attempt = 0; attempt < this.maxAttempts; attempt++) {
      let response: Response | undefined;
      let error: unknown;

      try {
        response = await this.attempt(input, init);
      } catch (thrown) {
        error = thrown;
      }

      if (response !== undefined && !this.retryStatuses.has(response.status)) {
        // Any definitive answer — 200, 404, 400 — closes the circuit. The host
        // is up; what it said about this request is the rule's business.
        this.recordSuccess(origin);
        return response;
      }

      if (error !== undefined && !isRetryableError(error)) {
        this.recordFailure(origin);
        throw error;
      }

      if (response !== undefined) lastResponse = response;
      if (error !== undefined) lastError = error;

      const isLast = attempt === this.maxAttempts - 1;
      if (isLast) break;

      const delayMs = this.delayFor(attempt, response);
      this.notify({
        url,
        attempt,
        maxAttempts: this.maxAttempts,
        delayMs,
        ...(response === undefined ? {} : { status: response.status }),
        ...(error === undefined ? {} : { error }),
      });
      await this.sleep(delayMs);
    }

    this.recordFailure(origin);
    if (lastResponse !== undefined) return lastResponse;
    throw lastError ?? new Error(`request to ${url} failed after ${this.maxAttempts} attempts`);
  }

  /** The breaker's current view of one origin, for tests and diagnostics. */
  circuitFor(url: string): CircuitSnapshot {
    const origin = originOf(url);
    const record = this.circuits.get(origin);
    if (record === undefined) {
      return { origin, state: 'closed', consecutiveFailures: 0 };
    }
    return {
      origin,
      state: this.stateOf(record),
      consecutiveFailures: record.consecutiveFailures,
      ...(record.openedAt === undefined ? {} : { openedAt: record.openedAt }),
    };
  }

  /** Forgets all breaker state. Useful between test cases and after a sleep. */
  resetCircuits(): void {
    this.circuits.clear();
  }

  /** One attempt, with the per-attempt deadline layered onto the caller's signal. */
  private async attempt(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    if (this.timeoutMs === 0) return this.fetchImpl(input, init);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    if (typeof timer === 'object' && timer !== null && 'unref' in timer) timer.unref();

    // A caller that passed its own signal still owns cancellation; chain to it
    // so aborting the run aborts the attempt rather than waiting out the
    // deadline.
    const callerSignal = init?.signal;
    const forward = (): void => controller.abort();
    if (callerSignal) {
      if (callerSignal.aborted) controller.abort();
      else callerSignal.addEventListener('abort', forward, { once: true });
    }

    try {
      return await this.fetchImpl(input, { ...init, signal: controller.signal });
    } finally {
      clearTimeout(timer);
      callerSignal?.removeEventListener('abort', forward);
    }
  }

  /** The sleep before the next attempt, preferring a server's `Retry-After`. */
  private delayFor(attempt: number, response: Response | undefined): number {
    const jittered = fullJitterDelay(attempt, this.baseDelayMs, this.capDelayMs, this.random);
    if (!this.honorRetryAfter || response === undefined) return jittered;

    const stated = retryAfterMs(response, this.now());
    if (stated === undefined) return jittered;
    return Math.min(stated, this.capDelayMs);
  }

  private stateOf(record: CircuitRecord): CircuitState {
    if (record.openedAt === undefined) return 'closed';
    return this.now() - record.openedAt >= this.resetAfterMs ? 'half-open' : 'open';
  }

  /** The error to throw instead of requesting, or `undefined` to proceed. */
  private rejectIfOpen(origin: string): CircuitOpenError | undefined {
    const record = this.circuits.get(origin);
    if (record?.openedAt === undefined) return undefined;

    const elapsed = this.now() - record.openedAt;
    // Half-open: let exactly this request through as a probe. A success closes
    // the circuit; a failure re-opens it with a fresh clock.
    if (elapsed >= this.resetAfterMs) return undefined;
    return new CircuitOpenError(origin, record.consecutiveFailures, this.resetAfterMs - elapsed);
  }

  private recordSuccess(origin: string): void {
    this.circuits.delete(origin);
  }

  private recordFailure(origin: string): void {
    const record = this.circuits.get(origin) ?? { consecutiveFailures: 0 };
    record.consecutiveFailures += 1;
    if (this.failureThreshold > 0 && record.consecutiveFailures >= this.failureThreshold) {
      record.openedAt = this.now();
    }
    this.circuits.set(origin, record);
  }

  /** An observer that throws must not turn a recoverable request into a failure. */
  private notify(event: RetryEvent): void {
    if (this.onRetry === undefined) return;
    try {
      this.onRetry(event);
    } catch {
      // Intentionally ignored: see the doc comment on `onRetry`.
    }
  }
}

/**
 * A `fetch`-compatible function backed by a fresh {@link AdaptiveClient}.
 *
 * The usual way to opt a call site in: `fetchImpl: typeof fetch = adaptiveFetch`
 * keeps the signature every rule already has while upgrading the default
 * transport.
 */
export function createAdaptiveFetch(options: AdaptiveClientOptions = {}): typeof fetch {
  return new AdaptiveClient(options).fetch;
}

/**
 * The process-wide client the rules use when the caller supplies no transport.
 *
 * Shared deliberately: the circuit breaker is only useful if the fifth request
 * to a dead host knows about the first four, and in a lint run those requests
 * come from five different rules.
 */
export const defaultAdaptiveClient = new AdaptiveClient();

/** {@link defaultAdaptiveClient}'s `fetch`, as a plain function. */
export const adaptiveFetch: typeof fetch = defaultAdaptiveClient.fetch;
