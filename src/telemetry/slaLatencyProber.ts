/**
 * Synthetic SLA latency prober for anchor SEP endpoints.
 *
 * Wallets time out when an anchor's SEP-6 / SEP-24 / SEP-31 / SEP-38 servers
 * are slow, so SLAs usually promise a Time To First Byte under 500 ms.
 * `AnchorSlaLatencyProber` sends repeated read-only `GET` probes (`/info`
 * only — never anything that creates a transaction) to every endpoint
 * declared in `stellar.toml`, measuring each phase of the request on a fresh
 * connection:
 *
 *   - DNS lookup
 *   - TCP connect
 *   - TLS handshake (HTTPS only)
 *   - Time To First Byte, measured from request start to response headers
 *
 * and reports p50 / p95 / p99 per endpoint plus an ASCII latency histogram.
 */
import http from 'node:http';
import https from 'node:https';
import { trimTrailingSlashes } from '../strings.js';

/** `stellar.toml` keys that point at SEP servers worth probing. */
export const SLA_ENDPOINT_FIELDS: readonly string[] = [
  'TRANSFER_SERVER',
  'TRANSFER_SERVER_SEP0024',
  'DIRECT_PAYMENT_SERVER',
  'ANCHOR_QUOTE_SERVER',
];

/** Read-only paths the prober is allowed to request. */
export const READ_ONLY_PROBE_PATHS: readonly string[] = ['/info', '/prices'];

/** Default SLA benchmark for TTFB, in milliseconds. */
export const DEFAULT_TTFB_SLA_MS = 500;

export interface ProbeTiming {
  /** HTTP status, or undefined when the request failed. */
  status?: number;
  dnsMs: number;
  connectMs: number;
  tlsMs: number;
  ttfbMs: number;
  totalMs: number;
  error?: string;
}

/** Performs one probe. Must never reject. */
export type TimingProbe = (url: string, timeoutMs: number) => Promise<ProbeTiming>;

export interface PercentileSet {
  p50: number;
  p95: number;
  p99: number;
  min: number;
  max: number;
  mean: number;
}

export interface SlaViolation {
  percentile: 'p50' | 'p95' | 'p99';
  valueMs: number;
  thresholdMs: number;
  severity: 'error' | 'warning';
  message: string;
}

export interface EndpointLatencyReport {
  field: string;
  url: string;
  samples: number;
  failures: number;
  ttfb?: PercentileSet;
  connect?: PercentileSet;
  tls?: PercentileSet;
  dns?: PercentileSet;
  violations: SlaViolation[];
  /** Raw successful TTFB samples, in probe order. */
  ttfbSamples: number[];
  errors: string[];
}

export interface SlaReport {
  ok: boolean;
  thresholdMs: number;
  endpoints: EndpointLatencyReport[];
}

/** Rounds to microsecond resolution so reports stay readable. */
function round3(value: number): number {
  return Math.round(value * 1000) / 1000;
}

/**
 * Linear-interpolated percentile (the "R-7" / Excel PERCENTILE.INC method).
 * `sorted` must be ascending; `p` is in [0, 100].
 */
export function percentile(sorted: readonly number[], p: number): number {
  if (sorted.length === 0) return Number.NaN;
  if (p <= 0) return sorted[0] as number;
  if (p >= 100) return sorted[sorted.length - 1] as number;
  const rank = (p / 100) * (sorted.length - 1);
  const lower = Math.floor(rank);
  const upper = Math.ceil(rank);
  const lo = sorted[lower] as number;
  const hi = sorted[upper] as number;
  return lo + (hi - lo) * (rank - lower);
}

/** p50 / p95 / p99 / min / max / mean of `values`. */
export function summarize(values: readonly number[]): PercentileSet | undefined {
  if (values.length === 0) return undefined;
  const sorted = [...values].sort((a, b) => a - b);
  const sum = sorted.reduce((acc, v) => acc + v, 0);
  return {
    p50: round3(percentile(sorted, 50)),
    p95: round3(percentile(sorted, 95)),
    p99: round3(percentile(sorted, 99)),
    min: round3(sorted[0] as number),
    max: round3(sorted[sorted.length - 1] as number),
    mean: round3(sum / sorted.length),
  };
}

/** Builds the probe URL for a SEP server base, enforcing the read-only allowlist. */
export function probeUrl(base: string, path = '/info'): string {
  if (!READ_ONLY_PROBE_PATHS.includes(path)) {
    throw new Error(
      `Refusing to probe ${path}: only read-only paths (${READ_ONLY_PROBE_PATHS.join(', ')}) are allowed`,
    );
  }
  return `${trimTrailingSlashes(base)}${path}`;
}

/** Returns `[field, baseUrl]` pairs for every declared SEP server. */
export function discoverSlaEndpoints(doc: Record<string, unknown>): [string, string][] {
  const out: [string, string][] = [];
  for (const field of SLA_ENDPOINT_FIELDS) {
    const value = doc[field];
    if (typeof value === 'string' && /^https?:\/\//i.test(value)) out.push([field, value]);
  }
  return out;
}

const elapsed = (start: bigint, end: bigint): number => Number(end - start) / 1e6;

/**
 * Default probe: a `GET` on a fresh, non-pooled connection, timing each phase
 * with `process.hrtime.bigint()` (nanosecond resolution).
 */
export const httpTimingProbe: TimingProbe = (url, timeoutMs) =>
  new Promise<ProbeTiming>((resolve) => {
    const start = process.hrtime.bigint();
    let lookupAt: bigint | undefined;
    let connectAt: bigint | undefined;
    let secureAt: bigint | undefined;
    let settled = false;
    const finish = (timing: Partial<ProbeTiming>) => {
      if (settled) return;
      settled = true;
      const now = process.hrtime.bigint();
      const dnsMs = lookupAt !== undefined ? elapsed(start, lookupAt) : 0;
      const connectMs = connectAt !== undefined ? elapsed(lookupAt ?? start, connectAt) : 0;
      const tlsMs =
        secureAt !== undefined && connectAt !== undefined ? elapsed(connectAt, secureAt) : 0;
      resolve({
        dnsMs: round3(dnsMs),
        connectMs: round3(connectMs),
        tlsMs: round3(tlsMs),
        ttfbMs: 0,
        totalMs: round3(elapsed(start, now)),
        ...timing,
      });
    };

    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      finish({ error: `Invalid URL ${url}` });
      return;
    }
    const lib = parsed.protocol === 'https:' ? https : http;
    const request = lib.request(
      parsed,
      { method: 'GET', agent: false, headers: { accept: 'application/json' } },
      (response) => {
        const ttfbMs = round3(elapsed(start, process.hrtime.bigint()));
        response.resume();
        response.on('end', () => finish({ status: response.statusCode, ttfbMs }));
        response.on('error', (error) =>
          finish({ status: response.statusCode, ttfbMs, error: error.message }),
        );
      },
    );
    request.setTimeout(timeoutMs, () => {
      request.destroy(new Error(`timed out after ${timeoutMs} ms`));
    });
    request.on('socket', (socket) => {
      socket.once('lookup', () => {
        lookupAt = process.hrtime.bigint();
      });
      socket.once('connect', () => {
        connectAt = process.hrtime.bigint();
      });
      socket.once('secureConnect', () => {
        secureAt = process.hrtime.bigint();
      });
    });
    request.on('error', (error) => finish({ error: error.message }));
    request.end();
  });

export interface AnchorSlaLatencyProberOptions {
  probe?: TimingProbe;
  samples?: number;
  thresholdMs?: number;
  timeoutMs?: number;
  /** Pause between rounds, so probes don't arrive as a burst. */
  intervalMs?: number;
  sleep?: (ms: number) => Promise<void>;
}

export class AnchorSlaLatencyProber {
  private readonly probe: TimingProbe;
  private readonly samples: number;
  private readonly thresholdMs: number;
  private readonly timeoutMs: number;
  private readonly intervalMs: number;
  private readonly sleep: (ms: number) => Promise<void>;

  constructor(options: AnchorSlaLatencyProberOptions = {}) {
    this.probe = options.probe ?? httpTimingProbe;
    this.samples = Math.max(1, Math.floor(options.samples ?? 10));
    this.thresholdMs = options.thresholdMs ?? DEFAULT_TTFB_SLA_MS;
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.intervalMs = options.intervalMs ?? 0;
    this.sleep = options.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  }

  /** Probes every SEP server declared in a parsed `stellar.toml`. */
  async probeToml(doc: Record<string, unknown>): Promise<SlaReport> {
    return this.probeEndpoints(
      discoverSlaEndpoints(doc).map(([field, base]) => [field, probeUrl(base)]),
    );
  }

  /** Probes `[label, url]` pairs; samples are interleaved round-robin across endpoints. */
  async probeEndpoints(endpoints: readonly (readonly [string, string])[]): Promise<SlaReport> {
    const timings: ProbeTiming[][] = endpoints.map(() => []);
    for (let round = 0; round < this.samples; round++) {
      if (round > 0 && this.intervalMs > 0) await this.sleep(this.intervalMs);
      for (let i = 0; i < endpoints.length; i++) {
        const [, url] = endpoints[i] as readonly [string, string];
        (timings[i] as ProbeTiming[]).push(await this.probe(url, this.timeoutMs));
      }
    }
    const reports = endpoints.map(([field, url], i) =>
      this.analyze(field, url, timings[i] as ProbeTiming[]),
    );
    return {
      ok: reports.every(
        (r) => r.violations.every((v) => v.severity !== 'error') && r.failures === 0,
      ),
      thresholdMs: this.thresholdMs,
      endpoints: reports,
    };
  }

  /** Turns raw timings into percentiles and SLA violations. */
  analyze(field: string, url: string, timings: readonly ProbeTiming[]): EndpointLatencyReport {
    const ok = timings.filter((t) => t.error === undefined && t.status !== undefined);
    const errors = timings.flatMap((t) =>
      t.error !== undefined ? [t.error] : t.status === undefined ? ['no response'] : [],
    );
    const ttfbSamples = ok.map((t) => t.ttfbMs);
    const ttfb = summarize(ttfbSamples);
    const violations: SlaViolation[] = [];
    if (ttfb !== undefined) {
      for (const key of ['p50', 'p95', 'p99'] as const) {
        if (ttfb[key] > this.thresholdMs) {
          // p50 and p95 breaches break the SLA; a slow p99 tail is a warning.
          const severity = key === 'p99' ? 'warning' : 'error';
          violations.push({
            percentile: key,
            valueMs: ttfb[key],
            thresholdMs: this.thresholdMs,
            severity,
            message: `${field} ${key} TTFB ${ttfb[key].toFixed(1)} ms exceeds the ${this.thresholdMs} ms SLA`,
          });
        }
      }
    }
    const report: EndpointLatencyReport = {
      field,
      url,
      samples: timings.length,
      failures: timings.length - ok.length,
      violations,
      ttfbSamples,
      errors: [...new Set(errors)],
    };
    if (ttfb !== undefined) report.ttfb = ttfb;
    const connect = summarize(ok.map((t) => t.connectMs));
    if (connect !== undefined) report.connect = connect;
    const tlsValues = ok.map((t) => t.tlsMs).filter((v) => v > 0);
    const tls = summarize(tlsValues);
    if (tls !== undefined) report.tls = tls;
    const dns = summarize(ok.map((t) => t.dnsMs));
    if (dns !== undefined) report.dns = dns;
    return report;
  }
}

/**
 * Renders an ASCII histogram of `values` into `buckets` equal-width bins,
 * marking the SLA threshold bin.
 */
export function renderLatencyHistogram(
  values: readonly number[],
  thresholdMs: number,
  buckets = 10,
  width = 40,
): string {
  if (values.length === 0) return '  (no successful samples)\n';
  const min = Math.min(...values);
  const max = Math.max(...values);
  const span = max - min || 1;
  const counts = new Array<number>(buckets).fill(0);
  for (const v of values) {
    const idx = Math.min(buckets - 1, Math.floor(((v - min) / span) * buckets));
    counts[idx] = (counts[idx] as number) + 1;
  }
  const peak = Math.max(...counts);
  const lines: string[] = [];
  for (let i = 0; i < buckets; i++) {
    const lo = min + (span * i) / buckets;
    const hi = min + (span * (i + 1)) / buckets;
    const count = counts[i] as number;
    const bar = '█'.repeat(Math.round((count / peak) * width));
    const marker = hi > thresholdMs ? ' ⚠' : '';
    lines.push(
      `  ${lo.toFixed(1).padStart(9)}–${hi.toFixed(1).padEnd(9)} ms │${bar} ${count}${count > 0 ? marker : ''}`,
    );
  }
  return `${lines.join('\n')}\n`;
}

/** Human-readable report. */
export function renderSlaReport(report: SlaReport): string {
  const out: string[] = [`SLA latency probe (TTFB threshold ${report.thresholdMs} ms)`];
  if (report.endpoints.length === 0) {
    out.push(
      'No SEP endpoints declared (TRANSFER_SERVER, TRANSFER_SERVER_SEP0024, DIRECT_PAYMENT_SERVER, ANCHOR_QUOTE_SERVER).',
    );
    return `${out.join('\n')}\n`;
  }
  const fmt = (set: PercentileSet | undefined) =>
    set === undefined
      ? 'n/a'
      : `p50 ${set.p50.toFixed(1)} · p95 ${set.p95.toFixed(1)} · p99 ${set.p99.toFixed(1)} ms`;
  for (const endpoint of report.endpoints) {
    out.push('');
    out.push(`${endpoint.field}  ${endpoint.url}`);
    out.push(`  samples ${endpoint.samples}, failures ${endpoint.failures}`);
    out.push(`  TTFB     ${fmt(endpoint.ttfb)}`);
    out.push(`  connect  ${fmt(endpoint.connect)}`);
    if (endpoint.tls !== undefined) out.push(`  TLS      ${fmt(endpoint.tls)}`);
    out.push(`  DNS      ${fmt(endpoint.dns)}`);
    out.push('  TTFB distribution:');
    out.push(renderLatencyHistogram(endpoint.ttfbSamples, report.thresholdMs).trimEnd());
    for (const v of endpoint.violations)
      out.push(`  ${v.severity === 'error' ? '✗' : '!'} ${v.message}`);
    for (const e of endpoint.errors) out.push(`  ✗ probe failed: ${e}`);
    if (endpoint.violations.length === 0 && endpoint.failures === 0) out.push('  ✓ within SLA');
  }
  out.push('');
  out.push(report.ok ? '✓ All endpoints meet the SLA' : '✗ SLA violations found');
  return `${out.join('\n')}\n`;
}
