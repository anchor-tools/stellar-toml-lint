/**
 * OpenTelemetry traces and metrics over OTLP/HTTP (issue #375).
 *
 * A platform team that already runs a collector wants linting in the same
 * dashboard as the rest of the pipeline: how long the run took, which rule
 * burned the time, how the endpoint probes latency-wise, and whether the error
 * count moved since last night. This module emits that as OTLP without adding
 * an OpenTelemetry dependency, because `test/package.test.ts` pins the runtime
 * dependency list and CONTRIBUTING is explicit: "no new runtime dependencies
 * without discussion. This runs in other people's CI."
 *
 * What that means in practice, stated plainly rather than discovered later:
 *
 * - **Encoding is OTLP/HTTP JSON** (`application/json`), the one format an
 *   `otlphttp` collector receiver accepts and the one a test can assert against
 *   byte for byte. Protobuf-over-HTTP and gRPC are *not* implemented: hand
 *   rolling a protobuf writer means hand-copying OTLP's field numbers, and a
 *   wrong number is a span a collector silently drops — an error invisible to
 *   every test in this repository. If a deployment only speaks `grpc://`, point
 *   `--otel-endpoint` at that collector's `otlp/http` receiver (4318 by
 *   default); the CLI rejects a `grpc:` URL with that advice instead of
 *   pretending to send it.
 * - **IDs are base64**, per the proto3 JSON mapping OTLP documents, not the hex
 *   a gRPC viewer shows. Same 16 and 8 bytes.
 * - **Nanosecond timestamps are strings**, because a 64-bit count of nanoseconds
 *   overflows `Number`'s exact range and JSON would round it.
 *
 * The three metric names the issue specifies are the three counters plus a
 * duration histogram: `stellar_toml_lint_errors_total`,
 * `stellar_toml_lint_warnings_total`, `stellar_toml_lint_duration_seconds`, and
 * `stellar_toml_lint_infos_total` for symmetry with the third severity a
 * `--max-warnings` policy reads.
 */
import { randomBytes } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import type { LintResult, RuleInstrumenter, RuleOutcome } from '../types.js';

/** The service name a collector shows in its UI when none is given. */
export const DEFAULT_OTEL_SERVICE_NAME = 'stellar-toml-lint';

/** The only content type this exporter writes. */
export const OTLP_JSON_CONTENT_TYPE = 'application/json';

/** Collector ports, so a bare `host:port` can be told which signal it means. */
export const OTLP_TRACES_PATH = '/v1/traces';
export const OTLP_METRICS_PATH = '/v1/metrics';

/** How long one signal export may take before the run stops waiting. */
export const DEFAULT_OTEL_TIMEOUT_MS = 10_000;

/** Histogram bounds for a lint run, in seconds. */
export const DURATION_BUCKETS_SECONDS = [0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10];

/** `SpanKind` from `trace/v1`, as the numeric values JSON carries. */
export const OTelSpanKind = {
  unspecified: 0,
  internal: 1,
  server: 2,
  client: 3,
  producer: 4,
  consumer: 5,
} as const;

export type OtelSpanKind = (typeof OTelSpanKind)[keyof typeof OTelSpanKind];

/** `StatusCode` from `trace/v1`. */
export const OTelStatusCode = { unset: 0, ok: 1, error: 2 } as const;

/** `AggregationTemporality`. One run, one export, so every point is a delta. */
const AGGREGATION_TEMPORALITY_DELTA = 1;

/** Anything an OTLP attribute value may hold. */
export type OtelAttributeValue = string | number | boolean | string[];

export interface OtelAttributes {
  [key: string]: OtelAttributeValue;
}

/** One finished span, before encoding. */
export interface OtelSpanRecord {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  name: string;
  kind: OtelSpanKind;
  startTimeUnixNano: string;
  endTimeUnixNano: string;
  attributes: OtelAttributes;
  status?: { code: number; message?: string };
}

/** A span in progress: the handle a caller sets attributes on and then ends. */
export interface OtelActiveSpan {
  readonly traceId: string;
  readonly spanId: string;
  /** Recorded on the span when it ends; later writes win. */
  set(key: string, value: OtelAttributeValue): void;
  /** Ends the span. `error` marks it `STATUS_CODE_ERROR` with that message. */
  end(options?: { endMs?: number; error?: string }): void;
}

/** What {@link OtelTracer.startSpan} accepts. */
export interface OtelSpanOptions {
  kind?: OtelSpanKind;
  attributes?: OtelAttributes;
  /** A `SpanKind.CLIENT` HTTP call, a `SpanKind.INTERNAL` rule: both hang off the run. */
  parentSpanId?: string;
  /** A `performance.now()` reading taken before the work started. */
  startMs?: number;
}

export interface OtelTracerOptions {
  serviceName?: string;
  /** Written into `resource.attributes`, which every collector indexes on. */
  resourceAttributes?: OtelAttributes;
  /** `scope.version`; the CLI passes its own `VERSION`. */
  scopeVersion?: string;
  /** Injectable for tests, which need deterministic nanosecond timestamps. */
  now?: () => number;
}

/**
 * Wall-clock nanoseconds as a decimal string.
 *
 * `performance.now()` is monotonic and starts at process launch, while
 * `Date.now()` is the wall clock; the difference between the two at module load
 * turns a monotonic reading into a timestamp a collector can order against the
 * rest of the trace. The origin is captured once — every span in one process
 * shares it, so they stay mutually consistent even though the clock underneath
 * is not perfect.
 */
const TIME_ORIGIN_MS = Date.now() - performance.now();

function unixNano(ms: number): string {
  return String(BigInt(Math.round((TIME_ORIGIN_MS + ms) * 1_000_000)));
}

/** 16 random bytes as base64, the OTLP JSON spelling of a `trace_id`. */
function newTraceId(): string {
  return randomBytes(16).toString('base64');
}

/** 8 random bytes as base64, the OTLP JSON spelling of a `span_id`. */
function newSpanId(): string {
  return randomBytes(8).toString('base64');
}

/**
 * One attribute value in its `oneof` wrapper.
 *
 * `intValue` is a string for the same reason timestamps are: 64 bits do not fit
 * exactly in a JSON number. Non-integers go down `doubleValue`, which is the
 * only part of the OTLP attribute model a `number` cannot decide on its own.
 */
function attributeValue(value: OtelAttributeValue): Record<string, unknown> {
  if (typeof value === 'string') return { stringValue: value };
  if (typeof value === 'boolean') return { boolValue: value };
  if (Array.isArray(value)) {
    return { arrayValue: { values: value.map((item) => attributeValue(item)) } };
  }
  if (Number.isInteger(value)) return { intValue: String(value) };
  return { doubleValue: value };
}

/** The key-value list OTLP uses for attributes, sorted for deterministic output. */
function toKeyValueList(
  attributes: OtelAttributes,
): { key: string; value: Record<string, unknown> }[] {
  return Object.keys(attributes)
    .sort()
    .map((key) => ({ key, value: attributeValue(attributes[key] as OtelAttributeValue) }));
}

/** The `Resource` every export carries, naming the service and this tool. */
function resourceOf(serviceName: string, extra: OtelAttributes): Record<string, unknown> {
  return {
    attributes: toKeyValueList({
      'service.name': serviceName,
      'telemetry.sdk.name': 'stellar-toml-lint',
      ...extra,
    }),
  };
}

/**
 * Collects the spans of one lint run.
 *
 * The tracer starts a root span when it is constructed, because the run itself
 * is the thing a dashboard wants the total duration of, and every rule and
 * probe should nest inside it rather than sit beside it.
 */
export class OtelTracer {
  readonly traceId: string;
  readonly rootSpanId: string;
  readonly serviceName: string;
  readonly scopeVersion: string | undefined;
  readonly resourceAttributes: OtelAttributes;
  private readonly now: () => number;
  private readonly rootStartMs: number;
  private readonly finished: OtelSpanRecord[] = [];
  private rootStatus: { code: number; message?: string } | undefined;
  private rootEndMs: number | undefined;

  constructor(options: OtelTracerOptions = {}) {
    this.now = options.now ?? (() => performance.now());
    this.traceId = newTraceId();
    this.rootSpanId = newSpanId();
    this.serviceName = options.serviceName ?? DEFAULT_OTEL_SERVICE_NAME;
    this.scopeVersion = options.scopeVersion;
    this.resourceAttributes = options.resourceAttributes ?? {};
    this.rootStartMs = this.now();
  }

  /** Opens the root span's child, ending it when the caller does. */
  startSpan(name: string, options: OtelSpanOptions = {}): OtelActiveSpan {
    const startMs = options.startMs ?? this.now();
    const spanId = newSpanId();
    const attributes: OtelAttributes = { ...(options.attributes ?? {}) };
    const parentSpanId = options.parentSpanId ?? this.rootSpanId;
    const kind = options.kind ?? OTelSpanKind.internal;
    return {
      traceId: this.traceId,
      spanId,
      set: (key, value) => {
        attributes[key] = value;
      },
      end: (endOptions = {}) => {
        this.finished.push({
          traceId: this.traceId,
          spanId,
          parentSpanId,
          name,
          kind,
          startTimeUnixNano: unixNano(startMs),
          endTimeUnixNano: unixNano(endOptions.endMs ?? this.now()),
          attributes,
          ...(endOptions.error === undefined
            ? { status: { code: OTelStatusCode.ok } }
            : { status: { code: OTelStatusCode.error, message: endOptions.error } }),
        });
      },
    };
  }

  /**
   * Adds a span from timings already taken, for a rule loop that cannot await.
   *
   * {@link lint}'s rule loop is synchronous, so the durations are measured by
   * the caller with `performance.now()` and dropped here after the fact.
   */
  addSpan(input: {
    name: string;
    startMs: number;
    endMs: number;
    kind?: OtelSpanKind;
    attributes?: OtelAttributes;
    parentSpanId?: string;
    error?: string;
  }): void {
    this.finished.push({
      traceId: this.traceId,
      spanId: newSpanId(),
      parentSpanId: input.parentSpanId ?? this.rootSpanId,
      name: input.name,
      kind: input.kind ?? OTelSpanKind.internal,
      startTimeUnixNano: unixNano(input.startMs),
      endTimeUnixNano: unixNano(input.endMs),
      attributes: input.attributes ?? {},
      status:
        input.error === undefined
          ? { code: OTelStatusCode.ok }
          : { code: OTelStatusCode.error, message: input.error },
    });
  }

  /** Closes the root span. Idempotent by design: a second call re-times it. */
  endRun(options: { endMs?: number; error?: string } = {}): void {
    this.rootStatus =
      options.error === undefined
        ? { code: OTelStatusCode.ok }
        : { code: OTelStatusCode.error, message: options.error };
    this.rootEndMs = options.endMs ?? this.now();
  }

  /** Seconds between construction and {@link endRun}, or `undefined` if not ended. */
  durationSeconds(): number | undefined {
    if (this.rootEndMs === undefined) return undefined;
    return Math.max(0, this.rootEndMs - this.rootStartMs) / 1000;
  }

  /** The root span plus everything that ended inside it, in completion order. */
  spans(): OtelSpanRecord[] {
    const endMs = this.rootEndMs ?? this.now();
    return [
      {
        traceId: this.traceId,
        spanId: this.rootSpanId,
        name: `stellar-toml-lint run`,
        kind: OTelSpanKind.internal,
        startTimeUnixNano: unixNano(this.rootStartMs),
        endTimeUnixNano: unixNano(endMs),
        attributes: { 'lint.trace.span_count': this.finished.length },
        ...(this.rootStatus === undefined
          ? { status: { code: OTelStatusCode.unset } }
          : { status: this.rootStatus }),
      },
      ...this.finished,
    ];
  }
}

/** A counter, histogram, or gauge ready for encoding. */
export interface OtelMetric {
  name: string;
  description?: string;
  unit?: string;
  kind: 'sum' | 'histogram';
  /** For a sum: the total. Ignored by a histogram. */
  value?: number;
  /** For a histogram: the one observation this run recorded. */
  observation?: number;
  attributes?: OtelAttributes;
}

/** The three severity counters, for one lint result. */
export function severityMetrics(result: LintResult, target?: string): OtelMetric[] {
  const attributes: OtelAttributes = target === undefined ? {} : { 'lint.target': target };
  const { counts } = result;
  return [
    {
      name: 'stellar_toml_lint_errors_total',
      description: 'Findings reported at error severity by this lint run.',
      unit: '{error}',
      kind: 'sum',
      value: counts.error,
      attributes,
    },
    {
      name: 'stellar_toml_lint_warnings_total',
      description: 'Findings reported at warning severity by this lint run.',
      unit: '{warning}',
      kind: 'sum',
      value: counts.warning,
      attributes,
    },
    {
      name: 'stellar_toml_lint_infos_total',
      description: 'Findings reported at info severity by this lint run.',
      unit: '{info}',
      kind: 'sum',
      value: counts.info,
      attributes,
    },
  ];
}

/**
 * The run duration as a histogram.
 *
 * Separate from the counters because a `--domain`-less run can lint several
 * files: the counters belong to each file, while the duration belongs to the
 * process, so exporting it once keeps a three-file run from reporting the same
 * wall clock three times.
 */
export function durationMetric(tracer: OtelTracer, target?: string): OtelMetric | undefined {
  const duration = tracer.durationSeconds();
  if (duration === undefined) return undefined;
  return {
    name: 'stellar_toml_lint_duration_seconds',
    description: 'Wall-clock duration of this lint run.',
    unit: 's',
    kind: 'histogram',
    observation: duration,
    attributes: target === undefined ? {} : { 'lint.target': target },
  };
}

/** The three severity counters plus the run duration, from one lint result. */
export function metricsFromRun(
  result: LintResult,
  tracer: OtelTracer,
  target?: string,
): OtelMetric[] {
  const duration = durationMetric(tracer, target);
  return [...severityMetrics(result, target), ...(duration === undefined ? [] : [duration])];
}

/** Places one observation in the bounds' buckets; the count is `bounds.length + 1`. */
function histogramOf(
  observation: number,
  bounds: number[],
): { bucketCounts: string[]; explicitBounds: number[]; sum: number } {
  const bucketCounts = new Array<string>(bounds.length + 1).fill('0');
  let index = bounds.findIndex((bound) => observation <= bound);
  if (index === -1) index = bounds.length;
  bucketCounts[index] = '1';
  return { bucketCounts, explicitBounds: bounds, sum: observation };
}

/**
 * Encodes spans as an `ExportTraceServiceRequest`.
 *
 * Sorted by start time so two runs that recorded the same spans emit the same
 * bytes, which is what makes the shape assertable in a test instead of merely
 * plausible.
 */
export function renderOtlpTraces(
  tracer: OtelTracer,
  spans: OtelSpanRecord[] = tracer.spans(),
): Record<string, unknown> {
  const ordered = [...spans].sort((a, b) =>
    BigInt(a.startTimeUnixNano) < BigInt(b.startTimeUnixNano)
      ? -1
      : BigInt(a.startTimeUnixNano) > BigInt(b.startTimeUnixNano)
        ? 1
        : 0,
  );
  return {
    resourceSpans: [
      {
        resource: resourceOf(tracer.serviceName, tracer.resourceAttributes),
        scopeSpans: [
          {
            scope: {
              name: 'stellar-toml-lint',
              ...(tracer.scopeVersion === undefined ? {} : { version: tracer.scopeVersion }),
            },
            spans: ordered.map((span) => ({
              traceId: span.traceId,
              spanId: span.spanId,
              ...(span.parentSpanId === undefined ? {} : { parentSpanId: span.parentSpanId }),
              name: span.name,
              kind: span.kind,
              startTimeUnixNano: span.startTimeUnixNano,
              endTimeUnixNano: span.endTimeUnixNano,
              attributes: toKeyValueList(span.attributes),
              ...(span.status === undefined ? {} : { status: span.status }),
            })),
          },
        ],
      },
    ],
  };
}

/** Encodes metrics as an `ExportMetricsServiceRequest`. */
export function renderOtlpMetrics(
  tracer: OtelTracer,
  metrics: OtelMetric[],
): Record<string, unknown> {
  const start = tracer.spans()[0] as OtelSpanRecord;
  const end = [...tracer.spans()].sort((a, b) =>
    BigInt(a.endTimeUnixNano) < BigInt(b.endTimeUnixNano) ? 1 : -1,
  )[0] as OtelSpanRecord;

  return {
    resourceMetrics: [
      {
        resource: resourceOf(tracer.serviceName, tracer.resourceAttributes),
        scopeMetrics: [
          {
            scope: {
              name: 'stellar-toml-lint',
              ...(tracer.scopeVersion === undefined ? {} : { version: tracer.scopeVersion }),
            },
            metrics: metrics.map((metric) => {
              const attributes = toKeyValueList(metric.attributes ?? {});
              const time = {
                startTimeUnixNano: start.startTimeUnixNano,
                timeUnixNano: end.endTimeUnixNano,
              };
              if (metric.kind === 'histogram') {
                const histogram = histogramOf(metric.observation ?? 0, DURATION_BUCKETS_SECONDS);
                return {
                  name: metric.name,
                  ...(metric.description === undefined ? {} : { description: metric.description }),
                  ...(metric.unit === undefined ? {} : { unit: metric.unit }),
                  histogram: {
                    aggregationTemporality: AGGREGATION_TEMPORALITY_DELTA,
                    // The bounds belong to the histogram, not the point: they
                    // describe the scale, which every point on this metric shares.
                    explicitBounds: histogram.explicitBounds,
                    dataPoints: [
                      {
                        attributes,
                        ...time,
                        count: '1',
                        sum: histogram.sum,
                        bucketCounts: histogram.bucketCounts,
                      },
                    ],
                  },
                };
              }
              return {
                name: metric.name,
                ...(metric.description === undefined ? {} : { description: metric.description }),
                ...(metric.unit === undefined ? {} : { unit: metric.unit }),
                sum: {
                  aggregationTemporality: AGGREGATION_TEMPORALITY_DELTA,
                  isMonotonic: true,
                  dataPoints: [
                    {
                      attributes,
                      ...time,
                      asInt: String(metric.value ?? 0),
                    },
                  ],
                },
              };
            }),
          },
        ],
      },
    ],
  };
}

/**
 * Resolves an `--otel-endpoint` value into the URL for one signal.
 *
 * Accepts the shapes a deployment actually hands out — a base URL, a base with
 * an ingress path, a `/v1` prefix, or the full `/v1/traces` URL — and rejects
 * the mistakes with the advice that fixes them: a schemeless `localhost:4318`
 * (copied from a `docker-compose` environment value) and a `grpc://` endpoint,
 * which this exporter does not speak.
 */
export function otlpEndpointFor(endpoint: string, signal: 'traces' | 'metrics'): URL {
  if (!/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(endpoint)) {
    throw new Error(
      `--otel-endpoint "${endpoint}" has no scheme. Give the collector's OTLP/HTTP URL, e.g. http://localhost:4318/v1/traces.`,
    );
  }
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    throw new Error(
      `--otel-endpoint expects an OTLP/HTTP URL such as http://localhost:4318/v1/traces, got "${endpoint}".`,
    );
  }
  if (url.protocol === 'grpc:' || url.protocol === 'grpc+insecure:') {
    throw new Error(
      `--otel-endpoint ${endpoint} is a gRPC URL, which this exporter does not speak. Point it at the collector's otlp/http receiver instead (http://host:4318 by default).`,
    );
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error(
      `--otel-endpoint expects an http(s) URL, got "${endpoint}" with scheme ${url.protocol}.`,
    );
  }
  const path = url.pathname.replace(/\/+$/, '');
  const suffix = signal === 'traces' ? OTLP_TRACES_PATH : OTLP_METRICS_PATH;
  if (path.endsWith(suffix)) return url;
  // A `/v1` base already holds the version segment, so only the signal name
  // goes on the end — otherwise the resolved path doubles it.
  url.pathname = path.endsWith('/v1') ? `${path}/${signal}` : `${path}${suffix}`;
  return url;
}

/** What one signal export did. */
export interface OtelExportResult {
  signal: 'traces' | 'metrics';
  ok: boolean;
  /** HTTP status when the collector answered. */
  status?: number;
  url: string;
  error?: string;
}

export interface OtelExporterOptions {
  /** The raw `--otel-endpoint` value; {@link otlpEndpointFor} resolves it per signal. */
  endpoint: string;
  serviceName?: string;
  resourceAttributes?: OtelAttributes;
  scopeVersion?: string;
  /** Sent on every request — for a collector behind a token-authenticating proxy. */
  headers?: Record<string, string>;
  timeoutMs?: number;
  /** Injectable so a test can stand up a mock collector without a socket. */
  fetchImpl?: typeof fetch;
}

/**
 * POSTs OTLP/HTTP JSON to a collector.
 *
 * A failed export is a result, not an exception: linting a file and failing a
 * build because the observability endpoint was down would invert what the tool
 * is for. {@link OtelExporter.exportRun} reports both signals, and the CLI
 * prints the failure to stderr while leaving the exit code to the diagnostics.
 */
export class OtelExporter {
  readonly serviceName: string;
  readonly headers: Record<string, string>;
  private readonly endpoint: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly tracerOptions: Pick<OtelTracerOptions, 'resourceAttributes' | 'scopeVersion'>;

  constructor(options: OtelExporterOptions) {
    this.endpoint = options.endpoint;
    this.serviceName = options.serviceName ?? DEFAULT_OTEL_SERVICE_NAME;
    this.headers = { 'content-type': OTLP_JSON_CONTENT_TYPE, ...options.headers };
    this.timeoutMs = options.timeoutMs ?? DEFAULT_OTEL_TIMEOUT_MS;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.tracerOptions = {
      ...(options.resourceAttributes !== undefined
        ? { resourceAttributes: options.resourceAttributes }
        : {}),
      ...(options.scopeVersion !== undefined ? { scopeVersion: options.scopeVersion } : {}),
    };
  }

  /** A tracer for this exporter's service, so the CLI builds one and shares it. */
  tracer(): OtelTracer {
    return new OtelTracer({
      serviceName: this.serviceName,
      ...this.tracerOptions,
    });
  }

  /** Where a signal goes, for a message or a `--dry-run` print. */
  urlFor(signal: 'traces' | 'metrics'): string {
    return otlpEndpointFor(this.endpoint, signal).toString();
  }

  private async post(signal: 'traces' | 'metrics', body: unknown): Promise<OtelExportResult> {
    const url = this.urlFor(signal);
    try {
      const response = await this.fetchImpl(url, {
        method: 'POST',
        headers: this.headers,
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      if (response.ok) return { signal, ok: true, status: response.status, url };
      // A collector tells you why it refused, and that text is the difference
      // between a fixed pipeline and an hour of guessing at a JSON payload.
      const detail = (await response.text().catch(() => '')).slice(0, 240);
      return {
        signal,
        ok: false,
        status: response.status,
        url,
        error:
          detail.length === 0 ? `HTTP ${response.status}` : `HTTP ${response.status}: ${detail}`,
      };
    } catch (error) {
      return {
        signal,
        ok: false,
        url,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  /** Sends the spans of one run. */
  exportTraces(tracer: OtelTracer): Promise<OtelExportResult> {
    return this.post('traces', renderOtlpTraces(tracer));
  }

  /** Sends the metrics of one run. */
  exportMetrics(tracer: OtelTracer, metrics: OtelMetric[]): Promise<OtelExportResult> {
    return this.post('metrics', renderOtlpMetrics(tracer, metrics));
  }

  /**
   * Sends both signals.
   *
   * Sequentially, not `Promise.all`: a collector that is down should cost one
   * timeout rather than two, and a CI job that exports on every commit should
   * not be able to outrank the build it is reporting on.
   */
  async exportRun(tracer: OtelTracer, metrics: OtelMetric[]): Promise<OtelExportResult[]> {
    const traces = await this.exportTraces(tracer);
    const metricsResult = await this.exportMetrics(tracer, metrics);
    return [traces, metricsResult];
  }
}

/**
 * Wraps a transport so every request becomes a `SpanKind.CLIENT` span.
 *
 * SEP-1 linting opens a lot of sockets — the file itself, the federation,
 * auth, transfer and quote servers, images, account lookups. Latency there is
 * the reason a lint job takes ninety seconds, so it is the part worth putting
 * on a waterfall. The wrapper is transparent: it observes, and re-raises
 * whatever the request did, so a probe that failed still fails the same way.
 */
export function instrumentedFetch(fetchImpl: typeof fetch, tracer: OtelTracer): typeof fetch {
  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const request = input instanceof Request ? input : undefined;
    const raw =
      request === undefined ? input : input instanceof URL ? input.href : (input as string);
    const method = (init?.method ?? request?.method ?? 'GET').toUpperCase();
    const url = describeUrl(raw);
    const startMs = performance.now();
    const span = tracer.startSpan(`HTTP ${method}`, {
      kind: OTelSpanKind.client,
      // Timed from before the URL is described, so the span covers the whole
      // call rather than whatever remained after the wrapper's own work.
      startMs,
      attributes: {
        'http.request.method': method,
        ...(url === undefined ? {} : { 'url.full': url }),
      },
    });
    try {
      const response = await fetchImpl(input as RequestInfo, init);
      span.set('http.response.status_code', response.status);
      span.set('http.response_content_length', Number(response.headers.get('content-length') ?? 0));
      if (response.status >= 400) {
        span.end({ endMs: performance.now(), error: `HTTP ${response.status}` });
      } else {
        span.end({ endMs: performance.now() });
      }
      return response;
    } catch (error) {
      span.end({
        endMs: performance.now(),
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  };
}

/** The URL as text, or `undefined` when the caller passed something unnameable. */
function describeUrl(raw: RequestInfo | URL): string | undefined {
  if (typeof raw === 'string') return raw;
  if (raw instanceof URL) return raw.href;
  return undefined;
}

/**
 * The {@link LintOptions.instrumentRule} hook that turns each rule into a span.
 *
 * Lives here rather than in `lint.ts` so the core stays free of telemetry: an
 * embedder that does not pass the hook pays nothing, and the rule loop only
 * gains the two lines that call it.
 */
export function ruleSpanRecorder(tracer: OtelTracer): RuleInstrumenter {
  return (ruleId, run) => {
    const startMs = performance.now();
    const outcome: RuleOutcome = run();
    tracer.addSpan({
      name: `rule ${ruleId}`,
      startMs,
      endMs: performance.now(),
      attributes: { 'stellar.toml.rule.id': ruleId, 'lint.rule.outcome': outcome },
      ...(outcome === 'ok' ? {} : { error: `rule ${ruleId} threw` }),
    });
  };
}
