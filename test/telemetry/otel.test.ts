import { afterEach, describe, expect, it, vi } from 'vitest';
import { execFile } from 'node:child_process';
import { createServer, type Server } from 'node:http';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { lint } from '../../src/lint.js';
import { allRules } from '../../src/rules/index.js';
import type { Rule, RuleOutcome } from '../../src/types.js';
import {
  DEFAULT_OTEL_SERVICE_NAME,
  DURATION_BUCKETS_SECONDS,
  instrumentedFetch,
  metricsFromRun,
  OtelExporter,
  otlpEndpointFor,
  OTelSpanKind,
  OTelStatusCode,
  OtelTracer,
  renderOtlpMetrics,
  renderOtlpTraces,
  ruleSpanRecorder,
  severityMetrics,
} from '../../src/telemetry/otel-exporter.js';

const run = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, '..', '..', 'dist', 'cli.js');
const VALID_TOML = readFileSync(join(here, '..', 'fixtures', 'valid.toml'), 'utf8');

/** A clock that returns each reading in order, then holds the last one. */
function fakeClock(...readings: number[]): () => number {
  let index = 0;
  return () => readings[Math.min(index++, readings.length - 1)] as number;
}

/** A tracer whose run lasts `seconds`, so durations are assertable. */
function tracerWithRun(seconds: number, options: { serviceName?: string } = {}): OtelTracer {
  const tracer = new OtelTracer({ now: fakeClock(0, seconds * 1000), ...options });
  tracer.endRun();
  return tracer;
}

function asRecord(value: unknown): Record<string, unknown> {
  return value as Record<string, unknown>;
}

function asList(value: unknown): Record<string, unknown>[] {
  return value as Record<string, unknown>[];
}

/** The `spans` array out of an `ExportTraceServiceRequest`. */
function spansOf(body: Record<string, unknown>): Record<string, unknown>[] {
  const scopes = asList(asList(body.resourceSpans)[0]!.scopeSpans);
  return asList(scopes[0]!.spans);
}

/** The `metrics` array out of an `ExportMetricsServiceRequest`. */
function metricsOf(body: Record<string, unknown>): Record<string, unknown>[] {
  const scopes = asList(asList(body.resourceMetrics)[0]!.scopeMetrics);
  return asList(scopes[0]!.metrics);
}

function resourceAttributes(body: Record<string, unknown>): Record<string, string> {
  const resource = asList(body.resourceSpans ?? body.resourceMetrics)[0]!.resource;
  const list = asList(asRecord(resource).attributes);
  const out: Record<string, string> = {};
  for (const entry of list) {
    out[entry.key as string] = asRecord(entry.value).stringValue as string;
  }
  return out;
}

function counterValue(metric: Record<string, unknown>): string {
  return asList(asRecord(metric.sum).dataPoints)[0]!.asInt as string;
}

/** A transport that answers with the given status, recording every call. */
function collector(status = 200, body = '') {
  const calls: { url: string; init?: RequestInit }[] = [];
  const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({ url: String(input), init });
    return new Response(body, { status });
  }) as unknown as typeof fetch;
  return { calls, fetchImpl };
}

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (server) =>
        new Promise<void>((resolve) => {
          server.close(() => resolve());
        }),
    ),
  );
});

/** A real listening collector that records the bodies it is POSTed. */
async function startCollector(): Promise<{
  origin: string;
  requests: { path: string; contentType: string; body: Record<string, unknown> }[];
}> {
  const requests: { path: string; contentType: string; body: Record<string, unknown> }[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      requests.push({
        path: req.url ?? '',
        contentType: String(req.headers['content-type']),
        body: JSON.parse(raw) as Record<string, unknown>,
      });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{}');
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  servers.push(server);
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('collector did not bind');
  return { origin: `http://127.0.0.1:${address.port}`, requests };
}

describe('OTLP/HTTP JSON encoding (#375)', () => {
  it('emits base64 ids and stringified nanoseconds, not hex and not numbers', () => {
    const tracer = tracerWithRun(1);
    tracer.addSpan({ name: 'rule general/version', startMs: 0, endMs: 500 });
    const [root, child] = spansOf(renderOtlpTraces(tracer));

    // proto3 JSON maps `bytes` to base64: 16 bytes to 22 characters plus the
    // usual two `=` of a three-group pad, 8 bytes to 11 plus one.
    expect(root!.traceId).toMatch(/^[A-Za-z0-9+/]{22}==$/);
    expect(root!.spanId).toMatch(/^[A-Za-z0-9+/]{11}=$/);
    expect(typeof root!.startTimeUnixNano).toBe('string');
    // A nanosecond epoch does not fit exactly in a JSON number, so a raw
    // numeric would silently round the timestamp on the collector's side.
    expect(Number(root!.startTimeUnixNano)).toBeGreaterThan(Number.MAX_SAFE_INTEGER);
    expect(child!.parentSpanId).toBe(root!.spanId);
  });

  it('orders the root span first and keeps one trace id across the run', () => {
    const tracer = new OtelTracer({ now: fakeClock(0, 10, 20, 30) });
    tracer.addSpan({ name: 'rule a', startMs: 10, endMs: 20 });
    tracer.addSpan({ name: 'rule b', startMs: 20, endMs: 30 });
    tracer.endRun({ endMs: 30 });
    const spans = spansOf(renderOtlpTraces(tracer));
    expect(spans.map((span) => span.name)).toEqual(['stellar-toml-lint run', 'rule a', 'rule b']);
    expect(new Set(spans.map((span) => span.traceId)).size).toBe(1);
  });

  it('marks a rule that threw as an error span and a clean rule as ok', () => {
    const tracer = new OtelTracer({ now: fakeClock(0, 1) });
    const instrument = ruleSpanRecorder(tracer);
    instrument('demo/ok', () => 'ok');
    instrument('demo/boom', () => 'error');
    tracer.endRun();
    const [ok, boom] = tracer.spans().slice(1);
    expect(ok!.status?.code).toBe(OTelStatusCode.ok);
    expect(boom!.status?.code).toBe(OTelStatusCode.error);
    expect(boom!.status?.message).toContain('demo/boom');
    expect(boom!.attributes['lint.rule.outcome']).toBe('error');
  });

  it('writes attributes in the OTLP oneof wrappers, ints as strings', () => {
    const tracer = tracerWithRun(1);
    tracer.addSpan({
      name: 'rule x',
      startMs: 0,
      endMs: 1,
      attributes: { str: 'v', num: 3, ratio: 1.5, flag: true, list: ['a', 'b'] },
    });
    const [, span] = spansOf(renderOtlpTraces(tracer));
    const attributes = asList(span!.attributes);
    const byKey = new Map(attributes.map((entry) => [entry.key as string, asRecord(entry.value)]));
    expect(byKey.get('str')).toEqual({ stringValue: 'v' });
    expect(byKey.get('num')).toEqual({ intValue: '3' });
    expect(byKey.get('ratio')).toEqual({ doubleValue: 1.5 });
    expect(byKey.get('flag')).toEqual({ boolValue: true });
    expect(asList(asRecord(byKey.get('list')!.arrayValue).values)).toHaveLength(2);
    // Sorted keys, so two identical runs serialize to identical bytes.
    expect(attributes.map((entry) => entry.key)).toEqual(['flag', 'list', 'num', 'ratio', 'str']);
  });

  it('describes the run with service.name and the instrumentation scope', () => {
    const tracer = new OtelTracer({ scopeVersion: '9.9.9' });
    tracer.endRun();
    const body = renderOtlpTraces(tracer);
    expect(resourceAttributes(body)['service.name']).toBe(DEFAULT_OTEL_SERVICE_NAME);
    expect(resourceAttributes(body)['telemetry.sdk.name']).toBe('stellar-toml-lint');
    const scope = asRecord(asList(asList(body.resourceSpans)[0]!.scopeSpans)[0]!.scope);
    expect(scope.name).toBe('stellar-toml-lint');
    expect(scope.version).toBe('9.9.9');
  });
});

describe('lint metrics (#375)', () => {
  it('counts the three severities for one result and keeps the sums monotonic', () => {
    const result = lint('NETWORK_PASSPHRASE = "Test Net"\n', { strict: false });
    const metrics = severityMetrics(result, 'anchor.example.com');
    expect(metrics.map((metric) => metric.name)).toEqual([
      'stellar_toml_lint_errors_total',
      'stellar_toml_lint_warnings_total',
      'stellar_toml_lint_infos_total',
    ]);

    const body = renderOtlpMetrics(tracerWithRun(1), metrics);
    const encoded = metricsOf(body);
    expect(encoded.map((metric) => metric.name)).toEqual([
      'stellar_toml_lint_errors_total',
      'stellar_toml_lint_warnings_total',
      'stellar_toml_lint_infos_total',
    ]);
    for (const metric of encoded) {
      const sum = asRecord(metric.sum);
      // DELTA, and monotonic: one run reports what it found, it never resets
      // a cumulative series the dashboard is already reading.
      expect(sum.aggregationTemporality).toBe(1);
      expect(sum.isMonotonic).toBe(true);
      expect(asList(sum.dataPoints)[0]!.attributes).toEqual([
        { key: 'lint.target', value: { stringValue: 'anchor.example.com' } },
      ]);
    }
    // The numbers a Grafana panel plots, in the order the issue named them.
    expect(counterValue(encoded[0]!)).toBe(String(result.counts.error));
    expect(counterValue(encoded[1]!)).toBe(String(result.counts.warning));
    expect(counterValue(encoded[2]!)).toBe(String(result.counts.info));
  });

  it('puts the run duration in the right histogram bucket with stringified counts', () => {
    const result = lint(VALID_TOML);
    const metrics = metricsFromRun(result, tracerWithRun(1.2), 'stellar.toml');
    const histogram = asRecord(metricsOf(renderOtlpMetrics(tracerWithRun(1.2), metrics))[3]!);
    const body = asRecord(histogram.histogram);
    expect(histogram.name).toBe('stellar_toml_lint_duration_seconds');
    expect(body.aggregationTemporality).toBe(1);
    const point = asRecord(asList(body.dataPoints)[0]);
    expect(point.count).toBe('1');
    expect(point.sum).toBeCloseTo(1.2);
    expect(asList(body.dataPoints).length).toBe(1);
    const counts = point.bucketCounts as string[];
    expect(counts).toHaveLength(DURATION_BUCKETS_SECONDS.length + 1);
    expect(counts.filter((count) => count !== '0')).toEqual(['1']);
    expect(counts.indexOf('1')).toBe(DURATION_BUCKETS_SECONDS.findIndex((b) => 1.2 <= b));
    expect(body.explicitBounds).toEqual(DURATION_BUCKETS_SECONDS);
  });

  it('omits the duration until the run has actually ended', () => {
    const tracer = new OtelTracer({ now: fakeClock(0, 0) });
    expect(metricsFromRun(lint(VALID_TOML), tracer)).toHaveLength(3);
    tracer.endRun();
    expect(metricsFromRun(lint(VALID_TOML), tracer)).toHaveLength(4);
  });
});

describe('endpoint resolution (#375)', () => {
  it('appends the signal path to the shapes a deployment hands out', () => {
    expect(otlpEndpointFor('http://localhost:4318', 'traces').toString()).toBe(
      'http://localhost:4318/v1/traces',
    );
    expect(otlpEndpointFor('http://localhost:4318/', 'metrics').toString()).toBe(
      'http://localhost:4318/v1/metrics',
    );
    expect(otlpEndpointFor('https://otel.example.com/otlp', 'metrics').toString()).toBe(
      'https://otel.example.com/otlp/v1/metrics',
    );
    // Already-resolved URLs are left alone, so a full path from a runbook
    // round-trips instead of doubling into /v1/traces/v1/traces.
    expect(otlpEndpointFor('http://localhost:4318/v1/traces', 'traces').toString()).toBe(
      'http://localhost:4318/v1/traces',
    );
    expect(otlpEndpointFor('http://localhost:4318/v1', 'metrics').toString()).toBe(
      'http://localhost:4318/v1/metrics',
    );
    expect(otlpEndpointFor('http://localhost:4318/v1', 'traces').toString()).toBe(
      'http://localhost:4318/v1/traces',
    );
    // A bare host and port is what a compose file names, so it has to be told
    // what to add rather than rejected with a parse error.
    expect(() => otlpEndpointFor('localhost:4318', 'traces')).toThrowError(/has no scheme/);
    expect(() => otlpEndpointFor('localhost:4318', 'traces')).toThrowError(
      /http:\/\/localhost:4318\/v1\/traces/,
    );
    expect(() => otlpEndpointFor('localhost:4318', 'traces')).toThrowError(/--otel-endpoint/);
  });

  it('refuses a gRPC endpoint with the advice that actually fixes it', () => {
    expect(() => otlpEndpointFor('grpc://localhost:4317', 'traces')).toThrowError(/does not speak/);
    expect(() => otlpEndpointFor('grpc://localhost:4317', 'traces')).toThrowError(/4318/);
    expect(() => otlpEndpointFor('ftp://localhost:4318', 'traces')).toThrowError(/scheme ftp:/);
  });
});

describe('exporting to a collector (#375)', () => {
  it('POSTs traces then metrics as OTLP JSON to the resolved paths', async () => {
    const { calls, fetchImpl } = collector();
    const exporter = new OtelExporter({
      endpoint: 'http://collector:4318',
      fetchImpl,
      headers: { authorization: 'Bearer token' },
    });
    const tracer = exporter.tracer();
    tracer.endRun();
    const results = await exporter.exportRun(tracer, severityMetrics(lint(VALID_TOML)));

    expect(results.map((result) => [result.signal, result.ok, result.status])).toEqual([
      ['traces', true, 200],
      ['metrics', true, 200],
    ]);
    expect(calls.map((call) => call.url)).toEqual([
      'http://collector:4318/v1/traces',
      'http://collector:4318/v1/metrics',
    ]);
    const init = calls[0]!.init!;
    expect(init.method).toBe('POST');
    expect(asRecord(init.headers)['content-type']).toBe('application/json');
    expect(asRecord(init.headers).authorization).toBe('Bearer token');
    expect(asRecord(JSON.parse(String(init.body))).resourceSpans).toBeInstanceOf(Array);
  });

  it('reports a refusing collector as a failed result instead of throwing', async () => {
    const { fetchImpl } = collector(400, 'missing scope name');
    const exporter = new OtelExporter({ endpoint: 'http://collector:4318', fetchImpl });
    const tracer = exporter.tracer();
    tracer.endRun();
    const [traces] = await exporter.exportRun(tracer, []);
    expect(traces!.ok).toBe(false);
    expect(traces!.status).toBe(400);
    expect(traces!.error).toContain('missing scope name');
  });

  it('survives a collector that never answers', async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error('ECONNREFUSED');
    }) as unknown as typeof fetch;
    const exporter = new OtelExporter({ endpoint: 'http://127.0.0.1:1', fetchImpl });
    const tracer = exporter.tracer();
    tracer.endRun();
    const results = await exporter.exportRun(tracer, []);
    expect(results.every((result) => !result.ok)).toBe(true);
    expect(results[0]!.error).toContain('ECONNREFUSED');
  });
});

describe('network probe spans (#375)', () => {
  it('records a client span per request, with the response attributes', async () => {
    const tracer = new OtelTracer({ now: fakeClock(0, 1) });
    const fetchImpl = vi.fn(
      async () => new Response('ok', { status: 200 }),
    ) as unknown as typeof fetch;
    const instrumented = instrumentedFetch(fetchImpl, tracer);
    await instrumented('https://anchor.example.com/.well-known/stellar.toml');
    const span = tracer.spans()[1]!;
    expect(span.name).toBe('HTTP GET');
    expect(span.kind).toBe(OTelSpanKind.client);
    expect(span.attributes['url.full']).toBe('https://anchor.example.com/.well-known/stellar.toml');
    expect(span.attributes['http.request.method']).toBe('GET');
    expect(span.attributes['http.response.status_code']).toBe(200);
    expect(span.status?.code).toBe(OTelStatusCode.ok);
  });

  it('marks a 5xx span as an error but still hands the response back', async () => {
    const tracer = new OtelTracer({ now: fakeClock(0, 1) });
    const fetchImpl = vi.fn(
      async () => new Response('nope', { status: 503 }),
    ) as unknown as typeof fetch;
    const response = await instrumentedFetch(fetchImpl, tracer)('https://anchor.example.com');
    expect(response.status).toBe(503);
    const span = tracer.spans()[1]!;
    expect(span.status?.code).toBe(OTelStatusCode.error);
    expect(span.status?.message).toContain('503');
  });

  it('re-raises a transport failure untouched after recording it', async () => {
    const tracer = new OtelTracer({ now: fakeClock(0, 1) });
    const failure = new Error('fetch failed');
    const fetchImpl = vi.fn(async () => {
      throw failure;
    }) as unknown as typeof fetch;
    await expect(instrumentedFetch(fetchImpl, tracer)('https://anchor.example.com')).rejects.toBe(
      failure,
    );
    expect(tracer.spans()[1]!.status?.message).toBe('fetch failed');
  });

  it('gives a request span the run as its parent', async () => {
    const tracer = new OtelTracer({ now: fakeClock(0, 1) });
    const fetchImpl = vi.fn(
      async () => new Response('', { status: 200 }),
    ) as unknown as typeof fetch;
    await instrumentedFetch(fetchImpl, tracer)('https://anchor.example.com');
    expect(tracer.spans()[1]!.parentSpanId).toBe(tracer.rootSpanId);
  });
});

describe('the rule hook leaves linting alone (#375)', () => {
  it('produces the same diagnostics instrumented or not', () => {
    const broken = 'VERSION = 1\nNETWORK_PASSPHRASE = "Public Net"\n';
    const plain = lint(broken);
    const tracer = new OtelTracer({ now: fakeClock(0, 1) });
    const instrumented = lint(broken, { instrumentRule: ruleSpanRecorder(tracer) });
    tracer.endRun();
    expect(instrumented.diagnostics).toEqual(plain.diagnostics);
    expect(instrumented.counts).toEqual(plain.counts);
    expect(tracer.spans().length).toBeGreaterThan(1);
  });

  it('reports a crashing rule to the instrumenter after recording the fallback', () => {
    const crasher: Rule = {
      id: 'test/crasher',
      category: 'file',
      severity: 'error',
      description: 'Throws, on purpose, to exercise the loop error path.',
      run: () => {
        throw new Error('boom');
      },
    };
    // Pushed onto the registry the loop actually iterates, so this tests the
    // real seam: the crash is converted inside the thunk, and the instrumenter
    // is handed the already-honest outcome.
    allRules.push(crasher);
    try {
      const outcomes: [string, RuleOutcome][] = [];
      const result = lint('VERSION = "2.7.0"\n', {
        instrumentRule: (ruleId, runRule) => outcomes.push([ruleId, runRule()]),
      });
      expect(outcomes).toContainEqual(['test/crasher', 'error']);
      expect(
        result.diagnostics.filter((diagnostic) => diagnostic.rule === 'internal/rule-error'),
      ).toHaveLength(1);
    } finally {
      allRules.pop();
    }
  });

  it('calls the instrumenter once per rule the loop runs, in rule order', () => {
    const seen: string[] = [];
    const result = lint(VALID_TOML, {
      instrumentRule: (ruleId, runRule) => {
        seen.push(ruleId);
        runRule();
      },
    });
    expect(result.ok).toBe(true);
    expect(seen).toEqual(allRules.map((rule) => rule.id));
  });

  it('does not call the instrumenter for a rule that is switched off', () => {
    const seen: string[] = [];
    lint(VALID_TOML, {
      rules: { 'general/version': 'off' },
      instrumentRule: (ruleId, runRule) => {
        seen.push(ruleId);
        runRule();
      },
    });
    expect(seen).not.toContain('general/version');
    expect(seen).toHaveLength(allRules.length - 1);
  });
});

describe('the CLI exports to a real collector (#375)', () => {
  async function cli(args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
    try {
      const { stdout, stderr } = await run('node', [CLI, ...args], {
        env: { ...process.env, NO_COLOR: '1' },
      });
      return { code: 0, stdout, stderr };
    } catch (error) {
      const e = error as { code?: number; stdout?: string; stderr?: string };
      return { code: e.code ?? 1, stdout: e.stdout ?? '', stderr: e.stderr ?? '' };
    }
  }

  it('sends spans and metrics for the run and still exits on the diagnostics', async () => {
    const { origin, requests } = await startCollector();
    const { code, stderr } = await cli([
      join(here, '..', 'fixtures', 'valid.toml'),
      '--strict',
      '--otel-endpoint',
      origin,
      '--otel-service-name',
      'acme-anchor',
    ]);
    expect(stderr).not.toContain('OTLP');
    expect(code).toBe(0);
    expect(requests.map((request) => request.path)).toEqual(['/v1/traces', '/v1/metrics']);
    expect(requests.every((request) => request.contentType === 'application/json')).toBe(true);

    const names = spansOf(requests[0]!.body).map((span) => span.name as string);
    expect(names[0]).toBe('stellar-toml-lint run');
    expect(names.some((name) => name.startsWith('rule '))).toBe(true);
    expect(resourceAttributes(requests[0]!.body)['service.name']).toBe('acme-anchor');
    expect(metricsOf(requests[1]!.body).map((metric) => metric.name)).toEqual([
      'stellar_toml_lint_errors_total',
      'stellar_toml_lint_warnings_total',
      'stellar_toml_lint_infos_total',
      'stellar_toml_lint_duration_seconds',
    ]);
  });

  it('a collector that is down warns on stderr without failing a clean file', async () => {
    const { origin } = await startCollector();
    // Closing the port is the outage this is meant to survive.
    const server = servers.pop()!;
    await new Promise<void>((resolve) => server.close(() => resolve()));
    const { code, stderr } = await cli([
      join(here, '..', 'fixtures', 'valid.toml'),
      '--strict',
      '--otel-endpoint',
      origin,
    ]);
    expect(code).toBe(0);
    expect(stderr).toContain('OTLP traces export');
    expect(stderr).toContain('failed');
  });

  it('exits 2 on a gRPC endpoint instead of quietly exporting nothing', async () => {
    const { code, stderr } = await cli([
      join(here, '..', 'fixtures', 'valid.toml'),
      '--otel-endpoint',
      'grpc://localhost:4317',
    ]);
    expect(code).toBe(2);
    expect(stderr).toContain('does not speak');
    expect(stderr).toContain('Run with --help for usage.');
  });
});
