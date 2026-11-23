import { describe, expect, it, vi } from 'vitest';
import {
  OpenTelemetryTraceValidator,
  discoverTraceEndpoints,
  generateTraceContext,
  parseTraceparent,
} from '../src/telemetry/traceValidator.js';

const SEP6 = 'TRANSFER_SERVER';
const TRACE_ID = 'abcdef0123456789'.repeat(2);
const PARENT_ID = '2'.repeat(16);
const OTHER_TRACE_ID = 'a'.repeat(32);
const OTHER_PARENT_ID = 'b'.repeat(16);

function traceparent(traceId = TRACE_ID, parentId = PARENT_ID, flags = '03'): string {
  return `00-${traceId}-${parentId}-${flags}`;
}

function fetchResponse(headers: Record<string, string> = {}, status = 200): Response {
  return new Response('{}', { status, headers });
}

function document(url = 'https://anchor.example.test/sep6'): Record<string, unknown> {
  return { [SEP6]: url };
}

function mockFetch(respond: (url: string, init?: RequestInit) => Response | Promise<Response>) {
  return vi.fn(async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    const url =
      typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    return respond(url, init);
  }) as unknown as typeof fetch;
}

describe('W3C trace context', () => {
  it('generates version-00 traceparent values with valid non-zero identifiers', () => {
    const generated = generateTraceContext();
    expect(generated.traceparent).toMatch(/^00-[0-9a-f]{32}-[0-9a-f]{16}-03$/);
    expect(generated.traceId).not.toBe('0'.repeat(32));
    expect(generated.parentId).not.toBe('0'.repeat(16));
    expect(parseTraceparent(generated.traceparent)).toEqual({
      version: '00',
      traceId: generated.traceId,
      parentId: generated.parentId,
      traceFlags: '03',
    });
  });

  it.each([
    '00-' + '0'.repeat(32) + '-' + PARENT_ID + '-01',
    '00-' + TRACE_ID + '-' + '0'.repeat(16) + '-01',
    `00-${TRACE_ID}-${PARENT_ID.slice(1)}-01`,
    `00-${TRACE_ID}-${PARENT_ID.slice(0, 15)}z-01`,
    `00-${TRACE_ID.toUpperCase()}-${PARENT_ID}-01`,
    `00-${TRACE_ID}-${PARENT_ID}-0`,
    `00-${TRACE_ID}-${PARENT_ID}-0g`,
    `01-${TRACE_ID}-${PARENT_ID}-01`,
    `ff-${TRACE_ID}-${PARENT_ID}-01`,
    `00-${TRACE_ID}-${PARENT_ID}-01-extra`,
  ])('rejects malformed traceparent %s', (value) => {
    expect(parseTraceparent(value)).toBeUndefined();
  });

  it('accepts unknown version-00 flag bits while preserving the byte', () => {
    expect(parseTraceparent(traceparent(TRACE_ID, PARENT_ID, 'ff'))?.traceFlags).toBe('ff');
  });
});

describe('SEP endpoint discovery', () => {
  it('discovers SEP-6, SEP-24, SEP-31 and SEP-38 info URLs', () => {
    const found = discoverTraceEndpoints({
      TRANSFER_SERVER: 'https://anchor.example.test/sep6/',
      TRANSFER_SERVER_SEP0024: 'https://anchor.example.test/sep24',
      DIRECT_PAYMENT_SERVER: 'https://anchor.example.test/sep31',
      ANCHOR_QUOTE_SERVER: 'https://anchor.example.test/sep38',
    });
    expect(found.invalid).toEqual([]);
    expect(
      found.endpoints.map(({ definitions, url }) => [
        definitions[0]?.sep,
        definitions[0]?.field,
        url.pathname,
      ]),
    ).toEqual([
      ['SEP-6', 'TRANSFER_SERVER', '/sep6/info'],
      ['SEP-24', 'TRANSFER_SERVER_SEP0024', '/sep24/info'],
      ['SEP-31', 'DIRECT_PAYMENT_SERVER', '/sep31/info'],
      ['SEP-38', 'ANCHOR_QUOTE_SERVER', '/sep38/info'],
    ]);
  });

  it('deduplicates identical service URLs while retaining all associated SEP fields', () => {
    const found = discoverTraceEndpoints({
      TRANSFER_SERVER: 'https://anchor.example.test/api',
      TRANSFER_SERVER_SEP0024: 'https://anchor.example.test/api/',
    });
    expect(found.endpoints).toHaveLength(1);
    expect(found.endpoints[0]?.definitions.map(({ field }) => field)).toEqual([
      'TRANSFER_SERVER',
      'TRANSFER_SERVER_SEP0024',
    ]);
  });

  it.each([
    'http://anchor.example.test',
    'https://localhost/api',
    'https://127.0.0.1/api',
    'https://169.254.169.254/latest',
    'https://anchor.example.test/api?token=secret',
    'https://user:pass@anchor.example.test/api',
  ])('rejects unsafe service URL %s', (url) => {
    expect(discoverTraceEndpoints({ TRANSFER_SERVER: url }).invalid).toHaveLength(1);
  });
});

describe('OpenTelemetryTraceValidator', () => {
  it('injects a valid traceparent and recognizes traceresponse correlation', async () => {
    let requestHeader = '';
    const fetchImpl = mockFetch((_url, init) => {
      requestHeader = new Headers(init?.headers).get('traceparent') ?? '';
      return fetchResponse({ traceresponse: requestHeader });
    });
    const result = await new OpenTelemetryTraceValidator({ fetchImpl }).verify(document());
    expect(requestHeader).toMatch(/^00-[0-9a-f]{32}-[0-9a-f]{16}-03$/);
    expect(fetchImpl).toHaveBeenCalledWith(
      'https://anchor.example.test/sep6/info',
      expect.objectContaining({ method: 'GET', redirect: 'manual' }),
    );
    expect(result.results[0]).toMatchObject({ status: 'compliant', evidence: 'traceresponse' });
    expect(result.diagnostics[0]?.rule).toBe('telemetry/correlation-observed');
  });

  it('recognizes Server-Timing trace correlation and trace restarts', async () => {
    const fetchImpl = mockFetch(() =>
      fetchResponse({
        'server-timing': `cache;desc="hit, fresh", trace;desc="${traceparent(OTHER_TRACE_ID, OTHER_PARENT_ID)}";dur=12`,
      }),
    );
    const result = await new OpenTelemetryTraceValidator({ fetchImpl }).verify(document());
    expect(result.results[0]?.status).toBe('compliant');
    expect(result.results[0]?.responseTraceId).toBe(OTHER_TRACE_ID);
    expect(result.results[0]?.detail).toContain('legitimate trace restart');
    expect(result.diagnostics[0]?.rule).toBe('telemetry/trace-restarted');
  });

  it('does not call missing response evidence a propagation failure', async () => {
    const fetchImpl = mockFetch(() => fetchResponse());
    const result = await new OpenTelemetryTraceValidator({ fetchImpl }).verify(document());
    expect(result.results[0]?.status).toBe('unobservable');
    expect(result.diagnostics[0]?.severity).toBe('info');
    expect(result.results[0]?.detail).toContain('cannot be determined externally');
  });

  it('reports malformed trace metadata and conflicting response mechanisms', async () => {
    const malformed = await new OpenTelemetryTraceValidator({
      fetchImpl: mockFetch(() => fetchResponse({ traceresponse: `00-${TRACE_ID}-bad-01` })),
    }).verify(document());
    expect(malformed.results[0]?.status).toBe('non-compliant');

    const inconsistent = await new OpenTelemetryTraceValidator({
      fetchImpl: mockFetch(() =>
        fetchResponse({
          traceresponse: traceparent(TRACE_ID),
          'server-timing': `trace;desc="${traceparent(OTHER_TRACE_ID, OTHER_PARENT_ID)}"`,
        }),
      ),
    }).verify(document());
    expect(inconsistent.results[0]?.status).toBe('non-compliant');
    expect(inconsistent.results[0]?.detail).toContain('conflicting trace or span IDs');
    expect(inconsistent.diagnostics[0]?.rule).toBe('telemetry/invalid-correlation');
  });

  it('inspects correlation headers on HTTP error responses', async () => {
    let requestContext = '';
    const result = await new OpenTelemetryTraceValidator({
      fetchImpl: mockFetch((_url, init) => {
        requestContext = new Headers(init?.headers).get('traceparent') ?? '';
        return fetchResponse({ traceresponse: requestContext }, 503);
      }),
    }).verify(document());
    expect(result.results[0]).toMatchObject({ status: 'compliant', httpStatus: 503 });
  });

  it('rejects redirects without following their location', async () => {
    const fetchImpl = mockFetch(
      () => new Response(null, { status: 302, headers: { location: 'http://127.0.0.1/' } }),
    );
    const result = await new OpenTelemetryTraceValidator({ fetchImpl }).verify(document());
    expect(result.results[0]?.status).toBe('unreachable');
    expect(result.results[0]?.detail).toContain('redirects are not followed');
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('reports a network failure as unreachable instead of throwing', async () => {
    const fetchImpl = mockFetch(() => Promise.reject(new TypeError('socket failed')));
    const result = await new OpenTelemetryTraceValidator({ fetchImpl }).verify(document());
    expect(result.results[0]?.status).toBe('unreachable');
    expect(result.results[0]?.detail).toContain('could not be safely reached');
  });

  it('makes one probe for a shared URL and reports each associated SEP field', async () => {
    const fetchImpl = mockFetch((_url, init) => {
      const context = new Headers(init?.headers).get('traceparent') ?? '';
      return fetchResponse({ traceresponse: context });
    });
    const result = await new OpenTelemetryTraceValidator({ fetchImpl }).verify({
      TRANSFER_SERVER: 'https://anchor.example.test/api',
      TRANSFER_SERVER_SEP0024: 'https://anchor.example.test/api/',
    });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(result.results.map(({ field }) => field)).toEqual([
      'TRANSFER_SERVER',
      'TRANSFER_SERVER_SEP0024',
    ]);
  });

  it('reports a timeout and does not wait for a transport that ignores abort', async () => {
    const fetchImpl = mockFetch(() => new Promise<Response>(() => {}));
    const result = await new OpenTelemetryTraceValidator({ fetchImpl, timeoutMs: 5 }).verify(
      document(),
    );
    expect(result.results[0]?.status).toBe('unreachable');
    expect(result.results[0]?.detail).toContain('timed out');
  });

  it('does not send requests to unsafe endpoints', async () => {
    const fetchImpl = mockFetch(() => fetchResponse({ traceresponse: traceparent() }));
    const result = await new OpenTelemetryTraceValidator({ fetchImpl }).verify(
      document('https://127.0.0.1/internal'),
    );
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(result.results[0]?.status).toBe('unreachable');
    expect(result.results[0]?.detail).toContain('no request was sent');
  });

  it('reports no eligible endpoints without inventing a successful probe', async () => {
    const result = await new OpenTelemetryTraceValidator({
      fetchImpl: mockFetch(() => fetchResponse()),
    }).verify({});
    expect(result.results).toEqual([]);
    expect(result.diagnostics[0]?.rule).toBe('telemetry/no-endpoints');
  });
});
