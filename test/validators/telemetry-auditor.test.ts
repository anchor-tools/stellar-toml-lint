import { describe, expect, it, vi } from 'vitest';

import {
  checkValidatorTelemetry,
  DEFAULT_LEDGER_CLOSE_LATENCY_MS,
  evaluateTelemetry,
  extractLedgerCloseLatencyMs,
  extractLostSync,
  extractTelemetryFromInfo,
  fetchTelemetrySnapshot,
  FREQUENT_LOST_SYNC_RULE,
  HIGH_NOMINATION_LATENCY_RULE,
  parsePrometheusMetrics,
  resolveTelemetryEndpoint,
  telemetryAuditorRules,
} from '../../src/validators/telemetry-auditor.js';

const A = 'GAOOOWJ2U7AITCNNUQ4LNRRTKOQGBYBSAXRXQHVUNOAQJYMZPM5QJ4EM';
const B = 'GAVLKMYOGHWXNBOQCH5XCGJPMHF7KWBAXRXQHVUNOAQJYMZPM5QB4CDD';

describe('parsePrometheusMetrics', () => {
  it('parses gauges, counters, labels, and normalised names', () => {
    const samples = parsePrometheusMetrics(`
# HELP ledger_close_latency Ledger close latency
# TYPE ledger_close_latency gauge
ledger_close_latency{host="v1"} 1200
scp.sync.lost-sync_total{reason="timeout"} 2
scp.sync.lost-sync_total{reason="peer"} 1
ignored non-numeric 5
not a metric line
`);
    expect(samples).toHaveLength(3);
    expect(samples[0]).toMatchObject({
      name: 'ledger_close_latency',
      normalizedName: 'ledger_close_latency',
      value: 1200,
      labels: { host: 'v1' },
    });
    expect(extractLostSync(samples)).toBe(3);
  });

  it('reads a histogram as sum/count and converts seconds to milliseconds', () => {
    const samples = parsePrometheusMetrics(`
ledger.close.latency.seconds_sum 12
ledger.close.latency.seconds_count 4
scp_sync_lost_sync_total 0
`);
    expect(extractLedgerCloseLatencyMs(samples)).toBe(3000);
  });

  it('averages a plain gauge and converts the seconds aliases', () => {
    const samples = parsePrometheusMetrics(`
ledger_close_latency_ms{node="a"} 1000
ledger_close_latency_ms{node="b"} 2000
`);
    expect(extractLedgerCloseLatencyMs(samples)).toBe(1500);
  });
});

describe('extractTelemetryFromInfo', () => {
  it('reads metrics nested in the JSON info response', () => {
    const extracted = extractTelemetryFromInfo({
      info: {
        metrics: {
          'ledger.close.latency': 1800,
          'scp.sync.lost-sync': 2,
        },
      },
    });
    expect(extracted).toEqual({
      averageLedgerCloseLatencyMs: 1800,
      lostSync: 2,
    });
  });

  it('ignores unrelated fields', () => {
    expect(extractTelemetryFromInfo({ info: { build: 'stellar-core 21' } })).toEqual({});
  });
});

describe('resolveTelemetryEndpoint', () => {
  it('prefers explicit URLs and accepts an index override', () => {
    expect(resolveTelemetryEndpoint({ METRICS_URL: 'https://metrics.example/custom' })).toBe(
      'https://metrics.example/custom',
    );
    expect(
      resolveTelemetryEndpoint({ PUBLIC_KEY: A }, 2, {
        endpoints: { [A]: 'http://127.0.0.1:11626/metrics' },
      }),
    ).toBe('http://127.0.0.1:11626/metrics');
    expect(
      resolveTelemetryEndpoint({ HOST: 'validator.example' }, 1, {
        endpoints: { 1: 'http://127.0.0.1:9999' },
      }),
    ).toBe('http://127.0.0.1:9999');
  });

  it('combines ADMIN_PORT/METRICS_PORT with the declared host', () => {
    expect(
      resolveTelemetryEndpoint({
        HOST: 'validator.example:11625',
        ADMIN_PORT: 11626,
      }),
    ).toBe('http://validator.example:11626/metrics');
    expect(
      resolveTelemetryEndpoint({
        HOST: 'validator.example',
        ADMIN_HOST: 'admin.example',
        METRICS_PORT: '9100',
        METRICS_TLS: true,
      }),
    ).toBe('https://admin.example:9100/metrics');
  });

  it('stays silent without an admin surface or with an invalid port', () => {
    expect(resolveTelemetryEndpoint({ HOST: 'validator.example' })).toBeUndefined();
    expect(
      resolveTelemetryEndpoint({ HOST: 'validator.example', ADMIN_PORT: 99999 }),
    ).toBeUndefined();
  });
});

describe('evaluateTelemetry', () => {
  it('passes a healthy node', () => {
    expect(
      evaluateTelemetry({
        endpoint: 'https://v1.example/metrics',
        source: 'metrics',
        averageLedgerCloseLatencyMs: 1200,
        lostSync: 0,
      }),
    ).toEqual([]);
  });

  it('warns when ledger close latency exceeds the 3500 ms budget', () => {
    const diagnostics = evaluateTelemetry({
      endpoint: 'https://v1.example/metrics',
      source: 'metrics',
      averageLedgerCloseLatencyMs: 4200,
    });
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      rule: HIGH_NOMINATION_LATENCY_RULE,
      severity: 'warning',
      path: 'VALIDATORS',
    });
    expect(diagnostics[0]?.message).toContain(`${DEFAULT_LEDGER_CLOSE_LATENCY_MS} ms`);
  });

  it('errors on any lost-sync event and honours a custom threshold', () => {
    const snapshot = {
      endpoint: 'https://v1.example/metrics',
      source: 'metrics' as const,
      lostSync: 2,
    };
    const diagnostics = evaluateTelemetry(snapshot);
    expect(diagnostics[0]).toMatchObject({
      rule: FREQUENT_LOST_SYNC_RULE,
      severity: 'error',
    });
    expect(evaluateTelemetry(snapshot, { maxLostSync: 2 })).toEqual([]);
  });

  it('honours --off, --warn, and --error overrides', () => {
    const snapshot = {
      endpoint: 'https://v1.example/metrics',
      source: 'metrics' as const,
      averageLedgerCloseLatencyMs: 9000,
    };
    expect(
      evaluateTelemetry(snapshot, { rules: { [HIGH_NOMINATION_LATENCY_RULE]: 'off' } }),
    ).toEqual([]);
    expect(
      evaluateTelemetry(snapshot, { rules: { [HIGH_NOMINATION_LATENCY_RULE]: 'error' } })[0]
        ?.severity,
    ).toBe('error');
  });
});

describe('fetchTelemetrySnapshot', () => {
  it('fetches Prometheus metrics first', async () => {
    const fetchImpl = vi.fn(
      async () => new Response('ledger_close_latency 800\nscp.sync.lost-sync 1\n', { status: 200 }),
    );
    const snapshot = await fetchTelemetrySnapshot('https://v1.example', fetchImpl as typeof fetch);
    expect(fetchImpl).toHaveBeenCalledWith('https://v1.example/metrics');
    expect(snapshot).toEqual({
      endpoint: 'https://v1.example/metrics',
      source: 'metrics',
      averageLedgerCloseLatencyMs: 800,
      lostSync: 1,
    });
  });

  it('falls back to the JSON /info endpoint', async () => {
    const fetchImpl = vi.fn(async (url: string | URL | Request) => {
      const href = String(url);
      if (href.endsWith('/metrics')) return new Response('not found', { status: 404 });
      return new Response(
        JSON.stringify({
          info: { metrics: { 'ledger.close.latency': 2400, 'scp.sync.lost-sync': 0 } },
        }),
        { status: 200 },
      );
    });
    const snapshot = await fetchTelemetrySnapshot('https://v1.example', fetchImpl as typeof fetch);
    expect(fetchImpl).toHaveBeenCalledWith('https://v1.example/info');
    expect(snapshot).toMatchObject({
      source: 'info',
      averageLedgerCloseLatencyMs: 2400,
      lostSync: 0,
    });
  });

  it('returns undefined when neither surface exposes a metric', async () => {
    const fetchImpl = vi.fn(async () => new Response('unrelated 1', { status: 200 }));
    expect(
      await fetchTelemetrySnapshot('https://v1.example', fetchImpl as typeof fetch),
    ).toBeUndefined();
  });
});

describe('checkValidatorTelemetry', () => {
  it('passes healthy validators and flags a slow one', async () => {
    const fetchImpl = vi.fn(async (url: string | URL | Request) => {
      const href = String(url);
      if (href.includes('slow')) {
        return new Response('ledger_close_latency 5000\nscp.sync.lost-sync 0\n', {
          status: 200,
        });
      }
      return new Response('ledger_close_latency 900\nscp.sync.lost-sync 0\n', {
        status: 200,
      });
    });

    const diagnostics = await checkValidatorTelemetry(
      {
        VALIDATORS: [
          { PUBLIC_KEY: A, METRICS_URL: 'https://fast.example/metrics' },
          { PUBLIC_KEY: B, METRICS_URL: 'https://slow.example/metrics' },
          { PUBLIC_KEY: 'no-endpoint' },
        ],
      },
      fetchImpl as typeof fetch,
    );

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      rule: HIGH_NOMINATION_LATENCY_RULE,
      path: 'VALIDATORS[1]',
    });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it('reports lost sync as an error', async () => {
    const fetchImpl = vi.fn(
      async () => new Response('scp.sync.lost-sync 4\nledger_close_latency 500\n', { status: 200 }),
    );
    const diagnostics = await checkValidatorTelemetry(
      { VALIDATORS: [{ PUBLIC_KEY: A, ADMIN_URL: 'https://v1.example' }] },
      fetchImpl as typeof fetch,
    );
    expect(diagnostics[0]).toMatchObject({
      rule: FREQUENT_LOST_SYNC_RULE,
      severity: 'error',
    });
  });

  it('stays silent when an endpoint cannot be reached', async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error('ECONNREFUSED');
    });
    expect(
      await checkValidatorTelemetry(
        { VALIDATORS: [{ PUBLIC_KEY: A, ADMIN_URL: 'https://v1.example' }] },
        fetchImpl as typeof fetch,
      ),
    ).toEqual([]);
  });

  it('is registered for --list-rules', () => {
    expect(telemetryAuditorRules.map((rule) => rule.id)).toEqual([
      HIGH_NOMINATION_LATENCY_RULE,
      FREQUENT_LOST_SYNC_RULE,
    ]);
  });
});
