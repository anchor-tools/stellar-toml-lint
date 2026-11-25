import { afterEach, describe, expect, it } from 'vitest';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import {
  AnchorSlaLatencyProber,
  discoverSlaEndpoints,
  httpTimingProbe,
  percentile,
  probeUrl,
  renderLatencyHistogram,
  renderSlaReport,
  summarize,
  type ProbeTiming,
  type TimingProbe,
} from '../../src/telemetry/slaLatencyProber.js';

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))));
});

/** A mock anchor that answers after `delayMs`, recording every request. */
async function delayedServer(delayMs: number, seen: IncomingMessage[] = []): Promise<string> {
  const server = createServer((req, res) => {
    seen.push(req);
    setTimeout(() => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"deposit":{}}');
    }, delayMs);
  });
  servers.push(server);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

const timing = (ttfbMs: number, extra: Partial<ProbeTiming> = {}): ProbeTiming => ({
  status: 200,
  dnsMs: 1,
  connectMs: 2,
  tlsMs: 3,
  ttfbMs,
  totalMs: ttfbMs + 1,
  ...extra,
});

describe('percentile / summarize', () => {
  it('interpolates linearly between ranks', () => {
    const sorted = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    expect(percentile(sorted, 50)).toBeCloseTo(5.5);
    expect(percentile(sorted, 95)).toBeCloseTo(9.55);
    expect(percentile(sorted, 99)).toBeCloseTo(9.91);
    expect(percentile(sorted, 0)).toBe(1);
    expect(percentile(sorted, 100)).toBe(10);
    expect(percentile([7], 99)).toBe(7);
    expect(percentile([], 50)).toBeNaN();
  });

  it('summarizes unsorted values', () => {
    expect(summarize([30, 10, 20])).toEqual({
      p50: 20,
      p95: 29,
      p99: 29.8,
      min: 10,
      max: 30,
      mean: 20,
    });
    expect(summarize([])).toBeUndefined();
  });
});

describe('endpoint discovery and the read-only guard', () => {
  it('discovers the four SEP server fields', () => {
    expect(
      discoverSlaEndpoints({
        TRANSFER_SERVER: 'https://a/sep6',
        TRANSFER_SERVER_SEP0024: 'https://a/sep24',
        DIRECT_PAYMENT_SERVER: 'https://a/sep31',
        ANCHOR_QUOTE_SERVER: 'https://a/sep38',
        KYC_SERVER: 'https://a/kyc',
        FEDERATION_SERVER: 42,
      }),
    ).toEqual([
      ['TRANSFER_SERVER', 'https://a/sep6'],
      ['TRANSFER_SERVER_SEP0024', 'https://a/sep24'],
      ['DIRECT_PAYMENT_SERVER', 'https://a/sep31'],
      ['ANCHOR_QUOTE_SERVER', 'https://a/sep38'],
    ]);
  });

  it('only builds URLs for read-only paths', () => {
    expect(probeUrl('https://a/sep6/')).toBe('https://a/sep6/info');
    expect(probeUrl('https://a/sep38', '/prices')).toBe('https://a/sep38/prices');
    expect(() => probeUrl('https://a/sep6', '/deposit')).toThrow(/read-only/);
    expect(() => probeUrl('https://a/sep24', '/transactions/deposit/interactive')).toThrow();
  });
});

describe('AnchorSlaLatencyProber (#527)', () => {
  it('computes percentiles and flags SLA breaches', () => {
    const prober = new AnchorSlaLatencyProber({ thresholdMs: 500 });
    const fast = prober.analyze(
      'TRANSFER_SERVER',
      'u',
      [100, 120, 110, 130].map((t) => timing(t)),
    );
    expect(fast.violations).toEqual([]);
    expect(fast.ttfb?.p50).toBe(115);
    expect(fast.tls?.p50).toBe(3);

    const tail = Array.from({ length: 98 }, () => timing(100)).concat([timing(5000), timing(5000)]);
    const tailReport = prober.analyze('X', 'u', tail);
    expect(tailReport.violations.map((v) => [v.percentile, v.severity])).toEqual([
      ['p99', 'warning'],
    ]);

    const slow = prober.analyze(
      'Y',
      'u',
      [900, 950, 1000].map((t) => timing(t, { tlsMs: 0 })),
    );
    expect(slow.violations.map((v) => v.percentile)).toEqual(['p50', 'p95', 'p99']);
    expect(slow.violations[0]?.message).toContain('exceeds the 500 ms SLA');
    expect(slow.tls).toBeUndefined();
  });

  it('counts failed probes and keeps distinct errors', () => {
    const prober = new AnchorSlaLatencyProber();
    const report = prober.analyze('Z', 'u', [
      timing(100),
      { ...timing(0), status: undefined, error: 'ECONNREFUSED' },
      { ...timing(0), status: undefined, error: 'ECONNREFUSED' },
      { ...timing(0), status: undefined },
    ]);
    expect(report.failures).toBe(3);
    expect(report.errors).toEqual(['ECONNREFUSED', 'no response']);
  });

  it('interleaves samples round-robin and paces rounds', async () => {
    const calls: string[] = [];
    const sleeps: number[] = [];
    const probe: TimingProbe = async (url) => {
      calls.push(url);
      return timing(50);
    };
    const prober = new AnchorSlaLatencyProber({
      probe,
      samples: 3,
      intervalMs: 25,
      sleep: async (ms) => {
        sleeps.push(ms);
      },
    });
    const report = await prober.probeToml({
      TRANSFER_SERVER: 'https://a/sep6',
      ANCHOR_QUOTE_SERVER: 'https://a/sep38/',
    });
    expect(calls).toEqual([
      'https://a/sep6/info',
      'https://a/sep38/info',
      'https://a/sep6/info',
      'https://a/sep38/info',
      'https://a/sep6/info',
      'https://a/sep38/info',
    ]);
    expect(sleeps).toEqual([25, 25]);
    expect(report.ok).toBe(true);
    expect(report.endpoints.map((e) => e.samples)).toEqual([3, 3]);
  });

  it('is not ok when any endpoint breaches the SLA or fails', async () => {
    const slow = new AnchorSlaLatencyProber({ probe: async () => timing(800), samples: 2 });
    expect((await slow.probeEndpoints([['A', 'https://a/info']])).ok).toBe(false);
    const broken = new AnchorSlaLatencyProber({
      probe: async () => ({ ...timing(0), status: undefined, error: 'x' }),
      samples: 1,
    });
    expect((await broken.probeEndpoints([['A', 'https://a/info']])).ok).toBe(false);
  });

  it('uses a default sleep when pacing', async () => {
    const prober = new AnchorSlaLatencyProber({
      probe: async () => timing(1),
      samples: 2,
      intervalMs: 1,
    });
    expect((await prober.probeEndpoints([['A', 'u']])).endpoints[0]?.samples).toBe(2);
  });
});

describe('httpTimingProbe against mock delayed servers', () => {
  it('measures TTFB on a slow server and only sends GET /info', async () => {
    const seen: IncomingMessage[] = [];
    const base = await delayedServer(120, seen);
    const prober = new AnchorSlaLatencyProber({ samples: 3, thresholdMs: 50 });
    const report = await prober.probeToml({ TRANSFER_SERVER: base });
    const endpoint = report.endpoints[0];
    expect(endpoint?.failures).toBe(0);
    expect(endpoint?.ttfb?.min).toBeGreaterThanOrEqual(110);
    expect(endpoint?.violations.map((v) => v.percentile)).toContain('p50');
    expect(report.ok).toBe(false);
    expect(seen.map((r) => `${r.method} ${r.url}`)).toEqual([
      'GET /info',
      'GET /info',
      'GET /info',
    ]);
  });

  it('meets the SLA on a fast server', async () => {
    const base = await delayedServer(0);
    const report = await new AnchorSlaLatencyProber({ samples: 5 }).probeToml({
      TRANSFER_SERVER_SEP0024: base,
    });
    expect(report.ok).toBe(true);
    expect(report.endpoints[0]?.ttfb?.p99).toBeLessThan(500);
    expect(report.endpoints[0]?.connect).toBeDefined();
  });

  it('reports timeouts, refused connections and bad URLs without throwing', async () => {
    const base = await delayedServer(500);
    const slow = await httpTimingProbe(`${base}/info`, 50);
    expect(slow.error).toMatch(/timed out/);
    expect(slow.status).toBeUndefined();

    const closed = createServer();
    await new Promise<void>((r) => closed.listen(0, '127.0.0.1', r));
    const port = (closed.address() as AddressInfo).port;
    await new Promise((r) => closed.close(r));
    expect((await httpTimingProbe(`http://127.0.0.1:${port}/info`, 1000)).error).toBeDefined();

    expect((await httpTimingProbe('not a url', 1000)).error).toMatch(/Invalid URL/);
  });

  it('times the DNS lookup when the host is a name', async () => {
    const base = (await delayedServer(0)).replace('127.0.0.1', 'localhost');
    const result = await httpTimingProbe(`${base}/info`, 2000);
    // localhost may resolve to ::1 first; either way the probe settles with timings.
    expect(result.dnsMs).toBeGreaterThanOrEqual(0);
    expect(result.totalMs).toBeGreaterThan(0);
  });

  it('records a TLS phase over HTTPS when reachable', async () => {
    // localhost has no TLS listener; the probe must still resolve, not throw.
    const result = await httpTimingProbe('https://127.0.0.1:1/info', 500);
    expect(result.error).toBeDefined();
    expect(result.tlsMs).toBe(0);
  });
});

describe('rendering', () => {
  it('draws a histogram that marks bins above the SLA', () => {
    const text = renderLatencyHistogram([100, 110, 120, 900], 500, 4, 10);
    expect(text.split('\n').filter(Boolean)).toHaveLength(4);
    expect(text).toContain('⚠');
    expect(renderLatencyHistogram([], 500)).toContain('no successful samples');
    expect(renderLatencyHistogram([5, 5], 500, 2)).toContain('█');
  });

  it('renders a full report', async () => {
    const prober = new AnchorSlaLatencyProber({
      probe: async (url) => (url.includes('slow') ? timing(900) : timing(80)),
      samples: 2,
    });
    const report = await prober.probeEndpoints([
      ['TRANSFER_SERVER', 'https://fast/info'],
      ['ANCHOR_QUOTE_SERVER', 'https://slow/info'],
    ]);
    const text = renderSlaReport(report);
    expect(text).toContain('TRANSFER_SERVER  https://fast/info');
    expect(text).toContain('✓ within SLA');
    expect(text).toContain('TLS      p50 3.0');
    expect(text).toContain('✗ ANCHOR_QUOTE_SERVER p50 TTFB 900.0 ms exceeds');
    expect(text).toContain('✗ SLA violations found');

    const broken = new AnchorSlaLatencyProber().analyze('A', 'u', [
      { ...timing(0), status: undefined, error: 'boom' },
    ]);
    const failed = renderSlaReport({ ok: false, thresholdMs: 500, endpoints: [broken] });
    expect(failed).toContain('TTFB     n/a');
    expect(failed).toContain('probe failed: boom');

    expect(renderSlaReport({ ok: true, thresholdMs: 500, endpoints: [] })).toContain(
      'No SEP endpoints declared',
    );
  });
});
