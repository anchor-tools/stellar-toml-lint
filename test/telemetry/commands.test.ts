import { describe, expect, it, vi } from 'vitest';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  auditErrorTaxonomyCommand,
  calculateUptimeCommand,
  fetchStellarToml,
  probeSlaCommand,
  processIo,
  verifyMetricsCommand,
  type CommandIo,
} from '../../src/telemetry/commands.js';
import type { ProbeTiming } from '../../src/telemetry/slaLatencyProber.js';

const GOOD_METRICS = `# HELP stellar_anchor_balance b
# TYPE stellar_anchor_balance gauge
stellar_anchor_balance 1
# HELP stellar_tx_processed_total t
# TYPE stellar_tx_processed_total counter
stellar_tx_processed_total 1
# HELP stellar_sep_request_duration_seconds d
# TYPE stellar_sep_request_duration_seconds histogram
stellar_sep_request_duration_seconds_bucket{le="+Inf"} 1
stellar_sep_request_duration_seconds_sum 1
stellar_sep_request_duration_seconds_count 1
`;

const TOML = `TRANSFER_SERVER = "https://anchor.example/sep6"
METRICS_URL = "https://anchor.example/metrics"
`;

interface Captured extends CommandIo {
  out: string;
  err: string;
  requested: string[];
}

function io(routes: Record<string, () => Response> = {}, extra: Partial<CommandIo> = {}): Captured {
  const c: Captured = {
    out: '',
    err: '',
    requested: [],
    stdout: (t) => {
      c.out += t;
    },
    stderr: (t) => {
      c.err += t;
    },
    fetchImpl: (async (input: string | URL | Request) => {
      const url = String(input);
      c.requested.push(url);
      const route = Object.entries(routes).find(([prefix]) => url.startsWith(prefix));
      if (route === undefined) return new Response('not found', { status: 404 });
      return route[1]();
    }) as typeof fetch,
    ...extra,
  };
  return c;
}

const text =
  (body: string, type = 'text/plain', status = 200) =>
  () =>
    new Response(body, { status, headers: { 'content-type': type } });

const timing = (ttfbMs: number): ProbeTiming => ({
  status: 200,
  dnsMs: 0,
  connectMs: 1,
  tlsMs: 0,
  ttfbMs,
  totalMs: ttfbMs,
});

describe('processIo', () => {
  it('writes to the real process streams', () => {
    const out = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const err = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    processIo.stdout('a');
    processIo.stderr('b');
    expect(out).toHaveBeenCalledWith('a');
    expect(err).toHaveBeenCalledWith('b');
    out.mockRestore();
    err.mockRestore();
  });
});

describe('fetchStellarToml', () => {
  it('fetches the well-known path over https or explicit http', async () => {
    const c = io({ 'https://anchor.example/.well-known/stellar.toml': text(TOML) });
    expect((await fetchStellarToml('https://anchor.example/', c.fetchImpl)).TRANSFER_SERVER).toBe(
      'https://anchor.example/sep6',
    );
    const h = io({ 'http://127.0.0.1:8000/.well-known/stellar.toml': text(TOML) });
    await fetchStellarToml('http://127.0.0.1:8000', h.fetchImpl);
    expect(h.requested).toEqual(['http://127.0.0.1:8000/.well-known/stellar.toml']);
    await expect(fetchStellarToml('missing.example', c.fetchImpl)).rejects.toThrow(/HTTP 404/);
  });
});

describe('verify-metrics', () => {
  it('validates an explicit --url', async () => {
    const c = io({ 'https://m/metrics': text(GOOD_METRICS) });
    expect(await verifyMetricsCommand(['--url', 'https://m/metrics'], c)).toBe(0);
    expect(c.out).toContain('✓ Exposition is valid');
  });

  it('discovers the endpoint from --domain and emits JSON', async () => {
    const c = io({
      'https://anchor.example/.well-known/stellar.toml': text(TOML),
      'https://anchor.example/metrics': text('# TYPE x bogus\nx 1\n'),
    });
    expect(
      await verifyMetricsCommand(
        ['--domain', 'anchor.example', '--format', 'json', '--no-required-metrics'],
        c,
      ),
    ).toBe(1);
    expect(JSON.parse(c.out).issues[0].code).toBe('metrics/invalid-type');
  });

  it('reads a local --toml and supports --require and multiple URLs', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'stl-metrics-'));
    const path = join(dir, 'stellar.toml');
    await writeFile(path, TOML);
    const c = io({ 'https://anchor.example/metrics': text(GOOD_METRICS) });
    expect(await verifyMetricsCommand(['--toml', path, '--require', 'custom_metric'], c)).toBe(0);
    expect(c.out).toContain('Required anchor metric custom_metric is not exported');

    const two = io({
      'https://a/metrics': text(GOOD_METRICS),
      'https://b/metrics': text(GOOD_METRICS),
    });
    expect(
      await verifyMetricsCommand(
        ['--url', 'https://a/metrics', '--url', 'https://b/metrics', '--format', 'json'],
        two,
      ),
    ).toBe(0);
    expect(JSON.parse(two.out)).toHaveLength(2);
  });

  it('fails cleanly without a metrics endpoint or arguments', async () => {
    const c = io({ 'https://x/.well-known/stellar.toml': text('ORG_NAME = "x"') });
    expect(await verifyMetricsCommand(['--domain', 'x'], c)).toBe(2);
    expect(c.err).toContain('advertises no metrics endpoint');
    const none = io();
    expect(await verifyMetricsCommand([], none)).toBe(2);
    expect(none.err).toContain('Usage: stellar-toml-lint verify-metrics');
    expect(await verifyMetricsCommand(['--bogus'], io())).toBe(2);
    expect(await verifyMetricsCommand(['--url'], io())).toBe(2);
    expect(await verifyMetricsCommand(['--url', 'u', '--format', 'xml'], io())).toBe(2);
    const down = io();
    expect(await verifyMetricsCommand(['--domain', 'down.example'], down)).toBe(2);
    expect(down.err).toContain('HTTP 404');
  });
});

describe('probe-sla', () => {
  it('probes every declared SEP endpoint and reports', async () => {
    const urls: string[] = [];
    const c = io(
      { 'https://anchor.example/.well-known/stellar.toml': text(TOML) },
      {
        probe: async (url) => {
          urls.push(url);
          return timing(120);
        },
      },
    );
    expect(
      await probeSlaCommand(
        [
          '--domain',
          'anchor.example',
          '--samples',
          '3',
          '--interval-ms',
          '0',
          '--timeout-ms',
          '100',
        ],
        c,
      ),
    ).toBe(0);
    expect(urls).toEqual(Array(3).fill('https://anchor.example/sep6/info'));
    expect(c.out).toContain('TRANSFER_SERVER  https://anchor.example/sep6/info');
  });

  it('fails on SLA breaches and supports JSON output', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'stl-sla-'));
    const path = join(dir, 'stellar.toml');
    await writeFile(path, TOML);
    const c = io({}, { probe: async () => timing(800) });
    expect(
      await probeSlaCommand(
        ['--toml', path, '--samples', '2', '--threshold-ms', '700', '--format', 'json'],
        c,
      ),
    ).toBe(1);
    expect(JSON.parse(c.out).endpoints[0].violations[0].percentile).toBe('p50');
  });

  it('validates arguments', async () => {
    for (const args of [
      [],
      ['--domain'],
      ['--domain', 'x', '--samples', '0'],
      ['--domain', 'x', '--threshold-ms', '-1'],
      ['--nope'],
    ]) {
      const c = io();
      expect(await probeSlaCommand(args, c)).toBe(2);
      expect(c.err).toContain('Usage: stellar-toml-lint probe-sla');
    }
    const c = io();
    expect(await probeSlaCommand(['--domain', 'gone.example'], c)).toBe(2);
    expect(c.err).toContain('HTTP 404');
  });
});

describe('--audit-error-taxonomy', () => {
  it('audits endpoints from --domain', async () => {
    const c = io({
      'https://anchor.example/.well-known/stellar.toml': text(TOML),
      'https://anchor.example/sep6': text('{"error":"bad"}', 'application/json', 400),
    });
    expect(
      await auditErrorTaxonomyCommand(['--audit-error-taxonomy', '--domain', 'anchor.example'], c),
    ).toBe(0);
    expect(c.out).toContain('HTTP error taxonomy audit');
    expect(c.requested.filter((u) => u.includes('/sep6')).length).toBeGreaterThan(0);
  });

  it('accepts a positional stellar.toml and fails on HTML errors', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'stl-err-'));
    const path = join(dir, 'stellar.toml');
    await writeFile(path, TOML);
    const c = io({ 'https://anchor.example/sep6': text('<html>oops</html>', 'text/html', 500) });
    expect(await auditErrorTaxonomyCommand([path, '-f', 'json'], c)).toBe(1);
    expect(JSON.parse(c.out).ok).toBe(false);
  });

  it('validates arguments', async () => {
    expect(await auditErrorTaxonomyCommand(['--audit-error-taxonomy'], io())).toBe(2);
    expect(await auditErrorTaxonomyCommand(['--domain', 'x', '--weird'], io())).toBe(2);
    const c = io();
    expect(await auditErrorTaxonomyCommand(['-d', 'nope.example'], c)).toBe(2);
    expect(c.err).toContain('HTTP 404');
  });
});

describe('calculate-uptime', () => {
  const CSV = [
    'timestamp,service,status',
    ...Array.from(
      { length: 10 },
      (_, i) =>
        `${new Date(Date.UTC(2026, 10, 1, 0, i)).toISOString()},sep24,${i === 4 ? 'down' : 'up'}`,
    ),
    'junk,sep24,up',
  ].join('\n');

  it('prints text, markdown and JSON and writes badges', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'stl-uptime-'));
    const log = join(dir, 'health.csv');
    await writeFile(log, CSV);
    const svg = join(dir, 'badge.svg');
    const json = join(dir, 'badge.json');

    const t = io();
    expect(
      await calculateUptimeCommand(
        ['--log-file', log, '--badge-svg', svg, '--badge-json', json],
        t,
      ),
    ).toBe(0);
    expect(t.out).toContain('sep24  (10 checks');
    expect(t.err).toContain('Skipped 1 unreadable row(s): 12');
    expect(await readFile(svg, 'utf8')).toContain('90%');
    expect(JSON.parse(await readFile(json, 'utf8')).message).toBe('90%');

    const md = io();
    expect(
      await calculateUptimeCommand(
        ['--log-file', log, '--format', 'markdown', '--decimals', '1'],
        md,
      ),
    ).toBe(0);
    expect(md.out).toContain('| sep24 | 90% |');

    const js = io();
    expect(
      await calculateUptimeCommand(
        [
          '--log-file',
          log,
          '--format',
          'json',
          '--now',
          '2026-11-01T00:10:00Z',
          '--interval-ms',
          '60000',
        ],
        js,
      ),
    ).toBe(0);
    expect(JSON.parse(js.out).services[0].incidents).toHaveLength(1);
  });

  it('exits 1 below --min-availability', async () => {
    const c = io({}, { readFile: async () => CSV });
    expect(
      await calculateUptimeCommand(['--log-file', 'h.csv', '--min-availability', '99.9'], c),
    ).toBe(1);
    expect(c.err).toContain('below the required 99.9%');
    const none = io({}, { readFile: async () => CSV });
    expect(
      await calculateUptimeCommand(
        ['--log-file', 'h.csv', '--now', '2020-01-01T00:00:00Z', '--min-availability', '1'],
        none,
      ),
    ).toBe(1);
    expect(none.err).toContain('n/a%');
  });

  it('reports empty logs, read errors and bad arguments', async () => {
    const empty = io({}, { readFile: async () => 'timestamp,status\n' });
    expect(await calculateUptimeCommand(['--log-file', 'e.csv'], empty)).toBe(2);
    expect(empty.err).toContain('No usable health-check records');
    const missing = io();
    expect(
      await calculateUptimeCommand(
        ['--log-file', join(tmpdir(), 'definitely-missing-stl.csv')],
        missing,
      ),
    ).toBe(2);
    expect(missing.err).toContain('ENOENT');
    for (const args of [
      [],
      ['--log-file', 'x', '--now', 'yesterday'],
      ['--log-file', 'x', '--decimals', '9'],
      ['--log-file', 'x', '--decimals', '1.5'],
      ['--log-file', 'x', '--format', 'pdf'],
      ['--x'],
    ]) {
      const c = io();
      expect(await calculateUptimeCommand(args, c)).toBe(2);
      expect(c.err).toContain('Usage: stellar-toml-lint calculate-uptime');
    }
    const thrown = io(
      {},
      {
        readFile: async () => {
          throw 'weird';
        },
      },
    );
    expect(await calculateUptimeCommand(['--log-file', 'x'], thrown)).toBe(2);
    expect(thrown.err).toBe('weird\n');
  });
});
