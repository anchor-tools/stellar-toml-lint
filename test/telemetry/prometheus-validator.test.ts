import { describe, expect, it } from 'vitest';
import {
  detectMetricsFormat,
  discoverMetricsEndpoints,
  MetricsTextParser,
  parseLabels,
  parseMetricValue,
  PrometheusMetricsValidator,
  renderMetricsReport,
  splitSampleLine,
  validateMetricsText,
  type MetricIssueCode,
} from '../../src/telemetry/prometheusValidator.js';

const REQUIRED = `# HELP stellar_anchor_balance Hot wallet balance
# TYPE stellar_anchor_balance gauge
stellar_anchor_balance{asset="USDC"} 1234.5
# HELP stellar_tx_processed_total Processed transactions
# TYPE stellar_tx_processed_total counter
stellar_tx_processed_total{sep="24",status="completed"} 42
# HELP stellar_sep_request_duration_seconds SEP request latency
# TYPE stellar_sep_request_duration_seconds histogram
stellar_sep_request_duration_seconds_bucket{le="0.1"} 10
stellar_sep_request_duration_seconds_bucket{le="0.5"} 18
stellar_sep_request_duration_seconds_bucket{le="+Inf"} 20
stellar_sep_request_duration_seconds_sum 4.2
stellar_sep_request_duration_seconds_count 20
`;

const codes = (text: string, opts = {}): MetricIssueCode[] =>
  validateMetricsText(text, opts).issues.map((i) => i.code);

const response = (body: string, contentType = 'text/plain; version=0.0.4', status = 200) =>
  new Response(body, { status, headers: { 'content-type': contentType } });

describe('parseMetricValue', () => {
  it('accepts floats, exponents and the special values', () => {
    expect(parseMetricValue('1.5')).toBe(1.5);
    expect(parseMetricValue('-2e3')).toBe(-2000);
    expect(parseMetricValue('.5')).toBe(0.5);
    expect(parseMetricValue('+Inf')).toBe(Infinity);
    expect(parseMetricValue('Inf')).toBe(Infinity);
    expect(parseMetricValue('-Inf')).toBe(-Infinity);
    expect(parseMetricValue('NaN')).toBeNaN();
  });
  it('rejects garbage', () => {
    expect(parseMetricValue('abc')).toBeUndefined();
    expect(parseMetricValue('1,5')).toBeUndefined();
  });
});

describe('parseLabels', () => {
  it('parses quoted values with escapes', () => {
    expect(parseLabels('a="1", b="x\\"y\\\\z\\n"')).toEqual([
      ['a', '1'],
      ['b', 'x"y\\z\n'],
    ]);
    expect(parseLabels('')).toEqual([]);
    expect(parseLabels('a="1",')).toEqual([['a', '1']]);
  });
  it('rejects malformed label sets', () => {
    expect(parseLabels('a=1')).toBeUndefined();
    expect(parseLabels('a')).toBeUndefined();
    expect(parseLabels('a="1')).toBeUndefined();
    expect(parseLabels('a="\\q"')).toBeUndefined();
    expect(parseLabels('a="1" b="2"')).toBeUndefined();
  });
});

describe('splitSampleLine', () => {
  it('keeps braces inside quoted label values', () => {
    expect(splitSampleLine('m{path="/a}b"} 1 123')).toEqual({
      name: 'm',
      labelBody: 'path="/a}b"',
      rawValue: '1',
      rawTimestamp: '123',
    });
    // An escaped backslash closes the value; an escaped quote does not.
    expect(splitSampleLine(String.raw`m{a="x\\"} 1`)?.labelBody).toBe(String.raw`a="x\\"`);
    expect(splitSampleLine(String.raw`m{a="x\"}"} 1`)?.labelBody).toBe(String.raw`a="x\"}"`);
  });
  it('rejects unterminated label sets, missing values and extra fields', () => {
    expect(splitSampleLine('m{a="1" 1')).toBeUndefined();
    expect(splitSampleLine('m')).toBeUndefined();
    expect(splitSampleLine('m 1 2 3')).toBeUndefined();
    expect(splitSampleLine('{a="1"} 1')).toBeUndefined();
  });
});

describe('validateMetricsText (#526)', () => {
  it('accepts a valid Prometheus 0.0.4 exposition with the anchor metrics', () => {
    const report = validateMetricsText(REQUIRED);
    expect(report.ok).toBe(true);
    expect(report.issues).toEqual([]);
    expect(report.format).toBe('prometheus-0.0.4');
    expect(report.families.map((f) => f.name)).toEqual([
      'stellar_anchor_balance',
      'stellar_tx_processed_total',
      'stellar_sep_request_duration_seconds',
    ]);
    expect(report.samples).toBe(7);
  });

  it('accepts OpenMetrics 1.0.0 with # EOF, units, timestamps and exemplars', () => {
    const text = `# TYPE stellar_tx_processed counter
# HELP stellar_tx_processed Processed transactions
stellar_tx_processed_total 42 1700000000.5
stellar_tx_processed_created 1700000000
# TYPE stellar_anchor_balance gauge
# UNIT stellar_anchor_balance usdc
# HELP stellar_anchor_balance Balance
stellar_anchor_balance 1
# TYPE stellar_sep_request_duration_seconds histogram
# HELP stellar_sep_request_duration_seconds Latency
stellar_sep_request_duration_seconds_bucket{le="+Inf"} 3 # {trace_id="abc"} 0.2
stellar_sep_request_duration_seconds_sum 0.4
stellar_sep_request_duration_seconds_count 3
# EOF
`;
    const report = validateMetricsText(text);
    expect(report.format).toBe('openmetrics-1.0.0');
    expect(report.issues).toEqual([]);
    expect(report.families.find((f) => f.name === 'stellar_anchor_balance')?.unit).toBe('usdc');
  });

  it('requires # EOF for OpenMetrics and rejects trailing content', () => {
    expect(
      codes('# TYPE a gauge\n# HELP a x\na 1\n', {
        format: 'openmetrics-1.0.0',
        requiredMetrics: [],
      }),
    ).toEqual(['metrics/missing-eof']);
    expect(
      codes('# EOF\na 1\nb 2\n', { format: 'openmetrics-1.0.0', requiredMetrics: [] }),
    ).toEqual(['metrics/content-after-eof']);
  });

  it('warns on missing TYPE and HELP declarations', () => {
    expect(codes('foo 1\n', { requiredMetrics: [] })).toEqual([
      'metrics/missing-type',
      'metrics/missing-help',
    ]);
  });

  it('flags invalid metric types per standard', () => {
    expect(codes('# TYPE a bogus\n# HELP a x\na 1\n', { requiredMetrics: [] })).toContain(
      'metrics/invalid-type',
    );
    // `info` is OpenMetrics-only.
    expect(codes('# TYPE a info\n# HELP a x\na_info 1\n', { requiredMetrics: [] })).toContain(
      'metrics/invalid-type',
    );
    expect(codes('# TYPE a info\n# HELP a x\na_info 1\n# EOF\n', { requiredMetrics: [] })).toEqual(
      [],
    );
  });

  it('flags malformed metric tokens', () => {
    const c = codes(
      [
        '# TYPE 9bad gauge',
        '9bad 1',
        'ok{9x="1"} 1',
        'ok{__name="1"} 1',
        'ok{a="1",a="2"} 1',
        'ok{a=1} 1',
        'ok abc',
        'ok 1 notatime',
        'just_a_name',
      ].join('\n'),
      { requiredMetrics: [] },
    );
    expect(c).toEqual(
      expect.arrayContaining([
        'metrics/invalid-metric-name',
        'metrics/invalid-label-name',
        'metrics/reserved-label-name',
        'metrics/duplicate-label',
        'metrics/malformed-labels',
        'metrics/invalid-value',
        'metrics/invalid-timestamp',
        'metrics/malformed-sample',
      ]),
    );
  });

  it('reports NaN gauges and negative counters', () => {
    expect(codes('# TYPE g gauge\n# HELP g x\ng NaN\n', { requiredMetrics: [] })).toEqual([
      'metrics/nan-gauge',
    ]);
    expect(
      codes('# TYPE c_total counter\n# HELP c_total x\nc_total -1\n', { requiredMetrics: [] }),
    ).toEqual(['metrics/negative-counter']);
    expect(
      codes('# TYPE s summary\n# HELP s x\ns_count -3\ns_sum 1\n', { requiredMetrics: [] }),
    ).toEqual(['metrics/negative-counter']);
  });

  it('enforces the _total suffix on Prometheus counters only', () => {
    expect(codes('# TYPE c counter\n# HELP c x\nc 1\n', { requiredMetrics: [] })).toEqual([
      'metrics/counter-name-suffix',
    ]);
  });

  it('validates histogram structure', () => {
    const noInf = '# TYPE h histogram\n# HELP h x\nh_bucket{le="1"} 1\nh_sum 1\nh_count 1\n';
    expect(codes(noInf, { requiredMetrics: [] })).toEqual(['metrics/histogram-missing-inf-bucket']);
    const noLe = '# TYPE h histogram\n# HELP h x\nh_bucket 1\nh_sum 1\nh_count 1\n';
    expect(codes(noLe, { requiredMetrics: [] })).toEqual(['metrics/histogram-missing-le']);
    const noSum = '# TYPE h histogram\n# HELP h x\nh_bucket{le="+Inf"} 1\n';
    expect(codes(noSum, { requiredMetrics: [] })).toEqual(['metrics/histogram-missing-sum-count']);
    const gauge =
      '# TYPE g gaugehistogram\n# HELP g x\ng_bucket{le="+Inf"} 1\ng_gsum 1\ng_gcount 1\n# EOF\n';
    expect(codes(gauge, { requiredMetrics: [] })).toEqual([]);
  });

  it('flags duplicate and late declarations', () => {
    const text = '# HELP a x\n# HELP a y\na 1\n# TYPE a gauge\n# TYPE a gauge\n';
    expect(codes(text, { requiredMetrics: [] })).toEqual([
      'metrics/duplicate-help',
      'metrics/type-after-samples',
      'metrics/duplicate-type',
    ]);
  });

  it('attributes samples of undeclared families to the previous family', () => {
    const report = validateMetricsText('h_bucket{le="+Inf"} 1\nh_bucket_sum 1\n', {
      requiredMetrics: [],
    });
    expect(report.families.map((f) => f.name)).toEqual(['h_bucket']);
  });

  it('warns about each missing required anchor metric', () => {
    const report = validateMetricsText('# TYPE x gauge\n# HELP x y\nx 1\n');
    expect(
      report.issues
        .filter((i) => i.code === 'metrics/missing-required-metric')
        .map((i) => i.metric),
    ).toEqual([
      'stellar_anchor_balance',
      'stellar_tx_processed_total',
      'stellar_sep_request_duration_seconds',
    ]);
    expect(report.ok).toBe(true);
  });

  it('ignores plain comments, blank lines and CRLF', () => {
    expect(
      codes('# just a comment\r\n\r\n# TYPE a gauge\r\n# HELP a x\r\na 1\r\n', {
        requiredMetrics: [],
      }),
    ).toEqual([]);
  });

  it('caps stored issues and counts the rest', () => {
    const text = Array.from({ length: 20 }, (_, i) => `bad${i} nope`).join('\n');
    const parser = new MetricsTextParser({ maxIssues: 5, requiredMetrics: [] });
    parser.push(text);
    const report = parser.end();
    expect(report.issues).toHaveLength(5);
    expect(report.truncatedIssues).toBeGreaterThan(0);
  });

  it('parses lines split across chunks', () => {
    const parser = new MetricsTextParser();
    for (const ch of REQUIRED) parser.push(ch);
    expect(parser.end().issues).toEqual([]);
  });

  it('handles a large payload in bounded memory', () => {
    const parser = new MetricsTextParser({ requiredMetrics: [] });
    parser.push('# HELP big x\n# TYPE big gauge\n');
    const line = 'big{shard="0000"} 1\n';
    const chunk = line.repeat(10_000);
    for (let i = 0; i < 50; i++) parser.push(chunk);
    const report = parser.end();
    expect(report.samples).toBe(500_000);
    expect(report.families).toHaveLength(1);
    expect(report.issues).toEqual([]);
  });
});

describe('detectMetricsFormat / discoverMetricsEndpoints', () => {
  it('detects OpenMetrics from content type', () => {
    expect(detectMetricsFormat('application/openmetrics-text; version=1.0.0')).toBe(
      'openmetrics-1.0.0',
    );
    expect(detectMetricsFormat('text/plain')).toBe('prometheus-0.0.4');
    expect(detectMetricsFormat(null)).toBe('prometheus-0.0.4');
  });

  it('finds metrics URLs at the top level and in DOCUMENTATION', () => {
    expect(
      discoverMetricsEndpoints({
        METRICS_URL: 'https://a.example/metrics',
        PROMETHEUS_ENDPOINT: 'http://b.example:9100/metrics',
        TRANSFER_SERVER: 'https://a.example/sep6',
        MONITORING_URL: 'not a url',
        DOCUMENTATION: { ORG_METRICS_URL: 'https://c.example/metrics' },
      }),
    ).toEqual([
      'https://a.example/metrics',
      'http://b.example:9100/metrics',
      'https://c.example/metrics',
    ]);
    expect(discoverMetricsEndpoints({ DOCUMENTATION: ['x'] })).toEqual([]);
  });
});

describe('PrometheusMetricsValidator.validateUrl', () => {
  it('streams and validates a scraped endpoint', async () => {
    const validator = new PrometheusMetricsValidator({ fetchImpl: async () => response(REQUIRED) });
    const report = await validator.validateUrl('https://anchor.example/metrics');
    expect(report.ok).toBe(true);
    expect(report.url).toBe('https://anchor.example/metrics');
    expect(renderMetricsReport(report)).toContain('✓ Exposition is valid');
  });

  it('uses the OpenMetrics rules when the server says so', async () => {
    const validator = new PrometheusMetricsValidator({
      fetchImpl: async () =>
        response('# TYPE a gauge\n# HELP a x\na 1\n', 'application/openmetrics-text'),
      requiredMetrics: [],
    });
    const report = await validator.validateUrl('https://x/metrics');
    expect(report.issues.map((i) => i.code)).toEqual(['metrics/missing-eof']);
    expect(report.ok).toBe(false);
  });

  it('reports unreachable endpoints and HTTP errors', async () => {
    const down = new PrometheusMetricsValidator({
      fetchImpl: async () => {
        throw new Error('ECONNREFUSED');
      },
    });
    expect((await down.validateUrl('https://x/metrics')).issues[0]?.message).toContain(
      'ECONNREFUSED',
    );
    const thrown = new PrometheusMetricsValidator({
      fetchImpl: async () => {
        throw 'boom';
      },
    });
    expect((await thrown.validateUrl('https://x/metrics')).issues[0]?.message).toContain('boom');
    const http500 = new PrometheusMetricsValidator({
      fetchImpl: async () => response('', 'text/plain', 500),
    });
    const report = await http500.validateUrl('https://x/metrics');
    expect(report.ok).toBe(false);
    expect(report.issues[0]?.code).toBe('metrics/unreachable');
  });

  it('aborts oversized payloads', async () => {
    const validator = new PrometheusMetricsValidator({
      fetchImpl: async () => response('a 1\n'.repeat(1000)),
      maxBytes: 100,
      requiredMetrics: [],
    });
    const report = await validator.validateUrl('https://x/metrics');
    expect(report.issues[0]?.code).toBe('metrics/payload-too-large');
    expect(report.ok).toBe(false);
  });

  it('handles an empty body', async () => {
    const validator = new PrometheusMetricsValidator({
      fetchImpl: async () => new Response(null, { status: 204 }),
      requiredMetrics: [],
    });
    expect((await validator.validateUrl('https://x/metrics')).issues).toEqual([]);
  });
});

describe('renderMetricsReport', () => {
  it('lists issues with line numbers and truncation', () => {
    const report = validateMetricsText('bad line here x\n', { requiredMetrics: ['need_me'] });
    report.truncatedIssues = 3;
    const text = renderMetricsReport(report);
    expect(text).toContain('(inline)');
    expect(text).toContain('(line 1)');
    expect(text).toContain('… 3 more issues not shown');
    expect(text).toMatch(/1 errors, 1 warnings/);
  });
});
