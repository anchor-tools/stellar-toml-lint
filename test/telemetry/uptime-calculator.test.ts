import { describe, expect, it } from 'vitest';
import {
  availabilityPercent,
  calculateServiceUptime,
  formatDuration,
  ninesTier,
  parseCsvLog,
  parseHealthLog,
  parseJsonLog,
  parseStatus,
  parseTimestamp,
  renderUptimeMarkdown,
  renderUptimeText,
  splitCsvLine,
  uptimeBadgeJson,
  uptimeBadgeSvg,
  UptimeAvailabilityCalculator,
  type HealthRecord,
} from '../../src/telemetry/uptimeCalculator.js';

const MIN = 60_000;
const T0 = Date.parse('2026-11-01T00:00:00Z');

/** One check per minute for `minutes`; `down(i)` decides failures. */
function series(
  minutes: number,
  down: (i: number) => boolean = () => false,
  service = 'sep24',
): HealthRecord[] {
  return Array.from({ length: minutes }, (_, i) => ({
    timestamp: T0 + i * MIN,
    up: !down(i),
    service,
  }));
}

describe('parsing helpers', () => {
  it('reads statuses in many spellings', () => {
    expect(['up', 'OK', 'healthy', 'true', '1', '200', '204'].map(parseStatus)).toEqual(
      Array(7).fill(true),
    );
    expect(['down', 'FAIL', 'timeout', 'false', '0', '503', '404'].map(parseStatus)).toEqual(
      Array(7).fill(false),
    );
    expect([true, false, 1, 0, 200, 500].map(parseStatus)).toEqual([
      true,
      false,
      true,
      false,
      true,
      false,
    ]);
    expect([42, 'maybe', null, undefined, {}].map(parseStatus)).toEqual(Array(5).fill(undefined));
  });

  it('reads ISO timestamps and epoch seconds or milliseconds', () => {
    expect(parseTimestamp('2026-11-01T00:00:00Z')).toBe(T0);
    expect(parseTimestamp(T0 / 1000)).toBe(T0);
    expect(parseTimestamp(T0)).toBe(T0);
    expect(parseTimestamp(String(T0 / 1000))).toBe(T0);
    expect(parseTimestamp('nope')).toBeUndefined();
    expect(parseTimestamp('')).toBeUndefined();
    expect(parseTimestamp(Number.NaN)).toBeUndefined();
    expect(parseTimestamp(null)).toBeUndefined();
  });

  it('splits quoted CSV cells', () => {
    expect(splitCsvLine('a, "b,c" ,"d ""e"""')).toEqual(['a', 'b,c', 'd "e"']);
  });

  it('parses CSV logs with flexible headers and reports bad rows', () => {
    const csv = [
      '# exported from uptime-kuma',
      'Timestamp,Endpoint,Status',
      '2026-11-01T00:00:00Z,sep6,up',
      '2026-11-01T00:01:00Z,sep6,DOWN',
      'garbage,sep6,up',
      '2026-11-01T00:02:00Z,,200',
    ].join('\r\n');
    const { records, skipped } = parseCsvLog(csv);
    expect(records).toEqual([
      { timestamp: T0, up: true, service: 'sep6' },
      { timestamp: T0 + MIN, up: false, service: 'sep6' },
      { timestamp: T0 + 2 * MIN, up: true, service: 'default' },
    ]);
    expect(skipped).toEqual([4]);
    expect(parseCsvLog('')).toEqual({ records: [], skipped: [] });
    expect(parseCsvLog('time,status\n1700000000,up\n1700000060').records).toHaveLength(1);
  });

  it('parses JSON arrays, wrapped records and NDJSON', () => {
    const rows = [
      { time: '2026-11-01T00:00:00Z', ok: true },
      { ts: T0 / 1000 + 60, healthy: false, service: 'api' },
    ];
    expect(parseJsonLog(JSON.stringify(rows)).records).toHaveLength(2);
    expect(parseJsonLog(JSON.stringify({ checks: rows })).records).toHaveLength(2);
    expect(parseJsonLog(JSON.stringify(rows[0])).records).toHaveLength(1);
    expect(parseJsonLog('"just a string"')).toEqual({ records: [], skipped: [1] });
    expect(parseJsonLog('42').records).toEqual([]);
    const nd = `${JSON.stringify(rows[0])}\n\nnot json\n${JSON.stringify(rows[1])}\n{"status":"up"}`;
    const parsed = parseJsonLog(nd);
    expect(parsed.records).toHaveLength(2);
    expect(parsed.skipped).toEqual([3, 3]);
    expect(parseJsonLog('  ')).toEqual({ records: [], skipped: [] });
    expect(parseJsonLog('[1, null, {"timestamp": 1, "status": "up"}]').records).toHaveLength(1);
  });

  it('picks the parser from the file name or content', () => {
    expect(parseHealthLog('time,status\n1700000000,up', 'log.csv').records).toHaveLength(1);
    expect(parseHealthLog('{"time":1700000000,"status":"up"}', 'log.jsonl').records).toHaveLength(
      1,
    );
    expect(parseHealthLog('[{"time":1700000000,"status":"up"}]').records).toHaveLength(1);
    expect(parseHealthLog('time,status\n1700000000,up').records).toHaveLength(1);
  });
});

describe('availability math', () => {
  it('truncates instead of rounding up', () => {
    // 99.98999…% must never be reported as 99.99%.
    expect(availabilityPercent(999_899, 1_000_000, 2)).toBe(99.98);
    expect(availabilityPercent(1, 3, 3)).toBe(33.333);
    expect(availabilityPercent(2, 3, 3)).toBe(66.666);
    expect(availabilityPercent(10, 10)).toBe(100);
    expect(availabilityPercent(0, 10)).toBe(0);
    expect(availabilityPercent(1, 0)).toBeNaN();
    // Large 30-day windows stay exact.
    const month = 30 * 86_400_000;
    expect(availabilityPercent(month - 2_592_000, month, 4)).toBe(99.9);
  });

  it('classifies nines tiers', () => {
    expect([100, 99.999, 99.995, 99.95, 99.5, 98].map(ninesTier)).toEqual([
      'five nines (99.999%)',
      'five nines (99.999%)',
      'four nines (99.99%)',
      'three nines (99.9%)',
      'two nines (99%)',
      'below 99%',
    ]);
  });
});

describe('UptimeAvailabilityCalculator (#530)', () => {
  it('reports 100% for a clean dataset', () => {
    const s = calculateServiceUptime('sep24', series(24 * 60));
    expect(s.windows.map((w) => w.availability)).toEqual([100, 100, 100]);
    expect(s.incidents).toEqual([]);
    expect(s.longestIncident).toBeUndefined();
    expect(s.mttrMs).toBeUndefined();
    expect(s.windows[0]?.observedMs).toBe(24 * 60 * MIN);
  });

  it('finds intermittent incidents and the longest streak', () => {
    // Down at minutes 100–101, 500–504 and 900 of a day.
    const down = (i: number) => (i >= 100 && i <= 101) || (i >= 500 && i <= 504) || i === 900;
    const s = calculateServiceUptime('sep24', series(24 * 60, down));
    expect(s.incidents.map((i) => [i.durationMs / MIN, i.checks])).toEqual([
      [2, 2],
      [5, 5],
      [1, 1],
    ]);
    expect(s.longestIncident?.durationMs).toBe(5 * MIN);
    expect(s.longestIncident?.start).toBe(T0 + 500 * MIN);
    expect(s.totalDowntimeMs).toBe(8 * MIN);
    expect(s.mttrMs).toBe(Math.round((8 * MIN) / 3));
    // 1432 of 1440 minutes up = 99.4444…% → truncated.
    expect(s.windows[0]?.availability).toBe(99.444);
    expect(s.windows[0]?.nines).toBe('two nines (99%)');
  });

  it('handles severe, ongoing downtime', () => {
    const s = calculateServiceUptime(
      'sep6',
      series(120, (i) => i >= 60),
    );
    expect(s.incidents).toHaveLength(1);
    expect(s.incidents[0]?.ongoing).toBe(true);
    expect(s.incidents[0]?.durationMs).toBe(60 * MIN);
    expect(s.mttrMs).toBeUndefined();
    expect(s.windows[0]?.availability).toBe(50);
    expect(s.windows[0]?.nines).toBe('below 99%');
  });

  it('computes sliding windows against a fixed now', () => {
    // 8 days of hourly checks, first day fully down.
    const hourly = Array.from({ length: 8 * 24 }, (_, i) => ({
      timestamp: T0 + i * 3_600_000,
      up: i >= 24,
      service: 'api',
    }));
    const now = T0 + 8 * 86_400_000;
    const s = calculateServiceUptime('api', hourly, { now });
    const [day, week, month] = s.windows;
    expect(day?.availability).toBe(100);
    expect(week?.availability).toBe(100); // the outage is older than 7 days
    expect(month?.availability).toBe(87.5); // 7 of 8 observed days
    expect(month?.observedMs).toBe(8 * 86_400_000);
  });

  it('honours an explicit interval and unsorted input, and leaves empty windows undefined', () => {
    const records = [
      { timestamp: T0 + 2 * MIN, up: true, service: 'x' },
      { timestamp: T0, up: false, service: 'x' },
    ];
    const s = calculateServiceUptime('x', records, {
      intervalMs: 3 * MIN,
      now: T0 + 5 * MIN,
      windows: [
        { label: '5m', ms: 5 * MIN },
        { label: 'future', ms: 1 },
      ],
    });
    expect(s.windows[0]?.availability).toBe(60);
    expect(s.incidents[0]?.durationMs).toBe(2 * MIN);
    const empty = calculateServiceUptime('x', records, { now: T0 - 10 * MIN });
    expect(empty.windows[0]?.availability).toBeUndefined();
    expect(calculateServiceUptime('x', []).checks).toBe(0);
    const even = calculateServiceUptime('x', [
      { timestamp: 0, up: true, service: 'x' },
      { timestamp: 1000, up: true, service: 'x' },
      { timestamp: 4000, up: true, service: 'x' },
    ]);
    expect(even.windows[0]?.observedMs).toBe(4000 + 2000);
  });

  it('groups by service and parses text', () => {
    const calc = new UptimeAvailabilityCalculator();
    const report = calc.calculate([
      ...series(10, () => false, 'b'),
      ...series(10, (i) => i === 3, 'a'),
    ]);
    expect(report.services.map((s) => s.service)).toEqual(['a', 'b']);
    expect(report.generatedAt).toBe(T0 + 9 * MIN);
    const fromText = calc.calculateFromText(
      'time,status\nbad,up\n1700000000,up\n1700000060,down',
      'x.csv',
    );
    expect(fromText.skipped).toEqual([2]);
    expect(new UptimeAvailabilityCalculator({ now: 5 }).calculate([]).generatedAt).toBe(5);
  });
});

describe('badges and summaries', () => {
  it('formats durations', () => {
    expect([0, 5_000, 65_000, 3_725_000, 90_061_000].map(formatDuration)).toEqual([
      '0s',
      '5s',
      '1m 05s',
      '1h 02m 05s',
      '1d 01h 01m',
    ]);
  });

  it('emits shields.io endpoint JSON and SVG badges', () => {
    expect(JSON.parse(uptimeBadgeJson('uptime', 99.95))).toEqual({
      schemaVersion: 1,
      label: 'uptime',
      message: '99.95%',
      color: '97ca00',
    });
    expect(JSON.parse(uptimeBadgeJson('uptime', undefined)).message).toBe('no data');
    expect(JSON.parse(uptimeBadgeJson('u', 99.99)).color).toBe('4c1');
    expect(JSON.parse(uptimeBadgeJson('u', 99.5)).color).toBe('dfb317');
    expect(JSON.parse(uptimeBadgeJson('u', 90)).color).toBe('e05d44');
    const svg = uptimeBadgeSvg('up<time>', 90);
    expect(svg).toContain('<svg');
    expect(svg).toContain('up&lt;time&gt;');
    expect(svg).toContain('#e05d44');
    expect(uptimeBadgeSvg('u', undefined)).toContain('no data');
  });

  it('renders markdown tables with incidents', () => {
    const calc = new UptimeAvailabilityCalculator();
    const md = renderUptimeMarkdown(
      calc.calculate([
        ...series(60, (i) => i >= 10 && i < 15),
        ...series(60, (i) => i >= 58, 'ongoing'),
      ]),
    );
    expect(md).toContain('| Service | 24h | 7d | 30d | Incidents | Longest outage | MTTR |');
    expect(md).toContain('| sep24 | 91.666% | 91.666% | 91.666% | 1 | 5m 00s | 5m 00s |');
    expect(md).toContain('## sep24 incidents');
    expect(md).toContain('| 2026-11-01T00:10:00Z | 2026-11-01T00:15:00Z | 5m 00s | 5 |');
    expect(md).toContain('| 2026-11-01T00:58:00Z | ongoing | 2m 00s | 2 |');
    expect(md).toContain('| — |');
    expect(renderUptimeMarkdown({ generatedAt: 0, services: [] })).toContain(
      'No health-check records',
    );
  });

  it('renders a text summary', () => {
    const calc = new UptimeAvailabilityCalculator({ now: T0 - 1 });
    const text = renderUptimeText(calc.calculate(series(10, (i) => i >= 5)));
    expect(text).toContain('sep24  (10 checks');
    expect(text).toContain('n/a');
    expect(text).toContain('(ongoing)');
    const ok = renderUptimeText(
      new UptimeAvailabilityCalculator().calculate(series(10, (i) => i === 2)),
    );
    expect(ok).toContain('MTTR 1m 00s');
    expect(renderUptimeText({ generatedAt: 0, services: [] })).toContain('No health-check records');
  });
});
