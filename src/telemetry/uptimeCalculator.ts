/**
 * Uptime SLA availability and downtime-streak calculator.
 *
 * Takes health-check records (JSON array, `{ "records": [...] }`, NDJSON or
 * CSV) and computes, per service:
 *
 *   - availability over sliding 24 h / 7 d / 30 d windows ending at the last
 *     check (or a caller-supplied `now`),
 *   - incidents (maximal runs of consecutive failed checks) and the longest one,
 *   - the "nines" tier the availability qualifies for.
 *
 * Each check's state is assumed to hold until the next check, so availability
 * is time-weighted rather than a raw ratio of passing checks. All durations are
 * integer milliseconds and percentages are computed with BigInt and truncated
 * (never rounded up), so 99.98 % can never be reported as 99.99 %.
 */

export interface HealthRecord {
  /** Epoch milliseconds. */
  timestamp: number;
  up: boolean;
  service: string;
}

export interface Incident {
  start: number;
  end: number;
  durationMs: number;
  checks: number;
  /** True when the service was still down at the end of the log. */
  ongoing: boolean;
}

export interface WindowAvailability {
  label: string;
  windowMs: number;
  /** Milliseconds of the window actually covered by the log. */
  observedMs: number;
  upMs: number;
  downMs: number;
  /** Truncated to {@link UptimeOptions.decimals} places; undefined without coverage. */
  availability?: number;
  nines?: string;
}

export interface ServiceUptime {
  service: string;
  checks: number;
  first: number;
  last: number;
  windows: WindowAvailability[];
  incidents: Incident[];
  longestIncident?: Incident;
  totalDowntimeMs: number;
  /** Mean time to recovery over resolved incidents. */
  mttrMs?: number;
}

export interface UptimeReport {
  generatedAt: number;
  services: ServiceUptime[];
}

export interface UptimeOptions {
  /** End of every window, epoch ms. Defaults to the latest check. */
  now?: number;
  decimals?: number;
  /**
   * How long the final check is assumed to hold. Defaults to the median gap
   * between checks.
   */
  intervalMs?: number;
  windows?: readonly { label: string; ms: number }[];
}

export const DEFAULT_WINDOWS: readonly { label: string; ms: number }[] = [
  { label: '24h', ms: 24 * 3_600_000 },
  { label: '7d', ms: 7 * 86_400_000 },
  { label: '30d', ms: 30 * 86_400_000 },
];

const UP_VALUES = new Set([
  'up',
  'ok',
  'pass',
  'passed',
  'success',
  'healthy',
  'true',
  '1',
  'online',
]);
const DOWN_VALUES = new Set([
  'down',
  'fail',
  'failed',
  'failure',
  'error',
  'unhealthy',
  'false',
  '0',
  'offline',
  'timeout',
]);

/** Interprets a status cell: words, booleans, or HTTP status codes. */
export function parseStatus(value: unknown): boolean | undefined {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (value === 1) return true;
    if (value === 0) return false;
    if (value >= 100 && value < 600) return value < 400;
    return undefined;
  }
  if (typeof value !== 'string') return undefined;
  const v = value.trim().toLowerCase();
  if (UP_VALUES.has(v)) return true;
  if (DOWN_VALUES.has(v)) return false;
  if (/^\d{3}$/.test(v)) return parseStatus(Number(v));
  return undefined;
}

/** Parses ISO-8601 strings and epoch seconds / milliseconds. */
export function parseTimestamp(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) {
    // Anything below 1e11 is epoch seconds (1e11 s is the year 5138).
    return value < 1e11 ? Math.round(value * 1000) : Math.round(value);
  }
  if (typeof value !== 'string' || value.trim() === '') return undefined;
  const trimmed = value.trim();
  if (/^\d+(\.\d+)?$/.test(trimmed)) return parseTimestamp(Number(trimmed));
  const ms = Date.parse(trimmed);
  return Number.isNaN(ms) ? undefined : ms;
}

const TIME_KEYS = ['timestamp', 'time', 'ts', 'date', 'checked_at', 'checkedAt', 'datetime'];
const STATUS_KEYS = [
  'status',
  'up',
  'ok',
  'healthy',
  'state',
  'result',
  'success',
  'status_code',
  'statusCode',
];
const SERVICE_KEYS = ['service', 'endpoint', 'url', 'name', 'target', 'check'];

function pick(row: Record<string, unknown>, keys: readonly string[]): unknown {
  for (const key of keys) {
    if (key in row) return row[key];
    const lower = Object.keys(row).find((k) => k.toLowerCase() === key.toLowerCase());
    if (lower !== undefined) return row[lower];
  }
  return undefined;
}

export interface ParseResult {
  records: HealthRecord[];
  /** 1-based row numbers that could not be interpreted. */
  skipped: number[];
}

function normalize(rows: Record<string, unknown>[], offset = 1): ParseResult {
  const records: HealthRecord[] = [];
  const skipped: number[] = [];
  rows.forEach((row, i) => {
    const timestamp = parseTimestamp(pick(row, TIME_KEYS));
    const up = parseStatus(pick(row, STATUS_KEYS));
    if (timestamp === undefined || up === undefined) {
      skipped.push(i + offset);
      return;
    }
    const service = pick(row, SERVICE_KEYS);
    records.push({
      timestamp,
      up,
      service: typeof service === 'string' && service !== '' ? service : 'default',
    });
  });
  return { records, skipped };
}

/** Splits one CSV line, honouring double-quoted fields. */
export function splitCsvLine(line: string): string[] {
  const cells: string[] = [];
  let cell = '';
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i] as string;
    if (quoted) {
      if (ch === '"' && line[i + 1] === '"') {
        cell += '"';
        i++;
      } else if (ch === '"') quoted = false;
      else cell += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ',') {
      cells.push(cell);
      cell = '';
    } else cell += ch;
  }
  cells.push(cell);
  return cells.map((c) => c.trim());
}

export function parseCsvLog(text: string): ParseResult {
  const lines = text.split(/\r?\n/).filter((l) => l.trim() !== '' && !l.startsWith('#'));
  if (lines.length === 0) return { records: [], skipped: [] };
  const header = splitCsvLine(lines[0] as string);
  const rows = lines.slice(1).map((line) => {
    const cells = splitCsvLine(line);
    const row: Record<string, unknown> = {};
    header.forEach((h, i) => {
      row[h] = cells[i] ?? '';
    });
    return row;
  });
  return normalize(rows, 2);
}

export function parseJsonLog(text: string): ParseResult {
  const trimmed = text.trim();
  if (trimmed === '') return { records: [], skipped: [] };
  if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
    try {
      const parsed: unknown = JSON.parse(trimmed);
      const rows = Array.isArray(parsed)
        ? parsed
        : parsed !== null && typeof parsed === 'object'
          ? ((['records', 'checks', 'data', 'results']
              .map((k) => (parsed as Record<string, unknown>)[k])
              .find(Array.isArray) as unknown[] | undefined) ?? [parsed])
          : [];
      return normalize(
        rows.filter((r): r is Record<string, unknown> => r !== null && typeof r === 'object'),
      );
    } catch {
      // fall through to NDJSON
    }
  }
  const rows: Record<string, unknown>[] = [];
  const skipped: number[] = [];
  trimmed.split(/\r?\n/).forEach((line, i) => {
    if (line.trim() === '') return;
    try {
      const row: unknown = JSON.parse(line);
      if (row !== null && typeof row === 'object' && !Array.isArray(row)) {
        rows.push(row as Record<string, unknown>);
      } else skipped.push(i + 1);
    } catch {
      skipped.push(i + 1);
    }
  });
  const result = normalize(rows);
  return { records: result.records, skipped: [...skipped, ...result.skipped] };
}

/** Detects JSON vs CSV from the file name or content. */
export function parseHealthLog(text: string, fileName = ''): ParseResult {
  if (/\.csv$/i.test(fileName)) return parseCsvLog(text);
  if (/\.(json|ndjson|jsonl)$/i.test(fileName)) return parseJsonLog(text);
  const head = text.trimStart();
  return head.startsWith('[') || head.startsWith('{') ? parseJsonLog(text) : parseCsvLog(text);
}

/**
 * `upMs / totalMs * 100`, truncated (not rounded) to `decimals` places using
 * integer arithmetic so binary floating point cannot inflate the figure.
 */
export function availabilityPercent(upMs: number, totalMs: number, decimals = 3): number {
  if (totalMs <= 0) return Number.NaN;
  const scale = 10n ** BigInt(decimals);
  const scaled = (BigInt(Math.round(upMs)) * 100n * scale) / BigInt(Math.round(totalMs));
  return Number(scaled) / Number(scale);
}

/** Highest "nines" tier the availability meets. */
export function ninesTier(availability: number): string {
  if (availability >= 99.999) return 'five nines (99.999%)';
  if (availability >= 99.99) return 'four nines (99.99%)';
  if (availability >= 99.9) return 'three nines (99.9%)';
  if (availability >= 99) return 'two nines (99%)';
  return 'below 99%';
}

function median(values: number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1
    ? (sorted[mid] as number)
    : Math.round(((sorted[mid - 1] as number) + (sorted[mid] as number)) / 2);
}

interface Segment {
  start: number;
  end: number;
  up: boolean;
}

/** Computes uptime for one service's checks. */
export function calculateServiceUptime(
  service: string,
  input: readonly HealthRecord[],
  options: UptimeOptions = {},
): ServiceUptime {
  const records = [...input].sort((a, b) => a.timestamp - b.timestamp);
  const decimals = options.decimals ?? 3;
  const gaps: number[] = [];
  for (let i = 1; i < records.length; i++) {
    gaps.push((records[i] as HealthRecord).timestamp - (records[i - 1] as HealthRecord).timestamp);
  }
  const interval = options.intervalMs ?? median(gaps.filter((g) => g > 0));
  const first = records[0]?.timestamp ?? 0;
  const lastCheck = records[records.length - 1]?.timestamp ?? 0;
  const logEnd = lastCheck + interval;
  const now = options.now ?? logEnd;

  const segments: Segment[] = records.map((r, i) => ({
    start: r.timestamp,
    end: i + 1 < records.length ? (records[i + 1] as HealthRecord).timestamp : logEnd,
    up: r.up,
  }));

  const windows = (options.windows ?? DEFAULT_WINDOWS).map(({ label, ms }) => {
    const from = now - ms;
    let upMs = 0;
    let downMs = 0;
    for (const s of segments) {
      const lo = Math.max(s.start, from);
      const hi = Math.min(s.end, now);
      if (hi <= lo) continue;
      if (s.up) upMs += hi - lo;
      else downMs += hi - lo;
    }
    const observedMs = upMs + downMs;
    const w: WindowAvailability = { label, windowMs: ms, observedMs, upMs, downMs };
    if (observedMs > 0) {
      w.availability = availabilityPercent(upMs, observedMs, decimals);
      w.nines = ninesTier(w.availability);
    }
    return w;
  });

  const incidents: Incident[] = [];
  let current: Incident | undefined;
  for (let i = 0; i < records.length; i++) {
    const r = records[i] as HealthRecord;
    if (!r.up) {
      if (current === undefined) {
        current = {
          start: r.timestamp,
          end: r.timestamp,
          durationMs: 0,
          checks: 0,
          ongoing: false,
        };
      }
      current.checks++;
    } else if (current !== undefined) {
      current.end = r.timestamp;
      current.durationMs = current.end - current.start;
      incidents.push(current);
      current = undefined;
    }
  }
  if (current !== undefined) {
    current.end = logEnd;
    current.durationMs = current.end - current.start;
    current.ongoing = true;
    incidents.push(current);
  }

  const result: ServiceUptime = {
    service,
    checks: records.length,
    first,
    last: lastCheck,
    windows,
    incidents,
    totalDowntimeMs: incidents.reduce((acc, i) => acc + i.durationMs, 0),
  };
  const longest = incidents.reduce<Incident | undefined>(
    (best, i) => (best === undefined || i.durationMs > best.durationMs ? i : best),
    undefined,
  );
  if (longest !== undefined) result.longestIncident = longest;
  const resolved = incidents.filter((i) => !i.ongoing);
  if (resolved.length > 0) {
    result.mttrMs = Math.round(
      resolved.reduce((acc, i) => acc + i.durationMs, 0) / resolved.length,
    );
  }
  return result;
}

export class UptimeAvailabilityCalculator {
  constructor(private readonly options: UptimeOptions = {}) {}

  calculate(records: readonly HealthRecord[]): UptimeReport {
    const byService = new Map<string, HealthRecord[]>();
    for (const r of records) {
      const list = byService.get(r.service) ?? [];
      list.push(r);
      byService.set(r.service, list);
    }
    const latest = records.reduce((acc, r) => Math.max(acc, r.timestamp), 0);
    return {
      generatedAt: this.options.now ?? latest,
      services: [...byService.entries()]
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([service, list]) => calculateServiceUptime(service, list, this.options)),
    };
  }

  calculateFromText(text: string, fileName = ''): UptimeReport & { skipped: number[] } {
    const { records, skipped } = parseHealthLog(text, fileName);
    return { ...this.calculate(records), skipped };
  }
}

/** Formats a duration like `1h 02m 05s`. */
export function formatDuration(ms: number): string {
  const total = Math.round(ms / 1000);
  const d = Math.floor(total / 86_400);
  const h = Math.floor((total % 86_400) / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  const pad = (n: number) => String(n).padStart(2, '0');
  if (d > 0) return `${d}d ${pad(h)}h ${pad(m)}m`;
  if (h > 0) return `${h}h ${pad(m)}m ${pad(s)}s`;
  if (m > 0) return `${m}m ${pad(s)}s`;
  return `${s}s`;
}

function badgeColor(availability: number | undefined): string {
  if (availability === undefined) return '#9f9f9f';
  if (availability >= 99.99) return '#4c1';
  if (availability >= 99.9) return '#97ca00';
  if (availability >= 99) return '#dfb317';
  return '#e05d44';
}

/** shields.io endpoint-badge JSON (https://shields.io/badges/endpoint-badge). */
export function uptimeBadgeJson(label: string, availability: number | undefined): string {
  return `${JSON.stringify(
    {
      schemaVersion: 1,
      label,
      message: availability === undefined ? 'no data' : `${availability}%`,
      color: badgeColor(availability).replace('#', ''),
    },
    null,
    2,
  )}\n`;
}

const escapeXml = (s: string) =>
  s.replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' })[c] as string,
  );

/** A flat, self-contained SVG badge. */
export function uptimeBadgeSvg(label: string, availability: number | undefined): string {
  const message = availability === undefined ? 'no data' : `${availability}%`;
  const charW = 6.5;
  const lw = Math.round(label.length * charW + 12);
  const mw = Math.round(message.length * charW + 12);
  const w = lw + mw;
  const color = badgeColor(availability);
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="20" role="img" aria-label="${escapeXml(label)}: ${escapeXml(message)}">
  <title>${escapeXml(label)}: ${escapeXml(message)}</title>
  <rect width="${lw}" height="20" fill="#555"/>
  <rect x="${lw}" width="${mw}" height="20" fill="${color}"/>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="${lw / 2}" y="14">${escapeXml(label)}</text>
    <text x="${lw + mw / 2}" y="14">${escapeXml(message)}</text>
  </g>
</svg>
`;
}

const iso = (ms: number) => new Date(ms).toISOString().replace('.000Z', 'Z');

/** Markdown summary: one availability table plus an incident table per service. */
export function renderUptimeMarkdown(report: UptimeReport): string {
  const out: string[] = ['# Uptime availability report', ''];
  if (report.services.length === 0) {
    out.push('_No health-check records found._');
    return `${out.join('\n')}\n`;
  }
  const labels = report.services[0]?.windows.map((w) => w.label) ?? [];
  out.push(`| Service | ${labels.join(' | ')} | Incidents | Longest outage | MTTR |`);
  out.push(`|---|${labels.map(() => '---:').join('|')}|---:|---:|---:|`);
  for (const s of report.services) {
    const cells = s.windows.map((w) =>
      w.availability === undefined ? 'n/a' : `${w.availability}%`,
    );
    out.push(
      `| ${s.service} | ${cells.join(' | ')} | ${s.incidents.length} | ${
        s.longestIncident ? formatDuration(s.longestIncident.durationMs) : '—'
      } | ${s.mttrMs !== undefined ? formatDuration(s.mttrMs) : '—'} |`,
    );
  }
  for (const s of report.services) {
    if (s.incidents.length === 0) continue;
    out.push(
      '',
      `## ${s.service} incidents`,
      '',
      '| Start | End | Duration | Failed checks |',
      '|---|---|---:|---:|',
    );
    for (const i of s.incidents) {
      out.push(
        `| ${iso(i.start)} | ${i.ongoing ? 'ongoing' : iso(i.end)} | ${formatDuration(i.durationMs)} | ${i.checks} |`,
      );
    }
  }
  return `${out.join('\n')}\n`;
}

export function renderUptimeText(report: UptimeReport): string {
  const out: string[] = ['Uptime availability'];
  if (report.services.length === 0) {
    out.push('No health-check records found.');
    return `${out.join('\n')}\n`;
  }
  for (const s of report.services) {
    out.push('', `${s.service}  (${s.checks} checks, ${iso(s.first)} → ${iso(s.last)})`);
    for (const w of s.windows) {
      out.push(
        `  ${w.label.padEnd(4)} ${w.availability === undefined ? 'n/a' : `${w.availability}%`.padEnd(10)} ${w.nines ?? ''}`.trimEnd(),
      );
    }
    out.push(
      `  incidents ${s.incidents.length}, total downtime ${formatDuration(s.totalDowntimeMs)}`,
    );
    if (s.longestIncident !== undefined) {
      out.push(
        `  longest outage ${formatDuration(s.longestIncident.durationMs)} from ${iso(s.longestIncident.start)}${
          s.longestIncident.ongoing ? ' (ongoing)' : ''
        }`,
      );
    }
    if (s.mttrMs !== undefined) out.push(`  MTTR ${formatDuration(s.mttrMs)}`);
  }
  return `${out.join('\n')}\n`;
}
