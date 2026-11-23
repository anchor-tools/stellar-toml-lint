/**
 * Prometheus / OpenMetrics endpoint validator.
 *
 * Anchors and validator operators expose `/metrics` endpoints so Grafana,
 * Datadog and friends can scrape operational health. A malformed exposition —
 * an unknown `TYPE`, a counter that goes negative, a histogram with no `+Inf`
 * bucket — makes those systems drop the whole scrape or silently ingest junk.
 *
 * `PrometheusMetricsValidator` scrapes an endpoint and checks the payload
 * against both the Prometheus text format 0.0.4 and OpenMetrics 1.0.0. The
 * parser is incremental: the body is consumed chunk by chunk and only
 * per-family aggregates are kept, so a payload with millions of samples is
 * validated in bounded memory.
 */

export type MetricsFormat = 'prometheus-0.0.4' | 'openmetrics-1.0.0';

export type MetricIssueCode =
  | 'metrics/invalid-metric-name'
  | 'metrics/invalid-label-name'
  | 'metrics/reserved-label-name'
  | 'metrics/duplicate-label'
  | 'metrics/malformed-labels'
  | 'metrics/malformed-sample'
  | 'metrics/invalid-value'
  | 'metrics/invalid-timestamp'
  | 'metrics/invalid-type'
  | 'metrics/duplicate-type'
  | 'metrics/duplicate-help'
  | 'metrics/type-after-samples'
  | 'metrics/missing-type'
  | 'metrics/missing-help'
  | 'metrics/nan-gauge'
  | 'metrics/negative-counter'
  | 'metrics/counter-name-suffix'
  | 'metrics/histogram-missing-inf-bucket'
  | 'metrics/histogram-missing-le'
  | 'metrics/histogram-missing-sum-count'
  | 'metrics/missing-eof'
  | 'metrics/content-after-eof'
  | 'metrics/missing-required-metric'
  | 'metrics/payload-too-large'
  | 'metrics/unreachable';

export interface MetricIssue {
  code: MetricIssueCode;
  severity: 'error' | 'warning';
  message: string;
  /** 1-based line in the exposition, when the issue is tied to one. */
  line?: number;
  metric?: string;
}

export interface MetricFamilySummary {
  name: string;
  type?: string;
  help?: string;
  unit?: string;
  samples: number;
}

export interface MetricsReport {
  ok: boolean;
  url?: string;
  format: MetricsFormat;
  families: MetricFamilySummary[];
  samples: number;
  lines: number;
  bytes: number;
  issues: MetricIssue[];
  /** Issues dropped once {@link ParserOptions.maxIssues} was reached. */
  truncatedIssues: number;
}

export interface ParserOptions {
  format?: MetricsFormat;
  /** Metric families that must be present; defaults to {@link REQUIRED_ANCHOR_METRICS}. */
  requiredMetrics?: readonly string[];
  /** Cap on stored issues so a pathological payload cannot exhaust memory. */
  maxIssues?: number;
}

/** Gauges and counters every anchor exporter is expected to publish. */
export const REQUIRED_ANCHOR_METRICS: readonly string[] = [
  'stellar_anchor_balance',
  'stellar_tx_processed_total',
  'stellar_sep_request_duration_seconds',
];

const PROMETHEUS_TYPES = new Set(['counter', 'gauge', 'histogram', 'summary', 'untyped']);
const OPENMETRICS_TYPES = new Set([
  'counter',
  'gauge',
  'histogram',
  'gaugehistogram',
  'summary',
  'stateset',
  'info',
  'unknown',
]);

const METRIC_NAME = /^[a-zA-Z_:][a-zA-Z0-9_:]*$/;
const LABEL_NAME = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

/** Suffixes a sample may carry on top of its family name. */
const SUFFIXES = ['_total', '_bucket', '_sum', '_count', '_created', '_gcount', '_gsum', '_info'];

interface FamilyState {
  name: string;
  type?: string;
  help?: string;
  unit?: string;
  samples: number;
  hasLe: boolean;
  hasInf: boolean;
  bucketSamples: number;
  hasSum: boolean;
  hasCount: boolean;
}

/** Parses `value` as a Prometheus float, accepting `NaN`, `+Inf`, `-Inf`. */
export function parseMetricValue(raw: string): number | undefined {
  if (raw === 'NaN') return Number.NaN;
  if (raw === '+Inf' || raw === 'Inf') return Number.POSITIVE_INFINITY;
  if (raw === '-Inf') return Number.NEGATIVE_INFINITY;
  if (!/^[-+]?(\d+\.?\d*|\.\d+)([eE][-+]?\d+)?$/.test(raw)) return undefined;
  return Number(raw);
}

/** Splits a `{a="b",c="d"}` label body; returns undefined when malformed. */
export function parseLabels(body: string): [string, string][] | undefined {
  const out: [string, string][] = [];
  let i = 0;
  while (i < body.length) {
    while (body[i] === ' ' || body[i] === ',') i++;
    if (i >= body.length) break;
    const eq = body.indexOf('=', i);
    if (eq === -1) return undefined;
    const name = body.slice(i, eq).trim();
    i = eq + 1;
    if (body[i] !== '"') return undefined;
    i++;
    let value = '';
    let closed = false;
    while (i < body.length) {
      const ch = body[i] as string;
      if (ch === '\\') {
        const next = body[i + 1];
        if (next === 'n') value += '\n';
        else if (next === '"' || next === '\\') value += next;
        else return undefined;
        i += 2;
        continue;
      }
      if (ch === '"') {
        closed = true;
        i++;
        break;
      }
      value += ch;
      i++;
    }
    if (!closed) return undefined;
    out.push([name, value]);
    while (body[i] === ' ') i++;
    if (i < body.length && body[i] !== ',') return undefined;
  }
  return out;
}

/**
 * Incremental OpenMetrics / Prometheus text parser.
 *
 * Feed chunks with {@link push}; call {@link end} for the report. Only one
 * partial line is buffered between chunks.
 */
export class MetricsTextParser {
  private readonly format: MetricsFormat;
  private readonly required: readonly string[];
  private readonly maxIssues: number;
  private readonly families = new Map<string, FamilyState>();
  private readonly issues: MetricIssue[] = [];
  private truncated = 0;
  private buffer = '';
  private lineNo = 0;
  private bytes = 0;
  private sampleTotal = 0;
  private sawEof = false;
  private reportedAfterEof = false;
  private lastFamily: string | undefined;

  constructor(options: ParserOptions = {}) {
    this.format = options.format ?? 'prometheus-0.0.4';
    this.required = options.requiredMetrics ?? REQUIRED_ANCHOR_METRICS;
    this.maxIssues = options.maxIssues ?? 500;
  }

  push(chunk: string): void {
    this.bytes += chunk.length;
    this.buffer += chunk;
    let nl = this.buffer.indexOf('\n');
    while (nl !== -1) {
      this.line(this.buffer.slice(0, nl));
      this.buffer = this.buffer.slice(nl + 1);
      nl = this.buffer.indexOf('\n');
    }
  }

  end(): MetricsReport {
    if (this.buffer.length > 0) {
      this.line(this.buffer);
      this.buffer = '';
    }
    if (this.format === 'openmetrics-1.0.0' && !this.sawEof) {
      this.issue('metrics/missing-eof', 'error', 'OpenMetrics exposition must end with "# EOF"');
    }
    for (const family of this.families.values()) this.finishFamily(family);
    for (const name of this.required) {
      if (!this.hasFamily(name)) {
        this.issue(
          'metrics/missing-required-metric',
          'warning',
          `Required anchor metric ${name} is not exported`,
          undefined,
          name,
        );
      }
    }
    return {
      ok: !this.issues.some((i) => i.severity === 'error'),
      format: this.format,
      families: [...this.families.values()].map((f) => ({
        name: f.name,
        ...(f.type !== undefined ? { type: f.type } : {}),
        ...(f.help !== undefined ? { help: f.help } : {}),
        ...(f.unit !== undefined ? { unit: f.unit } : {}),
        samples: f.samples,
      })),
      samples: this.sampleTotal,
      lines: this.lineNo,
      bytes: this.bytes,
      issues: this.issues,
      truncatedIssues: this.truncated,
    };
  }

  private hasFamily(name: string): boolean {
    if (this.families.has(name)) return true;
    // `foo_total` may be declared as family `foo` in OpenMetrics.
    for (const suffix of SUFFIXES) {
      if (name.endsWith(suffix) && this.families.has(name.slice(0, -suffix.length))) return true;
    }
    return false;
  }

  private issue(
    code: MetricIssueCode,
    severity: 'error' | 'warning',
    message: string,
    line?: number,
    metric?: string,
  ): void {
    if (this.issues.length >= this.maxIssues) {
      this.truncated++;
      return;
    }
    this.issues.push({
      code,
      severity,
      message,
      ...(line !== undefined ? { line } : {}),
      ...(metric !== undefined ? { metric } : {}),
    });
  }

  private family(name: string): FamilyState {
    let family = this.families.get(name);
    if (family === undefined) {
      family = {
        name,
        samples: 0,
        hasLe: false,
        hasInf: false,
        bucketSamples: 0,
        hasSum: false,
        hasCount: false,
      };
      this.families.set(name, family);
    }
    return family;
  }

  private line(raw: string): void {
    this.lineNo++;
    const line = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
    if (this.sawEof) {
      if (line.length > 0 && !this.reportedAfterEof) {
        this.reportedAfterEof = true;
        this.issue(
          'metrics/content-after-eof',
          'error',
          'Content found after "# EOF"',
          this.lineNo,
        );
      }
      return;
    }
    if (line.trim() === '') return;
    if (line.startsWith('#')) {
      this.comment(line);
      return;
    }
    this.sample(line);
  }

  private comment(line: string): void {
    if (line === '# EOF') {
      this.sawEof = true;
      return;
    }
    const match = /^#\s+(HELP|TYPE|UNIT)\s+(\S+)(?:\s+(.*))?$/.exec(line);
    if (match === null) return; // ordinary comment
    const [, keyword, name, rest = ''] = match as unknown as [string, string, string, string?];
    if (!METRIC_NAME.test(name)) {
      this.issue(
        'metrics/invalid-metric-name',
        'error',
        `Invalid metric name "${name}" in # ${keyword}`,
        this.lineNo,
        name,
      );
      return;
    }
    const family = this.family(name);
    if (keyword === 'HELP') {
      if (family.help !== undefined) {
        this.issue(
          'metrics/duplicate-help',
          'error',
          `Duplicate # HELP for ${name}`,
          this.lineNo,
          name,
        );
      }
      family.help = rest;
    } else if (keyword === 'TYPE') {
      const type = rest.trim();
      const allowed = this.format === 'openmetrics-1.0.0' ? OPENMETRICS_TYPES : PROMETHEUS_TYPES;
      if (family.type !== undefined) {
        this.issue(
          'metrics/duplicate-type',
          'error',
          `Duplicate # TYPE for ${name}`,
          this.lineNo,
          name,
        );
      } else if (family.samples > 0) {
        this.issue(
          'metrics/type-after-samples',
          'error',
          `# TYPE for ${name} appears after its samples`,
          this.lineNo,
          name,
        );
      }
      if (!allowed.has(type)) {
        this.issue(
          'metrics/invalid-type',
          'error',
          `Invalid metric type "${type}" for ${name}; expected one of ${[...allowed].join(', ')}`,
          this.lineNo,
          name,
        );
      }
      family.type = type;
    } else {
      family.unit = rest.trim();
    }
  }

  /** Finds which declared family a sample name belongs to. */
  private resolveFamily(sampleName: string): { family: FamilyState; suffix: string } {
    const exact = this.families.get(sampleName);
    if (exact !== undefined && exact.type !== undefined) return { family: exact, suffix: '' };
    for (const suffix of SUFFIXES) {
      if (!sampleName.endsWith(suffix)) continue;
      const base = this.families.get(sampleName.slice(0, -suffix.length));
      if (base !== undefined && base.type !== undefined) return { family: base, suffix };
    }
    // Consecutive samples of an undeclared histogram share the last family.
    if (this.lastFamily !== undefined) {
      for (const suffix of SUFFIXES) {
        if (sampleName === this.lastFamily + suffix) {
          return { family: this.family(this.lastFamily), suffix };
        }
      }
    }
    return { family: this.family(sampleName), suffix: '' };
  }

  private sample(line: string): void {
    const split = splitSampleLine(line);
    if (split === undefined) {
      this.issue(
        'metrics/malformed-sample',
        'error',
        `Malformed sample line: ${truncate(line)}`,
        this.lineNo,
      );
      return;
    }
    const { name, labelBody, rawValue, rawTimestamp } = split;
    if (!METRIC_NAME.test(name)) {
      this.issue(
        'metrics/invalid-metric-name',
        'error',
        `Invalid metric name "${name}"`,
        this.lineNo,
        name,
      );
      return;
    }
    this.sampleTotal++;
    const { family, suffix } = this.resolveFamily(name);
    this.lastFamily = family.name;
    family.samples++;

    let labels: [string, string][] = [];
    if (labelBody !== undefined) {
      const parsed = parseLabels(labelBody);
      if (parsed === undefined) {
        this.issue(
          'metrics/malformed-labels',
          'error',
          `Malformed label set on ${name}`,
          this.lineNo,
          name,
        );
      } else {
        labels = parsed;
        const seen = new Set<string>();
        for (const [labelName] of labels) {
          if (!LABEL_NAME.test(labelName)) {
            this.issue(
              'metrics/invalid-label-name',
              'error',
              `Invalid label name "${labelName}" on ${name}`,
              this.lineNo,
              name,
            );
          } else if (labelName.startsWith('__')) {
            this.issue(
              'metrics/reserved-label-name',
              'error',
              `Label name "${labelName}" on ${name} uses the reserved "__" prefix`,
              this.lineNo,
              name,
            );
          }
          if (seen.has(labelName)) {
            this.issue(
              'metrics/duplicate-label',
              'error',
              `Label "${labelName}" repeated on ${name}`,
              this.lineNo,
              name,
            );
          }
          seen.add(labelName);
        }
      }
    }

    const value = parseMetricValue(rawValue);
    if (value === undefined) {
      this.issue(
        'metrics/invalid-value',
        'error',
        `Invalid sample value "${rawValue}" on ${name}`,
        this.lineNo,
        name,
      );
    }
    if (rawTimestamp !== undefined && parseMetricValue(rawTimestamp) === undefined) {
      this.issue(
        'metrics/invalid-timestamp',
        'error',
        `Invalid timestamp "${rawTimestamp}" on ${name}`,
        this.lineNo,
        name,
      );
    }

    const type = family.type;
    if (value !== undefined) {
      if (type === 'gauge' && Number.isNaN(value)) {
        this.issue('metrics/nan-gauge', 'warning', `Gauge ${name} reports NaN`, this.lineNo, name);
      }
      if (
        (type === 'counter' || ((type === 'histogram' || type === 'summary') && suffix !== '')) &&
        value < 0
      ) {
        this.issue(
          'metrics/negative-counter',
          'error',
          `${type === 'counter' ? 'Counter' : 'Cumulative series'} ${name} is negative (${rawValue})`,
          this.lineNo,
          name,
        );
      }
    }
    if (type === 'histogram' || type === 'gaugehistogram') {
      if (suffix === '_bucket') {
        family.bucketSamples++;
        const le = labels.find(([labelName]) => labelName === 'le');
        if (le === undefined) {
          this.issue(
            'metrics/histogram-missing-le',
            'error',
            `Histogram bucket ${name} has no "le" label`,
            this.lineNo,
            name,
          );
        } else {
          family.hasLe = true;
          if (le[1] === '+Inf') family.hasInf = true;
        }
      } else if (suffix === '_sum' || suffix === '_gsum') family.hasSum = true;
      else if (suffix === '_count' || suffix === '_gcount') family.hasCount = true;
    }
  }

  private finishFamily(family: FamilyState): void {
    if (family.samples === 0) return;
    if (family.type === undefined) {
      this.issue(
        'metrics/missing-type',
        'warning',
        `Metric ${family.name} has no # TYPE declaration`,
        undefined,
        family.name,
      );
    }
    if (family.help === undefined || family.help.trim() === '') {
      this.issue(
        'metrics/missing-help',
        'warning',
        `Metric ${family.name} has no # HELP string`,
        undefined,
        family.name,
      );
    }
    if (
      family.type === 'counter' &&
      this.format === 'prometheus-0.0.4' &&
      !family.name.endsWith('_total')
    ) {
      this.issue(
        'metrics/counter-name-suffix',
        'warning',
        `Counter ${family.name} should end in "_total"`,
        undefined,
        family.name,
      );
    }
    if (family.type === 'histogram' || family.type === 'gaugehistogram') {
      if (family.bucketSamples > 0 && !family.hasInf && family.hasLe) {
        this.issue(
          'metrics/histogram-missing-inf-bucket',
          'error',
          `Histogram ${family.name} has no le="+Inf" bucket`,
          undefined,
          family.name,
        );
      }
      if (family.type === 'histogram' && (!family.hasSum || !family.hasCount)) {
        this.issue(
          'metrics/histogram-missing-sum-count',
          'warning',
          `Histogram ${family.name} should expose both _sum and _count`,
          undefined,
          family.name,
        );
      }
    }
  }
}

interface SampleParts {
  name: string;
  labelBody?: string;
  rawValue: string;
  rawTimestamp?: string;
}

/**
 * Splits `name{labels} value [timestamp] [# exemplar]`. The label body is
 * scanned with quote awareness so `}` inside a label value, or an OpenMetrics
 * exemplar's own `{...}`, cannot end it early or late.
 */
export function splitSampleLine(line: string): SampleParts | undefined {
  let i = 0;
  while (i < line.length && line[i] !== '{' && line[i] !== ' ' && line[i] !== '\t') i++;
  const name = line.slice(0, i);
  if (name === '') return undefined;
  let labelBody: string | undefined;
  if (line[i] === '{') {
    const start = ++i;
    let quoted = false;
    for (; i < line.length; i++) {
      const ch = line[i];
      if (quoted) {
        if (ch === '\\') i++;
        else if (ch === '"') quoted = false;
      } else if (ch === '"') quoted = true;
      else if (ch === '}') break;
    }
    if (i >= line.length) return undefined;
    labelBody = line.slice(start, i);
    i++;
  }
  let rest = line.slice(i);
  const exemplar = rest.indexOf(' # ');
  if (exemplar !== -1) rest = rest.slice(0, exemplar);
  const fields = rest
    .trim()
    .split(/\s+/)
    .filter((f) => f !== '');
  if (fields.length < 1 || fields.length > 2) return undefined;
  return {
    name,
    ...(labelBody !== undefined ? { labelBody } : {}),
    rawValue: fields[0] as string,
    ...(fields[1] !== undefined ? { rawTimestamp: fields[1] } : {}),
  };
}

function truncate(text: string, max = 80): string {
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

/** Picks the exposition format from a Content-Type header. */
export function detectMetricsFormat(contentType: string | null | undefined): MetricsFormat {
  return contentType !== null &&
    contentType !== undefined &&
    contentType.toLowerCase().includes('application/openmetrics-text')
    ? 'openmetrics-1.0.0'
    : 'prometheus-0.0.4';
}

/** Validates a complete exposition held in memory. */
export function validateMetricsText(text: string, options: ParserOptions = {}): MetricsReport {
  let format = options.format;
  if (format === undefined) {
    format = /(^|\n)# EOF\s*$/.test(text) ? 'openmetrics-1.0.0' : 'prometheus-0.0.4';
  }
  const parser = new MetricsTextParser({ ...options, format });
  parser.push(text);
  return parser.end();
}

/** Keys in `stellar.toml` that may advertise a metrics endpoint. */
const METRICS_KEY = /(METRICS|PROMETHEUS|OPENMETRICS|MONITORING)/i;

/**
 * Finds metrics endpoints advertised in a parsed `stellar.toml`.
 *
 * SEP-1 has no standard field, so any top-level or `[DOCUMENTATION]` key whose
 * name mentions metrics, Prometheus or monitoring and whose value is an
 * http(s) URL counts.
 */
export function discoverMetricsEndpoints(doc: Record<string, unknown>): string[] {
  const urls = new Set<string>();
  const scan = (table: Record<string, unknown>) => {
    for (const [key, value] of Object.entries(table)) {
      if (typeof value === 'string' && METRICS_KEY.test(key) && /^https?:\/\//i.test(value)) {
        urls.add(value);
      }
    }
  };
  scan(doc);
  const documentation = doc.DOCUMENTATION;
  if (
    documentation !== null &&
    typeof documentation === 'object' &&
    !Array.isArray(documentation)
  ) {
    scan(documentation as Record<string, unknown>);
  }
  return [...urls];
}

export interface PrometheusMetricsValidatorOptions {
  fetchImpl?: typeof fetch;
  requiredMetrics?: readonly string[];
  /** Abort the scrape after this many bytes (default 64 MiB). */
  maxBytes?: number;
  timeoutMs?: number;
}

export class PrometheusMetricsValidator {
  private readonly fetchImpl: typeof fetch;
  private readonly requiredMetrics: readonly string[] | undefined;
  private readonly maxBytes: number;
  private readonly timeoutMs: number;

  constructor(options: PrometheusMetricsValidatorOptions = {}) {
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.requiredMetrics = options.requiredMetrics;
    this.maxBytes = options.maxBytes ?? 64 * 1024 * 1024;
    this.timeoutMs = options.timeoutMs ?? 10_000;
  }

  /** Scrapes `url` and validates the body as it streams in. */
  async validateUrl(url: string): Promise<MetricsReport> {
    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        headers: {
          accept:
            'application/openmetrics-text;version=1.0.0,text/plain;version=0.0.4;q=0.5,*/*;q=0.1',
        },
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (error) {
      return failure(url, `Could not reach ${url}: ${errorMessage(error)}`);
    }
    if (!response.ok) {
      return failure(url, `${url} answered HTTP ${response.status}`);
    }
    const format = detectMetricsFormat(response.headers.get('content-type'));
    const parser = new MetricsTextParser({
      format,
      ...(this.requiredMetrics !== undefined ? { requiredMetrics: this.requiredMetrics } : {}),
    });
    let received = 0;
    let tooLarge = false;
    if (response.body !== null) {
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        received += value.byteLength;
        if (received > this.maxBytes) {
          tooLarge = true;
          await reader.cancel();
          break;
        }
        parser.push(decoder.decode(value, { stream: true }));
      }
      parser.push(decoder.decode());
    }
    const report = parser.end();
    report.url = url;
    if (tooLarge) {
      report.issues.unshift({
        code: 'metrics/payload-too-large',
        severity: 'error',
        message: `Metrics payload exceeds ${this.maxBytes} bytes; scrape aborted`,
      });
      report.ok = false;
    }
    return report;
  }
}

function failure(url: string, message: string): MetricsReport {
  return {
    ok: false,
    url,
    format: 'prometheus-0.0.4',
    families: [],
    samples: 0,
    lines: 0,
    bytes: 0,
    issues: [{ code: 'metrics/unreachable', severity: 'error', message }],
    truncatedIssues: 0,
  };
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Human-readable report. */
export function renderMetricsReport(report: MetricsReport): string {
  const lines: string[] = [];
  lines.push(`Metrics endpoint: ${report.url ?? '(inline)'}`);
  lines.push(
    `Format: ${report.format} · ${report.families.length} families · ${report.samples} samples · ${report.bytes} bytes`,
  );
  const errors = report.issues.filter((i) => i.severity === 'error');
  const warnings = report.issues.filter((i) => i.severity === 'warning');
  if (report.issues.length === 0) {
    lines.push('✓ Exposition is valid');
  } else {
    for (const issue of report.issues) {
      const where = issue.line !== undefined ? ` (line ${issue.line})` : '';
      lines.push(
        `  ${issue.severity === 'error' ? '✗' : '!'} ${issue.message}${where} [${issue.code}]`,
      );
    }
    if (report.truncatedIssues > 0)
      lines.push(`  … ${report.truncatedIssues} more issues not shown`);
  }
  lines.push(`${errors.length} errors, ${warnings.length} warnings`);
  return `${lines.join('\n')}\n`;
}
