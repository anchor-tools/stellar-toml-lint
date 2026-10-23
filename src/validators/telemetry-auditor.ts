/**
 * Stellar Core SCP telemetry extractor and nomination-round latency auditor
 * (issue #314).
 *
 * A validator that falls behind during SCP nomination or ballot rounds delays
 * every ledger for the whole network, and eventually gets dropped from peer
 * quorum sets. The overlay port only proves the process is listening; the
 * admin/metrics port reports what it is actually doing.
 *
 * Under opt-in `--check-network` this module resolves each `[[VALIDATORS]]`
 * node's configured admin or metrics endpoint (`METRICS_URL`, `ADMIN_URL`,
 * `ADMIN_PORT`, `METRICS_PORT`, or an explicit programmatic override), fetches
 * Prometheus `/metrics` (falling back to stellar-core's JSON `/info`), and
 * evaluates:
 *
 *   - `ledger.close.latency`: average ledger-close latency, in milliseconds;
 *   - `scp.sync.lost-sync`: how many times the node has lost SCP sync.
 *
 * A node whose average close latency exceeds 3500 ms emits
 * `validators/high-nomination-latency` (warning); lost sync emits
 * `validators/frequent-lost-sync` (error). A validator with no configured
 * telemetry endpoint, or an endpoint that cannot be read or exposes neither
 * metric, stays silent — the audit only reports what it observed.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { specUrl } from '../spec.js';

export const HIGH_NOMINATION_LATENCY_RULE = 'validators/high-nomination-latency';
export const FREQUENT_LOST_SYNC_RULE = 'validators/frequent-lost-sync';

export const VALIDATORS_HIGH_NOMINATION_LATENCY = HIGH_NOMINATION_LATENCY_RULE;
export const VALIDATORS_FREQUENT_LOST_SYNC = FREQUENT_LOST_SYNC_RULE;

/** Ledger close latency above this (milliseconds) delays consensus. */
export const DEFAULT_LEDGER_CLOSE_LATENCY_MS = 3500;

/** Any observed lost-sync event is treated as frequent by default. */
export const DEFAULT_MAX_LOST_SYNC = 0;

const LOST_SYNC_ALIASES = [
  'scp.sync.lost-sync',
  'scp_sync_lost_sync',
  'scp.sync.lost_sync',
  'scp-sync-lost-sync',
  'scp_sync_lost_sync_total',
] as const;

const LATENCY_ALIASES: ReadonlyArray<{ name: string; unit: 'ms' | 's' }> = [
  { name: 'ledger.close.latency', unit: 'ms' },
  { name: 'ledger_close_latency', unit: 'ms' },
  { name: 'ledger_close_latency_ms', unit: 'ms' },
  { name: 'ledger_close_latency_milliseconds', unit: 'ms' },
  { name: 'ledger.close.latency.ms', unit: 'ms' },
  { name: 'ledger_close_latency_seconds', unit: 's' },
  { name: 'ledger.close.latency.seconds', unit: 's' },
  { name: 'ledger_close_time', unit: 'ms' },
  { name: 'ledger.close.time', unit: 'ms' },
];

export interface TelemetryAuditorOptions {
  rules?: RuleOverrides;
  /** Explicit endpoint per public key or `VALIDATORS` index. */
  endpoints?: Record<string, string> | string;
  /** Latency above which a finding is raised, in milliseconds. */
  maxLedgerCloseLatencyMs?: number;
  /** Lost-sync count above which a finding is raised. */
  maxLostSync?: number;
}

export interface TelemetryEvaluationOptions {
  rules?: RuleOverrides;
  path?: string;
  maxLedgerCloseLatencyMs?: number;
  maxLostSync?: number;
}

/** One sample parsed from the Prometheus text exposition format. */
export interface PrometheusSample {
  name: string;
  normalizedName: string;
  labels: Record<string, string>;
  value: number;
}

/** The telemetry values relevant to consensus health for one node. */
export interface TelemetrySnapshot {
  endpoint: string;
  source: 'metrics' | 'info';
  lostSync?: number;
  averageLedgerCloseLatencyMs?: number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : undefined;
}

function numberValue(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value.trim());
    if (Number.isFinite(parsed)) return parsed;
  }
  return undefined;
}

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules: RuleOverrides | undefined,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

/** Prometheus normalises `-` and `.` out of metric names; so do we. */
export function normalizeMetricName(name: string): string {
  return name.trim().toLowerCase().replace(/[.-]/g, '_');
}

function isLabelKeyStart(character: string): boolean {
  return (
    (character >= 'a' && character <= 'z') ||
    (character >= 'A' && character <= 'Z') ||
    character === '_'
  );
}

function isLabelKeyCharacter(character: string): boolean {
  return isLabelKeyStart(character) || (character >= '0' && character <= '9');
}

function parseLabels(text: string | undefined): Record<string, string> {
  const labels: Record<string, string> = {};
  if (text === undefined) return labels;

  // A hand-written scanner rather than a quoted-value regex: the label body is
  // attacker-controlled, and a nested `(?:[^"\\]|\\.)*` quantifier
  // backtracks catastrophically on a long unterminated value.
  let index = 0;
  while (index < text.length) {
    if (!isLabelKeyStart(text[index] as string)) {
      index++;
      continue;
    }
    const keyStart = index;
    index++;
    while (index < text.length && isLabelKeyCharacter(text[index] as string)) index++;
    const keyEnd = index;
    while (index < text.length && /\s/.test(text[index] as string)) index++;
    if (text[index] !== '=') {
      index = keyEnd;
      continue;
    }
    index++;
    while (index < text.length && /\s/.test(text[index] as string)) index++;
    if (text[index] !== '"') {
      index = keyEnd;
      continue;
    }
    index++;

    let value = '';
    let closed = false;
    while (index < text.length) {
      const character = text[index] as string;
      if (character === '\\' && index + 1 < text.length) {
        const escaped = text[index + 1] as string;
        value += escaped === '"' || escaped === '\\' ? escaped : escaped;
        index += 2;
        continue;
      }
      if (character === '"') {
        closed = true;
        index++;
        break;
      }
      value += character;
      index++;
    }
    if (!closed) break;
    labels[text.slice(keyStart, keyEnd)] = value;
  }
  return labels;
}

/**
 * Parses Prometheus/OpenMetrics text into numeric samples. Comment lines,
 * blank lines, and non-finite values are skipped so a malformed exporter cannot
 * make the auditor throw.
 */
export function parsePrometheusMetrics(text: string): PrometheusSample[] {
  const samples: PrometheusSample[] = [];
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line === '' || line.startsWith('#')) continue;
    const match = /^([a-zA-Z_:][a-zA-Z0-9_:.-]*)(\{[^}]*\})?\s+(\S+)(?:\s+\d+)?$/.exec(line);
    if (match === null) continue;
    const name = match[1];
    const value = Number(match[3]);
    if (name === undefined || !Number.isFinite(value)) continue;
    samples.push({
      name,
      normalizedName: normalizeMetricName(name),
      labels: parseLabels(match[2]),
      value,
    });
  }
  return samples;
}

function samplesNamed(samples: readonly PrometheusSample[], name: string): PrometheusSample[] {
  const normalized = normalizeMetricName(name);
  return samples.filter(
    (sample) =>
      sample.normalizedName === normalized || sample.normalizedName === `${normalized}_total`,
  );
}

function sumSamples(samples: readonly PrometheusSample[]): number | undefined {
  if (samples.length === 0) return undefined;
  return samples.reduce((total, sample) => total + sample.value, 0);
}

function averageSamples(samples: readonly PrometheusSample[]): number | undefined {
  const total = sumSamples(samples);
  return total === undefined ? undefined : total / samples.length;
}

/** The agreed lost-sync counter, summed across labels on one node. */
export function extractLostSync(samples: readonly PrometheusSample[]): number | undefined {
  for (const alias of LOST_SYNC_ALIASES) {
    const value = sumSamples(samplesNamed(samples, alias));
    if (value !== undefined) return value;
  }
  return undefined;
}

/**
 * Average ledger-close latency in milliseconds. Histograms are read from their
 * `_sum`/`_count` siblings; a plain gauge is averaged directly. Names that say
 * `seconds` are converted, so the 3500 ms threshold is always in milliseconds.
 */
export function extractLedgerCloseLatencyMs(
  samples: readonly PrometheusSample[],
): number | undefined {
  for (const alias of LATENCY_ALIASES) {
    const base = normalizeMetricName(alias.name);
    const sum = sumSamples(samples.filter((sample) => sample.normalizedName === `${base}_sum`));
    const count = sumSamples(samples.filter((sample) => sample.normalizedName === `${base}_count`));
    if (sum !== undefined && count !== undefined && count > 0) {
      const milliseconds = sum / count;
      return alias.unit === 's' ? milliseconds * 1000 : milliseconds;
    }
    const direct = averageSamples(samplesNamed(samples, alias.name));
    if (direct !== undefined) return alias.unit === 's' ? direct * 1000 : direct;
  }
  return undefined;
}

interface JsonMetric {
  name: string;
  value: number;
}

function collectJsonMetrics(value: unknown, out: JsonMetric[], depth = 0): void {
  if (depth > 8) return;
  if (Array.isArray(value)) {
    for (const item of value) collectJsonMetrics(item, out, depth + 1);
    return;
  }
  if (!isRecord(value)) return;
  for (const [key, entry] of Object.entries(value)) {
    const numeric = numberValue(entry);
    if (numeric !== undefined) {
      out.push({ name: key, value: numeric });
      continue;
    }
    if (typeof entry === 'object' && entry !== null) collectJsonMetrics(entry, out, depth + 1);
  }
}

/** Extracts the same two metrics from stellar-core's JSON `/info` response. */
export function extractTelemetryFromInfo(
  body: unknown,
): Pick<TelemetrySnapshot, 'lostSync' | 'averageLedgerCloseLatencyMs'> {
  const metrics: JsonMetric[] = [];
  collectJsonMetrics(body, metrics);

  let lostSync: number | undefined;
  for (const metric of metrics) {
    const normalized = normalizeMetricName(metric.name);
    if (
      LOST_SYNC_ALIASES.some((alias) => {
        const candidate = normalizeMetricName(alias);
        return normalized === candidate || normalized === `${candidate}_total`;
      })
    ) {
      lostSync = (lostSync ?? 0) + metric.value;
    }
  }

  let averageLedgerCloseLatencyMs: number | undefined;
  for (const alias of LATENCY_ALIASES) {
    const normalized = normalizeMetricName(alias.name);
    const matches = metrics.filter((metric) => {
      const key = normalizeMetricName(metric.name);
      return key === normalized || key === `${normalized}_ms` || key === `${normalized}_seconds`;
    });
    if (matches.length === 0) continue;
    const seconds = matches.some((metric) => normalizeMetricName(metric.name).endsWith('_seconds'));
    const average = matches.reduce((total, metric) => total + metric.value, 0) / matches.length;
    averageLedgerCloseLatencyMs = alias.unit === 's' || seconds ? average * 1000 : average;
    break;
  }

  return {
    ...(lostSync === undefined ? {} : { lostSync }),
    ...(averageLedgerCloseLatencyMs === undefined ? {} : { averageLedgerCloseLatencyMs }),
  };
}

/** Parses a Prometheus body into the subset of telemetry this audit needs. */
export function extractTelemetryFromMetrics(
  text: string,
): Pick<TelemetrySnapshot, 'lostSync' | 'averageLedgerCloseLatencyMs'> {
  const samples = parsePrometheusMetrics(text);
  const lostSync = extractLostSync(samples);
  const averageLedgerCloseLatencyMs = extractLedgerCloseLatencyMs(samples);
  return {
    ...(lostSync === undefined ? {} : { lostSync }),
    ...(averageLedgerCloseLatencyMs === undefined ? {} : { averageLedgerCloseLatencyMs }),
  };
}

function endpointBase(endpoint: string): string {
  return endpoint.replace(/\/+$/, '');
}

/**
 * Fetches one node's telemetry. `/metrics` is tried first; when it answers but
 * exposes neither metric (or is not available), `/info` is tried. Returns
 * `undefined` when neither surface yields a usable value.
 */
export async function fetchTelemetrySnapshot(
  endpoint: string,
  fetchImpl: typeof fetch = fetch,
): Promise<TelemetrySnapshot | undefined> {
  const base = endpointBase(endpoint);
  const metricsUrl = /\/metrics$/i.test(base) ? base : `${base}/metrics`;
  const infoUrl = /\/info$/i.test(base) ? base : `${base}/info`;
  const candidates = /\/info$/i.test(base)
    ? [infoUrl]
    : /\/metrics$/i.test(base)
      ? [metricsUrl, infoUrl]
      : [metricsUrl, infoUrl];

  for (const url of candidates) {
    let response: Response;
    try {
      response = await fetchImpl(url);
    } catch {
      continue;
    }
    if (!response.ok) continue;

    if (/\/info$/i.test(url)) {
      let body: unknown;
      try {
        body = await response.json();
      } catch {
        continue;
      }
      const extracted = extractTelemetryFromInfo(body);
      if (extracted.lostSync !== undefined || extracted.averageLedgerCloseLatencyMs !== undefined) {
        return { endpoint: url, source: 'info', ...extracted };
      }
      continue;
    }

    let text: string;
    try {
      text = await response.text();
    } catch {
      continue;
    }
    const extracted = extractTelemetryFromMetrics(text);
    if (extracted.lostSync !== undefined || extracted.averageLedgerCloseLatencyMs !== undefined) {
      return { endpoint: url, source: 'metrics', ...extracted };
    }
  }

  return undefined;
}

function hostWithoutPort(host: string): string {
  const trimmed = host.trim();
  if (trimmed.startsWith('[')) {
    const end = trimmed.indexOf(']');
    return end > 0 ? trimmed.slice(0, end + 1) : trimmed;
  }
  return trimmed.split(':')[0] ?? trimmed;
}

function portValue(value: unknown): string | undefined {
  const numeric = numberValue(value);
  if (numeric === undefined) return undefined;
  if (!Number.isInteger(numeric) || numeric < 1 || numeric > 65535) return undefined;
  return String(numeric);
}

/**
 * Resolves the telemetry endpoint a `[[VALIDATORS]]` entry configures.
 *
 * Explicit `METRICS_URL`/`ADMIN_URL`/`TELEMETRY_URL` values win; otherwise an
 * `ADMIN_PORT`/`METRICS_PORT` is combined with the node's `HOST` (or an
 * `ADMIN_HOST` when present). Entries that declare no admin surface are skipped
 * rather than probed at a guessed port.
 */
export function resolveTelemetryEndpoint(
  entry: Record<string, unknown>,
  index = 0,
  options: TelemetryAuditorOptions = {},
): string | undefined {
  const publicKey = stringValue(entry.PUBLIC_KEY);
  const alias = stringValue(entry.ALIAS);
  const endpoints = options.endpoints;
  if (typeof endpoints === 'string') return endpoints;
  if (endpoints !== undefined) {
    const override =
      (publicKey === undefined ? undefined : endpoints[publicKey]) ??
      (alias === undefined ? undefined : endpoints[alias]) ??
      endpoints[String(index)];
    if (override !== undefined) return override;
  }

  const explicit =
    stringValue(entry.METRICS_URL) ??
    stringValue(entry.ADMIN_URL) ??
    stringValue(entry.TELEMETRY_URL) ??
    stringValue(entry.METRICS_ENDPOINT) ??
    stringValue(entry.ADMIN_ENDPOINT);
  if (explicit !== undefined) return explicit;

  const port =
    portValue(entry.ADMIN_PORT) ?? portValue(entry.METRICS_PORT) ?? portValue(entry.TELEMETRY_PORT);
  const adminHost = stringValue(entry.ADMIN_HOST);
  const host = stringValue(entry.HOST);
  if (port === undefined && adminHost === undefined) return undefined;

  const scheme = entry.ADMIN_TLS === true || entry.METRICS_TLS === true ? 'https' : 'http';
  const path = stringValue(entry.METRICS_PATH) ?? '/metrics';

  if (adminHost !== undefined) {
    const hasPort = /:\d+$/.test(adminHost) || /^\[[^\]]+\]:\d+$/.test(adminHost);
    return `${scheme}://${adminHost}${hasPort || port === undefined ? '' : `:${port}`}${path}`;
  }
  if (host === undefined || port === undefined) return undefined;
  return `${scheme}://${hostWithoutPort(host)}:${port}${path}`;
}

/**
 * Turns one snapshot into diagnostics. Values that are absent produce no
 * finding; a threshold override of `off` suppresses the rule entirely.
 */
export function evaluateTelemetry(
  snapshot: TelemetrySnapshot,
  options: TelemetryEvaluationOptions = {},
): Diagnostic[] {
  const diagnostics: Diagnostic[] = [];
  const path = options.path ?? 'VALIDATORS';
  const maxLatency = options.maxLedgerCloseLatencyMs ?? DEFAULT_LEDGER_CLOSE_LATENCY_MS;
  const maxLostSync = options.maxLostSync ?? DEFAULT_MAX_LOST_SYNC;

  const latency = snapshot.averageLedgerCloseLatencyMs;
  if (latency !== undefined && latency > maxLatency) {
    const severity = severityFor(HIGH_NOMINATION_LATENCY_RULE, 'warning', options.rules);
    if (severity !== undefined) {
      diagnostics.push({
        rule: HIGH_NOMINATION_LATENCY_RULE,
        severity,
        category: 'validators',
        message:
          `Average ledger close latency is ${Math.round(latency)} ms at ${snapshot.endpoint}, ` +
          `above the ${maxLatency} ms nomination-round budget`,
        path,
        helpUri: specUrl('validator-information'),
        suggestion:
          'Check CPU steal and disk latency, keep the node peering with Tier-1 validators, and ' +
          'raise the SCP ballot timeout only after the host is no longer starved.',
      });
    }
  }

  const lostSync = snapshot.lostSync;
  if (lostSync !== undefined && lostSync > maxLostSync) {
    const severity = severityFor(FREQUENT_LOST_SYNC_RULE, 'error', options.rules);
    if (severity !== undefined) {
      diagnostics.push({
        rule: FREQUENT_LOST_SYNC_RULE,
        severity,
        category: 'validators',
        message:
          `SCP lost sync ${lostSync} time${lostSync === 1 ? '' : 's'} according to ` +
          `${snapshot.endpoint}, which drops the node from peer quorum sets`,
        path,
        helpUri: specUrl('validator-information'),
        suggestion:
          'Investigate the node clock, overlay connectivity, and CPU pressure; a validator that ' +
          'repeatedly loses SCP sync delays ledger close for the whole network.',
      });
    }
  }

  return diagnostics;
}

function validatorEntries(
  doc: Record<string, unknown>,
): Array<{ index: number; entry: Record<string, unknown> }> {
  const list = Array.isArray(doc.VALIDATORS) ? doc.VALIDATORS : [];
  const entries: Array<{ index: number; entry: Record<string, unknown> }> = [];
  list.forEach((entry, index) => {
    if (isRecord(entry)) entries.push({ index, entry });
  });
  return entries;
}

/**
 * The `--check-network` entry point: reads telemetry from every declared
 * validator that configures an admin/metrics endpoint and reports consensus
 * latency and lost-sync findings.
 */
export async function checkValidatorTelemetry(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: TelemetryAuditorOptions = {},
): Promise<Diagnostic[]> {
  const diagnostics: Diagnostic[] = [];
  for (const { index, entry } of validatorEntries(doc)) {
    const endpoint = resolveTelemetryEndpoint(entry, index, options);
    if (endpoint === undefined) continue;
    const snapshot = await fetchTelemetrySnapshot(endpoint, fetchImpl);
    if (snapshot === undefined) continue;
    diagnostics.push(
      ...evaluateTelemetry(snapshot, {
        rules: options.rules,
        path: `VALIDATORS[${index}]`,
        ...(options.maxLedgerCloseLatencyMs === undefined
          ? {}
          : { maxLedgerCloseLatencyMs: options.maxLedgerCloseLatencyMs }),
        ...(options.maxLostSync === undefined ? {} : { maxLostSync: options.maxLostSync }),
      }),
    );
  }
  return diagnostics;
}

export const auditTelemetry = checkValidatorTelemetry;
export const checkScpTelemetry = checkValidatorTelemetry;
export const verifyTelemetry = checkValidatorTelemetry;

/** Rules registered so `--list-rules`, `--off`, and SARIF know the ids. */
export const telemetryAuditorRules: Rule[] = [
  {
    id: HIGH_NOMINATION_LATENCY_RULE,
    category: 'validators',
    severity: 'warning',
    description:
      'Average ledger close latency should stay under 3500 ms so SCP nomination rounds finish in time',
    run() {},
  },
  {
    id: FREQUENT_LOST_SYNC_RULE,
    category: 'validators',
    severity: 'error',
    description:
      'A validator reporting SCP lost-sync events is at risk of being dropped from peer quorum sets',
    run() {},
  },
];

export const telemetryAuditorRuleIds: readonly string[] = telemetryAuditorRules.map(
  (rule) => rule.id,
);
