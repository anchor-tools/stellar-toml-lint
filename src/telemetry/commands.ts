/**
 * CLI entry points for the telemetry subcommands:
 *
 *   stellar-toml-lint verify-metrics --url <metrics_url> | --domain <domain>
 *   stellar-toml-lint probe-sla --domain <domain> [--samples <n>]
 *   stellar-toml-lint --audit-error-taxonomy --domain <domain>
 *   stellar-toml-lint calculate-uptime --log-file <path>
 *
 * Each function takes its argument list and an IO bag so tests can drive it
 * without spawning a process. Exit codes follow the rest of the CLI: 0 clean,
 * 1 findings, 2 bad usage or I/O failure.
 */
import { readFile as fsReadFile, writeFile as fsWriteFile } from 'node:fs/promises';
import { basename } from 'node:path';
import { parse as parseToml } from 'smol-toml';
import {
  discoverMetricsEndpoints,
  PrometheusMetricsValidator,
  renderMetricsReport,
  type MetricsReport,
} from './prometheusValidator.js';
import {
  AnchorSlaLatencyProber,
  DEFAULT_TTFB_SLA_MS,
  renderSlaReport,
  type TimingProbe,
} from './slaLatencyProber.js';
import { Rfc7807ErrorValidator, renderErrorTaxonomyReport } from './rfc7807Validator.js';
import {
  renderUptimeMarkdown,
  renderUptimeText,
  uptimeBadgeJson,
  uptimeBadgeSvg,
  UptimeAvailabilityCalculator,
} from './uptimeCalculator.js';
import { trimTrailingSlashes } from '../strings.js';

export interface CommandIo {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  fetchImpl?: typeof fetch;
  probe?: TimingProbe;
  readFile?: (path: string) => Promise<string>;
  writeFile?: (path: string, data: string) => Promise<void>;
}

export const processIo: CommandIo = {
  stdout: (t) => process.stdout.write(t),
  stderr: (t) => process.stderr.write(t),
};

class UsageError extends Error {}

function value(args: readonly string[], i: number, flag: string): string {
  const v = args[i];
  if (v === undefined || v.startsWith('--')) throw new UsageError(`${flag} needs a value`);
  return v;
}

function positiveInt(raw: string, flag: string): number {
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1) throw new UsageError(`${flag} must be a positive integer`);
  return n;
}

function nonNegative(raw: string, flag: string): number {
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 0) throw new UsageError(`${flag} must be a non-negative number`);
  return n;
}

function format(raw: string, allowed: readonly string[]): string {
  if (!allowed.includes(raw)) throw new UsageError(`--format must be one of ${allowed.join(', ')}`);
  return raw;
}

/** Fetches and parses `https://<domain>/.well-known/stellar.toml`. */
export async function fetchStellarToml(
  domain: string,
  fetchImpl: typeof fetch = fetch,
): Promise<Record<string, unknown>> {
  const host = trimTrailingSlashes(domain.replace(/^https?:\/\//, ''));
  const scheme = /^http:\/\//.test(domain) ? 'http' : 'https';
  const url = `${scheme}://${host}/.well-known/stellar.toml`;
  const response = await fetchImpl(url);
  if (!response.ok) throw new Error(`Could not fetch ${url}: HTTP ${response.status}`);
  return parseToml(await response.text()) as Record<string, unknown>;
}

async function loadToml(
  opts: { domain?: string; toml?: string },
  io: CommandIo,
): Promise<Record<string, unknown>> {
  if (opts.toml !== undefined) {
    const read = io.readFile ?? ((p: string) => fsReadFile(p, 'utf8'));
    return parseToml(await read(opts.toml)) as Record<string, unknown>;
  }
  return fetchStellarToml(opts.domain as string, io.fetchImpl);
}

function fail(io: CommandIo, error: unknown, usage: string): number {
  if (error instanceof UsageError) {
    io.stderr(`${error.message}\n${usage}\n`);
  } else {
    io.stderr(`${error instanceof Error ? error.message : String(error)}\n`);
  }
  return 2;
}

const METRICS_USAGE =
  'Usage: stellar-toml-lint verify-metrics (--url <metrics_url> | --domain <domain> | --toml <path>) [--require <metric>]... [--no-required-metrics] [--format text|json]';

export async function verifyMetricsCommand(
  args: readonly string[],
  io: CommandIo = processIo,
): Promise<number> {
  const urls: string[] = [];
  let domain: string | undefined;
  let toml: string | undefined;
  let fmt = 'text';
  let required: string[] | undefined;
  try {
    for (let i = 0; i < args.length; i++) {
      const arg = args[i] as string;
      if (arg === '--url') urls.push(value(args, ++i, arg));
      else if (arg === '--domain') domain = value(args, ++i, arg);
      else if (arg === '--toml') toml = value(args, ++i, arg);
      else if (arg === '--format') fmt = format(value(args, ++i, arg), ['text', 'json']);
      else if (arg === '--require') (required ??= []).push(value(args, ++i, arg));
      else if (arg === '--no-required-metrics') required = [];
      else throw new UsageError(`Unknown option ${arg} for verify-metrics`);
    }
    if (urls.length === 0 && domain === undefined && toml === undefined) {
      throw new UsageError('verify-metrics needs --url, --domain or --toml');
    }
  } catch (error) {
    return fail(io, error, METRICS_USAGE);
  }

  try {
    if (urls.length === 0) {
      const doc = await loadToml(
        { ...(domain !== undefined ? { domain } : {}), ...(toml !== undefined ? { toml } : {}) },
        io,
      );
      urls.push(...discoverMetricsEndpoints(doc));
      if (urls.length === 0) {
        io.stderr(
          'stellar.toml advertises no metrics endpoint (e.g. METRICS_URL); pass --url instead.\n',
        );
        return 2;
      }
    }
    const validator = new PrometheusMetricsValidator({
      ...(io.fetchImpl !== undefined ? { fetchImpl: io.fetchImpl } : {}),
      ...(required !== undefined ? { requiredMetrics: required } : {}),
    });
    const reports: MetricsReport[] = [];
    for (const url of urls) reports.push(await validator.validateUrl(url));
    if (fmt === 'json')
      io.stdout(`${JSON.stringify(reports.length === 1 ? reports[0] : reports, null, 2)}\n`);
    else io.stdout(reports.map(renderMetricsReport).join('\n'));
    return reports.every((r) => r.ok) ? 0 : 1;
  } catch (error) {
    return fail(io, error, METRICS_USAGE);
  }
}

const SLA_USAGE =
  'Usage: stellar-toml-lint probe-sla (--domain <domain> | --toml <path>) [--samples <n>] [--threshold-ms <ms>] [--interval-ms <ms>] [--timeout-ms <ms>] [--format text|json]';

export async function probeSlaCommand(
  args: readonly string[],
  io: CommandIo = processIo,
): Promise<number> {
  let domain: string | undefined;
  let toml: string | undefined;
  let samples = 10;
  let thresholdMs = DEFAULT_TTFB_SLA_MS;
  let intervalMs = 0;
  let timeoutMs = 10_000;
  let fmt = 'text';
  try {
    for (let i = 0; i < args.length; i++) {
      const arg = args[i] as string;
      if (arg === '--domain') domain = value(args, ++i, arg);
      else if (arg === '--toml') toml = value(args, ++i, arg);
      else if (arg === '--samples') samples = positiveInt(value(args, ++i, arg), arg);
      else if (arg === '--threshold-ms') thresholdMs = nonNegative(value(args, ++i, arg), arg);
      else if (arg === '--interval-ms') intervalMs = nonNegative(value(args, ++i, arg), arg);
      else if (arg === '--timeout-ms') timeoutMs = positiveInt(value(args, ++i, arg), arg);
      else if (arg === '--format') fmt = format(value(args, ++i, arg), ['text', 'json']);
      else throw new UsageError(`Unknown option ${arg} for probe-sla`);
    }
    if (domain === undefined && toml === undefined)
      throw new UsageError('probe-sla needs --domain or --toml');
  } catch (error) {
    return fail(io, error, SLA_USAGE);
  }

  try {
    const doc = await loadToml(
      { ...(domain !== undefined ? { domain } : {}), ...(toml !== undefined ? { toml } : {}) },
      io,
    );
    const prober = new AnchorSlaLatencyProber({
      samples,
      thresholdMs,
      intervalMs,
      timeoutMs,
      ...(io.probe !== undefined ? { probe: io.probe } : {}),
    });
    const report = await prober.probeToml(doc);
    io.stdout(fmt === 'json' ? `${JSON.stringify(report, null, 2)}\n` : renderSlaReport(report));
    return report.ok ? 0 : 1;
  } catch (error) {
    return fail(io, error, SLA_USAGE);
  }
}

const TAXONOMY_USAGE =
  'Usage: stellar-toml-lint --audit-error-taxonomy (--domain <domain> | <stellar.toml>) [--format text|json]';

export async function auditErrorTaxonomyCommand(
  args: readonly string[],
  io: CommandIo = processIo,
): Promise<number> {
  let domain: string | undefined;
  let toml: string | undefined;
  let fmt = 'text';
  try {
    for (let i = 0; i < args.length; i++) {
      const arg = args[i] as string;
      if (arg === '--audit-error-taxonomy') continue;
      if (arg === '--domain' || arg === '-d') domain = value(args, ++i, arg);
      else if (arg === '--toml') toml = value(args, ++i, arg);
      else if (arg === '--format' || arg === '-f')
        fmt = format(value(args, ++i, arg), ['text', 'json']);
      else if (!arg.startsWith('-') && toml === undefined) toml = arg;
      else throw new UsageError(`Unknown option ${arg} for --audit-error-taxonomy`);
    }
    if (domain === undefined && toml === undefined) {
      throw new UsageError('--audit-error-taxonomy needs --domain or a stellar.toml path');
    }
  } catch (error) {
    return fail(io, error, TAXONOMY_USAGE);
  }

  try {
    const doc = await loadToml(
      { ...(domain !== undefined ? { domain } : {}), ...(toml !== undefined ? { toml } : {}) },
      io,
    );
    const validator = new Rfc7807ErrorValidator(
      io.fetchImpl !== undefined ? { fetchImpl: io.fetchImpl } : {},
    );
    const report = await validator.audit(doc);
    io.stdout(
      fmt === 'json' ? `${JSON.stringify(report, null, 2)}\n` : renderErrorTaxonomyReport(report),
    );
    return report.ok ? 0 : 1;
  } catch (error) {
    return fail(io, error, TAXONOMY_USAGE);
  }
}

const UPTIME_USAGE =
  'Usage: stellar-toml-lint calculate-uptime --log-file <path> [--format text|markdown|json] [--now <iso>] [--interval-ms <ms>] [--decimals <n>] [--min-availability <pct>] [--badge-svg <path>] [--badge-json <path>]';

export async function calculateUptimeCommand(
  args: readonly string[],
  io: CommandIo = processIo,
): Promise<number> {
  let logFile: string | undefined;
  let fmt = 'text';
  let now: number | undefined;
  let intervalMs: number | undefined;
  let decimals = 3;
  let minAvailability: number | undefined;
  let badgeSvg: string | undefined;
  let badgeJson: string | undefined;
  try {
    for (let i = 0; i < args.length; i++) {
      const arg = args[i] as string;
      if (arg === '--log-file') logFile = value(args, ++i, arg);
      else if (arg === '--format')
        fmt = format(value(args, ++i, arg), ['text', 'markdown', 'json']);
      else if (arg === '--now') {
        const raw = value(args, ++i, arg);
        const parsed = Date.parse(raw);
        if (Number.isNaN(parsed)) throw new UsageError('--now must be an ISO-8601 timestamp');
        now = parsed;
      } else if (arg === '--interval-ms') intervalMs = nonNegative(value(args, ++i, arg), arg);
      else if (arg === '--decimals') {
        decimals = nonNegative(value(args, ++i, arg), arg);
        if (!Number.isInteger(decimals) || decimals > 6)
          throw new UsageError('--decimals must be an integer 0–6');
      } else if (arg === '--min-availability')
        minAvailability = nonNegative(value(args, ++i, arg), arg);
      else if (arg === '--badge-svg') badgeSvg = value(args, ++i, arg);
      else if (arg === '--badge-json') badgeJson = value(args, ++i, arg);
      else throw new UsageError(`Unknown option ${arg} for calculate-uptime`);
    }
    if (logFile === undefined) throw new UsageError('calculate-uptime needs --log-file');
  } catch (error) {
    return fail(io, error, UPTIME_USAGE);
  }

  try {
    const read = io.readFile ?? ((p: string) => fsReadFile(p, 'utf8'));
    const write = io.writeFile ?? ((p: string, d: string) => fsWriteFile(p, d, 'utf8'));
    const text = await read(logFile);
    const calculator = new UptimeAvailabilityCalculator({
      decimals,
      ...(now !== undefined ? { now } : {}),
      ...(intervalMs !== undefined ? { intervalMs } : {}),
    });
    const report = calculator.calculateFromText(text, basename(logFile));
    if (report.services.length === 0) {
      io.stderr(`No usable health-check records in ${logFile}\n`);
      return 2;
    }
    if (report.skipped.length > 0) {
      io.stderr(
        `Skipped ${report.skipped.length} unreadable row(s): ${report.skipped.slice(0, 10).join(', ')}\n`,
      );
    }
    if (fmt === 'json') io.stdout(`${JSON.stringify(report, null, 2)}\n`);
    else if (fmt === 'markdown') io.stdout(renderUptimeMarkdown(report));
    else io.stdout(renderUptimeText(report));

    // Badges summarize the 30-day window (the last configured window) across all services.
    const headline = Math.min(
      ...report.services.map(
        (s) => s.windows[s.windows.length - 1]?.availability ?? Number.POSITIVE_INFINITY,
      ),
    );
    const badgeValue = Number.isFinite(headline) ? headline : undefined;
    if (badgeSvg !== undefined) await write(badgeSvg, uptimeBadgeSvg('uptime 30d', badgeValue));
    if (badgeJson !== undefined) await write(badgeJson, uptimeBadgeJson('uptime 30d', badgeValue));

    if (
      minAvailability !== undefined &&
      (badgeValue === undefined || badgeValue < minAvailability)
    ) {
      io.stderr(
        `30-day availability ${badgeValue ?? 'n/a'}% is below the required ${minAvailability}%\n`,
      );
      return 1;
    }
    return 0;
  } catch (error) {
    return fail(io, error, UPTIME_USAGE);
  }
}

const RATE_HEADERS_USAGE = `Usage: stellar-toml-lint verify-rate-headers --url <url> [--burst <n>] [--format text|json]`;

export async function verifyRateHeadersCommand(
  args: readonly string[],
  io: CommandIo = processIo,
): Promise<number> {
  let url: string | undefined;
  let burst = 3;
  let fmt: 'text' | 'json' = 'text';

  try {
    for (let i = 0; i < args.length; i++) {
      const arg = args[i]!;
      if (arg === '--url') url = value(args, ++i, arg);
      else if (arg === '--burst') burst = positiveInt(value(args, ++i, arg), arg);
      else if (arg === '--format')
        fmt = format(value(args, ++i, arg), ['text', 'json']) as 'text' | 'json';
      else throw new UsageError(`Unknown option ${arg} for verify-rate-headers`);
    }
    if (url === undefined) throw new UsageError('verify-rate-headers needs --url');
  } catch (error) {
    return fail(io, error, RATE_HEADERS_USAGE);
  }

  try {
    const { RateLimitHeaderVerifier } = await import('./rateLimitHeaderVerifier.js');
    const verifier = new RateLimitHeaderVerifier();
    const result = await verifier.verifyEndpoint(url, {
      burstCount: burst,
      fetchImpl: io.fetchImpl,
    });

    io.stdout(verifier.renderReport(result, fmt) + '\n');
    return result.ok ? 0 : 1;
  } catch (error) {
    return fail(io, error, RATE_HEADERS_USAGE);
  }
}

const TLS_AUDIT_USAGE = `Usage: stellar-toml-lint audit-tls --domain <domain> [--format text|json]`;

export async function auditTlsCommand(
  args: readonly string[],
  io: CommandIo = processIo,
): Promise<number> {
  let domain: string | undefined;
  let fmt: 'text' | 'json' = 'text';

  try {
    for (let i = 0; i < args.length; i++) {
      const arg = args[i]!;
      if (arg === '--domain') domain = value(args, ++i, arg);
      else if (arg === '--format')
        fmt = format(value(args, ++i, arg), ['text', 'json']) as 'text' | 'json';
      else throw new UsageError(`Unknown option ${arg} for audit-tls`);
    }
    if (domain === undefined) throw new UsageError('audit-tls needs --domain');
  } catch (error) {
    return fail(io, error, TLS_AUDIT_USAGE);
  }

  try {
    const { TlsCertificateWatchdog } = await import('./tlsWatchdog.js');
    const watchdog = new TlsCertificateWatchdog();
    const result = await watchdog.auditDomain(domain);

    io.stdout(watchdog.renderReport(result, fmt) + '\n');
    return result.valid ? 0 : 1;
  } catch (error) {
    return fail(io, error, TLS_AUDIT_USAGE);
  }
}
