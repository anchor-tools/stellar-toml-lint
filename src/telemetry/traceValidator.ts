/**
 * External W3C Trace Context probes for anchor service endpoints.
 *
 * This observes response correlation only. A valid response trace identifier
 * is evidence that the HTTP response exposed tracing metadata; it cannot prove
 * that an anchor propagated context to any invisible downstream service.
 */

import { randomBytes } from 'node:crypto';
import type { LookupAddress } from 'node:dns';
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { request as httpsRequest } from 'node:https';
import type { IncomingMessage } from 'node:http';
import type { Diagnostic, RuleOverrides } from '../types.js';
import { severityFor } from '../protocols/verifierSupport.js';
import { telemetryRules } from './rules.js';

const SEP_SPECS: Record<TraceSep, string> = {
  'SEP-6': 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0006.md',
  'SEP-24': 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0024.md',
  'SEP-31': 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0031.md',
  'SEP-38': 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0038.md',
};
const DEFAULT_TIMEOUT_MS = 5_000;
const MAX_RESULTS = 16;

export type TraceSep = 'SEP-6' | 'SEP-24' | 'SEP-31' | 'SEP-38';
export type TraceAuditStatus = 'compliant' | 'non-compliant' | 'unobservable' | 'unreachable';
export type TraceEvidence = 'traceresponse' | 'server-timing' | 'both';

export interface TraceContext {
  version: '00';
  traceId: string;
  parentId: string;
  traceFlags: string;
  traceparent: string;
}

export interface ParsedTraceparent {
  version: '00';
  traceId: string;
  parentId: string;
  traceFlags: string;
}

export interface TraceEndpointResult {
  sep: TraceSep;
  field: string;
  /** URL origin only; credentials, query values and paths are never reported. */
  endpoint: string;
  status: TraceAuditStatus;
  requestTraceparent: string;
  httpStatus?: number;
  evidence?: TraceEvidence;
  responseTraceId?: string;
  detail: string;
}

export interface TraceAuditResult {
  results: TraceEndpointResult[];
  diagnostics: Diagnostic[];
}

export interface TraceValidatorOptions {
  /** Explicit transport injection is intended for fixtures and controlled callers. */
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  randomBytes?: (size: number) => Uint8Array;
}

export interface TraceEndpointDefinition {
  sep: TraceSep;
  field: string;
}

export interface DiscoveredTraceEndpoint {
  definitions: TraceEndpointDefinition[];
  url: URL;
}

interface ProbeResponse {
  status: number;
  headers: Headers;
}

type Correlation =
  | { kind: 'missing' }
  | { kind: 'invalid'; reason: string }
  | { kind: 'inconsistent'; reason: string }
  | { kind: 'valid'; traceId: string; evidence: TraceEvidence };

const ENDPOINTS: readonly TraceEndpointDefinition[] = [
  { sep: 'SEP-6', field: 'TRANSFER_SERVER' },
  { sep: 'SEP-24', field: 'TRANSFER_SERVER_SEP0024' },
  { sep: 'SEP-31', field: 'DIRECT_PAYMENT_SERVER' },
  { sep: 'SEP-38', field: 'ANCHOR_QUOTE_SERVER' },
];

/** Creates a version-00 traceparent using independently generated non-zero IDs. */
export function generateTraceContext(
  random: (size: number) => Uint8Array = randomBytes,
): TraceContext {
  const traceId = randomIdentifier(16, random);
  const parentId = randomIdentifier(8, random);
  // Sampled + random-trace-id bits, as defined by Trace Context Level 2.
  const traceFlags = '03';
  return {
    version: '00',
    traceId,
    parentId,
    traceFlags,
    traceparent: `00-${traceId}-${parentId}-${traceFlags}`,
  };
}

function randomIdentifier(bytes: number, random: (size: number) => Uint8Array): string {
  for (let attempt = 0; attempt < 8; attempt++) {
    const value = Buffer.from(random(bytes)).toString('hex');
    if (value.length === bytes * 2 && !/^0+$/.test(value)) return value;
  }
  throw new Error('Unable to generate a non-zero trace identifier');
}

/** Parses only the supported W3C version-00 format. */
export function parseTraceparent(value: string): ParsedTraceparent | undefined {
  const match = /^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/.exec(value);
  if (match === null) return undefined;
  const [, traceId, parentId, traceFlags] = match;
  if (traceId === undefined || parentId === undefined || traceFlags === undefined) return undefined;
  if (/^0+$/.test(traceId) || /^0+$/.test(parentId)) return undefined;
  // Version 00 requires unknown flag bits to be ignored. The byte must be
  // syntactically valid, but future/reserved bits do not invalidate context.
  return { version: '00', traceId, parentId, traceFlags };
}

/** Discovers and deduplicates the four SEP service URLs from parsed stellar.toml. */
export function discoverTraceEndpoints(doc: Record<string, unknown>): {
  endpoints: DiscoveredTraceEndpoint[];
  invalid: TraceEndpointDefinition[];
} {
  const endpoints: DiscoveredTraceEndpoint[] = [];
  const invalid: TraceEndpointDefinition[] = [];
  const byUrl = new Map<string, DiscoveredTraceEndpoint>();
  for (const definition of ENDPOINTS) {
    const value = doc[definition.field];
    if (value === undefined || value === '') continue;
    if (typeof value !== 'string') {
      invalid.push(definition);
      continue;
    }
    const url = serviceInfoUrl(value);
    if (url === undefined) {
      invalid.push(definition);
      continue;
    }
    const key = `${url.origin}${url.pathname}`;
    const existing = byUrl.get(key);
    if (existing !== undefined) {
      existing.definitions.push(definition);
    } else {
      const discovered = { definitions: [definition], url };
      byUrl.set(key, discovered);
      endpoints.push(discovered);
    }
  }
  return { endpoints, invalid };
}

function serviceInfoUrl(value: string): URL | undefined {
  try {
    const base = new URL(value);
    if (
      base.protocol !== 'https:' ||
      base.username !== '' ||
      base.password !== '' ||
      base.search !== '' ||
      base.hash !== '' ||
      !isSafeHostname(base.hostname)
    ) {
      return undefined;
    }
    const path = base.pathname.replace(/\/+$/, '');
    base.pathname = path.endsWith('/info') ? path : `${path}/info`;
    return base;
  } catch {
    return undefined;
  }
}

function isSafeHostname(raw: string): boolean {
  const host = raw
    .replace(/^\[|\]$/g, '')
    .replace(/\.$/, '')
    .toLowerCase();
  if (
    host === '' ||
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host.endsWith('.local') ||
    host.endsWith('.internal') ||
    host.endsWith('.home.arpa')
  ) {
    return false;
  }
  const family = isIP(host);
  return family === 0 || isPublicAddress(host);
}

function ipv4Number(address: string): number | undefined {
  const parts = address.split('.').map(Number);
  if (
    parts.length !== 4 ||
    parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)
  ) {
    return undefined;
  }
  return (
    (((parts[0] ?? 0) << 24) |
      ((parts[1] ?? 0) << 16) |
      ((parts[2] ?? 0) << 8) |
      (parts[3] ?? 0)) >>>
    0
  );
}

function inV4Range(address: string, network: string, prefix: number): boolean {
  const value = ipv4Number(address);
  const base = ipv4Number(network);
  if (value === undefined || base === undefined) return false;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (value & mask) === (base & mask);
}

/** Blocks special-use addresses before requests and validates DNS answers before pinning them. */
function isPublicAddress(address: string): boolean {
  if (isIP(address) === 4) {
    const blocked = [
      ['0.0.0.0', 8],
      ['10.0.0.0', 8],
      ['100.64.0.0', 10],
      ['127.0.0.0', 8],
      ['169.254.0.0', 16],
      ['172.16.0.0', 12],
      ['192.0.0.0', 24],
      ['192.0.2.0', 24],
      ['192.88.99.0', 24],
      ['192.168.0.0', 16],
      ['198.18.0.0', 15],
      ['198.51.100.0', 24],
      ['203.0.113.0', 24],
      ['224.0.0.0', 4],
      ['240.0.0.0', 4],
    ] as const;
    return !blocked.some(([network, prefix]) => inV4Range(address, network, prefix));
  }
  if (isIP(address) === 6) {
    const groups = address.toLowerCase().split(':');
    const first = Number.parseInt(groups[0] || '0', 16);
    const second = Number.parseInt(groups[1] || '0', 16);
    if (first < 0x2000 || first > 0x3fff) return false;
    if (first === 0x2001 && (second < 0x0400 || second === 0x0db8)) return false;
    if (first === 0x2002) return false;
    if (first === 0x3fff && second < 0x1000) return false;
    return true;
  }
  return false;
}

function splitOutsideQuotes(value: string, separator: string): string[] | undefined {
  const parts: string[] = [];
  let start = 0;
  let quoted = false;
  let escaped = false;
  for (let i = 0; i < value.length; i++) {
    const char = value[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (quoted && char === '\\') {
      escaped = true;
      continue;
    }
    if (char === '"') quoted = !quoted;
    else if (!quoted && char === separator) {
      parts.push(value.slice(start, i).trim());
      start = i + 1;
    }
  }
  if (quoted || escaped) return undefined;
  parts.push(value.slice(start).trim());
  return parts;
}

function parseServerTiming(value: string): { values: string[]; malformed: boolean } {
  const metrics = splitOutsideQuotes(value, ',');
  if (metrics === undefined) {
    return { values: [], malformed: /(?:^|,)\s*trace(?:\s*[;,]|\s*$)/i.test(value) };
  }
  const values: string[] = [];
  let malformed = false;
  for (const metric of metrics) {
    const parts = splitOutsideQuotes(metric, ';');
    if (parts === undefined || parts[0]?.trim().toLowerCase() !== 'trace') continue;
    const desc = parts.slice(1).find((part) => /^\s*desc\s*=/i.test(part));
    if (desc === undefined) {
      malformed = true;
      continue;
    }
    const match = /^\s*desc\s*=\s*(?:"((?:\\.|[^"\\])*)"|([^;,\s]+))\s*$/i.exec(desc);
    const raw = match?.[1] ?? match?.[2];
    if (raw === undefined) {
      malformed = true;
      continue;
    }
    const decoded = raw.replace(/\\(.)/g, '$1');
    if (parseTraceparent(decoded) === undefined) malformed = true;
    else values.push(decoded);
  }
  return { values, malformed };
}

function correlationFrom(headers: Headers): Correlation {
  const traceResponses = headers.get('traceresponse');
  const serverTiming = headers.get('server-timing');
  const traceValues: { value: string; source: 'traceresponse' | 'server-timing' }[] = [];
  let malformed = false;

  if (traceResponses !== null) {
    // Headers.get() joins duplicate values with a comma; this format has no list syntax.
    const parsed = parseTraceparent(traceResponses.trim());
    if (parsed === undefined) malformed = true;
    else traceValues.push({ value: traceResponses.trim(), source: 'traceresponse' });
  }
  if (serverTiming !== null) {
    const parsed = parseServerTiming(serverTiming);
    malformed ||= parsed.malformed;
    for (const value of parsed.values) traceValues.push({ value, source: 'server-timing' });
  }
  if (malformed) return { kind: 'invalid', reason: 'Response trace metadata is malformed' };
  if (traceValues.length === 0) return { kind: 'missing' };

  const parsed = traceValues.map(({ value }) => parseTraceparent(value));
  if (parsed.some((entry) => entry === undefined)) {
    return { kind: 'invalid', reason: 'Response trace metadata is malformed' };
  }
  const responseContexts = new Set(
    parsed.map((entry) => `${entry?.traceId ?? ''}:${entry?.parentId ?? ''}`),
  );
  if (responseContexts.size > 1) {
    return {
      kind: 'inconsistent',
      reason: 'Response trace metadata reports conflicting trace or span IDs',
    };
  }
  const sources = new Set(traceValues.map(({ source }) => source));
  const evidence: TraceEvidence =
    sources.size > 1 ? 'both' : (traceValues[0]?.source ?? 'traceresponse');
  return { kind: 'valid', traceId: parsed[0]?.traceId ?? '', evidence };
}

function displayEndpoint(url: URL | undefined): string {
  return url === undefined ? '(unsafe or malformed URL)' : url.origin;
}

function timeoutError(): Error {
  const error = new Error('The endpoint request timed out');
  error.name = 'TimeoutError';
  return error;
}

async function lookupPublic(hostname: string, timeoutMs: number): Promise<LookupAddress[]> {
  const signal = AbortSignal.timeout(timeoutMs);
  const promise = lookup(hostname, { all: true, verbatim: true }) as Promise<LookupAddress[]>;
  const addresses = await Promise.race([
    promise,
    new Promise<never>((_, reject) => {
      signal.addEventListener('abort', () => reject(timeoutError()), { once: true });
    }),
  ]);
  if (addresses.length === 0 || addresses.some(({ address }) => !isPublicAddress(address))) {
    throw new Error('Endpoint host resolves to a non-public address');
  }
  return addresses;
}

/** Default pinned HTTPS transport: no redirects and no response body is consumed. */
async function requestPublicHttps(
  url: URL,
  traceparent: string,
  timeoutMs: number,
): Promise<ProbeResponse> {
  const hostname = url.hostname.replace(/^\[|\]$/g, '');
  const family = isIP(hostname);
  const addresses =
    family === 0 ? await lookupPublic(hostname, timeoutMs) : [{ address: hostname, family }];
  const first = addresses[0];
  if (first === undefined) throw new Error('Endpoint host did not resolve');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await new Promise<ProbeResponse>((resolve, reject) => {
      let settled = false;
      const done = (error?: Error, result?: ProbeResponse): void => {
        if (settled) return;
        settled = true;
        if (error !== undefined) reject(error);
        else if (result !== undefined) resolve(result);
        else reject(new Error('The endpoint returned no HTTP response'));
      };
      const request = httpsRequest(
        url,
        {
          method: 'GET',
          signal: controller.signal,
          headers: {
            accept: '*/*',
            'accept-encoding': 'identity',
            traceparent,
            'user-agent': 'stellar-toml-lint/0.1.0',
          },
          lookup: (_host, options, callback) => {
            if (options.all) callback(null, addresses);
            else callback(null, first.address, first.family);
          },
        },
        (response: IncomingMessage) => {
          const headers = new Headers();
          for (const [name, value] of Object.entries(response.headers)) {
            if (Array.isArray(value)) for (const item of value) headers.append(name, item);
            else if (value !== undefined) headers.set(name, String(value));
          }
          done(undefined, { status: response.statusCode ?? 0, headers });
          // Only headers are relevant to this audit. Destroy the stream so an
          // unexpectedly large body cannot be consumed or buffered.
          response.destroy();
        },
      );
      request.on('error', () => {
        done(controller.signal.aborted ? timeoutError() : new Error('The endpoint request failed'));
      });
      request.end();
    });
  } finally {
    clearTimeout(timer);
  }
}

async function injectedFetch(
  fetchImpl: typeof fetch,
  url: URL,
  headers: Record<string, string>,
  timeoutMs: number,
): Promise<ProbeResponse> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const response = await Promise.race([
      fetchImpl(url.toString(), {
        method: 'GET',
        headers,
        redirect: 'manual',
        credentials: 'omit',
        signal: controller.signal,
      }),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          reject(timeoutError());
        }, timeoutMs);
      }),
    ]);
    const result = { status: response.status, headers: response.headers };
    if (response.body !== null) void response.body.cancel().catch(() => {});
    return result;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function finding(
  rule: string,
  fallback: 'error' | 'warning' | 'info',
  result: TraceEndpointResult,
  rules?: RuleOverrides,
): Diagnostic[] {
  const severity = severityFor(rule, fallback, rules);
  if (severity === undefined) return [];
  return [
    {
      rule,
      severity,
      category: 'network',
      message: `${result.sep} ${result.field} (${result.endpoint}): ${result.detail}`,
      path: result.field,
      helpUri: SEP_SPECS[result.sep],
      suggestion:
        result.status === 'non-compliant'
          ? 'Emit well-formed, consistent trace correlation metadata when the service exposes tracing information; external checks cannot require an echo.'
          : 'Review endpoint reachability and instrumentation; this external probe cannot establish invisible downstream propagation.',
    },
  ];
}

export class OpenTelemetryTraceValidator {
  private readonly timeoutMs: number;

  constructor(private readonly options: TraceValidatorOptions = {}) {
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  async verify(doc: Record<string, unknown>, rules?: RuleOverrides): Promise<TraceAuditResult> {
    const { endpoints, invalid } = discoverTraceEndpoints(doc);
    const results: TraceEndpointResult[] = [];
    const diagnostics: Diagnostic[] = [];

    for (const definition of invalid) {
      const result: TraceEndpointResult = {
        ...definition,
        endpoint: '(unsafe or malformed URL)',
        status: 'unreachable',
        requestTraceparent: generateTraceContext(this.options.randomBytes).traceparent,
        detail:
          'The configured endpoint is not a safe absolute HTTPS service URL; no request was sent',
      };
      results.push(result);
      diagnostics.push(...finding('telemetry/unreachable-endpoint', 'warning', result, rules));
    }

    if (endpoints.length === 0 && invalid.length === 0) {
      const severity = severityFor('telemetry/no-endpoints', 'info', rules);
      if (severity !== undefined) {
        diagnostics.push({
          rule: 'telemetry/no-endpoints',
          severity,
          category: 'network',
          message: 'No SEP-6, SEP-24, SEP-31 or SEP-38 service endpoint is declared',
          helpUri: 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0001.md',
          suggestion:
            'Declare the relevant SEP service URL in stellar.toml to include it in this audit.',
        });
      }
    }

    for (const endpoint of endpoints.slice(0, MAX_RESULTS)) {
      const context = generateTraceContext(this.options.randomBytes);
      let response: ProbeResponse;
      try {
        response =
          this.options.fetchImpl === undefined
            ? await requestPublicHttps(endpoint.url, context.traceparent, this.timeoutMs)
            : await injectedFetch(
                this.options.fetchImpl,
                endpoint.url,
                { traceparent: context.traceparent },
                this.timeoutMs,
              );
      } catch (error) {
        const timedOut = error instanceof Error && error.name === 'TimeoutError';
        for (const definition of endpoint.definitions) {
          const result: TraceEndpointResult = {
            ...definition,
            endpoint: displayEndpoint(endpoint.url),
            status: 'unreachable',
            requestTraceparent: context.traceparent,
            detail: timedOut
              ? 'The endpoint request timed out'
              : 'The endpoint could not be safely reached',
          };
          results.push(result);
          diagnostics.push(...finding('telemetry/unreachable-endpoint', 'warning', result, rules));
        }
        continue;
      }

      if (response.status >= 300 && response.status < 400) {
        for (const definition of endpoint.definitions) {
          const result: TraceEndpointResult = {
            ...definition,
            endpoint: displayEndpoint(endpoint.url),
            status: 'unreachable',
            requestTraceparent: context.traceparent,
            httpStatus: response.status,
            detail: `The endpoint returned HTTP ${response.status}; redirects are not followed`,
          };
          results.push(result);
          diagnostics.push(...finding('telemetry/unreachable-endpoint', 'warning', result, rules));
        }
        continue;
      }

      const correlation = correlationFrom(response.headers);
      for (const definition of endpoint.definitions) {
        const base = {
          ...definition,
          endpoint: displayEndpoint(endpoint.url),
          requestTraceparent: context.traceparent,
          httpStatus: response.status,
        };
        let result: TraceEndpointResult;
        if (correlation.kind === 'missing') {
          result = {
            ...base,
            status: 'unobservable',
            detail: `HTTP ${response.status} exposed no response trace correlation evidence; propagation cannot be determined externally`,
          };
          diagnostics.push(...finding('telemetry/correlation-unobservable', 'info', result, rules));
        } else if (correlation.kind === 'invalid' || correlation.kind === 'inconsistent') {
          result = {
            ...base,
            status: 'non-compliant',
            detail: correlation.reason,
          };
          diagnostics.push(...finding('telemetry/invalid-correlation', 'error', result, rules));
        } else if (correlation.traceId !== context.traceId) {
          result = {
            ...base,
            status: 'compliant',
            evidence: correlation.evidence,
            responseTraceId: correlation.traceId,
            detail: `Valid response trace metadata was observed with a different trace ID; this may be a legitimate trace restart (HTTP ${response.status})`,
          };
          diagnostics.push(...finding('telemetry/trace-restarted', 'info', result, rules));
        } else {
          result = {
            ...base,
            status: 'compliant',
            evidence: correlation.evidence,
            responseTraceId: correlation.traceId,
            detail: `Valid response trace metadata correlates with the request (HTTP ${response.status})`,
          };
          diagnostics.push(...finding('telemetry/correlation-observed', 'info', result, rules));
        }
        results.push(result);
      }
    }

    return { results, diagnostics };
  }
}

export function renderTraceAuditReport(result: TraceAuditResult): string {
  const lines = ['OpenTelemetry trace context audit'];
  if (result.results.length === 0) {
    lines.push('  No eligible service endpoints were probed.');
  }
  for (const endpoint of result.results) {
    const http = endpoint.httpStatus === undefined ? '' : ` HTTP ${endpoint.httpStatus}`;
    lines.push(
      `  ${endpoint.status.toUpperCase()} ${endpoint.sep} ${endpoint.field} ${endpoint.endpoint}${http}`,
    );
    lines.push(`    ${endpoint.detail}`);
  }
  lines.push(
    '  Response metadata is correlation evidence only; this audit cannot prove downstream propagation.',
  );
  return `${lines.join('\n')}\n`;
}

export { telemetryRules };
