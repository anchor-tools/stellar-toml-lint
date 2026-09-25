import { performance } from 'node:perf_hooks';
import type { LintResult } from './types.js';
import { makeColors } from './reporters.js';

export interface HealthCheckResult {
  endpointName: string;
  url: string;
  statusCode: number | null;
  latencyMs: number;
  error?: string;
}

const ENDPOINT_KEYS = [
  'WEB_AUTH_ENDPOINT',
  'TRANSFER_SERVER_SEP0024',
  'TRANSFER_SERVER',
  'KYC_SERVER',
  'DIRECT_PAYMENT_SERVER',
  'ANCHOR_QUOTE_SERVER',
  'FEDERATION_SERVER',
];

export async function runHealthCheck(result: LintResult): Promise<HealthCheckResult[]> {
  if (!result.parsed) return [];

  const endpoints: { name: string; url: string }[] = [];

  for (const key of ENDPOINT_KEYS) {
    const value = result.parsed[key];
    if (typeof value === 'string' && value.startsWith('http')) {
      endpoints.push({ name: key, url: value });
    }
  }

  if (endpoints.length === 0) return [];

  const promises = endpoints.map(async (ep) => {
    const start = performance.now();
    let statusCode: number | null = null;
    let error: string | undefined;

    try {
      // Abort controller to timeout hanging connections
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);

      const response = await fetch(ep.url, {
        method: 'HEAD',
        redirect: 'follow',
        headers: { 'User-Agent': 'stellar-toml-lint/0.1.0' },
        signal: controller.signal,
      });
      clearTimeout(timeoutId);

      // Some endpoints might reject HEAD with 405 Method Not Allowed,
      // fallback to GET in that case.
      if (response.status === 405) {
        const fallbackController = new AbortController();
        const fallbackTimeout = setTimeout(() => fallbackController.abort(), 5000);
        const fallback = await fetch(ep.url, {
          method: 'GET',
          redirect: 'follow',
          headers: { 'User-Agent': 'stellar-toml-lint/0.1.0' },
          signal: fallbackController.signal,
        });
        clearTimeout(fallbackTimeout);
        statusCode = fallback.status;
      } else {
        statusCode = response.status;
      }
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }

    const latencyMs = Math.round(performance.now() - start);

    return {
      endpointName: ep.name,
      url: ep.url,
      statusCode,
      latencyMs,
      error,
    };
  });

  return Promise.all(promises);
}

export function formatHealthCheckTable(results: HealthCheckResult[], color: boolean): string {
  if (results.length === 0) return '';

  const c = makeColors(color);

  const nameWidth = Math.max(13, ...results.map((r) => r.endpointName.length));
  const urlWidth = Math.max(10, ...results.map((r) => r.url.length));

  const header = `  ${'Endpoint Name'.padEnd(nameWidth)}  ${'Target URL'.padEnd(urlWidth)}  Status  Latency  Health`;
  const separator = `  ${'-'.repeat(nameWidth)}  ${'-'.repeat(urlWidth)}  ------  -------  ------`;

  const lines = results.map((r) => {
    const statusText = r.statusCode ? String(r.statusCode).padEnd(6) : 'ERR   ';
    const latencyText = `${r.latencyMs}ms`.padEnd(7);

    let badge = '';
    if (r.error || (r.statusCode && r.statusCode >= 400)) {
      badge = c.red('FAIL');
    } else if (r.latencyMs < 200) {
      badge = c.green('GOOD');
    } else if (r.latencyMs <= 1000) {
      badge = c.yellow('FAIR');
    } else {
      badge = c.red('POOR');
    }

    return `  ${r.endpointName.padEnd(nameWidth)}  ${r.url.padEnd(urlWidth)}  ${statusText}  ${latencyText}  ${badge}`;
  });

  return `\nEndpoint Health:\n${header}\n${separator}\n${lines.join('\n')}\n`;
}
