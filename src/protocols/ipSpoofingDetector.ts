/**
 * IP spoofing and rate-limit bypass detector.
 *
 * Runs under opt-in `--audit-ip-spoofing`; requests are only sent with
 * `--check-network`.
 *
 * A backend that trusts client-supplied `X-Forwarded-For`, `X-Real-IP`,
 * `True-Client-IP` or `CF-Connecting-IP` without checking that the request came
 * from its own proxy lets anyone pick their "client IP", which defeats per-IP
 * rate limits and IP allowlists on SEP-10/SEP-24 endpoints.
 *
 * The probe is deliberately small and non-intrusive: per endpoint, two plain
 * GETs and one GET carrying spoofed headers, all with distinct documentation
 * addresses (RFC 5737), and nothing else. A spoofed address appearing in the
 * response, or a rate-limit counter that resets when the headers change, is
 * evidence the backend keys on the header.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isHttpsUrl, isString } from '../predicates.js';
import { errorMessage, fetchWithTimeout, severityFor } from './verifierSupport.js';

const REFLECTED_RULE = 'ipspoof/header-reflected';
const BYPASS_RULE = 'ipspoof/rate-limit-bypass';
const CHAIN_RULE = 'ipspoof/forwarded-chain-not-stripped';
const HOPS_RULE = 'ipspoof/excess-proxy-hops';
const UNREACHABLE_RULE = 'ipspoof/endpoint-unreachable';

const SPEC = 'https://www.rfc-editor.org/rfc/rfc7239#section-8';

/** Spoofed header -> the documentation address it carries, unique per header. */
export const SPOOF_HEADERS: Readonly<Record<string, string>> = {
  'X-Forwarded-For': '198.51.100.23',
  'X-Real-IP': '198.51.100.47',
  'True-Client-IP': '203.0.113.61',
  'CF-Connecting-IP': '203.0.113.89',
};

/** Prepended to X-Forwarded-For; a server that echoes it never trimmed the chain. */
const CHAIN_MARKER = '192.0.2.17';

/** `stellar.toml` endpoints worth probing, with a cheap unauthenticated GET path. */
const ENDPOINTS: readonly (readonly [string, string])[] = [
  ['WEB_AUTH_ENDPOINT', ''],
  ['TRANSFER_SERVER', '/info'],
  ['TRANSFER_SERVER_SEP0024', '/info'],
  ['DIRECT_PAYMENT_SERVER', '/info'],
  ['ANCHOR_QUOTE_SERVER', '/info'],
  ['KYC_SERVER', '/customer'],
];

const MITIGATION =
  'Only trust forwarded headers from your own proxies: in Nginx use "set_real_ip_from <proxy CIDR>; real_ip_header X-Forwarded-For; real_ip_recursive on;" and "proxy_set_header X-Forwarded-For $remote_addr;"; behind Cloudflare accept CF-Connecting-IP only from Cloudflare ranges and strip client-sent True-Client-IP/X-Real-IP with a Transform Rule.';

export interface IpSpoofingOptions {
  rules?: RuleOverrides;
  /** Actually send requests. */
  probe?: boolean;
  timeoutMs?: number;
  /** A `Via` chain longer than this is reported. Defaults to 3. */
  maxProxyHops?: number;
}

export interface EndpointFinding {
  field: string;
  url: string;
  reflectedHeaders: string[];
  rateLimitBypass: boolean;
  proxyHops: number;
}

export interface IpSpoofingResult {
  diagnostics: Diagnostic[];
  endpoints: EndpointFinding[];
}

interface Sample {
  status: number;
  text: string;
  headers: Headers;
}

/** `X-RateLimit-Remaining`, `RateLimit-Remaining` or the IETF `RateLimit: r=` form. */
export function rateLimitRemaining(headers: Headers): number | undefined {
  const plain = headers.get('x-ratelimit-remaining') ?? headers.get('ratelimit-remaining');
  if (plain !== null && /^\d+$/.test(plain.trim())) return Number(plain.trim());
  const ietf = /(?:^|[;,\s])r=(\d+)/.exec(headers.get('ratelimit') ?? '');
  return ietf ? Number(ietf[1]) : undefined;
}

/** Number of proxies named in a `Via` header. */
export function proxyHopCount(headers: Headers): number {
  const via = headers.get('via');
  return via === null ? 0 : via.split(',').filter((h) => h.trim() !== '').length;
}

/** The spoofed headers whose address shows up in a response body or header. */
export function findReflectedHeaders(sample: { text: string; headers: Headers }): string[] {
  let haystack = sample.text;
  sample.headers.forEach((value) => (haystack += `\n${value}`));
  return Object.entries(SPOOF_HEADERS)
    .filter(([, ip]) => haystack.includes(ip))
    .map(([header]) => header);
}

/**
 * True when the spoofed request was treated as a different client: either it
 * succeeded after we were rate limited, or its remaining-quota counter is
 * higher than our last plain request left it.
 */
export function isRateLimitBypass(plain: Sample, spoofed: Sample): boolean {
  if (plain.status === 429 && spoofed.status !== 429 && spoofed.status < 500) return true;
  const before = rateLimitRemaining(plain.headers);
  const after = rateLimitRemaining(spoofed.headers);
  return before !== undefined && after !== undefined && after > before;
}

export class IpSpoofingVulnerabilityDetector {
  constructor(
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly options: IpSpoofingOptions = {},
  ) {}

  async detect(doc: Record<string, unknown>): Promise<IpSpoofingResult> {
    const diagnostics: Diagnostic[] = [];
    const endpoints: EndpointFinding[] = [];
    if (!this.options.probe) return { diagnostics, endpoints };
    const maxHops = this.options.maxProxyHops ?? 3;

    for (const [field, suffix] of ENDPOINTS) {
      const base = doc[field];
      if (!isString(base) || !isHttpsUrl(base)) continue;
      const url = `${base.replace(/\/+$/, '')}${suffix}`;
      const push = (
        rule: string,
        fallback: 'error' | 'warning' | 'info',
        message: string,
        suggestion: string,
      ): void => {
        const severity = severityFor(rule, fallback, this.options.rules);
        if (severity === undefined) return;
        diagnostics.push({
          rule,
          severity,
          category: 'network',
          message,
          path: field,
          helpUri: SPEC,
          suggestion,
        });
      };

      let plain: Sample;
      let spoofed: Sample;
      try {
        await this.sample(url, {});
        plain = await this.sample(url, {});
        spoofed = await this.sample(url, {
          ...SPOOF_HEADERS,
          'X-Forwarded-For': `${CHAIN_MARKER}, ${SPOOF_HEADERS['X-Forwarded-For']}`,
        });
      } catch (error) {
        push(
          UNREACHABLE_RULE,
          'warning',
          `${url} could not be probed (${errorMessage(error)})`,
          'Make sure the endpoint answers within a few seconds.',
        );
        continue;
      }

      const finding: EndpointFinding = {
        field,
        url,
        reflectedHeaders: findReflectedHeaders(spoofed),
        rateLimitBypass: isRateLimitBypass(plain, spoofed),
        proxyHops: proxyHopCount(spoofed.headers),
      };
      endpoints.push(finding);

      if (finding.reflectedHeaders.length > 0) {
        push(
          REFLECTED_RULE,
          'error',
          `${field} treats client-supplied ${finding.reflectedHeaders.join(', ')} as the client address`,
          MITIGATION,
        );
      }
      if (finding.rateLimitBypass) {
        push(
          BYPASS_RULE,
          'error',
          `${field} rate limiting resets when spoofed client IP headers are sent; limits can be bypassed`,
          MITIGATION,
        );
      }
      const echoedChain = spoofed.text.includes(CHAIN_MARKER);
      if (echoedChain) {
        push(
          CHAIN_RULE,
          'warning',
          `${field} passed a client-supplied X-Forwarded-For chain through unchanged`,
          'Have the edge proxy overwrite X-Forwarded-For with the connecting address instead of appending to it.',
        );
      }
      if (finding.proxyHops > maxHops) {
        push(
          HOPS_RULE,
          'info',
          `${field} answered through ${finding.proxyHops} proxies (Via); each hop must be configured as trusted`,
          `Set the trusted hop count (e.g. Nginx real_ip_recursive with set_real_ip_from per hop) to ${finding.proxyHops}.`,
        );
      }
    }
    return { diagnostics, endpoints };
  }

  private async sample(url: string, headers: Record<string, string>): Promise<Sample> {
    const res = await fetchWithTimeout(
      this.fetchImpl,
      url,
      { method: 'GET', headers },
      this.options.timeoutMs,
    );
    const text = await res.text().catch(() => '');
    return { status: res.status, text, headers: res.headers };
  }
}

export async function auditIpSpoofing(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: IpSpoofingOptions = {},
): Promise<IpSpoofingResult> {
  return new IpSpoofingVulnerabilityDetector(fetchImpl, options).detect(doc);
}

const def = (id: string, severity: 'error' | 'warning' | 'info', description: string): Rule => ({
  id,
  category: 'network',
  severity,
  description,
  run() {},
});

export const ipSpoofingRules: Rule[] = [
  def(REFLECTED_RULE, 'error', 'Endpoints must not trust client-supplied IP headers'),
  def(BYPASS_RULE, 'error', 'Rate limits must not be keyed on client-supplied IP headers'),
  def(CHAIN_RULE, 'warning', 'Edge proxies should overwrite untrusted X-Forwarded-For chains'),
  def(HOPS_RULE, 'info', 'Long proxy chains need every hop configured as trusted'),
  def(UNREACHABLE_RULE, 'warning', 'Probed endpoints should be reachable'),
];

export const ipSpoofingRuleIds: readonly string[] = ipSpoofingRules.map((r) => r.id);
