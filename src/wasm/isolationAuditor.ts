/**
 * Cross-Origin Isolation (COOP/COEP) auditor.
 *
 * Multi-threaded WebAssembly needs `SharedArrayBuffer`, which browsers only
 * expose to a document that is cross-origin isolated. Isolation is granted by
 * response headers, not by the page: `Cross-Origin-Opener-Policy: same-origin`
 * severs the opener relationship and `Cross-Origin-Embedder-Policy:
 * require-corp` (or `credentialless`) makes every subresource opt in through
 * `Cross-Origin-Resource-Policy`.
 *
 * `CrossOriginIsolationAuditor` reads those headers from a deployed app and
 * reports what still blocks `SharedArrayBuffer`, including the third-party
 * resources that would be refused. It never executes page JavaScript and only
 * issues GET requests for the document and the resources it references.
 */

export type IsolationFindingCode =
  | 'isolation/missing-coop'
  | 'isolation/invalid-coop'
  | 'isolation/missing-coep'
  | 'isolation/invalid-coep'
  | 'isolation/missing-corp'
  | 'isolation/invalid-corp'
  | 'isolation/unreachable';

export interface IsolationFinding {
  code: IsolationFindingCode;
  severity: 'error' | 'warning';
  message: string;
  /** The header or resource the finding is about. */
  subject: string;
  suggestion: string;
}

export interface ResourceCheck {
  url: string;
  origin: string;
  crossOrigin: boolean;
  status?: number;
  corp?: string;
  ok: boolean;
  error?: string;
}

export interface IsolationReport {
  /** True when the document itself is cross-origin isolated. */
  ok: boolean;
  url: string;
  status?: number;
  headers: Record<string, string>;
  findings: IsolationFinding[];
  resources: ResourceCheck[];
  /** Copy-paste configuration for common web hosts. */
  guides: string[];
}

export interface IsolationAuditorOptions {
  fetchImpl?: typeof fetch;
  /** How many same-document subresources to probe. */
  maxResources?: number;
}

const VALID_CORP = new Set(['same-origin', 'same-site', 'cross-origin']);

function headerValue(headers: Headers, name: string): string | undefined {
  return headers.get(name) ?? undefined;
}

function parseToken(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  // A report-only or otherwise decorated value still names its policy first.
  return value.split(';')[0]?.trim().toLowerCase() || undefined;
}

/** Extracts same-origin `src`/`href` references without a DOM or parser. */
function extractResourceUrls(html: string, base: string): string[] {
  const urls = new Set<string>();
  const pattern = /\b(?:src|href)\s*=\s*["']([^"']+)["']/gi;
  for (const match of html.matchAll(pattern)) {
    const raw = match[1];
    if (raw === undefined || raw.startsWith('data:') || raw.startsWith('blob:')) continue;
    try {
      urls.add(new URL(raw, base).toString());
    } catch {
      // A malformed URL is not a resource this auditor can check.
    }
  }
  return [...urls];
}

export class CrossOriginIsolationAuditor {
  private readonly fetchImpl: typeof fetch;
  private readonly maxResources: number;

  constructor(options: IsolationAuditorOptions = {}) {
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.maxResources = options.maxResources ?? 10;
  }

  /**
   * Evaluates response headers without doing I/O. This is the check a test or
   * a deployment manifest can call directly.
   */
  evaluateHeaders(headers: Record<string, string> | Headers): IsolationFinding[] {
    const get = (name: string): string | undefined =>
      headers instanceof Headers ? (headers.get(name) ?? undefined) : headers[name.toLowerCase()];
    const findings: IsolationFinding[] = [];

    const coop = parseToken(get('cross-origin-opener-policy'));
    if (coop === undefined) {
      findings.push({
        code: 'isolation/missing-coop',
        severity: 'error',
        subject: 'Cross-Origin-Opener-Policy',
        message: 'Cross-Origin-Opener-Policy is not set, so the document cannot be isolated',
        suggestion: 'Send `Cross-Origin-Opener-Policy: same-origin` on the HTML response.',
      });
    } else if (coop !== 'same-origin') {
      findings.push({
        code: 'isolation/invalid-coop',
        severity: 'error',
        subject: 'Cross-Origin-Opener-Policy',
        message: `Cross-Origin-Opener-Policy is "${coop}", but isolation requires "same-origin"`,
        suggestion:
          coop === 'same-origin-allow-popups'
            ? 'Use "same-origin": allow-popups is not a cross-origin isolated state.'
            : 'Send `Cross-Origin-Opener-Policy: same-origin`.',
      });
    }

    const coep = parseToken(get('cross-origin-embedder-policy'));
    if (coep === undefined) {
      findings.push({
        code: 'isolation/missing-coep',
        severity: 'error',
        subject: 'Cross-Origin-Embedder-Policy',
        message: 'Cross-Origin-Embedder-Policy is not set, so SharedArrayBuffer stays disabled',
        suggestion: 'Send `Cross-Origin-Embedder-Policy: require-corp` on the HTML response.',
      });
    } else if (coep !== 'require-corp' && coep !== 'credentialless') {
      findings.push({
        code: 'isolation/invalid-coep',
        severity: 'error',
        subject: 'Cross-Origin-Embedder-Policy',
        message: `Cross-Origin-Embedder-Policy is "${coep}", which does not enable isolation`,
        suggestion: 'Use "require-corp" (or "credentialless" for extensionless embeds).',
      });
    }

    const reportOnly = get('cross-origin-embedder-policy-report-only');
    if (reportOnly !== undefined && coep === undefined) {
      findings.push({
        code: 'isolation/missing-coep',
        severity: 'warning',
        subject: 'Cross-Origin-Embedder-Policy-Report-Only',
        message: 'Only a report-only COEP header is present; report-only never enforces isolation',
        suggestion: get('cross-origin-opener-policy-report-only')
          ? 'Promote both report-only headers to their enforcing forms.'
          : 'Promote the report-only COEP header to `Cross-Origin-Embedder-Policy: require-corp`.',
      });
    }

    return findings;
  }

  /** Checks a probe response's `Cross-Origin-Resource-Policy`. */
  evaluateResource(response: ResourceCheck, coep: string | undefined): IsolationFinding[] {
    if (!response.crossOrigin) return [];
    // `credentialless` lets a cross-origin embed through without CORP as long
    // as the request carries no credentials.
    if (coep === 'credentialless') return [];

    const corp = response.corp === undefined ? undefined : response.corp.toLowerCase();
    if (corp === undefined) {
      return [
        {
          code: 'isolation/missing-corp',
          severity: 'error',
          subject: response.url,
          message: `Cross-origin resource ${response.url} has no Cross-Origin-Resource-Policy header`,
          suggestion:
            'Send `Cross-Origin-Resource-Policy: cross-origin` (or same-site) for this asset, or self-host it.',
        },
      ];
    }
    if (!VALID_CORP.has(corp)) {
      return [
        {
          code: 'isolation/invalid-corp',
          severity: 'error',
          subject: response.url,
          message: `Cross-origin resource ${response.url} declares unsupported CORP "${corp}"`,
          suggestion: 'Use one of `same-origin`, `same-site`, or `cross-origin`.',
        },
      ];
    }
    return [];
  }

  async audit(url: string): Promise<IsolationReport> {
    let response: Response;
    try {
      response = await this.fetchImpl(url);
    } catch (error) {
      return {
        ok: false,
        url,
        headers: {},
        resources: [],
        findings: [
          {
            code: 'isolation/unreachable',
            severity: 'error',
            subject: url,
            message: `Could not fetch ${url}: ${error instanceof Error ? error.message : String(error)}`,
            suggestion: 'Check the URL is deployed and reachable from this host.',
          },
        ],
        guides: renderDeploymentGuide(),
      };
    }

    const headers: Record<string, string> = {};
    response.headers.forEach((value, name) => {
      headers[name.toLowerCase()] = value;
    });

    const findings = this.evaluateHeaders(response.headers);
    const coep = parseToken(headerValue(response.headers, 'cross-origin-embedder-policy'));

    const contentType = headerValue(response.headers, 'content-type') ?? '';
    const body = contentType.includes('text/html') ? await response.text() : '';
    const origin = new URL(url).origin;
    const resources: ResourceCheck[] = [];

    if (body !== '') {
      for (const resourceUrl of extractResourceUrls(body, url).slice(0, this.maxResources)) {
        const resourceOrigin = new URL(resourceUrl).origin;
        const crossOrigin = resourceOrigin !== origin;
        const probe: ResourceCheck = {
          url: resourceUrl,
          origin: resourceOrigin,
          crossOrigin,
          ok: true,
        };
        try {
          const resource = await this.fetchImpl(resourceUrl, { method: 'GET' });
          probe.status = resource.status;
          probe.corp = headerValue(resource.headers, 'cross-origin-resource-policy');
          probe.ok = resource.status < 400;
          // Drain the body so the connection can be reused.
          await resource.arrayBuffer();
        } catch (error) {
          probe.ok = false;
          probe.error = error instanceof Error ? error.message : String(error);
        }
        resources.push(probe);
        findings.push(...this.evaluateResource(probe, coep));
      }
    }

    return {
      ok: findings.every((finding) => finding.severity !== 'error'),
      url,
      status: response.status,
      headers,
      findings,
      resources,
      guides: renderDeploymentGuide(),
    };
  }
}

/** Platform-specific snippets that turn on cross-origin isolation. */
export function renderDeploymentGuide(): string[] {
  return [
    'Netlify — add to _headers:',
    '  /*',
    '    Cross-Origin-Opener-Policy: same-origin',
    '    Cross-Origin-Embedder-Policy: require-corp',
    'Cloudflare Pages — add to public/_headers:',
    '  /*',
    '    Cross-Origin-Opener-Policy: same-origin',
    '    Cross-Origin-Embedder-Policy: require-corp',
    'Vercel — add to vercel.json:',
    '  { "headers": [{ "source": "/(.*)", "headers": [',
    '    { "key": "Cross-Origin-Opener-Policy", "value": "same-origin" },',
    '    { "key": "Cross-Origin-Embedder-Policy", "value": "require-corp" } ] }] }',
    'nginx — in the server block:',
    '  add_header Cross-Origin-Opener-Policy same-origin always;',
    '  add_header Cross-Origin-Embedder-Policy require-corp always;',
    'Apache — in .htaccess:',
    '  Header always set Cross-Origin-Opener-Policy "same-origin"',
    '  Header always set Cross-Origin-Embedder-Policy "require-corp"',
    'Any CDN asset embedded by an isolated page needs:',
    '  Cross-Origin-Resource-Policy: cross-origin',
  ];
}

export function renderIsolationReport(report: IsolationReport): string {
  const lines: string[] = [];
  const state = report.ok ? 'cross-origin isolated' : 'NOT cross-origin isolated';
  lines.push(
    `${report.url} is ${state}${report.status === undefined ? '' : ` (HTTP ${report.status})`}`,
  );
  lines.push('');
  for (const finding of report.findings) {
    lines.push(`  ${finding.severity}  ${finding.code}  ${finding.message}`);
    lines.push(`         fix: ${finding.suggestion}`);
  }
  if (report.resources.length > 0) {
    lines.push('');
    lines.push(`  Checked ${report.resources.length} subresource(s):`);
    for (const resource of report.resources) {
      const corp = resource.corp === undefined ? 'no CORP' : `CORP ${resource.corp}`;
      lines.push(
        `    ${resource.crossOrigin ? 'cross-origin' : 'same-origin'}  ${resource.url}  ${corp}`,
      );
    }
  }
  lines.push('');
  lines.push('Deployment guide:');
  for (const line of report.guides) lines.push(`  ${line}`);
  return `${lines.join('\n')}\n`;
}

/** Header bag from a plain object, for callers holding raw response metadata. */
export function normalizeHeaders(
  input: Record<string, string | string[] | undefined>,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(input)) {
    if (value !== undefined)
      out[name.toLowerCase()] = Array.isArray(value) ? value.join(', ') : value;
  }
  return out;
}
