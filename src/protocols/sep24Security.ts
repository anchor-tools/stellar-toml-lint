/**
 * SEP-24 interactive webview security policy validator.
 *
 * Runs under opt-in `--audit-sep24-security` (with `--sep10-token`).
 *
 * A SEP-24 interactive flow hands the wallet's user to an anchor-hosted
 * webview that collects KYC documents and moves money. That page is a
 * first-class phishing and clickjacking target, so the anchor must pin its
 * script origins with CSP, refuse framing outside the wallet (or name the
 * wallet's `frame-ancestors`), enforce HSTS, and avoid mixed-content loads.
 *
 * The validator starts a real interactive session, fetches the returned URL,
 * and inspects the response headers and initial HTML. It never submits the
 * form and never reads document contents.
 */

import type { Diagnostic, Rule, RuleCategory, RuleOverrides, Severity } from '../types.js';
import { fetchWithTimeout, isRecord, severityFor, trimTrailingSlashes } from './verifierSupport.js';

const UNVERIFIABLE_RULE = 'sep24/webview-unverifiable';
const MISSING_CSP_RULE = 'sep24/webview-missing-csp';
const MISSING_FRAME_ANCESTORS_RULE = 'sep24/webview-missing-frame-ancestors';
const WILDCARD_FRAME_ANCESTORS_RULE = 'sep24/webview-wildcard-frame-ancestors';
const MISSING_HSTS_RULE = 'sep24/webview-missing-hsts';
const WEAK_HSTS_RULE = 'sep24/webview-weak-hsts';
const MISSING_REFERRER_POLICY_RULE = 'sep24/webview-missing-referrer-policy';
const WEAK_REFERRER_POLICY_RULE = 'sep24/webview-weak-referrer-policy';
const MIXED_CONTENT_RULE = 'sep24/webview-mixed-content';
const SCRIPT_WITHOUT_SRI_RULE = 'sep24/webview-script-without-sri';
const FRAME_HEADER_RULE = 'sep24/webview-weak-frame-options';

const SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0024.md';
const CATEGORY: RuleCategory = 'security';

/** Six months, the HSTS max-age browsers preload lists expect. */
export const MIN_HSTS_MAX_AGE_SECONDS = 15_552_000;

/** Referrer policies that leak the full interactive-session URL cross-origin. */
const WEAK_REFERRER_POLICIES = new Set([
  'unsafe-url',
  'no-referrer-when-downgrade',
  'origin-when-cross-origin',
]);

export interface Sep24SecurityOptions {
  rules?: RuleOverrides;
  /** SEP-24 transfer server; defaults to `TRANSFER_SERVER_SEP0024`/`TRANSFER_SERVER`. */
  transferServer?: string;
  /** SEP-10 JWT authorising the interactive session. */
  token?: string;
  /** Asset code for the throwaway interactive session. */
  assetCode?: string;
  amount?: string;
  /** Start a withdrawal instead of a deposit. Defaults to deposit. */
  withdraw?: boolean;
  timeoutMs?: number;
}

export interface WebviewHeaders {
  csp?: string;
  frameAncestors?: string[];
  xFrameOptions?: string;
  hsts?: string;
  referrerPolicy?: string;
}

export interface WebviewSecurityReport {
  transferServer: string;
  interactiveUrl?: string;
  status?: number;
  headers: WebviewHeaders;
  /** Same-origin/third-party script URLs found in the initial payload. */
  scripts: string[];
  /** Plain-HTTP resources loaded by the page. */
  mixedContent: string[];
  findings: { code: string; severity: Severity; message: string }[];
  ok: boolean;
}

export interface Sep24SecurityResult {
  report: WebviewSecurityReport;
  diagnostics: Diagnostic[];
}

function ruleDiagnostics(
  code: string,
  fallback: Severity,
  message: string,
  suggestion: string,
  rules?: RuleOverrides,
  path = 'TRANSFER_SERVER_SEP0024',
): Diagnostic[] {
  const severity = severityFor(code, fallback, rules);
  if (severity === undefined) return [];
  return [{ rule: code, severity, category: CATEGORY, message, path, helpUri: SPEC, suggestion }];
}

function header(response: Response, name: string): string | undefined {
  const value = response.headers.get(name);
  return value === null || value.trim() === '' ? undefined : value.trim();
}

/** Splits a CSP into directive name → sources. */
export function parseCsp(csp: string): Map<string, string[]> {
  const directives = new Map<string, string[]>();
  for (const part of csp.split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    const name = tokens.shift();
    if (name === undefined) continue;
    directives.set(name.toLowerCase(), tokens);
  }
  return directives;
}

/** `true` when the CSP's `frame-ancestors` allows every origin. */
export function frameAncestorsAreWildcard(sources: readonly string[]): boolean {
  return sources.includes('*') || sources.includes('http:') || sources.includes('https:');
}

/**
 * Collects resource URLs from `src`, `href` and `action` attributes. This is a
 * deliberately narrow HTML scan: the audit only needs to flag plain-HTTP loads
 * and third-party scripts, not build a DOM.
 */
export function collectResourceUrls(html: string): { scripts: string[]; insecure: string[] } {
  const scripts: string[] = [];
  const insecure: string[] = [];
  const attributes = /\b(?:src|href|action)\s*=\s*["']([^"']+)["']/gi;
  for (const match of html.matchAll(attributes)) {
    const url = match[1]?.trim();
    if (url === undefined || url === '') continue;
    if (/^http:\/\//i.test(url) || /^\/\/(?!\/)/.test(url)) insecure.push(url);
    if (/^https?:\/\//i.test(url) || url.startsWith('//')) {
      const scriptTag = new RegExp(
        `<script\\b[^>]*\\bsrc\\s*=\\s*["']${url.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}["'][^>]*>`,
        'i',
      );
      if (scriptTag.test(html)) scripts.push(url);
    }
  }
  return { scripts: [...new Set(scripts)], insecure: [...new Set(insecure)] };
}

/** Third-party scripts must carry an SRI `integrity` attribute. */
export function scriptsWithoutSri(html: string): string[] {
  const missing: string[] = [];
  const tags = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi;
  for (const match of html.matchAll(tags)) {
    const tag = match[0];
    const src = match[1];
    if (src === undefined) continue;
    const thirdParty = /^https?:\/\//i.test(src) || src.startsWith('//');
    if (thirdParty && !/\bintegrity\s*=\s*["'][^"']+["']/i.test(tag)) missing.push(src);
  }
  return [...new Set(missing)];
}

function hstsMaxAge(value: string): number | undefined {
  const match = /(?:^|;)\s*max-age\s*=\s*(\d+)/i.exec(value);
  if (match?.[1] === undefined) return undefined;
  const seconds = Number(match[1]);
  return Number.isFinite(seconds) ? seconds : undefined;
}

export class Sep24WebviewSecurityValidator {
  private readonly fetchImpl: typeof fetch;
  private readonly options: Sep24SecurityOptions;

  constructor(fetchImpl: typeof fetch = fetch, options: Sep24SecurityOptions = {}) {
    this.fetchImpl = fetchImpl;
    this.options = options;
  }

  async audit(doc: Record<string, unknown>): Promise<Sep24SecurityResult> {
    const transferServer =
      this.options.transferServer ??
      (typeof doc.TRANSFER_SERVER_SEP0024 === 'string'
        ? doc.TRANSFER_SERVER_SEP0024
        : typeof doc.TRANSFER_SERVER === 'string'
          ? doc.TRANSFER_SERVER
          : undefined);

    const report: WebviewSecurityReport = {
      transferServer: transferServer ?? '',
      headers: {},
      scripts: [],
      mixedContent: [],
      findings: [],
      ok: false,
    };
    const diagnostics: Diagnostic[] = [];
    const add = (items: Diagnostic[]): void => {
      diagnostics.push(...items);
      for (const item of items) {
        report.findings.push({ code: item.rule, severity: item.severity, message: item.message });
      }
    };

    if (transferServer === undefined) {
      add(
        ruleDiagnostics(
          UNVERIFIABLE_RULE,
          'warning',
          'No SEP-24 transfer server is advertised, so the interactive webview cannot be audited',
          'Publish TRANSFER_SERVER_SEP0024 (or TRANSFER_SERVER) in stellar.toml.',
          this.options.rules,
        ),
      );
      return { report, diagnostics };
    }

    const token = this.options.token;
    if (token === undefined || token.trim() === '') {
      add(
        ruleDiagnostics(
          UNVERIFIABLE_RULE,
          'warning',
          'No SEP-10 token supplied, so the interactive webview cannot be started',
          'Obtain a token from POST /auth and pass it with --sep10-token <jwt>.',
          this.options.rules,
        ),
      );
      return { report, diagnostics };
    }

    const kind = this.options.withdraw === true ? 'withdraw' : 'deposit';
    let interactiveUrl: URL;
    try {
      const endpoint = new URL(
        trimTrailingSlashes(transferServer) + '/transactions/' + kind + '/interactive',
      );
      if (endpoint.protocol !== 'https:')
        throw new Error('The SEP-24 transfer server must use HTTPS');
      const response = await fetchWithTimeout(
        this.fetchImpl,
        endpoint.href,
        {
          method: 'POST',
          redirect: 'error',
          headers: {
            'content-type': 'application/json',
            authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({
            asset_code: this.options.assetCode ?? 'USD',
            ...(this.options.amount === undefined ? {} : { amount: this.options.amount }),
          }),
        },
        this.options.timeoutMs ?? 8000,
      );
      if (!response.ok) {
        add(
          ruleDiagnostics(
            UNVERIFIABLE_RULE,
            'warning',
            `POST /transactions/${kind}/interactive returned HTTP ${response.status}`,
            'Confirm the SEP-24 server accepts interactive session requests for this token.',
            this.options.rules,
          ),
        );
        return { report, diagnostics };
      }
      const body: unknown = await response.json();
      const rawUrl = isRecord(body) && typeof body.url === 'string' ? body.url : undefined;
      if (rawUrl === undefined) {
        add(
          ruleDiagnostics(
            UNVERIFIABLE_RULE,
            'warning',
            'Interactive session response carried no `url`',
            'Return the wallet-facing interactive URL as `url`.',
            this.options.rules,
          ),
        );
        return { report, diagnostics };
      }
      interactiveUrl = new URL(rawUrl);
      if (interactiveUrl.protocol !== 'https:')
        throw new Error('The SEP-24 webview must use HTTPS');
      report.interactiveUrl = interactiveUrl.origin + interactiveUrl.pathname;
    } catch (error) {
      add(
        ruleDiagnostics(
          UNVERIFIABLE_RULE,
          'warning',
          `Interactive session request failed: ${error instanceof Error ? error.message : String(error)}`,
          'Confirm the SEP-24 server is reachable from the audit host.',
          this.options.rules,
        ),
      );
      return { report, diagnostics };
    }

    try {
      const page = await fetchWithTimeout(
        this.fetchImpl,
        interactiveUrl.href,
        { method: 'GET', headers: { accept: 'text/html' } },
        this.options.timeoutMs ?? 8000,
      );
      report.status = page.status;

      const csp = header(page, 'content-security-policy');
      const frameAncestors = csp === undefined ? undefined : parseCsp(csp).get('frame-ancestors');
      report.headers = {
        ...(csp === undefined ? {} : { csp }),
        ...(frameAncestors === undefined ? {} : { frameAncestors }),
        ...(header(page, 'x-frame-options') === undefined
          ? {}
          : { xFrameOptions: header(page, 'x-frame-options') }),
        ...(header(page, 'strict-transport-security') === undefined
          ? {}
          : { hsts: header(page, 'strict-transport-security') }),
        ...(header(page, 'referrer-policy') === undefined
          ? {}
          : { referrerPolicy: header(page, 'referrer-policy') }),
      };

      if (csp === undefined) {
        add(
          ruleDiagnostics(
            MISSING_CSP_RULE,
            'error',
            'Interactive webview has no Content-Security-Policy header',
            'Send a CSP that pins script-src and sets frame-ancestors to the trusted wallet domains.',
            this.options.rules,
          ),
        );
      }

      const xFrameOptions = report.headers.xFrameOptions?.toUpperCase();
      if (frameAncestors === undefined) {
        add(
          ruleDiagnostics(
            MISSING_FRAME_ANCESTORS_RULE,
            'error',
            'Content-Security-Policy does not declare frame-ancestors',
            "Add `frame-ancestors 'none'` or the wallet domains allowed to embed the webview.",
            this.options.rules,
          ),
        );
      } else if (frameAncestorsAreWildcard(frameAncestors)) {
        add(
          ruleDiagnostics(
            WILDCARD_FRAME_ANCESTORS_RULE,
            'error',
            'frame-ancestors allows any origin, so any site can frame the KYC webview',
            'List the trusted wallet origins explicitly instead of `*`.',
            this.options.rules,
          ),
        );
      }

      if (
        xFrameOptions !== undefined &&
        xFrameOptions !== 'DENY' &&
        xFrameOptions !== 'SAMEORIGIN'
      ) {
        add(
          ruleDiagnostics(
            FRAME_HEADER_RULE,
            'warning',
            `X-Frame-Options is "${report.headers.xFrameOptions}", which browsers no longer honour`,
            'Use DENY or SAMEORIGIN, and declare frame-ancestors in CSP.',
            this.options.rules,
          ),
        );
      }

      const hsts = report.headers.hsts;
      if (hsts === undefined) {
        add(
          ruleDiagnostics(
            MISSING_HSTS_RULE,
            'error',
            'Interactive webview has no Strict-Transport-Security header',
            'Send HSTS with a max-age of at least six months.',
            this.options.rules,
          ),
        );
      } else {
        const maxAge = hstsMaxAge(hsts);
        if (maxAge === undefined || maxAge < MIN_HSTS_MAX_AGE_SECONDS) {
          add(
            ruleDiagnostics(
              WEAK_HSTS_RULE,
              'warning',
              `HSTS max-age is ${maxAge === undefined ? 'missing' : `${maxAge}s`}, below six months`,
              `Set max-age to at least ${MIN_HSTS_MAX_AGE_SECONDS} and includeSubDomains.`,
              this.options.rules,
            ),
          );
        }
      }

      const referrerPolicy = report.headers.referrerPolicy;
      if (referrerPolicy === undefined) {
        add(
          ruleDiagnostics(
            MISSING_REFERRER_POLICY_RULE,
            'warning',
            'Interactive webview has no Referrer-Policy header',
            'Send `Referrer-Policy: strict-origin-when-cross-origin` or `no-referrer`.',
            this.options.rules,
          ),
        );
      } else if (WEAK_REFERRER_POLICIES.has(referrerPolicy.toLowerCase())) {
        add(
          ruleDiagnostics(
            WEAK_REFERRER_POLICY_RULE,
            'warning',
            `Referrer-Policy "${referrerPolicy}" leaks the interactive session URL`,
            'Use strict-origin-when-cross-origin or no-referrer.',
            this.options.rules,
          ),
        );
      }

      let html = '';
      try {
        html = await page.text();
      } catch {
        html = '';
      }
      const resources = collectResourceUrls(html);
      report.scripts = resources.scripts;
      report.mixedContent = resources.insecure;
      if (resources.insecure.length > 0) {
        add(
          ruleDiagnostics(
            MIXED_CONTENT_RULE,
            'error',
            `Interactive webview loads ${resources.insecure.length} plain-HTTP resource(s)`,
            'Load every script, stylesheet and form action over HTTPS.',
            this.options.rules,
          ),
        );
      }
      const missingSri = scriptsWithoutSri(html);
      if (missingSri.length > 0) {
        add(
          ruleDiagnostics(
            SCRIPT_WITHOUT_SRI_RULE,
            'warning',
            `${missingSri.length} third-party script(s) omit Subresource Integrity`,
            'Add an integrity and crossorigin attribute to third-party script tags.',
            this.options.rules,
          ),
        );
      }

      report.ok =
        report.findings.filter((finding) => finding.severity === 'error').length === 0 &&
        report.findings.length === 0;
    } catch (error) {
      add(
        ruleDiagnostics(
          UNVERIFIABLE_RULE,
          'warning',
          `Interactive webview fetch failed: ${error instanceof Error ? error.message : String(error)}`,
          'Confirm the interactive URL is reachable from the audit host.',
          this.options.rules,
        ),
      );
    }

    return { report, diagnostics };
  }
}

export async function auditSep24WebviewSecurity(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: Sep24SecurityOptions = {},
): Promise<Sep24SecurityResult> {
  return new Sep24WebviewSecurityValidator(fetchImpl, options).audit(doc);
}

export function renderSep24SecurityReport(report: WebviewSecurityReport): string {
  const lines = [
    'SEP-24 interactive webview security',
    `  transfer server: ${report.transferServer || 'not advertised'}`,
  ];
  if (report.interactiveUrl !== undefined)
    lines.push(`  interactive:     ${report.interactiveUrl}`);
  if (report.status !== undefined) lines.push(`  status:          HTTP ${report.status}`);
  const { csp, frameAncestors, hsts, referrerPolicy, xFrameOptions } = report.headers;
  lines.push(`  CSP:             ${csp === undefined ? 'missing' : 'present'}`);
  lines.push(
    `  frame-ancestors: ${frameAncestors === undefined ? 'missing' : frameAncestors.join(' ') || "'none'"}`,
  );
  lines.push(`  X-Frame-Options: ${xFrameOptions ?? 'missing'}`);
  lines.push(`  HSTS:            ${hsts ?? 'missing'}`);
  lines.push(`  Referrer-Policy: ${referrerPolicy ?? 'missing'}`);
  if (report.mixedContent.length > 0) {
    lines.push(`  mixed content:   ${report.mixedContent.length} insecure resource(s)`);
  }
  lines.push(`  result:          ${report.ok ? 'PASS' : 'FAIL'}`);
  for (const finding of report.findings) {
    lines.push(`  [${finding.severity}] ${finding.code}: ${finding.message}`);
  }
  return `${lines.join('\n')}\n`;
}

export const sep24SecurityRules: Rule[] = [
  {
    id: UNVERIFIABLE_RULE,
    category: CATEGORY,
    severity: 'warning',
    description: 'SEP-24 interactive webview could not be audited',
    run() {},
  },
  {
    id: MISSING_CSP_RULE,
    category: CATEGORY,
    severity: 'error',
    description: 'SEP-24 interactive webview must send a Content-Security-Policy',
    run() {},
  },
  {
    id: MISSING_FRAME_ANCESTORS_RULE,
    category: CATEGORY,
    severity: 'error',
    description: 'SEP-24 webview CSP must declare frame-ancestors',
    run() {},
  },
  {
    id: WILDCARD_FRAME_ANCESTORS_RULE,
    category: CATEGORY,
    severity: 'error',
    description: 'frame-ancestors must not allow every origin',
    run() {},
  },
  {
    id: FRAME_HEADER_RULE,
    category: CATEGORY,
    severity: 'warning',
    description: 'X-Frame-Options must be DENY or SAMEORIGIN',
    run() {},
  },
  {
    id: MISSING_HSTS_RULE,
    category: CATEGORY,
    severity: 'error',
    description: 'SEP-24 webview must send Strict-Transport-Security',
    run() {},
  },
  {
    id: WEAK_HSTS_RULE,
    category: CATEGORY,
    severity: 'warning',
    description: 'HSTS max-age must be at least six months',
    run() {},
  },
  {
    id: MISSING_REFERRER_POLICY_RULE,
    category: CATEGORY,
    severity: 'warning',
    description: 'SEP-24 webview should send Referrer-Policy',
    run() {},
  },
  {
    id: WEAK_REFERRER_POLICY_RULE,
    category: CATEGORY,
    severity: 'warning',
    description: 'Referrer-Policy must not leak the session URL',
    run() {},
  },
  {
    id: MIXED_CONTENT_RULE,
    category: CATEGORY,
    severity: 'error',
    description: 'SEP-24 webview must not load plain-HTTP resources',
    run() {},
  },
  {
    id: SCRIPT_WITHOUT_SRI_RULE,
    category: CATEGORY,
    severity: 'warning',
    description: 'Third-party scripts should carry Subresource Integrity',
    run() {},
  },
];

export const sep24SecurityRuleIds: readonly string[] = sep24SecurityRules.map((rule) => rule.id);
