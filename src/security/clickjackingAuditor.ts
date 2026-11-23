/**
 * Clickjacking and frame-embedding defence auditor.
 *
 * A wallet opens SEP-24 deposit pages, KYC portals and the anchor's own site in
 * iframes. Without a framing policy a malicious page can put the same iframe
 * under a fake button and have the user authorise a transaction they never
 * intended — the OWASP clickjacking test case.
 *
 * The two defences are `Content-Security-Policy: frame-ancestors` (modern, and
 * the one browsers honour when both are present) and the legacy
 * `X-Frame-Options`. This auditor requests each interactive URL as a browser
 * would when embedding it — a `Sec-Fetch-Dest: iframe` navigation — and reads
 * both headers. An endpoint that permits framing must list the wallet origins
 * that need it; `frame-ancestors *` frames the page for everyone, which is no
 * defence at all.
 *
 * Severity follows OWASP: a wildcard ancestor set is an error, an endpoint with
 * no declared framing policy is a warning, since the operator may reasonably
 * decide an API URL needs no framing defence.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isHttpsUrl, isString } from '../predicates.js';
import { errorMessage, fetchWithTimeout } from '../protocols/verifierSupport.js';

const MISSING_PROTECTION_RULE = 'clickjacking/missing-frame-protection';
const WILDCARD_RULE = 'clickjacking/wildcard-frame-ancestors';
const ALLOW_FROM_RULE = 'clickjacking/deprecated-allow-from';
const UNREACHABLE_RULE = 'clickjacking/endpoint-unreachable';

const OWASP_CLICKJACKING_URL =
  'https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html';

export type FramingRole = 'website' | 'interactive' | 'kyc' | 'auth';

interface FramingTarget {
  field: string;
  url: string;
  role: FramingRole;
}

/** How an endpoint answered, after both headers are read. */
export type FramingDecision = 'denied' | 'self-only' | 'allowlist' | 'wildcard' | 'undeclared';

export interface FrameObservation {
  field: string;
  url: string;
  role: FramingRole;
  status?: number;
  /** The `frame-ancestors` source list, or `null` when no enforcing CSP names it. */
  frameAncestors: string[] | null;
  xFrameOptions: string | null;
  decision: FramingDecision;
  error?: string;
}

export interface ClickjackingFinding {
  code: string;
  severity: 'error' | 'warning';
  message: string;
  field: string;
  url: string;
  suggestion: string;
}

export interface ClickjackingReport {
  ok: boolean;
  observations: FrameObservation[];
  findings: ClickjackingFinding[];
}

export interface ClickjackingOptions {
  rules?: RuleOverrides;
  timeoutMs?: number;
}

/** Resolves the effective severity for a rule, or `undefined` when it is turned off. */
function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules?: RuleOverrides,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

/**
 * The `frame-ancestors` source list of a policy, or `null` when the policy does
 * not set it.
 *
 * Only the enforcing `Content-Security-Policy` counts: a
 * `Content-Security-Policy-Report-Only` header changes nothing for a real
 * framing attempt. Sources are matched case-insensitively, and a directive with
 * an empty list denies every ancestor, exactly as `'none'` does.
 */
export function frameAncestorsOf(policy: string | null): string[] | null {
  if (policy === null) return null;
  for (const directive of policy.split(';')) {
    const parts = directive
      .trim()
      .split(/\s+/)
      .filter((part) => part.length > 0);
    if (parts[0]?.toLowerCase() !== 'frame-ancestors') continue;
    return parts.slice(1);
  }
  return null;
}

/**
 * Classifies both headers into one decision, preferring CSP as browsers do.
 *
 * `X-Frame-Options: ALLOW-FROM` is reported as undeclared on purpose: no current
 * browser implements it, so the page stays framable and the auditor says so.
 */
export function framingDecision(ancestors: string[] | null, xfo: string | null): FramingDecision {
  if (ancestors !== null) {
    if (ancestors.length === 0 || ancestors.some((source) => source.toLowerCase() === "'none'")) {
      return 'denied';
    }
    if (ancestors.some((source) => source === '*')) return 'wildcard';
    if (ancestors.every((source) => source.toLowerCase() === "'self'")) return 'self-only';
    return 'allowlist';
  }
  const value = (xfo ?? '').trim().toUpperCase();
  if (value === 'DENY') return 'denied';
  if (value === 'SAMEORIGIN') return 'self-only';
  return 'undeclared';
}

/** The URLs a wallet embeds or opens in a top-level window. */
export function framingTargets(doc: Record<string, unknown>): FramingTarget[] {
  const targets: FramingTarget[] = [];
  const push = (field: string, value: unknown, role: FramingRole): void => {
    if (isString(value) && isHttpsUrl(value)) targets.push({ field, url: value, role });
  };

  const documentation = doc.DOCUMENTATION;
  if (
    typeof documentation === 'object' &&
    documentation !== null &&
    !Array.isArray(documentation)
  ) {
    push('DOCUMENTATION.ORG_URL', (documentation as Record<string, unknown>).ORG_URL, 'website');
  }

  push('TRANSFER_SERVER_SEP0024', doc.TRANSFER_SERVER_SEP0024, 'interactive');
  push('TRANSFER_SERVER', doc.TRANSFER_SERVER, 'interactive');
  push('KYC_SERVER', doc.KYC_SERVER, 'kyc');
  push('DIRECT_PAYMENT_SERVER', doc.DIRECT_PAYMENT_SERVER, 'kyc');
  push('WEB_AUTH_ENDPOINT', doc.WEB_AUTH_ENDPOINT, 'auth');

  if (Array.isArray(doc.CURRENCIES)) {
    doc.CURRENCIES.forEach((entry, index) => {
      if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) return;
      push(
        `CURRENCIES[${index}].approval_server`,
        (entry as Record<string, unknown>).approval_server,
        'interactive',
      );
    });
  }

  return targets;
}

export class ClickjackingAuditor {
  private readonly fetchImpl: typeof fetch;
  private readonly options: ClickjackingOptions;

  constructor(fetchImpl: typeof fetch = fetch, options: ClickjackingOptions = {}) {
    this.fetchImpl = fetchImpl;
    this.options = options;
  }

  /** Fetches each interactive URL as an embedded navigation and reads its framing headers. */
  async audit(doc: Record<string, unknown>): Promise<ClickjackingReport> {
    const observations: FrameObservation[] = [];
    const findings: ClickjackingFinding[] = [];

    for (const target of framingTargets(doc)) {
      const observation = await this.request(target);
      observations.push(observation);
      findings.push(...this.inspect(target, observation));
    }

    return {
      ok: findings.every((finding) => finding.severity !== 'error'),
      observations,
      findings,
    };
  }

  private async request(target: FramingTarget): Promise<FrameObservation> {
    const base = { field: target.field, url: target.url, role: target.role };
    try {
      const response = await fetchWithTimeout(
        this.fetchImpl,
        target.url,
        {
          headers: {
            'Sec-Fetch-Dest': 'iframe',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'cross-site',
          },
        },
        this.options.timeoutMs,
      );
      const ancestors = frameAncestorsOf(response.headers.get('content-security-policy'));
      const xfo = response.headers.get('x-frame-options');
      return {
        ...base,
        status: response.status,
        frameAncestors: ancestors,
        xFrameOptions: xfo,
        decision: framingDecision(ancestors, xfo),
      };
    } catch (error) {
      return {
        ...base,
        frameAncestors: null,
        xFrameOptions: null,
        decision: 'undeclared',
        error: errorMessage(error),
      };
    }
  }

  private inspect(target: FramingTarget, observation: FrameObservation): ClickjackingFinding[] {
    const findings: ClickjackingFinding[] = [];
    const emit = (
      code: string,
      fallback: 'error' | 'warning',
      message: string,
      suggestion: string,
    ): void => {
      const severity = severityFor(code, fallback, this.options.rules);
      if (severity === undefined) return;
      findings.push({ code, severity, message, field: target.field, url: target.url, suggestion });
    };

    if (observation.error !== undefined) {
      emit(
        UNREACHABLE_RULE,
        'warning',
        `${target.field} could not be probed for framing headers: ${observation.error}`,
        'Confirm the endpoint answers an https navigation; framing policy cannot be read without a response.',
      );
      return findings;
    }

    if (observation.decision === 'wildcard') {
      emit(
        WILDCARD_RULE,
        'error',
        `${target.field} allows any page to frame it: Content-Security-Policy frame-ancestors *`,
        'List the wallet origins that embed this page, or send frame-ancestors "none" when nothing should embed it.',
      );
      return findings;
    }

    const allowFrom = (observation.xFrameOptions ?? '')
      .trim()
      .toUpperCase()
      .startsWith('ALLOW-FROM');
    if (allowFrom) {
      emit(
        ALLOW_FROM_RULE,
        'warning',
        `${target.field} uses the deprecated X-Frame-Options ALLOW-FROM, which browsers ignore`,
        'Replace it with Content-Security-Policy: frame-ancestors <origin>; ALLOW-FROM was removed from the standard.',
      );
      return findings;
    }

    if (observation.decision === 'undeclared') {
      emit(
        MISSING_PROTECTION_RULE,
        'warning',
        `${target.field} (${target.role}) declares neither Content-Security-Policy frame-ancestors nor X-Frame-Options`,
        'Send frame-ancestors "none" for pages a user opens directly, or an explicit list of wallet origins for embedded ones.',
      );
    }

    return findings;
  }
}

/** Diagnostics for the lint pipeline, so `--audit-clickjacking` reports normally. */
export async function auditClickjacking(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: ClickjackingOptions = {},
): Promise<{ diagnostics: Diagnostic[]; report: ClickjackingReport }> {
  const report = await new ClickjackingAuditor(fetchImpl, options).audit(doc);
  const diagnostics: Diagnostic[] = report.findings.map((finding) => ({
    rule: finding.code,
    severity: finding.severity,
    category: 'network',
    message: finding.message,
    path: finding.field,
    helpUri: OWASP_CLICKJACKING_URL,
    suggestion: finding.suggestion,
  }));
  return { diagnostics, report };
}

export function renderClickjackingReport(report: ClickjackingReport): string {
  const lines: string[] = [];
  lines.push(`Clickjacking / frame-ancestors audit: ${report.ok ? 'clean' : 'issues found'}`);
  lines.push(`  endpoints: ${report.observations.length}`);
  for (const observation of report.observations) {
    if (observation.error !== undefined) {
      lines.push(`  ${observation.field} [${observation.role}]  unreachable: ${observation.error}`);
      continue;
    }
    const policy =
      observation.frameAncestors !== null
        ? `frame-ancestors ${observation.frameAncestors.join(' ') || '(none)'}`
        : (observation.xFrameOptions ?? '(no framing header)');
    lines.push(
      `  ${observation.field} [${observation.role}]  ${observation.decision}  ${policy}  status=${
        observation.status ?? '-'
      }`,
    );
  }
  for (const finding of report.findings) {
    lines.push(`  ${finding.severity}  ${finding.code}  ${finding.message}`);
    lines.push(`         fix: ${finding.suggestion}`);
  }
  if (report.findings.length === 0) {
    lines.push('  Every probed endpoint stated who may frame it.');
  }
  return `${lines.join('\n')}\n`;
}

/** Registered so `--list-rules`, completions and `--off`/`--warn`/`--error` know these ids. */
export const clickjackingRules: Rule[] = [
  {
    id: MISSING_PROTECTION_RULE,
    category: 'network',
    severity: 'warning',
    description: 'Interactive endpoints must declare a frame-ancestors or X-Frame-Options policy',
    run() {},
  },
  {
    id: WILDCARD_RULE,
    category: 'network',
    severity: 'error',
    description: 'frame-ancestors must list authorized origins rather than allow global framing',
    run() {},
  },
  {
    id: ALLOW_FROM_RULE,
    category: 'network',
    severity: 'warning',
    description: 'X-Frame-Options ALLOW-FROM is deprecated and ignored by browsers',
    run() {},
  },
  {
    id: UNREACHABLE_RULE,
    category: 'network',
    severity: 'warning',
    description: 'Clickjacking audit could not reach a declared interactive endpoint',
    run() {},
  },
];

export const clickjackingRuleIds: readonly string[] = clickjackingRules.map((rule) => rule.id);
