import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';

export const BLOCKING_FRAME_ANCESTORS_RULE = 'security/blocking-frame-ancestors-directive';
export const MISSING_CLICKJACKING_PROTECTION_RULE = 'security/missing-clickjacking-protection';

const CSP_DOC = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors';

export interface CspFrameOptions {
  rules?: RuleOverrides;
}

function severityFor(
  rule: string,
  fallback: Severity,
  rules: RuleOverrides | undefined,
): Severity | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' || override === 'info'
    ? override
    : fallback;
}

/** Audits the effective framing headers on a SEP-24 interactive page. */
export async function auditCspFramePolicy(
  url: string,
  fetchImpl: typeof fetch = fetch,
  options: CspFrameOptions = {},
): Promise<Diagnostic[]> {
  const blockingSeverity = severityFor(BLOCKING_FRAME_ANCESTORS_RULE, 'error', options.rules);
  const missingSeverity = severityFor(
    MISSING_CLICKJACKING_PROTECTION_RULE,
    'warning',
    options.rules,
  );
  if (blockingSeverity === undefined && missingSeverity === undefined) return [];

  let response: Response;
  try {
    response = await fetchImpl(url, { method: 'GET', redirect: 'follow' });
  } catch {
    return [];
  }

  const csp = response.headers.get('content-security-policy') ?? '';
  const framePolicies = csp.split(',').flatMap((policy) => {
    const directive = policy
      .split(';')
      .map((part) => part.trim())
      .find((part) => /^frame-ancestors(?:\s|$)/i.test(part));
    if (directive === undefined) return [];
    return [directive.replace(/^frame-ancestors\s*/i, '').toLowerCase().split(/\s+/).filter(Boolean)];
  });
  const blocksEmbedding =
    framePolicies.some((sources) => sources.length === 1 && sources[0] === "'none'") ||
    ['deny', 'sameorigin'].includes(
      (response.headers.get('x-frame-options') ?? '').trim().toLowerCase(),
    );
  const hasProtection =
    framePolicies.length > 0 || response.headers.has('x-frame-options');

  if (blocksEmbedding && blockingSeverity !== undefined) {
    return [
      {
        rule: BLOCKING_FRAME_ANCESTORS_RULE,
        severity: blockingSeverity,
        category: 'network',
        message: `SEP-24 interactive page ${url} blocks wallet framing with its CSP or X-Frame-Options policy`,
        path: 'TRANSFER_SERVER_SEP0024',
        helpUri: CSP_DOC,
        suggestion:
          'Allow the wallet webview origins in frame-ancestors; do not use frame-ancestors \'none\' or X-Frame-Options DENY.',
      },
    ];
  }

  if (!hasProtection && missingSeverity !== undefined) {
    return [
      {
        rule: MISSING_CLICKJACKING_PROTECTION_RULE,
        severity: missingSeverity,
        category: 'network',
        message: `SEP-24 interactive page ${url} has no frame-ancestors or X-Frame-Options protection`,
        path: 'TRANSFER_SERVER_SEP0024',
        helpUri: CSP_DOC,
        suggestion:
          'Set a Content-Security-Policy frame-ancestors source list that includes supported wallet origins.',
      },
    ];
  }
  return [];
}

export const cspFrameAuditorRules: Rule[] = [
  {
    id: BLOCKING_FRAME_ANCESTORS_RULE,
    category: 'network',
    severity: 'error',
    description: 'SEP-24 interactive pages must not block legitimate wallet iframe embedding',
    run() {},
  },
  {
    id: MISSING_CLICKJACKING_PROTECTION_RULE,
    category: 'network',
    severity: 'warning',
    description: 'SEP-24 interactive pages should define a frame-ancestors or X-Frame-Options policy',
    run() {},
  },
];