import type { Diagnostic, Rule, RuleOverrides } from '../types.js';

export const SECURITY_MISSING_CORP_HEADER = 'security/missing-corp-header';
export const SECURITY_MISSING_OPENER_POLICY = 'security/missing-opener-policy';
export const SECURITY_MISSING_NOSNIFF_HEADER = 'security/missing-nosniff-header';

const AUDIT_RULES: readonly [string, string, string][] = [
  [
    SECURITY_MISSING_CORP_HEADER,
    'Cross-Origin-Resource-Policy is missing or does not allow cross-origin access',
    'Set `Cross-Origin-Resource-Policy: cross-origin` so wallets on other sites can fetch stellar.toml.',
  ],
  [
    SECURITY_MISSING_OPENER_POLICY,
    'Cross-Origin-Opener-Policy header is missing',
    'Set `Cross-Origin-Opener-Policy: same-origin` where compatible with the anchor site.',
  ],
  [
    SECURITY_MISSING_NOSNIFF_HEADER,
    'X-Content-Type-Options: nosniff is missing',
    'Set `X-Content-Type-Options: nosniff` on stellar.toml responses.',
  ],
];

/** Audits isolation headers on the live stellar.toml response. */
export function auditCorpHeaders(headers: Headers, rules?: RuleOverrides): Diagnostic[] {
  const diagnostics: Diagnostic[] = [];
  const checks: readonly [string, string | null][] = [
    [SECURITY_MISSING_CORP_HEADER, headers.get('cross-origin-resource-policy')],
    [SECURITY_MISSING_OPENER_POLICY, headers.get('cross-origin-opener-policy')],
    [SECURITY_MISSING_NOSNIFF_HEADER, headers.get('x-content-type-options')],
  ];

  for (const [rule, value] of checks) {
    const normalized = value?.trim().toLowerCase();
    const valid =
      rule === SECURITY_MISSING_CORP_HEADER
        ? normalized === 'cross-origin'
        : rule === SECURITY_MISSING_NOSNIFF_HEADER
          ? normalized === 'nosniff'
          : normalized !== undefined;
    if (valid) continue;
    const override = rules?.[rule];
    if (override === 'off') continue;
    const definition = AUDIT_RULES.find(([id]) => id === rule);
    if (!definition) continue;
    diagnostics.push({
      rule,
      severity: override === 'error' ? 'error' : 'warning',
      category: 'network',
      message: definition[1],
      path: 'stellar.toml response headers',
      suggestion: definition[2],
    });
  }
  return diagnostics;
}

export const corpHeaderRules: Rule[] = AUDIT_RULES.map(([id, description]) => ({
  id,
  category: 'network',
  severity: 'warning',
  description,
  run() {},
}));
