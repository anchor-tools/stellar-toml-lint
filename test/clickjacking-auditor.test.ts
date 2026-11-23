import { describe, expect, it } from 'vitest';
import {
  ClickjackingAuditor,
  auditClickjacking,
  clickjackingRuleIds,
  clickjackingRules,
  frameAncestorsOf,
  framingDecision,
  framingTargets,
  renderClickjackingReport,
} from '../src/security/clickjackingAuditor.js';

const DOC = {
  DOCUMENTATION: { ORG_URL: 'https://anchor.example.com' },
  TRANSFER_SERVER_SEP0024: 'https://anchor.example.com/sep24',
  KYC_SERVER: 'https://kyc.anchor.example.com',
  WEB_AUTH_ENDPOINT: 'https://auth.anchor.example.com',
  CURRENCIES: [{ code: 'USD', approval_server: 'https://approval.anchor.example.com' }],
};

/** Serves each `host/path` the headers it was configured with. */
function framingFetch(
  byHostPath: Record<string, { headers?: Record<string, string>; status?: number }>,
) {
  return (async (input: string | URL | Request) => {
    const url = new URL(String(input));
    const served = byHostPath[`${url.hostname}${url.pathname}`];
    if (served === undefined) return new Response('<html></html>', { status: 200 });
    return new Response('<html></html>', {
      status: served.status ?? 200,
      headers: served.headers,
    });
  }) as unknown as typeof fetch;
}

const thrownFetch = (async () => {
  throw new Error('ENOTFOUND');
}) as unknown as typeof fetch;

const csp = (policy: string): Record<string, string> => ({ 'content-security-policy': policy });

const codesOf = (report: { findings: { code: string }[] }): string[] =>
  report.findings.map((finding) => finding.code);

const repeated = (code: string, times: number): string[] =>
  Array.from({ length: times }, () => code);

describe('frameAncestorsOf', () => {
  it('reads the source list out of a full policy', () => {
    expect(
      frameAncestorsOf("default-src 'self'; frame-ancestors https://wallet.example.com"),
    ).toEqual(['https://wallet.example.com']);
    expect(frameAncestorsOf("FRAME-ANCESTORS   'self'   *")).toEqual(["'self'", '*']);
  });

  it('returns null when the directive is absent', () => {
    expect(frameAncestorsOf(null)).toBeNull();
    expect(frameAncestorsOf("default-src 'self'")).toBeNull();
    expect(frameAncestorsOf('')).toBeNull();
  });

  it('distinguishes an empty list from a missing directive', () => {
    expect(frameAncestorsOf('frame-ancestors;')).toEqual([]);
  });
});

describe('framingDecision', () => {
  it('prefers CSP over the legacy header, as browsers do', () => {
    expect(framingDecision(["'none'"], 'ALLOW-FROM https://evil.example')).toBe('denied');
    expect(framingDecision(['https://wallet.example.com'], 'DENY')).toBe('allowlist');
  });

  it('classifies CSP source lists', () => {
    expect(framingDecision([], null)).toBe('denied');
    expect(framingDecision(["'NONE'"], null)).toBe('denied');
    expect(framingDecision(['*'], null)).toBe('wildcard');
    expect(framingDecision(["'self'"], null)).toBe('self-only');
    expect(framingDecision(["'self'", 'https://wallet.example.com'], null)).toBe('allowlist');
  });

  it('classifies X-Frame-Options when no CSP set the directive', () => {
    expect(framingDecision(null, 'deny')).toBe('denied');
    expect(framingDecision(null, ' SAMEORIGIN ')).toBe('self-only');
    expect(framingDecision(null, 'ALLOW-FROM https://wallet.example.com')).toBe('undeclared');
    expect(framingDecision(null, null)).toBe('undeclared');
    expect(framingDecision(null, 'garbage')).toBe('undeclared');
  });
});

describe('framingTargets', () => {
  it('labels every URL a wallet embeds or opens', () => {
    expect(framingTargets(DOC).map((t) => `${t.field} ${t.role}`)).toEqual([
      'DOCUMENTATION.ORG_URL website',
      'TRANSFER_SERVER_SEP0024 interactive',
      'KYC_SERVER kyc',
      'WEB_AUTH_ENDPOINT auth',
      'CURRENCIES[0].approval_server interactive',
    ]);
  });

  it('skips plain http and non-string values', () => {
    expect(
      framingTargets({
        DOCUMENTATION: { ORG_URL: 'https://anchor.example.com' },
        TRANSFER_SERVER: 'http://anchor.example.com/sep24',
        KYC_SERVER: 42,
      }).map((t) => t.field),
    ).toEqual(['DOCUMENTATION.ORG_URL']);
  });
});

describe('ClickjackingAuditor', () => {
  it('registers the documented rule ids and severities', () => {
    expect(clickjackingRuleIds).toEqual([
      'clickjacking/missing-frame-protection',
      'clickjacking/wildcard-frame-ancestors',
      'clickjacking/deprecated-allow-from',
      'clickjacking/endpoint-unreachable',
    ]);
    expect(clickjackingRules.map((rule) => rule.severity)).toEqual([
      'warning',
      'error',
      'warning',
      'warning',
    ]);
  });

  it('passes an endpoint that lists the wallet origins that frame it', async () => {
    const report = await new ClickjackingAuditor(
      framingFetch({
        'anchor.example.com/sep24': {
          headers: csp('frame-ancestors https://wallet.example.com https://lobstr.co'),
        },
      }),
    ).audit({ TRANSFER_SERVER_SEP0024: 'https://anchor.example.com/sep24' });

    expect(report.findings).toEqual([]);
    expect(report.ok).toBe(true);
    expect(report.observations[0]?.decision).toBe('allowlist');
  });

  it('rejects a deposit flow that any page may frame', async () => {
    const report = await new ClickjackingAuditor(
      framingFetch({
        'anchor.example.com/sep24': { headers: csp("default-src 'self'; frame-ancestors *") },
      }),
    ).audit({ TRANSFER_SERVER_SEP0024: 'https://anchor.example.com/sep24' });

    expect(codesOf(report)).toEqual(['clickjacking/wildcard-frame-ancestors']);
    expect(report.findings[0]?.severity).toBe('error');
    expect(report.findings[0]?.suggestion).toContain('List the wallet origins');
    expect(report.ok).toBe(false);
  });

  it('accepts the legacy headers when no CSP is present', async () => {
    const report = await new ClickjackingAuditor(
      framingFetch({
        'kyc.anchor.example.com/': { headers: { 'x-frame-options': 'DENY' } },
        'auth.anchor.example.com/': { headers: { 'x-frame-options': 'SAMEORIGIN' } },
      }),
    ).audit({
      KYC_SERVER: 'https://kyc.anchor.example.com',
      WEB_AUTH_ENDPOINT: 'https://auth.anchor.example.com',
    });

    expect(report.findings).toEqual([]);
    expect(report.observations.map((o) => o.decision)).toEqual(['denied', 'self-only']);
  });

  it('warns that browsers ignore X-Frame-Options ALLOW-FROM', async () => {
    const report = await new ClickjackingAuditor(
      framingFetch({
        'kyc.anchor.example.com/': {
          headers: { 'x-frame-options': 'ALLOW-FROM https://wallet.example.com' },
        },
      }),
    ).audit({ KYC_SERVER: 'https://kyc.anchor.example.com' });

    expect(codesOf(report)).toEqual(['clickjacking/deprecated-allow-from']);
    expect(report.observations[0]?.decision).toBe('undeclared');
    expect(report.ok).toBe(true);
  });

  it('warns about every endpoint that states no framing policy', async () => {
    const report = await new ClickjackingAuditor(framingFetch({})).audit(DOC);

    expect(report.observations).toHaveLength(5);
    expect(codesOf(report)).toEqual(repeated('clickjacking/missing-frame-protection', 5));
    expect(report.findings.every((f) => f.severity === 'warning')).toBe(true);
    expect(report.ok).toBe(true);
  });

  it('ignores a report-only policy, which protects nothing', async () => {
    const report = await new ClickjackingAuditor(
      framingFetch({
        'kyc.anchor.example.com/': {
          headers: { 'content-security-policy-report-only': "frame-ancestors 'none'" },
        },
      }),
    ).audit({ KYC_SERVER: 'https://kyc.anchor.example.com' });

    expect(report.observations[0]?.frameAncestors).toBeNull();
    expect(codesOf(report)).toEqual(['clickjacking/missing-frame-protection']);
  });

  it('navigates to the page the way an embedded frame would', async () => {
    const seen: RequestInit[] = [];
    const recordFetch = (async (input: string | URL | Request, init?: RequestInit) => {
      seen.push(init ?? {});
      return new Response('<html></html>', { headers: csp("frame-ancestors 'none'") });
    }) as unknown as typeof fetch;

    await new ClickjackingAuditor(recordFetch).audit({
      KYC_SERVER: 'https://kyc.anchor.example.com',
    });

    expect(seen[0]?.headers).toMatchObject({
      'Sec-Fetch-Dest': 'iframe',
      'Sec-Fetch-Mode': 'navigate',
      'Sec-Fetch-Site': 'cross-site',
    });
  });

  it('warns rather than guessing when an endpoint is unreachable', async () => {
    const report = await new ClickjackingAuditor(thrownFetch).audit(DOC);

    expect(codesOf(report)).toEqual(repeated('clickjacking/endpoint-unreachable', 5));
    expect(report.observations[0]).toMatchObject({ error: 'ENOTFOUND', decision: 'undeclared' });
    expect(report.ok).toBe(true);
  });

  it('honours overrides that silence or escalate a rule', async () => {
    const doc = { KYC_SERVER: 'https://kyc.anchor.example.com' };
    const silenced = await new ClickjackingAuditor(framingFetch({}), {
      rules: { 'clickjacking/missing-frame-protection': 'off' },
    }).audit(doc);
    expect(silenced.findings).toEqual([]);

    const escalated = await new ClickjackingAuditor(framingFetch({}), {
      rules: { 'clickjacking/missing-frame-protection': 'error' },
    }).audit(doc);
    expect(escalated.findings[0]?.severity).toBe('error');
    expect(escalated.ok).toBe(false);
  });
});

describe('auditClickjacking', () => {
  it('emits network diagnostics addressed by SEP-1 field', async () => {
    const { diagnostics, report } = await auditClickjacking(
      { TRANSFER_SERVER_SEP0024: 'https://anchor.example.com/sep24' },
      framingFetch({ 'anchor.example.com/sep24': { headers: csp('frame-ancestors *') } }),
    );

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      rule: 'clickjacking/wildcard-frame-ancestors',
      severity: 'error',
      category: 'network',
      message:
        'TRANSFER_SERVER_SEP0024 allows any page to frame it: Content-Security-Policy frame-ancestors *',
      path: 'TRANSFER_SERVER_SEP0024',
    });
    expect(diagnostics[0]?.helpUri).toContain('Clickjacking_Defense_Cheat_Sheet');
    expect(report.ok).toBe(false);
  });

  it('has nothing to probe in a document with no interactive URLs', async () => {
    const { diagnostics, report } = await auditClickjacking({}, thrownFetch);
    expect(diagnostics).toEqual([]);
    expect(report.observations).toEqual([]);
    expect(report.ok).toBe(true);
  });
});

describe('renderClickjackingReport', () => {
  it('lists each endpoint with its decision and the policy behind it', async () => {
    const report = await new ClickjackingAuditor(
      framingFetch({
        'anchor.example.com/sep24': { headers: csp('frame-ancestors *') },
        'kyc.anchor.example.com/': { headers: { 'x-frame-options': 'DENY' } },
      }),
    ).audit({
      TRANSFER_SERVER_SEP0024: 'https://anchor.example.com/sep24',
      KYC_SERVER: 'https://kyc.anchor.example.com',
    });

    const text = renderClickjackingReport(report);
    expect(text).toContain('Clickjacking / frame-ancestors audit: issues found');
    expect(text).toContain('endpoints: 2');
    expect(text).toContain(
      'TRANSFER_SERVER_SEP0024 [interactive]  wildcard  frame-ancestors *  status=200',
    );
    expect(text).toContain('KYC_SERVER [kyc]  denied  DENY  status=200');
    expect(text).toContain('fix: List the wallet origins');
  });

  it('marks unreachable endpoints and renders the clean result', async () => {
    const unreachable = await new ClickjackingAuditor(thrownFetch).audit({
      KYC_SERVER: 'https://kyc.anchor.example.com',
    });
    expect(renderClickjackingReport(unreachable)).toContain(
      'KYC_SERVER [kyc]  unreachable: ENOTFOUND',
    );

    const clean = await new ClickjackingAuditor(
      framingFetch({ 'kyc.anchor.example.com/': { headers: csp('frame-ancestors;') } }),
    ).audit({ KYC_SERVER: 'https://kyc.anchor.example.com' });
    const text = renderClickjackingReport(clean);
    expect(text).toContain('frame-ancestors (none)');
    expect(text).toContain('Every probed endpoint stated who may frame it.');
  });
});
