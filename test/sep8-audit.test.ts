import { describe, expect, it } from 'vitest';
import { lint } from '../src/lint.js';
import { checkRegulatedIssuerFlags, regulatedFlagRules } from '../src/rules/regulated-flags.js';

const NETWORK = 'Test SDF Network ; September 2015';
const ISSUER = 'GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY';

function regulatedSource(extra = ''): string {
  return [
    `NETWORK_PASSPHRASE="${NETWORK}"`,
    '',
    '[[CURRENCIES]]',
    'code="R-USD"',
    `issuer="${ISSUER}"`,
    'regulated=true',
    extra,
  ].join('\n');
}

function horizonFetch(
  flags: { auth_required?: boolean; auth_revocable?: boolean },
  status = 200,
): { fetchImpl: typeof fetch; calls: () => number; urls: string[] } {
  let calls = 0;
  const urls: string[] = [];
  const fetchImpl = (async (url: string | URL | globalThis.Request) => {
    calls++;
    urls.push(url.toString());
    if (status !== 200) return new Response('Not Found', { status });
    return new Response(
      JSON.stringify({
        id: ISSUER,
        flags: {
          auth_required: false,
          auth_revocable: false,
          auth_clawback_enabled: false,
          ...flags,
        },
      }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );
  }) as unknown as typeof fetch;
  return { fetchImpl, calls: () => calls, urls };
}

const AUTH_REQUIRED_RULE = 'currencies/regulated-asset-missing-auth-required';
const AUTH_REVOCABLE_RULE = 'currencies/regulated-missing-auth-revocable-flag';
const UNVERIFIABLE_RULE = 'currencies/regulated-issuer-flags-unverifiable';

describe('SEP-8 regulated issuer flags audit', () => {
  it('is silent when the issuer sets both required flags', async () => {
    const parsed = lint(regulatedSource()).parsed ?? {};
    const { fetchImpl } = horizonFetch({ auth_required: true, auth_revocable: true });

    const diagnostics = await checkRegulatedIssuerFlags(parsed, fetchImpl);
    expect(diagnostics).toEqual([]);
  });

  it('reports AUTH_REQUIRED_FLAG missing as an error', async () => {
    const parsed = lint(regulatedSource()).parsed ?? {};
    const { fetchImpl } = horizonFetch({ auth_required: false, auth_revocable: true });

    const diagnostics = await checkRegulatedIssuerFlags(parsed, fetchImpl);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: AUTH_REQUIRED_RULE,
        severity: 'error',
        category: 'currencies',
      }),
    );
    expect(diagnostics).not.toContainEqual(expect.objectContaining({ rule: AUTH_REVOCABLE_RULE }));
  });

  it('reports AUTH_REVOCABLE_FLAG missing as a warning', async () => {
    const parsed = lint(regulatedSource()).parsed ?? {};
    const { fetchImpl } = horizonFetch({ auth_required: true, auth_revocable: false });

    const diagnostics = await checkRegulatedIssuerFlags(parsed, fetchImpl);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({ rule: AUTH_REVOCABLE_RULE, severity: 'warning' }),
    );
    expect(diagnostics).not.toContainEqual(expect.objectContaining({ rule: AUTH_REQUIRED_RULE }));
  });

  it('emits both findings when neither flag is set', async () => {
    const parsed = lint(regulatedSource()).parsed ?? {};
    const { fetchImpl } = horizonFetch({});

    const diagnostics = await checkRegulatedIssuerFlags(parsed, fetchImpl);
    expect(diagnostics.map((d) => d.rule)).toEqual([AUTH_REQUIRED_RULE, AUTH_REVOCABLE_RULE]);
  });

  it('queries the Horizon instance matching NETWORK_PASSPHRASE', async () => {
    const parsed = lint(regulatedSource()).parsed ?? {};
    const { fetchImpl, urls } = horizonFetch({ auth_required: true, auth_revocable: true });

    await checkRegulatedIssuerFlags(parsed, fetchImpl);
    expect(urls).toEqual([`https://horizon-testnet.stellar.org/accounts/${ISSUER}`]);
  });

  it('does not query Horizon for non-regulated or invalid issuers', async () => {
    const { fetchImpl, calls } = horizonFetch({ auth_required: true, auth_revocable: true });

    const plain =
      lint(
        [
          `NETWORK_PASSPHRASE="${NETWORK}"`,
          '',
          '[[CURRENCIES]]',
          'code="USD"',
          `issuer="${ISSUER}"`,
        ].join('\n'),
      ).parsed ?? {};
    expect(await checkRegulatedIssuerFlags(plain, fetchImpl)).toEqual([]);

    const invalidIssuer =
      lint(
        [
          `NETWORK_PASSPHRASE="${NETWORK}"`,
          '',
          '[[CURRENCIES]]',
          'code="R-USD"',
          'issuer="G123"',
          'regulated=true',
        ].join('\n'),
      ).parsed ?? {};
    expect(await checkRegulatedIssuerFlags(invalidIssuer, fetchImpl)).toEqual([]);

    const pointer =
      lint(
        [
          `NETWORK_PASSPHRASE="${NETWORK}"`,
          '',
          '[[CURRENCIES]]',
          'code="R-USD"',
          'regulated=true',
          'toml="https://example.com/currencies.toml"',
        ].join('\n'),
      ).parsed ?? {};
    expect(await checkRegulatedIssuerFlags(pointer, fetchImpl)).toEqual([]);

    expect(calls()).toBe(0);
  });

  it('degrades to a warning on an outage', async () => {
    const parsed = lint(regulatedSource()).parsed ?? {};
    const { fetchImpl } = horizonFetch({}, 500);

    const diagnostics = await checkRegulatedIssuerFlags(parsed, fetchImpl);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({ rule: UNVERIFIABLE_RULE, severity: 'warning' }),
    );
  });

  it('degrades to a warning when the issuer account does not exist', async () => {
    const parsed = lint(regulatedSource()).parsed ?? {};
    const { fetchImpl } = horizonFetch({}, 404);

    const diagnostics = await checkRegulatedIssuerFlags(parsed, fetchImpl);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({ rule: UNVERIFIABLE_RULE, severity: 'warning' }),
    );
  });

  it('does not fail the run when fetch throws', async () => {
    const parsed = lint(regulatedSource()).parsed ?? {};
    const fetchImpl = (async () => {
      throw new Error('Network offline');
    }) as unknown as typeof fetch;

    const diagnostics = await checkRegulatedIssuerFlags(parsed, fetchImpl);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({ rule: UNVERIFIABLE_RULE, severity: 'warning' }),
    );
  });

  it('honours --off overrides', async () => {
    const parsed = lint(regulatedSource()).parsed ?? {};
    const { fetchImpl } = horizonFetch({});

    const diagnostics = await checkRegulatedIssuerFlags(parsed, fetchImpl, {
      rules: { [AUTH_REQUIRED_RULE]: 'off' },
    });
    expect(diagnostics).not.toContainEqual(expect.objectContaining({ rule: AUTH_REQUIRED_RULE }));
    expect(diagnostics.map((d) => d.rule)).toEqual([AUTH_REVOCABLE_RULE]);
  });

  it('registers the expected rule ids and severities', () => {
    expect(regulatedFlagRules.map((r) => ({ id: r.id, severity: r.severity }))).toEqual([
      { id: AUTH_REQUIRED_RULE, severity: 'error' },
      { id: AUTH_REVOCABLE_RULE, severity: 'warning' },
      { id: UNVERIFIABLE_RULE, severity: 'warning' },
    ]);
  });
});
