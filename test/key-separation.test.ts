import { StrKey } from '@stellar/stellar-base';
import { describe, expect, it } from 'vitest';
import {
  KeySeparationAuditor,
  OPERATIONAL_OPERATIONS,
  auditKeySeparation,
  collectKeyAssignments,
  keySeparationRuleIds,
  keySeparationRules,
  renderKeyRoleDiagram,
  renderKeySeparationReport,
} from '../src/security/keySeparationAuditor.js';

const SIGNING = StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 1));
const ISSUER = StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 2));
const HOT = StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 3));
const VALIDATOR = StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 4));
const RESERVE = StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 5));

/** A document where every account carries exactly one role. */
const SEPARATED = {
  NETWORK_PASSPHRASE: 'Test SDF Network ; September 2015',
  SIGNING_KEY: SIGNING,
  ACCOUNTS: [HOT],
  CURRENCIES: [{ code: 'USD', issuer: ISSUER, collateral_addresses: [RESERVE] }],
  VALIDATORS: [{ ALIAS: 'v1', PUBLIC_KEY: VALIDATOR }],
};

interface HorizonShape {
  thresholds?: Record<string, number>;
  signers?: { weight: number }[];
  records?: { type: string }[];
}

/** Serves `/accounts/:id` and `/accounts/:id/operations` from a per-account map. */
function horizonFetch(byAccount: Record<string, HorizonShape>, calls: string[] = []) {
  return (async (input: string | URL | Request) => {
    const url = new URL(String(input));
    calls.push(url.pathname);
    const [account] = url.pathname.split('/').filter((part) => part.startsWith('G'));
    const body = account === undefined ? undefined : byAccount[account];
    if (body === undefined) return new Response('not found', { status: 404 });
    if (url.pathname.endsWith('/operations')) {
      return Response.json({ _embedded: { records: body.records ?? [] } });
    }
    return Response.json({
      thresholds: {
        low_threshold: body.thresholds?.low ?? 1,
        med_threshold: body.thresholds?.med ?? 1,
        high_threshold: body.thresholds?.high ?? 1,
      },
      signers: body.signers ?? [{ weight: 1 }],
    });
  }) as unknown as typeof fetch;
}

/** Horizon answers nothing, exactly as an offline run or a firewalled CI job would. */
const downFetch = (async () => {
  throw new Error('ECONNREFUSED');
}) as unknown as typeof fetch;

const codesOf = (report: { findings: { code: string }[] }): string[] =>
  report.findings.map((finding) => finding.code);

describe('collectKeyAssignments', () => {
  it('orders accounts by id and stacks each role with its declaring field', () => {
    const byAccount = new Map(
      collectKeyAssignments(SEPARATED).map((assignment) => [assignment.account, assignment.roles]),
    );
    expect([...byAccount.keys()].sort()).toEqual([SIGNING, ISSUER, HOT, VALIDATOR, RESERVE].sort());
    expect(byAccount.get(SIGNING)).toEqual([{ role: 'signing-key', path: 'SIGNING_KEY' }]);
    expect(byAccount.get(ISSUER)).toEqual([
      { role: 'asset-issuer', path: 'CURRENCIES[0].issuer', label: 'USD' },
    ]);
    expect(byAccount.get(RESERVE)).toEqual([
      {
        role: 'collateral-address',
        path: 'CURRENCIES[0].collateral_addresses[0]',
        label: 'USD',
      },
    ]);
    expect(byAccount.get(HOT)).toEqual([{ role: 'declared-account', path: 'ACCOUNTS[0]' }]);
    expect(byAccount.get(VALIDATOR)).toEqual([
      { role: 'validator-identity', path: 'VALIDATORS[0].PUBLIC_KEY', label: 'v1' },
    ]);
  });

  it('ignores values that are not ed25519 account ids', () => {
    expect(
      collectKeyAssignments({
        SIGNING_KEY: 'not-an-account',
        ACCOUNTS: [StrKey.encodeMed25519PublicKey(Buffer.alloc(40, 3))],
        CURRENCIES: [{ code: 'USD', issuer: StrKey.encodeContract(Buffer.alloc(32, 9)) }],
      }),
    ).toEqual([]);
  });

  it('stacks the roles of a reused account in canonical order', () => {
    const [assignment] = collectKeyAssignments({
      SIGNING_KEY: ISSUER,
      ACCOUNTS: [ISSUER],
      CURRENCIES: [
        { code: 'USD', issuer: ISSUER },
        { code: 'EUR', issuer: ISSUER },
      ],
    });
    expect(assignment?.roles.map((occurrence) => occurrence.role)).toEqual([
      'signing-key',
      'declared-account',
      'asset-issuer',
      'asset-issuer',
    ]);
    expect(assignment?.roles.map((occurrence) => occurrence.label)).toEqual([
      undefined,
      undefined,
      'USD',
      'EUR',
    ]);
  });
});

describe('KeySeparationAuditor overlap detection', () => {
  it('treats issuer administration as separate from moving value', () => {
    expect(OPERATIONAL_OPERATIONS).toContain('payment');
    expect(OPERATIONAL_OPERATIONS).toContain('invoke_contract');
    expect(OPERATIONAL_OPERATIONS).not.toContain('allow_trust');
    expect(OPERATIONAL_OPERATIONS).not.toContain('set_options');
  });

  it('registers the documented rule ids and severities', () => {
    expect(keySeparationRuleIds).toEqual([
      'keys/signing-issuer-reuse',
      'keys/issuer-operational-account',
      'keys/validator-key-reuse',
      'keys/collateral-issuer-reuse',
      'keys/single-signer-root-account',
      'keys/issuer-operational-activity',
    ]);
    expect(keySeparationRules.map((rule) => rule.severity)).toEqual([
      'error',
      'error',
      'error',
      'warning',
      'warning',
      'warning',
    ]);
  });

  it('passes a document where every account has one role', async () => {
    const report = await new KeySeparationAuditor(downFetch, {
      queryNetwork: false,
    }).audit(SEPARATED);
    expect(report.findings).toEqual([]);
    expect(report.reused).toEqual([]);
    expect(report.ok).toBe(true);
  });

  it('flags the session key that is also the issuing root', async () => {
    const report = await new KeySeparationAuditor(downFetch, {
      queryNetwork: false,
    }).audit({ ...SEPARATED, SIGNING_KEY: ISSUER });
    expect(codesOf(report)).toEqual(['keys/signing-issuer-reuse']);
    expect(report.findings[0]?.severity).toBe('error');
    expect(report.findings[0]?.message).toContain(
      'both the SEP-10 SIGNING_KEY and an asset issuer',
    );
    expect(report.ok).toBe(false);
  });

  it('flags an issuer listed as an operational account', async () => {
    const report = await new KeySeparationAuditor(downFetch, {
      queryNetwork: false,
    }).audit({ ...SEPARATED, ACCOUNTS: [HOT, ISSUER] });
    expect(codesOf(report)).toEqual(['keys/issuer-operational-account']);
    expect(report.reused.map((assignment) => assignment.account)).toEqual([ISSUER]);
  });

  it('flags a validator identity reused for an anchor role, but not one reused across validators', async () => {
    const reusedForAnchor = await new KeySeparationAuditor(downFetch, {
      queryNetwork: false,
    }).audit({ ...SEPARATED, SIGNING_KEY: VALIDATOR });
    expect(codesOf(reusedForAnchor)).toEqual(['keys/validator-key-reuse']);

    const twoValidators = await new KeySeparationAuditor(downFetch, {
      queryNetwork: false,
    }).audit({
      ...SEPARATED,
      VALIDATORS: [
        { ALIAS: 'v1', PUBLIC_KEY: VALIDATOR },
        { ALIAS: 'v2', PUBLIC_KEY: VALIDATOR },
      ],
    });
    expect(twoValidators.findings).toEqual([]);
  });

  it('warns when the reserve address is also the issuer', async () => {
    const report = await new KeySeparationAuditor(downFetch, {
      queryNetwork: false,
    }).audit({
      ...SEPARATED,
      CURRENCIES: [{ code: 'USD', issuer: ISSUER, collateral_addresses: [ISSUER] }],
    });
    expect(codesOf(report)).toEqual(['keys/collateral-issuer-reuse']);
    expect(report.findings[0]?.severity).toBe('warning');
    expect(report.ok).toBe(true);
  });

  it('honours severity overrides and turning a rule off', async () => {
    const doc = { ...SEPARATED, SIGNING_KEY: ISSUER };
    const silenced = await new KeySeparationAuditor(downFetch, {
      queryNetwork: false,
      rules: { 'keys/signing-issuer-reuse': 'off' },
    }).audit(doc);
    expect(silenced.findings).toEqual([]);
    expect(silenced.ok).toBe(true);

    const downgraded = await new KeySeparationAuditor(downFetch, {
      queryNetwork: false,
      rules: { 'keys/signing-issuer-reuse': 'warning' },
    }).audit(doc);
    expect(downgraded.findings[0]?.severity).toBe('warning');
    expect(downgraded.ok).toBe(true);
  });

  it('reports the whole set of reuse findings in one pass', async () => {
    const report = await new KeySeparationAuditor(downFetch, {
      queryNetwork: false,
    }).audit({
      SIGNING_KEY: ISSUER,
      ACCOUNTS: [ISSUER],
      CURRENCIES: [{ code: 'USD', issuer: ISSUER, collateral_addresses: [ISSUER] }],
      VALIDATORS: [{ ALIAS: 'v1', PUBLIC_KEY: ISSUER }],
    });
    expect(codesOf(report).sort()).toEqual(
      [
        'keys/collateral-issuer-reuse',
        'keys/issuer-operational-account',
        'keys/signing-issuer-reuse',
        'keys/validator-key-reuse',
      ].sort(),
    );
  });
});

describe('KeySeparationAuditor Horizon checks', () => {
  it('warns about a single-signer issuer and an issuer doing operational work', async () => {
    const report = await new KeySeparationAuditor(
      horizonFetch({
        [ISSUER]: {
          signers: [{ weight: 1 }],
          thresholds: { low: 1, med: 1, high: 1 },
          records: [{ type: 'payment' }, { type: 'allow_trust' }],
        },
      }),
      { horizonUrl: 'https://horizon-testnet.stellar.org' },
    ).audit(SEPARATED);

    const kinds = codesOf(report);
    expect(kinds).toContain('keys/single-signer-root-account');
    expect(kinds).toContain('keys/issuer-operational-activity');
    expect(
      report.findings.find((f) => f.code === 'keys/issuer-operational-activity')?.message,
    ).toContain('recent payment operations');
  });

  it('stays quiet for a multisig issuer that only administers the asset', async () => {
    const report = await new KeySeparationAuditor(
      horizonFetch({
        [ISSUER]: {
          signers: [{ weight: 1 }, { weight: 1 }, { weight: 1 }],
          thresholds: { low: 2, med: 2, high: 3 },
          records: [{ type: 'allow_trust' }, { type: 'set_options' }],
        },
      }),
      { queryNetwork: true },
    ).audit(SEPARATED);
    expect(report.findings).toEqual([]);
    expect(report.horizonUrl).toBe('https://horizon-testnet.stellar.org');
  });

  it('never invents a finding for an account Horizon could not serve', async () => {
    const calls: string[] = [];
    const report = await new KeySeparationAuditor(horizonFetch({}, calls), {
      horizonUrl: 'https://horizon.example.invalid',
    }).audit(SEPARATED);

    expect(report.profiles).toHaveLength(5);
    expect(report.profiles.every((profile) => !profile.available)).toBe(true);
    expect(report.profiles[0]?.error).toBe('HTTP 404');
    expect(report.findings).toEqual([]);
    expect(report.ok).toBe(true);
    // A failed account read short-circuits the operations read for that account.
    expect(calls).toHaveLength(5);
  });

  it('degrades without throwing when the network is unreachable', async () => {
    const report = await new KeySeparationAuditor(downFetch).audit(SEPARATED);
    expect(report.profiles.every((profile) => !profile.available)).toBe(true);
    expect(report.profiles[0]?.error).toBe('ECONNREFUSED');
    expect(report.findings).toEqual([]);
  });

  it('skips Horizon entirely when queryNetwork is false', async () => {
    const calls: string[] = [];
    const report = await new KeySeparationAuditor(horizonFetch({}, calls), {
      queryNetwork: false,
    }).audit(SEPARATED);
    expect(calls).toEqual([]);
    expect(report.profiles).toEqual([]);
  });
});

describe('auditKeySeparation', () => {
  it('turns findings into network diagnostics with the declaring field as path', async () => {
    const { diagnostics, report } = await auditKeySeparation(
      { ...SEPARATED, ACCOUNTS: [ISSUER] },
      downFetch,
      { queryNetwork: false },
    );
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      rule: 'keys/issuer-operational-account',
      severity: 'error',
      category: 'network',
      path: 'ACCOUNTS[0]',
    });
    expect(report.ok).toBe(false);
  });

  it('produces no diagnostics for an empty document', async () => {
    const { diagnostics, report } = await auditKeySeparation({}, downFetch, {
      queryNetwork: false,
    });
    expect(diagnostics).toEqual([]);
    expect(report.assignments).toEqual([]);
    expect(report.ok).toBe(true);
  });
});

describe('rendering', () => {
  it('draws one tree per account with a branch per role', () => {
    const diagram = renderKeyRoleDiagram(
      collectKeyAssignments({ SIGNING_KEY: ISSUER, CURRENCIES: [{ code: 'USD', issuer: ISSUER }] }),
    );
    expect(diagram).toBe(
      `  key role assignments
    ${ISSUER}
      ├─ signing-key (SIGNING_KEY)
      └─ asset-issuer (CURRENCIES[0].issuer, USD)
`,
    );
    expect(renderKeyRoleDiagram([])).toBe('  no accounts declared\n');
  });

  it('renders a report with the diagram, the Horizon rows and the fixes', async () => {
    const report = await new KeySeparationAuditor(
      horizonFetch({
        [ISSUER]: {
          signers: [{ weight: 1 }],
          thresholds: { high: 1 },
          records: [{ type: 'payment' }],
        },
      }),
      { queryNetwork: true },
    ).audit(SEPARATED);
    const text = renderKeySeparationReport(report);
    expect(text).toContain('Key separation: clean');
    expect(text).toContain('accounts: 5, reused: 0');
    expect(text).toContain('horizon: https://horizon-testnet.stellar.org');
    expect(text).toContain('key role assignments');
    expect(text).toContain(`${ISSUER}  signers=1 weights=[1] thresholds=1/1/1 ops=payment`);
    expect(text).toContain('warning  keys/single-signer-root-account');
    expect(text).toContain('fix: Add signers and raise the high threshold');
  });

  it('says when nothing was found instead of leaving the report blank', async () => {
    const report = await new KeySeparationAuditor(downFetch, { queryNetwork: false }).audit(
      SEPARATED,
    );
    expect(renderKeySeparationReport(report)).toContain(
      'Every declared account carries a single role.',
    );
  });
});
