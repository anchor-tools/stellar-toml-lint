import { describe, expect, it } from 'vitest';
import {
  analyzeAccountThresholds,
  auditAccountThresholds,
  checkSigningKeyMultisig,
  SECURITY_SIGNING_KEY_INSUFFICIENT_WEIGHT,
  SECURITY_SIGNING_KEY_SINGLE_SIGNATURE,
  SECURITY_SINGLE_SIGNER_HIGH_THRESHOLD,
  SECURITY_UNREACHABLE_THRESHOLD,
} from '../src/security/multisig.js';

const ACCOUNT_ID = 'GABCDEF';
const SIGNER_1 = 'GSIGNER1';
const SIGNER_2 = 'GSIGNER2';
const ISSUER_ID = 'GISSUER1';

function accountResponse(
  signers: Array<{ key: string; weight: number }>,
  thresholds: { low_threshold?: number; med_threshold?: number; high_threshold?: number } = {},
  extra: Record<string, unknown> = {},
): Response {
  return new Response(
    JSON.stringify({
      id: ACCOUNT_ID,
      signers,
      thresholds: {
        low_threshold: thresholds.low_threshold ?? 0,
        med_threshold: thresholds.med_threshold ?? 0,
        high_threshold: thresholds.high_threshold ?? 0,
      },
      ...extra,
    }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  );
}

describe('analyzeAccountThresholds (pure) — issue #94 checks', () => {
  it('passes cleanly for a governed multisig (master weight 0, two signers, threshold 2)', () => {
    const diagnostics = analyzeAccountThresholds({
      accountId: ACCOUNT_ID,
      signers: [
        { key: ACCOUNT_ID, weight: 0 },
        { key: SIGNER_1, weight: 2 },
        { key: SIGNER_2, weight: 2 },
      ],
      medThreshold: 2,
      highThreshold: 3,
    });

    expect(diagnostics).toEqual([]);
  });

  it('errors with security/signing-key-insufficient-weight when the signing key alone cannot meet med_threshold', () => {
    const diagnostics = analyzeAccountThresholds({
      accountId: ACCOUNT_ID,
      signers: [
        { key: ACCOUNT_ID, weight: 1 },
        { key: SIGNER_1, weight: 1 },
        { key: SIGNER_2, weight: 1 },
      ],
      medThreshold: 2,
    });

    const finding = diagnostics.find((d) => d.rule === SECURITY_SIGNING_KEY_INSUFFICIENT_WEIGHT);
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('error');
    expect(finding?.message).toContain(ACCOUNT_ID);
    expect(finding?.message).toContain('weight 1');
    expect(finding?.message).toContain('medium threshold of 2');
  });

  it('does not flag insufficient weight when the signing key meets med_threshold alone', () => {
    const diagnostics = analyzeAccountThresholds({
      accountId: ACCOUNT_ID,
      signers: [
        { key: ACCOUNT_ID, weight: 2 },
        { key: SIGNER_1, weight: 1 },
      ],
      medThreshold: 2,
    });

    expect(diagnostics.map((d) => d.rule)).not.toContain(SECURITY_SIGNING_KEY_INSUFFICIENT_WEIGHT);
  });

  it('errors with security/unreachable-threshold when total weight cannot meet med_threshold', () => {
    const diagnostics = analyzeAccountThresholds({
      accountId: ACCOUNT_ID,
      signers: [{ key: SIGNER_1, weight: 1 }],
      medThreshold: 2,
    });

    const finding = diagnostics.find((d) => d.rule === SECURITY_UNREACHABLE_THRESHOLD);
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('error');
    expect(finding?.message).toContain('total signer weight 1');
  });

  it('reports a high-threshold deadlock when the medium threshold is reachable but the high one is not', () => {
    const diagnostics = analyzeAccountThresholds({
      accountId: ACCOUNT_ID,
      signers: [
        { key: SIGNER_1, weight: 2 },
        { key: SIGNER_2, weight: 1 },
      ],
      medThreshold: 2,
      highThreshold: 5,
    });

    const finding = diagnostics.find((d) => d.rule === SECURITY_UNREACHABLE_THRESHOLD);
    expect(finding).toBeDefined();
    expect(finding?.message).toContain('high threshold of 5');
  });

  it('mentions a zero master weight in the unreachable-threshold finding (account cannot self-heal)', () => {
    const diagnostics = analyzeAccountThresholds({
      accountId: ACCOUNT_ID,
      masterWeight: 0,
      signers: [{ key: SIGNER_1, weight: 1 }],
      medThreshold: 3,
    });

    const finding = diagnostics.find((d) => d.rule === SECURITY_UNREACHABLE_THRESHOLD);
    expect(finding).toBeDefined();
    expect(finding?.message).toContain('master key weight is 0');
  });

  it('warns with security/single-signer-high-threshold when one signer reaches the high threshold alone', () => {
    const diagnostics = analyzeAccountThresholds({
      accountId: ACCOUNT_ID,
      signers: [
        { key: ACCOUNT_ID, weight: 0 },
        { key: SIGNER_1, weight: 5 },
        { key: SIGNER_2, weight: 1 },
      ],
      medThreshold: 2,
      highThreshold: 5,
    });

    const finding = diagnostics.find((d) => d.rule === SECURITY_SINGLE_SIGNER_HIGH_THRESHOLD);
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('warning');
    expect(finding?.message).toContain(SIGNER_1);
    expect(finding?.message).toContain('high threshold of 5');
  });

  it('does not flag a single signer when its weight is below the high threshold', () => {
    const diagnostics = analyzeAccountThresholds({
      accountId: ACCOUNT_ID,
      signers: [
        { key: ACCOUNT_ID, weight: 0 },
        { key: SIGNER_1, weight: 2 },
        { key: SIGNER_2, weight: 2 },
      ],
      medThreshold: 2,
      highThreshold: 4,
    });

    expect(diagnostics).toEqual([]);
  });

  it('still warns when a lone master key with no additional signers controls the account', () => {
    const diagnostics = analyzeAccountThresholds({
      accountId: ACCOUNT_ID,
      signers: [{ key: ACCOUNT_ID, weight: 1 }],
      medThreshold: 1,
    });

    expect(diagnostics.map((d) => d.rule)).toEqual([SECURITY_SIGNING_KEY_SINGLE_SIGNATURE]);
  });

  it('treats a missing master signer entry as weight 0 via master_weight', () => {
    const diagnostics = analyzeAccountThresholds({
      accountId: ACCOUNT_ID,
      masterWeight: 0,
      signers: [{ key: SIGNER_1, weight: 1 }],
      medThreshold: 1,
    });

    expect(diagnostics).toEqual([]);
  });

  it('labels diagnostics with the account role', () => {
    const diagnostics = analyzeAccountThresholds(
      {
        accountId: ISSUER_ID,
        signers: [{ key: ISSUER_ID, weight: 1 }],
        medThreshold: 2,
      },
      { role: 'issuer USD' },
    );

    expect(diagnostics.some((d) => d.message.startsWith('issuer USD '))).toBe(true);
  });

  it('honours severity overrides, including off', () => {
    const base = {
      accountId: ACCOUNT_ID,
      signers: [{ key: ACCOUNT_ID, weight: 1 }],
      medThreshold: 2,
    };

    const off = analyzeAccountThresholds(base, {
      rules: {
        [SECURITY_SIGNING_KEY_SINGLE_SIGNATURE]: 'off',
        [SECURITY_SIGNING_KEY_INSUFFICIENT_WEIGHT]: 'off',
        [SECURITY_UNREACHABLE_THRESHOLD]: 'off',
      },
    });
    expect(off).toEqual([]);

    const downgraded = analyzeAccountThresholds(base, {
      rules: { [SECURITY_UNREACHABLE_THRESHOLD]: 'warning' },
    });
    const unreachable = downgraded.find((d) => d.rule === SECURITY_UNREACHABLE_THRESHOLD);
    expect(unreachable?.severity).toBe('warning');
  });
});

describe('auditAccountThresholds (Horizon)', () => {
  it('flags an insufficient-weight signing key fetched from Horizon', async () => {
    const fetchImpl = (async () =>
      accountResponse(
        [
          { key: ACCOUNT_ID, weight: 1 },
          { key: SIGNER_1, weight: 1 },
        ],
        { med_threshold: 2 },
      )) as typeof fetch;

    const diagnostics = await auditAccountThresholds(
      ACCOUNT_ID,
      'https://horizon.example',
      fetchImpl,
    );

    expect(diagnostics.map((d) => d.rule)).toContain(SECURITY_SIGNING_KEY_INSUFFICIENT_WEIGHT);
  });

  it('passes cleanly for a governed multisig account', async () => {
    const fetchImpl = (async () =>
      accountResponse(
        [
          { key: ACCOUNT_ID, weight: 0 },
          { key: SIGNER_1, weight: 2 },
          { key: SIGNER_2, weight: 2 },
        ],
        { med_threshold: 2, high_threshold: 3 },
      )) as typeof fetch;

    const diagnostics = await auditAccountThresholds(
      ACCOUNT_ID,
      'https://horizon.example',
      fetchImpl,
    );

    expect(diagnostics).toEqual([]);
  });

  it('reads master_weight from the Horizon record', async () => {
    const fetchImpl = (async () =>
      accountResponse(
        [{ key: SIGNER_1, weight: 1 }],
        { med_threshold: 2 },
        { master_weight: 1 },
      )) as typeof fetch;

    const diagnostics = await auditAccountThresholds(
      ACCOUNT_ID,
      'https://horizon.example',
      fetchImpl,
    );

    expect(diagnostics.map((d) => d.rule)).toContain(SECURITY_SIGNING_KEY_INSUFFICIENT_WEIGHT);
  });

  it('degrades to silence when Horizon times out', async () => {
    const fetchImpl = (async () => {
      throw new Error('Horizon request timed out');
    }) as unknown as typeof fetch;

    expect(await auditAccountThresholds(ACCOUNT_ID, 'https://horizon.example', fetchImpl)).toEqual(
      [],
    );
  });

  it('degrades to silence on a non-200 response', async () => {
    const fetchImpl = (async () => new Response('{}', { status: 503 })) as unknown as typeof fetch;

    expect(await auditAccountThresholds(ACCOUNT_ID, 'https://horizon.example', fetchImpl)).toEqual(
      [],
    );
  });

  it('requests the Horizon accounts endpoint for the account id', async () => {
    let requestedUrl = '';
    const fetchImpl = (async (input: string | URL | Request) => {
      requestedUrl = String(input);
      return accountResponse([{ key: ACCOUNT_ID, weight: 1 }], { med_threshold: 1 });
    }) as unknown as typeof fetch;

    await auditAccountThresholds(ACCOUNT_ID, 'https://horizon.example/', fetchImpl);

    expect(requestedUrl).toBe(`https://horizon.example/accounts/${ACCOUNT_ID}`);
  });
});

describe('checkSigningKeyMultisig (document entry point)', () => {
  it('does not fetch when no SIGNING_KEY or issuers are declared', async () => {
    let calls = 0;
    const fetchImpl = (async () => {
      calls++;
      return accountResponse([]);
    }) as unknown as typeof fetch;

    expect(await checkSigningKeyMultisig({}, { fetchImpl })).toEqual([]);
    expect(calls).toBe(0);
  });

  it('audits the declared SIGNING_KEY', async () => {
    const fetchImpl = (async () =>
      accountResponse(
        [
          { key: ACCOUNT_ID, weight: 1 },
          { key: SIGNER_1, weight: 1 },
        ],
        { med_threshold: 2 },
      )) as typeof fetch;

    const diagnostics = await checkSigningKeyMultisig(
      { SIGNING_KEY: ACCOUNT_ID },
      { fetchImpl, horizonUrl: 'https://horizon.example' },
    );

    expect(diagnostics.map((d) => d.rule)).toContain(SECURITY_SIGNING_KEY_INSUFFICIENT_WEIGHT);
  });

  it('audits issuer accounts declared in [[CURRENCIES]]', async () => {
    const requested: string[] = [];
    const fetchImpl = (async (input: string | URL | Request) => {
      const url = String(input);
      requested.push(url);
      const id = url.split('/accounts/')[1] ?? '';
      return accountResponse([{ key: id, weight: 3 }], { high_threshold: 3 });
    }) as unknown as typeof fetch;

    const diagnostics = await checkSigningKeyMultisig(
      {
        CURRENCIES: [
          { code: 'USD', issuer: ISSUER_ID },
          { code: 'EUR', issuer: ISSUER_ID },
        ],
      },
      { fetchImpl, horizonUrl: 'https://horizon.example' },
    );

    // Shared issuer is audited once, labeled with the currency code.
    expect(requested).toEqual([`https://horizon.example/accounts/${ISSUER_ID}`]);
    expect(diagnostics.map((d) => d.rule)).toContain(SECURITY_SINGLE_SIGNER_HIGH_THRESHOLD);
    expect(diagnostics.some((d) => d.message.startsWith('issuer USD '))).toBe(true);
  });

  it('audits both the signing key and distinct issuers', async () => {
    const requested: string[] = [];
    const fetchImpl = (async (input: string | URL | Request) => {
      const url = String(input);
      requested.push(url);
      const id = url.split('/accounts/')[1] ?? '';
      return accountResponse([{ key: id, weight: 1 }], { med_threshold: 2 });
    }) as unknown as typeof fetch;

    const diagnostics = await checkSigningKeyMultisig(
      {
        SIGNING_KEY: ACCOUNT_ID,
        CURRENCIES: [{ code: 'USD', issuer: ISSUER_ID }],
      },
      { fetchImpl, horizonUrl: 'https://horizon.example' },
    );

    expect(requested).toHaveLength(2);
    expect(diagnostics.filter((d) => d.rule === SECURITY_UNREACHABLE_THRESHOLD)).toHaveLength(2);
  });
});
