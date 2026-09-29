import { describe, expect, it } from 'vitest';
import {
  analyzeAccountThresholds,
  auditAccountThresholds,
  checkSigningKeyMultisig,
  SECURITY_SIGNING_KEY_SINGLE_SIGNATURE,
  SECURITY_SIGNING_KEY_UNUSABLE,
} from '../src/security/multisig.js';

const ACCOUNT_ID = 'GABCDEF';
const SIGNER_1 = 'GSIGNER1';
const SIGNER_2 = 'GSIGNER2';

function accountResponse(
  signers: Array<{ key: string; weight: number }>,
  thresholds: { low_threshold?: number; med_threshold?: number; high_threshold?: number } = {},
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
    }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  );
}

describe('analyzeAccountThresholds (pure)', () => {
  it('warns when a single master key of weight 1 controls the account', () => {
    const diagnostics = analyzeAccountThresholds({
      accountId: ACCOUNT_ID,
      signers: [{ key: ACCOUNT_ID, weight: 1 }],
      medThreshold: 1,
    });

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.rule).toBe(SECURITY_SIGNING_KEY_SINGLE_SIGNATURE);
    expect(diagnostics[0]?.severity).toBe('warning');
    expect(diagnostics[0]?.message).toContain(ACCOUNT_ID);
  });

  it('passes cleanly for multisig governance (master weight 0, two signers, threshold 2)', () => {
    const diagnostics = analyzeAccountThresholds({
      accountId: ACCOUNT_ID,
      signers: [
        { key: ACCOUNT_ID, weight: 0 },
        { key: SIGNER_1, weight: 1 },
        { key: SIGNER_2, weight: 1 },
      ],
      medThreshold: 2,
    });

    expect(diagnostics).toEqual([]);
  });

  it('errors when total signer weight cannot meet the medium threshold', () => {
    const diagnostics = analyzeAccountThresholds({
      accountId: ACCOUNT_ID,
      signers: [{ key: SIGNER_1, weight: 1 }],
      medThreshold: 2,
    });

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.rule).toBe(SECURITY_SIGNING_KEY_UNUSABLE);
    expect(diagnostics[0]?.severity).toBe('error');
  });

  it('reports both findings when a single key is present and the threshold is unreachable', () => {
    const diagnostics = analyzeAccountThresholds({
      accountId: ACCOUNT_ID,
      signers: [{ key: ACCOUNT_ID, weight: 1 }],
      medThreshold: 2,
    });

    expect(diagnostics.map((d) => d.rule)).toEqual([
      SECURITY_SIGNING_KEY_SINGLE_SIGNATURE,
      SECURITY_SIGNING_KEY_UNUSABLE,
    ]);
  });

  it('honours severity overrides', () => {
    const off = analyzeAccountThresholds(
      { accountId: ACCOUNT_ID, signers: [{ key: ACCOUNT_ID, weight: 1 }], medThreshold: 1 },
      { rules: { [SECURITY_SIGNING_KEY_SINGLE_SIGNATURE]: 'off' } },
    );
    expect(off).toEqual([]);

    const raised = analyzeAccountThresholds(
      { accountId: ACCOUNT_ID, signers: [{ key: ACCOUNT_ID, weight: 1 }], medThreshold: 1 },
      { rules: { [SECURITY_SIGNING_KEY_SINGLE_SIGNATURE]: 'error' } },
    );
    expect(raised[0]?.severity).toBe('error');
  });

  it('treats a missing master signer entry as weight 0', () => {
    const diagnostics = analyzeAccountThresholds({
      accountId: ACCOUNT_ID,
      signers: [{ key: SIGNER_1, weight: 1 }],
      medThreshold: 1,
    });

    expect(diagnostics).toEqual([]);
  });
});

describe('auditAccountThresholds (Horizon)', () => {
  it('flags a single-signature account fetched from Horizon', async () => {
    const fetchImpl = (async () =>
      accountResponse([{ key: ACCOUNT_ID, weight: 1 }], { med_threshold: 1 })) as typeof fetch;

    const diagnostics = await auditAccountThresholds(
      ACCOUNT_ID,
      'https://horizon.example',
      fetchImpl,
    );

    expect(diagnostics.map((d) => d.rule)).toContain(SECURITY_SIGNING_KEY_SINGLE_SIGNATURE);
  });

  it('passes cleanly for a governed multisig account', async () => {
    const fetchImpl = (async () =>
      accountResponse(
        [
          { key: ACCOUNT_ID, weight: 0 },
          { key: SIGNER_1, weight: 1 },
          { key: SIGNER_2, weight: 1 },
        ],
        { med_threshold: 2 },
      )) as typeof fetch;

    const diagnostics = await auditAccountThresholds(
      ACCOUNT_ID,
      'https://horizon.example',
      fetchImpl,
    );

    expect(diagnostics).toEqual([]);
  });

  it('errors for insufficient signer weight', async () => {
    const fetchImpl = (async () =>
      accountResponse([{ key: SIGNER_1, weight: 1 }], { med_threshold: 2 })) as typeof fetch;

    const diagnostics = await auditAccountThresholds(
      ACCOUNT_ID,
      'https://horizon.example',
      fetchImpl,
    );

    expect(diagnostics.map((d) => d.rule)).toContain(SECURITY_SIGNING_KEY_UNUSABLE);
    expect(diagnostics[0]?.severity).toBe('error');
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
  it('does not fetch when no SIGNING_KEY is declared', async () => {
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
      accountResponse([{ key: ACCOUNT_ID, weight: 1 }], { med_threshold: 1 })) as typeof fetch;

    const diagnostics = await checkSigningKeyMultisig(
      { SIGNING_KEY: ACCOUNT_ID },
      { fetchImpl, horizonUrl: 'https://horizon.example' },
    );

    expect(diagnostics.map((d) => d.rule)).toContain(SECURITY_SIGNING_KEY_SINGLE_SIGNATURE);
  });
});
