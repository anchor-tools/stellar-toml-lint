import { describe, expect, it } from 'vitest';
import {
  analyzeSigningKeyRevocation,
  checkSigningKeyRevocation,
  SECURITY_REVOKED_SIGNING_KEY,
  SECURITY_UNRECORDED_KEY_ROTATION,
} from '../src/security/key-revocation.js';

function accountResponse(signers: unknown[], medThreshold: number): Response {
  return new Response(JSON.stringify({ signers, thresholds: { med_threshold: medThreshold } }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

describe('signing key revocation', () => {
  it('passes for an active valid signing key', async () => {
    const fetchImpl = (async () =>
      accountResponse([{ key: 'GABC', weight: 10 }], 1)) as typeof fetch;

    const diagnostics = await checkSigningKeyRevocation(
      { SIGNING_KEY: 'GABC' },
      { fetchImpl, horizonUrl: 'https://horizon.example' },
    );

    expect(diagnostics).toEqual([]);
  });

  it('flags a revoked key on Horizon', async () => {
    const fetchImpl = (async () =>
      accountResponse([{ key: 'GABC', weight: 0 }], 1)) as typeof fetch;

    const diagnostics = await checkSigningKeyRevocation(
      { SIGNING_KEY: 'GABC' },
      { fetchImpl, horizonUrl: 'https://horizon.example' },
    );

    expect(diagnostics.map((d) => d.rule)).toContain(SECURITY_REVOKED_SIGNING_KEY);
    expect(diagnostics[0]?.severity).toBe('error');
  });

  it('flags a declared key that is missing from the signer list', async () => {
    const fetchImpl = (async () =>
      accountResponse([{ key: 'GOTHER', weight: 5 }], 1)) as typeof fetch;

    const diagnostics = await checkSigningKeyRevocation(
      { SIGNING_KEY: 'GABC' },
      { fetchImpl, horizonUrl: 'https://horizon.example' },
    );

    expect(diagnostics.map((d) => d.rule)).toContain(SECURITY_REVOKED_SIGNING_KEY);
  });

  it('degrades to silence when Horizon is unreachable', async () => {
    const fetchImpl = (async () => {
      throw new Error('ECONNREFUSED');
    }) as unknown as typeof fetch;

    expect(
      await checkSigningKeyRevocation(
        { SIGNING_KEY: 'GABC' },
        { fetchImpl, horizonUrl: 'https://horizon.example' },
      ),
    ).toEqual([]);
  });

  it('flags an unrecorded rotation when a superseding signer meets the threshold', () => {
    const diagnostics = analyzeSigningKeyRevocation({
      signingKey: 'GOLD',
      medThreshold: 10,
      signers: [
        { key: 'GOLD', weight: 1 },
        { key: 'GNEW', weight: 10 },
      ],
    });

    expect(diagnostics.map((d) => d.rule)).toContain(SECURITY_UNRECORDED_KEY_ROTATION);
  });

  it('does not fetch when no SIGNING_KEY is declared', async () => {
    let calls = 0;
    const fetchImpl = (async () => {
      calls++;
      return accountResponse([], 1);
    }) as unknown as typeof fetch;

    expect(
      await checkSigningKeyRevocation({}, { fetchImpl, horizonUrl: 'https://horizon.example' }),
    ).toEqual([]);
    expect(calls).toBe(0);
  });
});
