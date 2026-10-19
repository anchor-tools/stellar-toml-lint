import { Keypair } from '@stellar/stellar-base';
import { describe, expect, it } from 'vitest';
import {
  checkMpcGovernance,
  SECURITY_INSUFFICIENT_MPC_THRESHOLD,
} from '../../src/security/mpc-governance.js';

const signingKey = Keypair.random().publicKey();
const signerKeys = [signingKey, Keypair.random().publicKey(), Keypair.random().publicKey()];

function document(threshold: number, participants: number): Record<string, unknown> {
  return {
    SIGNING_KEY: signingKey,
    MPC_GOVERNANCE: {
      PROVIDER: 'Example Custody',
      CERTIFICATION_URL: 'https://custody.example/certification.json',
      THRESHOLD: threshold,
      PARTICIPANTS: participants,
      SIGNER_KEYS: signerKeys.slice(0, participants),
    },
  };
}

describe('checkMpcGovernance', () => {
  it('warns for an unsafe 1-of-2 threshold without making network requests', async () => {
    const diagnostics = await checkMpcGovernance(document(1, 2));

    expect(diagnostics.some((item) => item.rule === SECURITY_INSUFFICIENT_MPC_THRESHOLD)).toBe(
      true,
    );
  });

  it('verifies provider reachability and declared signer weight against Horizon', async () => {
    const fixture = document(2, 3);
    const fetchImpl: typeof fetch = async (input) => {
      const url = String(input);
      if (url.includes('certification.json')) {
        return Response.json({ provider: 'Example Custody', threshold: 2, participants: 3 });
      }
      return Response.json({
        thresholds: { med_threshold: 2, high_threshold: 3 },
        signers: signerKeys.map((key) => ({ key, weight: 1 })),
      });
    };

    expect(await checkMpcGovernance(fixture, { fetchImpl })).toEqual([]);
  });

  it('warns when declared keys cannot meet the on-chain threshold', async () => {
    const fetchImpl: typeof fetch = async (input) =>
      String(input).includes('certification.json')
        ? Response.json({ provider: 'Example Custody', threshold: 2, participants: 3 })
        : Response.json({
            thresholds: { med_threshold: 3, high_threshold: 4 },
            signers: signerKeys.map((key) => ({ key, weight: 1 })),
          });

    const diagnostics = await checkMpcGovernance(document(2, 3), { fetchImpl });

    expect(diagnostics.some((item) => item.message.includes('cannot meet'))).toBe(true);
  });

  it('rejects a provider attestation with a weaker threshold', async () => {
    const fetchImpl: typeof fetch = async (input) =>
      String(input).includes('certification.json')
        ? Response.json({ provider: 'Example Custody', threshold: 1, participants: 3 })
        : Response.json({
            thresholds: { med_threshold: 2, high_threshold: 3 },
            signers: signerKeys.map((key) => ({ key, weight: 1 })),
          });

    const diagnostics = await checkMpcGovernance(document(2, 3), { fetchImpl });

    expect(diagnostics.some((item) => item.message.includes('certification does not cover'))).toBe(
      true,
    );
  });
});
