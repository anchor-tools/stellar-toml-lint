import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  auditZkpAttestations,
  MALFORMED_ZKP_PROOF_RULE,
  ZKP_SUPPLY_COMMITMENT_MISMATCH_RULE,
} from '../../src/crypto/zkp-attestation.js';

const ISSUER = 'GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS';

function proof(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    protocol: 'groth16',
    curve: 'BLS12-381',
    pi_a: ['1', '2'],
    pi_b: [
      ['3', '4'],
      ['5', '6'],
    ],
    pi_c: ['7', '8'],
    public_inputs: ['1000000'],
    ...overrides,
  };
}

function commitmentFor(supply: string): string {
  return createHash('sha256').update(supply).digest('hex');
}

function doc(attestation: Record<string, unknown>, fixedNumber = 1000000): Record<string, unknown> {
  return {
    CURRENCIES: [
      {
        code: 'ZUSD',
        issuer: ISSUER,
        fixed_number: fixedNumber,
        zkp_attestation: attestation,
      },
    ],
  };
}

describe('ZKP reserve attestation validator', () => {
  it('accepts a valid Groth16 proof on BLS12-381', () => {
    const diagnostics = auditZkpAttestations(
      doc(proof({ supply_commitment: commitmentFor('1000000') })),
    );

    expect(diagnostics).toEqual([]);
  });

  it('accepts a valid BN254 proof whose public input is the supply', () => {
    const diagnostics = auditZkpAttestations(
      doc(proof({ curve: 'BN254', supply_commitment: '1000000' })),
    );

    expect(diagnostics).toEqual([]);
  });

  it('flags a supply commitment mismatch', () => {
    const diagnostics = auditZkpAttestations(
      doc(proof({ supply_commitment: commitmentFor('2000000') })),
    );

    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: ZKP_SUPPLY_COMMITMENT_MISMATCH_RULE,
        severity: 'error',
      }),
    );
  });

  it('flags malformed Groth16 proof data', () => {
    const diagnostics = auditZkpAttestations(doc(proof({ pi_c: ['only-one-coordinate'] })));

    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: MALFORMED_ZKP_PROOF_RULE,
        severity: 'error',
      }),
    );
  });

  it('flags an unsupported pairing curve', () => {
    const diagnostics = auditZkpAttestations(doc(proof({ curve: 'secp256k1' })));

    expect(diagnostics.map((d) => d.rule)).toContain(MALFORMED_ZKP_PROOF_RULE);
  });
});
