import { describe, expect, it } from 'vitest';
import {
  RangeProofVerifier,
  zkRules,
  zkRuleIds,
  ZK_INVALID_RANGE_PROOF,
  ZK_COMMITMENT_MISMATCH,
  ZK_UNSUPPORTED_CURVE,
  ZK_MALFORMED_COMMITMENT,
  type AnchorReserveDeclaration,
} from '../../src/zk/rangeProofVerifier.js';

describe('RangeProofVerifier', () => {
  const verifier = new RangeProofVerifier();

  it('exposes zk rules and rule IDs', () => {
    expect(zkRules).toHaveLength(4);
    expect(zkRuleIds).toContain(ZK_INVALID_RANGE_PROOF);
    expect(zkRuleIds).toContain(ZK_COMMITMENT_MISMATCH);
    expect(zkRuleIds).toContain(ZK_UNSUPPORTED_CURVE);
    expect(zkRuleIds).toContain(ZK_MALFORMED_COMMITMENT);
  });

  it('verifies valid range proofs on supported curves', () => {
    const value = 500n;
    const blinding = 123456789n;
    const proof = RangeProofVerifier.generateRangeProof(value, blinding, 16, 'secp256k1');

    const result = verifier.verifyRangeProof(proof);
    expect(result.valid).toBe(true);
    expect(result.curve).toBe('secp256k1');
  });

  it('rejects unsupported curve declarations', () => {
    const proof = RangeProofVerifier.generateRangeProof(100n, 1n, 16, 'secp256k1');
    // @ts-expect-error test invalid curve
    proof.curve = 'unsupported_curve';
    const result = verifier.verifyRangeProof(proof);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Unsupported curve');
  });

  it('reconciles anchor reserve declarations with commitments', () => {
    const declaration: AnchorReserveDeclaration = {
      code: 'USDC',
      public_reserve_amount: '1000000',
      pedersen_commitment: '02' + '11'.repeat(32),
      curve: 'secp256k1',
    };

    const reconciliation = verifier.reconcileReserves(declaration);
    expect(reconciliation).toBeDefined();
    expect(reconciliation.commitmentCount).toBeGreaterThanOrEqual(1);
  });
});
