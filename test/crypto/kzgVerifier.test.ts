import { describe, expect, it } from 'vitest';
import {
  KzgCommitmentVerifier,
  kzgRules,
  kzgRuleIds,
  KZG_INVALID_PROOF,
  KZG_SRS_UNLOADED,
  KZG_MALFORMED_COMMITMENT,
} from '../../src/crypto/kzgVerifier.js';

describe('KzgCommitmentVerifier', () => {
  it('exposes kzg rules and rule IDs', () => {
    expect(kzgRules).toHaveLength(3);
    expect(kzgRuleIds).toContain(KZG_INVALID_PROOF);
    expect(kzgRuleIds).toContain(KZG_SRS_UNLOADED);
    expect(kzgRuleIds).toContain(KZG_MALFORMED_COMMITMENT);
  });

  it('generates trusted setup, commits to polynomial, and creates valid opening proof', () => {
    const srs = KzgCommitmentVerifier.generateTrustedSetup(42n, 8);
    const verifier = new KzgCommitmentVerifier();
    verifier.loadSrs(srs);

    // Polynomial P(x) = 3 + 2x + x^2
    const polyCoeffs = [3n, 2n, 1n];
    const commitment = verifier.commit(polyCoeffs);
    expect(commitment).toBeDefined();

    // Evaluate at z = 2: P(2) = 3 + 4 + 4 = 11
    const z = 2n;
    const y = KzgCommitmentVerifier.evaluatePolynomial(polyCoeffs, z);
    expect(y).toBe(11n);

    const openingProof = verifier.computeOpeningProof(polyCoeffs, z);
    expect(openingProof).toBeDefined();

    const commitmentHex = '0x' + commitment.toHex();
    const verificationResult = verifier.verify({
      commitment: commitmentHex,
      proof: openingProof.proofHex,
      z,
      y,
    });
    expect(verificationResult.valid).toBe(true);
  });

  it('reports error when verifying without loaded SRS', () => {
    const freshVerifier = new KzgCommitmentVerifier();
    const result = freshVerifier.verify({
      commitment: '0x' + '00'.repeat(48),
      proof: '0x' + '00'.repeat(48),
      z: 2n,
      y: 11n,
    });

    expect(result.valid).toBe(false);
    expect(result.error).toContain('Trusted setup (SRS) not loaded');
  });
});
