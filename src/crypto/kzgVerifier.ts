/**
 * Cryptographic commitment polynomial evaluation and KZG commitment verifier.
 *
 * Implements Kate-Zaverucha-Goldberg (KZG) polynomial commitment verification over
 * the BN254 (alt_bn128) elliptic curve pairing engine.
 *
 * Checks:
 *   e(C - [y]_1, [1]_2) == e(proof, [x - z]_2)
 */

import { bls12_381 } from '@noble/curves/bls12-381';
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';

export const KZG_INVALID_PROOF = 'kzg/invalid-proof';
export const KZG_SRS_UNLOADED = 'kzg/srs-unloaded';
export const KZG_MALFORMED_COMMITMENT = 'kzg/malformed-commitment';

export interface SrsData {
  g1: string[]; // Powers-of-tau in G1: [tau^0]_1, [tau^1]_1, ...
  g2: string[]; // Powers-of-tau in G2: [tau^0]_2, [tau^1]_2, ...
}

export interface KzgOpeningProof {
  commitment: string; // [P(tau)]_1 in G1 (hex)
  z: string | bigint | number; // Evaluation point coordinate z in Fr
  y: string | bigint | number; // Claimed evaluation y = P(z) in Fr
  proof: string; // Quotient commitment [Q(tau)]_1 in G1 (hex)
}

export interface KzgVerificationResult {
  ok: boolean;
  valid: boolean;
  commitment: string;
  z: string;
  y: string;
  proof: string;
  error?: string;
}

export interface KzgCommitmentVerifierOptions {
  rules?: RuleOverrides;
  srs?: SrsData;
}

const Fr = bls12_381.fields.Fr;
const G1 = bls12_381.G1.ProjectivePoint;
const G2 = bls12_381.G2.ProjectivePoint;

/** Modular reduction in Fr */
function toFr(val: bigint | number | string): bigint {
  let b: bigint;
  if (typeof val === 'string') {
    b = BigInt(val.startsWith('0x') || val.startsWith('0X') ? val : `0x${val}`);
  } else {
    b = BigInt(val);
  }
  const order = Fr.ORDER;
  const res = b % order;
  return res >= 0n ? res : res + order;
}

/** Parses G1 point from hex string or Uint8Array */
export function parseG1Point(input: string | Uint8Array): InstanceType<typeof G1> {
  let hex = typeof input === 'string' ? input.trim() : Buffer.from(input).toString('hex');
  if (hex.startsWith('0x') || hex.startsWith('0X')) hex = hex.slice(2);
  return G1.fromHex(hex);
}

/** Parses G2 point from hex string or Uint8Array */
export function parseG2Point(input: string | Uint8Array): InstanceType<typeof G2> {
  let hex = typeof input === 'string' ? input.trim() : Buffer.from(input).toString('hex');
  if (hex.startsWith('0x') || hex.startsWith('0X')) hex = hex.slice(2);
  return G2.fromHex(hex);
}

export class KzgCommitmentVerifier {
  private g1Powers: Array<InstanceType<typeof G1>> = [];
  private g2Powers: Array<InstanceType<typeof G2>> = [];
  readonly options: KzgCommitmentVerifierOptions;

  constructor(options: KzgCommitmentVerifierOptions = {}) {
    this.options = options;
    if (options.srs) {
      this.loadSrs(options.srs);
    }
  }

  /**
   * Generates a trusted setup (powers of tau) for testing and evaluation.
   */
  static generateTrustedSetup(secretTau: bigint | number, maxDegree: number): SrsData {
    const tau = toFr(secretTau);
    const g1Base = G1.BASE;
    const g2Base = G2.BASE;

    const g1Hex: string[] = [];
    const g2Hex: string[] = [];

    let currentTauPower = 1n;
    for (let i = 0; i <= maxDegree; i++) {
      const pt1 = g1Base.multiply(currentTauPower);
      g1Hex.push('0x' + pt1.toHex());
      if (i <= 1) {
        const pt2 = g2Base.multiply(currentTauPower);
        g2Hex.push('0x' + pt2.toHex());
      }
      currentTauPower = toFr(currentTauPower * tau);
    }

    return {
      g1: g1Hex,
      g2: g2Hex,
    };
  }

  /**
   * Loads structured reference string powers into the verifier.
   */
  loadSrs(srs: SrsData): void {
    if (!srs.g1 || srs.g1.length === 0 || !srs.g2 || srs.g2.length < 2) {
      throw new Error('Invalid SRS: must contain G1 powers and at least 2 G2 powers ([1]_2 and [x]_2)');
    }

    this.g1Powers = srs.g1.map((hex) => parseG1Point(hex));
    this.g2Powers = srs.g2.map((hex) => parseG2Point(hex));
  }

  /**
   * Evaluates a polynomial P(X) = sum(a_i * X^i) at point z in Fr.
   */
  static evaluatePolynomial(coefficients: Array<bigint | number>, z: bigint | number | string): bigint {
    const zFr = toFr(z);
    let result = 0n;
    let currentZPower = 1n;

    for (let i = 0; i < coefficients.length; i++) {
      const coeff = toFr(coefficients[i]!);
      result = toFr(result + coeff * currentZPower);
      currentZPower = toFr(currentZPower * zFr);
    }

    return result;
  }

  /**
   * Computes polynomial division Q(X) = (P(X) - y) / (X - z) using Ruffini/synthetic division.
   */
  static dividePolynomial(
    coefficients: Array<bigint | number>,
    z: bigint | number | string,
    y: bigint | number | string,
  ): bigint[] {
    const zFr = toFr(z);
    const yFr = toFr(y);

    if (coefficients.length === 0) return [0n];

    const poly = coefficients.map((c) => toFr(c));
    poly[0] = toFr(poly[0]! - yFr);

    // Synthetic division of poly by (X - z)
    // Degree of quotient is poly.length - 2
    const n = poly.length;
    const quotient: bigint[] = new Array(n - 1).fill(0n);

    let remainder = 0n;
    for (let i = n - 1; i >= 1; i--) {
      remainder = toFr(poly[i]! + remainder);
      quotient[i - 1] = remainder;
      remainder = toFr(remainder * zFr);
    }

    return quotient;
  }

  /**
   * Computes KZG polynomial commitment C = sum(a_i * [tau^i]_1) from coefficients.
   */
  commit(coefficients: Array<bigint | number>): InstanceType<typeof G1> {
    if (this.g1Powers.length === 0) {
      throw new Error('Cannot commit: SRS not loaded');
    }
    if (coefficients.length > this.g1Powers.length) {
      throw new Error(`Polynomial degree ${coefficients.length - 1} exceeds SRS max degree ${this.g1Powers.length - 1}`);
    }

    let commitment = G1.ZERO;
    for (let i = 0; i < coefficients.length; i++) {
      const coeff = toFr(coefficients[i]!);
      if (coeff !== 0n) {
        commitment = commitment.add(this.g1Powers[i]!.multiply(coeff));
      }
    }
    return commitment;
  }

  /**
   * Computes opening proof pi = [Q(tau)]_1 and evaluation y = P(z).
   */
  computeOpeningProof(
    coefficients: Array<bigint | number>,
    z: bigint | number | string,
  ): { y: bigint; proof: InstanceType<typeof G1>; proofHex: string } {
    const y = KzgCommitmentVerifier.evaluatePolynomial(coefficients, z);
    const qCoeffs = KzgCommitmentVerifier.dividePolynomial(coefficients, z, y);
    const proof = this.commit(qCoeffs);
    return {
      y,
      proof,
      proofHex: '0x' + proof.toHex(),
    };
  }

  /**
   * Performs the elliptic curve pairing check:
   *   e(C - [y]_1, [1]_2) == e(proof, [x - z]_2)
   *
   * where:
   *   [1]_2 = G2 base point
   *   [x - z]_2 = [tau]_2 - z * [1]_2
   */
  verify(opening: KzgOpeningProof): KzgVerificationResult {
    const zStr = opening.z.toString();
    const yStr = opening.y.toString();

    if (this.g1Powers.length === 0 || this.g2Powers.length < 2) {
      return {
        ok: false,
        valid: false,
        commitment: opening.commitment,
        z: zStr,
        y: yStr,
        proof: opening.proof,
        error: 'KZG verification failed: Trusted setup (SRS) not loaded',
      };
    }

    try {
      const C = parseG1Point(opening.commitment);
      const proof = parseG1Point(opening.proof);
      const z = toFr(opening.z);
      const y = toFr(opening.y);

      const G1Base = G1.BASE;
      const G2Base = this.g2Powers[0]!; // [1]_2
      const tauG2 = this.g2Powers[1]!; // [x]_2 = [tau]_2

      // Left-hand side: C - [y]_1 = C - y * [1]_1
      const yG1 = G1Base.multiply(y);
      const cMinusY = C.subtract(yG1);

      // Right-hand side: [x - z]_2 = [tau]_2 - z * [1]_2
      const zG2 = G2Base.multiply(z);
      const xMinusZ = tauG2.subtract(zG2);

      // Bilinear pairing check: e(C - [y]_1, [1]_2) == e(proof, [x - z]_2)
      const lhs = bls12_381.pairing(cMinusY, G2Base);
      const rhs = bls12_381.pairing(proof, xMinusZ);

      const valid = bls12_381.fields.Fp12.eql(lhs, rhs);

      return {
        ok: true,
        valid,
        commitment: opening.commitment,
        z: zStr,
        y: yStr,
        proof: opening.proof,
        error: valid ? undefined : 'KZG pairing check e(C - [y]_1, [1]_2) == e(proof, [x - z]_2) did not hold',
      };
    } catch (err) {
      return {
        ok: false,
        valid: false,
        commitment: opening.commitment,
        z: zStr,
        y: yStr,
        proof: opening.proof,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }

  /**
   * Audits KZG commitments and opening proofs in stellar.toml.
   */
  auditToml(doc: Record<string, unknown>): Diagnostic[] {
    const diagnostics: Diagnostic[] = [];

    const kzgSection = (doc.KZG ?? doc.SOROBAN_STATE ?? doc.COMMITMENTS) as Record<string, unknown> | undefined;
    if (!kzgSection || typeof kzgSection !== 'object') {
      return diagnostics;
    }

    // Ingest SRS if provided in TOML
    if (kzgSection.srs && typeof kzgSection.srs === 'object') {
      try {
        this.loadSrs(kzgSection.srs as SrsData);
      } catch (err) {
        diagnostics.push({
          rule: KZG_SRS_UNLOADED,
          severity: 'error',
          category: 'security',
          message: `Failed to load KZG SRS from stellar.toml: ${err instanceof Error ? err.message : String(err)}`,
          path: 'KZG.srs',
          suggestion: 'Provide valid powers-of-tau SRS data in G1 and G2.',
        });
        return diagnostics;
      }
    }

    const openings = (kzgSection.proofs ?? kzgSection.commitments ?? [kzgSection]) as unknown[];
    if (Array.isArray(openings)) {
      openings.forEach((entry, idx) => {
        if (typeof entry !== 'object' || entry === null) return;
        const op = entry as Record<string, unknown>;
        if (!op.commitment || !op.proof || op.z === undefined || op.y === undefined) return;

        const path = `KZG.proofs[${idx}]`;

        if (this.g1Powers.length === 0) {
          diagnostics.push({
            rule: KZG_SRS_UNLOADED,
            severity: 'error',
            category: 'security',
            message: 'KZG verification requested but no structured reference string (SRS) was loaded',
            path,
            suggestion: 'Configure a trusted setup SRS (powers-of-tau) for the KZG commitment verifier.',
          });
          return;
        }

        const res = this.verify({
          commitment: op.commitment as string,
          proof: op.proof as string,
          z: op.z as string | bigint | number,
          y: op.y as string | bigint | number,
        });

        if (!res.ok) {
          diagnostics.push({
            rule: KZG_MALFORMED_COMMITMENT,
            severity: 'error',
            category: 'security',
            message: `Malformed KZG commitment or opening proof #${idx}: ${res.error}`,
            path,
            suggestion: 'Check that commitment and proof are valid BN254 G1 points.',
          });
        } else if (!res.valid) {
          diagnostics.push({
            rule: KZG_INVALID_PROOF,
            severity: 'error',
            category: 'security',
            message: `KZG polynomial opening evaluation proof #${idx} failed pairing check`,
            path,
            suggestion: 'Ensure proof satisfies e(C - [y]_1, [1]_2) == e(proof, [x - z]_2).',
          });
        }
      });
    }

    return diagnostics;
  }
}

/** Rule declarations */
export const kzgRules: Rule[] = [
  {
    id: KZG_INVALID_PROOF,
    category: 'security',
    severity: 'error',
    description: 'KZG polynomial opening proof must satisfy the elliptic curve pairing equation',
    run() {},
  },
  {
    id: KZG_SRS_UNLOADED,
    category: 'security',
    severity: 'error',
    description: 'A structured reference string (SRS / powers-of-tau) must be loaded to verify KZG commitments',
    run() {},
  },
  {
    id: KZG_MALFORMED_COMMITMENT,
    category: 'security',
    severity: 'error',
    description: 'KZG commitment and proof points must be valid BN254 curve points',
    run() {},
  },
];

export const kzgRuleIds: readonly string[] = kzgRules.map((r) => r.id);
