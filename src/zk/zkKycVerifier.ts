/**
 * Zero-knowledge proof verification engine for anonymous anchor KYC attestation.
 *
 * Implements:
 *  - stellar.toml inspection for [ZK_VERIFICATION] declarations (proving system, verification key URI)
 *  - Groth16 verification key parsing and BN254 / BLS12-381 curve point validation
 *  - Public input alignment checks (gamma_abc length vs declared input count)
 *  - Synthetic Groth16 proof payload generation and structural validation
 *  - Pairing equation verification: e(A, B) == e(alpha, beta) * e(vk, gamma) * e(C, delta)
 *  - CLI command: stellar-toml-lint verify-zk-kyc --domain <domain>
 *
 * Design note: Groth16 pairings require BN254 (bn256) or BLS12-381, both provided
 * by @noble/curves without native binaries, keeping the module fully pure-JS/TS.
 */

import { bls12_381 } from '@noble/curves/bls12-381';
import { bn254 } from '@noble/curves/bn254';
import { sha256 } from '@noble/hashes/sha256';
import type { Diagnostic, Rule } from '../types.js';

// ── Rule IDs ──────────────────────────────────────────────────────────────────

export const ZK_KYC_UNSUPPORTED_CURVE = 'zk-kyc/unsupported-curve';
export const ZK_KYC_INVALID_VK_POINT = 'zk-kyc/invalid-vk-curve-point';
export const ZK_KYC_PUBLIC_INPUT_MISMATCH = 'zk-kyc/public-input-count-mismatch';
export const ZK_KYC_PROOF_INVALID = 'zk-kyc/proof-verification-failed';
export const ZK_KYC_MISSING_ENDPOINT = 'zk-kyc/missing-verification-endpoint';

// ── Public types ──────────────────────────────────────────────────────────────

export type ZkProvingSystem = 'groth16' | 'plonk';
export type ZkCurve = 'bn254' | 'bls12-381';

export interface Groth16VerificationKey {
  protocol: 'groth16';
  curve: ZkCurve;
  nPublic: number;
  vk_alpha_1: string[];
  vk_beta_2: string[][];
  vk_gamma_2: string[][];
  vk_delta_2: string[][];
  IC: string[][];
}

export interface Groth16Proof {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
  protocol?: 'groth16';
  curve?: ZkCurve;
}

export interface ZkVerificationKeyParseResult {
  valid: boolean;
  curve: ZkCurve;
  provingSystem: ZkProvingSystem;
  nPublic: number;
  icLength: number;
  issues: string[];
}

export interface ZkProofVerifyResult {
  valid: boolean;
  provingSystem: ZkProvingSystem;
  curve: ZkCurve;
  error?: string;
}

export interface ZkKycDeclaration {
  proving_system: ZkProvingSystem;
  curve: ZkCurve;
  verification_key_uri?: string;
  verification_endpoint?: string;
  n_public_inputs?: number;
  verification_key?: Groth16VerificationKey;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function hexToBigInt(hex: string): bigint {
  const clean = hex.replace(/^0x/i, '') || '0';
  return BigInt('0x' + clean);
}

function coordsToG1Point_bn254(coords: string[]): ReturnType<typeof bn254.G1.ProjectivePoint.BASE.add> {
  if (coords.length < 2) throw new Error('G1 point requires at least 2 coordinates');
  const x = hexToBigInt(coords[0]!);
  const y = hexToBigInt(coords[1]!);
  const pt = bn254.G1.ProjectivePoint.fromAffine({ x, y });
  if (pt.equals(bn254.G1.ProjectivePoint.ZERO)) throw new Error('G1 point is the identity element');
  pt.assertValidity();
  return pt;
}

function coordsToG2Point_bn254(coords: string[][]): ReturnType<typeof bn254.G2.ProjectivePoint.BASE.add> {
  if (coords.length < 2 || coords[0]!.length < 2 || coords[1]!.length < 2) {
    throw new Error('G2 point requires Fp2 coordinates [[x0, x1], [y0, y1]]');
  }
  const x = { c0: hexToBigInt(coords[0]![0]!), c1: hexToBigInt(coords[0]![1]!) };
  const y = { c0: hexToBigInt(coords[1]![0]!), c1: hexToBigInt(coords[1]![1]!) };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const pt = bn254.G2.ProjectivePoint.fromAffine({ x, y } as any);
  if (pt.equals(bn254.G2.ProjectivePoint.ZERO)) throw new Error('G2 point is the identity element');
  pt.assertValidity();
  return pt;
}

// ── Main verifier ─────────────────────────────────────────────────────────────

export class ZkKycAttestationVerifier {
  /**
   * Parses and validates the structural integrity of a Groth16 verification key.
   * Validates:
   *  - Proving system and curve declarations
   *  - That all IC points are valid curve points
   *  - That IC.length == nPublic + 1
   */
  static parseVerificationKey(vk: Groth16VerificationKey): ZkVerificationKeyParseResult {
    const issues: string[] = [];
    const curve = vk.curve ?? 'bn254';
    const provingSystem = vk.protocol ?? 'groth16';

    if (provingSystem !== 'groth16') {
      issues.push(`Unsupported proving system: ${provingSystem}`);
    }
    if (!['bn254', 'bls12-381'].includes(curve)) {
      issues.push(`Unsupported curve: ${curve}. Expected bn254 or bls12-381`);
    }

    if (vk.IC.length !== vk.nPublic + 1) {
      issues.push(`IC array length (${vk.IC.length}) must be nPublic + 1 (${vk.nPublic + 1})`);
    }

    // Validate alpha_1, IC points on G1
    const g1Points: Array<{ name: string; coords: string[] }> = [
      { name: 'vk_alpha_1', coords: vk.vk_alpha_1 },
      ...vk.IC.map((ic, i) => ({ name: `IC[${i}]`, coords: ic })),
    ];

    for (const { name, coords } of g1Points) {
      try {
        if (curve === 'bn254') {
          coordsToG1Point_bn254(coords);
        } else {
          const hex = coords[0]!.replace(/^0x/i, '').padStart(96, '0');
          bls12_381.G1.ProjectivePoint.fromHex(hex).assertValidity();
        }
      } catch (err) {
        issues.push(`${name}: invalid G1 point — ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    // Validate beta_2, gamma_2, delta_2 on G2
    const g2Points: Array<{ name: string; coords: string[][] }> = [
      { name: 'vk_beta_2', coords: vk.vk_beta_2 },
      { name: 'vk_gamma_2', coords: vk.vk_gamma_2 },
      { name: 'vk_delta_2', coords: vk.vk_delta_2 },
    ];

    for (const { name, coords } of g2Points) {
      try {
        if (curve === 'bn254') {
          coordsToG2Point_bn254(coords);
        } else {
          const x0 = (coords[0]?.[0] ?? '').replace(/^0x/i, '').padStart(96, '0');
          const x1 = (coords[0]?.[1] ?? '').replace(/^0x/i, '').padStart(96, '0');
          bls12_381.G2.ProjectivePoint.fromHex(x0 + x1).assertValidity();
        }
      } catch (err) {
        issues.push(`${name}: invalid G2 point — ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    return {
      valid: issues.length === 0,
      curve,
      provingSystem,
      nPublic: vk.nPublic,
      icLength: vk.IC.length,
      issues,
    };
  }

  /**
   * Generates a synthetic Groth16 proof payload for testing verification endpoints.
   * The points are well-formed (on the curve) but encode no real witness.
   */
  static generateSyntheticProof(vk: Groth16VerificationKey): Groth16Proof {
    const curve = vk.curve ?? 'bn254';

    if (curve === 'bn254') {
      const { x: g1x, y: g1y } = bn254.G1.ProjectivePoint.BASE.toAffine();
      const g2aff = bn254.G2.ProjectivePoint.BASE.toAffine();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const g2x = g2aff.x as any as { c0: bigint; c1: bigint };
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const g2y = g2aff.y as any as { c0: bigint; c1: bigint };

      const pi_a = [g1x.toString(16).padStart(64, '0'), g1y.toString(16).padStart(64, '0')];
      const pi_b = [
        [g2x.c0.toString(16).padStart(64, '0'), g2x.c1.toString(16).padStart(64, '0')],
        [g2y.c0.toString(16).padStart(64, '0'), g2y.c1.toString(16).padStart(64, '0')],
      ];
      const pi_c = pi_a;
      return { pi_a, pi_b, pi_c, protocol: 'groth16', curve: 'bn254' };
    } else {
      const G1 = bls12_381.G1.ProjectivePoint.BASE.toRawBytes(true);
      const G2 = bls12_381.G2.ProjectivePoint.BASE.toRawBytes(true);
      const g1Hex = Array.from(G1).map((b) => b.toString(16).padStart(2, '0')).join('');
      const g2Hex = Array.from(G2).map((b) => b.toString(16).padStart(2, '0')).join('');
      return {
        pi_a: [g1Hex],
        pi_b: [[g2Hex.slice(0, 96), g2Hex.slice(96)]],
        pi_c: [g1Hex],
        protocol: 'groth16',
        curve: 'bls12-381',
      };
    }
  }

  /**
   * Verifies a Groth16 proof against a verification key and public inputs.
   *
   * Groth16 equation: e(A, B) == e(alpha, beta) * e(vk, gamma) * e(C, delta)
   * where vk = sum_i (inputs[i] * IC[i]) and inputs[0] = 1 (constant term).
   */
  verifyGroth16Proof(
    proof: Groth16Proof,
    vk: Groth16VerificationKey,
    publicInputs: (bigint | string)[],
  ): ZkProofVerifyResult {
    const curve = vk.curve ?? 'bn254';

    if (!['bn254', 'bls12-381'].includes(curve)) {
      return { valid: false, provingSystem: 'groth16', curve, error: `Unsupported curve: ${curve}` };
    }

    if (publicInputs.length !== vk.nPublic) {
      return {
        valid: false,
        provingSystem: 'groth16',
        curve,
        error: `Public input count mismatch: got ${publicInputs.length}, expected ${vk.nPublic}`,
      };
    }

    try {
      if (curve === 'bn254') {
        return this._verifyGroth16Bn254(proof, vk, publicInputs);
      } else {
        return this._verifyGroth16Bls12381(proof, vk, publicInputs);
      }
    } catch (err) {
      return { valid: false, provingSystem: 'groth16', curve, error: err instanceof Error ? err.message : String(err) };
    }
  }

  private _verifyGroth16Bn254(
    proof: Groth16Proof,
    vk: Groth16VerificationKey,
    publicInputs: (bigint | string)[],
  ): ZkProofVerifyResult {
    const A = coordsToG1Point_bn254(proof.pi_a);
    const B = coordsToG2Point_bn254(proof.pi_b);
    const C = coordsToG1Point_bn254(proof.pi_c);

    const alpha = coordsToG1Point_bn254(vk.vk_alpha_1);
    const beta  = coordsToG2Point_bn254(vk.vk_beta_2);
    const gamma = coordsToG2Point_bn254(vk.vk_gamma_2);
    const delta = coordsToG2Point_bn254(vk.vk_delta_2);

    // vkIC = IC[0] + sum_i(input_i * IC[i+1])
    let vkIC = coordsToG1Point_bn254(vk.IC[0]!);
    for (let i = 0; i < publicInputs.length; i++) {
      const scalar = BigInt(publicInputs[i]!);
      const ICi = coordsToG1Point_bn254(vk.IC[i + 1]!);
      vkIC = vkIC.add(ICi.multiply(scalar));
    }

    // e(A, B) must equal e(alpha, beta) * e(vkIC, gamma) * e(C, delta)
    const lhs = bn254.pairing(A, B);
    const rhs = bn254.fields.Fp12.mul(
      bn254.fields.Fp12.mul(bn254.pairing(alpha, beta), bn254.pairing(vkIC, gamma)),
      bn254.pairing(C, delta),
    );

    const valid = bn254.fields.Fp12.eql(lhs, rhs);
    return { valid, provingSystem: 'groth16', curve: 'bn254', error: valid ? undefined : 'Groth16 BN254 pairing equation failed' };
  }

  private _verifyGroth16Bls12381(
    proof: Groth16Proof,
    vk: Groth16VerificationKey,
    publicInputs: (bigint | string)[],
  ): ZkProofVerifyResult {
    const toG1 = (c: string[]) => bls12_381.G1.ProjectivePoint.fromHex(c[0]!.replace(/^0x/i, '').padStart(96, '0'));
    const toG2 = (c: string[][]) => {
      const x = (c[0]?.[0] ?? '').replace(/^0x/i, '').padStart(96, '0') + (c[0]?.[1] ?? '').replace(/^0x/i, '').padStart(96, '0');
      return bls12_381.G2.ProjectivePoint.fromHex(x);
    };

    const A = toG1(proof.pi_a);
    const B = toG2(proof.pi_b);
    const C = toG1(proof.pi_c);

    const alpha = toG1(vk.vk_alpha_1);
    const beta  = toG2(vk.vk_beta_2);
    const gamma = toG2(vk.vk_gamma_2);
    const delta = toG2(vk.vk_delta_2);

    let vkIC = toG1(vk.IC[0]!);
    for (let i = 0; i < publicInputs.length; i++) {
      const scalar = BigInt(publicInputs[i]!);
      vkIC = vkIC.add(toG1(vk.IC[i + 1]!).multiply(scalar));
    }

    const lhs = bls12_381.pairing(A, B);
    const rhs = bls12_381.fields.Fp12.mul(
      bls12_381.fields.Fp12.mul(bls12_381.pairing(alpha, beta), bls12_381.pairing(vkIC, gamma)),
      bls12_381.pairing(C, delta),
    );

    const valid = bls12_381.fields.Fp12.eql(lhs, rhs);
    return { valid, provingSystem: 'groth16', curve: 'bls12-381', error: valid ? undefined : 'Groth16 BLS12-381 pairing equation failed' };
  }

  /**
   * Inspects stellar.toml for [ZK_VERIFICATION] declarations and returns diagnostics.
   */
  auditToml(doc: Record<string, unknown>): Diagnostic[] {
    const diagnostics: Diagnostic[] = [];
    const zkSection = doc.ZK_VERIFICATION as Record<string, unknown> | ZkKycDeclaration | undefined;
    if (!zkSection || typeof zkSection !== 'object') return diagnostics;

    const decl = zkSection as ZkKycDeclaration;
    const curve = decl.curve ?? 'bn254';
    const field = 'ZK_VERIFICATION';

    if (!['bn254', 'bls12-381'].includes(curve)) {
      diagnostics.push({
        rule: ZK_KYC_UNSUPPORTED_CURVE,
        severity: 'error',
        category: 'security',
        message: `Unsupported ZK curve "${curve}" in ZK_VERIFICATION; expected bn254 or bls12-381`,
        path: `${field}.curve`,
        suggestion: 'Use either "bn254" (BN254/BN256) or "bls12-381" as the proving curve.',
      });
    }

    if (!decl.verification_endpoint && !decl.verification_key_uri) {
      diagnostics.push({
        rule: ZK_KYC_MISSING_ENDPOINT,
        severity: 'warning',
        category: 'security',
        message: 'ZK_VERIFICATION section is missing both verification_endpoint and verification_key_uri',
        path: field,
        suggestion: 'Provide a verification_endpoint URL or a verification_key_uri to allow auditors to verify proofs.',
      });
    }

    if (decl.verification_key) {
      const vk = decl.verification_key;
      const parseResult = ZkKycAttestationVerifier.parseVerificationKey(vk);
      parseResult.issues.forEach((issue) => {
        diagnostics.push({
          rule: issue.includes('nPublic') ? ZK_KYC_PUBLIC_INPUT_MISMATCH : ZK_KYC_INVALID_VK_POINT,
          severity: 'error',
          category: 'security',
          message: `ZK_VERIFICATION verification_key: ${issue}`,
          path: `${field}.verification_key`,
          suggestion: 'Ensure all curve points in the verification key are valid, and IC.length == nPublic + 1.',
        });
      });
    }

    return diagnostics;
  }

  /**
   * Hashes a KYC attestation claim to a 32-byte field element for use as a public input.
   */
  static hashClaimToFieldElement(claim: Record<string, unknown>, curve: ZkCurve = 'bn254'): bigint {
    const json = JSON.stringify(claim, Object.keys(claim).sort());
    const hash = sha256(new TextEncoder().encode(json));
    const p = curve === 'bn254'
      ? 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n
      : 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;
    let n = 0n;
    for (const b of hash) n = (n << 8n) | BigInt(b);
    return n % p;
  }
}

// ── Rule declarations ─────────────────────────────────────────────────────────

export const zkKycRules: Rule[] = [
  {
    id: ZK_KYC_UNSUPPORTED_CURVE,
    category: 'security',
    severity: 'error',
    description: 'ZK KYC verification key must use a supported elliptic curve (BN254 or BLS12-381)',
    run() {},
  },
  {
    id: ZK_KYC_INVALID_VK_POINT,
    category: 'security',
    severity: 'error',
    description: 'ZK KYC verification key contains an invalid curve point',
    run() {},
  },
  {
    id: ZK_KYC_PUBLIC_INPUT_MISMATCH,
    category: 'security',
    severity: 'error',
    description: 'ZK KYC verification key IC array length must equal nPublic + 1',
    run() {},
  },
  {
    id: ZK_KYC_PROOF_INVALID,
    category: 'security',
    severity: 'error',
    description: 'ZK KYC proof failed Groth16 pairing equation verification',
    run() {},
  },
  {
    id: ZK_KYC_MISSING_ENDPOINT,
    category: 'security',
    severity: 'warning',
    description: 'ZK_VERIFICATION section should declare a verification_endpoint or verification_key_uri',
    run() {},
  },
];

export const zkKycRuleIds: readonly string[] = zkKycRules.map((r) => r.id);
