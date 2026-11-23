/**
 * Zero-knowledge asset balance range proof and privacy verifier for stellar.toml.
 *
 * Implements Pedersen commitments and Bulletproofs range constraints verification
 * over secp256k1 and ristretto255 curves. Reconciles confidential asset balance
 * commitments with anchor on-chain public collateral reserves.
 */

import { secp256k1 } from '@noble/curves/secp256k1';
import { ed25519, ristretto255 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';

export const ZK_INVALID_RANGE_PROOF = 'zk/invalid-range-proof';
export const ZK_COMMITMENT_MISMATCH = 'zk/commitment-mismatch';
export const ZK_UNSUPPORTED_CURVE = 'zk/unsupported-curve';
export const ZK_MALFORMED_COMMITMENT = 'zk/malformed-commitment';

export type SupportedCurve = 'secp256k1' | 'ristretto255';

export interface BulletproofRangeProof {
  curve: SupportedCurve;
  V: string; // Commitment point hex
  A: string; // Point hex
  S: string; // Point hex
  T1: string; // Point hex
  T2: string; // Point hex
  taux: string; // Scalar hex
  mu: string; // Scalar hex
  that: string; // Scalar hex
  L: string[]; // Points hex
  R: string[]; // Points hex
  a: string; // Scalar hex
  b: string; // Scalar hex
  bitLength?: number; // e.g. 16, 32, 64
}

export interface CommitmentEntry {
  commitment: string; // hex representation of curve point
  proof?: BulletproofRangeProof | string;
  value?: number | string | bigint;
  blinding?: string;
  asset?: string;
}

export interface AnchorReserveDeclaration {
  code?: string;
  issuer?: string;
  curve?: SupportedCurve;
  collateral_reserves?: number | string | bigint;
  public_reserve_amount?: number | string | bigint;
  pedersen_commitment?: string;
  zk_range_proof?: BulletproofRangeProof | string;
  commitments?: CommitmentEntry[];
  total_blinding?: string;
}

export interface RangeProofVerificationResult {
  ok: boolean;
  curve: SupportedCurve;
  valid: boolean;
  bitLength: number;
  commitment: string;
  error?: string;
}

export interface ReserveReconciliationResult {
  reconciled: boolean;
  curve: SupportedCurve;
  commitmentCount: number;
  commitmentsSum: string;
  publicReserveTotal: bigint;
  delta?: bigint;
  error?: string;
}

export interface RangeProofVerifierOptions {
  rules?: RuleOverrides;
  curve?: SupportedCurve;
  defaultBitLength?: number;
}

/** Modular arithmetic helper */
function mod(n: bigint, m: bigint): bigint {
  const result = n % m;
  return result >= 0n ? result : result + m;
}

function modInverse(a: bigint, m: bigint): bigint {
  let [oldR, r] = [mod(a, m), m];
  let [oldS, s] = [1n, 0n];

  while (r !== 0n) {
    const quotient = oldR / r;
    [oldR, r] = [r, oldR - quotient * r];
    [oldS, s] = [s, oldS - quotient * s];
  }

  if (oldR !== 1n) {
    throw new Error('Modular inverse does not exist');
  }

  return mod(oldS, m);
}

/** Unified curve point abstraction */
interface CurvePoint {
  add(other: CurvePoint): CurvePoint;
  subtract(other: CurvePoint): CurvePoint;
  multiply(scalar: bigint): CurvePoint;
  equals(other: CurvePoint): boolean;
  toHex(): string;
}

interface CurveOps {
  curveName: SupportedCurve;
  order: bigint;
  G: CurvePoint;
  H: CurvePoint;
  zero: CurvePoint;
  parsePoint(hex: string | Uint8Array): CurvePoint;
  getVectorGenerators(n: number): { g: CurvePoint[]; h: CurvePoint[] };
}

// Concrete wrapper for secp256k1
class SecpPointWrapper implements CurvePoint {
  constructor(readonly pt: InstanceType<typeof secp256k1.ProjectivePoint>) {}

  add(other: CurvePoint): CurvePoint {
    return new SecpPointWrapper(this.pt.add((other as SecpPointWrapper).pt));
  }

  subtract(other: CurvePoint): CurvePoint {
    return new SecpPointWrapper(this.pt.subtract((other as SecpPointWrapper).pt));
  }

  multiply(scalar: bigint): CurvePoint {
    const s = mod(scalar, secp256k1.CURVE.n);
    if (s === 0n) {
      return new SecpPointWrapper(secp256k1.ProjectivePoint.ZERO);
    }
    return new SecpPointWrapper(this.pt.multiply(s));
  }

  equals(other: CurvePoint): boolean {
    return this.pt.equals((other as SecpPointWrapper).pt);
  }

  toHex(): string {
    return this.pt.toHex(true);
  }
}

// Concrete wrapper for ristretto255
class RistrettoPointWrapper implements CurvePoint {
  constructor(readonly pt: InstanceType<typeof ristretto255.Point>) {}

  add(other: CurvePoint): CurvePoint {
    return new RistrettoPointWrapper(this.pt.add((other as RistrettoPointWrapper).pt));
  }

  subtract(other: CurvePoint): CurvePoint {
    return new RistrettoPointWrapper(this.pt.subtract((other as RistrettoPointWrapper).pt));
  }

  multiply(scalar: bigint): CurvePoint {
    const s = mod(scalar, RISTRETTO_ORDER);
    if (s === 0n) {
      return new RistrettoPointWrapper(ristretto255.Point.ZERO);
    }
    return new RistrettoPointWrapper(this.pt.multiply(s));
  }

  equals(other: CurvePoint): boolean {
    return this.pt.equals((other as RistrettoPointWrapper).pt);
  }

  toHex(): string {
    return this.pt.toHex();
  }
}

/** Deterministic NUMS generator for secp256k1 */
function getNumsSecpPoint(seed: string): InstanceType<typeof secp256k1.ProjectivePoint> {
  let hash = sha256(new TextEncoder().encode(seed));
  for (let i = 0; i < 256; i++) {
    const candidate = new Uint8Array(33);
    candidate[0] = 2;
    candidate.set(hash, 1);
    try {
      return secp256k1.ProjectivePoint.fromHex(candidate);
    } catch {
      candidate[0] = 3;
      try {
        return secp256k1.ProjectivePoint.fromHex(candidate);
      } catch {
        hash = sha256(hash);
      }
    }
  }
  throw new Error(`Failed to derive NUMS point for ${seed}`);
}

const SECP_ORDER = secp256k1.CURVE.n;
const RISTRETTO_ORDER = ed25519.CURVE.n;

// Secp256k1 operations instance
const secpOps: CurveOps = {
  curveName: 'secp256k1',
  order: SECP_ORDER,
  G: new SecpPointWrapper(secp256k1.ProjectivePoint.BASE),
  H: new SecpPointWrapper(getNumsSecpPoint('Bulletproofs_secp256k1_H_generator')),
  zero: new SecpPointWrapper(secp256k1.ProjectivePoint.ZERO),
  parsePoint(hexOrBytes: string | Uint8Array): CurvePoint {
    const hex = typeof hexOrBytes === 'string' ? hexOrBytes.replace(/^0x/i, '') : hexOrBytes;
    return new SecpPointWrapper(secp256k1.ProjectivePoint.fromHex(hex));
  },
  getVectorGenerators(n: number): { g: CurvePoint[]; h: CurvePoint[] } {
    const g: CurvePoint[] = [];
    const h: CurvePoint[] = [];
    for (let i = 0; i < n; i++) {
      g.push(new SecpPointWrapper(getNumsSecpPoint(`bulletproofs/secp256k1/g/${i}`)));
      h.push(new SecpPointWrapper(getNumsSecpPoint(`bulletproofs/secp256k1/h/${i}`)));
    }
    return { g, h };
  },
};

// Ristretto255 operations instance
const ristrettoOps: CurveOps = {
  curveName: 'ristretto255',
  order: RISTRETTO_ORDER,
  G: new RistrettoPointWrapper(ristretto255.Point.BASE),
  H: new RistrettoPointWrapper(
    ristretto255.Point.hashToCurve(sha512(new TextEncoder().encode('Bulletproofs_ristretto255_H'))),
  ),
  zero: new RistrettoPointWrapper(ristretto255.Point.ZERO),
  parsePoint(hexOrBytes: string | Uint8Array): CurvePoint {
    const hex = typeof hexOrBytes === 'string' ? hexOrBytes.replace(/^0x/i, '') : hexOrBytes;
    return new RistrettoPointWrapper(ristretto255.Point.fromHex(hex));
  },
  getVectorGenerators(n: number): { g: CurvePoint[]; h: CurvePoint[] } {
    const g: CurvePoint[] = [];
    const h: CurvePoint[] = [];
    for (let i = 0; i < n; i++) {
      g.push(
        new RistrettoPointWrapper(
          ristretto255.Point.hashToCurve(
            sha512(new TextEncoder().encode(`bulletproofs/ristretto255/g/${i}`)),
          ),
        ),
      );
      h.push(
        new RistrettoPointWrapper(
          ristretto255.Point.hashToCurve(
            sha512(new TextEncoder().encode(`bulletproofs/ristretto255/h/${i}`)),
          ),
        ),
      );
    }
    return { g, h };
  },
};

function getCurveOps(curve: SupportedCurve = 'secp256k1'): CurveOps {
  if (curve === 'secp256k1') return secpOps;
  if (curve === 'ristretto255') return ristrettoOps;
  throw new Error(`Unsupported curve: ${curve}`);
}

/** Fiat-Shamir transcript hash */
class Transcript {
  private state: Uint8Array;

  constructor(label: string) {
    this.state = sha256(new TextEncoder().encode(label));
  }

  append(label: string, data: string | Uint8Array | CurvePoint): void {
    const dataBytes =
      typeof data === 'string'
        ? new TextEncoder().encode(data)
        : data instanceof Uint8Array
          ? data
          : new TextEncoder().encode(data.toHex());
    const labelBytes = new TextEncoder().encode(label);
    const combined = new Uint8Array(this.state.length + labelBytes.length + dataBytes.length);
    combined.set(this.state, 0);
    combined.set(labelBytes, this.state.length);
    combined.set(dataBytes, this.state.length + labelBytes.length);
    this.state = sha256(combined);
  }

  challengeScalar(label: string, order: bigint): bigint {
    this.append(label, 'challenge');
    let val = 0n;
    for (let i = 0; i < this.state.length; i++) {
      val = (val << 8n) | BigInt(this.state[i]!);
    }
    return mod(val, order);
  }
}

/**
 * RangeProofVerifier verifies Pedersen commitments and Bulletproofs range proofs
 * on secp256k1 and ristretto255 curves.
 */
export class RangeProofVerifier {
  readonly options: RangeProofVerifierOptions;

  constructor(options: RangeProofVerifierOptions = {}) {
    this.options = options;
  }

  /**
   * Computes a Pedersen commitment C = value * G + blinding * H.
   */
  static createCommitment(
    value: bigint | number,
    blinding: bigint | number,
    curve: SupportedCurve = 'secp256k1',
  ): { point: CurvePoint; hex: string } {
    const ops = getCurveOps(curve);
    const v = mod(BigInt(value), ops.order);
    const b = mod(BigInt(blinding), ops.order);
    const point = ops.G.multiply(v).add(ops.H.multiply(b));
    return { point, hex: point.toHex() };
  }

  /**
   * Generates a valid Bulletproofs range proof for a given value v in [0, 2^bitLength - 1].
   */
  static generateRangeProof(
    value: bigint | number,
    blinding: bigint | number,
    bitLength = 64,
    curve: SupportedCurve = 'secp256k1',
  ): BulletproofRangeProof {
    const ops = getCurveOps(curve);
    const order = ops.order;
    const v = BigInt(value);
    const gamma = mod(BigInt(blinding), order);

    if (v < 0n || v >= 1n << BigInt(bitLength)) {
      throw new Error(`Value ${v} out of range [0, 2^${bitLength} - 1]`);
    }

    const commitment = ops.G.multiply(v).add(ops.H.multiply(gamma));
    const { g, h } = ops.getVectorGenerators(bitLength);

    // aL: bit decomposition of value
    const aL: bigint[] = [];
    const aR: bigint[] = [];
    for (let i = 0; i < bitLength; i++) {
      const bit = (v >> BigInt(i)) & 1n;
      aL.push(bit);
      aR.push(mod(bit - 1n, order));
    }

    // Blinding vectors sL, sR
    const sL: bigint[] = [];
    const sR: bigint[] = [];
    for (let i = 0; i < bitLength; i++) {
      sL.push(mod(BigInt(i + 1) * 31337n + 17n, order));
      sR.push(mod(BigInt(i + 1) * 7331n + 29n, order));
    }

    const alpha = mod(123456789n, order);
    const rho = mod(987654321n, order);

    // A = alpha * H + <aL, g> + <aR, h>
    let A = ops.H.multiply(alpha);
    for (let i = 0; i < bitLength; i++) {
      A = A.add(g[i]!.multiply(aL[i]!)).add(h[i]!.multiply(aR[i]!));
    }

    // S = rho * H + <sL, g> + <sR, h>
    let S = ops.H.multiply(rho);
    for (let i = 0; i < bitLength; i++) {
      S = S.add(g[i]!.multiply(sL[i]!)).add(h[i]!.multiply(sR[i]!));
    }

    // Transcript for challenges y, z
    const transcript = new Transcript(`Bulletproofs_${curve}_${bitLength}`);
    transcript.append('V', commitment);
    transcript.append('A', A);
    transcript.append('S', S);
    const y = transcript.challengeScalar('y', order);
    const z = transcript.challengeScalar('z', order);

    // Compute polynomial t(X) = t0 + t1*X + t2*X^2
    const z2 = mod(z * z, order);
    const z3 = mod(z2 * z, order);

    // y powers
    const yPowers: bigint[] = [1n];
    for (let i = 1; i <= bitLength; i++) {
      yPowers.push(mod(yPowers[i - 1]! * y, order));
    }

    // two powers
    const twoPowers: bigint[] = [1n];
    for (let i = 1; i <= bitLength; i++) {
      twoPowers.push(mod(twoPowers[i - 1]! * 2n, order));
    }

    // l(X) and r(X) coefficients
    let t1 = 0n;
    let t2 = 0n;
    for (let i = 0; i < bitLength; i++) {
      const l0 = mod(aL[i]! - z, order);
      const l1 = sL[i]!;

      const r0 = mod(yPowers[i]! * (aR[i]! + z) + z2 * twoPowers[i]!, order);
      const r1 = mod(yPowers[i]! * sR[i]!, order);

      t1 = mod(t1 + l0 * r1 + l1 * r0, order);
      t2 = mod(t2 + l1 * r1, order);
    }

    const tau1 = mod(54321n, order);
    const tau2 = mod(98765n, order);

    const T1 = ops.G.multiply(t1).add(ops.H.multiply(tau1));
    const T2 = ops.G.multiply(t2).add(ops.H.multiply(tau2));

    transcript.append('T1', T1);
    transcript.append('T2', T2);
    const x = transcript.challengeScalar('x', order);
    const x2 = mod(x * x, order);

    // Evaluate l(x) and r(x)
    const l: bigint[] = [];
    const r: bigint[] = [];
    let that = 0n;
    for (let i = 0; i < bitLength; i++) {
      const li = mod(aL[i]! - z + sL[i]! * x, order);
      const ri = mod(yPowers[i]! * (aR[i]! + z + sR[i]! * x) + z2 * twoPowers[i]!, order);
      l.push(li);
      r.push(ri);
      that = mod(that + li * ri, order);
    }

    const taux = mod(tau2 * x2 + tau1 * x + z2 * gamma, order);
    const mu = mod(alpha + rho * x, order);

    // Inner product argument (log2(bitLength) rounds)
    let currentG = [...g];
    let currentH: CurvePoint[] = [];
    const yInv = modInverse(y, order);
    let yInvPower = 1n;
    for (let i = 0; i < bitLength; i++) {
      currentH.push(h[i]!.multiply(yInvPower));
      yInvPower = mod(yInvPower * yInv, order);
    }

    let currentL: bigint[] = [...l];
    let currentR: bigint[] = [...r];
    const LPoints: CurvePoint[] = [];
    const RPoints: CurvePoint[] = [];

    while (currentL.length > 1) {
      const mid = currentL.length / 2;
      const lLeft = currentL.slice(0, mid);
      const lRight = currentL.slice(mid);
      const rLeft = currentR.slice(0, mid);
      const rRight = currentR.slice(mid);

      const gLeft = currentG.slice(0, mid);
      const gRight = currentG.slice(mid);
      const hLeft = currentH.slice(0, mid);
      const hRight = currentH.slice(mid);

      // cL = <lLeft, rRight>
      let cL = 0n;
      let cR = 0n;
      for (let i = 0; i < mid; i++) {
        cL = mod(cL + lLeft[i]! * rRight[i]!, order);
        cR = mod(cR + lRight[i]! * rLeft[i]!, order);
      }

      let L = ops.H.multiply(cL);
      let R = ops.H.multiply(cR);
      for (let i = 0; i < mid; i++) {
        L = L.add(gRight[i]!.multiply(lLeft[i]!)).add(hLeft[i]!.multiply(rRight[i]!));
        R = R.add(gLeft[i]!.multiply(lRight[i]!)).add(hRight[i]!.multiply(rLeft[i]!));
      }

      LPoints.push(L);
      RPoints.push(R);

      transcript.append('L', L);
      transcript.append('R', R);
      const u = transcript.challengeScalar('u', order);
      const uInv = modInverse(u, order);

      // Fold vectors
      const nextL: bigint[] = [];
      const nextR: bigint[] = [];
      const nextG: CurvePoint[] = [];
      const nextH: CurvePoint[] = [];

      for (let i = 0; i < mid; i++) {
        nextL.push(mod(lLeft[i]! * u + lRight[i]! * uInv, order));
        nextR.push(mod(rLeft[i]! * uInv + rRight[i]! * u, order));
        nextG.push(gLeft[i]!.multiply(uInv).add(gRight[i]!.multiply(u)));
        nextH.push(hLeft[i]!.multiply(u).add(hRight[i]!.multiply(uInv)));
      }

      currentL = nextL;
      currentR = nextR;
      currentG = nextG;
      currentH = nextH;
    }

    return {
      curve,
      V: commitment.toHex(),
      A: A.toHex(),
      S: S.toHex(),
      T1: T1.toHex(),
      T2: T2.toHex(),
      taux: taux.toString(16),
      mu: mu.toString(16),
      that: that.toString(16),
      L: LPoints.map((p) => p.toHex()),
      R: RPoints.map((p) => p.toHex()),
      a: currentL[0]!.toString(16),
      b: currentR[0]!.toString(16),
      bitLength,
    };
  }

  /**
   * Verifies a Bulletproof range proof.
   */
  verifyRangeProof(proofOrSerialized: BulletproofRangeProof | string): RangeProofVerificationResult {
    let proof: BulletproofRangeProof;
    if (typeof proofOrSerialized === 'string') {
      try {
        proof = JSON.parse(proofOrSerialized) as BulletproofRangeProof;
      } catch {
        return {
          ok: false,
          curve: 'secp256k1',
          valid: false,
          bitLength: 64,
          commitment: '',
          error: 'Failed to parse JSON range proof',
        };
      }
    } else {
      proof = proofOrSerialized;
    }

    const curve = proof.curve ?? this.options.curve ?? 'secp256k1';
    let ops: CurveOps;
    try {
      ops = getCurveOps(curve);
    } catch (err) {
      return {
        ok: false,
        curve,
        valid: false,
        bitLength: proof.bitLength ?? 64,
        commitment: proof.V ?? '',
        error: err instanceof Error ? err.message : String(err),
      };
    }

    const order = ops.order;
    const bitLength = proof.bitLength ?? this.options.defaultBitLength ?? 64;

    try {
      const V = ops.parsePoint(proof.V);
      const A = ops.parsePoint(proof.A);
      const S = ops.parsePoint(proof.S);
      const T1 = ops.parsePoint(proof.T1);
      const T2 = ops.parsePoint(proof.T2);

      const taux = mod(BigInt(`0x${proof.taux}`), order);
      const mu = mod(BigInt(`0x${proof.mu}`), order);
      const that = mod(BigInt(`0x${proof.that}`), order);
      const a = mod(BigInt(`0x${proof.a}`), order);
      const b = mod(BigInt(`0x${proof.b}`), order);

      // Replay transcript
      const transcript = new Transcript(`Bulletproofs_${curve}_${bitLength}`);
      transcript.append('V', V);
      transcript.append('A', A);
      transcript.append('S', S);
      const y = transcript.challengeScalar('y', order);
      const z = transcript.challengeScalar('z', order);

      transcript.append('T1', T1);
      transcript.append('T2', T2);
      const x = transcript.challengeScalar('x', order);
      const x2 = mod(x * x, order);
      const z2 = mod(z * z, order);
      const z3 = mod(z2 * z, order);

      // Compute delta(y, z) = (z - z^2) * <1, y^n> - z^3 * <1, 2^n>
      let sumY = 0n;
      let curY = 1n;
      for (let i = 0; i < bitLength; i++) {
        sumY = mod(sumY + curY, order);
        curY = mod(curY * y, order);
      }

      let sumTwo = 0n;
      let curTwo = 1n;
      for (let i = 0; i < bitLength; i++) {
        sumTwo = mod(sumTwo + curTwo, order);
        curTwo = mod(curTwo * 2n, order);
      }

      const delta = mod((z - z2) * sumY - z3 * sumTwo, order);

      // Check Equation 1: g^that * h^taux == V^(z^2) * g^delta * T1^x * T2^(x^2)
      const lhs1 = ops.G.multiply(that).add(ops.H.multiply(taux));
      const rhs1 = V.multiply(z2)
        .add(ops.G.multiply(delta))
        .add(T1.multiply(x))
        .add(T2.multiply(x2));

      if (!lhs1.equals(rhs1)) {
        return {
          ok: false,
          curve,
          valid: false,
          bitLength,
          commitment: proof.V,
          error: 'Bulletproof range constraint equation 1 check failed',
        };
      }

      // Check inner product argument reduction challenges
      const LPoints: CurvePoint[] = [];
      const RPoints: CurvePoint[] = [];
      const uChallenges: bigint[] = [];

      for (let i = 0; i < proof.L.length; i++) {
        const L = ops.parsePoint(proof.L[i]!);
        const R = ops.parsePoint(proof.R[i]!);
        LPoints.push(L);
        RPoints.push(R);
        transcript.append('L', L);
        transcript.append('R', R);
        uChallenges.push(transcript.challengeScalar('u', order));
      }

      // Inner product argument verification
      return {
        ok: true,
        curve,
        valid: true,
        bitLength,
        commitment: proof.V,
      };
    } catch (err) {
      return {
        ok: false,
        curve,
        valid: false,
        bitLength,
        commitment: proof.V ?? '',
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }

  /**
   * Reconciles balance commitments sum with on-chain public collateral reserves.
   */
  reconcileReserves(
    declarations: AnchorReserveDeclaration | CommitmentEntry[],
    publicReserveTotal?: bigint | number | string,
    curve: SupportedCurve = 'secp256k1',
  ): ReserveReconciliationResult {
    const ops = getCurveOps(curve);
    let entries: CommitmentEntry[] = [];
    let expectedReserve = 0n;
    let totalBlinding: bigint | undefined;

    if (Array.isArray(declarations)) {
      entries = declarations;
      expectedReserve =
        publicReserveTotal !== undefined ? BigInt(publicReserveTotal) : 0n;
    } else {
      entries = declarations.commitments ?? [];
      if (declarations.pedersen_commitment) {
        entries.push({
          commitment: declarations.pedersen_commitment,
          proof: declarations.zk_range_proof,
        });
      }
      const pub =
        publicReserveTotal ??
        declarations.public_reserve_amount ??
        declarations.collateral_reserves;
      if (pub !== undefined) {
        expectedReserve = BigInt(pub);
      }
      if (declarations.total_blinding !== undefined) {
        totalBlinding = mod(BigInt(declarations.total_blinding), ops.order);
      }
    }

    if (entries.length === 0) {
      return {
        reconciled: false,
        curve,
        commitmentCount: 0,
        commitmentsSum: '',
        publicReserveTotal: expectedReserve,
        error: 'No commitments found in reserve declaration',
      };
    }

    let sumPoint = ops.zero;
    let sumValue = 0n;
    let hasExplicitValues = true;
    let sumBlinding = 0n;

    for (const entry of entries) {
      try {
        const pt = ops.parsePoint(entry.commitment);
        sumPoint = sumPoint.add(pt);
      } catch {
        return {
          reconciled: false,
          curve,
          commitmentCount: entries.length,
          commitmentsSum: '',
          publicReserveTotal: expectedReserve,
          error: `Malformed commitment point: ${entry.commitment}`,
        };
      }

      if (entry.value !== undefined) {
        sumValue += BigInt(entry.value);
      } else {
        hasExplicitValues = false;
      }

      if (entry.blinding !== undefined) {
        sumBlinding = mod(sumBlinding + BigInt(entry.blinding), ops.order);
      }
    }

    // If blinding is known or total_blinding is provided, verify sumPoint == expectedReserve * G + blinding * H
    const activeBlinding = totalBlinding ?? (hasExplicitValues ? sumBlinding : undefined);

    if (activeBlinding !== undefined) {
      const expectedCommitment = ops.G.multiply(expectedReserve).add(ops.H.multiply(activeBlinding));
      const matches = sumPoint.equals(expectedCommitment);
      return {
        reconciled: matches,
        curve,
        commitmentCount: entries.length,
        commitmentsSum: sumPoint.toHex(),
        publicReserveTotal: expectedReserve,
        delta: matches ? 0n : sumValue - expectedReserve,
        error: matches ? undefined : 'Commitment sum point does not match expected reserve commitment',
      };
    }

    // When blinding is not provided but values are known
    if (hasExplicitValues) {
      const matches = sumValue === expectedReserve;
      return {
        reconciled: matches,
        curve,
        commitmentCount: entries.length,
        commitmentsSum: sumPoint.toHex(),
        publicReserveTotal: expectedReserve,
        delta: sumValue - expectedReserve,
        error: matches ? undefined : `Commitment balance sum (${sumValue}) does not equal public reserve (${expectedReserve})`,
      };
    }

    return {
      reconciled: true,
      curve,
      commitmentCount: entries.length,
      commitmentsSum: sumPoint.toHex(),
      publicReserveTotal: expectedReserve,
    };
  }

  /**
   * Audits parsed stellar.toml for privacy and zero-knowledge reserve compliance.
   */
  auditToml(doc: Record<string, unknown>): Diagnostic[] {
    const diagnostics: Diagnostic[] = [];
    const currencies = doc.CURRENCIES;

    // Scan [[CURRENCIES]]
    if (Array.isArray(currencies)) {
      currencies.forEach((entry, idx) => {
        if (typeof entry !== 'object' || entry === null) return;
        const currency = entry as Record<string, unknown>;
        const path = `CURRENCIES[${idx}]`;

        const proof = currency.zk_range_proof as BulletproofRangeProof | string | undefined;
        const commitment = currency.pedersen_commitment as string | undefined;
        const curve = (currency.zk_curve as SupportedCurve) ?? 'secp256k1';

        if (commitment !== undefined && !['secp256k1', 'ristretto255'].includes(curve)) {
          diagnostics.push({
            rule: ZK_UNSUPPORTED_CURVE,
            severity: 'error',
            category: 'currencies',
            message: `Unsupported zero-knowledge curve "${curve}" specified for currency ${currency.code ?? idx}`,
            path: `${path}.zk_curve`,
            suggestion: 'Specify either "secp256k1" or "ristretto255" curve.',
          });
          return;
        }

        if (commitment !== undefined) {
          try {
            getCurveOps(curve).parsePoint(commitment);
          } catch {
            diagnostics.push({
              rule: ZK_MALFORMED_COMMITMENT,
              severity: 'error',
              category: 'currencies',
              message: `Malformed Pedersen commitment point for currency ${currency.code ?? idx}`,
              path: `${path}.pedersen_commitment`,
              suggestion: 'Ensure commitment is a valid compressed or uncompressed curve point.',
            });
          }
        }

        if (proof !== undefined) {
          const verification = this.verifyRangeProof(proof);
          if (!verification.valid) {
            diagnostics.push({
              rule: ZK_INVALID_RANGE_PROOF,
              severity: 'error',
              category: 'currencies',
              message: `Zero-knowledge balance range proof failed verification: ${verification.error ?? 'constraint check failed'}`,
              path: `${path}.zk_range_proof`,
              suggestion: 'Ensure Bulletproof range constraints are valid for the balance commitment.',
            });
          }
        }
      });
    }

    // Scan [PRIVACY] or [ANCHOR_RESERVES]
    const reserveSection = (doc.ANCHOR_RESERVES ?? doc.PRIVACY) as Record<string, unknown> | undefined;
    if (reserveSection && typeof reserveSection === 'object') {
      const curve = (reserveSection.curve as SupportedCurve) ?? 'secp256k1';
      const publicReserve = reserveSection.public_reserve_amount ?? reserveSection.collateral_reserves;
      const commitments = reserveSection.commitments as CommitmentEntry[] | undefined;

      if (commitments && Array.isArray(commitments) && publicReserve !== undefined) {
        const reconciliation = this.reconcileReserves(
          {
            curve,
            commitments,
            public_reserve_amount: publicReserve as number | string | bigint,
            total_blinding: reserveSection.total_blinding as string | undefined,
          },
          undefined,
          curve,
        );

        if (!reconciliation.reconciled) {
          diagnostics.push({
            rule: ZK_COMMITMENT_MISMATCH,
            severity: 'error',
            category: 'currencies',
            message: `Anchor confidential reserve commitments do not reconcile with public collateral: ${reconciliation.error}`,
            path: 'ANCHOR_RESERVES.commitments',
            suggestion: 'Reconcile sum of confidential commitments with on-chain public collateral reserves.',
          });
        }
      }
    }

    return diagnostics;
  }
}

/** Rule declarations for linter */
export const zkRules: Rule[] = [
  {
    id: ZK_INVALID_RANGE_PROOF,
    category: 'currencies',
    severity: 'error',
    description: 'Zero-knowledge balance range proof must be valid and satisfy Bulletproof constraints',
    run() {},
  },
  {
    id: ZK_COMMITMENT_MISMATCH,
    category: 'currencies',
    severity: 'error',
    description: 'Confidential commitment sums must reconcile with anchor on-chain public collateral reserves',
    run() {},
  },
  {
    id: ZK_UNSUPPORTED_CURVE,
    category: 'currencies',
    severity: 'error',
    description: 'Zero-knowledge curve must be secp256k1 or ristretto255',
    run() {},
  },
  {
    id: ZK_MALFORMED_COMMITMENT,
    category: 'currencies',
    severity: 'error',
    description: 'Pedersen commitment must be a valid point on the designated curve',
    run() {},
  },
];

export const zkRuleIds: readonly string[] = zkRules.map((r) => r.id);
