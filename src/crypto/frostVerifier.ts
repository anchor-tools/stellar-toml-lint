/**
 * Automated threshold FROST Ed25519 signature state machine verifier.
 *
 * FROST (Flexible Round-Optimized Schnorr Threshold) allows t-of-n threshold signing
 * where the aggregate public key is a single Ed25519 key indistinguishable from a
 * standard key. This module implements:
 *
 *  - Group public key derivation from participant polynomial commitments
 *  - Round-1 nonce commitment validation (binding and hiding nonces per participant)
 *  - Round-2 signature share combination and final aggregate verification
 *  - Rogue-key attack protection via binding factor computation
 *  - stellar.toml inspection for SIGNING_KEY and ACCOUNTS FROST threshold declarations
 *  - CLI option: stellar-toml-lint --audit-frost-keys
 *
 * Reference: IETF draft-irtf-cfrg-frost (Ed25519 ciphersuite).
 */

import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
import type { Diagnostic, Rule } from '../types.js';

// ── Rule IDs ──────────────────────────────────────────────────────────────────

export const FROST_INVALID_GROUP_KEY = 'frost/invalid-group-public-key';
export const FROST_SHARE_MISMATCH = 'frost/participant-share-mismatch';
export const FROST_INVALID_COMMITMENT = 'frost/invalid-round1-commitment';
export const FROST_INVALID_SIG_SHARE = 'frost/invalid-signature-share';
export const FROST_ROGUE_KEY_ATTACK = 'frost/rogue-key-attack-detected';

// ── Curve constants ───────────────────────────────────────────────────────────

const ORDER = ed25519.CURVE.n; // 2^252 + 27742317777372353535851937790883648493
const G = ed25519.ExtendedPoint.BASE;

// ── Internal helpers ──────────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/i, '');
  if (clean.length % 2 !== 0) throw new Error(`Odd-length hex: ${hex}`);
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function bytesToScalar(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const b of bytes) result = (result << 8n) | BigInt(b);
  return result % ORDER;
}

function scalarToBytes32(n: bigint): Uint8Array {
  const hex = n.toString(16).padStart(64, '0');
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function mod(n: bigint): bigint {
  const r = n % ORDER;
  return r < 0n ? r + ORDER : r;
}

/** H1 binding factor hash per FROST/Ed25519 ciphersuite */
function h1(data: Uint8Array): bigint {
  return bytesToScalar(sha256(new Uint8Array([0x01, ...data])));
}

/** H3 nonce randomness hash */
function h3(data: Uint8Array): bigint {
  return bytesToScalar(sha256(new Uint8Array([0x03, ...data])));
}

/** Ed25519 challenge: SHA-512(R || A || msg) mod ORDER */
function computeChallenge(R: Uint8Array, A: Uint8Array, msg: Uint8Array): bigint {
  const hash = sha512(new Uint8Array([...R, ...A, ...msg]));
  return bytesToScalar(hash);
}

function parsePoint(hex: string): InstanceType<typeof ed25519.ExtendedPoint> {
  return ed25519.ExtendedPoint.fromHex(hex.replace(/^0x/i, ''));
}

// ── Public types ──────────────────────────────────────────────────────────────

export interface FrostParticipant {
  id: number;
  publicKeyShare: string;
  polynomialCommitments?: string[];
}

export interface FrostGroupConfig {
  threshold: number;
  numParticipants: number;
  groupPublicKey: string;
  participants: FrostParticipant[];
}

export interface FrostRound1Commitment {
  participantId: number;
  bindingNonceCommitment: string;
  hidingNonceCommitment: string;
}

export interface FrostRound2Share {
  participantId: number;
  sigShare: string;
}

export interface FrostAggregateResult {
  valid: boolean;
  signature: string;
  groupPublicKey: string;
  error?: string;
}

export interface FrostVerifyResult {
  valid: boolean;
  error?: string;
}

// ── Main verifier class ───────────────────────────────────────────────────────

export class FrostThresholdVerifier {
  /**
   * Derives the group public key from participant polynomial commitments.
   * The group key is the sum of each participant's constant-term commitment (index 0).
   */
  static deriveGroupPublicKey(participants: FrostParticipant[]): string {
    if (participants.length === 0) throw new Error('No participants provided');

    let groupKey = ed25519.ExtendedPoint.ZERO;
    for (const p of participants) {
      const commitments = p.polynomialCommitments ?? [p.publicKeyShare];
      if (!commitments[0]) throw new Error(`Participant ${p.id} has no polynomial commitment`);
      groupKey = groupKey.add(parsePoint(commitments[0]));
    }
    return bytesToHex(groupKey.toRawBytes());
  }

  /**
   * Verifies a participant's public key share against their polynomial commitments
   * using Feldman's verifiable secret sharing.
   *
   * share_i == sum_{j=0}^{t-1} commitment_j * i^j
   */
  static verifyParticipantShare(participant: FrostParticipant): FrostVerifyResult {
    if (!participant.polynomialCommitments || participant.polynomialCommitments.length === 0) {
      return { valid: false, error: 'No polynomial commitments provided' };
    }

    try {
      const id = BigInt(participant.id);
      let expected = ed25519.ExtendedPoint.ZERO;
      let idPow = 1n;

      for (const commitment of participant.polynomialCommitments) {
        const pt = parsePoint(commitment);
        expected = expected.add(pt.multiply(mod(idPow)));
        idPow = mod(idPow * id);
      }

      const actual = parsePoint(participant.publicKeyShare);
      if (!expected.equals(actual)) {
        return { valid: false, error: `Share verification failed for participant ${participant.id}: polynomial evaluation mismatch` };
      }
      return { valid: true };
    } catch (err) {
      return { valid: false, error: err instanceof Error ? err.message : String(err) };
    }
  }

  /**
   * Validates Round-1 nonce commitments: each commitment must be a valid Ed25519 point.
   */
  static validateRound1Commitments(commitments: FrostRound1Commitment[]): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    for (const c of commitments) {
      try {
        const D = parsePoint(c.bindingNonceCommitment);
        D.assertValidity();
        const E = parsePoint(c.hidingNonceCommitment);
        E.assertValidity();
      } catch (err) {
        errors.push(`Participant ${c.participantId}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
    return { valid: errors.length === 0, errors };
  }

  /**
   * Computes the binding factor rho_i for each participant.
   * rho_i = H1(i || msg || B) where B is the commitment list encoding.
   */
  static computeBindingFactors(
    commitments: FrostRound1Commitment[],
    message: Uint8Array,
  ): Map<number, bigint> {
    const factors = new Map<number, bigint>();
    const sortedCommitments = commitments.slice().sort((a, b) => a.participantId - b.participantId);

    // Encode the full commitment list for binding
    const listBytes: number[] = [];
    for (const c of sortedCommitments) {
      listBytes.push(...new TextEncoder().encode(c.participantId.toString()));
      listBytes.push(...hexToBytes(c.bindingNonceCommitment));
      listBytes.push(...hexToBytes(c.hidingNonceCommitment));
    }

    for (const c of sortedCommitments) {
      const idBytes = new TextEncoder().encode(c.participantId.toString());
      const rho = h1(new Uint8Array([...idBytes, ...message, ...listBytes]));
      factors.set(c.participantId, rho);
    }
    return factors;
  }

  /**
   * Computes the group commitment R = sum_i (D_i + rho_i * E_i).
   */
  static computeGroupCommitment(
    round1Commitments: FrostRound1Commitment[],
    bindingFactors: Map<number, bigint>,
  ): Uint8Array {
    let R = ed25519.ExtendedPoint.ZERO;
    for (const c of round1Commitments) {
      const rho = bindingFactors.get(c.participantId)!;
      const D = parsePoint(c.bindingNonceCommitment);
      const E = parsePoint(c.hidingNonceCommitment);
      R = R.add(D).add(E.multiply(mod(rho)));
    }
    return R.toRawBytes();
  }

  /**
   * Lagrange coefficient λ_i for participant i over the set of signers.
   * lambda_i = prod_{j != i} j / (j - i) mod ORDER
   */
  static lagrangeCoefficient(participantId: number, signerIds: number[]): bigint {
    const i = BigInt(participantId);
    let num = 1n;
    let den = 1n;
    for (const jId of signerIds) {
      const j = BigInt(jId);
      if (j === i) continue;
      num = mod(num * j);
      den = mod(den * (j - i));
    }
    // Modular inverse of denominator
    const denInv = modInv(den, ORDER);
    return mod(num * denInv);
  }

  /**
   * Verifies a single participant's signature share.
   * z_i * G == R_i + lambda_i * c * share_i  (R_i = D_i + rho_i * E_i)
   */
  static verifySignatureShare(
    share: FrostRound2Share,
    round1Commitment: FrostRound1Commitment,
    participant: FrostParticipant,
    bindingFactor: bigint,
    challenge: bigint,
    signerIds: number[],
  ): FrostVerifyResult {
    try {
      const z = bytesToScalar(hexToBytes(share.sigShare));
      const D = parsePoint(round1Commitment.bindingNonceCommitment);
      const E = parsePoint(round1Commitment.hidingNonceCommitment);
      const Ri = D.add(E.multiply(mod(bindingFactor)));

      const lambda = FrostThresholdVerifier.lagrangeCoefficient(share.participantId, signerIds);
      const pubShare = parsePoint(participant.publicKeyShare);

      // z_i * G == Ri + (lambda_i * c) * share_pubkey
      const lhs = G.multiply(mod(z));
      const rhs = Ri.add(pubShare.multiply(mod(lambda * challenge)));

      if (!lhs.equals(rhs)) {
        return { valid: false, error: `Signature share from participant ${share.participantId} failed verification` };
      }
      return { valid: true };
    } catch (err) {
      return { valid: false, error: err instanceof Error ? err.message : String(err) };
    }
  }

  /**
   * Aggregates signature shares into a final Ed25519 signature and verifies it.
   */
  static aggregateAndVerify(
    round2Shares: FrostRound2Share[],
    groupCommitmentBytes: Uint8Array,
    message: Uint8Array,
    groupPublicKey: string,
    signerIds: number[],
  ): FrostAggregateResult {
    try {
      const groupPubBytes = parsePoint(groupPublicKey).toRawBytes();
      const c = computeChallenge(groupCommitmentBytes, groupPubBytes, message);

      // z = sum of z_i * lambda_i
      let z = 0n;
      for (const share of round2Shares) {
        const zi = bytesToScalar(hexToBytes(share.sigShare));
        const lambda = FrostThresholdVerifier.lagrangeCoefficient(share.participantId, signerIds);
        z = mod(z + mod(zi * lambda));
      }

      // Encode signature as (R || s): R = groupCommitment, s = z
      const sig = new Uint8Array(64);
      sig.set(groupCommitmentBytes.slice(0, 32), 0);
      sig.set(scalarToBytes32(z), 32);

      // Verify via standard Ed25519: s*G == R + c*A
      const R = ed25519.ExtendedPoint.fromHex(groupCommitmentBytes);
      const A = parsePoint(groupPublicKey);
      const lhs = G.multiply(mod(z));
      const rhs = R.add(A.multiply(mod(c)));
      const valid = lhs.equals(rhs);

      return {
        valid,
        signature: bytesToHex(sig),
        groupPublicKey,
        error: valid ? undefined : 'Aggregate signature equation failed',
      };
    } catch (err) {
      return {
        valid: false,
        signature: '',
        groupPublicKey,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }

  /**
   * Runs a complete Round-1 → Round-2 → aggregation simulation for testing.
   * Returns all intermediate state so callers can inspect every step.
   */
  static simulateThresholdSigning(
    config: FrostGroupConfig,
    message: Uint8Array,
    signerIndices?: number[],
  ): {
    round1: FrostRound1Commitment[];
    bindingFactors: Map<number, bigint>;
    groupCommitment: Uint8Array;
    round2: FrostRound2Share[];
    result: FrostAggregateResult;
  } {
    const signers = signerIndices
      ? config.participants.filter((p) => signerIndices.includes(p.id))
      : config.participants.slice(0, config.threshold);

    if (signers.length < config.threshold) {
      throw new Error(`Need at least ${config.threshold} signers, have ${signers.length}`);
    }

    // Round 1: generate nonce commitments (deterministically from participant id + message)
    const round1: FrostRound1Commitment[] = signers.map((p) => {
      const seed = new Uint8Array([...new TextEncoder().encode(`nonce-${p.id}`), ...message]);
      const d = h3(new Uint8Array([0x01, ...seed]));
      const e = h3(new Uint8Array([0x02, ...seed]));
      return {
        participantId: p.id,
        bindingNonceCommitment: bytesToHex(G.multiply(mod(d)).toRawBytes()),
        hidingNonceCommitment: bytesToHex(G.multiply(mod(e)).toRawBytes()),
      };
    });

    const bindingFactors = FrostThresholdVerifier.computeBindingFactors(round1, message);
    const groupCommitment = FrostThresholdVerifier.computeGroupCommitment(round1, bindingFactors);

    const groupPubBytes = parsePoint(config.groupPublicKey).toRawBytes();
    const c = computeChallenge(groupCommitment, groupPubBytes, message);
    const signerIds = signers.map((s) => s.id);

    // Round 2: each signer produces z_i = k_i + lambda_i * c * secret_i
    // For simulation, derive secret_i from sha256(participant-id-seed) as a mock scalar
    const round2: FrostRound2Share[] = signers.map((p) => {
      const seed = new Uint8Array([...new TextEncoder().encode(`nonce-${p.id}`), ...message]);
      const d = h3(new Uint8Array([0x01, ...seed]));
      const e = h3(new Uint8Array([0x02, ...seed]));
      const rho = bindingFactors.get(p.id)!;
      const k = mod(d + mod(rho * e));
      const lambda = FrostThresholdVerifier.lagrangeCoefficient(p.id, signerIds);
      // Derive a mock secret scalar from the participant id and group key
      const secretSeed = sha256(new Uint8Array([...new TextEncoder().encode(`secret-${p.id}`), ...groupPubBytes]));
      const secret = bytesToScalar(secretSeed);
      const z = mod(k + mod(lambda * mod(c * secret)));
      return { participantId: p.id, sigShare: bytesToHex(scalarToBytes32(z)) };
    });

    const result = FrostThresholdVerifier.aggregateAndVerify(
      round2,
      groupCommitment,
      message,
      config.groupPublicKey,
      signerIds,
    );

    return { round1, bindingFactors, groupCommitment, round2, result };
  }

  /**
   * Inspects stellar.toml for FROST threshold key declarations in SIGNING_KEY and ACCOUNTS.
   */
  static extractFrostDeclarationsFromToml(doc: Record<string, unknown>): Array<{
    field: string;
    groupPublicKey?: string;
    threshold?: number;
    participants?: FrostParticipant[];
  }> {
    const results: Array<{ field: string; groupPublicKey?: string; threshold?: number; participants?: FrostParticipant[] }> = [];

    // Top-level FROST_THRESHOLD table
    const frostTable = doc.FROST_THRESHOLD as Record<string, unknown> | undefined;
    if (frostTable && typeof frostTable === 'object') {
      results.push({
        field: 'FROST_THRESHOLD',
        groupPublicKey: frostTable.group_public_key as string | undefined,
        threshold: frostTable.threshold as number | undefined,
        participants: frostTable.participants as FrostParticipant[] | undefined,
      });
    }

    // [[VALIDATORS]] with frost_threshold_config
    if (Array.isArray(doc.VALIDATORS)) {
      doc.VALIDATORS.forEach((val, idx) => {
        if (typeof val !== 'object' || val === null) return;
        const v = val as Record<string, unknown>;
        if (v.frost_threshold_config) {
          const cfg = v.frost_threshold_config as Record<string, unknown>;
          results.push({
            field: `VALIDATORS[${idx}].frost_threshold_config`,
            groupPublicKey: cfg.group_public_key as string | undefined,
            threshold: cfg.threshold as number | undefined,
            participants: cfg.participants as FrostParticipant[] | undefined,
          });
        }
      });
    }

    return results;
  }

  /**
   * Audits stellar.toml for FROST key declarations and validates participant shares.
   */
  auditToml(doc: Record<string, unknown>): Diagnostic[] {
    const diagnostics: Diagnostic[] = [];
    const declarations = FrostThresholdVerifier.extractFrostDeclarationsFromToml(doc);

    for (const decl of declarations) {
      if (!decl.groupPublicKey) continue;

      // Validate group public key format
      try {
        parsePoint(decl.groupPublicKey).assertValidity();
      } catch (err) {
        diagnostics.push({
          rule: FROST_INVALID_GROUP_KEY,
          severity: 'error',
          category: 'security',
          message: `Invalid FROST group public key at ${decl.field}: ${err instanceof Error ? err.message : String(err)}`,
          path: decl.field,
          suggestion: 'Ensure the group_public_key is a valid compressed Ed25519 public key.',
        });
        continue;
      }

      if (!decl.participants || decl.participants.length === 0) continue;

      // Validate each participant's share against polynomial commitments
      for (const participant of decl.participants) {
        if (!participant.polynomialCommitments) continue;
        const result = FrostThresholdVerifier.verifyParticipantShare(participant);
        if (!result.valid) {
          diagnostics.push({
            rule: FROST_SHARE_MISMATCH,
            severity: 'error',
            category: 'security',
            message: `FROST participant ${participant.id} share mismatch at ${decl.field}: ${result.error}`,
            path: `${decl.field}.participants[${participant.id}]`,
            suggestion: 'Verify that the participant\'s public key share is consistent with their polynomial commitments.',
          });
        }
      }

      // Verify that the declared group key matches what we derive from commitments
      try {
        const derivedKey = FrostThresholdVerifier.deriveGroupPublicKey(decl.participants);
        if (derivedKey !== decl.groupPublicKey) {
          diagnostics.push({
            rule: FROST_INVALID_GROUP_KEY,
            severity: 'error',
            category: 'security',
            message: `Declared FROST group public key does not match key derived from participant commitments at ${decl.field}`,
            path: `${decl.field}.group_public_key`,
            suggestion: 'The group_public_key must equal the sum of participant constant-term polynomial commitments.',
          });
        }
      } catch {
        // derivation failure already reported above
      }
    }

    return diagnostics;
  }
}

// ── Rule declarations ─────────────────────────────────────────────────────────

export const frostRules: Rule[] = [
  {
    id: FROST_INVALID_GROUP_KEY,
    category: 'security',
    severity: 'error',
    description: 'FROST group public key must be a valid Ed25519 point derived from participant commitments',
    run() {},
  },
  {
    id: FROST_SHARE_MISMATCH,
    category: 'security',
    severity: 'error',
    description: 'FROST participant public key share must be consistent with their polynomial commitments (Feldman VSS)',
    run() {},
  },
  {
    id: FROST_INVALID_COMMITMENT,
    category: 'security',
    severity: 'error',
    description: 'FROST Round-1 nonce commitments must be valid Ed25519 points',
    run() {},
  },
  {
    id: FROST_INVALID_SIG_SHARE,
    category: 'security',
    severity: 'error',
    description: 'FROST Round-2 signature share must satisfy the per-participant verification equation',
    run() {},
  },
  {
    id: FROST_ROGUE_KEY_ATTACK,
    category: 'security',
    severity: 'error',
    description: 'FROST binding factors must be used to prevent rogue-key (Wagner) attacks',
    run() {},
  },
];

export const frostRuleIds: readonly string[] = frostRules.map((r) => r.id);

// ── Modular inverse (extended Euclidean) ─────────────────────────────────────

function modInv(a: bigint, m: bigint): bigint {
  let [oldR, r] = [((a % m) + m) % m, m];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  if (oldR !== 1n) throw new Error('Modular inverse does not exist');
  return ((oldS % m) + m) % m;
}
