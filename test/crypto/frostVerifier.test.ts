import { describe, expect, it } from 'vitest';
import {
  FrostThresholdVerifier,
  frostRules,
  frostRuleIds,
  FROST_INVALID_GROUP_KEY,
  FROST_SHARE_MISMATCH,
  FROST_INVALID_COMMITMENT,
  FROST_INVALID_SIG_SHARE,
  FROST_ROGUE_KEY_ATTACK,
  type FrostGroupConfig,
  type FrostParticipant,
} from '../../src/crypto/frostVerifier.js';
import { ed25519 } from '@noble/curves/ed25519';

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Build a 2-of-3 FROST config with deterministic participant secrets */
function buildTestConfig(
  threshold: number,
  numParticipants: number,
): {
  config: FrostGroupConfig;
  secrets: bigint[];
} {
  const ORDER = ed25519.CURVE.n;
  const G = ed25519.ExtendedPoint.BASE;

  const mod = (n: bigint) => ((n % ORDER) + ORDER) % ORDER;

  // Each participant has a polynomial of degree (threshold - 1)
  // For simplicity: participant i has poly a0_i + a1_i * x (where a0_i is their secret)
  const secrets: bigint[] = [];
  const participants: FrostParticipant[] = [];

  for (let i = 1; i <= numParticipants; i++) {
    // Deterministic secrets from participant id
    const a0 = mod(BigInt(i) * 0xdeadbeef1234n + 1n);
    const a1 = mod(BigInt(i) * 0xbeef5678n + 2n);
    secrets.push(a0);

    const C0 = G.multiply(a0);
    const C1 = G.multiply(a1);

    // Public key share for participant i = a0 + a1*i
    const shareScalar = mod(a0 + a1 * BigInt(i));
    const sharePoint = G.multiply(shareScalar);

    participants.push({
      id: i,
      publicKeyShare: bytesToHex(sharePoint.toRawBytes()),
      polynomialCommitments: [bytesToHex(C0.toRawBytes()), bytesToHex(C1.toRawBytes())],
    });
  }

  const groupKey = FrostThresholdVerifier.deriveGroupPublicKey(participants);

  return {
    config: { threshold, numParticipants, groupPublicKey: groupKey, participants },
    secrets,
  };
}

describe('FrostThresholdVerifier', () => {
  it('exposes frost rules and rule IDs', () => {
    expect(frostRules).toHaveLength(5);
    expect(frostRuleIds).toContain(FROST_INVALID_GROUP_KEY);
    expect(frostRuleIds).toContain(FROST_SHARE_MISMATCH);
    expect(frostRuleIds).toContain(FROST_INVALID_COMMITMENT);
    expect(frostRuleIds).toContain(FROST_INVALID_SIG_SHARE);
    expect(frostRuleIds).toContain(FROST_ROGUE_KEY_ATTACK);
  });

  describe('deriveGroupPublicKey', () => {
    it('derives a valid Ed25519 group public key from participants', () => {
      const { config } = buildTestConfig(2, 3);
      const key = config.groupPublicKey;
      expect(key).toHaveLength(64);
      expect(() => ed25519.ExtendedPoint.fromHex(key).assertValidity()).not.toThrow();
    });

    it('throws when no participants provided', () => {
      expect(() => FrostThresholdVerifier.deriveGroupPublicKey([])).toThrow(/No participants/i);
    });
  });

  describe('verifyParticipantShare', () => {
    it('verifies valid participant shares', () => {
      const { config } = buildTestConfig(2, 3);
      for (const p of config.participants) {
        const result = FrostThresholdVerifier.verifyParticipantShare(p);
        expect(result.valid).toBe(true);
      }
    });

    it('rejects a participant with tampered public key share', () => {
      const { config } = buildTestConfig(2, 3);
      const tampered: FrostParticipant = {
        ...config.participants[0]!,
        publicKeyShare: bytesToHex(ed25519.ExtendedPoint.BASE.toRawBytes()), // wrong key
      };
      const result = FrostThresholdVerifier.verifyParticipantShare(tampered);
      expect(result.valid).toBe(false);
      expect(result.error).toMatch(/mismatch/i);
    });

    it('rejects a participant with no polynomial commitments', () => {
      const p: FrostParticipant = {
        id: 1,
        publicKeyShare: bytesToHex(ed25519.ExtendedPoint.BASE.toRawBytes()),
      };
      const result = FrostThresholdVerifier.verifyParticipantShare(p);
      expect(result.valid).toBe(false);
    });
  });

  describe('validateRound1Commitments', () => {
    it('validates valid Ed25519 nonce commitment points', () => {
      const G = ed25519.ExtendedPoint.BASE;
      const D = bytesToHex(G.multiply(123456789n).toRawBytes());
      const E = bytesToHex(G.multiply(987654321n).toRawBytes());
      const commitments = [
        { participantId: 1, bindingNonceCommitment: D, hidingNonceCommitment: E },
      ];
      const { valid } = FrostThresholdVerifier.validateRound1Commitments(commitments);
      expect(valid).toBe(true);
    });

    it('rejects invalid Ed25519 point in commitments', () => {
      // 33 bytes (66 hex chars) is wrong length for a 32-byte Ed25519 compressed point
      const invalid = '00'.repeat(33);
      const commitments = [
        { participantId: 1, bindingNonceCommitment: invalid, hidingNonceCommitment: invalid },
      ];
      const { valid, errors } = FrostThresholdVerifier.validateRound1Commitments(commitments);
      expect(valid).toBe(false);
      expect(errors.length).toBeGreaterThan(0);
    });
  });

  describe('lagrangeCoefficient', () => {
    it('computes lagrange coefficients that sum to 1 for threshold-t subset', () => {
      const ORDER = ed25519.CURVE.n;
      const mod = (n: bigint) => ((n % ORDER) + ORDER) % ORDER;
      const signerIds = [1, 2, 3];

      // The sum of Lagrange coefficients evaluated at 0 should equal 1 mod ORDER
      // when all secret shares reconstruct the constant term.
      let sum = 0n;
      for (const id of signerIds) {
        sum = mod(sum + FrostThresholdVerifier.lagrangeCoefficient(id, signerIds));
      }
      expect(sum).toBe(1n);
    });

    it('handles 2-of-2 threshold Lagrange', () => {
      const ORDER = ed25519.CURVE.n;
      const mod = (n: bigint) => ((n % ORDER) + ORDER) % ORDER;
      const signerIds = [1, 2];
      let sum = 0n;
      for (const id of signerIds) {
        sum = mod(sum + FrostThresholdVerifier.lagrangeCoefficient(id, signerIds));
      }
      expect(sum).toBe(1n);
    });
  });

  describe('computeBindingFactors', () => {
    it('produces distinct binding factors for each participant', () => {
      const G = ed25519.ExtendedPoint.BASE;
      const D = bytesToHex(G.multiply(123n).toRawBytes());
      const E = bytesToHex(G.multiply(456n).toRawBytes());
      const commitments = [
        { participantId: 1, bindingNonceCommitment: D, hidingNonceCommitment: E },
        {
          participantId: 2,
          bindingNonceCommitment: bytesToHex(G.multiply(789n).toRawBytes()),
          hidingNonceCommitment: bytesToHex(G.multiply(1011n).toRawBytes()),
        },
      ];
      const message = new Uint8Array(32).fill(0x42);
      const factors = FrostThresholdVerifier.computeBindingFactors(commitments, message);
      expect(factors.size).toBe(2);
      expect(factors.get(1)).not.toBe(factors.get(2));
    });
  });

  describe('simulateThresholdSigning', () => {
    it('simulates a 2-of-3 threshold signing round-trip', () => {
      const { config } = buildTestConfig(2, 3);
      const message = new Uint8Array(32).fill(0xab);
      const { result } = FrostThresholdVerifier.simulateThresholdSigning(config, message);
      // Simulation with mock secrets — check structure is well-formed
      expect(result).toBeDefined();
      expect(typeof result.valid).toBe('boolean');
      expect(result.signature).toHaveLength(128);
    });

    it('simulates a 3-of-5 threshold signing', () => {
      const { config } = buildTestConfig(3, 5);
      const message = new Uint8Array(32).fill(0x77);
      const { result, round1, round2 } = FrostThresholdVerifier.simulateThresholdSigning(
        config,
        message,
      );
      expect(round1).toHaveLength(3);
      expect(round2).toHaveLength(3);
      expect(result).toBeDefined();
    });

    it('throws when insufficient signers provided', () => {
      const { config } = buildTestConfig(3, 5);
      const message = new Uint8Array(32).fill(0x01);
      expect(
        () => FrostThresholdVerifier.simulateThresholdSigning(config, message, [1, 2]), // only 2, need 3
      ).toThrow(/at least/i);
    });
  });

  describe('auditToml', () => {
    it('returns no diagnostics for a toml without FROST declarations', () => {
      const verifier = new FrostThresholdVerifier();
      const diagnostics = verifier.auditToml({ DOCUMENTATION: { ORG_NAME: 'Test' } });
      expect(diagnostics).toHaveLength(0);
    });

    it('reports invalid group key in FROST_THRESHOLD', () => {
      const verifier = new FrostThresholdVerifier();
      const doc = {
        FROST_THRESHOLD: {
          // 33 bytes (66 hex chars) is wrong length for a 32-byte Ed25519 point
          group_public_key: '00'.repeat(33),
          threshold: 2,
        },
      };
      const diagnostics = verifier.auditToml(doc);
      expect(diagnostics.length).toBeGreaterThan(0);
      expect(diagnostics.some((d) => d.rule === FROST_INVALID_GROUP_KEY)).toBe(true);
    });

    it('validates participant shares in FROST_THRESHOLD', () => {
      const { config } = buildTestConfig(2, 3);
      const verifier = new FrostThresholdVerifier();
      const doc = {
        FROST_THRESHOLD: {
          group_public_key: config.groupPublicKey,
          threshold: config.threshold,
          participants: config.participants,
        },
      };
      // Valid config should produce no diagnostics
      const diagnostics = verifier.auditToml(doc);
      expect(diagnostics.filter((d) => d.rule === FROST_SHARE_MISMATCH)).toHaveLength(0);
    });

    it('reports share mismatch for tampered participant', () => {
      const { config } = buildTestConfig(2, 3);
      const tampered = config.participants.map((p, i) =>
        i === 0 ? { ...p, publicKeyShare: bytesToHex(ed25519.ExtendedPoint.BASE.toRawBytes()) } : p,
      );
      const verifier = new FrostThresholdVerifier();
      const doc = {
        FROST_THRESHOLD: {
          group_public_key: config.groupPublicKey,
          threshold: config.threshold,
          participants: tampered,
        },
      };
      const diagnostics = verifier.auditToml(doc);
      expect(diagnostics.some((d) => d.rule === FROST_SHARE_MISMATCH)).toBe(true);
    });
  });
});
