import { describe, expect, it } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import {
  PostQuantumReadinessAuditor,
} from '../../src/crypto/postQuantumAuditor.js';

describe('PostQuantumReadinessAuditor', () => {
  it('recognizes standard ML-DSA parameter sets', () => {
    expect(PostQuantumReadinessAuditor.resolveParameterSet('ML-DSA-44')?.publicKeyBytes).toBe(1312);
    expect(PostQuantumReadinessAuditor.resolveParameterSet('dilithium3')?.publicKeyBytes).toBe(1952);
    expect(PostQuantumReadinessAuditor.resolveParameterSet('ML-DSA-87')?.publicKeyBytes).toBe(2592);
  });

  it('validates public key lengths correctly', () => {
    // Valid 1312 bytes for ML-DSA-44
    const valid44 = Buffer.alloc(1312, 0x42).toString('hex');
    const resValid = PostQuantumReadinessAuditor.validatePublicKey('ML-DSA-44', valid44);
    expect(resValid.valid).toBe(true);

    // Invalid length
    const invalid44 = Buffer.alloc(1300, 0x42).toString('hex');
    const resInvalid = PostQuantumReadinessAuditor.validatePublicKey('ML-DSA-44', invalid44);
    expect(resInvalid.valid).toBe(false);
    expect(resInvalid.error).toContain('expected 1312 bytes, got 1300 bytes');
  });

  it('verifies cross-signing signature between classic Ed25519 and PQ key', () => {
    const classicPriv = ed25519.utils.randomPrivateKey();
    const classicPub = ed25519.getPublicKey(classicPriv);

    const pqKeyBytes = Buffer.alloc(1952, 0x99);
    const signature = ed25519.sign(pqKeyBytes, classicPriv);

    const isVerified = PostQuantumReadinessAuditor.verifyCrossSignature(
      classicPub,
      pqKeyBytes,
      signature,
    );
    expect(isVerified).toBe(true);

    // Mismatched signature
    const corruptSig = new Uint8Array(64).fill(0x11);
    expect(
      PostQuantumReadinessAuditor.verifyCrossSignature(classicPub, pqKeyBytes, corruptSig),
    ).toBe(false);
  });

  it('audits toml without post-quantum config as Grade F', () => {
    const report = PostQuantumReadinessAuditor.audit({
      VERSION: '2.0.0',
    });
    expect(report.score).toBe(0);
    expect(report.grade).toBe('F');
    expect(report.isQuantumReady).toBe(false);
  });

  it('audits valid hybrid post-quantum configuration as Grade A', () => {
    const classicPriv = ed25519.utils.randomPrivateKey();
    const classicPub = Buffer.from(ed25519.getPublicKey(classicPriv)).toString('hex');

    const pqKeyBytes = Buffer.alloc(1952, 0xaa);
    const signature = Buffer.from(ed25519.sign(pqKeyBytes, classicPriv)).toString('hex');

    const toml = {
      SIGNING_KEY: classicPub,
      POST_QUANTUM: {
        PARAMETER_SET: 'ML-DSA-65',
        ML_DSA_PUBLIC_KEY: pqKeyBytes.toString('hex'),
        CROSS_SIGNATURE: signature,
        MIGRATION_DEADLINE: '2028-12-31',
      },
    };

    const report = PostQuantumReadinessAuditor.audit(toml);
    expect(report.score).toBeGreaterThanOrEqual(90);
    expect(report.grade).toBe('A');
    expect(report.isQuantumReady).toBe(true);
    expect(report.parameterSet).toBe('ML-DSA-65');
  });
});
