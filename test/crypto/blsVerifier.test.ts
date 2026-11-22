import { describe, expect, it } from 'vitest';
import { bls12_381 } from '@noble/curves/bls12-381';
import { BlsSignatureVerifier } from '../../src/crypto/blsVerifier.js';

describe('BlsSignatureVerifier', () => {
  it('parses valid G1 compressed public key', () => {
    const verifier = new BlsSignatureVerifier();
    const priv = 123456789n;
    const g1Point = bls12_381.G1.Point.fromPrivateKey(priv);
    const compressedHex = Buffer.from(g1Point.toRawBytes(true)).toString('hex');

    const result = verifier.parsePublicKey(compressedHex);
    expect(result.valid).toBe(true);
    expect(result.group).toBe('G1');
    expect(result.format).toBe('compressed');
    expect(result.byteLength).toBe(48);
    expect(result.inSubgroup).toBe(true);
    expect(result.isInfinity).toBe(false);
  });

  it('verifies BLS aggregate signature over a single message', () => {
    const verifier = new BlsSignatureVerifier();
    const msg = Buffer.from('stellar-anchor-governance-payload', 'utf-8');

    const priv1 = 11111111n;
    const pub1 = bls12_381.G1.Point.fromPrivateKey(priv1);
    const sig1 = bls12_381.sign(msg, priv1);

    const priv2 = 22222222n;
    const pub2 = bls12_381.G1.Point.fromPrivateKey(priv2);
    const sig2 = bls12_381.sign(msg, priv2);

    // Aggregate signatures (add G2 points)
    const sigPoint1 = bls12_381.G2.Point.fromHex(sig1);
    const sigPoint2 = bls12_381.G2.Point.fromHex(sig2);
    const aggSig = sigPoint1.add(sigPoint2).toRawBytes(true);

    const pubkeys = [
      Buffer.from(pub1.toRawBytes(true)).toString('hex'),
      Buffer.from(pub2.toRawBytes(true)).toString('hex'),
    ];

    const verifyResult = verifier.verifyAggregate(aggSig, msg, pubkeys);
    expect(verifyResult.valid).toBe(true);
    expect(verifyResult.numSigners).toBe(2);
    expect(verifyResult.subgroupChecked).toBe(true);
  });

  it('rejects invalid or corrupted signatures', () => {
    const verifier = new BlsSignatureVerifier();
    const msg = Buffer.from('test-message', 'utf-8');
    const priv1 = 987654321n;
    const pub1 = bls12_381.G1.Point.fromPrivateKey(priv1);
    const corruptSig = new Uint8Array(96).fill(0x55);

    const verifyResult = verifier.verifyAggregate(
      corruptSig,
      msg,
      [Buffer.from(pub1.toRawBytes(true)).toString('hex')],
    );
    expect(verifyResult.valid).toBe(false);
  });
});
