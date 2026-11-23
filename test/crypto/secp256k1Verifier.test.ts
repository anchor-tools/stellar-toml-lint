import { describe, expect, it } from 'vitest';
import {
  Secp256k1BridgeVerifier,
  secp256k1BridgeRules,
  secp256k1BridgeRuleIds,
  toChecksumAddress,
  CRYPTO_INVALID_SECP256K1_SIGNATURE,
  CRYPTO_BRIDGE_SIGNER_UNMATCHED,
  CRYPTO_MALFORMED_SIGNATURE,
} from '../../src/crypto/secp256k1Verifier.js';

describe('Secp256k1BridgeVerifier', () => {
  const verifier = new Secp256k1BridgeVerifier();

  it('exposes secp256k1 bridge rules and rule IDs', () => {
    expect(secp256k1BridgeRules).toHaveLength(3);
    expect(secp256k1BridgeRuleIds).toContain(CRYPTO_INVALID_SECP256K1_SIGNATURE);
    expect(secp256k1BridgeRuleIds).toContain(CRYPTO_BRIDGE_SIGNER_UNMATCHED);
    expect(secp256k1BridgeRuleIds).toContain(CRYPTO_MALFORMED_SIGNATURE);
  });

  it('computes correct checksum address', () => {
    const raw = '0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed';
    const checksummed = toChecksumAddress(raw);
    expect(checksummed).toBe('0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed');
  });

  it('signs and verifies valid secp256k1 bridge signatures', () => {
    const privateKey = '0x' + '01'.repeat(32);
    const message = 'stellar-bridge-deposit-authorization';

    const { hex: sigHex } = Secp256k1BridgeVerifier.sign(message, privateKey, 'eip191');
    const recovered = Secp256k1BridgeVerifier.recoverAddress(sigHex, message, 'eip191');
    const result = verifier.verifyBridgeSignature(sigHex, message, [recovered.checksumAddress], 'eip191');

    expect(result.valid).toBe(true);
    expect(result.recovered?.checksumAddress.toLowerCase()).toBe(recovered.checksumAddress.toLowerCase());
  });

  it('detects mismatched signer address', () => {
    const privateKey = '0x' + '01'.repeat(32);
    const message = 'stellar-bridge-deposit-authorization';
    const wrongAddress = '0x0000000000000000000000000000000000000000';

    const { hex: sigHex } = Secp256k1BridgeVerifier.sign(message, privateKey, 'eip191');
    const result = verifier.verifyBridgeSignature(sigHex, message, [wrongAddress], 'eip191');

    expect(result.signerMatched).toBe(false);
  });
});
