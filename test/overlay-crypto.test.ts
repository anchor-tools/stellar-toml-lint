import { describe, expect, it } from 'vitest';
import {
  auditCryptoFraming,
  auditOverlayCrypto,
  computeOverlayMac,
  deriveHkdf,
  OVERLAY_INVALID_CRYPTO_FRAMING,
  OVERLAY_MAC_AUTHENTICATION_FAILURE,
} from '../src/overlay/crypto-auditor.js';

const KEY = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
const PAYLOAD = new Uint8Array([1, 2, 3, 4]);

describe('overlay crypto auditor', () => {
  it('accepts valid four-byte length framing', () => {
    const stream = new Uint8Array([0, 0, 0, 4, 1, 2, 3, 4]);
    expect(auditCryptoFraming(stream)).toEqual([]);
  });

  it('reports a truncated length frame', () => {
    const stream = new Uint8Array([0, 0, 0, 4, 1, 2]);
    const diagnostics = auditCryptoFraming(stream);
    expect(diagnostics[0]).toMatchObject({
      rule: OVERLAY_INVALID_CRYPTO_FRAMING,
      severity: 'error',
    });
  });

  it('rejects a replayed sequence number', async () => {
    const diagnostics = await auditOverlayCrypto({ sequenceNumbers: [4, 4] });
    expect(diagnostics[0]?.rule).toBe(OVERLAY_INVALID_CRYPTO_FRAMING);
  });

  it('derives the RFC 5869 test key', async () => {
    const derived = await deriveHkdf(
      '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
      '000102030405060708090a0b0c',
      'f0f1f2f3f4f5f6f7f8f9',
      42,
    );
    expect(Buffer.from(derived).toString('hex')).toBe(
      '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
    );
  });

  it('reports a failed MAC tag', async () => {
    const tag = await computeOverlayMac(KEY, PAYLOAD);
    const diagnostics = await auditOverlayCrypto({
      frames: [{ payload: PAYLOAD, tag, expectedTag: new Uint8Array(tag.length) }],
    });
    expect(diagnostics[0]).toMatchObject({
      rule: OVERLAY_MAC_AUTHENTICATION_FAILURE,
      severity: 'error',
    });
  });

  it('accepts a matching MAC tag', async () => {
    const tag = await computeOverlayMac(KEY, PAYLOAD);
    const diagnostics = await auditOverlayCrypto({
      macKey: KEY,
      frames: [{ payload: PAYLOAD, tag }],
    });
    expect(diagnostics).toEqual([]);
  });
});
