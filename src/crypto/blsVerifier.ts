/**
 * BLS12-381 multi-signature aggregation and pairing verifier.
 *
 * Implements BLS12-381 curve operations, point serialization (compressed / uncompressed),
 * subgroup membership verification to prevent small-subgroup attacks, and pairing-based
 * aggregated signature verification using optimal Ate / Tate pairings.
 */

import { bls12_381 } from '@noble/curves/bls12-381';
import { parse as parseToml } from 'smol-toml';

export type BlsGroup = 'G1' | 'G2';
export type SerializationFormat = 'compressed' | 'uncompressed';

export interface BlsKeyParseResult {
  valid: boolean;
  group: BlsGroup;
  format: SerializationFormat;
  byteLength: number;
  hex: string;
  isInfinity: boolean;
  inSubgroup: boolean;
  error?: string;
}

export interface BlsSignatureVerifyResult {
  valid: boolean;
  subgroupChecked: boolean;
  pairingComputed: boolean;
  numSigners: number;
  error?: string;
}

export interface BlsAuditFinding {
  field: string;
  keyHex: string;
  group: BlsGroup;
  format: SerializationFormat;
  valid: boolean;
  inSubgroup: boolean;
  issues: string[];
}

export interface BlsAuditReport {
  totalKeys: number;
  validKeys: number;
  findings: BlsAuditFinding[];
  allValid: boolean;
  summary: string;
}

export interface BlsVerifyOptions {
  group?: BlsGroup; // Group of public keys: default G1 (signatures in G2) or G2 (signatures in G1)
  dst?: string; // Domain separation tag
}

// Subgroup order r for BLS12-381:
// r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
export const BLS12_381_R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;

// Base field modulus p for BLS12-381:
// p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
export const BLS12_381_P =
  0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn;

function toBytes(input: Uint8Array | string): Uint8Array {
  if (input instanceof Uint8Array || ArrayBuffer.isView(input) || Buffer.isBuffer(input)) return input as Uint8Array;
  if (typeof input !== 'string') return new Uint8Array(input as ArrayLike<number>);
  const cleaned = input.trim().replace(/^0x/i, '');
  return Buffer.from(cleaned, 'hex');
}

function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

/**
 * BLS12-381 Signature and Key Verifier.
 */
export class BlsSignatureVerifier {
  /**
   * Parse a BLS12-381 public key or point in G1 or G2.
   * Supports:
   * - Compressed G1: 48 bytes (96 hex)
   * - Uncompressed G1: 96 bytes (192 hex)
   * - Compressed G2: 96 bytes (192 hex)
   * - Uncompressed G2: 192 bytes (384 hex)
   */
  public parsePublicKey(rawKey: Uint8Array | string, expectedGroup?: BlsGroup): BlsKeyParseResult {
    let bytes: Uint8Array;
    try {
      bytes = toBytes(rawKey);
    } catch {
      return {
        valid: false,
        group: expectedGroup ?? 'G1',
        format: 'compressed',
        byteLength: 0,
        hex: typeof rawKey === 'string' ? rawKey : '',
        isInfinity: false,
        inSubgroup: false,
        error: 'Invalid hex encoding for BLS public key',
      };
    }

    const hex = toHex(bytes);
    const len = bytes.length;

    // Detect format and group
    let detectedGroup: BlsGroup = expectedGroup ?? 'G1';
    let format: SerializationFormat = 'compressed';

    if (len === 48) {
      detectedGroup = 'G1';
      format = 'compressed';
    } else if (len === 96) {
      if (expectedGroup === 'G2') {
        detectedGroup = 'G2';
        format = 'compressed';
      } else if (expectedGroup === 'G1') {
        detectedGroup = 'G1';
        format = 'uncompressed';
      } else {
        // Heuristic: Check top bits of first byte.
        // Compressed point top bit 7 is set (0x80).
        if ((bytes[0]! & 0x80) !== 0) {
          detectedGroup = 'G2';
          format = 'compressed';
        } else {
          detectedGroup = 'G1';
          format = 'uncompressed';
        }
      }
    } else if (len === 192) {
      detectedGroup = 'G2';
      format = 'uncompressed';
    } else {
      return {
        valid: false,
        group: detectedGroup,
        format,
        byteLength: len,
        hex,
        isInfinity: false,
        inSubgroup: false,
        error: `Unexpected BLS12-381 point length: ${len} bytes (expected 48, 96, or 192 bytes)`,
      };
    }

    // Verify infinity flag
    // Standard Zcash / IETF serialization:
    // Bit 7: compression flag (1 if compressed, 0 if uncompressed)
    // Bit 6: infinity flag (1 if point at infinity)
    // Bit 5: sort flag (y coordinate sign)
    const isInfinity = (bytes[0]! & 0x40) !== 0;

    // Subgroup membership & validity check
    try {
      if (detectedGroup === 'G1') {
        const point = bls12_381.G1.ProjectivePoint.fromHex(bytes);
        point.assertValidity();
        return {
          valid: true,
          group: 'G1',
          format,
          byteLength: len,
          hex,
          isInfinity,
          inSubgroup: true,
        };
      } else {
        const point = bls12_381.G2.ProjectivePoint.fromHex(bytes);
        point.assertValidity();
        return {
          valid: true,
          group: 'G2',
          format,
          byteLength: len,
          hex,
          isInfinity,
          inSubgroup: true,
        };
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        valid: false,
        group: detectedGroup,
        format,
        byteLength: len,
        hex,
        isInfinity,
        inSubgroup: false,
        error: `Point failed curve or subgroup validation: ${msg}`,
      };
    }
  }

  /**
   * Check whether a given point is in the prime-order subgroup r (prevents small-subgroup attacks).
   */
  public verifySubgroupMembership(pointBytes: Uint8Array | string, group: BlsGroup = 'G1'): boolean {
    try {
      const parsed = this.parsePublicKey(pointBytes, group);
      return parsed.valid && parsed.inSubgroup;
    } catch {
      return false;
    }
  }

  /**
   * Aggregate multiple public keys into a single combined public key.
   */
  public aggregatePublicKeys(keys: (Uint8Array | string)[], group: BlsGroup = 'G1'): Uint8Array {
    if (keys.length === 0) {
      throw new Error('Cannot aggregate an empty list of public keys');
    }

    const byteKeys = keys.map(toBytes);

    // Validate subgroup membership of every individual key before aggregation
    for (let i = 0; i < byteKeys.length; i++) {
      const k = byteKeys[i]!;
      const parsed = this.parsePublicKey(k, group);
      if (!parsed.valid || !parsed.inSubgroup) {
        throw new Error(`Key at index ${i} failed subgroup membership validation: ${parsed.error}`);
      }
    }

    if (group === 'G1') {
      return bls12_381.aggregatePublicKeys(byteKeys);
    } else {
      // In G2 public keys mode:
      let acc = bls12_381.G2.ProjectivePoint.fromHex(byteKeys[0]!);
      for (let i = 1; i < byteKeys.length; i++) {
        const pt = bls12_381.G2.ProjectivePoint.fromHex(byteKeys[i]!);
        acc = acc.add(pt);
      }
      return acc.toRawBytes(true);
    }
  }

  /**
   * Aggregate multiple signatures into a single aggregated signature.
   */
  public aggregateSignatures(signatures: (Uint8Array | string)[], signatureGroup: BlsGroup = 'G2'): Uint8Array {
    if (signatures.length === 0) {
      throw new Error('Cannot aggregate an empty list of signatures');
    }

    const byteSigs = signatures.map(toBytes);

    if (signatureGroup === 'G2') {
      return bls12_381.aggregateSignatures(byteSigs);
    } else {
      return bls12_381.aggregateShortSignatures(byteSigs);
    }
  }

  /**
   * Verify a single BLS12-381 signature over a message with a public key.
   */
  public verifySingle(
    signature: Uint8Array | string,
    message: Uint8Array | string,
    publicKey: Uint8Array | string,
    options: BlsVerifyOptions = {},
  ): BlsSignatureVerifyResult {
    const pubGroup = options.group ?? 'G1';
    const sigBytes = toBytes(signature);
    const msgBytes = typeof message === 'string' ? Buffer.from(message, 'utf-8') : message;
    const pubBytes = toBytes(publicKey);

    // 1. Validate public key subgroup membership
    const parsedPub = this.parsePublicKey(pubBytes, pubGroup);
    if (!parsedPub.valid || !parsedPub.inSubgroup) {
      return {
        valid: false,
        subgroupChecked: true,
        pairingComputed: false,
        numSigners: 1,
        error: `Public key failed subgroup check: ${parsedPub.error}`,
      };
    }

    // 2. Validate signature point validity
    const sigGroup: BlsGroup = pubGroup === 'G1' ? 'G2' : 'G1';
    const parsedSig = this.parsePublicKey(sigBytes, sigGroup);
    if (!parsedSig.valid || !parsedSig.inSubgroup) {
      return {
        valid: false,
        subgroupChecked: true,
        pairingComputed: false,
        numSigners: 1,
        error: `Signature point failed subgroup check: ${parsedSig.error}`,
      };
    }

    // 3. Pairing verification
    try {
      let valid = false;
      if (pubGroup === 'G1') {
        valid = bls12_381.verify(sigBytes, msgBytes, pubBytes);
      } else {
        valid = bls12_381.verifyShortSignature(sigBytes, msgBytes, pubBytes);
      }

      return {
        valid,
        subgroupChecked: true,
        pairingComputed: true,
        numSigners: 1,
        error: valid ? undefined : 'BLS pairing check failed: signature mismatch',
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        valid: false,
        subgroupChecked: true,
        pairingComputed: false,
        numSigners: 1,
        error: `Verification error: ${msg}`,
      };
    }
  }

  /**
   * Verify an aggregated BLS signature.
   * Can verify:
   * 1. Multi-signer same message: signature = sum(sig_i), message = m, publicKeys = [pk1, pk2, ...]
   *    e(sigma_agg, G2) == e(H(m), sum(pk_i))
   * 2. Multi-signer distinct messages: signature = sum(sig_i), messages = [m1, m2, ...], publicKeys = [pk1, pk2, ...]
   *    e(sigma_agg, G2) == prod(e(H(m_i), pk_i))
   */
  public verifyAggregate(
    signature: Uint8Array | string,
    messages: (Uint8Array | string)[] | Uint8Array | string,
    publicKeys: (Uint8Array | string)[],
    options: BlsVerifyOptions = {},
  ): BlsSignatureVerifyResult {
    const pubGroup = options.group ?? 'G1';
    const sigBytes = toBytes(signature);
    const pubBytesList = publicKeys.map(toBytes);

    if (pubBytesList.length === 0) {
      return {
        valid: false,
        subgroupChecked: false,
        pairingComputed: false,
        numSigners: 0,
        error: 'No public keys provided for aggregated verification',
      };
    }

    // Check all public keys
    for (let i = 0; i < pubBytesList.length; i++) {
      const k = pubBytesList[i]!;
      const parsed = this.parsePublicKey(k, pubGroup);
      if (!parsed.valid || !parsed.inSubgroup) {
        return {
          valid: false,
          subgroupChecked: true,
          pairingComputed: false,
          numSigners: pubBytesList.length,
          error: `Public key at index ${i} failed subgroup check: ${parsed.error}`,
        };
      }
    }

    // Check signature point
    const sigGroup: BlsGroup = pubGroup === 'G1' ? 'G2' : 'G1';
    const parsedSig = this.parsePublicKey(sigBytes, sigGroup);
    if (!parsedSig.valid || !parsedSig.inSubgroup) {
      return {
        valid: false,
        subgroupChecked: true,
        pairingComputed: false,
        numSigners: pubBytesList.length,
        error: `Aggregated signature failed subgroup check: ${parsedSig.error}`,
      };
    }

    try {
      // Case 1: Same message across all signers
      if (!Array.isArray(messages) || (Array.isArray(messages) && messages.length === 1)) {
        const msg = Array.isArray(messages) ? messages[0]! : messages;
        const msgBytes = typeof msg === 'string' ? Buffer.from(msg, 'utf-8') : msg;
        const aggPub = this.aggregatePublicKeys(pubBytesList, pubGroup);

        const res = this.verifySingle(sigBytes, msgBytes, aggPub, options);
        return {
          ...res,
          numSigners: pubBytesList.length,
        };
      }

      // Case 2: Multi-message aggregated verification
      if (messages.length !== pubBytesList.length) {
        return {
          valid: false,
          subgroupChecked: true,
          pairingComputed: false,
          numSigners: pubBytesList.length,
          error: `Length mismatch: ${messages.length} messages but ${pubBytesList.length} public keys`,
        };
      }

      const byteMessages = messages.map((m) => (typeof m === 'string' ? Buffer.from(m, 'utf-8') : m));

      let valid = false;
      if (pubGroup === 'G1') {
        valid = bls12_381.verifyBatch(sigBytes, byteMessages, pubBytesList);
      } else {
        // Pairing check for G2 public keys:
        // Compute pairing batch: e(sigma, G2_generator) == prod(e(H(m_i), pk_i))
        const P_sig = bls12_381.G1.ProjectivePoint.fromHex(sigBytes);
        const neg_G2 = bls12_381.G2.ProjectivePoint.BASE.negate();
        const pairs: { g1: typeof bls12_381.G1.ProjectivePoint.prototype; g2: typeof bls12_381.G2.ProjectivePoint.prototype }[] = [
          { g1: P_sig, g2: neg_G2 },
        ];
        for (let i = 0; i < byteMessages.length; i++) {
          const m = byteMessages[i]!;
          const pk = pubBytesList[i]!;
          const Hm = bls12_381.G1.hashToCurve(m);
          const Q_pk = bls12_381.G2.ProjectivePoint.fromHex(pk);
          pairs.push({ g1: Hm, g2: Q_pk });
        }
        const paired = bls12_381.pairingBatch(pairs);
        valid = bls12_381.fields.Fp12.eql(paired, bls12_381.fields.Fp12.ONE);
      }

      return {
        valid,
        subgroupChecked: true,
        pairingComputed: true,
        numSigners: pubBytesList.length,
        error: valid ? undefined : 'Aggregated pairing check failed',
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        valid: false,
        subgroupChecked: true,
        pairingComputed: false,
        numSigners: pubBytesList.length,
        error: `Aggregate verification exception: ${msg}`,
      };
    }
  }

  /**
   * Audit stellar.toml for BLS12-381 key declarations.
   */
  public auditTomlBlsKeys(toml: Record<string, unknown> | string): BlsAuditReport {
    let parsed: Record<string, unknown>;
    if (typeof toml === 'string') {
      try {
        parsed = parseToml(toml) as Record<string, unknown>;
      } catch {
        parsed = {};
      }
    } else {
      parsed = toml;
    }

    const findings: BlsAuditFinding[] = [];

    const inspectKey = (val: unknown, field: string) => {
      if (typeof val !== 'string' || val.trim().length === 0) return;
      const keyStr = val.trim();
      // Skip if clearly not hex (e.g. Ed25519 G... stellar key)
      if (keyStr.startsWith('G') && keyStr.length === 56) return;

      const parseRes = this.parsePublicKey(keyStr);
      const issues: string[] = [];
      if (!parseRes.valid) {
        issues.push(parseRes.error || 'Invalid point on curve');
      } else if (!parseRes.inSubgroup) {
        issues.push('Point does not belong to prime-order subgroup r (vulnerable to small-subgroup attacks)');
      }

      findings.push({
        field,
        keyHex: parseRes.hex,
        group: parseRes.group,
        format: parseRes.format,
        valid: parseRes.valid && parseRes.inSubgroup,
        inSubgroup: parseRes.inSubgroup,
        issues,
      });
    };

    // 1. [BLS_KEYS] table
    if (typeof parsed.BLS_KEYS === 'object' && parsed.BLS_KEYS !== null) {
      const blsTable = parsed.BLS_KEYS as Record<string, unknown>;
      for (const [k, v] of Object.entries(blsTable)) {
        if (typeof v === 'string') {
          inspectKey(v, `BLS_KEYS.${k}`);
        } else if (Array.isArray(v)) {
          v.forEach((item, idx) => inspectKey(item, `BLS_KEYS.${k}[${idx}]`));
        }
      }
    }

    // 2. SIGNING_KEY_BLS in root or documentation
    if (parsed.SIGNING_KEY_BLS) {
      inspectKey(parsed.SIGNING_KEY_BLS, 'SIGNING_KEY_BLS');
    }
    const doc = parsed.DOCUMENTATION as Record<string, unknown> | undefined;
    if (doc?.SIGNING_KEY_BLS) {
      inspectKey(doc.SIGNING_KEY_BLS, 'DOCUMENTATION.SIGNING_KEY_BLS');
    }

    // 3. [[VALIDATORS]] BLS_PUBLIC_KEY
    if (Array.isArray(parsed.VALIDATORS)) {
      parsed.VALIDATORS.forEach((val, idx) => {
        if (typeof val === 'object' && val !== null) {
          const vObj = val as Record<string, unknown>;
          if (vObj.BLS_PUBLIC_KEY) {
            inspectKey(vObj.BLS_PUBLIC_KEY, `VALIDATORS[${idx}].BLS_PUBLIC_KEY`);
          }
        }
      });
    }

    // 4. [[BLS_SIGNERS]]
    if (Array.isArray(parsed.BLS_SIGNERS)) {
      parsed.BLS_SIGNERS.forEach((signer, idx) => {
        if (typeof signer === 'object' && signer !== null) {
          const sObj = signer as Record<string, unknown>;
          if (sObj.PUBLIC_KEY) inspectKey(sObj.PUBLIC_KEY, `BLS_SIGNERS[${idx}].PUBLIC_KEY`);
          if (sObj.BLS_PUBLIC_KEY) inspectKey(sObj.BLS_PUBLIC_KEY, `BLS_SIGNERS[${idx}].BLS_PUBLIC_KEY`);
        }
      });
    }

    const validKeys = findings.filter((f) => f.valid).length;
    const allValid = findings.length > 0 && validKeys === findings.length;

    let summary: string;
    if (findings.length === 0) {
      summary = 'No BLS12-381 keys declared in stellar.toml';
    } else if (allValid) {
      summary = `Verified ${findings.length} BLS12-381 key(s) with valid subgroup membership`;
    } else {
      summary = `Found ${findings.length - validKeys} invalid BLS12-381 key(s) out of ${findings.length}`;
    }

    return {
      totalKeys: findings.length,
      validKeys,
      findings,
      allValid,
      summary,
    };
  }
}
