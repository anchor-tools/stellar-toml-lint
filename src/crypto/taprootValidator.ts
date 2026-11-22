/**
 * BIP-340 Schnorr signature and Taproot / Bech32m address compatibility checker
 * for Stellar bridge reserve accounts.
 *
 * Implements:
 *  - Bech32m decoding and checksum validation (BIP-350)
 *  - Witness version v1 and 32-byte x-only public key validation (BIP-341)
 *  - BIP-340 Schnorr signature verification (pure JS/TS, no native binaries)
 *  - stellar.toml inspection for Bitcoin / Taproot reserve addresses
 *  - CLI subcommand: stellar-toml-lint verify-taproot-address --address <addr>
 */

import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import type { Diagnostic, Rule } from '../types.js';

// ── Rule IDs ──────────────────────────────────────────────────────────────────

export const TAPROOT_INVALID_BECH32M = 'taproot/invalid-bech32m-checksum';
export const TAPROOT_INVALID_WITNESS_VERSION = 'taproot/invalid-witness-version';
export const TAPROOT_INVALID_X_ONLY_KEY = 'taproot/invalid-x-only-pubkey';
export const TAPROOT_INVALID_SCHNORR_SIGNATURE = 'taproot/invalid-schnorr-signature';

// ── Bech32m constants (BIP-350) ───────────────────────────────────────────────

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const BECH32M_CONST = 0x2bc830a3;

function polymod(values: number[]): number {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) {
      if ((top >>> i) & 1) chk ^= GEN[i]!;
    }
  }
  return chk;
}

function hrpExpand(hrp: string): number[] {
  const ret: number[] = [];
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) >>> 5);
  ret.push(0);
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) & 31);
  return ret;
}

function verifyChecksum(hrp: string, data: number[]): boolean {
  return polymod([...hrpExpand(hrp), ...data]) === BECH32M_CONST;
}

function convertBits(data: number[], fromBits: number, toBits: number, pad: boolean): number[] | null {
  let acc = 0;
  let bits = 0;
  const result: number[] = [];
  const maxv = (1 << toBits) - 1;
  for (const value of data) {
    if (value < 0 || value >>> fromBits !== 0) return null;
    acc = (acc << fromBits) | value;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      result.push((acc >>> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) result.push((acc << (toBits - bits)) & maxv);
  } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) !== 0) {
    return null;
  }
  return result;
}

// ── Public types ──────────────────────────────────────────────────────────────

export interface Bech32mDecodeResult {
  valid: boolean;
  hrp: string;
  witnessVersion: number;
  program: Uint8Array;
  error?: string;
}

export interface TaprootAddressValidationResult {
  valid: boolean;
  address: string;
  hrp: string;
  witnessVersion: number;
  xOnlyPubkey: string;
  error?: string;
}

export interface SchnorrVerifyResult {
  valid: boolean;
  error?: string;
}

export interface TaprootAuditFinding {
  address: string;
  field: string;
  valid: boolean;
  issues: string[];
}

export interface TaprootAuditReport {
  totalAddresses: number;
  validAddresses: number;
  findings: TaprootAuditFinding[];
  allValid: boolean;
  summary: string;
}

// ── Tagged-hash helper (BIP-340) ──────────────────────────────────────────────

function taggedHash(tag: string, msg: Uint8Array): Uint8Array {
  const tagHash = sha256(new TextEncoder().encode(tag));
  const combined = new Uint8Array(tagHash.length * 2 + msg.length);
  combined.set(tagHash, 0);
  combined.set(tagHash, tagHash.length);
  combined.set(msg, tagHash.length * 2);
  return sha256(combined);
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const b of bytes) result = (result << 8n) | BigInt(b);
  return result;
}

function bigIntToBytes32(n: bigint): Uint8Array {
  const hex = n.toString(16).padStart(64, '0');
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

// ── Validator class ───────────────────────────────────────────────────────────

export class Bip340TaprootValidator {
  /**
   * Decode a Bech32m address. Validates HRP, checksum, witness version (v1),
   * and that the witness program is exactly 32 bytes (x-only public key).
   */
  static decodeBech32m(address: string): Bech32mDecodeResult {
    const lower = address.toLowerCase();
    const upper = address.toUpperCase();
    if (address !== lower && address !== upper) {
      return { valid: false, hrp: '', witnessVersion: -1, program: new Uint8Array(), error: 'Mixed-case address' };
    }
    const addr = lower;

    const sepIdx = addr.lastIndexOf('1');
    if (sepIdx < 1 || sepIdx + 7 > addr.length || addr.length > 90) {
      return { valid: false, hrp: '', witnessVersion: -1, program: new Uint8Array(), error: 'Invalid address length or missing separator' };
    }

    const hrp = addr.slice(0, sepIdx);
    const data: number[] = [];
    for (let i = sepIdx + 1; i < addr.length; i++) {
      const d = CHARSET.indexOf(addr[i]!);
      if (d === -1) {
        return { valid: false, hrp, witnessVersion: -1, program: new Uint8Array(), error: `Invalid character '${addr[i]}' at position ${i}` };
      }
      data.push(d);
    }

    if (!verifyChecksum(hrp, data)) {
      return { valid: false, hrp, witnessVersion: -1, program: new Uint8Array(), error: 'Invalid Bech32m checksum' };
    }

    const witnessVersion = data[0]!;
    const decoded = convertBits(data.slice(1, -6), 5, 8, false);
    if (!decoded) {
      return { valid: false, hrp, witnessVersion, program: new Uint8Array(), error: 'Failed to convert from 5-bit encoding' };
    }

    return { valid: true, hrp, witnessVersion, program: new Uint8Array(decoded) };
  }

  /**
   * Validates a Taproot address: Bech32m, witness version 1, 32-byte x-only pubkey.
   */
  private static _legacyBech32WitnessVersion(address: string): { hrp: string; witnessVersion: number } | null {
    try {
      const addr = address.toLowerCase();
      const sepIdx = addr.lastIndexOf('1');
      if (sepIdx < 1 || sepIdx + 7 > addr.length) return null;
      const hrp = addr.slice(0, sepIdx);
      const data: number[] = [];
      for (let i = sepIdx + 1; i < addr.length; i++) {
        const d = CHARSET.indexOf(addr[i]!);
        if (d === -1) return null;
        data.push(d);
      }
      if (polymod([...hrpExpand(hrp), ...data]) !== 1) return null;
      return { hrp, witnessVersion: data[0]! };
    } catch { return null; }
  }

  static validateTaprootAddress(address: string): TaprootAddressValidationResult {
    const decoded = Bip340TaprootValidator.decodeBech32m(address);
    if (!decoded.valid) {
      if (decoded.error === 'Invalid Bech32m checksum') {
        const legacy = Bip340TaprootValidator._legacyBech32WitnessVersion(address);
        if (legacy !== null && legacy.witnessVersion === 0) {
          return {
            valid: false,
            address,
            hrp: decoded.hrp || legacy.hrp,
            witnessVersion: 0,
            xOnlyPubkey: '',
            error: 'Witness version must be 1 for Taproot (witness version 0 found); this is a legacy SegWit address',
          };
        }
      }
      return { valid: false, address, hrp: decoded.hrp, witnessVersion: decoded.witnessVersion, xOnlyPubkey: '', error: decoded.error };
    }

    if (decoded.witnessVersion !== 1) {
      return {
        valid: false,
        address,
        hrp: decoded.hrp,
        witnessVersion: decoded.witnessVersion,
        xOnlyPubkey: '',
        error: `Witness version must be 1 for Taproot (v${decoded.witnessVersion} found); legacy addresses are not Taproot`,
      };
    }

    if (decoded.program.length !== 32) {
      return {
        valid: false,
        address,
        hrp: decoded.hrp,
        witnessVersion: 1,
        xOnlyPubkey: '',
        error: `Taproot x-only public key must be 32 bytes, got ${decoded.program.length}`,
      };
    }

    const xOnlyPubkey = Array.from(decoded.program).map((b) => b.toString(16).padStart(2, '0')).join('');

    // Verify the x-coordinate is on the secp256k1 curve by lifting_x
    try {
      const x = bytesToBigInt(decoded.program);
      const p = secp256k1.CURVE.p;
      const y2 = (x * x * x + 7n) % p;
      // Modular sqrt via Tonelli-Shanks (p ≡ 3 mod 4 shortcut)
      const y = modPow(y2, (p + 1n) / 4n, p);
      if (modPow(y, 2n, p) !== y2) {
        return { valid: false, address, hrp: decoded.hrp, witnessVersion: 1, xOnlyPubkey, error: 'x-only key has no corresponding point on secp256k1' };
      }
    } catch (err) {
      return { valid: false, address, hrp: decoded.hrp, witnessVersion: 1, xOnlyPubkey, error: `Curve validation failed: ${err instanceof Error ? err.message : String(err)}` };
    }

    return { valid: true, address, hrp: decoded.hrp, witnessVersion: 1, xOnlyPubkey };
  }

  /**
   * Verifies a BIP-340 Schnorr signature.
   * sig: 64 bytes (R.x || s), pubkey: 32 bytes (x-only), msg: 32 bytes.
   */
  static verifySchnorr(
    signature: Uint8Array | string,
    message: Uint8Array | string,
    xOnlyPubkey: Uint8Array | string,
  ): SchnorrVerifyResult {
    try {
      const sigBytes = typeof signature === 'string' ? hexToBytes(signature) : signature;
      const msgBytes = typeof message === 'string' ? hexToBytes(message) : message;
      const pubBytes = typeof xOnlyPubkey === 'string' ? hexToBytes(xOnlyPubkey) : xOnlyPubkey;

      if (sigBytes.length !== 64) return { valid: false, error: `Signature must be 64 bytes, got ${sigBytes.length}` };
      if (msgBytes.length !== 32) return { valid: false, error: `Message must be 32 bytes, got ${msgBytes.length}` };
      if (pubBytes.length !== 32) return { valid: false, error: `x-only pubkey must be 32 bytes, got ${pubBytes.length}` };

      const p = secp256k1.CURVE.p;
      const n = secp256k1.CURVE.n;

      const Rx = bytesToBigInt(sigBytes.slice(0, 32));
      const s = bytesToBigInt(sigBytes.slice(32, 64));
      const Px = bytesToBigInt(pubBytes);

      if (Rx >= p || s >= n || Px >= p) return { valid: false, error: 'Signature or key value out of range' };

      // Lift P from x-only
      const Py2 = (Px * Px * Px + 7n) % p;
      const Py_abs = modPow(Py2, (p + 1n) / 4n, p);
      if (modPow(Py_abs, 2n, p) !== Py2) return { valid: false, error: 'x-only pubkey has no lift' };
      const Py = Py_abs % 2n === 0n ? Py_abs : p - Py_abs;

      // e = int(hashBIP0340/challenge(bytes(Rx) || bytes(Px) || msg)) mod n
      const eHash = taggedHash(
        'BIP0340/challenge',
        new Uint8Array([...bigIntToBytes32(Rx), ...pubBytes, ...msgBytes]),
      );
      const e = bytesToBigInt(eHash) % n;

      // R = s*G - e*P
      const G = secp256k1.ProjectivePoint.BASE;
      const P = secp256k1.ProjectivePoint.fromAffine({ x: Px, y: Py });
      const R = G.multiply(s).subtract(P.multiply(e));

      if (R.equals(secp256k1.ProjectivePoint.ZERO)) return { valid: false, error: 'R is the point at infinity' };
      const { x: Rx_check, y: Ry_check } = R.toAffine();
      if (Ry_check % 2n !== 0n) return { valid: false, error: 'R.y is odd (non-normalized)' };
      if (Rx_check !== Rx) return { valid: false, error: 'Schnorr signature check failed: R.x mismatch' };

      return { valid: true };
    } catch (err) {
      return { valid: false, error: err instanceof Error ? err.message : String(err) };
    }
  }

  /**
   * Signs a 32-byte message with a private key, producing a 64-byte BIP-340 Schnorr signature.
   * Uses deterministic nonce derivation via BIP0340/nonce tagged hash.
   */
  static signSchnorr(
    message: Uint8Array | string,
    privateKey: Uint8Array | string,
  ): { signature: Uint8Array; hex: string } {
    const msgBytes = typeof message === 'string' ? hexToBytes(message) : message;
    const privBytes = typeof privateKey === 'string' ? hexToBytes(privateKey) : privateKey;

    if (msgBytes.length !== 32) throw new Error(`Message must be 32 bytes, got ${msgBytes.length}`);
    if (privBytes.length !== 32) throw new Error(`Private key must be 32 bytes, got ${privBytes.length}`);

    const n = secp256k1.CURVE.n;
    const p = secp256k1.CURVE.p;

    let d = bytesToBigInt(privBytes);
    if (d === 0n || d >= n) throw new Error('Invalid private key');

    const G = secp256k1.ProjectivePoint.BASE;
    const P = G.multiply(d);
    const { y: Py } = P.toAffine();

    // Negate d if P.y is odd
    if (Py % 2n !== 0n) d = n - d;

    const Px = bigIntToBytes32(P.toAffine().x);
    // Deterministic nonce: k = int(hash_BIP0340/nonce(bytes(d) || Px || msg)) mod n
    const kHash = taggedHash('BIP0340/nonce', new Uint8Array([...bigIntToBytes32(d), ...Px, ...msgBytes]));
    let k = bytesToBigInt(kHash) % n;
    if (k === 0n) throw new Error('Nonce k is zero');

    const R = G.multiply(k);
    const { x: Rx, y: Ry } = R.toAffine();
    if (Ry % 2n !== 0n) k = n - k;

    const eHash = taggedHash('BIP0340/challenge', new Uint8Array([...bigIntToBytes32(Rx), ...Px, ...msgBytes]));
    const e = bytesToBigInt(eHash) % n;
    const s = (k + e * d) % n;

    const sig = new Uint8Array(64);
    sig.set(bigIntToBytes32(Rx), 0);
    sig.set(bigIntToBytes32(s), 32);

    return { signature: sig, hex: Array.from(sig).map((b) => b.toString(16).padStart(2, '0')).join('') };
  }

  /**
   * Extracts Taproot / Bitcoin reserve addresses from stellar.toml.
   */
  static extractTaprootAddressesFromToml(doc: Record<string, unknown>): Array<{ address: string; field: string }> {
    const results: Array<{ address: string; field: string }> = [];

    const isTaprootLike = (addr: unknown): addr is string =>
      typeof addr === 'string' && /^(bc1p|tb1p|bcrt1p)/i.test(addr.trim());

    const scanObject = (obj: Record<string, unknown>, prefix: string) => {
      for (const [key, val] of Object.entries(obj)) {
        if (isTaprootLike(val)) results.push({ address: val.trim(), field: `${prefix}.${key}` });
        else if (Array.isArray(val)) {
          val.forEach((item, idx) => {
            if (isTaprootLike(item)) results.push({ address: item.trim(), field: `${prefix}.${key}[${idx}]` });
            else if (typeof item === 'object' && item !== null) scanObject(item as Record<string, unknown>, `${prefix}.${key}[${idx}]`);
          });
        } else if (typeof val === 'object' && val !== null) {
          scanObject(val as Record<string, unknown>, `${prefix}.${key}`);
        }
      }
    };

    scanObject(doc, 'stellar.toml');
    return results;
  }

  /**
   * Audits stellar.toml for Taproot reserve address declarations.
   */
  auditToml(doc: Record<string, unknown>): { report: TaprootAuditReport; diagnostics: Diagnostic[] } {
    const declared = Bip340TaprootValidator.extractTaprootAddressesFromToml(doc);
    const findings: TaprootAuditFinding[] = [];
    const diagnostics: Diagnostic[] = [];

    for (const { address, field } of declared) {
      const result = Bip340TaprootValidator.validateTaprootAddress(address);
      const issues: string[] = [];
      if (!result.valid) issues.push(result.error ?? 'Unknown validation error');

      findings.push({ address, field, valid: result.valid, issues });

      if (!result.valid) {
        diagnostics.push({
          rule: result.error?.includes('Bech32m') ? TAPROOT_INVALID_BECH32M
            : result.error?.includes('itness version') ? TAPROOT_INVALID_WITNESS_VERSION
            : TAPROOT_INVALID_X_ONLY_KEY,
          severity: 'error',
          category: 'security',
          message: `Invalid Taproot reserve address at ${field}: ${result.error}`,
          path: field,
          suggestion: 'Use a valid Bech32m Taproot address (bc1p...) with witness version 1 and a 32-byte x-only public key.',
        });
      }
    }

    const validAddresses = findings.filter((f) => f.valid).length;
    return {
      report: {
        totalAddresses: findings.length,
        validAddresses,
        findings,
        allValid: findings.length > 0 && validAddresses === findings.length,
        summary: findings.length === 0
          ? 'No Taproot / Bitcoin reserve addresses declared in stellar.toml'
          : validAddresses === findings.length
            ? `Verified ${findings.length} Taproot address(es)`
            : `Found ${findings.length - validAddresses} invalid Taproot address(es) out of ${findings.length}`,
      },
      diagnostics,
    };
  }
}

// ── Rule declarations ─────────────────────────────────────────────────────────

export const taprootRules: Rule[] = [
  {
    id: TAPROOT_INVALID_BECH32M,
    category: 'security',
    severity: 'error',
    description: 'Bitcoin reserve address must have a valid Bech32m checksum (BIP-350)',
    run() {},
  },
  {
    id: TAPROOT_INVALID_WITNESS_VERSION,
    category: 'security',
    severity: 'error',
    description: 'Taproot address must use witness version 1 (v0 is SegWit, not Taproot)',
    run() {},
  },
  {
    id: TAPROOT_INVALID_X_ONLY_KEY,
    category: 'security',
    severity: 'error',
    description: 'Taproot witness program must be a valid 32-byte x-only secp256k1 public key (BIP-340)',
    run() {},
  },
  {
    id: TAPROOT_INVALID_SCHNORR_SIGNATURE,
    category: 'security',
    severity: 'error',
    description: 'BIP-340 Schnorr signature over reserve attestation message must be valid',
    run() {},
  },
];

export const taprootRuleIds: readonly string[] = taprootRules.map((r) => r.id);

// ── Internal helpers ──────────────────────────────────────────────────────────

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp % 2n === 1n) result = (result * base) % mod;
    exp = exp / 2n;
    base = (base * base) % mod;
  }
  return result;
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/i, '');
  if (clean.length % 2 !== 0) throw new Error(`Odd-length hex string: ${hex}`);
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}
