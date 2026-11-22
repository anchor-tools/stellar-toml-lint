/**
 * Automated verification of secp256k1 recoverable signatures for EVM-Stellar bridges.
 *
 * Parses 65-byte recoverable signatures (r, s, v), recovers uncompressed and compressed
 * public keys, derives EIP-55 checksummed EVM addresses via Keccak-256, and matches
 * recovered signer addresses against bridge contracts or validator declarations in stellar.toml.
 */

import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { sha256 } from '@noble/hashes/sha256';
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';

export const CRYPTO_INVALID_SECP256K1_SIGNATURE = 'crypto/invalid-secp256k1-signature';
export const CRYPTO_BRIDGE_SIGNER_UNMATCHED = 'crypto/bridge-signer-unmatched';
export const CRYPTO_MALFORMED_SIGNATURE = 'crypto/malformed-signature';

export interface ParsedSignature {
  r: bigint;
  s: bigint;
  v: number;
  recoveryBit: number;
  rawBytes: Uint8Array;
}

export interface RecoveredKeys {
  compressedPublicKey: string; // 33 bytes hex (0x02... or 0x03...)
  uncompressedPublicKey: string; // 65 bytes hex (0x04...)
  rawUncompressedPublicKey: string; // 64 bytes hex (X || Y)
  evmAddress: string; // lowercase 0x... (40 hex chars)
  checksumAddress: string; // EIP-55 checksummed address
}

export interface BridgeSignatureVerificationResult {
  ok: boolean;
  valid: boolean;
  signerMatched: boolean;
  recovered?: RecoveredKeys;
  matchedDeclaration?: string;
  expectedAddresses?: string[];
  error?: string;
}

export interface Secp256k1BridgeVerifierOptions {
  rules?: RuleOverrides;
  strictLowS?: boolean;
}

export type MessageHashAlgorithm = 'keccak256' | 'sha256' | 'raw' | 'eip191';

/** Helper to convert hex string or buffer to Uint8Array */
function toBytes(input: Uint8Array | string): Uint8Array {
  if (input instanceof Uint8Array) return input;
  let clean = input.trim();
  if (clean.startsWith('0x') || clean.startsWith('0X')) clean = clean.slice(2);
  if (clean.length % 2 !== 0) clean = '0' + clean;
  const len = clean.length / 2;
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    out[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** EIP-55 mixed-case checksum address encoder */
export function toChecksumAddress(address: string): string {
  const clean = address.toLowerCase().replace(/^0x/, '');
  const hash = Buffer.from(keccak_256(new TextEncoder().encode(clean))).toString('hex');
  let ret = '0x';
  for (let i = 0; i < clean.length; i++) {
    const char = clean[i]!;
    if (parseInt(hash[i]!, 16) >= 8) {
      ret += char.toUpperCase();
    } else {
      ret += char;
    }
  }
  return ret;
}

export class Secp256k1BridgeVerifier {
  readonly options: Secp256k1BridgeVerifierOptions;

  constructor(options: Secp256k1BridgeVerifierOptions = {}) {
    this.options = options;
  }

  /**
   * Hashes a message or raw payload according to the designated scheme.
   */
  static hashMessage(
    message: Uint8Array | string,
    algorithm: MessageHashAlgorithm = 'keccak256',
  ): Uint8Array {
    const bytes = typeof message === 'string' ? new TextEncoder().encode(message) : message;

    switch (algorithm) {
      case 'raw':
        if (bytes.length !== 32) {
          throw new Error(`Raw message hash must be exactly 32 bytes, got ${bytes.length}`);
        }
        return bytes;

      case 'sha256':
        return sha256(bytes);

      case 'eip191': {
        const prefix = `\x19Ethereum Signed Message:\n${bytes.length}`;
        const prefixBytes = new TextEncoder().encode(prefix);
        const combined = new Uint8Array(prefixBytes.length + bytes.length);
        combined.set(prefixBytes, 0);
        combined.set(bytes, prefixBytes.length);
        return keccak_256(combined);
      }

      case 'keccak256':
      default:
        return keccak_256(bytes);
    }
  }

  /**
   * Parses a 65-byte recoverable signature (r[32], s[32], v[1]) or signature object.
   */
  static parseSignature(
    sigInput:
      | Uint8Array
      | string
      | { r: string | bigint | Uint8Array; s: string | bigint | Uint8Array; v: number | bigint },
  ): ParsedSignature {
    let rBig: bigint;
    let sBig: bigint;
    let vNum: number;
    let rawBytes: Uint8Array;

    if (typeof sigInput === 'object' && !(sigInput instanceof Uint8Array)) {
      rBig = typeof sigInput.r === 'bigint' ? sigInput.r : BigInt(typeof sigInput.r === 'string' && !sigInput.r.startsWith('0x') ? `0x${sigInput.r}` : sigInput.r.toString());
      sBig = typeof sigInput.s === 'bigint' ? sigInput.s : BigInt(typeof sigInput.s === 'string' && !sigInput.s.startsWith('0x') ? `0x${sigInput.s}` : sigInput.s.toString());
      vNum = Number(sigInput.v);

      rawBytes = new Uint8Array(65);
      const rBytes = toBytes(rBig.toString(16).padStart(64, '0'));
      const sBytes = toBytes(sBig.toString(16).padStart(64, '0'));
      rawBytes.set(rBytes, 0);
      rawBytes.set(sBytes, 32);
      rawBytes[64] = vNum;
    } else {
      rawBytes = toBytes(sigInput);
      if (rawBytes.length !== 65) {
        throw new Error(`Expected 65-byte recoverable signature, got ${rawBytes.length} bytes`);
      }

      let rHex = '';
      for (let i = 0; i < 32; i++) rHex += rawBytes[i]!.toString(16).padStart(2, '0');
      let sHex = '';
      for (let i = 32; i < 64; i++) sHex += rawBytes[i]!.toString(16).padStart(2, '0');

      rBig = BigInt(`0x${rHex}`);
      sBig = BigInt(`0x${sHex}`);
      vNum = rawBytes[64]!;
    }

    const n = secp256k1.CURVE.n;
    if (rBig <= 0n || rBig >= n) {
      throw new Error(`Signature r value ${rBig} out of curve range`);
    }
    if (sBig <= 0n || sBig >= n) {
      throw new Error(`Signature s value ${sBig} out of curve range`);
    }

    // Determine 0/1 recovery bit from v (standard 0/1, 27/28, or EIP-155 v >= 35)
    let recoveryBit: number;
    if (vNum === 0 || vNum === 1) {
      recoveryBit = vNum;
    } else if (vNum === 27 || vNum === 28) {
      recoveryBit = vNum - 27;
    } else if (vNum >= 35) {
      recoveryBit = (vNum - 35) % 2;
    } else {
      throw new Error(`Invalid recovery identifier v: ${vNum}`);
    }

    return {
      r: rBig,
      s: sBig,
      v: vNum,
      recoveryBit,
      rawBytes,
    };
  }

  /**
   * Recovers public keys and derives the EVM address from a signature and message hash.
   */
  static recoverAddress(
    sigInput:
      | Uint8Array
      | string
      | { r: string | bigint | Uint8Array; s: string | bigint | Uint8Array; v: number | bigint },
    messageOrHash: Uint8Array | string,
    algorithm: MessageHashAlgorithm = 'keccak256',
    strictLowS = false,
  ): RecoveredKeys {
    const parsed = Secp256k1BridgeVerifier.parseSignature(sigInput);

    if (strictLowS) {
      const halfN = secp256k1.CURVE.n >> 1n;
      if (parsed.s > halfN) {
        throw new Error('Signature s value violates canonical low-s requirement');
      }
    }

    const msgHash = Secp256k1BridgeVerifier.hashMessage(messageOrHash, algorithm);

    // Format 64-byte compact signature for noble-curves
    const compact64 = parsed.rawBytes.slice(0, 64);
    const sig = secp256k1.Signature.fromCompact(compact64).addRecoveryBit(parsed.recoveryBit);
    const point = sig.recoverPublicKey(msgHash);

    const compressed = point.toRawBytes(true);
    const uncompressed = point.toRawBytes(false);
    const raw64 = uncompressed.slice(1); // Drop 0x04 uncompressed prefix

    // EVM address = keccak256(raw64).slice(12, 32)
    const hash = keccak_256(raw64);
    const addressBytes = hash.slice(12, 32);

    let addressHex = '0x';
    for (let i = 0; i < addressBytes.length; i++) {
      addressHex += addressBytes[i]!.toString(16).padStart(2, '0');
    }

    const checksumAddress = toChecksumAddress(addressHex);

    return {
      compressedPublicKey: '0x' + Buffer.from(compressed).toString('hex'),
      uncompressedPublicKey: '0x' + Buffer.from(uncompressed).toString('hex'),
      rawUncompressedPublicKey: '0x' + Buffer.from(raw64).toString('hex'),
      evmAddress: addressHex.toLowerCase(),
      checksumAddress,
    };
  }

  /**
   * Verifies a bridge signature against a list of expected EVM contracts or validator signers.
   */
  verifyBridgeSignature(
    sigInput:
      | Uint8Array
      | string
      | { r: string | bigint | Uint8Array; s: string | bigint | Uint8Array; v: number | bigint },
    messageOrHash: Uint8Array | string,
    expectedAddresses: string[],
    algorithm: MessageHashAlgorithm = 'keccak256',
  ): BridgeSignatureVerificationResult {
    try {
      const recovered = Secp256k1BridgeVerifier.recoverAddress(
        sigInput,
        messageOrHash,
        algorithm,
        this.options.strictLowS,
      );

      const normalizedExpected = expectedAddresses.map((a) => a.toLowerCase().trim());
      const matchIndex = normalizedExpected.indexOf(recovered.evmAddress.toLowerCase());

      return {
        ok: true,
        valid: true,
        signerMatched: matchIndex >= 0,
        recovered,
        matchedDeclaration: matchIndex >= 0 ? expectedAddresses[matchIndex] : undefined,
        expectedAddresses,
      };
    } catch (err) {
      return {
        ok: false,
        valid: false,
        signerMatched: false,
        expectedAddresses,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }

  /**
   * Helper to produce a 65-byte recoverable signature from a private key.
   */
  static sign(
    messageOrHash: Uint8Array | string,
    privateKey: Uint8Array | string,
    algorithm: MessageHashAlgorithm = 'keccak256',
  ): { signature65: Uint8Array; hex: string; r: string; s: string; v: number } {
    const privBytes = toBytes(privateKey);
    const hash = Secp256k1BridgeVerifier.hashMessage(messageOrHash, algorithm);
    const sig = secp256k1.sign(hash, privBytes);

    const compact = sig.toCompactRawBytes();
    const sig65 = new Uint8Array(65);
    sig65.set(compact, 0);
    // Standard EVM v = recovery + 27
    const v = sig.recovery + 27;
    sig65[64] = v;

    const rHex = Buffer.from(compact.slice(0, 32)).toString('hex');
    const sHex = Buffer.from(compact.slice(32, 64)).toString('hex');

    return {
      signature65: sig65,
      hex: '0x' + Buffer.from(sig65).toString('hex'),
      r: '0x' + rHex,
      s: '0x' + sHex,
      v,
    };
  }

  /**
   * Extracts bridge and validator EVM addresses declared in stellar.toml.
   */
  static extractBridgeAddressesFromToml(doc: Record<string, unknown>): Array<{ address: string; path: string }> {
    const results: Array<{ address: string; path: string }> = [];

    const isEvmAddress = (addr: unknown): addr is string =>
      typeof addr === 'string' && /^0x[a-fA-F0-9]{40}$/.test(addr.trim());

    // Check [BRIDGE] or [[BRIDGES]] or [EVM]
    const bridgeTables = [doc.BRIDGE, doc.BRIDGES, doc.EVM, doc.EVM_BRIDGE].filter(Boolean);
    bridgeTables.forEach((entry, idx) => {
      const items = Array.isArray(entry) ? entry : [entry];
      items.forEach((item, itemIdx) => {
        if (typeof item !== 'object' || item === null) return;
        const b = item as Record<string, unknown>;
        const basePath = Array.isArray(entry) ? `BRIDGES[${itemIdx}]` : 'BRIDGE';

        for (const key of ['BRIDGE_ADDRESS', 'CONTRACT_ADDRESS', 'EVM_ADDRESS', 'SIGNER_ADDRESS']) {
          if (isEvmAddress(b[key])) {
            results.push({ address: b[key] as string, path: `${basePath}.${key}` });
          }
        }

        if (Array.isArray(b.VALIDATOR_ADDRESSES)) {
          b.VALIDATOR_ADDRESSES.forEach((v, vIdx) => {
            if (isEvmAddress(v)) {
              results.push({ address: v, path: `${basePath}.VALIDATOR_ADDRESSES[${vIdx}]` });
            }
          });
        }
      });
    });

    // Check [[VALIDATORS]]
    if (Array.isArray(doc.VALIDATORS)) {
      doc.VALIDATORS.forEach((val, idx) => {
        if (typeof val !== 'object' || val === null) return;
        const v = val as Record<string, unknown>;
        for (const key of ['EVM_ADDRESS', 'ETH_ADDRESS', 'BRIDGE_SIGNER']) {
          if (isEvmAddress(v[key])) {
            results.push({ address: v[key] as string, path: `VALIDATORS[${idx}].${key}` });
          }
        }
      });
    }

    // Check [[CURRENCIES]]
    if (Array.isArray(doc.CURRENCIES)) {
      doc.CURRENCIES.forEach((cur, idx) => {
        if (typeof cur !== 'object' || cur === null) return;
        const c = cur as Record<string, unknown>;
        for (const key of ['bridge_address', 'evm_contract', 'custody_address']) {
          if (isEvmAddress(c[key])) {
            results.push({ address: c[key] as string, path: `CURRENCIES[${idx}].${key}` });
          }
        }
      });
    }

    // Top-level keys
    for (const key of ['BRIDGE_CONTRACT', 'EVM_BRIDGE_ADDRESS', 'BRIDGE_SIGNER']) {
      if (isEvmAddress(doc[key])) {
        results.push({ address: doc[key] as string, path: key });
      }
    }

    return results;
  }

  /**
   * Audits bridge signatures against stellar.toml declarations.
   */
  auditTomlBridgeSignatures(
    doc: Record<string, unknown>,
    attestations?: Array<{
      signature: Uint8Array | string;
      message: Uint8Array | string;
      algorithm?: MessageHashAlgorithm;
    }>,
  ): Diagnostic[] {
    const diagnostics: Diagnostic[] = [];
    const declared = Secp256k1BridgeVerifier.extractBridgeAddressesFromToml(doc);
    const declaredAddresses = declared.map((d) => d.address);

    if (!attestations || attestations.length === 0) {
      return diagnostics;
    }

    attestations.forEach((attestation, idx) => {
      try {
        const result = this.verifyBridgeSignature(
          attestation.signature,
          attestation.message,
          declaredAddresses,
          attestation.algorithm ?? 'keccak256',
        );

        if (!result.valid) {
          diagnostics.push({
            rule: CRYPTO_INVALID_SECP256K1_SIGNATURE,
            severity: 'error',
            category: 'security',
            message: `Bridge signature #${idx} is cryptographically invalid: ${result.error}`,
            suggestion: 'Verify the secp256k1 signature and signed message hash.',
          });
        } else if (!result.signerMatched) {
          diagnostics.push({
            rule: CRYPTO_BRIDGE_SIGNER_UNMATCHED,
            severity: 'warning',
            category: 'security',
            message: `Recovered EVM signer ${result.recovered?.checksumAddress} does not match any declared bridge contract or validator in stellar.toml`,
            suggestion: 'Register the EVM bridge signer address under [BRIDGE] or [[VALIDATORS]].',
          });
        }
      } catch (err) {
        diagnostics.push({
          rule: CRYPTO_MALFORMED_SIGNATURE,
          severity: 'error',
          category: 'security',
          message: `Malformed secp256k1 bridge signature #${idx}: ${err instanceof Error ? err.message : String(err)}`,
          suggestion: 'Provide a valid 65-byte recoverable secp256k1 signature.',
        });
      }
    });

    return diagnostics;
  }
}

/** Rule declarations */
export const secp256k1BridgeRules: Rule[] = [
  {
    id: CRYPTO_INVALID_SECP256K1_SIGNATURE,
    category: 'security',
    severity: 'error',
    description: 'Secp256k1 recoverable bridge signature must be cryptographically valid',
    run() {},
  },
  {
    id: CRYPTO_BRIDGE_SIGNER_UNMATCHED,
    category: 'security',
    severity: 'warning',
    description: 'Recovered EVM bridge signer address should match declared bridge contracts or validators in stellar.toml',
    run() {},
  },
  {
    id: CRYPTO_MALFORMED_SIGNATURE,
    category: 'security',
    severity: 'error',
    description: 'Secp256k1 recoverable signature must be properly formatted 65 bytes (r, s, v)',
    run() {},
  },
];

export const secp256k1BridgeRuleIds: readonly string[] = secp256k1BridgeRules.map((r) => r.id);
