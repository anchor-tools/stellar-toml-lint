/**
 * Cryptographic verification of `[[CURRENCIES]]` collateral signatures.
 *
 * SEP-1 lets an issuer prove control of its reserve addresses by publishing,
 * for each entry in `collateral_addresses`, a message and that message signed
 * by the address's key. Matching list lengths prove nothing; only verifying
 * the signature does. Three address families are understood:
 *
 * - Stellar `G...` accounts: an Ed25519 signature over the raw message, or
 *   over the SEP-53 `Stellar Signed Message` digest.
 * - Bitcoin `1...`, `3...`, and `bc1q...` addresses: a BIP-137 compact
 *   secp256k1 signature, whose recovered key must hash to the address.
 * - Ethereum `0x...` addresses: an EIP-191 `personal_sign` signature, whose
 *   recovered key must hash to the address.
 *
 * Everything runs offline on pure-JS primitives (`@noble/*`, already shipped
 * with `@stellar/stellar-base`), so it works in the browser bundle too.
 */
import { StrKey } from '@stellar/stellar-base';
import { ed25519 } from '@noble/curves/ed25519';
import { secp256k1 } from '@noble/curves/secp256k1';
import { ripemd160 } from '@noble/hashes/legacy';
import { sha256 } from '@noble/hashes/sha2';
import { keccak_256 } from '@noble/hashes/sha3';

/**
 * - `valid`: the signature verifies against the address.
 * - `invalid`: it decodes, but was not produced by the address's key over the message.
 * - `malformed`: it is not base64 (or `0x` hex for Ethereum) of the right length.
 * - `unsupported`: the address family is not one this module can verify.
 */
export type CollateralVerdict = 'valid' | 'invalid' | 'malformed' | 'unsupported';

type Scheme = 'stellar' | 'bitcoin' | 'ethereum';

const encoder = new TextEncoder();

/** Which signature scheme an address implies, if any this module handles. */
function schemeOf(address: string): Scheme | undefined {
  if (StrKey.isValidEd25519PublicKey(address)) return 'stellar';
  if (/^0x[0-9a-fA-F]{40}$/.test(address)) return 'ethereum';
  if (/^(1|3|bc1q|tb1q|[mn2])/i.test(address)) return 'bitcoin';
  return undefined;
}

/** Strict base64 (standard alphabet, padded); `undefined` for anything else. */
function decodeBase64(value: string): Uint8Array | undefined {
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length % 4 !== 0) return undefined;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(trimmed)) return undefined;
  // `atob` rather than `Buffer`, so the rule also runs in the browser bundle.
  return Uint8Array.from(atob(trimmed), (c) => c.charCodeAt(0));
}

function hexToBytes(hex: string): Uint8Array {
  return Uint8Array.from(hex.match(/../g) ?? [], (pair) => parseInt(pair, 16));
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/** `0x`-prefixed hex, the form Ethereum tooling prints signatures in. */
function decodeHex(value: string): Uint8Array | undefined {
  const match = /^0x((?:[0-9a-fA-F]{2})+)$/.exec(value.trim());
  return match ? hexToBytes(match[1] as string) : undefined;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

const hash160 = (bytes: Uint8Array): Uint8Array => ripemd160(sha256(bytes));

/**
 * Recovers the secp256k1 public key behind a 64-byte `r || s` signature and a
 * recovery id, or `undefined` when no key recovers.
 */
function recoverPoint(
  rs: Uint8Array,
  recovery: number,
  digest: Uint8Array,
): { toRawBytes(compressed?: boolean): Uint8Array } | undefined {
  try {
    return secp256k1.Signature.fromCompact(rs).addRecoveryBit(recovery).recoverPublicKey(digest);
  } catch {
    return undefined;
  }
}

// --- Stellar -----------------------------------------------------------------

/** The SEP-53 digest wallets sign when asked to sign an arbitrary message. */
function sep53Digest(message: string): Uint8Array {
  return sha256(concat(encoder.encode('Stellar Signed Message:\n'), encoder.encode(message)));
}

function verifyStellar(address: string, message: string, signature: string): CollateralVerdict {
  const sig = decodeBase64(signature);
  if (sig === undefined || sig.length !== 64) return 'malformed';

  // The same Ed25519 verification `Keypair.verify` performs, without needing
  // a Node `Buffer` for its arguments.
  const publicKey = new Uint8Array(StrKey.decodeEd25519PublicKey(address));
  const valid =
    ed25519.verify(sig, encoder.encode(message), publicKey) ||
    ed25519.verify(sig, sep53Digest(message), publicKey);
  return valid ? 'valid' : 'invalid';
}

// --- Bitcoin -----------------------------------------------------------------

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/** Base58Check decode: version byte plus payload, or `undefined` on a bad checksum. */
function decodeBase58Check(value: string): Uint8Array | undefined {
  let num = 0n;
  for (const char of value) {
    const digit = BASE58_ALPHABET.indexOf(char);
    if (digit < 0) return undefined;
    num = num * 58n + BigInt(digit);
  }
  const hex = num === 0n ? '' : num.toString(16);
  const body = hexToBytes(hex.length % 2 ? `0${hex}` : hex);
  const zeros = value.length - value.replace(/^1+/, '').length;
  const bytes = concat(new Uint8Array(zeros), body);
  if (bytes.length < 5) return undefined;

  const payload = bytes.subarray(0, -4);
  const checksum = sha256(sha256(payload)).subarray(0, 4);
  return equalBytes(checksum, bytes.subarray(-4)) ? payload : undefined;
}

const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

function bech32Polymod(values: number[]): number {
  const generators = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const value of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ value;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= generators[i] as number;
  }
  return chk;
}

/**
 * The witness program of a segwit v0 (`bc1q`/`tb1q`) address, or `undefined`
 * for anything else. Taproot (`bc1p`) uses BIP-322 message signing, which
 * BIP-137 cannot express, so it is not decoded here.
 */
function decodeSegwitV0(value: string): Uint8Array | undefined {
  const lower = value.toLowerCase();
  if (value !== lower && value !== value.toUpperCase()) return undefined;
  const separator = lower.lastIndexOf('1');
  if (separator < 1) return undefined;

  const hrp = lower.slice(0, separator);
  const data: number[] = [];
  for (const char of lower.slice(separator + 1)) {
    const digit = BECH32_CHARSET.indexOf(char);
    if (digit < 0) return undefined;
    data.push(digit);
  }
  const expanded = [
    ...[...hrp].map((c) => c.charCodeAt(0) >> 5),
    0,
    ...[...hrp].map((c) => c.charCodeAt(0) & 31),
  ];
  // Segwit v0 uses the original bech32 constant (1), not bech32m.
  if (data.length < 7 || bech32Polymod([...expanded, ...data]) !== 1) return undefined;
  if (data[0] !== 0) return undefined;

  // Regroup the 5-bit words after the version into bytes.
  const program: number[] = [];
  let acc = 0;
  let bits = 0;
  for (const word of data.slice(1, -6)) {
    acc = (acc << 5) | word;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      program.push((acc >> bits) & 0xff);
    }
  }
  return program.length === 20 ? new Uint8Array(program) : undefined;
}

/** Bitcoin's CompactSize length prefix. */
function varint(n: number): Uint8Array {
  if (n < 0xfd) return Uint8Array.of(n);
  if (n <= 0xffff) return Uint8Array.of(0xfd, n & 0xff, n >> 8);
  return Uint8Array.of(0xfe, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, n >>> 24);
}

function bitcoinMessageDigest(message: string): Uint8Array {
  const prefix = encoder.encode('\x18Bitcoin Signed Message:\n');
  const body = encoder.encode(message);
  return sha256(sha256(concat(prefix, varint(body.length), body)));
}

/**
 * The hash an address commits to, and how a public key is turned into it:
 * P2PKH hashes the key, P2SH-P2WPKH hashes the witness script around it,
 * and P2WPKH carries the key hash as its witness program.
 */
function addressCommitment(
  address: string,
): { hash: Uint8Array; derive: (pub: Uint8Array) => Uint8Array } | undefined {
  const segwit = decodeSegwitV0(address);
  if (segwit !== undefined) return { hash: segwit, derive: hash160 };

  const decoded = decodeBase58Check(address);
  if (decoded === undefined || decoded.length !== 21) return undefined;
  const version = decoded[0];
  const hash = decoded.subarray(1);
  // 0x00 / 0x6f: P2PKH on mainnet / testnet.
  if (version === 0x00 || version === 0x6f) return { hash, derive: hash160 };
  // 0x05 / 0xc4: P2SH; for a signed message that is P2SH-wrapped P2WPKH.
  if (version === 0x05 || version === 0xc4) {
    return { hash, derive: (pub) => hash160(concat(Uint8Array.of(0x00, 0x14), hash160(pub))) };
  }
  return undefined;
}

function verifyBitcoin(address: string, message: string, signature: string): CollateralVerdict {
  const commitment = addressCommitment(address);
  if (commitment === undefined) return 'unsupported';

  const sig = decodeBase64(signature);
  if (sig === undefined || sig.length !== 65) return 'malformed';

  // BIP-137 header: 27-30 uncompressed P2PKH, 31-34 compressed P2PKH,
  // 35-38 P2SH-P2WPKH, 39-42 P2WPKH. Electrum signs segwit with 31-34 too,
  // so the header only decides the recovery id and key compression; the
  // address itself decides how the key is hashed.
  const header = sig[0] as number;
  if (header < 27 || header > 42) return 'malformed';
  const recovery = (header - 27) & 3;
  const compressed = header >= 31;

  const point = recoverPoint(sig.subarray(1), recovery, bitcoinMessageDigest(message));
  if (point === undefined) return 'invalid';
  const derived = commitment.derive(point.toRawBytes(compressed));
  return equalBytes(derived, commitment.hash) ? 'valid' : 'invalid';
}

// --- Ethereum ----------------------------------------------------------------

function eip191Digest(message: string): Uint8Array {
  const body = encoder.encode(message);
  return keccak_256(concat(encoder.encode(`\x19Ethereum Signed Message:\n${body.length}`), body));
}

function verifyEthereum(address: string, message: string, signature: string): CollateralVerdict {
  const sig = decodeHex(signature) ?? decodeBase64(signature);
  if (sig === undefined || sig.length !== 65) return 'malformed';

  // `v` is 27/28 from most wallets, 0/1 from some libraries.
  const v = sig[64] as number;
  const recovery = v >= 27 ? v - 27 : v;
  if (recovery !== 0 && recovery !== 1) return 'malformed';

  const point = recoverPoint(sig.subarray(0, 64), recovery, eip191Digest(message));
  if (point === undefined) return 'invalid';
  const recovered = keccak_256(point.toRawBytes(false).subarray(1)).subarray(-20);
  return bytesToHex(recovered) === address.slice(2).toLowerCase() ? 'valid' : 'invalid';
}

/**
 * Verifies that `signature` is `address`'s signature over `message`.
 * Never throws: every failure is expressed as a {@link CollateralVerdict}.
 */
export function verifyCollateralSignature(
  address: string,
  message: string,
  signature: string,
): CollateralVerdict {
  try {
    switch (schemeOf(address.trim())) {
      case 'stellar':
        return verifyStellar(address.trim(), message, signature);
      case 'bitcoin':
        return verifyBitcoin(address.trim(), message, signature);
      case 'ethereum':
        return verifyEthereum(address.trim(), message, signature);
      default:
        return 'unsupported';
    }
  } catch {
    return 'invalid';
  }
}
