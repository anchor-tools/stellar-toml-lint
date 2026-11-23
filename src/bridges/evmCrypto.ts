/**
 * Keccak-256 and secp256k1 public key recovery in plain TypeScript.
 *
 * The bridge verifiers need Ethereum-style signature recovery (Wormhole
 * guardians sign with secp256k1 and are identified by their 20-byte Ethereum
 * address) and Keccak-256 hashing. Node's `crypto` has neither Keccak (its
 * `sha3-256` uses different padding) nor public key recovery, and this package
 * avoids native or extra crypto dependencies, so both live here. Everything is
 * BigInt arithmetic over byte slices; it is not constant time, which is fine
 * because it only ever handles public data.
 */

const MASK64 = (1n << 64n) - 1n;

const ROUND_CONSTANTS: readonly bigint[] = [
  0x0000000000000001n,
  0x0000000000008082n,
  0x800000000000808an,
  0x8000000080008000n,
  0x000000000000808bn,
  0x0000000080000001n,
  0x8000000080008081n,
  0x8000000000008009n,
  0x000000000000008an,
  0x0000000000000088n,
  0x0000000080008009n,
  0x000000008000000an,
  0x000000008000808bn,
  0x800000000000008bn,
  0x8000000000008089n,
  0x8000000000008003n,
  0x8000000000008002n,
  0x8000000000000080n,
  0x000000000000800an,
  0x800000008000000an,
  0x8000000080008081n,
  0x8000000000008080n,
  0x0000000080000001n,
  0x8000000080008008n,
];

/** Rotation offsets indexed by `x + 5 * y`. */
const ROTATIONS: readonly number[] = [
  0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

const lane = (state: bigint[], i: number): bigint => state[i] as bigint;

function rotl(value: bigint, shift: number): bigint {
  if (shift === 0) return value;
  const n = BigInt(shift);
  return ((value << n) | (value >> (64n - n))) & MASK64;
}

function keccakF(state: bigint[]): void {
  const c: bigint[] = new Array<bigint>(5);
  const b: bigint[] = new Array<bigint>(25);
  for (const rc of ROUND_CONSTANTS) {
    for (let x = 0; x < 5; x++) {
      c[x] =
        lane(state, x) ^
        lane(state, x + 5) ^
        lane(state, x + 10) ^
        lane(state, x + 15) ^
        lane(state, x + 20);
    }
    for (let x = 0; x < 5; x++) {
      const d = lane(c, (x + 4) % 5) ^ rotl(lane(c, (x + 1) % 5), 1);
      for (let y = 0; y < 25; y += 5) state[x + y] = lane(state, x + y) ^ d;
    }
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(
          lane(state, x + 5 * y),
          ROTATIONS[x + 5 * y] as number,
        );
      }
    }
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 25; y += 5) {
        state[x + y] =
          lane(b, x + y) ^ (~lane(b, ((x + 1) % 5) + y) & MASK64 & lane(b, ((x + 2) % 5) + y));
      }
    }
    state[0] = lane(state, 0) ^ rc;
  }
}

/** Ethereum's Keccak-256 (original Keccak padding, not FIPS-202 SHA3-256). */
export function keccak256(data: Uint8Array): Uint8Array {
  const rate = 136;
  const padded = new Uint8Array(Math.floor(data.length / rate + 1) * rate);
  padded.set(data);
  padded[data.length] = 0x01;
  padded[padded.length - 1] = (padded[padded.length - 1] as number) | 0x80;
  const state: bigint[] = new Array<bigint>(25).fill(0n);
  for (let offset = 0; offset < padded.length; offset += rate) {
    for (let i = 0; i < rate / 8; i++) {
      let value = 0n;
      for (let j = 7; j >= 0; j--) value = (value << 8n) | BigInt(padded[offset + i * 8 + j] ?? 0);
      state[i] = lane(state, i) ^ value;
    }
    keccakF(state);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    let value = lane(state, i);
    for (let j = 0; j < 8; j++) {
      out[i * 8 + j] = Number(value & 0xffn);
      value >>= 8n;
    }
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/** Decodes hex with or without `0x`; `undefined` for odd length or non-hex input. */
export function hexToBytes(hex: string): Uint8Array | undefined {
  const clean = hex.trim().replace(/^0x/i, '');
  if (clean.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(clean)) return undefined;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const b of bytes) value = (value << 8n) | BigInt(b);
  return value;
}

export function bigIntToBytes(value: bigint, length = 32): Uint8Array {
  const out = new Uint8Array(length);
  let v = value;
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

// --- secp256k1 -------------------------------------------------------------

const P = 2n ** 256n - 2n ** 32n - 977n;
export const CURVE_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

export interface AffinePoint {
  x: bigint;
  y: bigint;
}

interface JacobianPoint {
  x: bigint;
  y: bigint;
  z: bigint;
}

const INFINITY: JacobianPoint = { x: 0n, y: 1n, z: 0n };

const mod = (a: bigint, m: bigint = P): bigint => ((a % m) + m) % m;

function modPow(base: bigint, exponent: bigint, m: bigint): bigint {
  let result = 1n;
  let b = mod(base, m);
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return result;
}

/** Modular inverse by the extended Euclidean algorithm. */
export function modInverse(a: bigint, m: bigint): bigint {
  let [oldR, r] = [mod(a, m), m];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  if (oldR !== 1n) throw new RangeError('value has no modular inverse');
  return mod(oldS, m);
}

function double(p: JacobianPoint): JacobianPoint {
  if (p.z === 0n || p.y === 0n) return INFINITY;
  const a = mod(p.x * p.x);
  const b = mod(p.y * p.y);
  const c = mod(b * b);
  const d = mod(2n * (mod((p.x + b) * (p.x + b)) - a - c));
  const e = mod(3n * a);
  const x = mod(e * e - 2n * d);
  return { x, y: mod(e * (d - x) - 8n * c), z: mod(2n * p.y * p.z) };
}

function add(p: JacobianPoint, q: JacobianPoint): JacobianPoint {
  if (p.z === 0n) return q;
  if (q.z === 0n) return p;
  const z1z1 = mod(p.z * p.z);
  const z2z2 = mod(q.z * q.z);
  const u1 = mod(p.x * z2z2);
  const u2 = mod(q.x * z1z1);
  const s1 = mod(p.y * q.z * z2z2);
  const s2 = mod(q.y * p.z * z1z1);
  if (u1 === u2) return s1 === s2 ? double(p) : INFINITY;
  const h = mod(u2 - u1);
  const r = mod(s2 - s1);
  const h2 = mod(h * h);
  const h3 = mod(h * h2);
  const u1h2 = mod(u1 * h2);
  const x = mod(r * r - h3 - 2n * u1h2);
  return { x, y: mod(r * (u1h2 - x) - s1 * h3), z: mod(h * p.z * q.z) };
}

function multiply(p: JacobianPoint, k: bigint): JacobianPoint {
  let result = INFINITY;
  for (let i = BigInt(k.toString(2).length - 1); i >= 0n; i--) {
    result = double(result);
    if ((k >> i) & 1n) result = add(result, p);
  }
  return result;
}

function toAffine(p: JacobianPoint): AffinePoint | undefined {
  if (p.z === 0n) return undefined;
  const zInv = modInverse(p.z, P);
  const zInv2 = mod(zInv * zInv);
  return { x: mod(p.x * zInv2), y: mod(p.y * zInv2 * zInv) };
}

/** `k * G`; exported so fixtures can derive keys and nonces. */
export function multiplyGenerator(k: bigint): AffinePoint | undefined {
  return toAffine(multiply({ x: GX, y: GY, z: 1n }, mod(k, CURVE_N)));
}

/**
 * Recovers the signer's public key from a 32-byte digest and an `(r, s,
 * recoveryId)` signature, as Ethereum's `ecrecover` does. Returns `undefined`
 * for any signature that cannot be valid.
 */
export function recoverPublicKey(
  digest: Uint8Array,
  r: bigint,
  s: bigint,
  recoveryId: number,
): AffinePoint | undefined {
  if (digest.length !== 32) return undefined;
  if (r <= 0n || r >= CURVE_N || s <= 0n || s >= CURVE_N) return undefined;
  if (recoveryId !== 0 && recoveryId !== 1) return undefined;
  const alpha = mod(r * r * r + 7n);
  const beta = modPow(alpha, (P + 1n) / 4n, P);
  if (mod(beta * beta) !== alpha) return undefined;
  const y = (beta & 1n) === BigInt(recoveryId) ? beta : P - beta;
  const rInv = modInverse(r, CURVE_N);
  const u1 = mod(-bytesToBigInt(digest) * rInv, CURVE_N);
  const u2 = mod(s * rInv, CURVE_N);
  const generator = { x: GX, y: GY, z: 1n };
  return toAffine(add(multiply(generator, u1), multiply({ x: r, y, z: 1n }, u2)));
}

/** Lower-case `0x` Ethereum address of an uncompressed public key. */
export function publicKeyToAddress(point: AffinePoint): string {
  const raw = new Uint8Array(64);
  raw.set(bigIntToBytes(point.x), 0);
  raw.set(bigIntToBytes(point.y), 32);
  return `0x${bytesToHex(keccak256(raw).slice(12))}`;
}
