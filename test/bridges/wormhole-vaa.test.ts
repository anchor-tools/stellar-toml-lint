import { describe, expect, it } from 'vitest';
import {
  CURVE_N,
  bigIntToBytes,
  bytesToBigInt,
  bytesToHex,
  keccak256,
  modInverse,
  multiplyGenerator,
  publicKeyToAddress,
  recoverPublicKey,
} from '../../src/bridges/evmCrypto.js';
import {
  WormholeVaaAuditor,
  auditWormholeVaa,
  decodeVaaInput,
  parseGuardianSet,
  parseVaa,
  quorumFor,
  renderVaaReport,
  wormholeRuleIds,
} from '../../src/bridges/wormholeVaaAuditor.js';
import type { GuardianSet } from '../../src/bridges/wormholeVaaAuditor.js';

const KEYS = Array.from({ length: 19 }, (_, i) => 0xabc000n + BigInt(i) * 7919n);
const ADDRESSES = KEYS.map((k) => publicKeyToAddress(multiplyGenerator(k)!));
const SET: GuardianSet = { index: 4, addresses: ADDRESSES, expirationTime: 0 };
const NOW = Date.UTC(2026, 10, 19);

/** Deterministic secp256k1 signature with an Ethereum-style recovery id. */
function sign(digest: Uint8Array, key: bigint): Uint8Array {
  const seed = new Uint8Array([...bigIntToBytes(key), ...digest]);
  const k = (bytesToBigInt(keccak256(seed)) % (CURVE_N - 1n)) + 1n;
  const point = multiplyGenerator(k)!;
  const r = point.x % CURVE_N;
  const s = (modInverse(k, CURVE_N) * (bytesToBigInt(digest) + r * key)) % CURVE_N;
  return new Uint8Array([...bigIntToBytes(r), ...bigIntToBytes(s), Number(point.y & 1n)]);
}

function u(value: number | bigint, bytes: number): number[] {
  return Array.from(bigIntToBytes(BigInt(value), bytes));
}

/** A type-1 token transfer: 1,000 units of an Ethereum token to a Stellar recipient. */
const TRANSFER = [
  1,
  ...u(100_000_000_000n, 32),
  ...u(0xa0b86991n, 32),
  ...u(2, 2),
  ...u(0x5151n, 32),
  ...u(61, 2),
  ...u(0, 32),
];

const BODY = new Uint8Array([
  ...u(1_763_500_000, 4),
  ...u(7, 4),
  ...u(2, 2),
  ...u(0x3ee18b2214aff97000d974cf647e7c347e8fa585n, 32),
  ...u(123_456n, 8),
  ...u(15, 1),
  ...TRANSFER,
]);

interface Build {
  signers?: number[];
  setIndex?: number;
  version?: number;
  body?: Uint8Array;
  /** Sign this body instead of the one embedded (forged signature). */
  signedBody?: Uint8Array;
}

function buildVaa(opts: Build = {}): Uint8Array {
  const body = opts.body ?? BODY;
  const digest = keccak256(keccak256(opts.signedBody ?? body));
  const signers = opts.signers ?? Array.from({ length: 13 }, (_, i) => i);
  const sigs = signers.flatMap((g) => [g, ...sign(digest, KEYS[g] as bigint)]);
  return new Uint8Array([
    opts.version ?? 1,
    ...u(opts.setIndex ?? 4, 4),
    signers.length,
    ...sigs,
    ...body,
  ]);
}

const rules = (r: { diagnostics: { rule: string }[] }): string[] =>
  r.diagnostics.map((d) => d.rule);
const audit = (bytes: Uint8Array, set: GuardianSet | null = SET) =>
  auditWormholeVaa(bytes, { now: NOW, ...(set ? { guardianSet: set } : {}) });

describe('evm crypto primitives', () => {
  it('matches published Keccak-256 and address vectors', () => {
    expect(bytesToHex(keccak256(new Uint8Array()))).toBe(
      'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
    );
    expect(bytesToHex(keccak256(new TextEncoder().encode('abc')))).toBe(
      '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45',
    );
    expect(publicKeyToAddress(multiplyGenerator(1n)!)).toBe(
      '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf',
    );
  });

  it('recovers signers and rejects out-of-range signatures', () => {
    const digest = keccak256(new Uint8Array([1, 2, 3]));
    const sig = sign(digest, 42n);
    const r = bytesToBigInt(sig.slice(0, 32));
    const s = bytesToBigInt(sig.slice(32, 64));
    const key = recoverPublicKey(digest, r, s, sig[64] as number);
    expect(publicKeyToAddress(key!)).toBe(publicKeyToAddress(multiplyGenerator(42n)!));
    expect(recoverPublicKey(digest, 0n, s, 0)).toBeUndefined();
    expect(recoverPublicKey(digest, r, CURVE_N, 0)).toBeUndefined();
    expect(recoverPublicKey(digest, r, s, 2)).toBeUndefined();
    expect(recoverPublicKey(new Uint8Array(31), r, s, 0)).toBeUndefined();
  });
});

describe('WormholeVaaAuditor', () => {
  it('registers rule ids and computes the 13-of-19 quorum', () => {
    expect(wormholeRuleIds).toContain('wormhole/insufficient-quorum');
    expect(quorumFor(19)).toBe(13);
    expect(quorumFor(1)).toBe(1);
  });

  it('accepts a VAA signed by a guardian quorum and decodes the transfer', () => {
    const r = audit(buildVaa());
    expect(r.diagnostics).toEqual([]);
    expect(r.validSignatures).toBe(13);
    expect(r.signers.slice(0, 2)).toEqual(ADDRESSES.slice(0, 2));
    expect(r.vaa).toMatchObject({
      version: 1,
      guardianSetIndex: 4,
      emitterChain: 2,
      sequence: 123_456n,
      consistencyLevel: 15,
    });
    expect(r.vaa?.transfer).toMatchObject({
      payloadType: 1,
      amount: 100_000_000_000n,
      tokenChain: 2,
      toChain: 61,
      fee: 0n,
    });
    expect(renderVaaReport(r)).toContain('valid signatures 13/13 required');
  });

  it('rejects a VAA below quorum', () => {
    const r = audit(buildVaa({ signers: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11] }));
    expect(rules(r)).toEqual(['wormhole/insufficient-quorum']);
    expect(r.diagnostics[0]?.message).toContain('Only 12 of 19');
  });

  it('flags forged signatures over a different body', () => {
    const forged = new Uint8Array(BODY);
    forged[forged.length - 40] = 0xff;
    const r = audit(buildVaa({ signedBody: forged }));
    expect(rules(r).filter((x) => x === 'wormhole/invalid-signature')).toHaveLength(13);
    expect(rules(r)).toContain('wormhole/insufficient-quorum');
  });

  it('flags duplicate, unordered and out-of-range guardian indices', () => {
    const vaa = buildVaa({ signers: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 12, 3, 18] });
    vaa[6 + 15 * 66] = 30; // the last signature now claims guardian 30 of 19
    const r = audit(vaa);
    expect(rules(r).filter((x) => x === 'wormhole/invalid-guardian-index')).toHaveLength(3);
    expect(r.validSignatures).toBe(13);
  });

  it('detects an expired or mismatched guardian set', () => {
    const old = audit(buildVaa({ setIndex: 3 }));
    expect(rules(old)).toEqual(['wormhole/guardian-set-mismatch']);
    const expired = audit(buildVaa(), { ...SET, expirationTime: NOW / 1000 - 60 });
    expect(rules(expired)).toEqual(['wormhole/expired-guardian-set']);
  });

  it('parses without verifying when no guardian set is supplied', () => {
    const r = audit(buildVaa(), null);
    expect(rules(r)).toEqual(['wormhole/unverified-signatures']);
    expect(r.quorum).toBeUndefined();
  });

  it('reports truncated and corrupted buffers instead of throwing', () => {
    const full = buildVaa();
    expect(rules(audit(full.slice(0, 3)))).toEqual(['wormhole/malformed-vaa']);
    expect(rules(audit(full.slice(0, 6 + 13 * 66 + 20)))).toEqual(['wormhole/malformed-vaa']);
    const truncatedPayload = buildVaa({ body: BODY.slice(0, 51 + 40) });
    expect(rules(audit(truncatedPayload))).toEqual(['wormhole/malformed-payload']);
    expect(rules(audit(buildVaa({ version: 2 })))).toEqual(['wormhole/unsupported-version']);
    expect(typeof parseVaa(new Uint8Array(2))).toBe('string');
  });

  it('accepts hex and base64 input and rejects garbage', () => {
    const bytes = buildVaa();
    const auditor = new WormholeVaaAuditor({ guardianSet: SET, now: NOW });
    expect(auditor.audit(`0x${bytesToHex(bytes)}`).validSignatures).toBe(13);
    expect(decodeVaaInput(Buffer.from(bytes).toString('base64'))).toEqual(bytes);
    expect(rules(auditor.audit('not a vaa!'))).toEqual(['wormhole/malformed-vaa']);
  });

  it('parses guardian set JSON', () => {
    expect(
      parseGuardianSet({ index: 4, keys: ADDRESSES.map((a) => a.toUpperCase().replace('0X', '')) }),
    ).toMatchObject({ index: 4, addresses: ADDRESSES });
    expect(parseGuardianSet({ index: -1, keys: ADDRESSES })).toBeUndefined();
    expect(parseGuardianSet({ index: 1, keys: ['0x1234'] })).toBeUndefined();
    expect(parseGuardianSet({ index: 1, keys: [] })).toBeUndefined();
    expect(parseGuardianSet('x')).toBeUndefined();
  });
});
