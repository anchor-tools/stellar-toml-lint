/**
 * Wormhole VAA (Verifiable Action Approval) guardian signature auditor.
 *
 * Run as `stellar-toml-lint audit-wormhole-vaa --vaa <hex|base64>
 * [--guardian-set <file.json>]`. Fully offline.
 *
 * A VAA is `header || body`. The header is `version u8, guardian_set_index
 * u32, signature count u8` followed by 66-byte signatures `(guardian index u8,
 * r 32, s 32, v u8)`. Guardians sign `keccak256(keccak256(body))`, and the
 * core contract accepts a VAA when strictly ascending guardian indices from
 * the active set produce at least `floor(2n / 3) + 1` valid signatures (13 of
 * 19). The auditor parses with bounds-checked byte slices, so truncated or
 * corrupted buffers become diagnostics, never exceptions, then recovers each
 * signer's Ethereum address and compares it to the supplied guardian set. Token
 * bridge payloads (types 1 and 3) are decoded for the report.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isRecord } from '../protocols/verifierSupport.js';
import { bridgeRule, diagnosticSink } from './bridgeSupport.js';
import type { Push } from './bridgeSupport.js';
import {
  bytesToBigInt,
  bytesToHex,
  hexToBytes,
  keccak256,
  publicKeyToAddress,
  recoverPublicKey,
} from './evmCrypto.js';

const MALFORMED_RULE = 'wormhole/malformed-vaa';
const VERSION_RULE = 'wormhole/unsupported-version';
const INDEX_RULE = 'wormhole/invalid-guardian-index';
const SIGNATURE_RULE = 'wormhole/invalid-signature';
const QUORUM_RULE = 'wormhole/insufficient-quorum';
const SET_RULE = 'wormhole/guardian-set-mismatch';
const EXPIRED_RULE = 'wormhole/expired-guardian-set';
const UNVERIFIED_RULE = 'wormhole/unverified-signatures';
const PAYLOAD_RULE = 'wormhole/malformed-payload';

const SPEC = 'https://wormhole.com/docs/protocol/infrastructure/vaas/';
const SIGNATURE_BYTES = 66;
const HEADER_BYTES = 6;
const BODY_BYTES = 51;

/** Wormhole chain ids of networks that commonly bridge to Stellar. */
export const WORMHOLE_CHAINS: Readonly<Record<number, string>> = {
  1: 'solana',
  2: 'ethereum',
  4: 'bsc',
  5: 'polygon',
  6: 'avalanche',
  23: 'arbitrum',
  24: 'optimism',
  30: 'base',
};

export interface GuardianSet {
  index: number;
  /** Lower-case `0x` Ethereum addresses, in guardian index order. */
  addresses: string[];
  /** Unix seconds after which the set is expired; `0` for the current set. */
  expirationTime?: number;
}

export interface VaaSignature {
  guardianIndex: number;
  r: bigint;
  s: bigint;
  v: number;
}

export interface TokenTransfer {
  payloadType: 1 | 3;
  amount: bigint;
  tokenAddress: string;
  tokenChain: number;
  to: string;
  toChain: number;
  fee?: bigint;
  fromAddress?: string;
}

export interface ParsedVaa {
  version: number;
  guardianSetIndex: number;
  signatures: VaaSignature[];
  timestamp: number;
  nonce: number;
  emitterChain: number;
  emitterAddress: string;
  sequence: bigint;
  consistencyLevel: number;
  payload: Uint8Array;
  /** `keccak256(keccak256(body))`, the message guardians sign. */
  digest: Uint8Array;
  transfer?: TokenTransfer;
}

export interface WormholeAuditOptions {
  rules?: RuleOverrides;
  guardianSet?: GuardianSet;
  /** Current time in ms, for guardian set expiry; defaults to `Date.now()`. */
  now?: number;
}

export interface WormholeAuditResult {
  diagnostics: Diagnostic[];
  vaa?: ParsedVaa;
  validSignatures: number;
  quorum?: number;
  /** Recovered signer address per signature (`undefined` if recovery failed). */
  signers: (string | undefined)[];
}

/** Guardian quorum the core contract enforces: more than two thirds. */
export const quorumFor = (guardians: number): number => Math.floor((guardians * 2) / 3) + 1;

/** Decodes a VAA given as hex (optionally `0x`) or base64. */
export function decodeVaaInput(text: string): Uint8Array | undefined {
  const trimmed = text.trim();
  const hex = /^(0x)?[0-9a-f]+$/i.test(trimmed) ? hexToBytes(trimmed) : undefined;
  if (hex !== undefined) return hex;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(trimmed) || trimmed.length % 4 !== 0) return undefined;
  return Uint8Array.from(atob(trimmed), (c) => c.charCodeAt(0));
}

/** Validates `{ index, keys | addresses, expirationTime? }` JSON into a guardian set. */
export function parseGuardianSet(json: unknown): GuardianSet | undefined {
  if (!isRecord(json)) return undefined;
  const list = json.addresses ?? json.keys;
  const index = json.index;
  if (typeof index !== 'number' || !Number.isInteger(index) || index < 0) return undefined;
  if (!Array.isArray(list) || list.length === 0 || list.length > 255) return undefined;
  const addresses: string[] = [];
  for (const a of list) {
    if (typeof a !== 'string' || !/^(0x)?[0-9a-f]{40}$/i.test(a)) return undefined;
    addresses.push(`0x${a.replace(/^0x/i, '').toLowerCase()}`);
  }
  const expiry = json.expirationTime;
  return typeof expiry === 'number'
    ? { index, addresses, expirationTime: expiry }
    : { index, addresses };
}

function decodeTransfer(payload: Uint8Array): TokenTransfer | undefined {
  const type = payload[0];
  if ((type !== 1 && type !== 3) || payload.length < 133) return undefined;
  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const transfer: TokenTransfer = {
    payloadType: type,
    amount: bytesToBigInt(payload.slice(1, 33)),
    tokenAddress: `0x${bytesToHex(payload.slice(33, 65))}`,
    tokenChain: view.getUint16(65),
    to: `0x${bytesToHex(payload.slice(67, 99))}`,
    toChain: view.getUint16(99),
  };
  if (type === 1) transfer.fee = bytesToBigInt(payload.slice(101, 133));
  else transfer.fromAddress = `0x${bytesToHex(payload.slice(101, 133))}`;
  return transfer;
}

/** Parses a VAA; returns a reason string for truncated or inconsistent buffers. */
export function parseVaa(bytes: Uint8Array): ParsedVaa | string {
  if (bytes.length < HEADER_BYTES) return `VAA is ${bytes.length} bytes, shorter than its header`;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const count = view.getUint8(5);
  const bodyStart = HEADER_BYTES + count * SIGNATURE_BYTES;
  if (bytes.length < bodyStart + BODY_BYTES) {
    return `VAA is truncated: ${count} signatures and a body need at least ${bodyStart + BODY_BYTES} bytes, got ${bytes.length}`;
  }
  const signatures: VaaSignature[] = [];
  for (let i = 0; i < count; i++) {
    const o = HEADER_BYTES + i * SIGNATURE_BYTES;
    signatures.push({
      guardianIndex: view.getUint8(o),
      r: bytesToBigInt(bytes.slice(o + 1, o + 33)),
      s: bytesToBigInt(bytes.slice(o + 33, o + 65)),
      v: view.getUint8(o + 65),
    });
  }
  const body = bytes.slice(bodyStart);
  const payload = bytes.slice(bodyStart + BODY_BYTES);
  const vaa: ParsedVaa = {
    version: view.getUint8(0),
    guardianSetIndex: view.getUint32(1),
    signatures,
    timestamp: view.getUint32(bodyStart),
    nonce: view.getUint32(bodyStart + 4),
    emitterChain: view.getUint16(bodyStart + 8),
    emitterAddress: `0x${bytesToHex(bytes.slice(bodyStart + 10, bodyStart + 42))}`,
    sequence: view.getBigUint64(bodyStart + 42),
    consistencyLevel: view.getUint8(bodyStart + 50),
    payload,
    digest: keccak256(keccak256(body)),
  };
  const transfer = decodeTransfer(payload);
  if (transfer !== undefined) vaa.transfer = transfer;
  return vaa;
}

function checkSignatures(
  vaa: ParsedVaa,
  set: GuardianSet,
  push: Push,
  signers: (string | undefined)[],
): number {
  let valid = 0;
  let previous = -1;
  vaa.signatures.forEach((sig, i) => {
    const path = `signatures[${i}]`;
    if (sig.guardianIndex <= previous || sig.guardianIndex >= set.addresses.length) {
      push(
        INDEX_RULE,
        'error',
        `Signature ${i} uses guardian index ${sig.guardianIndex}, which is out of range or not strictly ascending`,
        path,
        'Guardian indices must be unique, ascending and within the guardian set.',
      );
      signers.push(undefined);
      return;
    }
    previous = sig.guardianIndex;
    const recoveryId = sig.v >= 27 ? sig.v - 27 : sig.v;
    const key = recoverPublicKey(vaa.digest, sig.r, sig.s, recoveryId);
    const signer = key === undefined ? undefined : publicKeyToAddress(key);
    signers.push(signer);
    if (signer !== set.addresses[sig.guardianIndex]) {
      push(
        SIGNATURE_RULE,
        'error',
        `Signature ${i} does not recover to guardian ${sig.guardianIndex} (${set.addresses[sig.guardianIndex]})`,
        path,
        'The signature is forged, corrupted, or made over a different body.',
      );
      return;
    }
    valid++;
  });
  return valid;
}

/** Audits a serialized VAA against an optional guardian set. */
export function auditWormholeVaa(
  input: Uint8Array,
  options: WormholeAuditOptions = {},
): WormholeAuditResult {
  const diagnostics: Diagnostic[] = [];
  const push = diagnosticSink(diagnostics, SPEC, options.rules);
  const result: WormholeAuditResult = { diagnostics, validSignatures: 0, signers: [] };
  const parsed = parseVaa(input);
  if (typeof parsed === 'string') {
    push(
      MALFORMED_RULE,
      'error',
      parsed,
      'vaa',
      'Re-fetch the VAA; the byte buffer is incomplete.',
    );
    return result;
  }
  result.vaa = parsed;
  if (parsed.version !== 1) {
    push(
      VERSION_RULE,
      'error',
      `VAA version ${parsed.version} is not 1`,
      'vaa.version',
      'Only v1 VAAs exist.',
    );
  }
  if ((parsed.payload[0] === 1 || parsed.payload[0] === 3) && parsed.transfer === undefined) {
    push(
      PAYLOAD_RULE,
      'warning',
      `Token bridge payload type ${parsed.payload[0]} is ${parsed.payload.length} bytes, shorter than 133`,
      'vaa.payload',
      'The transfer payload is truncated or not a token bridge message.',
    );
  }
  const set = options.guardianSet;
  if (set === undefined) {
    push(
      UNVERIFIED_RULE,
      'warning',
      `${parsed.signatures.length} signatures were parsed but not verified; no guardian set was given`,
      'vaa.signatures',
      'Pass --guardian-set with the active guardian addresses to verify quorum.',
    );
    return result;
  }
  result.quorum = quorumFor(set.addresses.length);
  if (parsed.guardianSetIndex !== set.index) {
    push(
      SET_RULE,
      'error',
      `VAA is signed by guardian set ${parsed.guardianSetIndex}, but set ${set.index} was supplied`,
      'vaa.guardianSetIndex',
      'Verify against the guardian set the VAA names; an old index means an expired set.',
    );
    return result;
  }
  const now = Math.floor((options.now ?? Date.now()) / 1000);
  if (set.expirationTime !== undefined && set.expirationTime !== 0 && set.expirationTime < now) {
    push(
      EXPIRED_RULE,
      'error',
      `Guardian set ${set.index} expired at ${new Date(set.expirationTime * 1000).toISOString()}`,
      'vaa.guardianSetIndex',
      'Request a VAA re-signed by the current guardian set.',
    );
  }
  result.validSignatures = checkSignatures(parsed, set, push, result.signers);
  if (result.validSignatures < result.quorum) {
    push(
      QUORUM_RULE,
      'error',
      `Only ${result.validSignatures} of ${set.addresses.length} guardians signed validly; quorum is ${result.quorum}`,
      'vaa.signatures',
      'The VAA is not authentic until a two-thirds guardian quorum has signed it.',
    );
  }
  return result;
}

export class WormholeVaaAuditor {
  constructor(private readonly options: WormholeAuditOptions = {}) {}

  audit(input: Uint8Array | string): WormholeAuditResult {
    const bytes = typeof input === 'string' ? decodeVaaInput(input) : input;
    if (bytes === undefined) {
      const diagnostics: Diagnostic[] = [];
      diagnosticSink(diagnostics, SPEC, this.options.rules)(
        MALFORMED_RULE,
        'error',
        'VAA is neither valid hex nor base64',
        'vaa',
        'Pass the VAA bytes as hex (0x...) or base64.',
      );
      return { diagnostics, validSignatures: 0, signers: [] };
    }
    return auditWormholeVaa(bytes, this.options);
  }
}

/** Plain-text summary for the CLI. */
export function renderVaaReport(result: WormholeAuditResult): string {
  const v = result.vaa;
  if (v === undefined) return 'VAA could not be parsed\n';
  const chain = (id: number): string => `${id} (${WORMHOLE_CHAINS[id] ?? 'unknown'})`;
  const lines = [
    `VAA v${v.version}, guardian set ${v.guardianSetIndex}, ${v.signatures.length} signatures`,
    `emitter ${chain(v.emitterChain)} ${v.emitterAddress} sequence ${v.sequence}`,
    `timestamp ${new Date(v.timestamp * 1000).toISOString()}, consistency ${v.consistencyLevel}`,
  ];
  if (result.quorum !== undefined) {
    lines.push(`valid signatures ${result.validSignatures}/${result.quorum} required`);
  }
  const t = v.transfer;
  if (t !== undefined) {
    lines.push(
      `token transfer (type ${t.payloadType}): amount ${t.amount} of ${t.tokenAddress} from chain ${chain(t.tokenChain)} to ${t.to} on chain ${chain(t.toChain)}`,
    );
  }
  return `${lines.join('\n')}\n`;
}

export const wormholeRules: Rule[] = [
  bridgeRule(MALFORMED_RULE, 'error', 'VAAs must be complete, well-formed byte buffers'),
  bridgeRule(VERSION_RULE, 'error', 'VAAs must be version 1'),
  bridgeRule(INDEX_RULE, 'error', 'Guardian indices must be ascending and within the set'),
  bridgeRule(SIGNATURE_RULE, 'error', 'Each signature must recover to its guardian'),
  bridgeRule(QUORUM_RULE, 'error', 'A two-thirds guardian quorum must sign the VAA'),
  bridgeRule(SET_RULE, 'error', 'The VAA must be checked against the guardian set it names'),
  bridgeRule(EXPIRED_RULE, 'error', 'The signing guardian set must not be expired'),
  bridgeRule(UNVERIFIED_RULE, 'warning', 'Signatures cannot be verified without a guardian set'),
  bridgeRule(PAYLOAD_RULE, 'warning', 'Token bridge payloads must be complete'),
];

export const wormholeRuleIds: readonly string[] = wormholeRules.map((r) => r.id);
