/**
 * Ed25519 signature malleability and non-canonical S-scalar auditor.
 *
 * RFC 8032 requires the second half of an Ed25519 signature — the `S` scalar —
 * to be strictly less than the group order `L`. Some libraries accept a
 * non-canonical `S` (an equivalent scalar with `L` added), which lets an
 * intermediary mutate a signature and therefore the transaction hash while
 * the signature still verifies. Anchors that track transactions by hash can
 * lose track of a payment after such a mutation.
 *
 * This module is intentionally dependency-light: it decodes base64/hex
 * signatures with the same primitives the rest of the linter uses and compares
 * the little-endian scalar against `L` with BigInt. It checks every
 * `collateral_address_signatures` entry and can also inspect signatures taken
 * from a SEP-10 challenge transaction XDR.
 */
import { TransactionBuilder } from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleContext, RuleOverrides } from '../types.js';
import { specUrl } from '../spec.js';

export const MALLEABLE_SIGNATURE_RULE = 'crypto/malleable-signature-detected';
export const CRYPTO_MALLEABLE_SIGNATURE = MALLEABLE_SIGNATURE_RULE;
export const MALLEABLE_SIGNATURE_DETECTED_RULE = MALLEABLE_SIGNATURE_RULE;
export const MALLEABILITY_RULE = MALLEABLE_SIGNATURE_RULE;

/** The prime-order subgroup order of Curve25519: `2^252 + 27742317777372353535851937790883648493`. */
export const ED25519_GROUP_ORDER = 2n ** 252n + 27742317777372353535851937790883648493n;
export const ED25519_L = ED25519_GROUP_ORDER;
export const ED25519_SIGNATURE_BYTES = 64;

export interface ParsedEd25519Signature {
  /** First 32 bytes: the encoded `R` point. */
  r: Uint8Array;
  /** Last 32 bytes: the little-endian `S` scalar. */
  s: Uint8Array;
  /** `S` as an integer, for direct comparison with {@link ED25519_GROUP_ORDER}. */
  sValue: bigint;
}

export interface SignatureMalleabilityResult {
  /** The value decoded to exactly 64 bytes and could be parsed. */
  parsed: boolean;
  /** `S < L`; only meaningful when {@link parsed} is true. */
  canonical: boolean;
  /** `!canonical`, or `false` for malformed input. */
  malleable: boolean;
  /** Decoded bytes when parsing succeeded. */
  signature?: ParsedEd25519Signature;
}

function decodeBase64(value: string): Uint8Array | undefined {
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length % 4 !== 0) return undefined;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(trimmed)) return undefined;
  try {
    // `atob` keeps this usable in the browser bundle.
    return Uint8Array.from(atob(trimmed), (character) => character.charCodeAt(0));
  } catch {
    return undefined;
  }
}

function decodeHex(value: string): Uint8Array | undefined {
  const trimmed = value.trim();
  const match = /^(?:0x)?([0-9a-fA-F]+)$/.exec(trimmed);
  if (!match || (match[1] as string).length % 2 !== 0) return undefined;
  const body = match[1] as string;
  return Uint8Array.from(body.match(/../g) ?? [], (pair) => parseInt(pair, 16));
}

/** Decodes a signature from raw bytes, hex (`0x...`), or standard base64. */
export function decodeEd25519Signature(signature: Uint8Array | string): Uint8Array | undefined {
  if (signature instanceof Uint8Array) {
    return signature.length === ED25519_SIGNATURE_BYTES ? signature : undefined;
  }
  if (typeof signature !== 'string') return undefined;
  const trimmed = signature.trim();
  let decoded: Uint8Array | undefined;
  if (trimmed.startsWith('0x') || /^[0-9a-fA-F]{128}$/.test(trimmed)) {
    decoded = decodeHex(trimmed);
  } else {
    decoded = decodeBase64(trimmed) ?? decodeBase64(trimmed.replace(/-/g, '+').replace(/_/g, '/'));
  }
  return decoded?.length === ED25519_SIGNATURE_BYTES ? decoded : undefined;
}

/** Reads a little-endian unsigned integer from `bytes`. */
export function bytesToBigIntLE(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    value = (value << 8n) | BigInt(bytes[i] as number);
  }
  return value;
}

/**
 * Splits a 64-byte Ed25519 signature into `R || S` and parses `S`.
 * Returns `undefined` for anything that is not exactly 64 bytes.
 */
export function parseEd25519Signature(
  signature: Uint8Array | string,
): ParsedEd25519Signature | undefined {
  const bytes = decodeEd25519Signature(signature);
  if (bytes === undefined) return undefined;
  const r = bytes.slice(0, 32);
  const s = bytes.slice(32);
  return { r, s, sValue: bytesToBigIntLE(s) };
}

/**
 * True when the signature is a well-formed 64-byte Ed25519 signature whose
 * `S` scalar is strictly below the group order. Malformed input is `false`.
 */
export function isCanonicalEd25519Signature(signature: Uint8Array | string): boolean {
  const parsed = parseEd25519Signature(signature);
  return parsed !== undefined && parsed.sValue < ED25519_GROUP_ORDER;
}

/** True when a validly encoded signature carries a non-canonical `S >= L`. */
export function isMalleableEd25519Signature(signature: Uint8Array | string): boolean {
  const parsed = parseEd25519Signature(signature);
  return parsed !== undefined && parsed.sValue >= ED25519_GROUP_ORDER;
}

/** Classifies a signature without throwing on malformed input. */
export function auditEd25519Signature(signature: Uint8Array | string): SignatureMalleabilityResult {
  const parsed = parseEd25519Signature(signature);
  if (parsed === undefined) {
    return { parsed: false, canonical: false, malleable: false };
  }
  const canonical = parsed.sValue < ED25519_GROUP_ORDER;
  return { parsed: true, canonical, malleable: !canonical, signature: parsed };
}

const SIGNATURE_FIELDS = [
  'collateral_address_signatures',
  'SEP10_CHALLENGE_SIGNATURES',
  'SEP10_SIGNATURES',
] as const;

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules: RuleOverrides | undefined,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

function diagnosticFor(
  signature: Uint8Array | string,
  path: string,
  rules: RuleOverrides | undefined,
  position?: Diagnostic['position'],
): Diagnostic | undefined {
  if (!isMalleableEd25519Signature(signature)) return undefined;
  const severity = severityFor(MALLEABLE_SIGNATURE_RULE, 'error', rules);
  if (severity === undefined) return undefined;
  const scalar = parseEd25519Signature(signature)?.sValue;
  return {
    rule: MALLEABLE_SIGNATURE_RULE,
    severity,
    category: 'currencies',
    message: `${path} contains a non-canonical Ed25519 S scalar${scalar === undefined ? '' : ` (${scalar})`} that is not strictly below the Curve25519 group order L`,
    path,
    ...(position === undefined ? {} : { position }),
    helpUri: specUrl('currency-documentation'),
    suggestion:
      'Re-sign with an RFC 8032 compliant Ed25519 implementation that reduces S modulo L; never accept malleated signatures from intermediaries.',
  };
}

export interface MalleabilityAuditOptions {
  rules?: RuleOverrides;
  /** Additional raw signature samples (e.g. from a SEP-10 challenge). */
  signatures?: readonly (Uint8Array | string)[];
  /** Optional dotted path for the additional samples. */
  signaturesPath?: string;
  /** A SEP-10 challenge transaction XDR whose signatures should be checked. */
  sep10ChallengeXdr?: string;
  /** Network passphrase for {@link sep10ChallengeXdr}; public network by default. */
  networkPassphrase?: string;
}

/**
 * Audits every Ed25519 signature this module can find in a document.
 *
 * `collateral_address_signatures` is the canonical SEP-1 location. Signatures
 * from an optional SEP-10 challenge XDR (or explicit samples) are checked too,
 * so the same canonicality rule covers the authentication path.
 */
export function checkSignatureMalleability(
  doc: Record<string, unknown> | string | Uint8Array,
  options: MalleabilityAuditOptions = {},
): Diagnostic[] {
  const diagnostics: Diagnostic[] = [];

  // Convenience overload: a raw signature sample.
  if (typeof doc === 'string' || doc instanceof Uint8Array) {
    const diagnostic = diagnosticFor(doc, options.signaturesPath ?? 'signature', options.rules);
    return diagnostic === undefined ? [] : [diagnostic];
  }

  const currencies = doc.CURRENCIES;
  if (Array.isArray(currencies)) {
    currencies.forEach((raw, index) => {
      if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return;
      const entry = raw as Record<string, unknown>;
      if (entry.toml !== undefined) return;

      for (const field of SIGNATURE_FIELDS) {
        const values = entry[field];
        if (!Array.isArray(values)) continue;
        values.forEach((signature, signatureIndex) => {
          if (typeof signature !== 'string') return;
          const path = `CURRENCIES[${index}].${field}[${signatureIndex}]`;
          const diagnostic = diagnosticFor(signature, path, options.rules);
          if (diagnostic !== undefined) diagnostics.push(diagnostic);
        });
      }
    });
  }

  options.signatures?.forEach((signature, index) => {
    const path = `${options.signaturesPath ?? 'signatures'}[${index}]`;
    const diagnostic = diagnosticFor(signature, path, options.rules);
    if (diagnostic !== undefined) diagnostics.push(diagnostic);
  });

  if (options.sep10ChallengeXdr !== undefined) {
    diagnostics.push(
      ...auditSep10ChallengeSignatures(
        options.sep10ChallengeXdr,
        options.networkPassphrase,
        options.rules,
      ),
    );
  }

  return diagnostics;
}

export const auditSignatureMalleability = checkSignatureMalleability;
export const isSignatureMalleable = isMalleableEd25519Signature;
export const isEd25519SignatureMalleable = isMalleableEd25519Signature;
export const isCanonicalSignature = isCanonicalEd25519Signature;
export const auditCollateralSignatureMalleability = checkSignatureMalleability;
export const checkMalleability = checkSignatureMalleability;
export const auditMalleability = checkSignatureMalleability;
export const parseSignature = parseEd25519Signature;

/**
 * Extracts and audits the Ed25519 signatures attached to a SEP-10 challenge
 * transaction. A transaction that cannot be parsed is ignored; SEP-10's own
 * structural rules report unparseable challenges.
 */
export function auditSep10ChallengeSignatures(
  challengeXdr: string,
  networkPassphrase = 'Public Global Stellar Network ; September 2015',
  rules?: RuleOverrides,
): Diagnostic[] {
  let transaction: { signatures: { signature(): Uint8Array }[] };
  try {
    transaction = TransactionBuilder.fromXDR(challengeXdr, networkPassphrase) as typeof transaction;
  } catch {
    return [];
  }

  const diagnostics: Diagnostic[] = [];
  transaction.signatures.forEach((decorated, index) => {
    let bytes: Uint8Array;
    try {
      bytes = decorated.signature();
    } catch {
      return;
    }
    const diagnostic = diagnosticFor(bytes, `SEP10_CHALLENGE.signatures[${index}]`, rules);
    if (diagnostic !== undefined) diagnostics.push(diagnostic);
  });
  return diagnostics;
}

/** Rule objects registered for `--list-rules` and severity overrides. */
export const malleabilityAuditorRules: Rule[] = [
  {
    id: MALLEABLE_SIGNATURE_RULE,
    category: 'currencies',
    severity: 'error',
    description: 'Ed25519 signatures must use a canonical S scalar strictly below the group order',
    run(ctx: RuleContext) {
      for (const diagnostic of checkSignatureMalleability(ctx.doc, {
        rules: ctx.options.rules,
      })) {
        ctx.report(diagnostic);
      }
    },
  },
];

export const malleabilityRules = malleabilityAuditorRules;
export const signatureMalleabilityRules = malleabilityAuditorRules;
export const malleabilityAuditorRuleIds: readonly string[] = malleabilityAuditorRules.map(
  (rule) => rule.id,
);
