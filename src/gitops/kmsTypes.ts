/**
 * Shared types and helpers for the Cloud KMS signer coordinator.
 *
 * Institutional anchors keep their master signing keys in a managed HSM
 * (AWS KMS, Google Cloud KMS, Azure Key Vault) and ask the provider to sign a
 * 32-byte Stellar transaction digest. Every adapter returns the same shape, so
 * the coordinator can verify the result as a Stellar `DecoratedSignature`
 * regardless of which cloud produced it.
 */
import { createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { StrKey } from '@stellar/stellar-base';

/** Cloud providers the coordinator understands. */
export type KmsProvider = 'aws' | 'gcp' | 'azure';

/**
 * Asymmetric algorithms that can back a Stellar signer.
 *
 * `ECC_NIST_ED25519` is the only key type Stellar accounts accept as a signer;
 * `ECC_SECG_P256K1` appears in institutional deployments that bridge EVM
 * custody, and is carried through the same structural verification path.
 */
export const KMS_KEY_ALGORITHMS = ['ECC_NIST_ED25519', 'ECC_SECG_P256K1'] as const;

export type KmsKeyAlgorithm = (typeof KMS_KEY_ALGORITHMS)[number];

/** True when `value` is an algorithm this harness knows how to verify. */
export function isKmsKeyAlgorithm(value: string): value is KmsKeyAlgorithm {
  return (KMS_KEY_ALGORITHMS as readonly string[]).includes(value);
}

/** What `describeKey` reports about the hardware key. */
export interface KmsKeyDescriptor {
  provider: KmsProvider;
  /** The identifier exactly as the operator supplied it. */
  keyId: string;
  /** Provider-canonical resource name (ARN, versioned resource, or key URL). */
  resourceName: string;
  algorithm: KmsKeyAlgorithm;
  /**
   * Raw public key bytes: 32 for Ed25519, 33 (compressed) for secp256k1.
   * The last four bytes are the Stellar signature hint.
   */
  publicKey: Buffer;
  /** SubjectPublicKeyInfo PEM, used for local signature verification. */
  publicKeyPem: string;
  /** Provider key state/usage, surfaced in the report for audit trails. */
  keyState?: string;
  keyUsage?: string;
  /** Algorithm name the provider's sign API expects, e.g. `ECDSA_SHA_256`. */
  signingAlgorithm?: string;
  /** Provider version identifier, when the key is versioned. */
  version?: string;
}

/** A signature returned by the provider, still in provider encoding. */
export interface KmsSignResult {
  /** Ed25519: 64 raw bytes. ECDSA: DER-encoded `SEQUENCE { r, s }`. */
  signature: Buffer;
  keyVersion?: string;
  signingAlgorithm?: string;
  /** Provider calls made, including retries, for throttling audits. */
  attempts?: number;
}

/** Minimal client contract every cloud adapter implements. */
export interface KmsClient {
  readonly provider: KmsProvider;
  describeKey(): Promise<KmsKeyDescriptor>;
  /**
   * Signs a 32-byte Stellar transaction digest.
   *
   * Adapters translate this into the provider's own request shape (AWS
   * `MessageType`, GCP `data` vs `digest`, Azure `value`) but must never
   * receive or return credentials through this interface.
   */
  signDigest(digest: Buffer): Promise<KmsSignResult>;
}

/** Base class for every failure this harness reports. */
export class KmsError extends Error {
  readonly code: string;
  readonly retryable: boolean;
  readonly status?: number;
  readonly provider?: KmsProvider;
  /** Provider hint in milliseconds, from `Retry-After` or the error body. */
  readonly retryAfterMs?: number;

  constructor(
    code: string,
    message: string,
    options: {
      retryable?: boolean;
      status?: number;
      provider?: KmsProvider;
      retryAfterMs?: number;
      cause?: unknown;
    } = {},
  ) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'KmsError';
    this.code = code;
    this.retryable = options.retryable ?? false;
    this.status = options.status;
    this.provider = options.provider;
    this.retryAfterMs = options.retryAfterMs;
  }
}

/** Credentials are missing, rejected, or lack `kms:Sign` / equivalent. */
export class KmsAuthorizationError extends KmsError {
  constructor(message: string, options: ConstructorParameters<typeof KmsError>[2] = {}) {
    super('authorization-failed', message, { ...options, retryable: false });
    this.name = 'KmsAuthorizationError';
  }
}

/** The provider asked us to slow down (`429`, `ThrottlingException`, ...). */
export class KmsThrottlingError extends KmsError {
  constructor(message: string, options: ConstructorParameters<typeof KmsError>[2] = {}) {
    super('throttled', message, { ...options, retryable: true });
    this.name = 'KmsThrottlingError';
  }
}

/** The key exists but cannot produce a Stellar-compatible signature. */
export class KmsUnsupportedAlgorithmError extends KmsError {
  constructor(message: string, options: ConstructorParameters<typeof KmsError>[2] = {}) {
    super('unsupported-algorithm', message, { ...options, retryable: false });
    this.name = 'KmsUnsupportedAlgorithmError';
  }
}

/** Retry behaviour shared by every adapter, overridable for tests. */
export interface KmsRetryOptions {
  /** Total attempts, including the first. Defaults to 5. */
  maxAttempts?: number;
  /** First backoff, doubled each attempt. Defaults to 200ms. */
  baseDelayMs?: number;
  /** Ceiling for a single wait. Defaults to 5s. */
  maxDelayMs?: number;
  /** Injected for deterministic tests. */
  sleep?: (ms: number) => Promise<void>;
  /** Jitter source in `[0, 1)`. */
  random?: () => number;
}

const DEFAULT_RETRY: Required<Omit<KmsRetryOptions, 'sleep' | 'random'>> = {
  maxAttempts: 5,
  baseDelayMs: 200,
  maxDelayMs: 5000,
};

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Retries only failures a repeat can fix: throttling and 5xx responses.
 *
 * Authorization errors, validation errors, and unsupported keys are returned
 * immediately — retrying a rejected credential only delays the operator's
 * diagnosis. `Retry-After` from the provider wins over the exponential curve,
 * capped by `maxDelayMs`.
 */
export async function withKmsRetry<T>(
  operation: (attempt: number) => Promise<T>,
  options: KmsRetryOptions = {},
): Promise<T> {
  const maxAttempts = options.maxAttempts ?? DEFAULT_RETRY.maxAttempts;
  const baseDelayMs = options.baseDelayMs ?? DEFAULT_RETRY.baseDelayMs;
  const maxDelayMs = options.maxDelayMs ?? DEFAULT_RETRY.maxDelayMs;
  const sleep = options.sleep ?? defaultSleep;
  const random = options.random ?? Math.random;

  let lastError: unknown;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await operation(attempt);
    } catch (error) {
      lastError = error;
      const retryable = error instanceof KmsError && error.retryable;
      if (!retryable || attempt === maxAttempts) throw error;

      const exponential = Math.min(maxDelayMs, baseDelayMs * 2 ** (attempt - 1));
      const jittered = Math.round(exponential * (0.5 + random() * 0.5));
      const hinted =
        error instanceof KmsError && error.retryAfterMs !== undefined
          ? Math.min(maxDelayMs, error.retryAfterMs)
          : undefined;
      await sleep(hinted ?? jittered);
    }
  }

  throw lastError;
}

/** `Authorization: Bearer ...` values and cloud access-key ids, for logs. */
const SECRET_PATTERNS: readonly RegExp[] = [
  /\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{12,20}\b/g,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{12,}\b/gi,
  /"?(?:private_key|client_secret|secret_access_key|session_token|access_token)"?\s*[:=]\s*"[^"]*"/gi,
];

/**
 * Removes credential-shaped text from an error message.
 *
 * The adapters never interpolate credentials into messages, but provider
 * error bodies are opaque enough that a shared sanitizer is cheap insurance
 * against an operator pasting a response into an issue.
 */
export function redactSecrets(text: string, extraSecrets: readonly string[] = []): string {
  let redacted = text;
  for (const secret of extraSecrets) {
    if (secret.length >= 4) redacted = redacted.split(secret).join('[redacted]');
  }
  for (const pattern of SECRET_PATTERNS) redacted = redacted.replace(pattern, '[redacted]');
  return redacted;
}

/** Parses `Retry-After` as seconds or an HTTP date into milliseconds. */
export function parseRetryAfter(value: string | null, now = Date.now()): number | undefined {
  if (value === null) return undefined;
  const trimmed = value.trim();
  if (trimmed === '') return undefined;

  const seconds = Number(trimmed);
  if (Number.isFinite(seconds) && seconds >= 0) return Math.round(seconds * 1000);

  const date = Date.parse(trimmed);
  if (!Number.isNaN(date)) return Math.max(0, date - now);
  return undefined;
}

/** Builds a provider error from a non-2xx response without echoing the request. */
export async function kmsHttpError(response: Response, provider: KmsProvider): Promise<KmsError> {
  const status = response.status;
  let code = `http-${status}`;
  let message = `${provider} KMS responded with HTTP ${status}`;

  try {
    const text = await response.text();
    if (text !== '') {
      const parsed: unknown = JSON.parse(text);
      if (isRecord(parsed)) {
        const error = isRecord(parsed.error) ? parsed.error : parsed;
        const rawCode = firstString(error.code, error.__type, error.type, parsed.name);
        const rawMessage = firstString(error.message, parsed.Message, parsed.message);
        if (rawCode !== undefined) code = rawCode.replace(/^.*#/, '');
        if (rawMessage !== undefined) message = `${provider} KMS: ${rawMessage}`;
      }
    }
  } catch {
    // A non-JSON body contributes nothing safer than the status line.
  }

  message = redactSecrets(message);
  const retryAfterMs = parseRetryAfter(response.headers.get('retry-after'));

  const throttled =
    status === 429 ||
    /throttl|rate.?limit|too.?many|limit.?exceeded/i.test(code) ||
    /throttl|rate.?limit|too.?many/i.test(message);
  if (throttled) {
    return new KmsThrottlingError(message, {
      status,
      provider,
      ...(retryAfterMs !== undefined ? { retryAfterMs } : {}),
    });
  }

  const unauthorized =
    status === 401 ||
    status === 403 ||
    /access.?denied|unauthori[sz]ed|forbidden|invalid.?client.?token|expired.?token|signature.?does.?not.?match|permission/i.test(
      code,
    );
  if (unauthorized) {
    return new KmsAuthorizationError(message, { status, provider });
  }

  return new KmsError(code, message, {
    status,
    provider,
    retryable: status >= 500,
    ...(retryAfterMs !== undefined ? { retryAfterMs } : {}),
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function firstString(...values: unknown[]): string | undefined {
  for (const value of values) {
    if (typeof value === 'string' && value !== '') return value;
  }
  return undefined;
}

/* ── Encoding helpers ─────────────────────────────────────────────────────── */

export function base64(value: Buffer | Uint8Array): string {
  return Buffer.from(value).toString('base64');
}

/** Decodes base64 or base64url, tolerating whitespace from a wrapped CLI arg. */
export function decodeBase64(value: string): Buffer {
  const normalized = value.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(normalized, 'base64');
}

export function base64Url(value: Buffer | Uint8Array): string {
  return Buffer.from(value).toString('base64url');
}

/* ── Public key helpers ───────────────────────────────────────────────────── */

/** Raw public-key bytes plus the PEM the coordinator verifies against. */
export interface ParsedPublicKey {
  publicKey: Buffer;
  publicKeyPem: string;
}

/**
 * Normalises an Ed25519/secp256k1 public key from PEM or DER SPKI.
 *
 * AWS and GCP return DER/PEM; Azure returns JWK coordinates. Going through
 * Node's `KeyObject` means all three converge on the same raw bytes, which is
 * what the Stellar hint is computed from.
 */
export function parsePublicKey(key: Buffer | string, format: 'pem' | 'der'): ParsedPublicKey {
  const keyObject =
    format === 'pem'
      ? createPublicKey({ key: String(key), format: 'pem' })
      : createPublicKey({ key: Buffer.from(key), format: 'der', type: 'spki' });

  const jwk = keyObject.export({ format: 'jwk' });
  if (!isRecord(jwk)) {
    throw new KmsError('invalid-public-key', 'KMS public key could not be exported as JWK');
  }

  let publicKey: Buffer;
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519' && typeof jwk.x === 'string') {
    publicKey = Buffer.from(jwk.x, 'base64url');
  } else if (jwk.kty === 'EC' && typeof jwk.x === 'string' && typeof jwk.y === 'string') {
    publicKey = compressEcPoint(Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url'));
  } else {
    throw new KmsError(
      'unsupported-key-type',
      `KMS public key is ${String(jwk.kty)}/${String(jwk.crv)}, not Ed25519 or secp256k1`,
    );
  }

  const publicKeyPem = keyObject.export({ format: 'pem', type: 'spki' }).toString();
  return { publicKey, publicKeyPem };
}

/** Compresses an uncompressed EC point into its 33-byte SEC1 form. */
export function compressEcPoint(x: Buffer, y: Buffer): Buffer {
  const x32 = leftPad(x, 32);
  const y32 = leftPad(y, 32);
  const prefix = (y32[31] as number) % 2 === 0 ? 0x02 : 0x03;
  return Buffer.concat([Buffer.from([prefix]), x32]);
}

function leftPad(value: Buffer, length: number): Buffer {
  if (value.length === length) return value;
  if (value.length > length) return value.subarray(value.length - length);
  return Buffer.concat([Buffer.alloc(length - value.length), value]);
}

/** Derives the G... address for an Ed25519 KMS key. */
export function stellarAddressFor(publicKey: Buffer): string | undefined {
  if (publicKey.length !== 32) return undefined;
  return StrKey.encodeEd25519PublicKey(publicKey);
}

/* ── Signature conversion ─────────────────────────────────────────────────── */

/**
 * Converts a provider signature into the 64-byte form Stellar XDR carries.
 *
 * Ed25519 is already 64 raw bytes. ECDSA providers return DER, so `r` and `s`
 * are extracted and left-padded to 32 bytes each; Stellar has no room for DER
 * length prefixes inside `DecoratedSignature.signature`.
 */
export function signatureToStellarFormat(
  signature: Buffer,
  algorithm: KmsKeyAlgorithm,
): { signature: Buffer; format: 'raw' | 'der-converted' } {
  if (algorithm === 'ECC_NIST_ED25519') {
    if (signature.length !== 64) {
      throw new KmsError(
        'invalid-signature',
        `Ed25519 signature is ${signature.length} bytes; expected 64`,
      );
    }
    return { signature, format: 'raw' };
  }

  if (signature.length === 64) return { signature, format: 'raw' };
  const { r, s } = parseDerSignature(signature);
  return { signature: Buffer.concat([leftPad(r, 32), leftPad(s, 32)]), format: 'der-converted' };
}

/** Converts a raw 64-byte ECDSA signature back to DER for local verification. */
export function rawSignatureToDer(raw: Buffer): Buffer {
  if (raw.length !== 64) {
    throw new KmsError('invalid-signature', `ECDSA signature is ${raw.length} bytes; expected 64`);
  }
  const r = derInteger(raw.subarray(0, 32));
  const s = derInteger(raw.subarray(32, 64));
  const body = Buffer.concat([r, s]);
  return Buffer.concat([Buffer.from([0x30]), derLength(body.length), body]);
}

function derInteger(value: Buffer): Buffer {
  let start = 0;
  while (start < value.length - 1 && value[start] === 0) start++;
  const trimmed = value.subarray(start);
  const positive = ((trimmed[0] as number) & 0x80) !== 0;
  const content = positive ? Buffer.concat([Buffer.from([0]), trimmed]) : trimmed;
  return Buffer.concat([Buffer.from([0x02]), derLength(content.length), content]);
}

function derLength(length: number): Buffer {
  if (length < 0x80) return Buffer.from([length]);
  const bytes: number[] = [];
  let remaining = length;
  while (remaining > 0) {
    bytes.unshift(remaining & 0xff);
    remaining >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

/** Parses a DER `SEQUENCE { INTEGER r, INTEGER s }` ECDSA signature. */
export function parseDerSignature(der: Buffer): { r: Buffer; s: Buffer } {
  let offset = 0;
  if (der[offset] !== 0x30) {
    throw new KmsError('invalid-signature', 'ECDSA signature is not a DER SEQUENCE');
  }
  offset++;
  const sequenceLength = readDerLength(der, offset);
  offset = sequenceLength.offset;
  if (offset + sequenceLength.length !== der.length) {
    throw new KmsError('invalid-signature', 'ECDSA signature length does not match its DER header');
  }

  const readInteger = (): Buffer => {
    if (der[offset] !== 0x02) {
      throw new KmsError('invalid-signature', 'ECDSA signature is missing a DER INTEGER');
    }
    offset++;
    const length = readDerLength(der, offset);
    offset = length.offset;
    const value = der.subarray(offset, offset + length.length);
    if (value.length !== length.length) {
      throw new KmsError('invalid-signature', 'ECDSA signature INTEGER is truncated');
    }
    offset += length.length;
    return value;
  };

  const r = readInteger();
  const s = readInteger();
  return { r, s };
}

function readDerLength(der: Buffer, offset: number): { length: number; offset: number } {
  const first = der[offset];
  if (first === undefined) {
    throw new KmsError('invalid-signature', 'ECDSA signature is truncated');
  }
  if (first < 0x80) return { length: first, offset: offset + 1 };

  const count = first & 0x7f;
  if (count === 0 || count > 4) {
    throw new KmsError('invalid-signature', 'unsupported DER length encoding');
  }
  let length = 0;
  for (let i = 0; i < count; i++) {
    const byte = der[offset + 1 + i];
    if (byte === undefined) {
      throw new KmsError('invalid-signature', 'ECDSA signature is truncated');
    }
    length = (length << 8) | byte;
  }
  return { length, offset: offset + 1 + count };
}

/**
 * Checks a KMS signature against the transaction it claims to sign.
 *
 * Ed25519 signs the 32-byte digest directly. ECDSA providers sign the digest
 * too, but Node's verifier only exposes pre-image verification, so the
 * signature base is supplied and hashed back to the same digest.
 */
export function verifySignature(
  publicKeyPem: string,
  algorithm: KmsKeyAlgorithm,
  signature: Buffer,
  digest: Buffer,
  signatureBase: Buffer,
): boolean {
  try {
    const key = createPublicKey(publicKeyPem);
    if (algorithm === 'ECC_NIST_ED25519') {
      return cryptoVerify(null, digest, key, signature);
    }
    return cryptoVerify('sha256', signatureBase, key, rawSignatureToDer(signature));
  } catch {
    return false;
  }
}

/** The four-byte hint Stellar puts in front of a signature. */
export function signatureHint(publicKey: Buffer): Buffer {
  return Buffer.from(publicKey.subarray(Math.max(0, publicKey.length - 4)));
}
