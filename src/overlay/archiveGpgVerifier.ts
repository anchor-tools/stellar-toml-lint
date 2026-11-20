import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { request as httpsRequest } from 'node:https';
import { gunzipSync } from 'node:zlib';
import * as openpgp from 'openpgp';

const MANIFEST_PATH = '.well-known/stellar-history.json';
const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_MANIFEST_BYTES = 1024 * 1024;
const DEFAULT_MAX_PAYLOAD_BYTES = 32 * 1024 * 1024;
const DEFAULT_MAX_SIGNATURE_BYTES = 1024 * 1024;
const DEFAULT_MAX_PUBLIC_KEY_BYTES = 1024 * 1024;
const MAX_PUBLIC_KEYS = 64;
const MAX_SIGNATURES = 16;
const PGP_PUBLIC_KEY_HEADER = '-----BEGIN PGP PUBLIC KEY BLOCK-----';
const PGP_PRIVATE_KEY_HEADER = /-----BEGIN PGP (?:PRIVATE|SECRET) KEY BLOCK-----/i;
const ALLOWED_HASHES = [
  openpgp.enums.hash.sha256,
  openpgp.enums.hash.sha384,
  openpgp.enums.hash.sha512,
];
const VERIFICATION_CONFIG = { ...openpgp.config, minRSABits: 0 };

export type ArchiveGpgStatus =
  | 'verified'
  | 'missing-key'
  | 'invalid-key'
  | 'weak-key'
  | 'unsupported-algorithm'
  | 'expired-key'
  | 'revoked-key'
  | 'untrusted-key'
  | 'invalid-signature'
  | 'malformed-signature'
  | 'expired-signature'
  | 'unsupported-signature-algorithm'
  | 'ambiguous-signer'
  | 'missing-manifest'
  | 'malformed-manifest'
  | 'malformed-checkpoint'
  | 'missing-checkpoint'
  | 'missing-signature'
  | 'http-error'
  | 'timeout'
  | 'unsafe-url'
  | 'oversized-response'
  | 'unexpected-content-type';

export type ArchiveGpgIdentityTrust = 'unknown' | 'trusted' | 'mismatch';

export interface ArchiveGpgSigner {
  fingerprint: string;
  primaryFingerprint: string;
  algorithm: string;
  keyBits?: number;
}

export interface ArchiveGpgVerificationResult {
  ok: boolean;
  status: ArchiveGpgStatus;
  /** True only when OpenPGP.js verified the detached signature over these bytes. */
  cryptographicallyValid: boolean;
  /** A key supplied by the caller is not operator-identity proof by itself. */
  identityTrust: ArchiveGpgIdentityTrust;
  keySource: 'provided' | 'not-provided';
  signers: ArchiveGpgSigner[];
  keyExpiresAt?: string | null;
  archiveUrl?: string;
  manifestUrl?: string;
  checkpointSequence?: number;
  payloadUrl?: string;
  signatureUrl?: string;
  error?: string;
}

export interface ArchiveGpgVerifierOptions {
  /** An injected transport is useful for tests and controlled applications. */
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  maxManifestBytes?: number;
  maxPayloadBytes?: number;
  maxSignatureBytes?: number;
  maxPublicKeyBytes?: number;
  now?: Date;
}

export interface VerifyDetachedOptions {
  payload: Uint8Array;
  signature: Uint8Array | string;
  publicKey?: string;
  trustedFingerprint?: string;
  payloadUrl?: string;
  signatureUrl?: string;
  archiveUrl?: string;
  manifestUrl?: string;
  checkpointSequence?: number;
}

export interface VerifyArchiveOptions {
  archiveUrl: string;
  publicKey?: string;
  /** Optional fingerprint pinned out of band by the caller. */
  trustedFingerprint?: string;
  /** Stellar Core has no standard signature URL; this overrides the .sig candidate. */
  signatureUrl?: string;
}

interface BoundedResponse {
  status: number;
  headers: Headers;
  bytes: Uint8Array;
}

class VerificationError extends Error {
  constructor(
    readonly status: ArchiveGpgStatus,
    message: string,
  ) {
    super(message);
    this.name = 'VerificationError';
  }
}

function result(
  status: ArchiveGpgStatus,
  error: string,
  fields: Partial<ArchiveGpgVerificationResult> = {},
): ArchiveGpgVerificationResult {
  return {
    ok: false,
    status,
    cryptographicallyValid: false,
    identityTrust: 'unknown',
    keySource: 'not-provided',
    signers: [],
    error,
    ...fields,
  };
}

function textBytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function normalizeFingerprint(value: string): string | undefined {
  const normalized = value.replace(/\s+/g, '').toLowerCase();
  return /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(normalized) ? normalized : undefined;
}

function statusFromError(error: unknown): VerificationError | undefined {
  return error instanceof VerificationError ? error : undefined;
}

function ipV4Number(address: string): number | undefined {
  const parts = address.split('.').map(Number);
  if (
    parts.length !== 4 ||
    parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)
  ) {
    return undefined;
  }
  return (
    (((parts[0] ?? 0) << 24) |
      ((parts[1] ?? 0) << 16) |
      ((parts[2] ?? 0) << 8) |
      (parts[3] ?? 0)) >>>
    0
  );
}

function inV4Range(address: string, network: string, prefix: number): boolean {
  const value = ipV4Number(address);
  const base = ipV4Number(network);
  if (value === undefined || base === undefined) return false;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (value & mask) === (base & mask);
}

function isPublicAddress(rawAddress: string): boolean {
  const address =
    rawAddress
      .toLowerCase()
      .replace(/^\[|\]$/g, '')
      .split('%')[0] ?? '';
  const family = isIP(address);
  if (family === 4) {
    const blocked = [
      ['0.0.0.0', 8],
      ['10.0.0.0', 8],
      ['100.64.0.0', 10],
      ['127.0.0.0', 8],
      ['169.254.0.0', 16],
      ['172.16.0.0', 12],
      ['192.0.0.0', 24],
      ['192.0.2.0', 24],
      ['192.88.99.0', 24],
      ['192.168.0.0', 16],
      ['198.18.0.0', 15],
      ['198.51.100.0', 24],
      ['203.0.113.0', 24],
      ['224.0.0.0', 4],
      ['240.0.0.0', 4],
    ] as const;
    return !blocked.some(([network, prefix]) => inV4Range(address, network, prefix));
  }
  if (family === 6) {
    // Accept only global-unicast space, excluding documentation, transition,
    // and special-use prefixes that may tunnel or map to non-public IPv4.
    const groups = address.split(':');
    const first = Number.parseInt(groups[0] || '0', 16);
    const second = Number.parseInt(groups[1] || '0', 16);
    if (first < 0x2000 || first > 0x3fff) return false;
    if (first === 0x2001 && (second < 0x0400 || second === 0x0db8)) {
      return false;
    }
    if (first === 0x2002) return false;
    if (first === 0x3fff && second < 0x1000) return false;
    return true;
  }
  return false;
}

function validateHttpsUrl(rawUrl: string): URL {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new VerificationError('unsafe-url', 'A request URL is not a valid absolute URL');
  }
  if (
    url.protocol !== 'https:' ||
    url.hostname === '' ||
    url.username !== '' ||
    url.password !== '' ||
    url.hash !== ''
  ) {
    throw new VerificationError(
      'unsafe-url',
      'Archive requests require an HTTPS URL without credentials or a fragment',
    );
  }
  const hostname = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  const normalizedHostname = hostname.replace(/\.$/, '');
  if (
    normalizedHostname === 'localhost' ||
    normalizedHostname.endsWith('.localhost') ||
    normalizedHostname.endsWith('.local') ||
    (isIP(normalizedHostname) !== 0 && !isPublicAddress(normalizedHostname))
  ) {
    throw new VerificationError('unsafe-url', 'Archive requests cannot target local hostnames');
  }
  return url;
}

function timeoutSignal(timeoutMs: number): AbortSignal {
  return AbortSignal.timeout(timeoutMs);
}

function requirePositiveSafeInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new RangeError(`${name} must be a positive safe integer`);
  }
  return value;
}

async function lookupPublicAddresses(hostname: string, signal: AbortSignal) {
  if (signal.aborted) throw new VerificationError('timeout', 'The archive request timed out');
  const lookupPromise = lookup(hostname, { all: true, verbatim: true });
  const addresses = await Promise.race([
    lookupPromise,
    new Promise<never>((_, reject) => {
      if (signal.aborted) {
        reject(new VerificationError('timeout', 'The archive request timed out'));
        return;
      }
      signal.addEventListener(
        'abort',
        () => reject(new VerificationError('timeout', 'The archive request timed out')),
        { once: true },
      );
    }),
  ]);
  if (addresses.length === 0 || addresses.some((entry) => !isPublicAddress(entry.address))) {
    throw new VerificationError('unsafe-url', 'The archive host resolves to a non-public address');
  }
  return addresses;
}

/** HTTPS transport that pins the DNS answer and never follows redirects. */
async function requestPublicHttps(
  url: URL,
  maxBytes: number,
  timeoutMs: number,
): Promise<BoundedResponse> {
  const signal = timeoutSignal(timeoutMs);
  const hostname = url.hostname.replace(/^\[|\]$/g, '');
  const addresses = await lookupPublicAddresses(hostname, signal);
  const first = addresses[0];
  if (first === undefined)
    throw new VerificationError('unsafe-url', 'The archive host did not resolve');

  return new Promise<BoundedResponse>((resolve, reject) => {
    let settled = false;
    const finish = (error?: Error, response?: BoundedResponse): void => {
      if (settled) return;
      settled = true;
      if (error !== undefined) reject(error);
      else if (response !== undefined) resolve(response);
      else reject(new VerificationError('http-error', 'The archive response could not be read'));
    };

    const request = httpsRequest(
      url,
      {
        method: 'GET',
        signal,
        headers: {
          accept: '*/*',
          'accept-encoding': 'identity',
          'user-agent': 'stellar-toml-lint/0.1.0',
        },
        lookup: (_host, options, callback) => {
          if (options.all) {
            callback(null, addresses);
          } else {
            callback(null, first.address, first.family);
          }
        },
      },
      (response) => {
        const status = response.statusCode ?? 0;
        const headers = new Headers();
        for (const [name, value] of Object.entries(response.headers)) {
          if (Array.isArray(value)) {
            for (const item of value) headers.append(name, item);
          } else if (value !== undefined) {
            headers.set(name, String(value));
          }
        }

        const declaredSize = Number(headers.get('content-length'));
        if (Number.isFinite(declaredSize) && declaredSize > maxBytes) {
          const error = new VerificationError(
            'oversized-response',
            'The archive response is too large',
          );
          response.destroy(error);
          finish(error);
          return;
        }

        const chunks: Buffer[] = [];
        let size = 0;
        response.on('data', (chunk: Buffer | string) => {
          const bytes = typeof chunk === 'string' ? Buffer.from(chunk) : chunk;
          size += bytes.length;
          if (size > maxBytes) {
            const error = new VerificationError(
              'oversized-response',
              'The archive response is too large',
            );
            response.destroy(error);
            finish(error);
            return;
          }
          chunks.push(bytes);
        });
        response.on('end', () => {
          const body = new Uint8Array(Buffer.concat(chunks, size));
          finish(undefined, { status, headers, bytes: body });
        });
        response.on('error', (error: Error) => finish(error));
      },
    );
    request.on('error', (error: Error) => {
      if (signal.aborted) {
        finish(new VerificationError('timeout', 'The archive request timed out'));
      } else {
        finish(new VerificationError('http-error', 'The archive request failed'));
      }
      void error;
    });
    request.end();
  });
}

async function readInjectedResponse(
  fetchImpl: typeof fetch,
  url: URL,
  maxBytes: number,
  timeoutMs: number,
): Promise<BoundedResponse> {
  const signal = timeoutSignal(timeoutMs);
  let response: Response;
  try {
    response = await fetchImpl(url.toString(), {
      method: 'GET',
      redirect: 'manual',
      signal,
      headers: { accept: '*/*', 'accept-encoding': 'identity' },
    });
  } catch {
    if (signal.aborted) throw new VerificationError('timeout', 'The archive request timed out');
    throw new VerificationError('http-error', 'The archive request failed');
  }
  if (response.status >= 300 && response.status < 400) {
    await response.body?.cancel();
    throw new VerificationError(
      'unsafe-url',
      'The archive returned a redirect, which is not followed',
    );
  }

  const declaredSize = Number(response.headers.get('content-length'));
  if (Number.isFinite(declaredSize) && declaredSize > maxBytes) {
    await response.body?.cancel();
    throw new VerificationError('oversized-response', 'The archive response is too large');
  }
  const chunks: Uint8Array[] = [];
  let size = 0;
  if (response.body !== null) {
    const reader = response.body.getReader();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.length;
        if (size > maxBytes) {
          await reader.cancel();
          throw new VerificationError('oversized-response', 'The archive response is too large');
        }
        chunks.push(value);
      }
    } catch (error) {
      if (error instanceof VerificationError) throw error;
      if (signal.aborted) throw new VerificationError('timeout', 'The archive request timed out');
      throw new VerificationError('http-error', 'The archive response could not be read');
    }
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return { status: response.status, headers: response.headers, bytes };
}

function checkContentType(
  response: BoundedResponse,
  kind: 'manifest' | 'payload' | 'signature',
): void {
  const contentEncoding = response.headers.get('content-encoding')?.trim().toLowerCase();
  if (contentEncoding !== undefined && contentEncoding !== '' && contentEncoding !== 'identity') {
    throw new VerificationError(
      'unexpected-content-type',
      `The ${kind} response uses an unsupported HTTP content encoding`,
    );
  }
  const contentType = response.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();
  if (contentType === undefined || contentType === '') return;
  if (kind === 'manifest') {
    if (contentType === 'application/json' || contentType.endsWith('+json')) return;
  } else if (kind === 'payload') {
    if (
      contentType === 'application/octet-stream' ||
      contentType === 'application/gzip' ||
      contentType === 'application/x-gzip' ||
      contentType === 'application/x-xdr'
    ) {
      return;
    }
  } else if (
    contentType === 'application/octet-stream' ||
    contentType === 'application/pgp-signature' ||
    contentType === 'application/x-pgp-signature'
  ) {
    return;
  }
  throw new VerificationError(
    'unexpected-content-type',
    `The ${kind} response has an unexpected content type`,
  );
}

function parseManifest(bytes: Uint8Array): number {
  let body: unknown;
  try {
    body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown;
  } catch {
    throw new VerificationError(
      'malformed-manifest',
      'The Stellar history manifest is not valid JSON',
    );
  }
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    throw new VerificationError(
      'malformed-manifest',
      'The Stellar history manifest is not an object',
    );
  }
  const manifest = body as Record<string, unknown>;
  const version = manifest.version;
  const currentLedger = manifest.currentLedger;
  if (
    (version !== 1 && version !== 2) ||
    typeof currentLedger !== 'number' ||
    !Number.isSafeInteger(currentLedger) ||
    currentLedger < 63 ||
    currentLedger > 0xffffffff ||
    (currentLedger + 1) % 64 !== 0
  ) {
    throw new VerificationError(
      'malformed-manifest',
      'The Stellar history manifest does not contain a supported version and checkpoint ledger',
    );
  }
  return currentLedger;
}

function checkpointLedgerUrl(archiveRoot: URL, sequence: number): URL {
  const hex = sequence.toString(16).padStart(8, '0');
  const path = `ledger/${hex.slice(0, 2)}/${hex.slice(2, 4)}/${hex.slice(4, 6)}/ledger-${hex}.xdr.gz`;
  return new URL(path, archiveRoot);
}

function validateCheckpointGzip(bytes: Uint8Array): void {
  if (bytes.length < 18 || bytes[0] !== 0x1f || bytes[1] !== 0x8b) {
    throw new VerificationError('malformed-checkpoint', 'The ledger checkpoint is not a gzip file');
  }
  let decompressed: Buffer;
  try {
    decompressed = gunzipSync(bytes, { maxOutputLength: 8 * 1024 * 1024 });
  } catch {
    throw new VerificationError(
      'malformed-checkpoint',
      'The ledger checkpoint gzip data is corrupt',
    );
  }
  if (decompressed.length === 0 || decompressed.length % 4 !== 0) {
    throw new VerificationError(
      'malformed-checkpoint',
      'The ledger checkpoint does not contain aligned XDR bytes',
    );
  }
}

function algorithmProblem(
  algorithm: string,
  bits?: number,
  curve?: string,
): ArchiveGpgStatus | undefined {
  const name = algorithm.toLowerCase();
  const curveName = curve?.toLowerCase();
  if (
    name === 'rsaencryptsign' ||
    name === 'rsasignonly' ||
    name === 'rsageneral' ||
    name === 'rsa'
  ) {
    if (bits === undefined) return 'unsupported-algorithm';
    return bits < 2048 ? 'weak-key' : undefined;
  }
  if (
    (name === 'eddsa' || name === 'eddsalegacy') &&
    (curveName === 'ed25519' || curveName === 'ed25519legacy')
  ) {
    return undefined;
  }
  return 'unsupported-algorithm';
}

function safeErrorText(status: ArchiveGpgStatus): string {
  const messages: Record<ArchiveGpgStatus, string> = {
    verified: 'The detached signature is valid',
    'missing-key': 'A public key is required',
    'invalid-key': 'The supplied public key cannot be parsed or validated',
    'weak-key': 'The signing key does not meet the RSA 2048-bit minimum',
    'unsupported-algorithm': 'The signing key algorithm is not supported by policy',
    'expired-key': 'The signing key or signing subkey is expired',
    'revoked-key': 'The signing key or signing subkey is revoked',
    'untrusted-key': 'The signer fingerprint does not match the independently pinned fingerprint',
    'invalid-signature': 'The detached signature does not verify for the supplied payload and key',
    'malformed-signature': 'The detached signature cannot be parsed',
    'expired-signature': 'The detached signature is expired or outside its validity period',
    'unsupported-signature-algorithm': 'The signature uses a hash algorithm that is not allowed',
    'ambiguous-signer': 'The signature has multiple or ambiguous signing identities',
    'missing-manifest': 'The archive does not provide .well-known/stellar-history.json',
    'malformed-manifest': 'The Stellar history manifest is malformed or unsupported',
    'malformed-checkpoint': 'The latest ledger checkpoint is not valid gzip-compressed XDR data',
    'missing-checkpoint': 'The latest ledger checkpoint payload is unavailable',
    'missing-signature': 'No detached signature was found for the latest ledger checkpoint',
    'http-error': 'The archive request failed',
    timeout: 'The archive request timed out',
    'unsafe-url': 'The archive URL is unsafe or redirects to another location',
    'oversized-response': 'An archive response exceeded its configured size limit',
    'unexpected-content-type': 'An archive response has an unexpected content type',
  };
  return messages[status];
}

export class ArchiveGpgVerifier {
  private readonly timeoutMs: number;
  private readonly maxManifestBytes: number;
  private readonly maxPayloadBytes: number;
  private readonly maxSignatureBytes: number;
  private readonly maxPublicKeyBytes: number;
  private readonly now: Date;

  constructor(private readonly options: ArchiveGpgVerifierOptions = {}) {
    this.timeoutMs = requirePositiveSafeInteger(
      options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      'timeoutMs',
    );
    this.maxManifestBytes = requirePositiveSafeInteger(
      options.maxManifestBytes ?? DEFAULT_MAX_MANIFEST_BYTES,
      'maxManifestBytes',
    );
    this.maxPayloadBytes = requirePositiveSafeInteger(
      options.maxPayloadBytes ?? DEFAULT_MAX_PAYLOAD_BYTES,
      'maxPayloadBytes',
    );
    this.maxSignatureBytes = requirePositiveSafeInteger(
      options.maxSignatureBytes ?? DEFAULT_MAX_SIGNATURE_BYTES,
      'maxSignatureBytes',
    );
    this.maxPublicKeyBytes = requirePositiveSafeInteger(
      options.maxPublicKeyBytes ?? DEFAULT_MAX_PUBLIC_KEY_BYTES,
      'maxPublicKeyBytes',
    );
    this.now = options.now ?? new Date();
    if (Number.isNaN(this.now.getTime())) throw new RangeError('now must be a valid date');
  }

  async verifyArchive(options: VerifyArchiveOptions): Promise<ArchiveGpgVerificationResult> {
    let archiveRoot: URL;
    let manifestUrl: URL;
    try {
      archiveRoot = validateHttpsUrl(options.archiveUrl);
      archiveRoot.search = '';
      archiveRoot.pathname = `${archiveRoot.pathname.replace(/\/+$/, '')}/`;
      manifestUrl = new URL(MANIFEST_PATH, archiveRoot);
    } catch (error) {
      const failure = statusFromError(error);
      return result(
        failure?.status ?? 'unsafe-url',
        failure?.message ?? safeErrorText('unsafe-url'),
        {
          archiveUrl: options.archiveUrl,
        },
      );
    }

    const base = {
      archiveUrl: archiveRoot.toString(),
      manifestUrl: manifestUrl.toString(),
      keySource:
        options.publicKey === undefined ? ('not-provided' as const) : ('provided' as const),
    };
    if (options.publicKey === undefined || options.publicKey.trim() === '') {
      return result('missing-key', safeErrorText('missing-key'), base);
    }
    if (Buffer.byteLength(options.publicKey, 'utf8') > this.maxPublicKeyBytes) {
      return result('oversized-response', safeErrorText('oversized-response'), base);
    }

    let manifestResponse: BoundedResponse;
    try {
      manifestResponse = await this.get(manifestUrl, this.maxManifestBytes);
      if (manifestResponse.status === 404) {
        return result('missing-manifest', safeErrorText('missing-manifest'), base);
      }
      if (manifestResponse.status < 200 || manifestResponse.status >= 300) {
        return result(
          'http-error',
          `The archive manifest request returned HTTP ${manifestResponse.status}`,
          base,
        );
      }
      checkContentType(manifestResponse, 'manifest');
    } catch (error) {
      const failure = statusFromError(error);
      return result(
        failure?.status ?? 'http-error',
        failure?.message ?? safeErrorText('http-error'),
        base,
      );
    }

    let checkpointSequence: number;
    try {
      checkpointSequence = parseManifest(manifestResponse.bytes);
    } catch (error) {
      const failure = statusFromError(error);
      return result(
        'malformed-manifest',
        failure?.message ?? safeErrorText('malformed-manifest'),
        base,
      );
    }

    const payloadUrl = checkpointLedgerUrl(archiveRoot, checkpointSequence);
    let signatureTarget: URL;
    let signature: BoundedResponse;
    try {
      signatureTarget =
        options.signatureUrl === undefined
          ? new URL(`${payloadUrl}.sig`)
          : validateHttpsUrl(options.signatureUrl);
      signature = await this.get(signatureTarget, this.maxSignatureBytes);
      if (signature.status === 404) {
        return result('missing-signature', safeErrorText('missing-signature'), {
          ...base,
          checkpointSequence,
          payloadUrl: payloadUrl.toString(),
          signatureUrl: signatureTarget.toString(),
        });
      }
      if (signature.status < 200 || signature.status >= 300) {
        return result('http-error', `The signature request returned HTTP ${signature.status}`, {
          ...base,
          checkpointSequence,
          payloadUrl: payloadUrl.toString(),
          signatureUrl: signatureTarget.toString(),
        });
      }
      checkContentType(signature, 'signature');
    } catch (error) {
      const failure = statusFromError(error);
      return result(
        failure?.status ?? 'http-error',
        failure?.message ?? safeErrorText('http-error'),
        {
          ...base,
          checkpointSequence,
          payloadUrl: payloadUrl.toString(),
          ...(options.signatureUrl === undefined
            ? { signatureUrl: `${payloadUrl}.sig` }
            : { signatureUrl: options.signatureUrl }),
        },
      );
    }

    let payload: BoundedResponse;
    try {
      payload = await this.get(payloadUrl, this.maxPayloadBytes);
      if (payload.status === 404) {
        return result('missing-checkpoint', safeErrorText('missing-checkpoint'), {
          ...base,
          checkpointSequence,
          payloadUrl: payloadUrl.toString(),
          signatureUrl: signatureTarget.toString(),
        });
      }
      if (payload.status < 200 || payload.status >= 300) {
        return result('http-error', `The checkpoint request returned HTTP ${payload.status}`, {
          ...base,
          checkpointSequence,
          payloadUrl: payloadUrl.toString(),
          signatureUrl: signatureTarget.toString(),
        });
      }
      checkContentType(payload, 'payload');
      validateCheckpointGzip(payload.bytes);
    } catch (error) {
      const failure = statusFromError(error);
      return result(
        failure?.status ?? 'http-error',
        failure?.message ?? safeErrorText('http-error'),
        {
          ...base,
          checkpointSequence,
          payloadUrl: payloadUrl.toString(),
          signatureUrl: signatureTarget.toString(),
        },
      );
    }

    return this.verifyDetached({
      payload: payload.bytes,
      signature: signature.bytes,
      publicKey: options.publicKey,
      trustedFingerprint: options.trustedFingerprint,
      archiveUrl: archiveRoot.toString(),
      manifestUrl: manifestUrl.toString(),
      checkpointSequence,
      payloadUrl: payloadUrl.toString(),
      signatureUrl: signatureTarget.toString(),
    });
  }

  async verifyDetached(options: VerifyDetachedOptions): Promise<ArchiveGpgVerificationResult> {
    const fields = {
      ...(options.archiveUrl === undefined ? {} : { archiveUrl: options.archiveUrl }),
      ...(options.manifestUrl === undefined ? {} : { manifestUrl: options.manifestUrl }),
      ...(options.checkpointSequence === undefined
        ? {}
        : { checkpointSequence: options.checkpointSequence }),
      ...(options.payloadUrl === undefined ? {} : { payloadUrl: options.payloadUrl }),
      ...(options.signatureUrl === undefined ? {} : { signatureUrl: options.signatureUrl }),
      keySource:
        options.publicKey === undefined ? ('not-provided' as const) : ('provided' as const),
    };

    if (options.publicKey === undefined || options.publicKey.trim() === '') {
      return result('missing-key', safeErrorText('missing-key'), fields);
    }
    if (Buffer.byteLength(options.publicKey, 'utf8') > this.maxPublicKeyBytes) {
      return result(
        'oversized-response',
        'The supplied public key exceeds the configured size limit',
        fields,
      );
    }
    if (options.payload.length === 0 || options.payload.length > this.maxPayloadBytes) {
      return result(
        options.payload.length > this.maxPayloadBytes ? 'oversized-response' : 'invalid-signature',
        options.payload.length > this.maxPayloadBytes
          ? safeErrorText('oversized-response')
          : 'The checkpoint payload is empty',
        fields,
      );
    }

    const publicKeyText = options.publicKey.trim();
    if (
      PGP_PRIVATE_KEY_HEADER.test(publicKeyText) ||
      !publicKeyText.includes(PGP_PUBLIC_KEY_HEADER)
    ) {
      return result('invalid-key', safeErrorText('invalid-key'), fields);
    }

    let keys: openpgp.PublicKey[];
    let signature: openpgp.Signature;
    try {
      const blocks = publicKeyText.match(
        /-----BEGIN PGP PUBLIC KEY BLOCK-----[\s\S]*?-----END PGP PUBLIC KEY BLOCK-----/g,
      );
      const remainder = publicKeyText.replace(
        /-----BEGIN PGP PUBLIC KEY BLOCK-----[\s\S]*?-----END PGP PUBLIC KEY BLOCK-----/g,
        '',
      );
      if (blocks === null || blocks.length === 0 || remainder.trim() !== '') {
        return result('invalid-key', safeErrorText('invalid-key'), fields);
      }
      if (blocks.length > MAX_PUBLIC_KEYS) {
        return result('oversized-response', safeErrorText('oversized-response'), fields);
      }
      keys = await Promise.all(blocks.map((armoredKey) => openpgp.readKey({ armoredKey })));
      if (keys.some((key) => key.isPrivate())) {
        return result('invalid-key', safeErrorText('invalid-key'), fields);
      }
      const unique = new Map(keys.map((key) => [key.getFingerprint(), key]));
      keys = [...unique.values()];
    } catch {
      return result('invalid-key', safeErrorText('invalid-key'), fields);
    }

    if (
      typeof options.signature === 'string' &&
      Buffer.byteLength(options.signature, 'utf8') > this.maxSignatureBytes
    ) {
      return result('oversized-response', safeErrorText('oversized-response'), fields);
    }
    const signatureBytes =
      typeof options.signature === 'string' ? textBytes(options.signature) : options.signature;
    if (signatureBytes.length === 0 || signatureBytes.length > this.maxSignatureBytes) {
      return result(
        signatureBytes.length > this.maxSignatureBytes
          ? 'oversized-response'
          : 'malformed-signature',
        signatureBytes.length > this.maxSignatureBytes
          ? safeErrorText('oversized-response')
          : safeErrorText('malformed-signature'),
        fields,
      );
    }
    try {
      const signatureText = new TextDecoder().decode(signatureBytes);
      signature = signatureText.trimStart().startsWith('-----BEGIN PGP SIGNATURE-----')
        ? await openpgp.readSignature({ armoredSignature: signatureText })
        : await openpgp.readSignature({ binarySignature: signatureBytes });
    } catch {
      return result('malformed-signature', safeErrorText('malformed-signature'), fields);
    }

    const signingKeyIDs = signature.getSigningKeyIDs();
    if (signingKeyIDs.length === 0) {
      return result(
        'invalid-signature',
        'The detached signature does not identify a signer',
        fields,
      );
    }
    if (signingKeyIDs.length > MAX_SIGNATURES) {
      return result('oversized-response', safeErrorText('oversized-response'), fields);
    }

    const primaryFingerprints = new Set<string>();
    const signers: ArchiveGpgSigner[] = [];
    let expiration: string | null | undefined;
    for (const keyID of signingKeyIDs) {
      const candidates = keys.flatMap((key) =>
        key.getKeys(keyID).map((signingKey) => ({ key, signingKey })),
      );
      if (candidates.length !== 1) {
        return result(
          candidates.length === 0 ? 'invalid-signature' : 'ambiguous-signer',
          candidates.length === 0
            ? safeErrorText('invalid-signature')
            : safeErrorText('ambiguous-signer'),
          fields,
        );
      }
      const candidate = candidates[0];
      if (candidate === undefined) {
        return result('invalid-signature', safeErrorText('invalid-signature'), fields);
      }

      try {
        if (await candidate.key.isRevoked(undefined, undefined, this.now, VERIFICATION_CONFIG)) {
          return result('revoked-key', safeErrorText('revoked-key'), fields);
        }
      } catch {
        return result('invalid-key', safeErrorText('invalid-key'), fields);
      }

      let primaryExpiration: Date | typeof Infinity | null;
      let signerExpiration: Date | typeof Infinity | null;
      try {
        primaryExpiration = await candidate.key.getExpirationTime(undefined, VERIFICATION_CONFIG);
        signerExpiration =
          candidate.signingKey === candidate.key
            ? primaryExpiration
            : await candidate.signingKey.getExpirationTime(this.now, VERIFICATION_CONFIG);
      } catch {
        return result('invalid-key', safeErrorText('invalid-key'), fields);
      }
      if (primaryExpiration === null || signerExpiration === null) {
        return result('invalid-key', safeErrorText('invalid-key'), fields);
      }
      const expirations = [primaryExpiration, signerExpiration]
        .filter((value): value is Date => value instanceof Date)
        .sort((left, right) => left.getTime() - right.getTime());
      if (expirations[0] !== undefined) expiration = expirations[0].toISOString();
      if (
        (primaryExpiration instanceof Date && primaryExpiration.getTime() <= this.now.getTime()) ||
        (signerExpiration instanceof Date && signerExpiration.getTime() <= this.now.getTime())
      ) {
        return result('expired-key', safeErrorText('expired-key'), {
          ...fields,
          keyExpiresAt: expiration ?? null,
        });
      }

      const primaryInfo = candidate.key.getAlgorithmInfo();
      const primaryProblem = algorithmProblem(
        primaryInfo.algorithm,
        primaryInfo.bits,
        primaryInfo.curve,
      );
      if (primaryProblem !== undefined) {
        return result(primaryProblem, safeErrorText(primaryProblem), {
          ...fields,
          keyExpiresAt: expiration ?? null,
        });
      }

      const info = candidate.signingKey.getAlgorithmInfo();
      const problem = algorithmProblem(info.algorithm, info.bits, info.curve);
      if (problem !== undefined) {
        return result(problem, safeErrorText(problem), {
          ...fields,
          keyExpiresAt: expiration ?? null,
        });
      }

      try {
        await candidate.key.verifyPrimaryKey(this.now, undefined, VERIFICATION_CONFIG);
        if ('verify' in candidate.signingKey) {
          await candidate.signingKey.verify(this.now, VERIFICATION_CONFIG);
        }
        const eligible = await candidate.key.getSigningKey(
          keyID,
          this.now,
          undefined,
          VERIFICATION_CONFIG,
        );
        if (!eligible.getKeyID().equals(keyID)) {
          return result('invalid-signature', safeErrorText('invalid-signature'), fields);
        }
      } catch (error) {
        const message = error instanceof Error ? error.message.toLowerCase() : '';
        if (message.includes('revoked')) {
          return result('revoked-key', safeErrorText('revoked-key'), fields);
        }
        if (message.includes('expired')) {
          return result('expired-key', safeErrorText('expired-key'), fields);
        }
        return result('invalid-key', safeErrorText('invalid-key'), fields);
      }

      primaryFingerprints.add(candidate.key.getFingerprint());
      signers.push({
        fingerprint: candidate.signingKey.getFingerprint(),
        primaryFingerprint: candidate.key.getFingerprint(),
        algorithm: info.algorithm,
        ...(info.bits === undefined ? {} : { keyBits: info.bits }),
      });
    }
    if (primaryFingerprints.size !== 1) {
      return result('ambiguous-signer', safeErrorText('ambiguous-signer'), {
        ...fields,
        signers,
        ...(expiration === undefined ? {} : { keyExpiresAt: expiration }),
      });
    }

    for (const packet of signature.packets) {
      if (packet.isExpired(this.now)) {
        return result('expired-signature', safeErrorText('expired-signature'), {
          ...fields,
          signers,
          ...(expiration === undefined ? {} : { keyExpiresAt: expiration }),
        });
      }
      if (packet.hashAlgorithm === null || !ALLOWED_HASHES.includes(packet.hashAlgorithm)) {
        return result(
          'unsupported-signature-algorithm',
          safeErrorText('unsupported-signature-algorithm'),
          {
            ...fields,
            signers,
            ...(expiration === undefined ? {} : { keyExpiresAt: expiration }),
          },
        );
      }
    }

    try {
      const message = await openpgp.createMessage({ binary: options.payload });
      const verification = await openpgp.verify({
        message,
        signature,
        verificationKeys: keys,
        date: this.now,
        format: 'binary',
        config: VERIFICATION_CONFIG,
      });
      const verificationResults = verification.signatures;
      if (verificationResults.length !== signingKeyIDs.length) {
        return result('invalid-signature', safeErrorText('invalid-signature'), {
          ...fields,
          signers,
          ...(expiration === undefined ? {} : { keyExpiresAt: expiration }),
        });
      }
      await Promise.all(verificationResults.map((verification) => verification.verified));
    } catch (error) {
      const message = error instanceof Error ? error.message.toLowerCase() : '';
      const status = message.includes('expired') ? 'expired-signature' : 'invalid-signature';
      return result(status, safeErrorText(status), {
        ...fields,
        signers,
        ...(expiration === undefined ? {} : { keyExpiresAt: expiration }),
      });
    }

    const primaryFingerprint = [...primaryFingerprints][0];
    const expectedFingerprint =
      options.trustedFingerprint === undefined
        ? undefined
        : normalizeFingerprint(options.trustedFingerprint);
    if (options.trustedFingerprint !== undefined && expectedFingerprint === undefined) {
      return result(
        'invalid-key',
        'The trusted fingerprint must be a 40- or 64-digit hexadecimal fingerprint',
        {
          ...fields,
          cryptographicallyValid: true,
          signers,
          ...(expiration === undefined ? {} : { keyExpiresAt: expiration }),
        },
      );
    }
    const identityTrust: ArchiveGpgIdentityTrust =
      expectedFingerprint === undefined
        ? 'unknown'
        : primaryFingerprint === expectedFingerprint
          ? 'trusted'
          : 'mismatch';
    if (identityTrust === 'mismatch') {
      return result('untrusted-key', safeErrorText('untrusted-key'), {
        ...fields,
        cryptographicallyValid: true,
        identityTrust,
        signers,
        ...(expiration === undefined ? {} : { keyExpiresAt: expiration }),
      });
    }

    return {
      ok: true,
      status: 'verified',
      cryptographicallyValid: true,
      identityTrust,
      signers,
      ...(expiration === undefined ? {} : { keyExpiresAt: expiration }),
      ...fields,
      error:
        identityTrust === 'unknown'
          ? 'Signature valid; signer identity is not independently trusted'
          : undefined,
    };
  }

  private async get(url: URL, maxBytes: number): Promise<BoundedResponse> {
    const validated = validateHttpsUrl(url.toString());
    if (this.options.fetchImpl === undefined) {
      return requestPublicHttps(validated, maxBytes, this.timeoutMs);
    }
    return readInjectedResponse(this.options.fetchImpl, validated, maxBytes, this.timeoutMs);
  }
}

export const verifyArchiveGpg = async (
  options: VerifyArchiveOptions,
  verifierOptions: ArchiveGpgVerifierOptions = {},
): Promise<ArchiveGpgVerificationResult> =>
  new ArchiveGpgVerifier(verifierOptions).verifyArchive(options);
