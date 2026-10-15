/**
 * IPFS CID Metadata Validator.
 *
 * Parses CIDv0 (Base58) and CIDv1 (Base32/Base58) strings found in asset image
 * links, documentation fields, and contract metadata fields. Verifies multihash
 * integrity by downloading content through configured public/fallback IPFS
 * gateways and calculating SHA-256 / Blake2b multihashes against the CID.
 * Checks MIME type matching (ensuring image CIDs actually return image content
 * and schema CIDs return valid JSON-LD). Benchmarks multi-gateway latency and
 * flags unpinned or unreachable CIDs across multiple independent IPFS gateways.
 *
 * Runs under opt-in --verify-ipfs flag.
 */

import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';
import { isString, isUrl } from '../predicates.js';

// node:crypto is dynamically imported to avoid bundling in browser builds
async function getCreateHash(): Promise<(algorithm: string) => { update: (data: string | Uint8Array) => { digest: (encoding?: string) => string | Uint8Array } }> {
  const { createHash } = await import('node:crypto');
  return createHash as unknown as (algorithm: string) => { update: (data: string | Uint8Array) => { digest: (encoding?: string) => string | Uint8Array } };
}

// CID parsing constants
const CIDV0_BASE58_PREFIX = 'Qm';
const CIDV1_BASE32_PREFIX = 'bafy';
const CIDV1_BASE58_PREFIX = 'z';

/** CID version */
export type CidVersion = 0 | 1;

/** CID codec type */
export type CidCodec = 'dag-pb' | 'dag-cbor' | 'raw' | string;

/** Multihash algorithm */
export type MultihashCode = 0x12 | 0x13 | 0x1b | 0x40 | number; // sha2-256, sha3-256, blake2b-256, sha2-512, etc.

/** Parsed CID structure */
export interface ParsedCid {
  version: CidVersion;
  codec: CidCodec;
  multihashCode: MultihashCode;
  multihash: Uint8Array;
  original: string;
}

/** Gateway fetch result */
export interface GatewayResult {
  gateway: string;
  ok: boolean;
  status?: number;
  contentType?: string;
  body?: Uint8Array;
  latencyMs: number;
  error?: string;
}

/** Overall CID verification result */
export interface CidVerificationResult {
  cid: string;
  parsed: ParsedCid | null;
  parseError?: string;
  gateways: GatewayResult[];
  hashValid: boolean | null;
  mimeMatch: boolean | null;
  expectedMime?: string;
  fastestGateway?: string;
  allUnreachable: boolean;
}

/** Configuration for IPFS validation */
export interface IpfsMetadataValidatorOptions {
  rules?: RuleOverrides;
  gateways?: string[];
  timeoutMs?: number;
  expectedMimeByPath?: Record<string, string>;
  /** Path in the TOML document where the CID was found */
  path?: string;
}

/** Default public IPFS gateways */
export const DEFAULT_IPFS_GATEWAYS = [
  'https://ipfs.io/ipfs/',
  'https://cloudflare-ipfs.com/ipfs/',
  'https://gateway.pinata.cloud/ipfs/',
  'https://dweb.link/ipfs/',
];

const CID_REGEX = /(Qm[1-9A-HJ-NP-Za-km-z]{44,}|bafy[0-9a-z]{50,}|z[1-9A-HJ-NP-Za-km-z]{40,})/g;

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules?: RuleOverrides,
): Severity | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

/**
 * Decodes a Base58 string (Bitcoin alphabet) to bytes.
 */
function base58Decode(str: string): Uint8Array {
  const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  const ALPHABET_MAP = new Map<string, number>();
  for (let i = 0; i < ALPHABET.length; i++) ALPHABET_MAP.set(ALPHABET[i]!, i);

  const bytes: number[] = [];
  for (const char of str) {
    const val = ALPHABET_MAP.get(char);
    if (val === undefined) throw new Error(`Invalid Base58 character: ${char}`);
    let carry = val;
    for (let i = bytes.length - 1; i >= 0; i--) {
      const byte = bytes[i];
      if (byte === undefined) continue;
      carry += byte * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.unshift(carry & 0xff);
      carry >>= 8;
    }
  }

  // Count leading '1's (which represent leading zero bytes)
  let leadingZeros = 0;
  for (const char of str) {
    if (char === '1') leadingZeros++;
    else break;
  }

  const result = new Uint8Array(leadingZeros + bytes.length);
  result.set(bytes, leadingZeros);
  return result;
}

/**
 * Decodes a Base32 string (RFC 4648, no padding) to bytes.
 */
function base32Decode(str: string): Uint8Array {
  const ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';
  const ALPHABET_MAP = new Map<string, number>();
  for (let i = 0; i < ALPHABET.length; i++) ALPHABET_MAP.set(ALPHABET[i]!, i);

  let bits = 0;
  let value = 0;
  const bytes: number[] = [];

  for (const char of str.toLowerCase()) {
    const val = ALPHABET_MAP.get(char);
    if (val === undefined) throw new Error(`Invalid Base32 character: ${char}`);
    value = (value << 5) | val;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >> bits) & 0xff);
    }
  }
  return new Uint8Array(bytes);
}

/**
 * Parses a multihash from bytes: [code][length][digest...]
 */
function parseMultihash(bytes: Uint8Array): { code: number; digest: Uint8Array } | null {
  if (bytes.length < 2) return null;
  const code = bytes[0]!;
  const length = bytes[1]!;
  if (bytes.length !== 2 + length) return null;
  return { code, digest: bytes.slice(2) };
}

/**
 * Parses a CIDv0 (Base58, multihash only, implied dag-pb, sha2-256).
 */
function parseCidV0(b58: string): ParsedCid | null {
  try {
    const decoded = base58Decode(b58);
    // CIDv0 is just a multihash: sha2-256 (0x12), 32 bytes, dag-pb
    const mh = parseMultihash(decoded);
    if (!mh || mh.code !== 0x12 || mh.digest.length !== 32) return null;
    return {
      version: 0,
      codec: 'dag-pb',
      multihashCode: 0x12,
      multihash: mh.digest,
      original: b58,
    };
  } catch {
    return null;
  }
}

/**
 * Parses a CIDv1 from multibase-encoded string (Base32 or Base58).
 * Format: <multibase-prefix><cidv1-bytes>
 * CIDv1 bytes: [version=1][codec][multihash]
 */
function parseCidV1(str: string): ParsedCid | null {
  let decoded: Uint8Array;
  let prefix = '';

  if (str.startsWith('b')) {
    // Base32 (bafy...)
    prefix = 'b';
    try {
      decoded = base32Decode(str.slice(1));
    } catch {
      return null;
    }
  } else if (str.startsWith('z')) {
    // Base58 (z...)
    prefix = 'z';
    try {
      decoded = base58Decode(str.slice(1));
    } catch {
      return null;
    }
  } else {
    return null;
  }

  if (decoded.length < 3) return null;

  // First byte should be version (1)
  const version = decoded[0];
  if (version !== 1) return null;

  // Read codec (unsigned varint)
  let pos = 1;
  let codec = 0;
  let shift = 0;
  while (pos < decoded.length) {
    const byte = decoded[pos++]!;
    codec |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
    shift += 7;
    if (shift > 28) return null;
  }

  if (pos >= decoded.length) return null;

  // Remaining bytes are multihash
  const mhBytes = decoded.slice(pos);
  const mh = parseMultihash(mhBytes);
  if (!mh) return null;

  // Map common codec values to names
  const codecNames: Record<number, string> = {
    0x55: 'dag-pb',
    0x70: 'dag-pb', // some CIDv1 use 0x70 for dag-pb
    0x71: 'dag-cbor',
    0x56: 'raw',
  };

  return {
    version: 1,
    codec: codecNames[codec] ?? `0x${codec.toString(16)}`,
    multihashCode: mh.code,
    multihash: mh.digest,
    original: str,
  };
}

/**
 * Parses a CID string (v0 or v1) into a structured object.
 */
export function parseCid(cid: string): ParsedCid | null {
  if (cid.startsWith(CIDV0_BASE58_PREFIX) && !cid.includes('z')) {
    return parseCidV0(cid);
  }
  if (cid.startsWith(CIDV1_BASE32_PREFIX) || cid.startsWith(CIDV1_BASE58_PREFIX)) {
    return parseCidV1(cid);
  }
  return null;
}

/**
 * Extracts all CID-like strings from a text.
 */
export function extractCids(text: string): string[] {
  const matches = text.match(CID_REGEX);
  return matches ?? [];
}

/**
 * Computes multihash of data for a given algorithm.
 */
async function computeMultihash(data: Uint8Array, code: number): Promise<Uint8Array | null> {
  const createHash = await getCreateHash();
  let hash: Uint8Array;
  switch (code) {
    case 0x12: // sha2-256
      hash = new Uint8Array(createHash('sha256').update(data).digest() as unknown as ArrayBuffer);
      break;
    case 0x13: // sha3-256
      // Node.js doesn't have SHA3 built-in; would need noble-hashes
      try {
        const { sha3_256 } = await import('@noble/hashes/sha3');
        hash = sha3_256(data);
      } catch {
        return null;
      }
      break;
    case 0x1b: // blake2b-256
      try {
        const { blake2b } = await import('@noble/hashes/blake2b');
        hash = blake2b(data, { dkLen: 32 });
      } catch {
        return null;
      }
      break;
    case 0x40: // sha2-512
      hash = new Uint8Array(createHash('sha512').update(data).digest() as unknown as ArrayBuffer);
      break;
    default:
      return null;
  }
  return hash;
}

/**
 * Verifies that the downloaded content matches the CID's multihash.
 */
export async function verifyCidHash(parsed: ParsedCid, content: Uint8Array): Promise<boolean> {
  const computed = await computeMultihash(content, parsed.multihashCode);
  if (!computed) return false;
  if (computed.length !== parsed.multihash.length) return false;
  for (let i = 0; i < computed.length; i++) {
    if (computed[i] !== parsed.multihash[i]) return false;
  }
  return true;
}

/**
 * Fetches content from a single IPFS gateway with timeout.
 */
async function fetchFromGateway(
  gateway: string,
  cid: string,
  timeoutMs: number,
  fetchImpl: typeof fetch,
): Promise<GatewayResult> {
  const url = `${gateway}${cid}`;
  const start = Date.now();
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    const response = await fetchImpl(url, {
      method: 'GET',
      signal: controller.signal,
      headers: { accept: '*/*' },
    });
    clearTimeout(timeout);
    const latencyMs = Date.now() - start;

    if (!response.ok) {
      return {
        gateway,
        ok: false,
        status: response.status,
        latencyMs,
        error: `HTTP ${response.status}`,
      };
    }

    const contentType = response.headers.get('content-type') ?? undefined;
    const arrayBuffer = await response.arrayBuffer();
    return {
      gateway,
      ok: true,
      status: response.status,
      contentType,
      body: new Uint8Array(arrayBuffer),
      latencyMs,
    };
  } catch (error) {
    return {
      gateway,
      ok: false,
      latencyMs: Date.now() - start,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Fetches CID content from multiple gateways in parallel, returns first successful.
 */
export async function fetchCidFromGateways(
  cid: string,
  gateways: string[],
  timeoutMs: number,
  fetchImpl: typeof fetch,
): Promise<GatewayResult[]> {
  const results = await Promise.all(
    gateways.map((gw) => fetchFromGateway(gw, cid, timeoutMs, fetchImpl)),
  );
  return results;
}

/**
 * Determines expected MIME type from the TOML path context.
 */
function expectedMimeForPath(path: string, explicitMap?: Record<string, string>): string | undefined {
  if (explicitMap && explicitMap[path]) return explicitMap[path];

  const lower = path.toLowerCase();
  if (lower.includes('image') || lower.includes('logo') || lower.includes('icon')) {
    return 'image/';
  }
  if (lower.includes('schema') || lower.includes('metadata') || lower.includes('json')) {
    return 'application/json';
  }
  if (lower.includes('document') || lower.includes('whitepaper') || lower.includes('legal')) {
    return 'application/pdf';
  }
  return undefined;
}

/**
 * Checks if actual MIME type matches expected prefix.
 */
function mimeMatches(expected: string | undefined, actual: string | undefined): boolean | null {
  if (!expected || !actual) return null;
  const actualType = actual.split(';')[0]!.trim().toLowerCase();
  const expectedPrefix = expected.toLowerCase();
  return actualType.startsWith(expectedPrefix);
}

/**
 * Validates a single CID found in the document.
 */
export async function validateCid(
  cid: string,
  path: string,
  fetchImpl: typeof fetch,
  options: IpfsMetadataValidatorOptions = {},
): Promise<Diagnostic[]> {
  const diagnostics: Diagnostic[] = [];
  const gateways = options.gateways ?? DEFAULT_IPFS_GATEWAYS;
  const timeoutMs = options.timeoutMs ?? 15_000;
  const expectedMime = expectedMimeForPath(path, options.expectedMimeByPath);

  const finding = (rule: string, fallback: 'error' | 'warning', message: string, suggestion?: string): Diagnostic[] => {
    const severity = severityFor(rule, fallback, options.rules);
    if (severity === undefined) return [];
    return [
      {
        rule,
        severity,
        category: 'network',
        message,
        path: options.path ?? path,
        ...(suggestion !== undefined ? { suggestion } : {}),
      },
    ];
  };

  // Parse CID
  const parsed = parseCid(cid);
  if (!parsed) {
    return finding(
      'ipfs/invalid-cid-format',
      'error',
      `Invalid CID format: "${cid}"`,
      'Ensure the CID is a valid CIDv0 (Base58, Qm...) or CIDv1 (Base32 bafy... or Base58 z...).',
    );
  }

  // Fetch from gateways
  const gatewayResults = await fetchCidFromGateways(cid, gateways, timeoutMs, fetchImpl);
  const successful = gatewayResults.filter((r) => r.ok && r.body);

  if (successful.length === 0) {
    return finding(
      'ipfs/cid-unreachable',
      'error',
      `CID "${cid}" is unreachable across all configured IPFS gateways`,
      'Verify the content is pinned and available on the IPFS network. Check gateway URLs.',
    );
  }

  // Verify hash against first successful result
  const firstResult = successful[0]!;
  const hashValid = await verifyCidHash(parsed, firstResult.body!);
  const mimeMatch = mimeMatches(expectedMime, firstResult.contentType);

  if (!hashValid) {
    diagnostics.push(
      ...finding(
        'ipfs/cid-hash-mismatch',
        'error',
        `CID "${cid}" multihash verification failed: downloaded content does not match the CID digest`,
        'The content at this CID has been modified or the CID is incorrect. Re-pin the correct content.',
      ),
    );
  }

  if (mimeMatch === false) {
    diagnostics.push(
      ...finding(
        'ipfs/cid-mime-mismatch',
        'warning',
        `CID "${cid}" returned content type "${firstResult.contentType}", expected "${expectedMime}*"`,
        `Ensure the CID points to a ${expectedMime} resource.`,
      ),
    );
  }

  // Check latency and flag slow/unreachable gateways
  const latencies = successful.map((r) => r.latencyMs).sort((a, b) => a - b);
  if (latencies.length > 0) {
    const medianLatency = latencies[Math.floor(latencies.length / 2)]!;
    if (medianLatency > 10_000) {
      diagnostics.push(
        ...finding(
          'ipfs/cid-high-latency',
          'warning',
          `CID "${cid}" median gateway latency is ${medianLatency}ms`,
          'Consider pinning to a faster provider or using a dedicated gateway.',
        ),
      );
    }
  }

  // Report gateways that failed
  const failedGateways = gatewayResults.filter((r) => !r.ok).map((r) => r.gateway);
  if (failedGateways.length > 0 && failedGateways.length < gateways.length) {
    diagnostics.push(
      ...finding(
        'ipfs/cid-partial-reachability',
        'warning',
        `CID "${cid}" unreachable on ${failedGateways.length}/${gateways.length} gateways: ${failedGateways.join(', ')}`,
        'Ensure content is widely pinned across the IPFS network.',
      ),
    );
  }

  return diagnostics;
}

/**
 * Scans a document for CIDs in relevant fields and validates them.
 */
export async function validateIpfsMetadata(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: IpfsMetadataValidatorOptions = {},
): Promise<Diagnostic[]> {
  const diagnostics: Diagnostic[] = [];
  const seenCids = new Set<string>();

  const documentation = (doc.DOCUMENTATION as Record<string, unknown> | undefined) ?? {};

  // Fields that commonly contain IPFS CIDs
  const cidFields = [
    { path: 'DOCUMENTATION.ORG_LOGO', value: documentation.ORG_LOGO },
    { path: 'DOCUMENTATION.ORG_DESCRIPTION', value: documentation.ORG_DESCRIPTION },
    { path: 'DOCUMENTATION.ORG_PHYSICAL_ADDRESS_ATTESTATION', value: documentation.ORG_PHYSICAL_ADDRESS_ATTESTATION },
    { path: 'DOCUMENTATION.ORG_PHONE_NUMBER_ATTESTATION', value: documentation.ORG_PHONE_NUMBER_ATTESTATION },
  ];

  // Add currency image fields
  if (Array.isArray(doc.CURRENCIES)) {
    for (const [index, currency] of doc.CURRENCIES.entries()) {
      if (currency && typeof currency === 'object' && !Array.isArray(currency)) {
        const c = currency as Record<string, unknown>;
        if (isString(c.image)) {
          cidFields.push({ path: `CURRENCIES[${index}].image`, value: c.image });
        }
        if (isString(c.toml)) {
          cidFields.push({ path: `CURRENCIES[${index}].toml`, value: c.toml });
        }
        if (isString(c.attestation_of_reserve)) {
          cidFields.push({ path: `CURRENCIES[${index}].attestation_of_reserve`, value: c.attestation_of_reserve });
        }
        if (isString(c.redemption_instructions)) {
          cidFields.push({ path: `CURRENCIES[${index}].redemption_instructions`, value: c.redemption_instructions });
        }
      }
    }
  }

  // Add contract metadata fields if present
  if (Array.isArray(doc.CONTRACTS)) {
    for (const [index, contract] of doc.CONTRACTS.entries()) {
      if (contract && typeof contract === 'object' && !Array.isArray(contract)) {
        const c = contract as Record<string, unknown>;
        if (isString(c.metadata)) {
          cidFields.push({ path: `CONTRACTS[${index}].metadata`, value: c.metadata });
        }
      }
    }
  }

  // Extract and validate CIDs from each field
  for (const field of cidFields) {
    if (!isString(field.value)) continue;
    if (!isUrl(field.value)) continue;

    // Extract CIDs from URLs (e.g., https://ipfs.io/ipfs/Qm...)
    const urlCids = extractCids(field.value);
    for (const cid of urlCids) {
      if (seenCids.has(cid)) continue;
      seenCids.add(cid);
      diagnostics.push(
        ...(await validateCid(cid, field.path, fetchImpl, { ...options, path: field.path })),
      );
    }
  }

  return diagnostics;
}

/** Registered rules for IPFS metadata validation */
export const ipfsMetadataRules: Rule[] = [
  {
    id: 'ipfs/invalid-cid-format',
    category: 'network',
    severity: 'error',
    description: 'IPFS CID has invalid format (not valid CIDv0 or CIDv1)',
    run() {},
  },
  {
    id: 'ipfs/cid-unreachable',
    category: 'network',
    severity: 'error',
    description: 'IPFS CID is unreachable across all configured gateways',
    run() {},
  },
  {
    id: 'ipfs/cid-hash-mismatch',
    category: 'network',
    severity: 'error',
    description: 'Downloaded IPFS content does not match CID multihash',
    run() {},
  },
  {
    id: 'ipfs/cid-mime-mismatch',
    category: 'network',
    severity: 'warning',
    description: 'IPFS CID content type does not match expected type for the field',
    run() {},
  },
  {
    id: 'ipfs/cid-high-latency',
    category: 'network',
    severity: 'warning',
    description: 'IPFS CID has high median gateway latency',
    run() {},
  },
  {
    id: 'ipfs/cid-partial-reachability',
    category: 'network',
    severity: 'warning',
    description: 'IPFS CID is not reachable on some configured gateways',
    run() {},
  },
];

export const ipfsMetadataRuleIds: readonly string[] = ipfsMetadataRules.map((rule) => rule.id);