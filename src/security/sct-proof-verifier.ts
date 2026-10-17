/**
 * TLS Certificate Transparency (CT) Signed Certificate Timestamp (SCT)
 * inclusion-proof verifier.
 *
 * Modern browsers require certificates for public hosts to carry Signed
 * Certificate Timestamps — proof that the certificate was submitted to one or
 * more public CT logs — either embedded in the certificate (extension
 * 1.3.6.1.4.1.11129.2.4.2) or stapled in the TLS handshake. An anchor that
 * handles financial traffic and serves a certificate without that proof is
 * trusting whatever internal CA signed it; a rogue or compromised CA can mint
 * a certificate for the anchor's domain and no log records it. The audit
 * parses the peer certificate's extensions, decodes the RFC 6962
 * `SignedCertificateTimestampList`, and checks that the SCTs name logs run by
 * the operators the ecosystem trusts.
 *
 * Runs under opt-in `--check-network --audit-security`, and only observes what
 * the TLS handshake actually served: a host that cannot be reached, or a
 * certificate that cannot be read, is skipped rather than guessed at.
 */
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isString } from '../predicates.js';

/** The X.509 extension that carries a certificate's embedded SCT list. */
export const SCT_EXTENSION_OID = '1.3.6.1.4.1.11129.2.4.2';

export const SECURITY_MISSING_EMBEDDED_SCT = 'security/missing-embedded-sct';
export const SECURITY_UNTRUSTED_CT_LOG_SIGNATURE = 'security/untrusted-ct-log-signature';

/** RFC 6962 `Version` for an SCT: v1 is the only version in use. */
const SCT_VERSION_V1 = 0;

/** RFC 6962 `SignatureAndHashAlgorithm`: hash 4 is SHA-256. */
const HASH_SHA256 = 4;
/** RFC 6962 signature algorithm 1 (RSA) and 3 (ECDSA). */
const SIGNATURE_RSA = 1;
const SIGNATURE_ECDSA = 3;

export interface CtLogOperator {
  /** Human-readable operator, e.g. `Google`. */
  operator: string;
  /** Log id: the SHA-256 of the log's public key, as lowercase hex. */
  logId: string;
  /** Log description, e.g. `Google Argon2026h2`. */
  description?: string;
}

/**
 * Public CT logs run by the three operators a browser will accept an SCT from.
 *
 * Log ids are the SHA-256 of the log's public key, taken from the Chrome CT log
 * list (`https://www.gstatic.com/ct/log_list/v3/log_list.json`). A certificate
 * whose SCTs name none of these logs cannot be relied on by a browser, which is
 * what {@link verifySctProof} reports.
 */
export const CT_LOG_OPERATORS: readonly CtLogOperator[] = [
  {
    operator: 'Google',
    description: 'Google Argon2026h2',
    logId: 'd76d7d10d1a7f577c2c7e95fd700bff982c9335a65e1d0b3017317c0c8c56977',
  },
  {
    operator: 'Google',
    description: 'Google Argon2027h1',
    logId: 'd6d58da9d01753f36a4aa0c7574902afebc7dc2cd38cd9f764c80c89191e9f02',
  },
  {
    operator: 'Google',
    description: 'Google Xenon2026h2',
    logId: 'd809553b944f7affc816196f944f85abb0f8fc5e8755260f15d12e72bb454b14',
  },
  {
    operator: 'Google',
    description: 'Google Xenon2027h1',
    logId: '44c2bd0ce9140e64a5c94a01930a5aa1bb35970e00ee111689682a1c44d7b566',
  },
  {
    operator: 'Cloudflare',
    description: 'Cloudflare Nimbus2026',
    logId: 'cb38f715897c84a1445f5bc1ddfbc96ef29a59cd470a690585b0cb14c31458e7',
  },
  {
    operator: 'Cloudflare',
    description: 'Cloudflare Nimbus2027',
    logId: '4c63dc98e59c1dab88f61e8a3ddeae8fab44a3377b5f9b94c3fba19cfcc1be26',
  },
  {
    operator: 'DigiCert',
    description: 'DigiCert Wyvern2026h2',
    logId: 'c2317e574519a345ee7f38deb29041ebc7c2215a22bf7fd5b5ad769ad90e52cd',
  },
  {
    operator: 'DigiCert',
    description: 'DigiCert Wyvern2027h1',
    logId: '001a5d1a1c2d9375b6485578f82f71a1ae6eef397d297c8ae3157bcadee1a01e',
  },
  {
    operator: 'DigiCert',
    description: 'DigiCert Wyvern2027h2',
    logId: '37aa07cc216f2e6d919c709d24d8f731b00f2b147c621cc091a5fa1a84d816dd',
  },
  {
    operator: 'DigiCert',
    description: 'DigiCert Sphinx2026h2',
    logId: '944e4387faecc1ef81f3192426a8186501c7d35f3802013f72677d55372e19d8',
  },
  {
    operator: 'DigiCert',
    description: 'DigiCert Sphinx2027h1',
    logId: '46a23967c60db64687c66f3df999947693a6a611208457d555e7e3d0a1d9b646',
  },
  {
    operator: 'DigiCert',
    description: 'DigiCert Sphinx2027h2',
    logId: '1fb0f8a92d8adda121776c05e2aa2e15bacbc62b65393695576aaab52e11d11d',
  },
];

/** One decoded SCT, as RFC 6962 §3.2 serialises it. */
export interface SctEntry {
  version: number;
  /** Log id as lowercase hex. */
  logId: string;
  /** SCT timestamp, in milliseconds since the Unix epoch. */
  timestamp: number;
  hashAlgorithm: number;
  signatureAlgorithm: number;
  /** Signature bytes, empty when the entry was truncated. */
  signature: Uint8Array;
  extensions: Uint8Array;
}

/** A single DER TLV header, with the byte ranges that matter. */
interface Tlv {
  tag: number;
  /** Offset of the content (right after the header). */
  contentStart: number;
  /** Length of the content. */
  length: number;
  /** Offset of the next TLV. */
  next: number;
}

function readTlv(bytes: Uint8Array, offset: number): Tlv | undefined {
  if (offset + 2 > bytes.length) return undefined;
  const tag = bytes[offset] as number;
  let length = bytes[offset + 1] as number;
  let header = 2;

  if ((length & 0x80) !== 0) {
    const count = length & 0x7f;
    // 0 means indefinite length (illegal in DER); more than 4 bytes cannot fit
    // in a JavaScript bitwise integer.
    if (count === 0 || count > 4) return undefined;
    if (offset + 2 + count > bytes.length) return undefined;
    length = 0;
    for (let index = 0; index < count; index++) {
      length = (length << 8) | (bytes[offset + 2 + index] as number);
    }
    header = 2 + count;
  }

  const contentStart = offset + header;
  const next = contentStart + length;
  if (next > bytes.length) return undefined;
  return { tag, contentStart, length, next };
}

function isConstructed(tag: number): boolean {
  return (tag & 0x20) !== 0;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index++) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

/** The DER encoding of an OID, without the tag or length header. */
export function encodeOid(oid: string): Uint8Array {
  const parts = oid.split('.').map((part) => Number(part));
  if (parts.length < 2 || parts.some((part) => !Number.isInteger(part) || part < 0)) {
    throw new Error(`Not an OID: ${oid}`);
  }
  const first = parts[0] as number;
  const second = parts[1] as number;
  const bytes: number[] = [first * 40 + second];

  for (const part of parts.slice(2)) {
    const encoded: number[] = [];
    let value = part;
    do {
      encoded.unshift(value & 0x7f);
      value = Math.floor(value / 128);
    } while (value > 0);
    for (let index = 0; index < encoded.length - 1; index++) {
      encoded[index] = (encoded[index] as number) | 0x80;
    }
    bytes.push(...encoded);
  }
  return Uint8Array.from(bytes);
}

/**
 * Recursively walks a DER tree looking for the extension `oid` and returning
 * the contents of its `extnValue` OCTET STRING.
 *
 * The walk descends into every constructed value rather than assuming a fixed
 * certificate layout, so it keeps working across the alternative encodings
 * different CAs emit for the same extension.
 */
function findExtensionValue(
  bytes: Uint8Array,
  start: number,
  end: number,
  oid: Uint8Array,
): Uint8Array | undefined {
  let offset = start;
  while (offset < end) {
    const tlv = readTlv(bytes, offset);
    if (tlv === undefined || tlv.next > end) return undefined;

    if (tlv.tag === 0x06) {
      const value = bytes.subarray(tlv.contentStart, tlv.next);
      if (bytesEqual(value, oid)) {
        // The extension is `SEQUENCE { OID, BOOLEAN critical DEFAULT FALSE,
        // OCTET STRING extnValue }`; a critical boolean may sit in between.
        let cursor = tlv.next;
        while (cursor < end) {
          const sibling = readTlv(bytes, cursor);
          if (sibling === undefined || sibling.next > end) return undefined;
          if (sibling.tag === 0x04) {
            return bytes.subarray(sibling.contentStart, sibling.next);
          }
          if (sibling.tag === 0x01 || sibling.tag === 0x05) {
            cursor = sibling.next;
            continue;
          }
          return undefined;
        }
        return undefined;
      }
    }

    if (isConstructed(tlv.tag)) {
      const found = findExtensionValue(bytes, tlv.contentStart, tlv.next, oid);
      if (found !== undefined) return found;
    }
    offset = tlv.next;
  }
  return undefined;
}

/**
 * The `SignedCertificateTimestampList` embedded in a DER certificate, or
 * `undefined` when the certificate does not carry the CT extension.
 */
export function extractEmbeddedSctList(certificateDer: Uint8Array): Uint8Array | undefined {
  const raw = findExtensionValue(
    certificateDer,
    0,
    certificateDer.length,
    encodeOid(SCT_EXTENSION_OID),
  );
  if (raw === undefined) return undefined;

  // The extension value is the TLS-serialized list. Some encoders wrap it one
  // more time in an OCTET STRING, which is still unambiguous: a list always
  // starts with a two-byte length, and 0x04 is not a valid first length byte
  // for the lists these CAs publish.
  if (raw.length > 2 && raw[0] === 0x04) {
    const innerLength = raw[1] as number;
    if (innerLength < 0x80 && 2 + innerLength === raw.length) {
      return raw.subarray(2);
    }
  }
  return raw;
}

function readUint16(bytes: Uint8Array, offset: number): number {
  return ((bytes[offset] as number) << 8) | (bytes[offset + 1] as number);
}

function readUint64(bytes: Uint8Array, offset: number): number {
  let value = 0;
  for (let index = 0; index < 8; index++) {
    value = value * 256 + (bytes[offset + index] as number);
  }
  return value;
}

function toHex(bytes: Uint8Array): string {
  let hex = '';
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0');
  return hex;
}

/**
 * Decodes the RFC 6962 `SignedCertificateTimestampList`.
 *
 * Returns `undefined` when the bytes are not a well-formed list: a truncated
 * length prefix, an entry that overruns its own frames, or an SCT shorter than
 * its fixed 43-byte head. A list of zero SCTs is a valid empty array, which the
 * caller treats as "no usable proof".
 */
export function decodeSctList(bytes: Uint8Array): SctEntry[] | undefined {
  if (bytes.length < 2) return undefined;
  const listLength = readUint16(bytes, 0);
  if (listLength > bytes.length - 2) return undefined;

  const entries: SctEntry[] = [];
  let offset = 2;
  const end = 2 + listLength;
  while (offset < end) {
    if (offset + 2 > end) return undefined;
    const entryLength = readUint16(bytes, offset);
    offset += 2;
    if (offset + entryLength > end) return undefined;
    const entry = bytes.subarray(offset, offset + entryLength);
    offset += entryLength;

    // Fixed head: version(1) + log id(32) + timestamp(8) + extensions length(2).
    if (entry.length < 43) return undefined;
    const version = entry[0] as number;
    const logId = toHex(entry.subarray(1, 33));
    const timestamp = readUint64(entry, 33);
    const extensionsLength = readUint16(entry, 41);
    const signatureStart = 43 + extensionsLength;
    if (signatureStart + 4 > entry.length) return undefined;
    const extensions = entry.subarray(43, signatureStart);
    const hashAlgorithm = entry[signatureStart] as number;
    const signatureAlgorithm = entry[signatureStart + 1] as number;
    const signatureLength = readUint16(entry, signatureStart + 2);
    const signatureEnd = signatureStart + 4 + signatureLength;
    if (signatureEnd > entry.length) return undefined;

    entries.push({
      version,
      logId,
      timestamp,
      hashAlgorithm,
      signatureAlgorithm,
      signature: entry.subarray(signatureStart + 4, signatureEnd),
      extensions,
    });
  }
  return entries;
}

export interface SctVerifyOptions {
  rules?: RuleOverrides;
  /** The field or host the certificate came from, attached to a finding. */
  path?: string;
  /** Overrides the built-in operator registry, for tests and private logs. */
  knownLogs?: readonly CtLogOperator[];
}

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules?: RuleOverrides,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

/**
 * Audits one certificate's embedded SCT list.
 *
 * Three outcomes, each its own finding:
 * - no CT extension at all → `security/missing-embedded-sct` (warning)
 * - an extension that does not decode → `security/untrusted-ct-log-signature`
 * - an SCT naming a log outside the trusted operators, or a signature whose
 *   structure is not a recognised hash/algorithm pair → the same error
 *
 * A certificate that carries at least one well-formed SCT from a recognised
 * operator is clean.
 */
export function verifySctProof(
  certificateDer: Uint8Array | string,
  options: SctVerifyOptions = {},
): Diagnostic[] {
  const der =
    typeof certificateDer === 'string' ? Buffer.from(certificateDer, 'base64') : certificateDer;

  const missingSeverity = severityFor(SECURITY_MISSING_EMBEDDED_SCT, 'warning', options.rules);
  const untrustedSeverity = severityFor(
    SECURITY_UNTRUSTED_CT_LOG_SIGNATURE,
    'error',
    options.rules,
  );
  if (missingSeverity === undefined && untrustedSeverity === undefined) return [];

  const path = options.path;
  const finding = (
    rule: string,
    severity: 'error' | 'warning',
    message: string,
    suggestion: string,
  ): Diagnostic => ({
    rule,
    severity,
    category: 'network',
    message,
    ...(path === undefined ? {} : { path }),
    helpUri: 'https://datatracker.ietf.org/doc/html/rfc6962',
    suggestion,
  });

  const extension = extractEmbeddedSctList(der);
  if (extension === undefined) {
    return missingSeverity === undefined
      ? []
      : [
          finding(
            SECURITY_MISSING_EMBEDDED_SCT,
            missingSeverity,
            'TLS certificate carries no embedded Signed Certificate Timestamp list',
            'Obtain the certificate from a CA that logs to public CT logs, or staple an SCT over OCSP.',
          ),
        ];
  }

  const entries = decodeSctList(extension);
  if (entries === undefined || entries.length === 0) {
    return untrustedSeverity === undefined
      ? []
      : [
          finding(
            SECURITY_UNTRUSTED_CT_LOG_SIGNATURE,
            untrustedSeverity,
            'TLS certificate embeds a malformed Signed Certificate Timestamp list',
            'Reissue the certificate — a list no client can parse is not proof of logging.',
          ),
        ];
  }

  const registry = new Map<string, CtLogOperator>();
  for (const log of options.knownLogs ?? CT_LOG_OPERATORS) {
    registry.set(log.logId.toLowerCase(), log);
  }

  const trusted = entries.filter((entry) => {
    const log = registry.get(entry.logId);
    if (log === undefined) return false;
    if (entry.version !== SCT_VERSION_V1) return false;
    const hashOk = entry.hashAlgorithm === HASH_SHA256;
    const signatureOk =
      entry.signatureAlgorithm === SIGNATURE_RSA || entry.signatureAlgorithm === SIGNATURE_ECDSA;
    return hashOk && signatureOk && entry.signature.length > 0;
  });

  if (trusted.length === 0) {
    if (untrustedSeverity === undefined) return [];
    const named = [...new Set(entries.map((entry) => entry.logId.slice(0, 16)))];
    return [
      finding(
        SECURITY_UNTRUSTED_CT_LOG_SIGNATURE,
        untrustedSeverity,
        `TLS certificate is logged only to unrecognised Certificate Transparency logs (${named.join(', ')})`,
        'Use a CA that submits to the public CT logs browsers trust (Google, Cloudflare, DigiCert).',
      ),
    ];
  }

  // At least one well-formed SCT from a recognised operator is proof of
  // logging; how many operators signed it is informational, not a finding.
  return [];
}

/** Opens a TLS connection and returns the peer certificate's DER bytes. */
export type SctCertificateProbe = (host: string, port: number) => Promise<Uint8Array | null>;

/** How long to wait for a handshake before abandoning the audit. */
const PROBE_TIMEOUT_MS = 5_000;

/**
 * The default probe: one short handshake per host, reading the leaf
 * certificate's DER off the peer.
 *
 * `node:tls` is loaded lazily for the same reason `tls.ts` does it: this module
 * sits in the rule registry the browser bundle walks, and a static import would
 * drag a Node built-in into every browser build.
 */
const handshakeProbe: SctCertificateProbe = async (host, port) => {
  const tls = await import('node:tls').catch(() => null);
  if (tls === null) return null;

  return new Promise((resolve) => {
    let settled = false;
    const socket = tls.connect({ host, port, servername: host });

    const settle = (value: Uint8Array | null): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(value);
    };

    socket.setTimeout(PROBE_TIMEOUT_MS);
    socket.once('secureConnect', () => {
      const certificate = socket.getPeerCertificate();
      const raw = certificate?.raw;
      settle(raw !== undefined && raw.length > 0 ? new Uint8Array(raw) : null);
    });
    socket.once('timeout', () => settle(null));
    socket.once('error', () => settle(null));
  });
};

export interface SctAuditOptions extends SctVerifyOptions {
  /** Extra hosts to probe, usually the domain under audit. */
  hosts?: readonly string[];
  probe?: SctCertificateProbe;
}

/**
 * Probes every HTTPS host the file declares (and any the caller names) and
 * audits the SCT list of each peer certificate.
 *
 * Findings are keyed by host so a maintainer knows which certificate to
 * replace. Hosts sharing a name are probed once, and an unobservable
 * certificate is skipped rather than reported — reachability is the fetch's
 * concern, not this audit's.
 */
export async function checkSctProof(
  doc: Record<string, unknown>,
  options: SctAuditOptions = {},
): Promise<Diagnostic[]> {
  const missingSeverity = severityFor(SECURITY_MISSING_EMBEDDED_SCT, 'warning', options.rules);
  const untrustedSeverity = severityFor(
    SECURITY_UNTRUSTED_CT_LOG_SIGNATURE,
    'error',
    options.rules,
  );
  if (missingSeverity === undefined && untrustedSeverity === undefined) return [];

  const hosts = new Set<string>();
  for (const host of options.hosts ?? []) if (isString(host) && host !== '') hosts.add(host);
  for (const host of declaredHttpsHosts(doc)) hosts.add(host);
  if (hosts.size === 0) return [];

  const probe = options.probe ?? handshakeProbe;
  const diagnostics: Diagnostic[] = [];

  for (const host of hosts) {
    let certificate: Uint8Array | null;
    try {
      certificate = await probe(host, 443);
    } catch {
      continue;
    }
    if (certificate === null) continue;

    diagnostics.push(
      ...verifySctProof(certificate, {
        ...options,
        path: host,
      }),
    );
  }

  return diagnostics;
}

/** The hosts of every declared `https://` endpoint, deduplicated. */
function declaredHttpsHosts(doc: Record<string, unknown>): string[] {
  const hosts = new Set<string>();

  const consider = (value: unknown): void => {
    if (!isString(value)) return;
    try {
      const url = new URL(value);
      if (url.protocol === 'https:') hosts.add(url.hostname);
    } catch {
      // Not a URL; the offline rules report that with a position.
    }
  };

  for (const [field, value] of Object.entries(doc)) {
    if (
      typeof value === 'string' &&
      (field.endsWith('_SERVER') || field.endsWith('_URL') || field.endsWith('_ENDPOINT'))
    ) {
      consider(value);
    }
  }

  const documentation = doc.DOCUMENTATION;
  if (
    typeof documentation === 'object' &&
    documentation !== null &&
    !Array.isArray(documentation)
  ) {
    consider((documentation as Record<string, unknown>).ORG_URL);
  }

  return [...hosts];
}

/** The SCT verifier's rules, registered so the CLI can address them by id. */
export const sctProofRules: Rule[] = [
  {
    id: SECURITY_MISSING_EMBEDDED_SCT,
    category: 'network',
    severity: 'warning',
    description: 'A TLS certificate should embed a Signed Certificate Timestamp list',
    run() {},
  },
  {
    id: SECURITY_UNTRUSTED_CT_LOG_SIGNATURE,
    category: 'network',
    severity: 'error',
    description:
      'Embedded SCTs must name logs run by recognised Certificate Transparency operators',
    run() {},
  },
];

/** Rule ids emitted by {@link checkSctProof} and {@link verifySctProof}. */
export const sctProofRuleIds: readonly string[] = sctProofRules.map((rule) => rule.id);
