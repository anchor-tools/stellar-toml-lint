/**
 * Overlay authentication handshake and ChaCha20-Poly1305 cipher state
 * verifier (issue #311).
 *
 * `--verify-overlay` already proves who answers on a published `HOST`: the
 * handshake in `./handshake.ts` reads the peer's `HELLO`, verifies its
 * `AuthCert`, and trades one HMAC-authenticated `AUTH`. What it does not do is
 * carry the session past that point. A node whose key schedule is broken, or
 * whose sequence counters drift, still sends a perfectly good `HELLO` — the
 * failure only shows once frames start flowing under the derived keys, as
 * dropped connections or frames a peer cannot tell from a replay.
 *
 * This module drives that next stage against each `[[VALIDATORS]]` entry:
 *
 * 1. the authenticated Curve25519 session handshake — our `HELLO` with a fresh
 *    signed `AuthCert`, the peer's `HELLO`, and verification that its cert is
 *    signed by the node ID it announces and has not expired;
 * 2. HKDF-SHA256 key derivation — HKDF-Extract over the X25519 secret and both
 *    announced keys (the same extract step `deriveSharedMacKey` performs), then
 *    HKDF-Expand into one ChaCha20-Poly1305 key per direction, bound to both
 *    `HELLO` nonces so no two sessions ever share a key;
 * 3. one authenticated `PEERS` (peer-address) request frame, sealed under our
 *    send key at sequence 0;
 * 4. decryption and Poly1305 tag verification of the peer's response under
 *    our receive key at the sequence we expect next.
 *
 * Each sealed frame keeps the `AuthenticatedMessage` header shape — a 4-byte
 * version and an 8-byte sequence — followed by the ciphertext and a 16-byte
 * tag. The header is the AEAD's associated data and the 96-bit nonce is the
 * sequence, so a replayed or out-of-order frame fails authentication exactly
 * like a tampered one: the receiver decrypts at the sequence *it* expects.
 *
 * A broken step 1 emits `overlay/cipher-negotiation-failed`; a response whose
 * tag does not verify emits `overlay/mac-tag-mismatch`. A peer that never
 * engages with the sealed probe — it answers in the plaintext HMAC overlay,
 * closes the socket, or stays silent — is classified `unsupported` and not
 * reported: reachability is `overlay/handshake-timeout`'s business, and a node
 * that does not speak this framing has not mis-negotiated it.
 *
 * The socket and the AEAD both need Node built-ins, so they are imported
 * lazily; the browser bundle never loads `node:net` or `node:crypto`. Nothing
 * here runs unless `--check-network --verify-overlay` both appear.
 */
import { xdr } from '@stellar/stellar-base';
import { expand } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';
import { isString } from '../predicates.js';
import { OVERLAY_MAX_FRAME_BYTES } from './crawler.js';
import {
  OVERLAY_HANDSHAKE_TIMEOUT_MS,
  OVERLAY_PROTOCOL_VERSION,
  decodeAuthenticatedMessage,
  decodeStellarMessage,
  deriveSharedMacKey,
  encodeAuthenticatedMessage,
  encodeHello,
  encodeOverlayFrame,
  generateEphemeralIdentity,
  networkIdForPassphrase,
  overlayFrameLength,
  sharedSecret,
  signedAuthCert,
  validatorEndpoints,
  verifyAuthCert,
  type OverlayPeerRole,
  type ValidatorEndpoint,
} from './handshake.js';

export const OVERLAY_CIPHER_NEGOTIATION_FAILED_RULE = 'overlay/cipher-negotiation-failed';
export const OVERLAY_MAC_TAG_MISMATCH_RULE = 'overlay/mac-tag-mismatch';
export const CIPHER_NEGOTIATION_FAILED_RULE = OVERLAY_CIPHER_NEGOTIATION_FAILED_RULE;
export const MAC_TAG_MISMATCH_RULE = OVERLAY_MAC_TAG_MISMATCH_RULE;

export const CHACHA20_POLY1305_KEY_BYTES = 32;
export const CHACHA20_POLY1305_NONCE_BYTES = 12;
export const POLY1305_TAG_BYTES = 16;

/** Bytes of a sealed frame before its ciphertext: version (4) + sequence (8). */
export const SEALED_FRAME_HEADER_BYTES = 12;

/** HKDF-Expand labels, one per direction, so the two keys never coincide. */
const INITIATOR_TO_RESPONDER = 'stellar-overlay chacha20-poly1305 initiator->responder';
const RESPONDER_TO_INITIATOR = 'stellar-overlay chacha20-poly1305 responder->initiator';

const OVERLAY_HELP_URI =
  'https://developers.stellar.org/docs/learn/networks-and-topology/overlay-network';

/**
 * The ledger protocol our `HELLO` announces; informational, as in the plain
 * handshake.
 */
const LEDGER_PROTOCOL_VERSION = 29;

/** A peer may not send more than this before either side holds a key. */
const MAX_UNAUTHENTICATED_FRAME_BYTES = 0x1000;

/** One duplex overlay connection: whole frame payloads in, whole payloads out. */
export interface CipherChannel {
  /** Sends one frame payload; the channel adds the length header. */
  send(payload: Uint8Array): Promise<void>;
  /** The next frame payload, or a rejection when the peer closes or times out. */
  receive(): Promise<Uint8Array>;
  close(): void;
}

/** Opens a channel to one endpoint, or rejects when it cannot be dialled. */
export type CipherChannelFactory = (
  endpoint: ValidatorEndpoint,
  options: { timeoutMs: number },
) => Promise<CipherChannel>;

export interface CipherVerifierOptions {
  rules?: RuleOverrides;
  /** The network the session's certs are bound to. */
  passphrase?: string;
  timeoutMs?: number;
  overlayVersion?: number;
  /** Replaces the TCP transport; tests play the peer themselves. */
  channelFactory?: CipherChannelFactory;
  /** Clock in seconds, for cert expiry. */
  now?: () => number;
}

/**
 * What the session with one peer came to. `unsupported` and `unreachable` are
 * deliberately not findings; see the module comment.
 */
export type CipherOutcome =
  | { status: 'verified'; responseType: string }
  | { status: 'negotiation-failed'; detail: string }
  | { status: 'mac-mismatch'; detail: string }
  | { status: 'unsupported'; detail: string }
  | { status: 'unreachable'; detail: string };

/** The two directional ChaCha20-Poly1305 keys one side of a session holds. */
export interface CipherKeys {
  send: Buffer;
  receive: Buffer;
}

/**
 * Derives the session's ChaCha20-Poly1305 keys from the X25519 secret, both
 * announced Curve25519 keys, and both `HELLO` nonces. Each side calls this
 * with its own role and the mirror is exact: the initiator's `send` is the
 * responder's `receive`.
 */
export function deriveCipherKeys(input: {
  dhSecret: Uint8Array;
  initiatorCurvePublic: Uint8Array;
  responderCurvePublic: Uint8Array;
  initiatorNonce: Uint8Array;
  responderNonce: Uint8Array;
  role: OverlayPeerRole;
}): CipherKeys {
  const prk = deriveSharedMacKey(
    input.dhSecret,
    input.initiatorCurvePublic,
    input.responderCurvePublic,
  );
  const directional = (label: string): Buffer =>
    Buffer.from(
      expand(
        sha256,
        prk,
        Buffer.concat([
          Buffer.from(label, 'utf8'),
          Buffer.from(input.initiatorNonce),
          Buffer.from(input.responderNonce),
        ]),
        CHACHA20_POLY1305_KEY_BYTES,
      ),
    );
  const outbound = directional(INITIATOR_TO_RESPONDER);
  const inbound = directional(RESPONDER_TO_INITIATOR);
  return input.role === 'initiator'
    ? { send: outbound, receive: inbound }
    : { send: inbound, receive: outbound };
}

/** The 96-bit AEAD nonce for a sequence: four zero bytes, then the sequence. */
export function cipherNonce(sequence: bigint): Buffer {
  const nonce = Buffer.alloc(CHACHA20_POLY1305_NONCE_BYTES);
  nonce.writeBigUInt64BE(sequence, 4);
  return nonce;
}

function sealedHeader(sequence: bigint): Buffer {
  const header = Buffer.alloc(SEALED_FRAME_HEADER_BYTES);
  header.writeUInt32BE(0, 0);
  header.writeBigUInt64BE(sequence, 4);
  return header;
}

/** Loaded lazily so browser bundles never pull in `node:crypto`. */
// The return type is inferred: a static `node:` type import would put the
// built-in in the browser graph's import scan.
async function nodeCrypto() {
  return import('node:crypto');
}

/**
 * Seals one `StellarMessage` under `key` at `sequence`: the header, the
 * ChaCha20 ciphertext, and the Poly1305 tag over both.
 */
export async function sealFrame(
  key: Uint8Array,
  sequence: bigint,
  message: Uint8Array,
): Promise<Buffer> {
  const { createCipheriv } = await nodeCrypto();
  const header = sealedHeader(sequence);
  const cipher = createCipheriv('chacha20-poly1305', Buffer.from(key), cipherNonce(sequence), {
    authTagLength: POLY1305_TAG_BYTES,
  });
  cipher.setAAD(header, { plaintextLength: message.length });
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(message)), cipher.final()]);
  return Buffer.concat([header, ciphertext, cipher.getAuthTag()]);
}

/** The result of opening one sealed frame. */
export type OpenedFrame =
  { ok: true; message: Buffer } | { ok: false; reason: 'malformed' | 'tag'; detail: string };

/**
 * Opens a sealed frame at the sequence the receiver expects. The sequence the
 * frame claims is never trusted: a replayed or out-of-order frame is
 * authenticated against the expected one and fails the tag check.
 */
export async function openFrame(
  key: Uint8Array,
  expectedSequence: bigint,
  frame: Uint8Array,
): Promise<OpenedFrame> {
  const bytes = Buffer.from(frame);
  if (bytes.length < SEALED_FRAME_HEADER_BYTES + POLY1305_TAG_BYTES) {
    return {
      ok: false,
      reason: 'malformed',
      detail: `${bytes.length}-byte frame is too short to carry a Poly1305 tag`,
    };
  }
  if (bytes.readUInt32BE(0) !== 0) {
    return { ok: false, reason: 'malformed', detail: 'frame has an unknown envelope version' };
  }
  const claimed = bytes.readBigUInt64BE(4);
  const ciphertext = bytes.subarray(SEALED_FRAME_HEADER_BYTES, bytes.length - POLY1305_TAG_BYTES);
  const tag = bytes.subarray(bytes.length - POLY1305_TAG_BYTES);

  const { createDecipheriv } = await nodeCrypto();
  const decipher = createDecipheriv(
    'chacha20-poly1305',
    Buffer.from(key),
    cipherNonce(expectedSequence),
    { authTagLength: POLY1305_TAG_BYTES },
  );
  decipher.setAAD(sealedHeader(expectedSequence), { plaintextLength: ciphertext.length });
  decipher.setAuthTag(tag);
  try {
    const message = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return { ok: true, message };
  } catch {
    return {
      ok: false,
      reason: 'tag',
      detail:
        claimed === expectedSequence
          ? `Poly1305 tag on the frame at sequence ${expectedSequence} does not authenticate`
          : `frame claims sequence ${claimed} but sequence ${expectedSequence} was expected, and its Poly1305 tag does not authenticate at that sequence (replayed or desynchronised)`,
    };
  }
}

/** The peer-address request the probe sends once keys exist. */
export function encodePeerAddressRequest(): Buffer {
  return Buffer.from(xdr.StellarMessage.peers([]).toXDR());
}

/** True when a frame is a plaintext overlay message rather than a sealed one. */
function isPlaintextOverlayFrame(frame: Uint8Array): string | undefined {
  const envelope = decodeAuthenticatedMessage(frame);
  if (envelope === undefined) return undefined;
  const decoded = decodeStellarMessage(envelope.message);
  if (decoded === undefined) return undefined;
  return decoded.type === 'other' ? decoded.name : decoded.type;
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function allZero(bytes: Uint8Array): boolean {
  return bytes.every((byte) => byte === 0);
}

/**
 * Runs the session described in the module comment over an open channel and
 * classifies the result. Never throws.
 */
export async function verifyCipherSession(
  endpoint: ValidatorEndpoint,
  channel: CipherChannel,
  options: CipherVerifierOptions = {},
): Promise<CipherOutcome> {
  const { randomBytes } = await nodeCrypto();
  const timeoutMs = options.timeoutMs ?? OVERLAY_HANDSHAKE_TIMEOUT_MS;
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));
  const networkId =
    options.passphrase === undefined
      ? new Uint8Array(32)
      : networkIdForPassphrase(options.passphrase);
  const identity = generateEphemeralIdentity();
  const ourNonce = randomBytes(32);
  const expiration = now() + Math.ceil(timeoutMs / 1000) + 60;

  // 1. HELLO exchange and AuthCert verification.
  try {
    await channel.send(
      encodeAuthenticatedMessage(
        encodeHello({
          ledgerVersion: LEDGER_PROTOCOL_VERSION,
          overlayVersion: options.overlayVersion ?? OVERLAY_PROTOCOL_VERSION,
          overlayMinVersion: 1,
          networkId,
          versionStr: 'stellar-toml-lint',
          listeningPort: endpoint.port,
          nodePublic: identity.nodePublic,
          cert: signedAuthCert(identity, expiration, networkId),
          nonce: ourNonce,
        }),
      ),
    );
  } catch (error) {
    return { status: 'unreachable', detail: describe(error) };
  }

  let helloFrame: Uint8Array;
  try {
    helloFrame = await channel.receive();
  } catch (error) {
    return { status: 'unreachable', detail: describe(error) };
  }
  if (helloFrame.length > MAX_UNAUTHENTICATED_FRAME_BYTES) {
    return {
      status: 'negotiation-failed',
      detail: `peer sent a ${helloFrame.length}-byte frame before either side had a key`,
    };
  }
  const envelope = decodeAuthenticatedMessage(helloFrame);
  const decoded = envelope === undefined ? undefined : decodeStellarMessage(envelope.message);
  if (decoded === undefined || decoded.type !== 'hello') {
    return {
      status: 'negotiation-failed',
      detail:
        decoded === undefined
          ? 'peer answered with bytes that are not an overlay HELLO'
          : decoded.type === 'error'
            ? `peer rejected the session: ${decoded.message}`
            : `peer answered with ${decoded.type === 'other' ? decoded.name : decoded.type} instead of HELLO`,
    };
  }
  if (!verifyAuthCert(decoded.cert, decoded.hello.peerId, decoded.hello.networkId)) {
    return {
      status: 'negotiation-failed',
      detail: `AuthCert is not signed by the announced node ID ${decoded.hello.peerId}`,
    };
  }
  const certExpiry = Number(decoded.cert.expiration().toString());
  if (certExpiry <= now()) {
    return {
      status: 'negotiation-failed',
      detail: `AuthCert expired at ${new Date(certExpiry * 1000).toISOString()}`,
    };
  }
  const peerCurve = Buffer.from(decoded.cert.pubkey().key() as Uint8Array);
  let dhSecret: Buffer;
  try {
    dhSecret = sharedSecret(identity.curvePrivate, peerCurve);
  } catch (error) {
    return {
      status: 'negotiation-failed',
      detail: `announced Curve25519 key is unusable: ${describe(error)}`,
    };
  }
  if (allZero(dhSecret)) {
    return {
      status: 'negotiation-failed',
      detail: 'announced Curve25519 key is a low-order point; the shared secret is all zeros',
    };
  }

  // 2. HKDF key schedule.
  const keys = deriveCipherKeys({
    dhSecret,
    initiatorCurvePublic: identity.curvePublic,
    responderCurvePublic: peerCurve,
    initiatorNonce: ourNonce,
    responderNonce: decoded.nonce,
    role: 'initiator',
  });

  // 3. The sealed peer-address request.
  try {
    await channel.send(await sealFrame(keys.send, 0n, encodePeerAddressRequest()));
  } catch (error) {
    return {
      status: 'unsupported',
      detail: `peer closed before the sealed request: ${describe(error)}`,
    };
  }

  // 4. The peer's sealed response.
  let response: Uint8Array;
  try {
    response = await channel.receive();
  } catch (error) {
    return { status: 'unsupported', detail: `no sealed response: ${describe(error)}` };
  }
  const plaintextType = isPlaintextOverlayFrame(response);
  if (plaintextType !== undefined) {
    return {
      status: 'unsupported',
      detail: `peer answered the sealed request with a plaintext ${plaintextType}`,
    };
  }
  const opened = await openFrame(keys.receive, 0n, response);
  if (!opened.ok) {
    return opened.reason === 'tag'
      ? { status: 'mac-mismatch', detail: opened.detail }
      : { status: 'negotiation-failed', detail: opened.detail };
  }
  const inner = decodeStellarMessage(opened.message);
  if (inner === undefined) {
    return {
      status: 'negotiation-failed',
      detail: 'response authenticated but does not decrypt to a StellarMessage',
    };
  }
  return { status: 'verified', responseType: inner.type === 'other' ? inner.name : inner.type };
}

/** Opens a TCP channel speaking length-prefixed overlay frames. */
export async function openSocketChannel(
  endpoint: ValidatorEndpoint,
  options: { timeoutMs: number },
): Promise<CipherChannel> {
  const { createConnection } = await import('node:net');
  const socket = createConnection({ host: endpoint.host, port: endpoint.port });
  socket.setNoDelay(true);

  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`no TCP connection within ${options.timeoutMs}ms`));
    }, options.timeoutMs);
    socket.once('connect', () => {
      clearTimeout(timer);
      resolve();
    });
    socket.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });

  let buffer: Buffer = Buffer.alloc(0);
  const frames: Buffer[] = [];
  let ended: Error | undefined;
  const waiting: { resolve: (frame: Buffer) => void; reject: (error: Error) => void }[] = [];

  const flush = (): void => {
    while (waiting.length > 0 && frames.length > 0)
      waiting.shift()?.resolve(frames.shift() as Buffer);
    if (ended !== undefined) while (waiting.length > 0) waiting.shift()?.reject(ended);
  };
  const end = (error: Error): void => {
    ended ??= error;
    flush();
  };

  socket.on('data', (chunk: Buffer) => {
    buffer = Buffer.concat([buffer, chunk]);
    while (buffer.length >= 4) {
      const length = overlayFrameLength(buffer.subarray(0, 4));
      if (length === 0 || length > OVERLAY_MAX_FRAME_BYTES) {
        end(new Error(`peer declared a ${length}-byte frame`));
        socket.destroy();
        return;
      }
      if (buffer.length < length + 4) break;
      frames.push(buffer.subarray(4, length + 4));
      buffer = buffer.subarray(length + 4);
    }
    flush();
  });
  socket.once('close', () => end(new Error('the peer closed the connection')));
  socket.once('error', (error: Error) => end(error));
  socket.setTimeout(options.timeoutMs, () => {
    end(new Error(`no overlay frame within ${options.timeoutMs}ms`));
    socket.destroy();
  });

  return {
    send: (payload) =>
      new Promise<void>((resolve, reject) => {
        if (ended !== undefined) {
          reject(ended);
          return;
        }
        socket.write(encodeOverlayFrame(payload), (error) => (error ? reject(error) : resolve()));
      }),
    receive: () =>
      new Promise<Buffer>((resolve, reject) => {
        waiting.push({ resolve, reject });
        flush();
      }),
    close: () => socket.destroy(),
  };
}

function severityFor(
  rule: string,
  fallback: Severity,
  rules?: RuleOverrides,
): Severity | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' || override === 'info'
    ? override
    : fallback;
}

function named(endpoint: ValidatorEndpoint): string {
  return endpoint.alias === undefined
    ? endpoint.publicKey
    : `${endpoint.alias} (${endpoint.publicKey})`;
}

/** The findings for one session outcome. */
export function cipherFindings(
  endpoint: ValidatorEndpoint,
  outcome: CipherOutcome,
  rules?: RuleOverrides,
): Diagnostic[] {
  const where = `${named(endpoint)} at ${endpoint.host}:${endpoint.port}`;
  if (outcome.status === 'negotiation-failed') {
    const severity = severityFor(OVERLAY_CIPHER_NEGOTIATION_FAILED_RULE, 'error', rules);
    if (severity === undefined) return [];
    return [
      {
        rule: OVERLAY_CIPHER_NEGOTIATION_FAILED_RULE,
        severity,
        category: 'network',
        message: `Overlay cipher negotiation with ${where} failed: ${outcome.detail}`,
        path: `${endpoint.path}.HOST`,
        helpUri: OVERLAY_HELP_URI,
        suggestion:
          'The node could not establish authenticated session keys. Check that its node seed matches PUBLIC_KEY, its clock is correct (AuthCerts expire), and that it runs a supported stellar-core release.',
      },
    ];
  }
  if (outcome.status === 'mac-mismatch') {
    const severity = severityFor(OVERLAY_MAC_TAG_MISMATCH_RULE, 'error', rules);
    if (severity === undefined) return [];
    return [
      {
        rule: OVERLAY_MAC_TAG_MISMATCH_RULE,
        severity,
        category: 'network',
        message: `Overlay peer ${where} sent a frame that failed authentication: ${outcome.detail}`,
        path: `${endpoint.path}.HOST`,
        helpUri: OVERLAY_HELP_URI,
        suggestion:
          'Frames that do not authenticate under the negotiated keys are dropped by every peer, and desynchronised sequence numbers open the node to replay. Look for a middlebox rewriting traffic on the overlay port or a node with a broken key schedule.',
      },
    ];
  }
  return [];
}

/**
 * The `--check-network --verify-overlay` cipher entry point: negotiate a
 * session with every declared validator and verify one sealed exchange.
 */
export async function checkOverlayCipher(
  doc: Record<string, unknown>,
  options: CipherVerifierOptions = {},
): Promise<Diagnostic[]> {
  const endpoints = validatorEndpoints(doc);
  if (endpoints.length === 0) return [];
  const passphrase = isString(doc.NETWORK_PASSPHRASE) ? doc.NETWORK_PASSPHRASE : options.passphrase;
  const timeoutMs = options.timeoutMs ?? OVERLAY_HANDSHAKE_TIMEOUT_MS;
  const open = options.channelFactory ?? openSocketChannel;
  const diagnostics: Diagnostic[] = [];

  for (const endpoint of endpoints) {
    let channel: CipherChannel;
    try {
      channel = await open(endpoint, { timeoutMs });
    } catch {
      continue; // unreachable peers are reported by overlay/handshake-timeout
    }
    try {
      const outcome = await verifyCipherSession(endpoint, channel, {
        ...options,
        ...(passphrase === undefined ? {} : { passphrase }),
        timeoutMs,
      });
      diagnostics.push(...cipherFindings(endpoint, outcome, options.rules));
    } finally {
      channel.close();
    }
  }
  return diagnostics;
}

export const verifyOverlayCipher = checkOverlayCipher;

/** Registered so `--list-rules`, `--off`, and SARIF know these ids. */
export const overlayCipherRules: Rule[] = [
  {
    id: OVERLAY_CIPHER_NEGOTIATION_FAILED_RULE,
    category: 'network',
    severity: 'error',
    description:
      'A validator fails the authenticated Curve25519 handshake or HKDF/ChaCha20-Poly1305 session setup',
    run() {},
  },
  {
    id: OVERLAY_MAC_TAG_MISMATCH_RULE,
    category: 'network',
    severity: 'error',
    description:
      'A validator sends an encrypted overlay frame whose Poly1305 tag does not authenticate',
    run() {},
  },
];

export const overlayCipherRuleIds: readonly string[] = overlayCipherRules.map((rule) => rule.id);
