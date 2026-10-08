/**
 * Did the port in `[[VALIDATORS]].HOST` answer as a Stellar overlay peer?
 *
 * SEP-20 validators publish `HOST` and `PUBLIC_KEY`, and a TCP probe that gets a
 * SYN-ACK proves only that something is listening on 11625 — a banner, a
 * load balancer, a completely different service. What an operator actually
 * means when they publish those two fields is: dial this address and you will
 * complete an overlay handshake with the node whose peer ID is this key, on
 * this network. That claim is checkable, and it is the one that matters for a
 * quorum slice.
 *
 * So this module dials each declared validator, performs the overlay handshake,
 * reads the peer's `HELLO`, and compares what it says against what the file
 * says. A peer on the wrong network is a misconfiguration; a peer whose ID is
 * not the published one is a takeover or a stale record.
 *
 * On the wire every overlay message is one frame: a 4-byte big-endian length
 * whose high bit is the XDR continuation flag, followed by an
 * `AuthenticatedMessage` — a version, a sequence number, the `StellarMessage`
 * itself, and a 32-byte HMAC-SHA256 over the sequence and the message. `HELLO`
 * and `ERROR` are the two messages sent before any key exists, so they carry
 * sequence 0 and an all-zero MAC; everything after them is authenticated under
 * keys both peers derive from the Curve25519 pair announced in their certs.
 *
 * The socket lives in `./handshake-socket.ts`, imported dynamically, for the
 * same reason the peer crawler isolates `node:net`: a lint run in a browser or a
 * worker must not load it. The rule objects are registered from
 * `src/rules/index.ts` so `--list-rules` and `--off` know these ids, and nothing
 * here runs unless `--check-network --verify-overlay` both appear.
 */
import { xdr, StrKey } from '@stellar/stellar-base';
import { ed25519, x25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha2';
import { hmac } from '@noble/hashes/hmac';
import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';
import { isString } from '../predicates.js';

export const OVERLAY_HANDSHAKE_TIMEOUT_RULE = 'overlay/handshake-timeout';
export const OVERLAY_NETWORK_MISMATCH_RULE = 'overlay/network-mismatch';
export const OVERLAY_PUBLIC_KEY_MISMATCH_RULE = 'overlay/public-key-mismatch';
export const OVERLAY_PROTOCOL_VERSION_OUTDATED_RULE = 'overlay/protocol-version-outdated';

/** `StellarMessageType` discriminants, as the published XDR defines them. */
export const OVERLAY_MESSAGE_ERROR = 0;
export const OVERLAY_MESSAGE_AUTH = 2;
export const OVERLAY_MESSAGE_HELLO = 13;

/**
 * `AUTH_MSG_FLAG_FLOW_CONTROL_BYTES_REQUESTED`. A peer that does not ask for
 * flow-control bytes is dropped as misconfigured, so an `AUTH` that wants the
 * connection to survive has to set it.
 */
export const OVERLAY_AUTH_FLOW_CONTROL_FLAGS = 200;

/** `EnvelopeType` value the `AuthCert` signature is bound to. */
export const ENVELOPE_TYPE_AUTH = 3;

/** The XDR continuation flag, set on the length header of every frame. */
export const OVERLAY_FRAME_CONTINUATION_BIT = 0x8000_0000;

/** `HmacSha256Mac`, and the sequence `HELLO` and `ERROR` always carry. */
export const OVERLAY_MAC_BYTES = 32;
export const OVERLAY_UNAUTHENTICATED_SEQUENCE = 0n;

/**
 * stellar-core's overlay protocol as of the version this package targets.
 *
 * Measured, not recalled: mainnet `core-live-{a,b,c}.stellar.org` run stellar-core
 * 29.0.0 and announce overlay version 42 with a minimum of 41. A node answers a
 * `HELLO` whose version does not overlap that window and then drops the
 * connection, so this constant has to track the network for the `AUTH` step of
 * the handshake to complete against a live peer at all.
 */
export const OVERLAY_PROTOCOL_VERSION = 42;

/** How long a single peer may take to complete a handshake. */
export const OVERLAY_HANDSHAKE_TIMEOUT_MS = 5_000;

const OVERLAY_HELP_URI =
  'https://developers.stellar.org/docs/learn/networks-and-topology/overlay-network';

/** What a peer's `HELLO` said. */
export interface PeerHello {
  ledgerVersion: number;
  overlayVersion: number;
  overlayMinVersion: number;
  /** The 32-byte SHA-256 of the passphrase the peer claims to be on. */
  networkId: Uint8Array;
  versionStr: string;
  listeningPort: number;
  /** The peer's node ID as a `G...` account. */
  peerId: string;
}

/** One `[[VALIDATORS]]` entry worth dialing. */
export interface ValidatorEndpoint {
  index: number;
  path: string;
  alias: string | undefined;
  publicKey: string;
  host: string;
  port: number;
}

/**
 * A peer's `HELLO`, the `AuthCert` that authenticates its claim, and the nonce
 * that — together with ours — picks the session's MAC keys.
 */
export interface AnnouncedHello {
  hello: PeerHello;
  cert: xdr.AuthCert;
  nonce: Uint8Array;
}

/** An ephemeral Curve25519/Ed25519 pair for one handshake. */
export interface EphemeralIdentity {
  curvePrivate: Uint8Array;
  curvePublic: Uint8Array;
  nodePrivate: Uint8Array;
  nodePublic: Uint8Array;
}

/**
 * Fresh keys for one dial. Nothing about a lint run's identity needs to outlive
 * it, so the pair is generated per connection and thrown away with the socket.
 */
export function generateEphemeralIdentity(): EphemeralIdentity {
  const curvePrivate = x25519.utils.randomPrivateKey();
  const nodePrivate = ed25519.utils.randomPrivateKey();
  return {
    curvePrivate,
    curvePublic: x25519.getPublicKey(curvePrivate),
    nodePrivate,
    nodePublic: ed25519.getPublicKey(nodePrivate),
  };
}

/** The X25519 secret between our ephemeral key and the peer's announced one. */
export function sharedSecret(ourPrivate: Uint8Array, theirPublic: Uint8Array): Buffer {
  return Buffer.from(x25519.getSharedSecret(Buffer.from(ourPrivate), Buffer.from(theirPublic)));
}

/**
 * Why a handshake did not produce a `HELLO` worth comparing to the file:
 * `timeout` never answered, `unreachable` refused the dial, `protocol` answered
 * with something that is not a StellarMessage, and `authentication` announced a
 * node ID it could not sign for.
 */
export type HandshakeFailure = 'timeout' | 'unreachable' | 'protocol' | 'authentication';

export interface HandshakeOutcome {
  endpoint: ValidatorEndpoint;
  hello?: PeerHello | undefined;
  failure?: HandshakeFailure | undefined;
  detail?: string | undefined;
  /**
   * Whether an `AUTH` frame authenticated under keys derived from both peers'
   * announced Curve25519 keys came back. Absent means the peer never sent one,
   * which is reported as negotiation that did not happen rather than as a
   * violation: what a node sends after its `HELLO` is its own business.
   */
  authenticated?: boolean | undefined;
}

/** Dials one endpoint and reports what its handshake said. */
export type OverlayTransport = (
  endpoint: ValidatorEndpoint,
  options: HandshakeOptions,
) => Promise<HandshakeOutcome>;

export interface HandshakeOptions {
  rules?: RuleOverrides;
  /** The network whose hash a peer must present. */
  passphrase?: string;
  timeoutMs?: number;
  /** The protocol version peers are expected to reach. */
  overlayVersion?: number;
  /** Overrides the socket transport; tests speak the protocol themselves. */
  transport?: OverlayTransport;
}

/** The SHA-256 hash a peer on this network must name in its `HELLO`. */
export function networkIdForPassphrase(passphrase: string): Uint8Array {
  return sha256(Buffer.from(passphrase, 'utf8'));
}

/** Reads `[[VALIDATORS]]` into the endpoints a handshake can dial. */
export function validatorEndpoints(doc: Record<string, unknown>): ValidatorEndpoint[] {
  const validators = Array.isArray(doc.VALIDATORS) ? doc.VALIDATORS : [];
  const endpoints: ValidatorEndpoint[] = [];
  validators.forEach((entry, index) => {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) return;
    const record = entry as Record<string, unknown>;
    const publicKey = isString(record.PUBLIC_KEY) ? record.PUBLIC_KEY : undefined;
    const host = isString(record.HOST) ? splitHost(record.HOST) : undefined;
    if (publicKey === undefined || host === undefined) return;
    endpoints.push({
      index,
      path: `VALIDATORS[${index}]`,
      alias: isString(record.ALIAS) ? record.ALIAS : undefined,
      publicKey,
      host: host.host,
      port: host.port,
    });
  });
  return endpoints;
}

/** Splits a SEP-20 `HOST` of the form `example.com:11625` or `[::1]:11625`. */
function splitHost(value: string): { host: string; port: number } | undefined {
  const raw = value.trim();
  const bracket = raw.startsWith('[') ? raw.indexOf(']') : -1;
  const separator = bracket > 0 ? raw.lastIndexOf(':') : raw.indexOf(':');
  if (separator <= 0 || separator === raw.length - 1) return undefined;
  const host = bracket > 0 ? raw.slice(1, bracket) : raw.slice(0, separator);
  const port = Number(raw.slice(separator + 1));
  if (host === '' || !Number.isInteger(port) || port < 1 || port > 65535) return undefined;
  return { host, port };
}

/** The `HELLO` this package would send, as an overlay frame payload. */
export function encodeHello(input: {
  ledgerVersion: number;
  overlayVersion: number;
  overlayMinVersion: number;
  networkId: Uint8Array;
  versionStr: string;
  listeningPort: number;
  /** The Ed25519 key this message is signed by, i.e. the claimed node ID. */
  nodePublic: Uint8Array;
  cert: xdr.AuthCert;
  nonce: Uint8Array;
}): Buffer {
  return Buffer.from(
    xdr.StellarMessage.hello(
      new xdr.Hello({
        ledgerVersion: input.ledgerVersion,
        overlayVersion: input.overlayVersion,
        overlayMinVersion: input.overlayMinVersion,
        networkId: Buffer.from(input.networkId),
        versionStr: input.versionStr,
        listeningPort: input.listeningPort,
        peerId: xdr.PublicKey.publicKeyTypeEd25519(Buffer.from(input.nodePublic)),
        cert: input.cert,
        nonce: Buffer.from(input.nonce),
      }),
    ).toXDR(),
  );
}

/** An `AUTH` frame asking for the flow-control bytes a real peer insists on. */
export function encodeAuth(flags = OVERLAY_AUTH_FLOW_CONTROL_FLAGS): Buffer {
  return Buffer.from(xdr.StellarMessage.auth(new xdr.Auth({ flags })).toXDR());
}

/** An `AuthCert` announcing one peer's ephemeral Curve25519 key. */
export function authCert(
  curve25519PublicKey: Uint8Array,
  expiration: number,
  signature: Uint8Array = new Uint8Array(64),
): xdr.AuthCert {
  return new xdr.AuthCert({
    pubkey: new xdr.Curve25519Public({ key: Buffer.from(curve25519PublicKey) }),
    expiration: new xdr.Uint64(Math.trunc(expiration)),
    sig: Buffer.from(signature),
  });
}

/** The XDR bytes of an `AuthCert`. */
export function encodeAuthCert(
  curve25519PublicKey: Uint8Array,
  expiration: number,
  signature: Uint8Array = new Uint8Array(64),
): Buffer {
  return Buffer.from(authCert(curve25519PublicKey, expiration, signature).toXDR());
}

/**
 * The bytes a node certifies to bind an `AuthCert` to itself: the network it is
 * announcing them on, the envelope type that keeps this signature from being
 * reusable as some other one, when the cert stops being valid, and the key it is
 * announcing. Including the network hash means a cert minted for testnet cannot
 * be replayed against a mainnet peer.
 */
export function authCertPreimage(
  networkId: Uint8Array,
  expiration: number,
  curve25519PublicKey: Uint8Array,
): Buffer {
  const envelope = Buffer.alloc(4);
  envelope.writeUInt32BE(ENVELOPE_TYPE_AUTH);
  const until = Buffer.alloc(8);
  until.writeBigUInt64BE(BigInt(Math.trunc(expiration)));
  return Buffer.concat([Buffer.from(networkId), envelope, until, Buffer.from(curve25519PublicKey)]);
}

/**
 * What the node actually signs: the SHA-256 of that preimage. stellar-core
 * hashes before signing, so verifying against the raw preimage fails against
 * every real peer.
 */
export function authCertDigest(
  networkId: Uint8Array,
  expiration: number,
  curve25519PublicKey: Uint8Array,
): Buffer {
  return Buffer.from(sha256(authCertPreimage(networkId, expiration, curve25519PublicKey)));
}

/** A signed `AuthCert`: an ephemeral key bound to a node ID and a network. */
export function signedAuthCert(
  identity: EphemeralIdentity,
  expiration: number,
  networkId: Uint8Array,
): xdr.AuthCert {
  return authCert(
    identity.curvePublic,
    expiration,
    ed25519.sign(authCertDigest(networkId, expiration, identity.curvePublic), identity.nodePrivate),
  );
}

/**
 * True when a peer's `AuthCert` was signed by the node ID its `HELLO` announces.
 * This is the only step that turns the identity claim into evidence: a listener
 * that cannot produce this signature is not the node the file describes, whatever
 * its `HELLO` says.
 */
export function verifyAuthCert(cert: xdr.AuthCert, peerId: string, networkId: Uint8Array): boolean {
  let nodePublic: Uint8Array;
  try {
    nodePublic = StrKey.decodeEd25519PublicKey(peerId);
  } catch {
    return false;
  }
  const signature = Buffer.from(cert.sig() as Uint8Array);
  try {
    return ed25519.verify(
      signature,
      authCertDigest(
        networkId,
        Number(cert.expiration().toString()),
        Buffer.from(cert.pubkey().key() as Uint8Array),
      ),
      Buffer.from(nodePublic),
    );
  } catch {
    return false;
  }
}

/** One `AuthenticatedMessage`: the envelope every overlay frame carries. */
export interface OverlayEnvelope {
  sequence: bigint;
  /** The inner `StellarMessage`, as XDR bytes. */
  message: Buffer;
  mac: Buffer;
}

/**
 * Wraps a `StellarMessage` in the envelope the overlay puts on the wire.
 * `HELLO` and `ERROR` go out before either peer holds a key, which is why the
 * defaults are the sequence and all-zero MAC stellar-core itself uses for them.
 */
export function encodeAuthenticatedMessage(
  message: Uint8Array,
  sequence: bigint = OVERLAY_UNAUTHENTICATED_SEQUENCE,
  mac: Uint8Array = new Uint8Array(OVERLAY_MAC_BYTES),
): Buffer {
  const header = Buffer.alloc(12);
  header.writeUInt32BE(0, 0);
  header.writeBigUInt64BE(sequence, 4);
  const trailing = Buffer.alloc(OVERLAY_MAC_BYTES);
  Buffer.from(mac).subarray(0, OVERLAY_MAC_BYTES).copy(trailing);
  return Buffer.concat([header, Buffer.from(message), trailing]);
}

/** The envelope's `StellarMessage` and MAC, or `undefined` for malformed bytes. */
export function decodeAuthenticatedMessage(bytes: Uint8Array): OverlayEnvelope | undefined {
  const frame = Buffer.from(bytes);
  if (frame.length < 12 + 4 + OVERLAY_MAC_BYTES) return undefined;
  if (frame.readUInt32BE(0) !== 0) return undefined;
  const end = frame.length - OVERLAY_MAC_BYTES;
  if (end < 16) return undefined;
  return {
    sequence: frame.readBigUInt64BE(4),
    message: frame.subarray(12, end),
    mac: frame.subarray(end),
  };
}

/** A frame: the length header with its continuation flag set, then the payload. */
export function encodeOverlayFrame(payload: Uint8Array): Buffer {
  const header = Buffer.alloc(4);
  // Bitwise arithmetic in JavaScript is signed, so the flag has to come back
  // out unsigned or the header write rejects its own value.
  header.writeUInt32BE((OVERLAY_FRAME_CONTINUATION_BIT | payload.length) >>> 0, 0);
  return Buffer.concat([header, Buffer.from(payload)]);
}

/**
 * The payload length a frame header declares. stellar-core masks the
 * continuation bit off rather than rejecting it, so a reader that takes the
 * header literally sees a multi-megabyte frame from a healthy node.
 */
export function overlayFrameLength(header: Uint8Array): number {
  const bytes = Buffer.from(header);
  return (bytes.readUInt32BE(0) & ~OVERLAY_FRAME_CONTINUATION_BIT) >>> 0;
}

/** The bytes the MAC covers: the sequence, then the message, both as XDR. */
export function macSigningInput(sequence: bigint, message: Uint8Array): Buffer {
  const header = Buffer.alloc(8);
  header.writeBigUInt64BE(sequence, 0);
  return Buffer.concat([header, Buffer.from(message)]);
}

/** `HmacSha256Mac` over the sequence and the message, under `key`. */
export function overlayMac(key: Uint8Array, sequence: bigint, message: Uint8Array): Buffer {
  return Buffer.from(hmac(sha256, Buffer.from(key), macSigningInput(sequence, message)));
}

/** True when `mac` is the MAC this key produces for this frame. */
export function verifyOverlayMac(
  key: Uint8Array,
  sequence: bigint,
  message: Uint8Array,
  mac: Uint8Array,
): boolean {
  const expected = overlayMac(key, sequence, message);
  const actual = Buffer.from(mac);
  return expected.length === actual.length && expected.equals(actual);
}

/** Which half of a pair of MAC keys one peer holds depends on who dialled. */
export type OverlayPeerRole = 'initiator' | 'responder';

/**
 * The medium-duration key for one peer pair: HKDF-Extract over the X25519 shared
 * secret and both announced Curve25519 keys, ordered so that the peer that
 * placed the call contributes its key first. Both sides reach the same key from
 * their own halves of that exchange, which is what makes it evidence.
 */
export function deriveSharedMacKey(
  dhSecret: Uint8Array,
  initiatorCurvePublic: Uint8Array,
  responderCurvePublic: Uint8Array,
): Buffer {
  return Buffer.from(
    hmac(
      sha256,
      new Uint8Array(OVERLAY_MAC_BYTES),
      Buffer.concat([
        Buffer.from(dhSecret),
        Buffer.from(initiatorCurvePublic),
        Buffer.from(responderCurvePublic),
      ]),
    ),
  );
}

/**
 * The two session keys, each HKDF-Expand of the shared key over a role byte and
 * the two `HELLO` nonces in the order the calling side's nonce comes first. The
 * mirror is exact: one peer's send key is the other's receive key.
 */
export function deriveMacKeys(
  sharedMacKey: Uint8Array,
  initiatorNonce: Uint8Array,
  responderNonce: Uint8Array,
  role: OverlayPeerRole,
): { send: Buffer; receive: Buffer } {
  const expand = (label: number, first: Uint8Array, second: Uint8Array): Buffer =>
    Buffer.from(
      hmac(
        sha256,
        Buffer.from(sharedMacKey),
        Buffer.concat([
          Buffer.from([label]),
          Buffer.from(first),
          Buffer.from(second),
          Buffer.from([1]),
        ]),
      ),
    );
  const called = role === 'initiator';
  return {
    send: called
      ? expand(0, initiatorNonce, responderNonce)
      : expand(1, responderNonce, initiatorNonce),
    receive: called
      ? expand(1, responderNonce, initiatorNonce)
      : expand(0, initiatorNonce, responderNonce),
  };
}

/**
 * Decodes one overlay message. `undefined` means the bytes are not a
 * `StellarMessage` at all, which callers treat as a protocol failure rather
 * than a finding about the file. A `HELLO` also carries its `AuthCert`, since
 * that is what authenticates the node ID the message claims.
 */
export function decodeStellarMessage(
  bytes: Uint8Array,
):
  | { type: 'hello'; hello: PeerHello; cert: xdr.AuthCert; nonce: Uint8Array }
  | { type: 'auth' }
  | { type: 'error'; message: string }
  | { type: 'other'; name: string }
  | undefined {
  try {
    const message = xdr.StellarMessage.fromXDR(Buffer.from(bytes));
    const name = message.switch().name as string;
    if (name === 'hello') {
      const hello = message.hello() as xdr.Hello;
      return {
        type: 'hello',
        hello: helloOf(hello),
        cert: hello.cert(),
        nonce: Buffer.from(hello.nonce() as Uint8Array),
      };
    }
    if (name === 'auth') return { type: 'auth' };
    if (name === 'errorMsg') {
      // The arm accessor is a static factory in this XDR binding, so the error
      // body is read straight off the wire instead.
      try {
        const error = xdr.Error.fromXDR(Buffer.from(bytes.subarray(4)));
        return { type: 'error', message: String(error.msg() ?? error.code().name) };
      } catch {
        return { type: 'error', message: 'rejected' };
      }
    }
    return { type: 'other', name };
  } catch {
    return undefined;
  }
}

/** Reads the fields this package validates out of a decoded `HELLO`. */
function helloOf(hello: xdr.Hello): PeerHello {
  const peerId = Buffer.from(hello.peerId().ed25519() as Uint8Array);
  return {
    ledgerVersion: Number(hello.ledgerVersion()),
    overlayVersion: Number(hello.overlayVersion()),
    overlayMinVersion: Number(hello.overlayMinVersion()),
    networkId: Buffer.from(hello.networkId() as Uint8Array),
    versionStr: Buffer.from(hello.versionStr() as Uint8Array).toString('utf8'),
    listeningPort: Number(hello.listeningPort()),
    peerId: StrKey.encodeEd25519PublicKey(peerId),
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

function finding(
  rule: string,
  fallback: Severity,
  message: string,
  path: string,
  suggestion: string,
  rules?: RuleOverrides,
): Diagnostic[] {
  const severity = severityFor(rule, fallback, rules);
  if (severity === undefined) return [];
  return [
    {
      rule,
      severity,
      category: 'network',
      message,
      path,
      helpUri: OVERLAY_HELP_URI,
      suggestion,
    },
  ];
}

function named(endpoint: ValidatorEndpoint): string {
  return endpoint.alias === undefined
    ? endpoint.publicKey
    : `${endpoint.alias} (${endpoint.publicKey})`;
}

/**
 * Compares a peer's answer with what the file claims about it.
 *
 * The peer ID is the identity claim and the network hash is the loyalty claim;
 * both are errors because a wrong answer means the file is pointing quorum
 * slices at a node that is not the one described. The protocol version is only
 * a warning: an outdated node still validates, it just cannot be relied on for
 * the newest ledger rules.
 */
export function helloFindings(
  endpoint: ValidatorEndpoint,
  hello: PeerHello,
  options: { passphrase?: string; overlayVersion?: number; rules?: RuleOverrides } = {},
): Diagnostic[] {
  const diagnostics: Diagnostic[] = [];
  const label = named(endpoint);

  if (options.passphrase !== undefined) {
    const expected = Buffer.from(networkIdForPassphrase(options.passphrase));
    if (!expected.equals(Buffer.from(hello.networkId))) {
      diagnostics.push(
        ...finding(
          OVERLAY_NETWORK_MISMATCH_RULE,
          'error',
          `Overlay peer ${label} at ${endpoint.host}:${endpoint.port} is on a different network: its HELLO hashes a passphrase to ${Buffer.from(hello.networkId).toString('hex').slice(0, 16)}…, not to ${expected.toString('hex').slice(0, 16)}…`,
          `${endpoint.path}.HOST`,
          'NETWORK_PASSPHRASE and [[VALIDATORS]] must describe the same network, or peers will be trusted on a ledger their operators never intended.',
          options.rules,
        ),
      );
      // Every other comparison is meaningless against a peer on another network.
      return diagnostics;
    }
  }

  if (hello.peerId !== endpoint.publicKey) {
    diagnostics.push(
      ...finding(
        OVERLAY_PUBLIC_KEY_MISMATCH_RULE,
        'error',
        `Overlay peer at ${endpoint.host}:${endpoint.port} identified itself as ${hello.peerId}, not the declared ${endpoint.publicKey}`,
        `${endpoint.path}.PUBLIC_KEY`,
        'Either the node is not the one this file describes, or its HOST or PUBLIC_KEY has gone stale. Update the entry to the peer that answered.',
        options.rules,
      ),
    );
  }

  const current = options.overlayVersion ?? OVERLAY_PROTOCOL_VERSION;
  if (hello.overlayMinVersion > current || hello.overlayVersion < current) {
    diagnostics.push(
      ...finding(
        OVERLAY_PROTOCOL_VERSION_OUTDATED_RULE,
        'warning',
        `Overlay peer ${label} speaks protocol version ${hello.overlayVersion} (minimum ${hello.overlayMinVersion}) at ledger ${hello.ledgerVersion}, older than version ${current}`,
        `${endpoint.path}.HOST`,
        `Upgrade the node to a stellar-core release that speaks overlay ${current}. Its version string was ${hello.versionStr || 'unreported'}.`,
        options.rules,
      ),
    );
  }

  if (hello.listeningPort !== endpoint.port) {
    diagnostics.push(
      ...finding(
        OVERLAY_NETWORK_MISMATCH_RULE,
        'error',
        `Overlay peer ${label} listens on port ${hello.listeningPort} but is published at ${endpoint.host}:${endpoint.port}`,
        `${endpoint.path}.HOST`,
        'A port that disagrees with the advertised one means the published HOST forwards somewhere other than this node.',
        options.rules,
      ),
    );
  }

  return diagnostics;
}

/** The findings for a handshake that never produced a trustworthy `HELLO`. */
export function failureFindings(
  outcome: HandshakeOutcome,
  options: HandshakeOptions = {},
): Diagnostic[] {
  const { endpoint } = outcome;
  if (outcome.failure === undefined) return [];
  const detail = outcome.detail === undefined ? '' : `: ${outcome.detail}`;

  if (outcome.failure === 'authentication') {
    return finding(
      OVERLAY_PUBLIC_KEY_MISMATCH_RULE,
      'error',
      `Overlay peer at ${endpoint.host}:${endpoint.port} announced ${endpoint.publicKey} but could not sign with it${detail}`,
      `${endpoint.path}.PUBLIC_KEY`,
      'A listener that cannot produce an AuthCert signature for the published node ID is not that node. Verify the HOST really belongs to this validator before keeping the entry in a quorum slice.',
      options.rules,
    );
  }

  return finding(
    OVERLAY_HANDSHAKE_TIMEOUT_RULE,
    'error',
    `Overlay handshake with ${named(endpoint)} at ${endpoint.host}:${endpoint.port} did not complete${
      outcome.failure === 'timeout' ? ' before the timeout' : ''
    }${detail}`,
    `${endpoint.path}.HOST`,
    outcome.failure === 'unreachable'
      ? 'Nothing is listening on that port. Publish the peer port stellar-core is actually bound to, or remove the entry.'
      : 'A peer that never completes the overlay handshake is not an overlay peer; check the HOST port, the firewall, and that the node is running.',
    options.rules,
  );
}

/**
 * The `--check-network --verify-overlay` entry point: dial every declared
 * validator and compare its answer against the file.
 */
export async function checkOverlayHandshake(
  doc: Record<string, unknown>,
  options: HandshakeOptions = {},
): Promise<Diagnostic[]> {
  const endpoints = validatorEndpoints(doc);
  if (endpoints.length === 0) return [];
  const passphrase = isString(doc.NETWORK_PASSPHRASE) ? doc.NETWORK_PASSPHRASE : options.passphrase;
  const transport = options.transport ?? (await loadTransport()).performOverlayHandshake;
  const diagnostics: Diagnostic[] = [];

  for (const endpoint of endpoints) {
    let outcome: HandshakeOutcome;
    try {
      outcome = await transport(endpoint, { ...options, passphrase });
    } catch (error) {
      outcome = {
        endpoint,
        failure: 'protocol',
        detail: error instanceof Error ? error.message : String(error),
      };
    }
    if (outcome.hello === undefined) {
      diagnostics.push(...failureFindings({ ...outcome, endpoint }, options));
      continue;
    }
    diagnostics.push(
      ...helloFindings(endpoint, outcome.hello, {
        passphrase,
        overlayVersion: options.overlayVersion,
        rules: options.rules,
      }),
    );
  }

  return diagnostics;
}

/** Loaded lazily so the browser and worker bundles never pull in `node:net`. */
async function loadTransport(): Promise<{ performOverlayHandshake: OverlayTransport }> {
  return import('./handshake-socket.js');
}

/** Registered from `src/rules/validators.ts` so `--list-rules` knows these ids. */
export const overlayHandshakeRules: Rule[] = [
  {
    id: OVERLAY_HANDSHAKE_TIMEOUT_RULE,
    category: 'network',
    severity: 'error',
    description: 'A declared validator HOST never completes the Stellar overlay handshake',
    run() {},
  },
  {
    id: OVERLAY_NETWORK_MISMATCH_RULE,
    category: 'network',
    severity: 'error',
    description: 'An overlay peer is on another network or listens on another port than published',
    run() {},
  },
  {
    id: OVERLAY_PUBLIC_KEY_MISMATCH_RULE,
    category: 'network',
    severity: 'error',
    description: 'An overlay peer identifies itself with a key other than the published PUBLIC_KEY',
    run() {},
  },
  {
    id: OVERLAY_PROTOCOL_VERSION_OUTDATED_RULE,
    category: 'network',
    severity: 'warning',
    description: 'An overlay peer cannot speak the current overlay protocol version',
    run() {},
  },
];

/** Rule ids emitted by {@link checkOverlayHandshake}. */
export const overlayHandshakeRuleIds: readonly string[] = overlayHandshakeRules.map(
  (rule) => rule.id,
);
