/**
 * The socket half of the overlay handshake.
 *
 * Everything here needs a Node runtime — `node:net` for the dial — so it lives
 * apart from `handshake.ts`, which imports it lazily. A lint run in a browser or
 * a worker never loads this file, exactly as the peer crawler keeps
 * `node-connector.ts` to itself. The framing, the cert signature and the MAC
 * keys are all in `handshake.ts`, because those are checkable without a socket.
 *
 * On the wire, in the order the overlay speaks it:
 *
 * 1. each side opens with an unencrypted `HELLO`: an `AuthenticatedMessage` with
 *    sequence 0 and an all-zero MAC, wrapped in a length header. Every finding
 *    this package reports comes out of that frame, which is why linting a file
 *    never requires a key.
 * 2. a `HELLO` carries an `AuthCert` — an ephemeral Curve25519 key, an expiry,
 *    and an Ed25519 signature over the network hash, the auth envelope type,
 *    both, and the peer's node ID — so the node ID the peer claims is checked
 *    against a signature rather than against a claim. A node verifies that
 *    signature against the network *it* is on, before it answers.
 * 3. both sides then derive two MAC keys from the X25519 secret between the
 *    announced Curve25519 keys and both `HELLO` nonces, and the caller sends an
 *    `AUTH` under them. The responder answers with its own `AUTH`, and an echo
 *    that authenticates is proof the two peers agree on the key — which only
 *    peers holding the same pair of ephemeral keys can do.
 * 4. the connection closes.
 *
 * Step 3 is attempted and never required: a node that answers `HELLO` and then
 * sends something else, or nothing, has still told us who it is and what network
 * it is on. Step 2 is required — a peer that cannot sign with the node ID it
 * announces is not that peer.
 */
import { createConnection, type Socket } from 'node:net';
import { randomBytes } from 'node:crypto';
import { StrKey } from '@stellar/stellar-base';
import {
  OVERLAY_AUTH_FLOW_CONTROL_FLAGS,
  OVERLAY_HANDSHAKE_TIMEOUT_MS,
  OVERLAY_MAC_BYTES,
  OVERLAY_PROTOCOL_VERSION,
  decodeAuthenticatedMessage,
  decodeStellarMessage,
  deriveMacKeys,
  deriveSharedMacKey,
  encodeAuthenticatedMessage,
  encodeAuth,
  encodeHello,
  encodeOverlayFrame,
  generateEphemeralIdentity,
  networkIdForPassphrase,
  overlayFrameLength,
  overlayMac,
  sharedSecret,
  signedAuthCert,
  verifyAuthCert,
  verifyOverlayMac,
  type AnnouncedHello,
  type EphemeralIdentity,
  type HandshakeFailure,
  type HandshakeOptions,
  type HandshakeOutcome,
  type OverlayEnvelope,
  type PeerHello,
  type ValidatorEndpoint,
} from './handshake.js';
import { OVERLAY_MAX_FRAME_BYTES } from './crawler.js';

export {
  authCertDigest,
  authCertPreimage,
  deriveMacKeys,
  deriveSharedMacKey,
  generateEphemeralIdentity,
  signedAuthCert,
  verifyAuthCert,
} from './handshake.js';
export type { EphemeralIdentity };

/**
 * stellar-core rejects a frame whose payload is larger than this while no key
 * exists yet, so a `HELLO` is the only thing that can arrive this early.
 */
const MAX_UNAUTHENTICATED_FRAME_BYTES = 0x1000;

/**
 * The ledger protocol our `HELLO` announces. It is informational — a peer
 * negotiates ledgers over `GET_LEDGER` — but it should still describe the ledger
 * we claim to be on, and mainnet runs 29.
 */
const LEDGER_PROTOCOL_VERSION = 29;

/** One step of the exchange: a whole frame, or the failure that stopped us. */
type Step = { frame: Buffer } | { failure: HandshakeFailure; detail?: string };

/**
 * One reader per socket, yielding each frame the peer sends. A reader that
 * started per step would lose whatever arrived in the same packet as the
 * `HELLO`, and a node in a hurry sends its `AUTH` immediately after.
 */
interface FrameReader {
  /** The next frame, or the failure that ended the exchange. */
  next: () => Promise<Step>;
}

function readOverlayFrames(socket: Socket, timeoutMs: number): FrameReader {
  let buffer: Buffer = Buffer.alloc(0);
  let stopped: Step | undefined;
  const waiting: ((step: Step) => void)[] = [];

  const settle = (step: Step): void => {
    const waiter = waiting.shift();
    if (waiter !== undefined) waiter(step);
    else stopped = step;
  };

  const take = (): Buffer | undefined => {
    if (buffer.length < 4) return undefined;
    const length = overlayFrameLength(buffer.subarray(0, 4));
    if (length === 0 || length > OVERLAY_MAX_FRAME_BYTES) {
      buffer = Buffer.alloc(0);
      settle({ failure: 'protocol', detail: `peer declared a ${length}-byte frame` });
      return undefined;
    }
    if (buffer.length < length + 4) return undefined;
    const frame = buffer.subarray(4, length + 4);
    buffer = buffer.subarray(length + 4);
    return frame;
  };

  socket.on('data', (chunk: Buffer) => {
    buffer = Buffer.concat([buffer, chunk]);
    for (;;) {
      const frame = take();
      if (frame === undefined) return;
      settle({ frame });
    }
  });
  socket.once('close', () =>
    settle({ failure: 'protocol', detail: 'the peer closed the connection mid-handshake' }),
  );
  socket.once('error', (error: Error) => settle({ failure: 'protocol', detail: error.message }));
  socket.setTimeout(timeoutMs, () =>
    settle({ failure: 'timeout', detail: `no overlay reply within ${timeoutMs}ms` }),
  );

  return {
    next: () =>
      new Promise<Step>((resolve) => {
        if (stopped !== undefined) {
          const step = stopped;
          stopped = undefined;
          resolve(step);
          return;
        }
        waiting.push(resolve);
      }),
  };
}

/** Resolves once the TCP connection lands or the dial fails outright. */
function connectionStep(socket: Socket): Promise<Step> {
  return new Promise((resolve) => {
    socket.once('connect', () => resolve({ frame: Buffer.alloc(0) }));
    socket.once('error', (error: Error) =>
      resolve({
        failure:
          (error as NodeJS.ErrnoException).code === 'ECONNREFUSED' ? 'unreachable' : 'timeout',
        detail: error.message,
      }),
    );
  });
}

/**
 * Dials one validator and performs the handshake described above. Never throws:
 * every transport outcome is a classified {@link HandshakeOutcome}.
 */
export async function performOverlayHandshake(
  endpoint: ValidatorEndpoint,
  options: HandshakeOptions = {},
): Promise<HandshakeOutcome> {
  const timeoutMs = options.timeoutMs ?? OVERLAY_HANDSHAKE_TIMEOUT_MS;
  const networkId =
    options.passphrase === undefined
      ? new Uint8Array(32)
      : networkIdForPassphrase(options.passphrase);
  const identity = generateEphemeralIdentity();
  const ourNonce = randomBytes(32);
  // The cert is valid for the run plus a minute; a peer that would accept a
  // much longer window is not the peer this file is describing.
  const expiration = Math.floor(Date.now() / 1000) + Math.ceil(timeoutMs / 1000) + 60;

  const socket = createConnection({ host: endpoint.host, port: endpoint.port });
  socket.setNoDelay(true);
  const frames = readOverlayFrames(socket, timeoutMs);

  try {
    const connected = await connectionStep(socket);
    if ('failure' in connected) return { endpoint, ...connected };

    socket.write(
      encodeOverlayFrame(
        encodeAuthenticatedMessage(
          encodeHello({
            ledgerVersion: LEDGER_PROTOCOL_VERSION,
            overlayVersion: options.overlayVersion ?? OVERLAY_PROTOCOL_VERSION,
            overlayMinVersion: 1,
            networkId,
            versionStr: 'stellar-toml-lint',
            // We never listen, and a node drops a HELLO naming port 0 before it
            // answers, so the handshake announces the port it is dialling.
            listeningPort: endpoint.port,
            nodePublic: identity.nodePublic,
            cert: signedAuthCert(identity, expiration, networkId),
            nonce: ourNonce,
          }),
        ),
      ),
    );

    const answer = await frames.next();
    if ('failure' in answer) {
      return {
        endpoint,
        failure: answer.failure,
        ...(answer.detail === undefined ? {} : { detail: answer.detail }),
      };
    }
    if (answer.frame.length > MAX_UNAUTHENTICATED_FRAME_BYTES) {
      return {
        endpoint,
        failure: 'protocol',
        detail: `peer sent a ${answer.frame.length}-byte frame before either side had a key`,
      };
    }

    const envelope = decodeAuthenticatedMessage(answer.frame);
    if (envelope === undefined) {
      return {
        endpoint,
        failure: 'protocol',
        detail: 'peer sent a frame that is not an AuthenticatedMessage',
      };
    }
    const decoded = decodeStellarMessage(envelope.message);
    if (decoded === undefined || decoded.type !== 'hello') {
      return {
        endpoint,
        failure: 'protocol',
        detail:
          decoded === undefined
            ? 'peer sent bytes that are not a StellarMessage'
            : decoded.type === 'error'
              ? `peer rejected us with an overlay error: ${decoded.message}`
              : `peer answered with ${decoded.type === 'other' ? `'${decoded.name}'` : 'an AUTH'} instead of HELLO`,
      };
    }

    // The cert is checked against the network the peer itself names, because
    // verifying a signature and disbelieving a claim are different questions: a
    // peer on the wrong network is still a peer that knows its own key.
    if (!verifyAuthCert(decoded.cert, decoded.hello.peerId, decoded.hello.networkId)) {
      return {
        endpoint,
        failure: 'authentication',
        detail: `the AuthCert in its HELLO is not signed by ${decoded.hello.peerId}`,
      };
    }

    const echo = await negotiateAuthentication(socket, frames, identity, ourNonce, {
      hello: decoded.hello,
      cert: decoded.cert,
      nonce: decoded.nonce,
    });
    return { endpoint, hello: decoded.hello, authenticated: echo };
  } catch (error) {
    return {
      endpoint,
      failure: 'protocol',
      detail: error instanceof Error ? error.message : String(error),
    };
  } finally {
    socket.destroy();
  }
}

/**
 * Derives the session keys from the two announced Curve25519 keys and the two
 * `HELLO` nonces, sends an `AUTH` under them, and authenticates the peer's own
 * `AUTH` in reply. `undefined` means no authenticated frame ever came back, which
 * the caller reports as negotiation that did not happen rather than as a
 * violation; `false` means a frame came back that the derived key could not
 * explain.
 */
async function negotiateAuthentication(
  socket: Socket,
  frames: FrameReader,
  identity: EphemeralIdentity,
  ourNonce: Uint8Array,
  peer: AnnouncedHello,
): Promise<boolean | undefined> {
  const theirCurve = Buffer.from(peer.cert.pubkey().key() as Uint8Array);
  const keys = deriveMacKeys(
    deriveSharedMacKey(
      sharedSecret(identity.curvePrivate, theirCurve),
      identity.curvePublic,
      theirCurve,
    ),
    ourNonce,
    peer.nonce,
    'initiator',
  );
  const auth = encodeAuth(OVERLAY_AUTH_FLOW_CONTROL_FLAGS);
  socket.write(
    encodeOverlayFrame(encodeAuthenticatedMessage(auth, 0n, overlayMac(keys.send, 0n, auth))),
  );

  const echo = await frames.next();
  if ('failure' in echo) return undefined;
  const envelope: OverlayEnvelope | undefined = decodeAuthenticatedMessage(echo.frame);
  if (envelope === undefined) return undefined;
  if (decodeStellarMessage(envelope.message)?.type !== 'auth') return undefined;
  return verifyOverlayMac(keys.receive, envelope.sequence, envelope.message, envelope.mac);
}

/** The peer side of the exchange, so a test can stand in for a validator. */
export interface MockPeerOptions {
  /** What this peer's `HELLO` says, minus the identity, which is declared. */
  hello: Omit<PeerHello, 'peerId' | 'networkId'> & { networkId?: Uint8Array };
  /**
   * The Ed25519 seed that signs the `AuthCert`. A peer announces one node ID and
   * signs with this key, so a seed belonging to some other node is how a test
   * models a listener that cannot prove the identity it claims.
   */
  nodePrivate: Uint8Array;
  /** Announces this node ID; defaults to the one the file declares. */
  peerId?: string;
  /** Answers the `HELLO` at all. */
  silent?: boolean;
  /** Answers with a well-framed envelope carrying something else than a `StellarMessage`. */
  garbage?: boolean;
  /** Drops the connection as soon as our `HELLO` arrives. */
  hangUp?: boolean;
  /** Answers the peer's `AUTH` under a key it did not derive. */
  tamper?: boolean;
  /** Answers `HELLO` and then never sends an `AUTH` of its own. */
  silentEcho?: boolean;
  timeoutMs?: number;
}

/**
 * Speaks the peer half of the handshake over an accepted socket, as a node that
 * was dialled does: read the caller's `HELLO`, answer with our own unauthenticated
 * one, then wait for the caller's `AUTH` and reply with ours under the derived
 * keys.
 *
 * Exported for the test suite. A mock validator built from the same primitives
 * proves the framing, the identity signature, and the MAC handling round-trip,
 * which is the part of this module that can be checked without a live network.
 */
export async function respondAsOverlayPeer(
  socket: Socket,
  options: MockPeerOptions,
  announcedNetworkId: Uint8Array,
  declaredPeerId: string,
): Promise<void> {
  const frames = readOverlayFrames(socket, options.timeoutMs ?? 5_000);
  const clientHello = await frames.next();
  if ('failure' in clientHello || options.silent) return;
  if (options.hangUp) {
    socket.destroy();
    return;
  }
  if (options.garbage) {
    socket.write(
      encodeOverlayFrame(encodeAuthenticatedMessage(Buffer.from('not a stellar message', 'utf8'))),
    );
    socket.end();
    return;
  }

  const identity = generateEphemeralIdentity();
  const ourNonce = randomBytes(32);
  const peerId = options.peerId ?? declaredPeerId;
  const networkId = options.hello.networkId ?? announcedNetworkId;
  const expiration = Math.floor(Date.now() / 1000) + 600;
  socket.write(
    encodeOverlayFrame(
      encodeAuthenticatedMessage(
        encodeHello({
          ledgerVersion: options.hello.ledgerVersion,
          overlayVersion: options.hello.overlayVersion,
          overlayMinVersion: options.hello.overlayMinVersion,
          networkId,
          versionStr: options.hello.versionStr,
          listeningPort: options.hello.listeningPort,
          nodePublic: StrKey.decodeEd25519PublicKey(peerId),
          cert: signedAuthCert(
            { ...identity, nodePrivate: options.nodePrivate },
            expiration,
            networkId,
          ),
          nonce: ourNonce,
        }),
      ),
    ),
  );

  if (options.silentEcho) {
    // Half-closing after the `HELLO` is what a node that keeps connections for
    // its own reasons does: it has still answered the identity question.
    socket.end();
    return;
  }

  const hello = decodedHello(clientHello.frame);
  if (hello === undefined) return;
  const clientCurve = Buffer.from(hello.cert.pubkey().key() as Uint8Array);
  const sealed = await frames.next();
  if ('failure' in sealed) return;
  const keys = deriveMacKeys(
    deriveSharedMacKey(
      sharedSecret(identity.curvePrivate, clientCurve),
      // The peer that placed the call contributes its key first, whichever side we are.
      clientCurve,
      identity.curvePublic,
    ),
    hello.nonce,
    ourNonce,
    'responder',
  );
  // A node drops a caller whose `AUTH` does not authenticate under the agreed
  // key, so the mock speaks the same rule and the echo only comes back when the
  // two halves of this exchange really do agree.
  const clientEnvelope = decodeAuthenticatedMessage(sealed.frame);
  if (
    clientEnvelope === undefined ||
    !verifyOverlayMac(
      keys.receive,
      clientEnvelope.sequence,
      clientEnvelope.message,
      clientEnvelope.mac,
    )
  ) {
    socket.destroy();
    return;
  }
  const auth = encodeAuth(OVERLAY_AUTH_FLOW_CONTROL_FLAGS);
  const mac = overlayMac(options.tamper ? Buffer.alloc(OVERLAY_MAC_BYTES) : keys.send, 0n, auth);
  socket.write(encodeOverlayFrame(encodeAuthenticatedMessage(auth, 0n, mac)));
  socket.end();
}

/** The client's `HELLO`, read out of the frame the mock peer was given. */
function decodedHello(frame: Buffer): AnnouncedHello | undefined {
  const envelope = decodeAuthenticatedMessage(frame);
  if (envelope === undefined) return undefined;
  const decoded = decodeStellarMessage(envelope.message);
  return decoded !== undefined && decoded.type === 'hello' ? decoded : undefined;
}
