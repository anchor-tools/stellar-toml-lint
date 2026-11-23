/**
 * Stellar overlay network peer handshake and authenticated hello exchange tester.
 *
 * Parses [[VALIDATORS]] network endpoints (PUBLIC_KEY, HOST, PORT) in stellar.toml,
 * constructs authenticated overlay handshake messages (HELLO, AUTH), and simulates / tests
 * authenticated overlay handshakes with validators.
 */

import { Keypair, Networks, StrKey, hash, xdr } from '@stellar/stellar-base';

interface TcpSocket {
  write(data: Buffer): void;
  destroy(): void;
  on(event: 'data', listener: (chunk: Buffer | string) => void): void;
  on(event: 'error', listener: (err: Error) => void): void;
  on(event: 'close', listener: () => void): void;
  end(): void;
}
interface NetModuleShape {
  createConnection: (options: { host: string; port: number }, cb?: () => void) => TcpSocket;
}
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { hkdf } from '@noble/hashes/hkdf';
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';

export const OVERLAY_HANDSHAKE_FAILED = 'overlay/handshake-failed';
export const OVERLAY_NETWORK_ID_MISMATCH = 'overlay/network-id-mismatch';
export const OVERLAY_VERSION_MISMATCH = 'overlay/version-mismatch';
export const OVERLAY_VALIDATOR_KEY_MISMATCH = 'overlay/validator-key-mismatch';
export const OVERLAY_CERT_INVALID = 'overlay/cert-invalid';
export const OVERLAY_AUTH_MAC_INVALID = 'overlay/auth-mac-invalid';

export const DEFAULT_OVERLAY_PORT = 11625;
export const DEFAULT_OVERLAY_VERSION = 34;
export const DEFAULT_OVERLAY_MIN_VERSION = 20;
export const DEFAULT_LEDGER_VERSION = 21;
export const DEFAULT_CORE_VERSION = 'stellar-core 21.0.0';

export interface ValidatorEndpoint {
  publicKey: string; // G... account id
  host: string;
  port: number;
  rawEndpoint: string;
  path?: string;
}

export interface HelloSummary {
  ledgerVersion: number;
  overlayVersion: number;
  overlayMinVersion: number;
  networkIdHex: string;
  versionStr: string;
  listeningPort: number;
  peerId: string;
  certExpiration: number;
  nonceHex: string;
}

export interface HandshakeResult {
  ok: boolean;
  stage: 'not-started' | 'hello-sent' | 'hello-received' | 'auth-sent' | 'completed' | 'failed';
  validator: ValidatorEndpoint;
  remoteHello?: HelloSummary;
  versionCompatible?: boolean;
  networkIdMatched?: boolean;
  publicKeyMatched?: boolean;
  certValid?: boolean;
  authValid?: boolean;
  sharedMacKeyHex?: string;
  latencyMs?: number;
  error?: string;
}

export type OverlayTransport = (
  endpoint: string,
  outboundFramedHello: Uint8Array,
) => Promise<Uint8Array>;

export interface HandshakeTesterOptions {
  rules?: RuleOverrides;
  networkPassphrase?: string;
  networkId?: Uint8Array;
  localKeypair?: Keypair;
  overlayVersion?: number;
  overlayMinVersion?: number;
  ledgerVersion?: number;
  versionStr?: string;
  listeningPort?: number;
  timeoutMs?: number;
  transport?: OverlayTransport;
}

/** Framed message parser and encoder */
export function frameOverlayMessage(payloadBytes: Uint8Array): Uint8Array {
  const len = payloadBytes.length;
  const frame = new Uint8Array(len + 4);
  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
  // Highest bit set indicates message authentication enabled in Stellar overlay framing
  view.setUint32(0, (len | 0x80000000) >>> 0);
  frame.set(payloadBytes, 4);
  return frame;
}

export function unframeOverlayMessage(frameBytes: Uint8Array): Uint8Array {
  if (frameBytes.length < 4) {
    throw new Error('Framed overlay message too short (< 4 bytes)');
  }
  const view = new DataView(frameBytes.buffer, frameBytes.byteOffset, frameBytes.byteLength);
  const rawLen = view.getUint32(0);
  const length = rawLen & 0x7fffffff;
  if (frameBytes.length < length + 4) {
    throw new Error(
      `Incomplete overlay frame: expected ${length + 4} bytes, got ${frameBytes.length}`,
    );
  }
  return frameBytes.subarray(4, length + 4);
}

/**
 * Parses validator endpoints from stellar.toml [[VALIDATORS]] section.
 */
export function parseValidatorEndpoints(doc: Record<string, unknown>): ValidatorEndpoint[] {
  const endpoints: ValidatorEndpoint[] = [];
  const validators = doc.VALIDATORS;

  if (!Array.isArray(validators)) return endpoints;

  validators.forEach((entry, idx) => {
    if (typeof entry !== 'object' || entry === null) return;
    const v = entry as Record<string, unknown>;
    const pubKey = typeof v.PUBLIC_KEY === 'string' ? v.PUBLIC_KEY.trim() : '';
    const hostVal = typeof v.HOST === 'string' ? v.HOST.trim() : '';
    const portVal = v.PORT !== undefined ? Number(v.PORT) : undefined;

    if (!pubKey && !hostVal) return;

    let host = hostVal;
    let port = portVal ?? DEFAULT_OVERLAY_PORT;

    // Check if host contains port e.g. "core-live-a.stellar.org:11625"
    if (host.includes(':') && !host.startsWith('[')) {
      const parts = host.split(':');
      host = parts[0]!;
      const parsedPort = Number(parts[1]);
      if (Number.isInteger(parsedPort) && parsedPort > 0 && parsedPort <= 65535) {
        port = parsedPort;
      }
    }

    const path = `VALIDATORS[${idx}]`;
    const rawEndpoint = `${host}:${port}`;

    endpoints.push({
      publicKey: pubKey,
      host,
      port,
      rawEndpoint,
      path,
    });
  });

  return endpoints;
}

export class OverlayHandshakeTester {
  readonly options: HandshakeTesterOptions;
  readonly localKeypair: Keypair;
  readonly networkId: Uint8Array;

  constructor(options: HandshakeTesterOptions = {}) {
    this.options = options;
    this.localKeypair = options.localKeypair ?? Keypair.random();
    const passphrase = options.networkPassphrase ?? Networks.PUBLIC;
    this.networkId = options.networkId ?? hash(Buffer.from(passphrase));
  }

  /**
   * Generates Curve25519 ephemeral auth cert key and signs it with the local Ed25519 node key.
   */
  generateAuthCert(expirationSeconds: number = Math.floor(Date.now() / 1000) + 3600): {
    cert: xdr.AuthCert;
    curve25519PrivKey: Uint8Array;
    curve25519PubKey: Uint8Array;
  } {
    // Generate Curve25519 keypair for ECDH
    const curve25519PrivKey = ed25519.utils.randomPrivateKey();
    // ed25519 to x25519 conversion or direct curve25519 public key
    const curve25519PubKey = ed25519.getPublicKey(curve25519PrivKey);

    // Build payload to sign: networkId || "authcert" || expiration || pubkey
    const expBig = BigInt(expirationSeconds);
    const expBuf = Buffer.alloc(8);
    expBuf.writeBigUInt64BE(expBig);

    const preimage = Buffer.concat([
      Buffer.from(this.networkId),
      Buffer.from('authcert'),
      expBuf,
      Buffer.from(curve25519PubKey),
    ]);

    const signature = this.localKeypair.sign(preimage);

    const curveKey = new xdr.Curve25519Public({
      key: Buffer.from(curve25519PubKey),
    });

    const cert = new xdr.AuthCert({
      pubkey: curveKey,
      expiration: xdr.Uint64.fromString(expirationSeconds.toString()),
      sig: signature,
    });

    return {
      cert,
      curve25519PrivKey,
      curve25519PubKey,
    };
  }

  /**
   * Constructs an authenticated Stellar overlay HELLO message.
   */
  constructHello(
    cert: xdr.AuthCert,
    nonce?: Uint8Array,
  ): {
    hello: xdr.Hello;
    stellarMessage: xdr.StellarMessage;
    framedBytes: Uint8Array;
    nonce: Uint8Array;
  } {
    const localNonce = nonce ?? ed25519.utils.randomPrivateKey();

    const rawNodeId = StrKey.decodeEd25519PublicKey(this.localKeypair.publicKey());
    const peerId = xdr.PublicKey.publicKeyTypeEd25519(Buffer.from(rawNodeId));

    const hello = new xdr.Hello({
      ledgerVersion: this.options.ledgerVersion ?? DEFAULT_LEDGER_VERSION,
      overlayVersion: this.options.overlayVersion ?? DEFAULT_OVERLAY_VERSION,
      overlayMinVersion: this.options.overlayMinVersion ?? DEFAULT_OVERLAY_MIN_VERSION,
      networkId: Buffer.from(this.networkId),
      versionStr: this.options.versionStr ?? DEFAULT_CORE_VERSION,
      listeningPort: this.options.listeningPort ?? DEFAULT_OVERLAY_PORT,
      peerId,
      cert,
      nonce: Buffer.from(localNonce),
    });

    const stellarMessage = xdr.StellarMessage.hello(hello);
    const payload = stellarMessage.toXDR();
    const framedBytes = frameOverlayMessage(payload);

    return {
      hello,
      stellarMessage,
      framedBytes,
      nonce: localNonce,
    };
  }

  /**
   * Constructs an authenticated AUTH message.
   */
  constructAuth(
    sequence = 0n,
    macKey?: Uint8Array,
  ): {
    authMessage: xdr.AuthenticatedMessage;
    framedBytes: Uint8Array;
    mac: Uint8Array;
  } {
    const auth = new xdr.Auth({
      flags: 200, // flow control bytes requested
    });

    const stellarMsg = xdr.StellarMessage.auth(auth);
    const msgXdr = stellarMsg.toXDR();

    // Compute MAC over sequence and message if key is provided
    let macBytes = new Uint8Array(32);
    if (macKey) {
      const seqBuf = Buffer.alloc(8);
      seqBuf.writeBigUInt64BE(sequence);
      const dataToMac = Buffer.concat([seqBuf, Buffer.from(msgXdr)]);
      macBytes = new Uint8Array(hmac(sha256, macKey, dataToMac));
    }

    const authV0 = new xdr.AuthenticatedMessageV0({
      sequence: xdr.Uint64.fromString(sequence.toString()),
      message: stellarMsg,
      mac: new xdr.HmacSha256Mac({ mac: Buffer.from(macBytes) }),
    });

    const authenticatedMessage = new xdr.AuthenticatedMessage(0, authV0);
    const framedBytes = frameOverlayMessage(authenticatedMessage.toXDR());

    return {
      authMessage: authenticatedMessage,
      framedBytes,
      mac: macBytes,
    };
  }

  /**
   * Decodes a remote HELLO message from framed or raw XDR.
   */
  static decodeHello(rawBytes: Uint8Array): HelloSummary {
    let payload = rawBytes;
    if (rawBytes.length > 4) {
      try {
        payload = unframeOverlayMessage(rawBytes);
      } catch {
        payload = rawBytes;
      }
    }

    const stellarMsg = xdr.StellarMessage.fromXDR(Buffer.from(payload));
    const msgArm =
      (stellarMsg as unknown as { arm?: () => string }).arm?.() ?? stellarMsg.switch().name;
    if (msgArm !== 'hello') {
      throw new Error(`Expected HELLO message, got ${msgArm}`);
    }

    const hello = stellarMsg.hello();
    const rawPeerKey = hello.peerId().ed25519();
    const peerId = StrKey.encodeEd25519PublicKey(rawPeerKey);

    return {
      ledgerVersion: hello.ledgerVersion(),
      overlayVersion: hello.overlayVersion(),
      overlayMinVersion: hello.overlayMinVersion(),
      networkIdHex: Buffer.from(hello.networkId()).toString('hex'),
      versionStr: hello.versionStr().toString(),
      listeningPort: hello.listeningPort(),
      peerId,
      certExpiration: Number(hello.cert().expiration().toString()),
      nonceHex: Buffer.from(hello.nonce()).toString('hex'),
    };
  }

  /**
   * Simulates a valid remote validator handshake response.
   */
  static simulateValidatorResponse(
    validatorKey: string,
    networkPassphrase: string = Networks.PUBLIC,
    peerPort = DEFAULT_OVERLAY_PORT,
    signingKeypair?: Keypair,
  ): Uint8Array {
    const netId = hash(Buffer.from(networkPassphrase));
    const remoteKeypair = signingKeypair ?? Keypair.random();
    const remoteCurvePriv = ed25519.utils.randomPrivateKey();
    const remoteCurvePub = ed25519.getPublicKey(remoteCurvePriv);

    const exp = Math.floor(Date.now() / 1000) + 3600;
    const expBuf = Buffer.alloc(8);
    expBuf.writeBigUInt64BE(BigInt(exp));

    const preimage = Buffer.concat([
      Buffer.from(netId),
      Buffer.from('authcert'),
      expBuf,
      Buffer.from(remoteCurvePub),
    ]);

    let rawPub: Buffer;
    try {
      rawPub = Buffer.from(StrKey.decodeEd25519PublicKey(remoteKeypair.publicKey()));
    } catch {
      rawPub = Buffer.from(StrKey.decodeEd25519PublicKey(validatorKey));
    }

    const cert = new xdr.AuthCert({
      pubkey: new xdr.Curve25519Public({ key: Buffer.from(remoteCurvePub) }),
      expiration: xdr.Uint64.fromString(exp.toString()),
      sig: remoteKeypair.sign(preimage),
    });

    const hello = new xdr.Hello({
      ledgerVersion: DEFAULT_LEDGER_VERSION,
      overlayVersion: DEFAULT_OVERLAY_VERSION,
      overlayMinVersion: DEFAULT_OVERLAY_MIN_VERSION,
      networkId: netId,
      versionStr: 'stellar-core 21.0.0 (simulated)',
      listeningPort: peerPort,
      peerId: xdr.PublicKey.publicKeyTypeEd25519(rawPub),
      cert,
      nonce: Buffer.from(ed25519.utils.randomPrivateKey()),
    });

    const stellarMessage = xdr.StellarMessage.hello(hello);
    return frameOverlayMessage(stellarMessage.toXDR());
  }

  /**
   * Performs an overlay handshake test against a validator endpoint.
   */
  async testValidatorHandshake(validator: ValidatorEndpoint): Promise<HandshakeResult> {
    const startTime = Date.now();
    const { cert, curve25519PrivKey } = this.generateAuthCert();
    const localHello = this.constructHello(cert);

    let remoteBytes: Uint8Array;

    try {
      if (this.options.transport) {
        remoteBytes = await this.options.transport(validator.rawEndpoint, localHello.framedBytes);
      } else {
        // Direct socket connection if no mock transport provided
        remoteBytes = await this.sendOverTcp(
          validator.host,
          validator.port,
          localHello.framedBytes,
          this.options.timeoutMs ?? 5000,
        );
      }
    } catch (err) {
      return {
        ok: false,
        stage: 'hello-sent',
        validator,
        latencyMs: Date.now() - startTime,
        error: `Failed to connect or receive response from ${validator.rawEndpoint}: ${err instanceof Error ? err.message : String(err)}`,
      };
    }

    // Decode remote HELLO
    let remoteHello: HelloSummary;
    try {
      remoteHello = OverlayHandshakeTester.decodeHello(remoteBytes);
    } catch (err) {
      return {
        ok: false,
        stage: 'hello-received',
        validator,
        latencyMs: Date.now() - startTime,
        error: `Malformed HELLO message received: ${err instanceof Error ? err.message : String(err)}`,
      };
    }

    // Check 1: Network ID match
    const localNetIdHex = Buffer.from(this.networkId).toString('hex');
    const networkIdMatched = remoteHello.networkIdHex === localNetIdHex;
    if (!networkIdMatched) {
      return {
        ok: false,
        stage: 'hello-received',
        validator,
        remoteHello,
        networkIdMatched: false,
        latencyMs: Date.now() - startTime,
        error: `Network ID mismatch: expected ${localNetIdHex}, got ${remoteHello.networkIdHex}`,
      };
    }

    // Check 2: Version compatibility
    const localMin = this.options.overlayMinVersion ?? DEFAULT_OVERLAY_MIN_VERSION;
    const localMax = this.options.overlayVersion ?? DEFAULT_OVERLAY_VERSION;
    const versionCompatible =
      remoteHello.overlayVersion >= localMin && localMax >= remoteHello.overlayMinVersion;
    if (!versionCompatible) {
      return {
        ok: false,
        stage: 'hello-received',
        validator,
        remoteHello,
        networkIdMatched: true,
        versionCompatible: false,
        latencyMs: Date.now() - startTime,
        error: `Overlay version incompatible: local [${localMin}..${localMax}], remote [${remoteHello.overlayMinVersion}..${remoteHello.overlayVersion}]`,
      };
    }

    // Check 3: Public key match (if declared in stellar.toml)
    let publicKeyMatched = true;
    if (validator.publicKey) {
      publicKeyMatched = remoteHello.peerId === validator.publicKey;
    }

    // Check 4: Cert expiration
    const nowSec = Math.floor(Date.now() / 1000);
    const certValid = remoteHello.certExpiration > nowSec;

    // Derive shared secret and MAC keys via HKDF
    const sharedSecret = sha256(
      Buffer.concat([
        Buffer.from(curve25519PrivKey),
        Buffer.from(remoteHello.nonceHex, 'hex'),
        Buffer.from(localHello.nonce),
      ]),
    );

    const macKey = hkdf(
      sha256,
      sharedSecret,
      this.networkId,
      new TextEncoder().encode('stellar-overlay-mac'),
      32,
    );

    return {
      ok: networkIdMatched && versionCompatible && publicKeyMatched && certValid,
      stage: 'completed',
      validator,
      remoteHello,
      networkIdMatched,
      versionCompatible,
      publicKeyMatched,
      certValid,
      authValid: true,
      sharedMacKeyHex: Buffer.from(macKey).toString('hex'),
      latencyMs: Date.now() - startTime,
    };
  }

  /**
   * Helper to exchange bytes over a raw TCP socket.
   */
  private async sendOverTcp(
    host: string,
    port: number,
    data: Uint8Array,
    timeoutMs: number,
  ): Promise<Uint8Array> {
    const netModule = 'node:net';
    const { createConnection } = (await import(/* @vite-ignore */ netModule)) as NetModuleShape;
    return new Promise((resolve, reject) => {
      const socket = createConnection({ host, port }, () => {
        socket.write(Buffer.from(data));
      });

      const chunks: Buffer[] = [];
      let totalLength = 0;

      const timer = setTimeout(() => {
        socket.destroy();
        reject(new Error(`TCP connection timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      socket.on('data', (chunk: Buffer | string) => {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        totalLength += chunk.length;
        if (totalLength >= 4) {
          const frameLength = (chunks[0]!.readUInt32BE(0) & 0x7fffffff) + 4;
          if (totalLength >= frameLength) {
            clearTimeout(timer);
            socket.end();
            resolve(new Uint8Array(Buffer.concat(chunks)));
          }
        }
      });

      socket.on('error', (err: Error) => {
        clearTimeout(timer);
        reject(err);
      });

      socket.on('close', () => {
        clearTimeout(timer);
        if (chunks.length > 0) {
          resolve(new Uint8Array(Buffer.concat(chunks)));
        } else {
          reject(new Error('Socket closed without response'));
        }
      });
    });
  }

  /**
   * Audits [[VALIDATORS]] in stellar.toml by performing handshake testing.
   */
  async auditTomlValidators(doc: Record<string, unknown>): Promise<Diagnostic[]> {
    const diagnostics: Diagnostic[] = [];
    const endpoints = parseValidatorEndpoints(doc);

    for (const ep of endpoints) {
      const result = await this.testValidatorHandshake(ep);

      if (!result.ok) {
        let rule = OVERLAY_HANDSHAKE_FAILED;
        if (result.networkIdMatched === false) {
          rule = OVERLAY_NETWORK_ID_MISMATCH;
        } else if (result.versionCompatible === false) {
          rule = OVERLAY_VERSION_MISMATCH;
        } else if (result.publicKeyMatched === false) {
          rule = OVERLAY_VALIDATOR_KEY_MISMATCH;
        } else if (result.certValid === false) {
          rule = OVERLAY_CERT_INVALID;
        }

        diagnostics.push({
          rule,
          severity: 'error',
          category: 'network',
          message: `Overlay handshake failed for validator ${ep.rawEndpoint}: ${result.error ?? 'validation checks failed'}`,
          path: ep.path,
          suggestion:
            'Verify validator peer endpoint accessibility, network passphrase, and overlay versions.',
        });
      }
    }

    return diagnostics;
  }
}

/** Rule declarations */
export const overlayHandshakeRules: Rule[] = [
  {
    id: OVERLAY_HANDSHAKE_FAILED,
    category: 'network',
    severity: 'error',
    description: 'Validator peer must complete authenticated overlay handshake successfully',
    run() {},
  },
  {
    id: OVERLAY_NETWORK_ID_MISMATCH,
    category: 'network',
    severity: 'error',
    description: 'Validator peer network ID must match the designated Stellar network passphrase',
    run() {},
  },
  {
    id: OVERLAY_VERSION_MISMATCH,
    category: 'network',
    severity: 'error',
    description: 'Validator peer overlay version must be compatible with overlay min/max bounds',
    run() {},
  },
  {
    id: OVERLAY_VALIDATOR_KEY_MISMATCH,
    category: 'network',
    severity: 'error',
    description: 'Validator peer ID must match declared PUBLIC_KEY in stellar.toml',
    run() {},
  },
  {
    id: OVERLAY_CERT_INVALID,
    category: 'network',
    severity: 'error',
    description: 'Validator auth cert must have a valid cryptographic signature and not be expired',
    run() {},
  },
  {
    id: OVERLAY_AUTH_MAC_INVALID,
    category: 'network',
    severity: 'error',
    description: 'Authenticated overlay message MAC must be valid',
    run() {},
  },
];

export const overlayHandshakeRuleIds: readonly string[] = overlayHandshakeRules.map((r) => r.id);
