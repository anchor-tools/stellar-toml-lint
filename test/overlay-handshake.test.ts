import { describe, expect, it } from 'vitest';
import { createServer, type AddressInfo, type Server, type Socket } from 'node:net';
import { createHash } from 'node:crypto';
import { StrKey } from '@stellar/stellar-base';
import { ed25519 } from '@noble/curves/ed25519';
import { allRules } from '../src/rules/index.js';
import {
  authCert,
  authCertDigest,
  authCertPreimage,
  checkOverlayHandshake,
  decodeAuthenticatedMessage,
  decodeStellarMessage,
  deriveMacKeys,
  deriveSharedMacKey,
  encodeAuthenticatedMessage,
  encodeAuth,
  encodeHello,
  encodeOverlayFrame,
  ENVELOPE_TYPE_AUTH,
  failureFindings,
  generateEphemeralIdentity,
  helloFindings,
  macSigningInput,
  networkIdForPassphrase,
  OVERLAY_AUTH_FLOW_CONTROL_FLAGS,
  OVERLAY_FRAME_CONTINUATION_BIT,
  OVERLAY_MAC_BYTES,
  OVERLAY_PROTOCOL_VERSION,
  OVERLAY_UNAUTHENTICATED_SEQUENCE,
  overlayFrameLength,
  overlayHandshakeRuleIds,
  overlayMac,
  sharedSecret,
  signedAuthCert,
  validatorEndpoints,
  verifyAuthCert,
  verifyOverlayMac,
  type PeerHello,
  type ValidatorEndpoint,
} from '../src/overlay/handshake.js';
import type { RuleOverrides } from '../src/types.js';
import {
  performOverlayHandshake,
  respondAsOverlayPeer,
  type MockPeerOptions,
} from '../src/overlay/handshake-socket.js';
import { frameOverlayMessage } from '../src/overlay/crawler.js';

const TIMEOUT = 'overlay/handshake-timeout';
const NETWORK = 'overlay/network-mismatch';
const IDENTITY = 'overlay/public-key-mismatch';
const VERSION = 'overlay/protocol-version-outdated';

const MAINNET = 'Public Global Stellar Network ; September 2015';
const TESTNET = 'Test SDF Network ; September 2015';
const PRIVATE_NET = 'Private Anchor Net ; March 2026';

/** Deterministic node keys, so an identity finding names a reproducible peer. */
function keypair(byte: number): { secret: Uint8Array; id: string } {
  const secret = new Uint8Array(32).fill(byte);
  return { secret, id: StrKey.encodeEd25519PublicKey(Buffer.from(ed25519.getPublicKey(secret))) };
}

const NODE = keypair(1);
const OTHER = keypair(2);

function endpoint(host = '127.0.0.1:11625', publicKey = NODE.id): ValidatorEndpoint {
  const [address, port] = host.split(':');
  return {
    index: 0,
    path: 'VALIDATORS[0]',
    alias: 'Node A',
    publicKey,
    host: address ?? '',
    port: Number(port),
  };
}

/** What an up-to-date, correctly configured validator announces. */
function announcement(port: number, overrides: Partial<PeerHello> = {}): Omit<PeerHello, 'peerId'> {
  return {
    ledgerVersion: 21,
    overlayVersion: OVERLAY_PROTOCOL_VERSION,
    overlayMinVersion: 12,
    networkId: networkIdForPassphrase(MAINNET),
    versionStr: 'v21.4.0-release_5e21b45',
    listeningPort: port,
    ...overrides,
  };
}

function file(host: string, passphrase = MAINNET): Record<string, unknown> {
  return {
    NETWORK_PASSPHRASE: passphrase,
    VALIDATORS: [{ ALIAS: 'Node A', PUBLIC_KEY: NODE.id, HOST: host }],
  };
}

function rulesOf(diagnostics: { rule: string }[]): string[] {
  return diagnostics.map((one) => one.rule);
}

interface Mock {
  port: number;
  close: () => Promise<void>;
}

/**
 * A listener that speaks the peer half of the handshake. `build` receives the
 * port the peer should advertise, which is how a test creates a listening port
 * that disagrees with the published `HOST`.
 */
async function listen(
  build: (port: number) => MockPeerOptions,
  options: { network?: string; peerId?: string } = {},
): Promise<Mock> {
  const sockets = new Set<Socket>();
  let port = 0;
  const server: Server = createServer((socket) => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
    void respondAsOverlayPeer(
      socket,
      build(port),
      networkIdForPassphrase(options.network ?? MAINNET),
      options.peerId ?? NODE.id,
    );
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  port = (server.address() as AddressInfo).port;

  return {
    port,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

/** Dials a mock listener with the real transport, then lints what came back. */
async function lint(
  build: (port: number) => MockPeerOptions,
  options: { rules?: RuleOverrides; passphrase?: string; timeoutMs?: number } = {},
): ReturnType<typeof checkOverlayHandshake> {
  const mock = await listen(build);
  try {
    return await checkOverlayHandshake(file(`127.0.0.1:${mock.port}`, options.passphrase), {
      timeoutMs: options.timeoutMs ?? 2_000,
      ...(options.rules === undefined ? {} : { rules: options.rules }),
    });
  } finally {
    await mock.close();
  }
}

describe('overlay handshake', () => {
  it('accepts a peer that signs the published identity on the published network', async () => {
    const diagnostics = await checkOverlayHandshake(file('127.0.0.1:11625'), {
      transport: async (one) => ({
        endpoint: one,
        hello: { ...announcement(one.port), peerId: NODE.id },
      }),
    });

    expect(diagnostics).toEqual([]);
  });

  it('reports a peer that answers for a different node ID', async () => {
    const diagnostics = await checkOverlayHandshake(file('127.0.0.1:11625'), {
      transport: async (one) => ({
        endpoint: one,
        hello: { ...announcement(one.port), peerId: OTHER.id },
      }),
    });

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      rule: IDENTITY,
      severity: 'error',
      path: 'VALIDATORS[0].PUBLIC_KEY',
    });
    expect(diagnostics[0]?.message).toContain(OTHER.id);
  });

  it('reports a peer on another network and stops comparing what it said', async () => {
    const diagnostics = await checkOverlayHandshake(file('127.0.0.1:11625'), {
      transport: async (one) => ({
        endpoint: one,
        hello: {
          ...announcement(one.port, {
            networkId: networkIdForPassphrase(TESTNET),
            overlayVersion: 4,
            listeningPort: 1,
          }),
          peerId: NODE.id,
        },
      }),
    });

    expect(rulesOf(diagnostics)).toEqual([NETWORK]);
    expect(diagnostics[0]?.message).toContain('different network');
  });

  it('warns when a peer cannot speak the current protocol version', async () => {
    const diagnostics = await checkOverlayHandshake(file('127.0.0.1:11625'), {
      transport: async (one) => ({
        endpoint: one,
        hello: { ...announcement(one.port, { overlayVersion: 20 }), peerId: NODE.id },
      }),
    });

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({ rule: VERSION, severity: 'warning' });
    expect(diagnostics[0]?.suggestion).toContain('v21.4.0-release_5e21b45');
  });

  it('flags a listening port that disagrees with the published HOST', async () => {
    const diagnostics = await checkOverlayHandshake(file('127.0.0.1:11625'), {
      transport: async (one) => ({
        endpoint: one,
        hello: { ...announcement(one.port + 1), peerId: NODE.id },
      }),
    });

    expect(rulesOf(diagnostics)).toEqual([NETWORK]);
    expect(diagnostics[0]?.message).toContain('listens on port');
  });

  it('reports a handshake that never completed, naming the peer', async () => {
    const diagnostics = await checkOverlayHandshake(file('127.0.0.1:11625'), {
      transport: async (one) => ({ endpoint: one, failure: 'timeout', detail: 'no reply' }),
    });

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({ rule: TIMEOUT, severity: 'error' });
    expect(diagnostics[0]?.message).toContain('Node A');
    expect(diagnostics[0]?.message).toContain('no reply');
    expect(diagnostics[0]?.message).toContain('before the timeout');
  });

  it('tells an unreachable port apart from a peer that went quiet', async () => {
    const unreachable = await checkOverlayHandshake(file('127.0.0.1:11625'), {
      transport: async (one) => ({ endpoint: one, failure: 'unreachable' }),
    });
    const stalled = await checkOverlayHandshake(file('127.0.0.1:11625'), {
      transport: async (one) => ({ endpoint: one, failure: 'protocol' }),
    });

    expect(unreachable[0]?.suggestion).toContain('Nothing is listening');
    expect(stalled[0]?.suggestion).toContain('firewall');
  });

  it('honours rule overrides on every handshake finding', async () => {
    const suppressed = await checkOverlayHandshake(file('127.0.0.1:11625'), {
      rules: { [TIMEOUT]: 'off' },
      transport: async (one) => ({ endpoint: one, failure: 'timeout' }),
    });
    const downgraded = await checkOverlayHandshake(file('127.0.0.1:11625'), {
      rules: { [IDENTITY]: 'warning' },
      transport: async (one) => ({
        endpoint: one,
        hello: { ...announcement(one.port), peerId: OTHER.id },
      }),
    });

    expect(suppressed).toEqual([]);
    expect(downgraded[0]).toMatchObject({ rule: IDENTITY, severity: 'warning' });
  });

  it('says nothing about a file that declares no dialable validator', async () => {
    const diagnostics = await checkOverlayHandshake(
      {
        NETWORK_PASSPHRASE: MAINNET,
        VALIDATORS: [
          { PUBLIC_KEY: NODE.id },
          { HOST: 'relay.example.com' },
          { HOST: 'relay.example.com:11625' },
        ],
      },
      { transport: async () => ({ endpoint: endpoint(), failure: 'unreachable' }) },
    );

    expect(diagnostics).toEqual([]);
  });

  it('dials a real socket and authenticates the AUTH echo end to end', async () => {
    const mock = await listen((port) => ({ hello: announcement(port), nodePrivate: NODE.secret }));

    try {
      const outcome = await performOverlayHandshake(endpoint(`127.0.0.1:${mock.port}`), {
        passphrase: MAINNET,
        timeoutMs: 2_000,
      });

      expect(outcome.failure).toBeUndefined();
      expect(outcome.hello?.peerId).toBe(NODE.id);
      expect(outcome.hello?.versionStr).toBe('v21.4.0-release_5e21b45');
      expect(outcome.authenticated).toBe(true);
    } finally {
      await mock.close();
    }
  });

  it('reports a peer whose HELLO is not signed by the identity it announces', async () => {
    const diagnostics = await lint((port) => ({
      hello: announcement(port),
      nodePrivate: OTHER.secret,
      peerId: NODE.id,
    }));

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({ rule: IDENTITY, severity: 'error' });
    expect(diagnostics[0]?.message).toContain('could not sign');
  });

  it('reports a listener that answers with something other than a StellarMessage', async () => {
    const diagnostics = await lint((port) => ({
      hello: announcement(port),
      nodePrivate: NODE.secret,
      garbage: true,
    }));

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({ rule: TIMEOUT });
    expect(diagnostics[0]?.message).toContain('not a StellarMessage');
  });

  it('reports a listener that hangs up mid-handshake', async () => {
    const diagnostics = await lint((port) => ({
      hello: announcement(port),
      nodePrivate: NODE.secret,
      hangUp: true,
    }));

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.message).toContain('closed the connection');
  });

  it('reports a listener that never answers within the timeout', async () => {
    const diagnostics = await lint(
      (port) => ({ hello: announcement(port), nodePrivate: NODE.secret, silent: true }),
      { timeoutMs: 250 },
    );

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({ rule: TIMEOUT });
    expect(diagnostics[0]?.message).toContain('before the timeout');
  });

  it('reports a port with nothing listening behind it', async () => {
    const mock = await listen((port) => ({ hello: announcement(port), nodePrivate: NODE.secret }));
    const port = mock.port;
    await mock.close();

    const diagnostics = await checkOverlayHandshake(file(`127.0.0.1:${port}`), {
      timeoutMs: 2_000,
    });

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.message).toContain('did not complete');
    expect(diagnostics[0]?.suggestion).toContain('Nothing is listening');
  });

  it('treats an echo it cannot authenticate as negotiation that did not happen', async () => {
    const mock = await listen((port) => ({
      hello: announcement(port),
      nodePrivate: NODE.secret,
      tamper: true,
    }));

    try {
      const outcome = await performOverlayHandshake(endpoint(`127.0.0.1:${mock.port}`), {
        passphrase: MAINNET,
        timeoutMs: 2_000,
      });

      expect(outcome.hello?.peerId).toBe(NODE.id);
      expect(outcome.failure).toBeUndefined();
      expect(outcome.authenticated).toBe(false);
    } finally {
      await mock.close();
    }
  });

  it('treats a peer that answers HELLO and then goes quiet as no negotiation', async () => {
    const mock = await listen((port) => ({
      hello: announcement(port),
      nodePrivate: NODE.secret,
      silentEcho: true,
    }));

    try {
      const outcome = await performOverlayHandshake(endpoint(`127.0.0.1:${mock.port}`), {
        passphrase: MAINNET,
        timeoutMs: 400,
      });

      expect(outcome.hello?.peerId).toBe(NODE.id);
      expect(outcome.failure).toBeUndefined();
      expect(outcome.authenticated).toBeUndefined();
    } finally {
      await mock.close();
    }
  });

  it('lints a live socket against a file naming another network', async () => {
    const diagnostics = await lint(
      (port) => ({ hello: announcement(port), nodePrivate: NODE.secret }),
      {
        passphrase: PRIVATE_NET,
      },
    );

    expect(rulesOf(diagnostics)).toEqual([NETWORK]);
  });

  it('keeps every validator in the file in its own finding path', async () => {
    const mock = await listen((port) => ({
      hello: announcement(port),
      nodePrivate: OTHER.secret,
      peerId: OTHER.id,
    }));

    try {
      const diagnostics = await checkOverlayHandshake(
        {
          NETWORK_PASSPHRASE: MAINNET,
          VALIDATORS: [
            { ALIAS: 'Node A', PUBLIC_KEY: NODE.id, HOST: `127.0.0.1:${mock.port}` },
            { ALIAS: 'Node B', PUBLIC_KEY: 'GBOGUS', HOST: 'nowhere.invalid:11625' },
          ],
        },
        { timeoutMs: 2_000 },
      );

      expect(diagnostics.map((one) => one.path)).toEqual([
        'VALIDATORS[0].PUBLIC_KEY',
        'VALIDATORS[1].HOST',
      ]);
    } finally {
      await mock.close();
    }
  });
});

describe('overlay handshake messages', () => {
  it('round-trips a HELLO through the wire format', () => {
    const identity = generateEphemeralIdentity();
    const networkId = networkIdForPassphrase(MAINNET);
    const encoded = encodeHello({
      ledgerVersion: 21,
      overlayVersion: OVERLAY_PROTOCOL_VERSION,
      overlayMinVersion: 12,
      networkId,
      versionStr: 'v21.4.0',
      listeningPort: 11625,
      nodePublic: identity.nodePublic,
      cert: signedAuthCert(identity, 1_800_000_000, networkId),
      nonce: new Uint8Array(32).fill(9),
    });

    const decoded = decodeStellarMessage(encoded);

    expect(decoded?.type).toBe('hello');
    if (decoded === undefined || decoded.type !== 'hello') return;
    expect(decoded.hello.versionStr).toBe('v21.4.0');
    expect(decoded.hello.peerId).toBe(
      StrKey.encodeEd25519PublicKey(Buffer.from(identity.nodePublic)),
    );
    // The nonce is what the session keys are built from, so it has to survive.
    expect(Buffer.from(decoded.nonce).toString('hex')).toBe('09'.repeat(32));
    expect(verifyAuthCert(decoded.cert, decoded.hello.peerId, networkId)).toBe(true);
  });

  it('rejects a cert signed for another network', () => {
    const identity = generateEphemeralIdentity();
    const cert = signedAuthCert(identity, 1_800_000_000, networkIdForPassphrase(TESTNET));

    expect(
      verifyAuthCert(
        cert,
        StrKey.encodeEd25519PublicKey(Buffer.from(identity.nodePublic)),
        networkIdForPassphrase(MAINNET),
      ),
    ).toBe(false);
  });

  it('rejects a node ID that is not an account key at all', () => {
    const identity = generateEphemeralIdentity();
    const cert = signedAuthCert(identity, 1_800_000_000, networkIdForPassphrase(MAINNET));

    expect(verifyAuthCert(cert, 'not-a-stellar-key', networkIdForPassphrase(MAINNET))).toBe(false);
  });

  it('reads the message types the handshake has to tell apart', () => {
    // DONT_HAVE and ERROR are hand-built because this XDR binding exposes their
    // arms only as static factories, which is how a hostile listener reaches them.
    const dontHave = Buffer.alloc(4 + 4 + 32);
    dontHave.writeUInt32BE(3, 0);
    dontHave.writeUInt32BE(13, 4);
    const rejected = Buffer.concat([
      Buffer.from([0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 5]),
      Buffer.from('TXBAD\0\0\0', 'utf8'),
    ]);

    expect(decodeStellarMessage(encodeAuth())?.type).toBe('auth');
    expect(decodeStellarMessage(dontHave)).toEqual({ type: 'other', name: 'dontHave' });
    expect(decodeStellarMessage(rejected)).toEqual({ type: 'error', message: 'TXBAD' });
    expect(decodeStellarMessage(Buffer.from('not xdr at all', 'utf8'))).toBeUndefined();
    expect(decodeStellarMessage(frameOverlayMessage(encodeAuth()))).toBeUndefined();
  });

  it('names the network the way the ledger does', () => {
    expect(Buffer.from(networkIdForPassphrase(MAINNET)).toString('hex')).toBe(
      createHash('sha256').update(MAINNET, 'utf8').digest('hex'),
    );
  });

  it('reads dialable endpoints out of VALIDATORS, including bracketed IPv6', () => {
    const endpoints = validatorEndpoints({
      VALIDATORS: [
        { ALIAS: 'A', PUBLIC_KEY: NODE.id, HOST: 'validator.example.com:11625' },
        { PUBLIC_KEY: OTHER.id, HOST: '[2001:db8::1]:11626' },
        { PUBLIC_KEY: NODE.id, HOST: 'no-port.example.com' },
        { PUBLIC_KEY: NODE.id, HOST: 'bad-port.example.com:99999' },
        { HOST: 'keyless.example.com:11625' },
        'not a table',
      ],
    });

    expect(endpoints).toHaveLength(2);
    expect(endpoints[1]).toMatchObject({ host: '2001:db8::1', port: 11626, index: 1 });
  });

  it('wraps a message in the envelope the overlay puts on the wire', () => {
    const message = encodeAuth();
    const mac = Buffer.alloc(OVERLAY_MAC_BYTES, 3);
    const envelope = encodeAuthenticatedMessage(message, 7n, mac);

    expect(envelope.length).toBe(12 + message.length + OVERLAY_MAC_BYTES);
    // `AuthenticatedMessage` is a union on a uint32 version, with only a v0 arm.
    expect(envelope.readUInt32BE(0)).toBe(0);
    expect(envelope.readBigUInt64BE(4)).toBe(7n);
    expect(envelope.subarray(12, 12 + message.length).equals(message)).toBe(true);
    // `HmacSha256Mac` is 32 raw bytes: no length prefix, no padding.
    expect(envelope.subarray(envelope.length - OVERLAY_MAC_BYTES).equals(mac)).toBe(true);

    const decoded = decodeAuthenticatedMessage(envelope);
    expect(decoded?.sequence).toBe(7n);
    expect(decoded?.message.equals(message)).toBe(true);
    expect(decoded?.mac.equals(mac)).toBe(true);
  });

  it('sends a HELLO with sequence 0 and a zero MAC, because no key exists yet', () => {
    const unauthenticated = decodeAuthenticatedMessage(
      encodeAuthenticatedMessage(Buffer.from('a hello goes here', 'utf8')),
    );

    expect(unauthenticated?.sequence).toBe(OVERLAY_UNAUTHENTICATED_SEQUENCE);
    expect(unauthenticated?.mac.equals(Buffer.alloc(OVERLAY_MAC_BYTES))).toBe(true);
    expect(
      decodeAuthenticatedMessage(Buffer.from([0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 5])),
    ).toBeUndefined();
  });

  it('sets the continuation bit on a frame header and reads it back off', () => {
    const payload = encodeAuth();
    const frame = encodeOverlayFrame(payload);

    expect(frame.readUInt32BE(0)).toBe((OVERLAY_FRAME_CONTINUATION_BIT | payload.length) >>> 0);
    expect(frame.subarray(4).equals(payload)).toBe(true);
    expect(overlayFrameLength(frame.subarray(0, 4))).toBe(payload.length);
    // A reader that took that header literally would wait for two gigabytes.
    expect(overlayFrameLength(Buffer.from([0x80, 0x00, 0x00, 0x0c]))).toBe(12);
    expect(overlayFrameLength(Buffer.from([0x00, 0x00, 0x00, 0x0c]))).toBe(12);
  });

  it('signs an AuthCert over the network, envelope type, expiry, and key', () => {
    const networkId = networkIdForPassphrase(MAINNET);
    const key = new Uint8Array(32).fill(7);
    const preimage = authCertPreimage(networkId, 1_800_000_000, key);

    expect(preimage.length).toBe(32 + 4 + 8 + 32);
    expect(preimage.subarray(0, 32).equals(Buffer.from(networkId))).toBe(true);
    expect(preimage.readUInt32BE(32)).toBe(ENVELOPE_TYPE_AUTH);
    expect(preimage.readBigUInt64BE(36)).toBe(1_800_000_000n);
    expect(preimage.subarray(44).equals(Buffer.from(key))).toBe(true);
    // stellar-core hashes before signing, so the digest is what the ed25519 sees.
    expect(authCertDigest(networkId, 1_800_000_000, key).toString('hex')).toBe(
      createHash('sha256').update(preimage).digest('hex'),
    );
  });

  it('derives mirrored MAC keys that authenticate one direction each', () => {
    const caller = generateEphemeralIdentity();
    const listener = generateEphemeralIdentity();
    const callerNonce = new Uint8Array(32).fill(1);
    const listenerNonce = new Uint8Array(32).fill(2);
    const theirCurve = Buffer.from(listener.curvePublic);

    // Each side reaches the same key from its own secret and the other's public key.
    const fromCaller = deriveSharedMacKey(
      sharedSecret(caller.curvePrivate, theirCurve),
      caller.curvePublic,
      theirCurve,
    );
    const fromListener = deriveSharedMacKey(
      sharedSecret(listener.curvePrivate, Buffer.from(caller.curvePublic)),
      caller.curvePublic,
      theirCurve,
    );
    expect(fromListener.equals(fromCaller)).toBe(true);

    const sender = deriveMacKeys(fromCaller, callerNonce, listenerNonce, 'initiator');
    const receiver = deriveMacKeys(fromCaller, callerNonce, listenerNonce, 'responder');
    expect(sender.send.equals(receiver.receive)).toBe(true);
    expect(sender.receive.equals(receiver.send)).toBe(true);

    const auth = encodeAuth(OVERLAY_AUTH_FLOW_CONTROL_FLAGS);
    const mac = overlayMac(sender.send, 0n, auth);
    expect(mac.length).toBe(OVERLAY_MAC_BYTES);
    expect(verifyOverlayMac(receiver.receive, 0n, auth, mac)).toBe(true);
    // Direction, sequence, and payload are all covered, so a frame cannot be
    // reflected back at the peer that sent it or reused for the next slot.
    expect(verifyOverlayMac(sender.receive, 0n, auth, mac)).toBe(false);
    expect(verifyOverlayMac(receiver.receive, 1n, auth, mac)).toBe(false);
    expect(verifyOverlayMac(receiver.receive, 0n, encodeAuth(0), mac)).toBe(false);
    expect(macSigningInput(1n, auth).readBigUInt64BE(0)).toBe(1n);
    expect(macSigningInput(1n, auth).subarray(8).equals(auth)).toBe(true);
  });

  it('asks for the flow-control bytes a real peer insists on', () => {
    expect(encodeAuth().readUInt32BE(4)).toBe(OVERLAY_AUTH_FLOW_CONTROL_FLAGS);
    expect(encodeAuth(0).readUInt32BE(4)).toBe(0);
  });

  it('registers its rule ids so --list-rules and --off know them', () => {
    const ids = allRules.map((rule) => rule.id);

    expect(overlayHandshakeRuleIds).toHaveLength(4);
    for (const rule of overlayHandshakeRuleIds) expect(ids).toContain(rule);
  });
});

describe('overlay handshake comparisons', () => {
  const hello = (overrides: Partial<PeerHello> = {}): PeerHello => ({
    ...announcement(11625),
    peerId: NODE.id,
    ...overrides,
  });

  it('skips the version and port questions when the network itself is wrong', () => {
    const diagnostics = helloFindings(endpoint(), hello({ networkId: new Uint8Array(32) }), {
      passphrase: MAINNET,
    });

    expect(rulesOf(diagnostics)).toEqual([NETWORK]);
  });

  it('says nothing when the file gives no network to compare against', () => {
    expect(helloFindings(endpoint(), hello({ networkId: new Uint8Array(32) }))).toEqual([]);
  });

  it('accepts a peer whose minimum version already covers the current one', () => {
    const diagnostics = helloFindings(
      endpoint(),
      hello({
        overlayVersion: OVERLAY_PROTOCOL_VERSION,
        overlayMinVersion: OVERLAY_PROTOCOL_VERSION,
      }),
      { passphrase: MAINNET },
    );

    expect(diagnostics).toEqual([]);
  });

  it('reports a HELLO with the public key it could not prove', () => {
    const diagnostics = failureFindings(
      { endpoint: endpoint(), failure: 'authentication', detail: 'bad signature' },
      { rules: {} },
    );

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({ rule: IDENTITY, path: 'VALIDATORS[0].PUBLIC_KEY' });
    expect(diagnostics[0]?.message).toContain('bad signature');
  });

  it('reports nothing for an outcome that did complete', () => {
    expect(failureFindings({ endpoint: endpoint(), hello: hello() })).toEqual([]);
  });

  it('carries a path and a help link but no invented position', () => {
    const diagnostics = helloFindings(endpoint('127.0.0.1:11625', OTHER.id), hello(), {
      passphrase: MAINNET,
    });

    expect(diagnostics[0]).toMatchObject({ category: 'network', path: 'VALIDATORS[0].PUBLIC_KEY' });
    expect(diagnostics[0]?.helpUri).toContain('overlay-network');
    expect(diagnostics[0]?.position).toBeUndefined();
  });

  it('keeps the expiry the signature covers inside the cert', () => {
    const cert = authCert(new Uint8Array(32).fill(4), 1_800_000_000);

    expect(Number(cert.expiration().toString())).toBe(1_800_000_000);
    expect(Buffer.from(cert.pubkey().key() as Uint8Array).toString('hex')).toContain('0404');
  });
});
