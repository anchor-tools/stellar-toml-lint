import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { StrKey } from '@stellar/stellar-base';
import {
  checkOverlayCipher,
  cipherNonce,
  deriveCipherKeys,
  encodePeerAddressRequest,
  openFrame,
  OVERLAY_CIPHER_NEGOTIATION_FAILED_RULE,
  OVERLAY_MAC_TAG_MISMATCH_RULE,
  sealFrame,
  type CipherChannel,
  type CipherChannelFactory,
} from '../../src/overlay/cipher-verifier.js';
import {
  authCert,
  decodeAuthenticatedMessage,
  decodeStellarMessage,
  encodeAuth,
  encodeAuthenticatedMessage,
  encodeHello,
  generateEphemeralIdentity,
  networkIdForPassphrase,
  sharedSecret,
  signedAuthCert,
} from '../../src/overlay/handshake.js';

const PASSPHRASE = 'Test SDF Network ; September 2015';
const NETWORK_ID = networkIdForPassphrase(PASSPHRASE);

/** How the mock peer misbehaves, if at all. */
type Behaviour =
  | 'valid'
  | 'corrupt-tag'
  | 'replay-sequence'
  | 'wrong-key'
  | 'bad-cert'
  | 'expired-cert'
  | 'plaintext'
  | 'silent';

/**
 * A responder that speaks the sealed overlay session over an in-memory
 * channel: it answers our HELLO with its own, derives keys as the responder,
 * opens our sealed request, and seals a response.
 */
function mockPeer(behaviour: Behaviour): { factory: CipherChannelFactory; received: string[] } {
  const received: string[] = [];
  const factory: CipherChannelFactory = async () => {
    const identity = generateEphemeralIdentity();
    const nonce = randomBytes(32);
    const now = Math.floor(Date.now() / 1000);
    const outbox: Uint8Array[] = [];
    let initiator: { curve: Uint8Array; nonce: Uint8Array } | undefined;
    let keys: ReturnType<typeof deriveCipherKeys> | undefined;

    const channel: CipherChannel = {
      async send(payload) {
        if (initiator === undefined) {
          const envelope = decodeAuthenticatedMessage(payload);
          const hello = envelope && decodeStellarMessage(envelope.message);
          if (hello?.type !== 'hello') throw new Error('expected HELLO');
          initiator = {
            curve: Buffer.from(hello.cert.pubkey().key() as Uint8Array),
            nonce: hello.nonce,
          };
          const cert =
            behaviour === 'bad-cert'
              ? authCert(identity.curvePublic, now + 600, new Uint8Array(64).fill(7))
              : signedAuthCert(
                  identity,
                  behaviour === 'expired-cert' ? now - 10 : now + 600,
                  NETWORK_ID,
                );
          outbox.push(
            encodeAuthenticatedMessage(
              encodeHello({
                ledgerVersion: 29,
                overlayVersion: 42,
                overlayMinVersion: 41,
                networkId: NETWORK_ID,
                versionStr: 'mock-core',
                listeningPort: 11625,
                nodePublic: identity.nodePublic,
                cert,
                nonce,
              }),
            ),
          );
          keys = deriveCipherKeys({
            dhSecret: sharedSecret(identity.curvePrivate, initiator.curve),
            initiatorCurvePublic: initiator.curve,
            responderCurvePublic: identity.curvePublic,
            initiatorNonce: initiator.nonce,
            responderNonce: nonce,
            role: 'responder',
          });
          return;
        }

        const opened = await openFrame((keys as NonNullable<typeof keys>).receive, 0n, payload);
        received.push(
          opened.ok ? `sealed ${decodeStellarMessage(opened.message)?.type}` : 'garbage',
        );
        if (behaviour === 'silent') return;
        if (behaviour === 'plaintext') {
          outbox.push(encodeAuthenticatedMessage(encodeAuth()));
          return;
        }
        const sendKey =
          behaviour === 'wrong-key' ? randomBytes(32) : (keys as NonNullable<typeof keys>).send;
        const sequence = behaviour === 'replay-sequence' ? 1n : 0n;
        const response = await sealFrame(sendKey, sequence, encodePeerAddressRequest());
        if (behaviour === 'corrupt-tag') {
          response[response.length - 1] = (response[response.length - 1] as number) ^ 0x01;
        }
        outbox.push(response);
      },
      async receive() {
        const next = outbox.shift();
        if (next === undefined) throw new Error('no overlay frame within 5000ms');
        return next;
      },
      close() {},
    };
    return channel;
  };
  return { factory, received };
}

function document(publicKey = StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 1))) {
  return {
    NETWORK_PASSPHRASE: PASSPHRASE,
    VALIDATORS: [{ ALIAS: 'mock', PUBLIC_KEY: publicKey, HOST: 'core.example.com:11625' }],
  };
}

describe('cipher primitives', () => {
  it('derives mirrored directional keys', () => {
    const a = generateEphemeralIdentity();
    const b = generateEphemeralIdentity();
    const nonces = { initiatorNonce: randomBytes(32), responderNonce: randomBytes(32) };
    const initiator = deriveCipherKeys({
      dhSecret: sharedSecret(a.curvePrivate, b.curvePublic),
      initiatorCurvePublic: a.curvePublic,
      responderCurvePublic: b.curvePublic,
      ...nonces,
      role: 'initiator',
    });
    const responder = deriveCipherKeys({
      dhSecret: sharedSecret(b.curvePrivate, a.curvePublic),
      initiatorCurvePublic: a.curvePublic,
      responderCurvePublic: b.curvePublic,
      ...nonces,
      role: 'responder',
    });
    expect(initiator.send.equals(responder.receive)).toBe(true);
    expect(initiator.receive.equals(responder.send)).toBe(true);
    expect(initiator.send.equals(initiator.receive)).toBe(false);
    expect(initiator.send).toHaveLength(32);
  });

  it('seals and opens a frame, and binds it to its sequence', async () => {
    const key = randomBytes(32);
    const message = encodePeerAddressRequest();
    const sealed = await sealFrame(key, 7n, message);
    expect(cipherNonce(7n).toString('hex')).toBe('000000000000000000000007');

    const opened = await openFrame(key, 7n, sealed);
    expect(opened.ok && opened.message.equals(message)).toBe(true);

    const replayed = await openFrame(key, 8n, sealed);
    expect(replayed).toMatchObject({ ok: false, reason: 'tag' });
    if (!replayed.ok) expect(replayed.detail).toContain('replayed or desynchronised');

    expect(await openFrame(key, 7n, sealed.subarray(0, 20))).toMatchObject({
      ok: false,
      reason: 'malformed',
    });
  });
});

describe('checkOverlayCipher', () => {
  it('passes a peer responding with valid encrypted frames', async () => {
    const { factory, received } = mockPeer('valid');
    expect(await checkOverlayCipher(document(), { channelFactory: factory })).toEqual([]);
    // The peer could open our sealed request under the keys it derived.
    expect(received).toEqual(['sealed other']);
  });

  it('reports a corrupted MAC tag as overlay/mac-tag-mismatch', async () => {
    const { factory } = mockPeer('corrupt-tag');
    const diagnostics = await checkOverlayCipher(document(), { channelFactory: factory });
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      rule: OVERLAY_MAC_TAG_MISMATCH_RULE,
      severity: 'error',
      path: 'VALIDATORS[0].HOST',
    });
  });

  it('reports a desynchronised sequence number as a tag mismatch', async () => {
    const { factory } = mockPeer('replay-sequence');
    const diagnostics = await checkOverlayCipher(document(), { channelFactory: factory });
    expect(diagnostics.map((d) => d.rule)).toEqual([OVERLAY_MAC_TAG_MISMATCH_RULE]);
    expect(diagnostics[0]?.message).toContain('claims sequence 1');
  });

  it('reports frames sealed under the wrong key', async () => {
    const { factory } = mockPeer('wrong-key');
    const diagnostics = await checkOverlayCipher(document(), { channelFactory: factory });
    expect(diagnostics.map((d) => d.rule)).toEqual([OVERLAY_MAC_TAG_MISMATCH_RULE]);
  });

  it('reports an AuthCert the node cannot sign for as a negotiation failure', async () => {
    const { factory } = mockPeer('bad-cert');
    const diagnostics = await checkOverlayCipher(document(), { channelFactory: factory });
    expect(diagnostics.map((d) => d.rule)).toEqual([OVERLAY_CIPHER_NEGOTIATION_FAILED_RULE]);
    expect(diagnostics[0]?.message).toContain('AuthCert is not signed');
  });

  it('reports an expired AuthCert as a negotiation failure', async () => {
    const { factory } = mockPeer('expired-cert');
    const diagnostics = await checkOverlayCipher(document(), { channelFactory: factory });
    expect(diagnostics.map((d) => d.rule)).toEqual([OVERLAY_CIPHER_NEGOTIATION_FAILED_RULE]);
    expect(diagnostics[0]?.message).toContain('expired');
  });

  it('stays silent for peers that do not engage with the sealed session', async () => {
    for (const behaviour of ['plaintext', 'silent'] as const) {
      const { factory } = mockPeer(behaviour);
      expect(await checkOverlayCipher(document(), { channelFactory: factory })).toEqual([]);
    }
    const unreachable: CipherChannelFactory = async () => {
      throw new Error('ECONNREFUSED');
    };
    expect(await checkOverlayCipher(document(), { channelFactory: unreachable })).toEqual([]);
  });

  it('honours rule overrides', async () => {
    const { factory } = mockPeer('corrupt-tag');
    expect(
      await checkOverlayCipher(document(), {
        channelFactory: factory,
        rules: { [OVERLAY_MAC_TAG_MISMATCH_RULE]: 'off' },
      }),
    ).toEqual([]);
    const warned = await checkOverlayCipher(document(), {
      channelFactory: mockPeer('corrupt-tag').factory,
      rules: { [OVERLAY_MAC_TAG_MISMATCH_RULE]: 'warning' },
    });
    expect(warned[0]?.severity).toBe('warning');
  });

  it('does nothing without [[VALIDATORS]]', async () => {
    const { factory } = mockPeer('corrupt-tag');
    expect(await checkOverlayCipher({}, { channelFactory: factory })).toEqual([]);
  });
});
