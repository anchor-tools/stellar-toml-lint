import { describe, expect, it } from 'vitest';
import {
  OverlayHandshakeTester,
  overlayHandshakeRules,
  overlayHandshakeRuleIds,
  parseValidatorEndpoints,
  frameOverlayMessage,
  unframeOverlayMessage,
  OVERLAY_HANDSHAKE_FAILED,
  OVERLAY_NETWORK_ID_MISMATCH,
  OVERLAY_VERSION_MISMATCH,
  OVERLAY_VALIDATOR_KEY_MISMATCH,
  OVERLAY_CERT_INVALID,
  OVERLAY_AUTH_MAC_INVALID,
} from '../../src/overlay/handshakeTester.js';
import { Keypair, Networks } from '@stellar/stellar-base';

describe('OverlayHandshakeTester', () => {
  const tester = new OverlayHandshakeTester();

  it('exposes overlay handshake rules and rule IDs', () => {
    expect(overlayHandshakeRules).toHaveLength(6);
    expect(overlayHandshakeRuleIds).toContain(OVERLAY_HANDSHAKE_FAILED);
    expect(overlayHandshakeRuleIds).toContain(OVERLAY_NETWORK_ID_MISMATCH);
    expect(overlayHandshakeRuleIds).toContain(OVERLAY_VERSION_MISMATCH);
    expect(overlayHandshakeRuleIds).toContain(OVERLAY_VALIDATOR_KEY_MISMATCH);
    expect(overlayHandshakeRuleIds).toContain(OVERLAY_CERT_INVALID);
    expect(overlayHandshakeRuleIds).toContain(OVERLAY_AUTH_MAC_INVALID);
  });

  it('frames and unframes overlay network XDR message packets', () => {
    const payload = new Uint8Array([1, 2, 3, 4, 5]);
    const framed = frameOverlayMessage(payload);

    expect(framed.length).toBe(payload.length + 4);
    const unframed = unframeOverlayMessage(framed);
    expect(unframed).toEqual(payload);
  });

  it('parses validator endpoints from stellar.toml document', () => {
    const tomlDoc = {
      VALIDATORS: [
        {
          PUBLIC_KEY: Keypair.random().publicKey(),
          HOST: 'validator1.stellar.org',
          PORT: 11625,
        },
        {
          PUBLIC_KEY: Keypair.random().publicKey(),
          HOST: 'validator2.stellar.org',
        },
      ],
    };

    const endpoints = parseValidatorEndpoints(tomlDoc);
    expect(endpoints).toHaveLength(2);
    expect(endpoints[0]?.host).toBe('validator1.stellar.org');
    expect(endpoints[0]?.port).toBe(11625);
    expect(endpoints[1]?.port).toBe(11625); // Default port
  });

  it('simulates and completes authenticated handshake with validator endpoint', async () => {
    const validatorKeypair = Keypair.random();
    const endpoint = {
      publicKey: validatorKeypair.publicKey(),
      host: 'node.example.org',
      port: 11625,
      rawEndpoint: 'node.example.org:11625',
    };

    // Use mock simulated transport
    const mockTransport = async (_ep: string, _data: Uint8Array): Promise<Uint8Array> => {
      return OverlayHandshakeTester.simulateValidatorResponse(
        endpoint.publicKey,
        Networks.PUBLIC,
        endpoint.port,
        validatorKeypair,
      );
    };

    const customTester = new OverlayHandshakeTester({ transport: mockTransport });
    const result = await customTester.testValidatorHandshake(endpoint);

    expect(result.ok).toBe(true);
    expect(result.remoteHello?.peerId).toBe(endpoint.publicKey);
  });
});
