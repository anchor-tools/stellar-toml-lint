import { describe, expect, it } from 'vitest';
import {
  checkOverlayPeers,
  decodePeersMessage,
  encodeGetPeersMessage,
  encodePeersMessage,
  frameOverlayMessage,
  type PeerAddress,
} from '../src/overlay/crawler.js';

const HOST = 'node.example.com:11625';
const ZERO = 'overlay/isolated-node-zero-peers';
const LOW = 'overlay/low-peer-count';

function peers(count: number): PeerAddress[] {
  return Array.from({ length: count }, (_, index) => ({
    ip: `192.0.2.${index + 1}`,
    port: 11625,
  }));
}

function document(): Record<string, unknown> {
  return { VALIDATORS: [{ HOST }] };
}

describe('overlay peer crawler', () => {
  it('passes when a validator reports more than five peers', async () => {
    const diagnostics = await checkOverlayPeers(document(), {
      maxDepth: 0,
      connector: async () => peers(6),
    });
    expect(diagnostics).toEqual([]);
  });

  it('reports an isolated node for an empty PEERS response', async () => {
    const diagnostics = await checkOverlayPeers(document(), {
      maxDepth: 0,
      connector: async () => [],
    });
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({ rule: ZERO, severity: 'error' });
  });

  it('reports a low peer count as a warning', async () => {
    const diagnostics = await checkOverlayPeers(document(), {
      maxDepth: 0,
      connector: async () => peers(5),
    });
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({ rule: LOW, severity: 'warning' });
  });

  it('honours rule overrides', async () => {
    const diagnostics = await checkOverlayPeers(document(), {
      maxDepth: 0,
      connector: async () => [],
      rules: { [ZERO]: 'off' },
    });
    expect(diagnostics).toEqual([]);
  });

  it('round-trips IPv4 and IPv6 PEERS records', () => {
    const encoded = encodePeersMessage([
      { ip: '192.0.2.1', port: 11625 },
      { ip: '2001:db8::1', port: 11626 },
    ]);
    expect(decodePeersMessage(encoded)).toEqual([
      { ip: '192.0.2.1', port: 11625, failures: 0 },
      { ip: '2001:db8:0:0:0:0:0:1', port: 11626, failures: 0 },
    ]);
  });

  it('uses a four-byte big-endian GET_PEERS XDR message', () => {
    expect(Array.from(encodeGetPeersMessage())).toEqual([0, 0, 0, 4]);
    expect(Array.from(frameOverlayMessage(encodeGetPeersMessage()))).toEqual([
      0, 0, 0, 4, 0, 0, 0, 4,
    ]);
  });
});
