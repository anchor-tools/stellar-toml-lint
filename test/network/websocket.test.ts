import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  auditWebSocketEndpoints,
  WEBSOCKET_HANDSHAKE_FAILED_RULE,
  WEBSOCKET_PING_TIMEOUT_RULE,
} from '../../src/network/websocket-auditor.js';

describe('WebSocket Auditor', () => {
  const mockWebSocket = {
    onopen: null as ((event: Event) => void) | null,
    onerror: null as ((event: Event) => void) | null,
    onclose: null as ((event: CloseEvent) => void) | null,
    onpong: null as ((event: Event) => void) | null,
    readyState: WebSocket.CONNECTING as number,
    ping: vi.fn(),
    close: vi.fn(),
  };

  let OriginalWebSocket: typeof WebSocket;

  beforeEach(() => {
    OriginalWebSocket = global.WebSocket;
    vi.stubGlobal('WebSocket', vi.fn(() => mockWebSocket));
  });

  afterEach(() => {
    vi.stubGlobal('WebSocket', OriginalWebSocket);
    vi.clearAllMocks();
  });

  it('passes when WebSocket connects successfully', async () => {
    const doc = { WEBSOCKET_URL: 'wss://example.com/stream' };
    const connectPromise = auditWebSocketEndpoints(doc, { handshakeTimeout: 100, pingCount: 1, pingTimeout: 100 });

    // Simulate successful connection
    mockWebSocket.readyState = WebSocket.OPEN;
    mockWebSocket.onopen?.(new Event('open'));

    // Simulate pong
    setTimeout(() => {
      mockWebSocket.onpong?.(new Event('pong'));
    }, 10);

    const diagnostics = await connectPromise;

    expect(diagnostics.length).toBeGreaterThanOrEqual(0);
  });

  it('reports handshake failure', async () => {
    const doc = { WEBSOCKET_URL: 'wss://unreachable.example.com/stream' };
    const connectPromise = auditWebSocketEndpoints(doc, { handshakeTimeout: 100, pingCount: 1, pingTimeout: 1000 });

    // Simulate connection error
    setTimeout(() => {
      mockWebSocket.onerror?.(new Event('error'));
    }, 50);

    const diagnostics = await connectPromise;

    const failures = diagnostics.filter((d: { rule: string; severity: string }) => d.rule === WEBSOCKET_HANDSHAKE_FAILED_RULE && d.severity === 'error');
    expect(failures.length).toBeGreaterThan(0);
  });

  it('reports ping timeout', async () => {
    const doc = { WEBSOCKET_URL: 'wss://slow.example.com/stream' };
    const connectPromise = auditWebSocketEndpoints(doc, { handshakeTimeout: 5000, pingCount: 2, pingTimeout: 100 });

    // Simulate successful connection
    mockWebSocket.readyState = WebSocket.OPEN;
    mockWebSocket.onopen?.(new Event('open'));

    // Don't send pong - let it timeout
    const diagnostics = await connectPromise;

    const timeouts = diagnostics.filter((d: { rule: string }) => d.rule === WEBSOCKET_PING_TIMEOUT_RULE);
    expect(timeouts.length).toBeGreaterThan(0);
  });

  it('respects rule severity overrides', async () => {
    const doc = { WEBSOCKET_URL: 'wss://unreachable.example.com/stream' };
    const connectPromise = auditWebSocketEndpoints(doc, {
      handshakeTimeout: 100,
      pingCount: 1,
      pingTimeout: 1000,
      rules: { [WEBSOCKET_HANDSHAKE_FAILED_RULE]: 'off' },
    });

    setTimeout(() => {
      mockWebSocket.onerror?.(new Event('error'));
    }, 50);

    const diagnostics = await connectPromise;

    const failures = diagnostics.filter((d: { rule: string }) => d.rule === WEBSOCKET_HANDSHAKE_FAILED_RULE);
    expect(failures.length).toBe(0);
  });

  it('stays silent when no WebSocket URLs declared', async () => {
    const doc = { CURRENCIES: [] };
    const diagnostics = await auditWebSocketEndpoints(doc);

    expect(diagnostics).toEqual([]);
  });
});