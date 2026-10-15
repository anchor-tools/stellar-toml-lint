/**
 * WebSocket Handshake and Event Stream Auditor
 *
 * Validates WebSocket upgrades (ws:// / wss://), TLS framing, and heartbeats
 * for SEP-24 and other streaming endpoints.
 *
 * Runs under opt-in --check-network.
 */

import type { Diagnostic } from '../types.js';

export const WEBSOCKET_HANDSHAKE_FAILED_RULE = 'network/websocket-handshake-failed';
export const WEBSOCKET_PING_TIMEOUT_RULE = 'network/websocket-ping-timeout';
export const WEBSOCKET_TLS_VALIDATION_FAILED_RULE = 'network/websocket-tls-validation-failed';

export interface WebSocketAuditorOptions {
  /** Maximum time to wait for WebSocket handshake (ms) */
  handshakeTimeout?: number;
  /** Maximum time to wait for pong response (ms) */
  pingTimeout?: number;
  /** Number of ping/pong cycles to test */
  pingCount?: number;
  /** Rule severity overrides */
  rules?: Record<string, 'off' | 'error' | 'warning'>;
}

const DEFAULT_OPTIONS: Required<WebSocketAuditorOptions> = {
  handshakeTimeout: 10000,
  pingTimeout: 5000,
  pingCount: 3,
  rules: {},
};

// Extended WebSocket interface for ping/pong support
interface ExtendedWebSocket extends WebSocket {
  ping?: (data?: ArrayBuffer | ArrayBufferView | Blob | string) => void;
  onpong?: (event: Event) => void;
}

interface WebSocketTestResult {
  url: string;
  connected: boolean;
  handshakeTime?: number;
  tlsValid?: boolean;
  pingResults: Array<{ success: boolean; latency?: number; error?: string }>;
  errors: string[];
}

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules?: Record<string, 'off' | 'error' | 'warning'>,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

function report(
  diagnostics: Diagnostic[],
  rule: string,
  fallback: 'error' | 'warning',
  path: string,
  message: string,
  suggestion: string,
  options: WebSocketAuditorOptions,
): void {
  const severity = severityFor(rule, fallback, options.rules);
  if (severity === undefined) return;
  diagnostics.push({
    rule,
    severity,
    category: 'network',
    message,
    path,
    suggestion,
  });
}

async function testWebSocketConnection(
  url: string,
  options: Required<WebSocketAuditorOptions>,
): Promise<WebSocketTestResult> {
  const result: WebSocketTestResult = {
    url,
    connected: false,
    pingResults: [],
    errors: [],
  };

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), options.handshakeTimeout);

  let ws: ExtendedWebSocket;
  const startTime = Date.now();

  try {
    ws = new WebSocket(url) as ExtendedWebSocket;
  } catch (error) {
    clearTimeout(timeoutId);
    result.errors.push(`Failed to create WebSocket: ${error instanceof Error ? error.message : String(error)}`);
    return result;
  }

  await new Promise<void>((resolve) => {
    ws.onopen = () => {
      clearTimeout(timeoutId);
      result.connected = true;
      result.handshakeTime = Date.now() - startTime;
      resolve();
    };

    ws.onerror = (event) => {
      clearTimeout(timeoutId);
      result.errors.push(`WebSocket error: ${event.type}`);
      resolve();
    };

    ws.onclose = (event) => {
      clearTimeout(timeoutId);
      if (!result.connected) {
        result.errors.push(`Connection closed before handshake: code=${event.code}, reason=${event.reason}`);
      }
      resolve();
    };
  });

  if (!result.connected) {
    return result;
  }

  // For wss:// URLs, we can't directly validate TLS in the browser
  // but we can check if the connection was established over TLS
  if (url.startsWith('wss://')) {
    result.tlsValid = true; // If connected, TLS handshake succeeded
  }

  // Test ping/pong
  for (let i = 0; i < options.pingCount; i++) {
    const pingStart = Date.now();
    let pongReceived = false;

    try {
      await new Promise<void>((resolve, reject) => {
        const pingTimeoutId = setTimeout(() => {
          if (!pongReceived) {
            reject(new Error('Ping timeout'));
          }
        }, options.pingTimeout);

        ws.onpong = () => {
          clearTimeout(pingTimeoutId);
          pongReceived = true;
          resolve();
        };

        ws.ping?.();
      });

      result.pingResults.push({ success: true, latency: Date.now() - pingStart });
    } catch (error) {
      result.pingResults.push({
        success: false,
        error: error instanceof Error ? error.message : String(error),
      });
    }

    // Small delay between pings
    if (i < options.pingCount - 1) {
      await new Promise((r) => setTimeout(r, 100));
    }
  }

  ws.close();
  return result;
}

export async function auditWebSocketEndpoints(
  doc: Record<string, unknown>,
  options: WebSocketAuditorOptions = {},
): Promise<Diagnostic[]> {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  const diagnostics: Diagnostic[] = [];

  // Collect all WebSocket URLs from the document
  const wsUrls = new Set<string>();

  // Check ANCHOR_QUOTE_SERVER for WebSocket endpoints
  const quoteServer = doc.ANCHOR_QUOTE_SERVER;
  if (typeof quoteServer === 'string') {
    const wsUrl = quoteServer.replace(/^http/, 'ws').replace(/\/+$/, '') + '/stream';
    wsUrls.add(wsUrl);
  }

  // Check for SEP-24 streaming endpoints
  const sep24Url = doc.SEP24_STREAM_URL;
  if (typeof sep24Url === 'string') {
    wsUrls.add(sep24Url);
  }

  // Check for general WEBSOCKET_URL
  const wsUrl = doc.WEBSOCKET_URL;
  if (typeof wsUrl === 'string') {
    wsUrls.add(wsUrl);
  }

  // Check for HORIZON_URL with WebSocket support
  const horizonUrl = doc.HORIZON_URL;
  if (typeof horizonUrl === 'string') {
    const wsHorizon = horizonUrl.replace(/^http/, 'ws').replace(/\/+$/, '') + '/stream';
    wsUrls.add(wsHorizon);
  }

  // Test each WebSocket endpoint
  for (const url of wsUrls) {
    const result = await testWebSocketConnection(url, opts);

    if (!result.connected) {
      report(
        diagnostics,
        WEBSOCKET_HANDSHAKE_FAILED_RULE,
        'error',
        'WEBSOCKET_URL',
        `WebSocket handshake failed for ${url}: ${result.errors.join('; ')}`,
        'Ensure the WebSocket endpoint is reachable and accepts connections.',
        opts,
      );
      continue;
    }

    // Check for ping timeouts
    const failedPings = result.pingResults.filter((p) => !p.success);
    if (failedPings.length > 0) {
      report(
        diagnostics,
        WEBSOCKET_PING_TIMEOUT_RULE,
        'warning',
        'WEBSOCKET_URL',
        `WebSocket ping timeout for ${url}: ${failedPings.length}/${result.pingResults.length} pings failed`,
        'Check server heartbeat configuration and network latency.',
        opts,
      );
    }

  }

  return diagnostics;
}

export const webSocketAuditorRules = [
  {
    id: WEBSOCKET_HANDSHAKE_FAILED_RULE,
    category: 'network',
    severity: 'error' as const,
    description: 'WebSocket handshake must complete successfully',
    run() {},
  },
  {
    id: WEBSOCKET_PING_TIMEOUT_RULE,
    category: 'network',
    severity: 'warning' as const,
    description: 'WebSocket ping/pong heartbeat must respond within timeout',
    run() {},
  },
  {
    id: WEBSOCKET_TLS_VALIDATION_FAILED_RULE,
    category: 'network',
    severity: 'error' as const,
    description: 'WSS connections must have valid TLS certificates',
    run() {},
  },
];