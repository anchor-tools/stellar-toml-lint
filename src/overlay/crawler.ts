import type { Diagnostic, RuleOverrides } from '../types.js';
import { isHostPort } from '../predicates.js';
import { OVERLAY_ISOLATED_NODE_ZERO_PEERS, OVERLAY_LOW_PEER_COUNT } from './crawler-rules.js';

export {
  crawlerRules,
  ISOLATED_NODE_ZERO_PEERS_RULE,
  LOW_PEER_COUNT_RULE,
  overlayCrawlerRuleIds,
  overlayCrawlerRules,
} from './crawler-rules.js';

export const OVERLAY_MESSAGE_GET_PEERS = 4;
export const OVERLAY_MESSAGE_PEERS = 5;
export const OVERLAY_DEFAULT_PORT = 11625;
export const OVERLAY_MAX_PEERS = 100;
export const OVERLAY_MAX_FRAME_BYTES = 16 * 1024 * 1024;

export interface PeerAddress {
  ip: string;
  port: number;
  failures?: number;
}

export interface OverlayConnectorOptions {
  timeoutMs?: number;
}

export type OverlayConnectorResult =
  | PeerAddress[]
  | Uint8Array
  | ArrayBuffer
  | {
      peers?: unknown;
      data?: unknown;
    }
  | string;

export type OverlayConnector = (
  address: string,
  options?: OverlayConnectorOptions,
) => Promise<OverlayConnectorResult>;

export interface CrawlOptions {
  rules?: RuleOverrides;
  connector?: OverlayConnector;
  connect?: OverlayConnector;
  maxNodes?: number;
  maxDepth?: number;
  maxPeersPerNode?: number;
  timeoutMs?: number;
}

export interface PeerCrawlResult {
  seeds: string[];
  visited: string[];
  peers: PeerAddress[];
  adjacency: Record<string, string[]>;
  bidirectionalPeers: string[];
  errors: Record<string, string>;
}

export type PeerCrawlCheckOptions = CrawlOptions;

function readUint32(bytes: Uint8Array, offset: number): number {
  if (offset < 0 || offset + 4 > bytes.length) {
    throw new Error('XDR message ended before a 32-bit value');
  }
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(offset);
}

function readUint64(bytes: Uint8Array, offset: number): bigint {
  if (offset < 0 || offset + 8 > bytes.length) {
    throw new Error('XDR message ended before a 64-bit value');
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return view.getBigUint64(offset);
}

function writeUint32(bytes: Uint8Array, offset: number, value: number): void {
  new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).setUint32(offset, value);
}

function copyBytes(bytes: Uint8Array, start: number, length: number): Uint8Array {
  if (start < 0 || length < 0 || start + length > bytes.length) {
    throw new Error('XDR message ended inside a variable-length field');
  }
  return bytes.slice(start, start + length);
}

function ipFromBytes(bytes: Uint8Array, type: number): string {
  if (type === 0 && bytes.length === 4) return Array.from(bytes).join('.');
  if (type === 1 && bytes.length === 16) {
    const groups: string[] = [];
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    for (let offset = 0; offset < 16; offset += 2) {
      groups.push(view.getUint16(offset).toString(16));
    }
    return groups.join(':');
  }
  throw new Error(`Unsupported overlay IP address type ${type}`);
}

function bytesFromIpv4(ip: string): Uint8Array {
  const parts = ip.split('.');
  if (parts.length !== 4) throw new Error(`Invalid IPv4 address ${ip}`);
  const bytes = new Uint8Array(4);
  for (let index = 0; index < parts.length; index++) {
    const part = Number(parts[index]);
    if (!Number.isInteger(part) || part < 0 || part > 255) {
      throw new Error(`Invalid IPv4 address ${ip}`);
    }
    bytes[index] = part;
  }
  return bytes;
}

function bytesFromIpv6(ip: string): Uint8Array {
  const normalized = ip.toLowerCase();
  const pieces = normalized.split('::');
  if (pieces.length > 2) throw new Error(`Invalid IPv6 address ${ip}`);
  const firstPiece = pieces[0] ?? '';
  const secondPiece = pieces[1];
  const left = firstPiece === '' ? [] : firstPiece.split(':');
  const right = secondPiece === undefined || secondPiece === '' ? [] : secondPiece.split(':');
  const missing = 8 - left.length - right.length;
  if (missing < 0 || (pieces.length === 1 && missing !== 0)) {
    throw new Error(`Invalid IPv6 address ${ip}`);
  }
  const groups = [...left, ...Array.from({ length: missing }, () => '0'), ...right];
  if (groups.length !== 8 || groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) {
    throw new Error(`Invalid IPv6 address ${ip}`);
  }
  const bytes = new Uint8Array(16);
  const view = new DataView(bytes.buffer);
  for (let index = 0; index < groups.length; index++) {
    view.setUint16(index * 2, Number.parseInt(groups[index] as string, 16));
  }
  return bytes;
}

function encodePeer(peer: PeerAddress): Uint8Array {
  const isIpv6 = peer.ip.includes(':');
  const address = isIpv6 ? bytesFromIpv6(peer.ip) : bytesFromIpv4(peer.ip);
  const bytes = new Uint8Array(4 + address.length + 8);
  writeUint32(bytes, 0, isIpv6 ? 1 : 0);
  bytes.set(address, 4);
  writeUint32(bytes, 4 + address.length, peer.port);
  writeUint32(bytes, 8 + address.length, peer.failures ?? 0);
  return bytes;
}

export function encodePeersMessage(peers: PeerAddress[], legacyNonce?: number): Uint8Array {
  const encoded = peers.slice(0, OVERLAY_MAX_PEERS).map(encodePeer);
  const nonceLength = legacyNonce === undefined ? 0 : 4;
  const totalLength = 8 + nonceLength + encoded.reduce((sum, peer) => sum + peer.length, 0);
  const bytes = new Uint8Array(totalLength);
  writeUint32(bytes, 0, OVERLAY_MESSAGE_PEERS);
  if (legacyNonce !== undefined) writeUint32(bytes, 4, legacyNonce);
  writeUint32(bytes, 4 + nonceLength, Math.min(peers.length, OVERLAY_MAX_PEERS));
  let offset = 8 + nonceLength;
  for (const peer of encoded) {
    bytes.set(peer, offset);
    offset += peer.length;
  }
  return bytes;
}

export function encodeGetPeersMessage(nonce?: number): Uint8Array {
  const bytes = new Uint8Array(nonce === undefined ? 4 : 8);
  writeUint32(bytes, 0, OVERLAY_MESSAGE_GET_PEERS);
  if (nonce !== undefined) writeUint32(bytes, 4, nonce);
  return bytes;
}

export const encodeGetPeersXdr = encodeGetPeersMessage;

export function frameOverlayMessage(message: Uint8Array): Uint8Array {
  if (message.length > OVERLAY_MAX_FRAME_BYTES) {
    throw new Error(`Overlay frame exceeds ${OVERLAY_MAX_FRAME_BYTES} bytes`);
  }
  const framed = new Uint8Array(4 + message.length);
  writeUint32(framed, 0, message.length);
  framed.set(message, 4);
  return framed;
}

export const encodeGetPeersFrame = (nonce?: number): Uint8Array =>
  frameOverlayMessage(encodeGetPeersMessage(nonce));

function parsePeersAt(bytes: Uint8Array, offset: number, authenticated = false): PeerAddress[] {
  let cursor = offset;
  if (authenticated) {
    if (readUint32(bytes, cursor) !== 0)
      throw new Error('Unsupported authenticated message version');
    readUint64(bytes, cursor + 4);
    cursor += 12;
  }

  if (readUint32(bytes, cursor) !== OVERLAY_MESSAGE_PEERS) {
    throw new Error('Overlay response is not a PEERS message');
  }
  cursor += 4;

  const parseCountAt = (countOffset: number): PeerAddress[] => {
    const count = readUint32(bytes, countOffset);
    if (count > OVERLAY_MAX_PEERS) throw new Error('PEERS message contains too many peers');
    let peerOffset = countOffset + 4;
    const peers: PeerAddress[] = [];
    for (let index = 0; index < count; index++) {
      const type = readUint32(bytes, peerOffset);
      const addressLength = type === 0 ? 4 : type === 1 ? 16 : -1;
      if (addressLength < 0) throw new Error(`Unsupported overlay IP address type ${type}`);
      const address = copyBytes(bytes, peerOffset + 4, addressLength);
      const ip = ipFromBytes(address, type);
      const port = readUint32(bytes, peerOffset + 4 + addressLength);
      const failures = readUint32(bytes, peerOffset + 8 + addressLength);
      if (port < 1 || port > 65535) throw new Error(`Invalid overlay peer port ${port}`);
      peers.push({ ip, port, failures });
      peerOffset += 12 + addressLength;
    }
    if (peerOffset > bytes.length) throw new Error('PEERS message contains a truncated peer');
    return peers;
  };

  try {
    return parseCountAt(cursor);
  } catch (error) {
    if (bytes.length - cursor < 8) throw error;
    return parseCountAt(cursor + 4);
  }
}

export function decodePeersMessage(data: Uint8Array): PeerAddress[] {
  if (data.length < 8) throw new Error('Overlay response is too short');

  if (readUint32(data, 0) === OVERLAY_MESSAGE_PEERS) {
    return parsePeersAt(data, 0);
  }

  if (
    data.length >= 16 &&
    readUint32(data, 0) === 0 &&
    readUint32(data, 12) === OVERLAY_MESSAGE_PEERS
  ) {
    return parsePeersAt(data, 0, true);
  }

  if (data.length >= 8) {
    const frameLength = readUint32(data, 0);
    if (
      frameLength > 0 &&
      frameLength <= OVERLAY_MAX_FRAME_BYTES &&
      frameLength + 4 <= data.length
    ) {
      const payload = data.subarray(4, 4 + frameLength);
      if (readUint32(payload, 0) === OVERLAY_MESSAGE_PEERS) {
        return parsePeersAt(payload, 0);
      }
      if (
        payload.length >= 16 &&
        readUint32(payload, 0) === 0 &&
        readUint32(payload, 12) === OVERLAY_MESSAGE_PEERS
      ) {
        return parsePeersAt(payload, 0, true);
      }
    }
  }

  throw new Error('Overlay response has an invalid message header');
}

export const parsePeersResponse = decodePeersMessage;

function normalizePeer(value: unknown): PeerAddress | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  const record = value as Record<string, unknown>;
  const rawIp = record.ip ?? record.address ?? record.host;
  const rawPort = record.port;
  if (typeof rawIp !== 'string' || !Number.isInteger(rawPort)) return undefined;
  const port = Number(rawPort);
  if (port < 1 || port > 65535) return undefined;
  const failures = Number.isInteger(record.failures) ? Number(record.failures) : undefined;
  return {
    ip: rawIp,
    port,
    ...(failures === undefined ? {} : { failures }),
  };
}

function normalizePeers(value: unknown): PeerAddress[] {
  if (typeof value === 'string') {
    try {
      return normalizePeers(JSON.parse(value) as unknown);
    } catch {
      throw new Error('Overlay connector returned a non-JSON string response');
    }
  }
  if (value instanceof Uint8Array) return decodePeersMessage(value);
  if (value instanceof ArrayBuffer) return decodePeersMessage(new Uint8Array(value));
  if (Array.isArray(value)) {
    return value
      .map((peer) => normalizePeer(peer))
      .filter((peer): peer is PeerAddress => peer !== undefined);
  }
  if (typeof value === 'object' && value !== null) {
    const record = value as Record<string, unknown>;
    if (record.data !== undefined) return normalizePeers(record.data);
    if (record.peers !== undefined) return normalizePeers(record.peers);
  }
  return [];
}

function endpointOf(peer: PeerAddress): string {
  return peer.ip.includes(':') ? `[${peer.ip}]:${peer.port}` : `${peer.ip}:${peer.port}`;
}

function normalizeEndpoint(value: unknown, defaultPort = OVERLAY_DEFAULT_PORT): string | undefined {
  if (typeof value !== 'string' || value.trim() === '') return undefined;
  const raw = value.trim();
  if (isHostPort(raw)) return raw;
  try {
    const url = new URL(raw.includes('://') ? raw : `tcp://${raw}`);
    const host = url.hostname;
    if (host === '') return undefined;
    const port = url.port === '' ? defaultPort : Number(url.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) return undefined;
    return host.includes(':') ? `[${host}]:${port}` : `${host}:${port}`;
  } catch {
    return undefined;
  }
}

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules: RuleOverrides | undefined,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

function validatorsOf(doc: Record<string, unknown>): Record<string, unknown>[] {
  if (!Array.isArray(doc.VALIDATORS)) return [];
  return doc.VALIDATORS.filter(
    (value): value is Record<string, unknown> =>
      typeof value === 'object' && value !== null && !Array.isArray(value),
  );
}

async function defaultConnector(
  address: string,
  options: OverlayConnectorOptions = {},
): Promise<OverlayConnectorResult> {
  const connector = await import('./node-connector.js');
  return connector.connectOverlayPeer(address, options);
}

export function crawlOverlayPeers(
  addresses: string[],
  connector?: OverlayConnector,
): Promise<PeerCrawlResult>;
export function crawlOverlayPeers(
  addresses: string[],
  options?: CrawlOptions,
): Promise<PeerCrawlResult>;
export async function crawlOverlayPeers(
  addresses: string[],
  optionsOrConnector: CrawlOptions | OverlayConnector = {},
): Promise<PeerCrawlResult> {
  const options =
    typeof optionsOrConnector === 'function'
      ? { connector: optionsOrConnector }
      : optionsOrConnector;
  const connector = options.connector ?? options.connect ?? defaultConnector;
  const maxNodes = Math.max(1, options.maxNodes ?? 32);
  const maxDepth = Math.max(0, options.maxDepth ?? 2);
  const maxPeersPerNode = Math.max(1, options.maxPeersPerNode ?? OVERLAY_MAX_PEERS);
  const queue = addresses
    .map((address) => normalizeEndpoint(address))
    .filter((address): address is string => address !== undefined)
    .map((address) => ({ address, depth: 0 }));
  const seeds = [...new Set(queue.map((entry) => entry.address))];
  const visited: string[] = [];
  const peers: PeerAddress[] = [];
  const adjacency: Record<string, string[]> = {};
  const errors: Record<string, string> = {};

  while (queue.length > 0 && visited.length < maxNodes) {
    const current = queue.shift();
    if (current === undefined) break;
    if (visited.includes(current.address)) continue;
    visited.push(current.address);

    try {
      const response = await connector(current.address, { timeoutMs: options.timeoutMs });
      const discovered = normalizePeers(response).slice(0, maxPeersPerNode);
      const endpoints = [
        ...new Set(
          discovered
            .map((peer) => normalizeEndpoint(endpointOf(peer)))
            .filter((endpoint): endpoint is string => endpoint !== undefined),
        ),
      ];
      adjacency[current.address] = endpoints;
      peers.push(...discovered);
      if (current.depth < maxDepth) {
        for (const endpoint of endpoints) {
          if (!visited.includes(endpoint) && queue.length + visited.length < maxNodes) {
            queue.push({ address: endpoint, depth: current.depth + 1 });
          }
        }
      }
    } catch (error) {
      adjacency[current.address] = [];
      errors[current.address] = error instanceof Error ? error.message : String(error);
    }
  }

  const bidirectionalPeers = [
    ...new Set(
      Object.entries(adjacency).flatMap(([source, targets]) =>
        targets.filter((target) => adjacency[target]?.includes(source) === true),
      ),
    ),
  ];
  return { seeds, visited, peers, adjacency, bidirectionalPeers, errors };
}

export function checkOverlayPeers(
  doc: Record<string, unknown>,
  connector?: OverlayConnector,
): Promise<Diagnostic[]>;
export function checkOverlayPeers(
  doc: Record<string, unknown>,
  options?: PeerCrawlCheckOptions,
): Promise<Diagnostic[]>;
export async function checkOverlayPeers(
  doc: Record<string, unknown>,
  optionsOrConnector: PeerCrawlCheckOptions | OverlayConnector = {},
): Promise<Diagnostic[]> {
  const options =
    typeof optionsOrConnector === 'function'
      ? { connector: optionsOrConnector }
      : optionsOrConnector;
  const entries = validatorsOf(doc);
  const seeds: string[] = [];
  const paths: string[] = [];
  const pathsByAddress = new Map<string, string>();
  for (const [index, entry] of entries.entries()) {
    const endpoint = normalizeEndpoint(entry.HOST);
    if (endpoint === undefined) continue;
    seeds.push(endpoint);
    const path = `VALIDATORS[${index}].HOST`;
    paths.push(path);
    pathsByAddress.set(endpoint, path);
  }
  if (seeds.length === 0) return [];

  const crawl = await crawlOverlayPeers(seeds, options);
  const zeroPeers: string[] = [];
  const lowPeers: Array<{ address: string; count: number }> = [];
  for (const address of crawl.seeds) {
    const endpoints = crawl.adjacency[address] ?? [];
    if (endpoints.length === 0) zeroPeers.push(address);
    else if (endpoints.length <= 5) lowPeers.push({ address, count: endpoints.length });
  }

  const diagnostics: Diagnostic[] = [];
  if (zeroPeers.length > 0) {
    const severity = severityFor(OVERLAY_ISOLATED_NODE_ZERO_PEERS, 'error', options.rules);
    if (severity !== undefined) {
      diagnostics.push({
        rule: OVERLAY_ISOLATED_NODE_ZERO_PEERS,
        severity,
        category: 'network',
        message: `Overlay node ${zeroPeers[0]} reported zero reachable peers`,
        path: pathsByAddress.get(zeroPeers[0] ?? '') ?? paths[0],
        suggestion:
          'Open the validator peer port and verify inbound and outbound overlay connectivity.',
      });
    }
  } else if (lowPeers.length > 0) {
    const severity = severityFor(OVERLAY_LOW_PEER_COUNT, 'warning', options.rules);
    if (severity !== undefined) {
      const first = lowPeers[0];
      diagnostics.push({
        rule: OVERLAY_LOW_PEER_COUNT,
        severity,
        category: 'network',
        message: `Overlay node ${first?.address} reported only ${first?.count} peers; more than five are recommended`,
        path: pathsByAddress.get(first?.address ?? '') ?? paths[0],
        suggestion: 'Add independent well-connected validators to reduce overlay isolation risk.',
      });
    }
  }
  return diagnostics;
}

export const checkOverlayPeerDiscovery = checkOverlayPeers;
export const checkOverlayCrawler = checkOverlayPeers;
export const checkPeerDiscovery = checkOverlayPeers;
export const crawlPeers = crawlOverlayPeers;
export const crawlValidatorPeers = crawlOverlayPeers;
