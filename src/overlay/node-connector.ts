import { Buffer } from 'node:buffer';
import { createConnection } from 'node:net';
import {
  decodePeersMessage,
  encodeGetPeersFrame,
  OVERLAY_MAX_FRAME_BYTES,
  OVERLAY_MESSAGE_PEERS,
  type OverlayConnectorOptions,
} from './crawler.js';

function splitAddress(address: string): { host: string; port: number } {
  const value = address.trim();
  const bracket = value.startsWith('[') ? value.indexOf(']') : -1;
  if (bracket > 0) {
    const host = value.slice(1, bracket);
    const port = Number(value.slice(bracket + 2));
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new Error(`Invalid overlay address ${address}`);
    }
    return { host, port };
  }
  const separator = value.lastIndexOf(':');
  if (separator <= 0 || separator === value.length - 1) {
    throw new Error(`Invalid overlay address ${address}`);
  }
  const host = value.slice(0, separator);
  const port = Number(value.slice(separator + 1));
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`Invalid overlay address ${address}`);
  }
  return { host, port };
}

function readResponse(buffer: Uint8Array): Uint8Array | undefined {
  if (buffer.length < 4) return undefined;
  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  const length = view.getUint32(0);
  if (length > 0 && length <= OVERLAY_MAX_FRAME_BYTES && buffer.length >= length + 4) {
    return buffer.subarray(4, length + 4);
  }
  if (length === 0 || length > OVERLAY_MAX_FRAME_BYTES) {
    const type = view.getUint32(0);
    if (type === OVERLAY_MESSAGE_PEERS || type === 0) {
      try {
        decodePeersMessage(buffer);
        return buffer;
      } catch {
        return undefined;
      }
    }
    throw new Error('Overlay response has an invalid length prefix');
  }
  const type = view.getUint32(0);
  if (type === OVERLAY_MESSAGE_PEERS || type === 0) {
    try {
      decodePeersMessage(buffer);
      return buffer;
    } catch {
      return undefined;
    }
  }
  return undefined;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function connectOverlayPeer(
  address: string,
  options: OverlayConnectorOptions = {},
): Promise<Uint8Array> {
  const { host, port } = splitAddress(address);
  const timeoutMs = options.timeoutMs ?? 3000;

  return new Promise<Uint8Array>((resolve, reject) => {
    let settled = false;
    let buffer: Uint8Array = new Uint8Array(0);
    const socket = createConnection({ host, port });

    const finish = (error?: Error, response?: Uint8Array): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      if (error !== undefined) reject(error);
      else if (response !== undefined) resolve(response);
    };

    socket.setTimeout(timeoutMs);
    socket.once('connect', () => {
      try {
        socket.write(Buffer.from(encodeGetPeersFrame()));
      } catch (error) {
        finish(error instanceof Error ? error : new Error(errorMessage(error)));
      }
    });
    socket.on('data', (chunk: Uint8Array) => {
      try {
        buffer = Buffer.concat([buffer, chunk]);
        const response = readResponse(buffer);
        if (response !== undefined) finish(undefined, response);
      } catch (error) {
        finish(error instanceof Error ? error : new Error(errorMessage(error)));
      }
    });
    socket.once('timeout', () => finish(new Error(`Overlay request to ${address} timed out`)));
    socket.once('error', (error: Error) => finish(error));
    socket.once('close', () => {
      if (!settled) finish(new Error(`Overlay connection to ${address} closed before a response`));
    });
  });
}
