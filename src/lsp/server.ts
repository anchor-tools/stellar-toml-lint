/**
 * Language Server Protocol server over stdio — `stellar-toml-lint --lsp`.
 *
 * Speaks only what editors need to show diagnostics, offer #42 quick fixes, and
 * explain a field under the cursor: `initialize`, open/change/close sync,
 * `publishDiagnostics`, `textDocument/codeAction`, and `textDocument/hover`.
 * Framing is the standard `Content-Length` header; payloads are UTF-8 JSON.
 * Deliberately no `vscode-languageserver` dependency (package.json freezes
 * runtime deps to two packages).
 */
import process from 'node:process';
import { lint } from '../lint.js';
import type { Diagnostic } from '../types.js';
import { codeActionsFor, toLspDiagnostic } from './code-actions.js';
import type { LspCodeAction } from './code-actions.js';
import { getHoverInfo } from './hover.js';
import type { Hover } from './hover.js';
import type {
  CodeActionParams,
  DidChangeTextDocumentParams,
  DidCloseTextDocumentParams,
  DidOpenTextDocumentParams,
  HoverParams,
  LspInitializeResult,
  RpcMessage,
} from './protocol.js';
import { RPC_INTERNAL_ERROR, RPC_METHOD_NOT_FOUND, SYNC_FULL } from './protocol.js';

const SERVER_NAME = 'stellar-toml-lint';
const SERVER_VERSION = '0.1.0';

/** Runs the LSP server until the client sends `exit` (or stdin closes). */
export async function runLspServer(
  input: NodeJS.ReadableStream = process.stdin,
  output: NodeJS.WritableStream = process.stdout,
): Promise<void> {
  const documents = new Map<string, string>();
  let shuttingDown = false;

  const send = (message: RpcMessage): void => {
    const body = Buffer.from(JSON.stringify(message), 'utf8');
    output.write(`Content-Length: ${body.length}\r\n\r\n`);
    output.write(body);
  };

  const notify = (method: string, params: unknown): void => {
    send({ jsonrpc: '2.0', method, params });
  };

  const publishDiagnostics = (uri: string, diagnostics: Diagnostic[]): void => {
    notify('textDocument/publishDiagnostics', {
      uri,
      diagnostics: diagnostics.map(toLspDiagnostic),
    });
  };

  const handleRequest = (message: RpcMessage): RpcMessage => {
    const id = message.id ?? null;
    try {
      switch (message.method) {
        case 'initialize': {
          const result: LspInitializeResult = {
            capabilities: {
              textDocumentSync: { openClose: true, change: SYNC_FULL },
              codeActionProvider: { codeActionKinds: ['quickfix'] },
              hoverProvider: true,
            },
            serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
          };
          return { jsonrpc: '2.0', id, result };
        }
        case 'shutdown': {
          shuttingDown = true;
          return { jsonrpc: '2.0', id, result: null };
        }
        case 'textDocument/codeAction': {
          const params = message.params as CodeActionParams;
          const source = documents.get(params.textDocument.uri);
          if (source === undefined) return { jsonrpc: '2.0', id, result: [] };
          const result: LspCodeAction[] = codeActionsFor(
            source,
            params.textDocument.uri,
            lint(source).diagnostics,
            params.range,
          );
          return { jsonrpc: '2.0', id, result };
        }
        case 'textDocument/hover': {
          const params = message.params as HoverParams;
          const source = documents.get(params.textDocument.uri);
          if (source === undefined) return { jsonrpc: '2.0', id, result: null };
          const result: Hover | null = getHoverInfo(source, params.position);
          return { jsonrpc: '2.0', id, result };
        }
        default:
          if (message.id !== undefined && message.id !== null) {
            return {
              jsonrpc: '2.0',
              id,
              error: { code: RPC_METHOD_NOT_FOUND, message: `Method not found: ${message.method}` },
            };
          }
          return { jsonrpc: '2.0', id: null };
      }
    } catch (error) {
      return {
        jsonrpc: '2.0',
        id,
        error: {
          code: RPC_INTERNAL_ERROR,
          message: error instanceof Error ? error.message : String(error),
        },
      };
    }
  };

  const handleNotification = (message: RpcMessage): boolean => {
    switch (message.method) {
      case 'exit':
        return false;
      case 'initialized':
      case '$/cancelRequest':
      case 'workspace/didChangeConfiguration':
        return true;
      case 'textDocument/didOpen': {
        const params = message.params as DidOpenTextDocumentParams;
        documents.set(params.textDocument.uri, params.textDocument.text);
        publishDiagnostics(params.textDocument.uri, lint(params.textDocument.text).diagnostics);
        return true;
      }
      case 'textDocument/didChange': {
        const params = message.params as DidChangeTextDocumentParams;
        const text = params.contentChanges[params.contentChanges.length - 1]?.text;
        if (text === undefined) return true;
        documents.set(params.textDocument.uri, text);
        publishDiagnostics(params.textDocument.uri, lint(text).diagnostics);
        return true;
      }
      case 'textDocument/didClose': {
        const params = message.params as DidCloseTextDocumentParams;
        documents.delete(params.textDocument.uri);
        return true;
      }
      default:
        return true;
    }
  };

  await readMessages(input, (message) => {
    if (message.method === 'exit') return false;
    if (message.id !== undefined && message.method !== undefined) {
      const response = handleRequest(message);
      if (response.id !== undefined && response.id !== null) send(response);
      if (message.method === 'shutdown' && shuttingDown) {
        // Wait for the subsequent `exit` notification per the LSP lifecycle.
      }
      return true;
    }
    return handleNotification(message);
  });
}

/**
 * Reads `Content-Length`-framed JSON-RPC messages from `input`.
 * Invokes `onMessage` for each; returns when it returns `false` or the stream ends.
 */
async function readMessages(
  input: NodeJS.ReadableStream,
  onMessage: (message: RpcMessage) => boolean,
): Promise<void> {
  let buffer = Buffer.alloc(0);

  for await (const chunk of input) {
    buffer = Buffer.concat([buffer, Buffer.from(chunk as Buffer)]);

    for (;;) {
      const headerEnd = buffer.indexOf('\r\n\r\n');
      if (headerEnd < 0) break;

      const header = buffer.subarray(0, headerEnd).toString('ascii');
      const match = /Content-Length:\s*(\d+)/i.exec(header);
      if (!match) {
        // Unrecoverable framing — drop the junk and resync on the next header.
        buffer = buffer.subarray(headerEnd + 4);
        continue;
      }

      const length = Number(match[1]);
      const bodyStart = headerEnd + 4;
      if (buffer.length < bodyStart + length) break;

      const body = buffer.subarray(bodyStart, bodyStart + length).toString('utf8');
      buffer = buffer.subarray(bodyStart + length);

      let message: RpcMessage;
      try {
        message = JSON.parse(body) as RpcMessage;
      } catch {
        continue;
      }
      if (!onMessage(message)) return;
    }
  }
}
