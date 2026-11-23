/**
 * Language Server Protocol server over stdio — `stellar-toml-lint --lsp`.
 *
 * Speaks only what editors need to show diagnostics, offer #42 quick fixes, and
 * explain a field under the cursor: `initialize`, open/change/close sync,
 * `publishDiagnostics`, `textDocument/codeAction`, and `textDocument/hover`
 * (with contract error docs when `initializationOptions.checkContracts` is set).
 * Framing is the standard `Content-Length` header; payloads are UTF-8 JSON.
 * Deliberately no `vscode-languageserver` dependency (package.json freezes
 * runtime deps to two packages).
 */
import process from 'node:process';
import { lint } from '../lint.js';
import type { Diagnostic } from '../types.js';
import { codeActionsFor, toLspDiagnostic } from './code-actions.js';
import type { LspCodeAction } from './code-actions.js';
import { getDocumentSymbols } from './document-symbols.js';
import type { LspDocumentSymbol } from './document-symbols.js';
import { getHoverInfo } from './hover.js';
import type { Hover } from './hover.js';
import { ContractErrorDocs, withContractErrors } from './contract-hover.js';
import { fetchContractWasm } from '../soroban.js';
import { rpcUrlFor } from '../rules/display-decimals-audit.js';
import type {
  CodeActionParams,
  DidChangeTextDocumentParams,
  DidCloseTextDocumentParams,
  DidOpenTextDocumentParams,
  DocumentSymbolParams,
  HoverParams,
  InitializeParams,
  LspInitializeResult,
  RpcMessage,
} from './protocol.js';
import { RPC_INTERNAL_ERROR, RPC_METHOD_NOT_FOUND, SYNC_FULL } from './protocol.js';

const SERVER_NAME = 'stellar-toml-lint';
const SERVER_VERSION = '0.1.0';

/** Injection points for tests; production uses the real network. */
export interface LspServerOptions {
  fetchImpl?: typeof fetch;
}

/** The `NETWORK_PASSPHRASE = "…"` value of a document, read without a full parse. */
function networkPassphraseIn(source: string): string | undefined {
  return /^\s*NETWORK_PASSPHRASE\s*=\s*"([^"]*)"/m.exec(source)?.[1];
}

/** Runs the LSP server until the client sends `exit` (or stdin closes). */
export async function runLspServer(
  input: NodeJS.ReadableStream = process.stdin,
  output: NodeJS.WritableStream = process.stdout,
  serverOptions: LspServerOptions = {},
): Promise<void> {
  const documents = new Map<string, string>();
  let shuttingDown = false;
  // Set on `initialize` when the editor opts in to contract lookups.
  let contractDocs: ((source: string) => ContractErrorDocs | undefined) | undefined;

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
          const options = (message.params as InitializeParams | undefined)?.initializationOptions;
          if (options?.checkContracts === true) {
            const fetchImpl = serverOptions.fetchImpl ?? fetch;
            // One cache per RPC endpoint, so a network switch in the file
            // never serves another network's contract.
            const byRpc = new Map<string, ContractErrorDocs>();
            contractDocs = (source) => {
              const rpcUrl = options.sorobanRpc ?? rpcUrlFor(networkPassphraseIn(source));
              if (rpcUrl === undefined) return undefined;
              let docs = byRpc.get(rpcUrl);
              if (docs === undefined) {
                docs = new ContractErrorDocs((id) => fetchContractWasm(id, rpcUrl, fetchImpl));
                byRpc.set(rpcUrl, docs);
              }
              return docs;
            };
          }
          const result: LspInitializeResult = {
            capabilities: {
              textDocumentSync: { openClose: true, change: SYNC_FULL },
              codeActionProvider: { codeActionKinds: ['quickfix'] },
              hoverProvider: true,
              documentSymbolProvider: true,
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
        case 'textDocument/documentSymbol': {
          const params = message.params as DocumentSymbolParams;
          const source = documents.get(params.textDocument.uri);
          if (source === undefined) return { jsonrpc: '2.0', id, result: [] };
          const result: LspDocumentSymbol[] = getDocumentSymbols(source);
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

  /**
   * Hover with contract error docs needs an RPC round trip, so it answers
   * asynchronously; LSP allows responses out of order, matched by id.
   */
  const handleContractHover = (
    message: RpcMessage,
    docs: ContractErrorDocs,
    source: string,
  ): void => {
    const params = message.params as HoverParams;
    const id = message.id ?? null;
    const base = getHoverInfo(source, params.position);
    withContractErrors(source, params.position, base, docs)
      .then((result) => send({ jsonrpc: '2.0', id, result }))
      .catch(() => send({ jsonrpc: '2.0', id, result: base }));
  };

  await readMessages(input, (message) => {
    if (message.method === 'exit') return false;
    if (message.method === 'textDocument/hover' && message.id !== undefined && contractDocs) {
      const params = message.params as HoverParams;
      const source = documents.get(params.textDocument.uri);
      const docs = source === undefined ? undefined : contractDocs(source);
      if (source !== undefined && docs !== undefined) {
        handleContractHover(message, docs, source);
        return true;
      }
    }
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
