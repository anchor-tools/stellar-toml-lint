/**
 * Language Server Protocol server over stdio — `stellar-toml-lint --lsp`.
 *
 * Speaks only what editors need to show diagnostics, offer #42/#332 code
 * actions (quick fixes, fix-all, SAC-derivation refactor), explain a field
 * under the cursor, and colour tokens by meaning: `initialize`,
 * open/change/close sync, `publishDiagnostics`, `textDocument/codeAction`,
 * `textDocument/hover`, and `textDocument/semanticTokens/full`.
 * Framing is the standard `Content-Length` header; payloads are UTF-8 JSON.
 * Deliberately no `vscode-languageserver` dependency (package.json freezes
 * runtime deps to two packages).
 */
import process from 'node:process';
import { createHash } from 'node:crypto';
import { IncrementalParser } from '../cst/incremental-parser.js';
import type { Diagnostic } from '../types.js';
import { CODE_ACTION_KINDS, codeActionsFor, toLspDiagnostic } from './code-actions-provider.js';
import type { LspCodeAction } from './code-actions-provider.js';
import { getCompletionItems } from './completion-provider.js';
import { getHoverInfo } from './hover.js';
import type { Hover } from './hover.js';
import { computeSemanticTokens, SEMANTIC_TOKEN_LEGEND } from './semantic-tokens.js';
import type {
  CodeActionParams,
  CompletionParams,
  DidChangeTextDocumentParams,
  DidCloseTextDocumentParams,
  DidOpenTextDocumentParams,
  HoverParams,
  LspInitializeResult,
  RpcMessage,
  SemanticTokens,
  SemanticTokensParams,
} from './protocol.js';
import { RPC_INTERNAL_ERROR, RPC_METHOD_NOT_FOUND, SYNC_FULL } from './protocol.js';

const SERVER_NAME = 'stellar-toml-lint';
const SERVER_VERSION = '0.1.0';

/** Runs the LSP server until the client sends `exit` (or stdin closes). */
export async function runLspServer(
  input: NodeJS.ReadableStream = process.stdin,
  output: NodeJS.WritableStream = process.stdout,
): Promise<void> {
  const documents = new Map<
    string,
    { text: string; resultId: string; diagnostics: Diagnostic[] }
  >();
  // Incremental reparsing: keeps the previous CST per URI and re-runs only the
  // rules a keystroke can affect, falling back to a full `lint()` whenever the
  // edit is one it cannot reason about exactly.
  const parser = new IncrementalParser();
  let shuttingDown = false;
  let clientSupportsDiagnosticPull = false;

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

  const updateDocument = (uri: string, text: string): void => {
    const diagnostics = parser.update(uri, text).diagnostics;
    const resultId = createHash('sha256').update(text).digest('hex');
    documents.set(uri, { text, resultId, diagnostics });
    if (!clientSupportsDiagnosticPull) publishDiagnostics(uri, diagnostics);
  };

  const handleRequest = (message: RpcMessage): RpcMessage => {
    const id = message.id ?? null;
    try {
      switch (message.method) {
        case 'initialize': {
          const params = message.params as {
            capabilities?: { textDocument?: { diagnostic?: unknown } };
          };
          clientSupportsDiagnosticPull =
            params.capabilities?.textDocument?.diagnostic !== undefined;
          const result: LspInitializeResult = {
            capabilities: {
              textDocumentSync: { openClose: true, change: SYNC_FULL },
              codeActionProvider: { codeActionKinds: [...CODE_ACTION_KINDS] },
              completionProvider: { resolveProvider: false, triggerCharacters: ['=', '.'] },
              hoverProvider: true,
              semanticTokensProvider: { legend: SEMANTIC_TOKEN_LEGEND, full: true },
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
          const document = documents.get(params.textDocument.uri);
          if (document === undefined) return { jsonrpc: '2.0', id, result: [] };
          const result: LspCodeAction[] = codeActionsFor(
            document.text,
            params.textDocument.uri,
            document.diagnostics,
            params.range,
            params.context?.only,
          );
          return { jsonrpc: '2.0', id, result };
        }
        case 'textDocument/hover': {
          const params = message.params as HoverParams;
          const document = documents.get(params.textDocument.uri);
          if (document === undefined) return { jsonrpc: '2.0', id, result: null };
          const result: Hover | null = getHoverInfo(document.text, params.position);
          return { jsonrpc: '2.0', id, result };
        }
        case 'textDocument/completion': {
          const params = message.params as CompletionParams;
          const document = documents.get(params.textDocument.uri);
          const result =
            document === undefined
              ? { isIncomplete: false, items: [] }
              : getCompletionItems(document.text, params.position);
          return { jsonrpc: '2.0', id, result };
        }
        case 'textDocument/semanticTokens/full': {
          const params = message.params as SemanticTokensParams;
          const document = documents.get(params.textDocument.uri);
          const result: SemanticTokens = {
            data: document === undefined ? [] : computeSemanticTokens(document.text),
          };
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
        updateDocument(params.textDocument.uri, params.textDocument.text);
        return true;
      }
      case 'textDocument/didChange': {
        const params = message.params as DidChangeTextDocumentParams;
        const text = params.contentChanges[params.contentChanges.length - 1]?.text;
        if (text === undefined) return true;
        updateDocument(params.textDocument.uri, text);
        return true;
      }
      case 'textDocument/didClose': {
        const params = message.params as DidCloseTextDocumentParams;
        documents.delete(params.textDocument.uri);
        parser.close(params.textDocument.uri);
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
