/**
 * Minimal LSP + JSON-RPC message shapes for `stellar-toml-lint --lsp`.
 *
 * Only the subset this server speaks is typed. Hand-rolled rather than
 * depending on `vscode-languageserver` because package.json freezes runtime
 * dependencies to two packages the linter core already needs.
 */

export interface RpcMessage {
  jsonrpc: '2.0';
  id?: number | string | null;
  method?: string;
  params?: unknown;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

export interface LspInitializeResult {
  capabilities: {
    textDocumentSync?: { openClose: boolean; change: number };
    codeActionProvider?: boolean | { codeActionKinds?: string[] };
    hoverProvider?: boolean;
  };
  serverInfo?: { name: string; version: string };
}

export interface TextDocumentItem {
  uri: string;
  version: number;
  text: string;
}

export interface VersionedTextDocumentIdentifier {
  uri: string;
  version: number;
}

export interface DidOpenTextDocumentParams {
  textDocument: TextDocumentItem;
}

export interface DidChangeTextDocumentParams {
  textDocument: VersionedTextDocumentIdentifier;
  contentChanges: { text: string }[];
}

export interface DidCloseTextDocumentParams {
  textDocument: { uri: string };
}

export interface CodeActionParams {
  textDocument: { uri: string };
  range: {
    start: { line: number; character: number };
    end: { line: number; character: number };
  };
  context: { diagnostics: unknown[] };
}

export interface HoverParams {
  textDocument: { uri: string };
  position: { line: number; character: number };
}

/** JSON-RPC error codes used by this server. */
export const RPC_METHOD_NOT_FOUND = -32601;
export const RPC_INTERNAL_ERROR = -32603;

/** TextDocumentSyncKind.Incremental — full text on each change for simplicity. */
export const SYNC_FULL = 1;
