/**
 * Web Worker wrapper — `stellar-toml-lint/worker`.
 *
 * Linting a large `stellar.toml` is cheap, but a playground that re-lints on
 * every keystroke is not, so the work belongs off the main thread. The protocol
 * is deliberately small: send `{ type: 'lint', content, options }`, get back
 * `{ type: 'result', result }`, or `{ type: 'error', message }` when the request
 * itself was malformed.
 *
 * {@link handleMessage} never rejects. A worker that throws loses the request
 * silently — the UI just stops updating — so every failure comes back as a
 * message the caller can render.
 */

import { lintBrowser, type BrowserLintOptions } from './browser.js';
import type { LintResult } from './types.js';

export interface LintRequest {
  type: 'lint';
  /** Echoed on the response so a caller can match concurrent requests. */
  id?: string | number;
  content: string;
  options?: BrowserLintOptions;
}

export interface PingRequest {
  type: 'ping';
  id?: string | number;
}

export type WorkerRequest = LintRequest | PingRequest;

export interface ResultResponse {
  type: 'result';
  id?: string | number;
  result: LintResult;
}

export interface ErrorResponse {
  type: 'error';
  id?: string | number;
  message: string;
}

export interface PongResponse {
  type: 'pong';
  id?: string | number;
}

export type WorkerResponse = ResultResponse | ErrorResponse | PongResponse;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function identifierOf(message: unknown): string | number | undefined {
  if (!isRecord(message)) return undefined;
  const id = message.id;
  return typeof id === 'string' || typeof id === 'number' ? id : undefined;
}

/**
 * Handles one worker message. Malformed input is answered, not thrown: a
 * playground sending a half-typed object should see an error it can show, and
 * a `ping` lets the page check the worker is alive before a long run.
 */
export async function handleMessage(message: unknown): Promise<WorkerResponse> {
  const id = identifierOf(message);

  try {
    if (!isRecord(message)) {
      return { type: 'error', id, message: 'Expected an object message.' };
    }

    if (message.type === 'ping') return { type: 'pong', id };

    if (message.type !== 'lint') {
      return {
        type: 'error',
        id,
        message: `Unsupported message type ${JSON.stringify(message.type)}; expected "lint" or "ping".`,
      };
    }

    if (typeof message.content !== 'string') {
      return { type: 'error', id, message: '"lint" messages need a string "content".' };
    }

    const options = isRecord(message.options) ? (message.options as BrowserLintOptions) : undefined;
    const result = await lintBrowser(message.content, options ?? {});

    return { type: 'result', id, result };
  } catch (error) {
    return {
      type: 'error',
      id,
      message: error instanceof Error ? error.message : String(error),
    };
  }
}

/** The part of a `DedicatedWorkerGlobalScope` this module needs. */
export interface WorkerScope {
  onmessage: ((event: { data: unknown }) => void) | null;
  postMessage(message: unknown): void;
}

/**
 * Routes messages from `scope` through {@link handleMessage}. Kept separate
 * from the global so it can be pointed at a fake scope in tests.
 */
export function connectWorker(scope: WorkerScope): void {
  scope.onmessage = (event) => {
    void handleMessage(event.data).then((response) => scope.postMessage(response));
  };
}

/** True for a Worker scope: Node and a page both lack a global `postMessage`. */
function looksLikeWorkerScope(candidate: unknown): candidate is WorkerScope {
  return isRecord(candidate) && typeof candidate['postMessage'] === 'function';
}

/**
 * Wires up when this module is loaded inside a worker, and does nothing
 * anywhere else, so importing it from a test or the Node build is harmless.
 */
export function installWorker(): boolean {
  const scope: unknown = globalThis;
  if (!looksLikeWorkerScope(scope)) return false;
  connectWorker(scope);
  return true;
}

installWorker();
