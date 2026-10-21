/**
 * Web Worker used by the Monaco helper.
 *
 * It speaks the package's small JSON protocol: `lint` is delegated to the same
 * worker handler the browser bundle ships, and `hover` is answered from the
 * SEP-1 field documentation the language server uses. Keeping both in one
 * worker means a playground does not have to spin up a second process just to
 * explain a key.
 */
import { getHoverInfo } from '../../../src/lsp/hover.js';
import { handleMessage } from '../../../src/worker.js';

interface WorkerScope {
  onmessage: ((event: { data: unknown }) => void) | null;
  postMessage(message: unknown): void;
}

interface HoverRequest {
  type: 'hover';
  id?: string | number;
  content: string;
  position: { line: number; character: number };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function isHoverRequest(message: unknown): message is HoverRequest {
  return (
    isRecord(message) &&
    message.type === 'hover' &&
    typeof message.content === 'string' &&
    isRecord(message.position) &&
    typeof message.position.line === 'number' &&
    typeof message.position.character === 'number'
  );
}

/** Handles one worker message; exported so the protocol is testable. */
export async function handleMonacoMessage(message: unknown): Promise<unknown> {
  if (!isHoverRequest(message)) return handleMessage(message);

  const hover = getHoverInfo(message.content, {
    line: message.position.line,
    character: message.position.character,
  });
  return { type: 'hover', id: message.id, hover };
}

/** Connects a worker-like global to the handler. */
export function connectMonacoWorker(scope: WorkerScope): void {
  scope.onmessage = (event) => {
    void handleMonacoMessage(event.data).then((response) => scope.postMessage(response));
  };
}

/**
 * Detect a Worker global; Node (where this module is only imported by tests)
 * has no `postMessage` on the global object.
 */
function looksLikeWorkerScope(candidate: unknown): candidate is WorkerScope {
  return isRecord(candidate) && typeof candidate['postMessage'] === 'function';
}

if (looksLikeWorkerScope(globalThis)) connectMonacoWorker(globalThis);
