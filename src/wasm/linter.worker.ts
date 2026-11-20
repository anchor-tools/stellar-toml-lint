/**
 * The worker side of {@link WebWorkerLinterEngine}.
 *
 * The message protocol is platform neutral: any host that can deliver a
 * `MessageEvent` can wire this handler up. The reply carries the result as a
 * transferable `ArrayBuffer`, so the diagnostics are not structured-cloned.
 */

import { lint } from '../lint.js';
import {
  decodeLintSource,
  encodeLintResponse,
  type LintWorkerMessage,
  type LintWorkerResponse,
} from './workerEngine.js';

export function handleLintWorkerMessage(message: unknown): LintWorkerResponse | undefined {
  if (typeof message !== 'object' || message === null) return undefined;
  const request = message as Partial<LintWorkerMessage>;
  if (request.type !== 'lint' || typeof request.id !== 'string') return undefined;
  if (!(request.source instanceof ArrayBuffer)) {
    return { type: 'error', id: request.id, message: 'source must be a transferred ArrayBuffer' };
  }

  try {
    const result = lint(decodeLintSource(request.source), request.options);
    return { type: 'result', id: request.id, payload: encodeLintResponse(result) };
  } catch (error) {
    return {
      type: 'error',
      id: request.id,
      message: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Binds the handler to a `postMessage` function, returning the listener a host
 * can attach to its worker scope. Response buffers are transferred.
 */
export function createLintWorkerHandler(
  post: (response: LintWorkerResponse, transfer: ArrayBuffer[]) => void,
): (event: { data: unknown } | unknown) => void {
  return (event) => {
    const data =
      typeof event === 'object' && event !== null && 'data' in event
        ? (event as { data: unknown }).data
        : event;
    const response = handleLintWorkerMessage(data);
    if (response === undefined) return;
    const transfer = response.type === 'result' ? [response.payload] : [];
    post(response, transfer);
  };
}
