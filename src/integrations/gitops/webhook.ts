import {
  createServer as createHttpServer,
  type IncomingMessage,
  type Server as HttpServer,
  type ServerResponse,
} from 'node:http';
import { createServer as createHttpsServer, type Server as HttpsServer } from 'node:https';
import { lint } from '../../lint.js';

const MAX_REVIEW_BYTES = 1024 * 1024;

interface AdmissionReview {
  apiVersion?: unknown;
  kind?: unknown;
  request?: {
    uid?: unknown;
    object?: unknown;
  };
}

export interface AdmissionResponse {
  apiVersion: string;
  kind: 'AdmissionReview';
  response: {
    uid: string;
    allowed: boolean;
    status?: { message: string };
    warnings?: string[];
  };
}

function tomlFromObject(value: unknown): string | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  const object = value as Record<string, unknown>;
  for (const key of ['stellarToml', 'stellar_toml', 'stellar.toml']) {
    if (typeof object[key] === 'string') return object[key] as string;
  }

  const data = object.data;
  if (typeof data === 'object' && data !== null && !Array.isArray(data)) {
    const source = (data as Record<string, unknown>)['stellar.toml'];
    if (typeof source === 'string') return source;
  }
  const binaryData = object.binaryData;
  if (typeof binaryData === 'object' && binaryData !== null && !Array.isArray(binaryData)) {
    const encoded = (binaryData as Record<string, unknown>)['stellar.toml'];
    if (typeof encoded === 'string') return Buffer.from(encoded, 'base64').toString('utf8');
  }
  return undefined;
}

/** Convert a Kubernetes AdmissionReview into an allow/deny response. */
export function evaluateGitOpsAdmission(review: AdmissionReview): AdmissionResponse {
  const request = review.request;
  const uid = typeof request?.uid === 'string' ? request.uid : '';
  const source = tomlFromObject(request?.object);
  const diagnostics = source === undefined ? [] : lint(source).diagnostics;
  const messages =
    source === undefined
      ? ['Admission object must contain stellar.toml in data, binaryData, or stellarToml']
      : diagnostics.map((diagnostic) => `${diagnostic.severity}: ${diagnostic.message}`);
  const allowed = source !== undefined && !diagnostics.some(({ severity }) => severity === 'error');
  const apiVersion =
    typeof review.apiVersion === 'string' ? review.apiVersion : 'admission.k8s.io/v1';

  return {
    apiVersion,
    kind: 'AdmissionReview',
    response: {
      uid,
      allowed,
      ...(!allowed ? { status: { message: messages.join('; ') } } : {}),
      ...(allowed && diagnostics.length > 0 ? { warnings: messages } : {}),
    },
  };
}

async function readBody(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > MAX_REVIEW_BYTES) throw new Error('AdmissionReview body exceeds 1 MiB');
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString('utf8');
}

function sendJson(response: ServerResponse, status: number, value: unknown): void {
  response.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  response.end(JSON.stringify(value));
}

function handleAdmission(request: IncomingMessage, response: ServerResponse): void {
  void (async () => {
    if (request.method !== 'POST') {
      sendJson(response, 405, { error: 'Only POST is supported' });
      return;
    }
    try {
      const body = JSON.parse(await readBody(request)) as AdmissionReview;
      if (
        body.kind !== 'AdmissionReview' ||
        typeof body.request !== 'object' ||
        body.request === null
      ) {
        sendJson(response, 400, { error: 'Expected an AdmissionReview request' });
        return;
      }
      sendJson(response, 200, evaluateGitOpsAdmission(body));
    } catch (error) {
      sendJson(response, 400, {
        error: error instanceof Error ? error.message : 'Invalid AdmissionReview body',
      });
    }
  })();
}

/** Create an HTTP webhook server, useful behind a TLS-terminating proxy. */
export function createGitOpsWebhookServer(): HttpServer {
  return createHttpServer(handleAdmission);
}

/** Create the TLS server Kubernetes admission webhooks require. */
export function createGitOpsWebhookHttpsServer(options: {
  key: Buffer;
  cert: Buffer;
}): HttpsServer {
  return createHttpsServer(options, handleAdmission);
}
