/**
 * Automated SEP-31 customer KYC callback webhook delivery verifier (issue #391).
 *
 * SEP-31 direct payment processing is asynchronous: when a customer's KYC
 * state transitions (`customer_info_needed`, `transaction_cleared`, ...), the
 * anchor is expected to notify the sending financial partner through a
 * webhook. A callback that never arrives — or arrives unauthenticated — leaves
 * cross-border settlements hanging, and a payload that does not match the
 * SEP-31 schema crashes the partner's receiver.
 *
 * This verifier exercises the contract end to end. It starts an ephemeral
 * webhook listener on the loopback interface, creates a synthetic SEP-31
 * transaction pointed at that listener, and waits for the anchor to call back:
 *
 * - no callback before the timeout emits `sep31/webhook-delivery-timeout`
 *   (warning) — the settlement hangs.
 * - a callback without a well-formed `X-Stellar-Signature` HMAC-SHA256 header
 *   emits `sep31/missing-webhook-signature` (error).
 * - a callback whose body does not match the SEP-31 webhook schema emits
 *   `sep31/webhook-payload-invalid` (warning).
 *
 * Runs under opt-in `--check-network --verify-sep31`. When the anchor does not
 * create the test transaction (auth-gated or unreachable), the audit stays
 * silent rather than reporting a delivery failure it never triggered.
 */
import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';
import { isString, isUrl } from '../predicates.js';
import { VALID_SEP31_STATUSES } from './sep31.js';

export const MISSING_WEBHOOK_SIGNATURE_RULE = 'sep31/missing-webhook-signature';
export const WEBHOOK_DELIVERY_TIMEOUT_RULE = 'sep31/webhook-delivery-timeout';
export const INVALID_WEBHOOK_PAYLOAD_RULE = 'sep31/webhook-payload-invalid';

const SEP31_SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0031.md';

/** How long the anchor has to deliver the callback after the test transfer. */
export const DEFAULT_WEBHOOK_TIMEOUT_MS = 10_000;

/** One HTTP request the anchor delivered to the ephemeral listener. */
export interface Sep31WebhookDelivery {
  method: string;
  path: string;
  /** Header names as received; lookups must be case-insensitive. */
  headers: Record<string, string | undefined>;
  body: string;
}

/** The ephemeral listener a webhook is expected to call back into. */
export interface Sep31WebhookListener {
  url: string;
  /** Resolves the first delivery, or `null` when the timeout elapses first. */
  waitForDelivery(timeoutMs: number): Promise<Sep31WebhookDelivery | null>;
  close(): Promise<void>;
}

/** Creates the listener; injectable so tests never open a real socket. */
export type Sep31WebhookListenerFactory = () => Promise<Sep31WebhookListener>;

export interface Sep31WebhookOptions {
  rules?: RuleOverrides;
  /** Listener factory override, primarily for tests. */
  createListener?: Sep31WebhookListenerFactory;
  /** How long to wait for the callback, in milliseconds. */
  timeoutMs?: number;
  /**
   * Shared HMAC secret. When provided, the `X-Stellar-Signature` value is
   * recomputed over the raw body and compared in constant time; without it,
   * the header is only checked for the expected `sha256=<hex>` shape.
   */
  webhookSecret?: string;
}

function severityFor(
  rule: string,
  fallback: Severity,
  rules: RuleOverrides | undefined,
): Severity | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' || override === 'info' ? override : fallback;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Case-insensitive header lookup. */
function headerValue(
  headers: Record<string, string | undefined>,
  name: string,
): string | undefined {
  const wanted = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === wanted) return value;
  }
  return undefined;
}

/** The outcome of validating an `X-Stellar-Signature` header. */
export interface SignatureValidation {
  /** Whether the header was present at all. */
  present: boolean;
  /** Whether the value has the right shape (and matches the secret, when known). */
  valid: boolean;
  /** Human-readable explanation for a failure. */
  reason?: string;
}

/**
 * Validates the `X-Stellar-Signature` HMAC-SHA256 value of a callback.
 *
 * SEP-31 deployments sign the raw request body and send the lowercase hex
 * digest, optionally prefixed with `sha256=`. When a shared secret is
 * available the digest is recomputed over the exact bytes received and
 * compared with `timingSafeEqual`; when it is not, only the shape can be
 * checked, which still catches unsigned callbacks.
 */
export async function verifyWebhookSignature(
  body: string,
  header: string | undefined,
  secret: string | undefined,
): Promise<SignatureValidation> {
  if (!isString(header) || header.trim() === '') {
    return { present: false, valid: false, reason: 'the X-Stellar-Signature header is missing' };
  }

  const value = header.trim().replace(/^sha256=/i, '');
  if (!/^[0-9a-f]{64}$/i.test(value)) {
    return {
      present: true,
      valid: false,
      reason: 'the X-Stellar-Signature value is not a sha256 hex digest',
    };
  }

  if (secret === undefined || secret === '') {
    return { present: true, valid: true };
  }

  const crypto = await import('node:crypto').catch(() => null);
  if (crypto === null) {
    // No HMAC implementation in this runtime: the shape is all we can prove.
    return { present: true, valid: true };
  }

  const expected = crypto.createHmac('sha256', secret).update(body, 'utf8').digest('hex');
  const expectedBytes = Buffer.from(expected, 'utf8');
  const actualBytes = Buffer.from(value.toLowerCase(), 'utf8');
  const matches =
    expectedBytes.length === actualBytes.length && crypto.timingSafeEqual(expectedBytes, actualBytes);

  return matches
    ? { present: true, valid: true }
    : {
        present: true,
        valid: false,
        reason: 'the X-Stellar-Signature HMAC does not match the request body',
      };
}

/** The documented SEP-31 events a callback may announce. */
export const SEP31_WEBHOOK_EVENT_TYPES: ReadonlySet<string> = new Set([
  'customer_info_needed',
  'transaction_cleared',
  'transaction_status_change',
  'transaction_status_changed',
  'transaction_updated',
  'customer_status_change',
  'customer_status_changed',
]);

/**
 * Validates a callback body against the SEP-31 webhook schema.
 *
 * The event must be a JSON object carrying at least a string `type` or a
 * string `status`; a `transaction_id`, when present, must be a string, and a
 * `status` must be one of the statuses the SEP-31 transaction API defines.
 * Returns `undefined` when the payload is acceptable, otherwise the reason.
 */
export function webhookPayloadProblem(payload: unknown): string | undefined {
  if (!isRecord(payload)) return 'the callback body is not a JSON object';

  const type = payload.type;
  const status = payload.status;
  if (!isString(type) && !isString(status)) {
    return 'the callback body carries neither a "type" nor a "status" field';
  }
  if (type !== undefined && !isString(type)) {
    return 'the callback "type" field must be a string';
  }
  if (status !== undefined) {
    if (!isString(status)) return 'the callback "status" field must be a string';
    if (!VALID_SEP31_STATUSES.has(status)) {
      return `the transaction status "${status}" is not a valid SEP-31 status`;
    }
  }
  if (payload.transaction_id !== undefined && !isString(payload.transaction_id)) {
    return 'the callback "transaction_id" field must be a string';
  }
  return undefined;
}

/**
 * The default listener: a short-lived HTTP server on `127.0.0.1` with an
 * ephemeral port. `node:http` is loaded lazily so the browser bundle that
 * walks this module never pulls a Node built-in in.
 */
const httpWebhookListener: Sep31WebhookListenerFactory = async () => {
  const http = await import('node:http').catch(() => null);
  if (http === null) throw new Error('node:http is unavailable in this runtime');

  let settle: (delivery: Sep31WebhookDelivery | null) => void = () => {};
  const delivered = new Promise<Sep31WebhookDelivery | null>((resolve) => {
    settle = resolve;
  });

  const server = http.createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer) => chunks.push(chunk));
    request.on('end', () => {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end('{"status":"ok"}');
      settle({
        method: request.method ?? 'POST',
        path: request.url ?? '/',
        headers: { ...request.headers } as Record<string, string | undefined>,
        body: Buffer.concat(chunks).toString('utf8'),
      });
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });

  const address = server.address();
  const port = typeof address === 'object' && address !== null ? address.port : 0;

  return {
    url: `http://127.0.0.1:${port}/sep31/webhook`,
    waitForDelivery: async (timeoutMs) => {
      let timer: NodeJS.Timeout | undefined;
      const timeout = new Promise<null>((resolve) => {
        timer = setTimeout(() => resolve(null), timeoutMs);
        if (typeof timer.unref === 'function') timer.unref();
      });
      try {
        return await Promise.race([delivered, timeout]);
      } finally {
        if (timer !== undefined) clearTimeout(timer);
      }
    },
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections?.();
      }),
  };
};

/**
 * Audits the anchor's SEP-31 webhook delivery contract.
 *
 * Returns `[]` — never throws — when `DIRECT_PAYMENT_SERVER` is absent, when
 * every webhook rule is disabled, when the listener cannot start, or when the
 * test transaction cannot be created. The listener is always closed.
 */
export async function verifySep31Webhooks(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: Sep31WebhookOptions = {},
): Promise<Diagnostic[]> {
  const server = doc.DIRECT_PAYMENT_SERVER;
  if (!isString(server) || !isUrl(server)) return [];

  const timeoutSeverity = severityFor(WEBHOOK_DELIVERY_TIMEOUT_RULE, 'warning', options.rules);
  const signatureSeverity = severityFor(MISSING_WEBHOOK_SIGNATURE_RULE, 'error', options.rules);
  const payloadSeverity = severityFor(INVALID_WEBHOOK_PAYLOAD_RULE, 'warning', options.rules);
  if (
    timeoutSeverity === undefined &&
    signatureSeverity === undefined &&
    payloadSeverity === undefined
  ) {
    return [];
  }

  const base = server.replace(/\/+$/, '');
  const diagnostics: Diagnostic[] = [];

  // Pick a receive asset from /info when the server offers one; a failure here
  // is the other SEP-31 rules' finding, not this one's.
  let assetCode = 'USD';
  try {
    const infoResponse = await fetchImpl(`${base}/info`, { redirect: 'follow' });
    if (infoResponse.ok) {
      const info: unknown = await infoResponse.json();
      if (isRecord(info) && isRecord(info.receive)) {
        assetCode = Object.keys(info.receive)[0] ?? assetCode;
      }
    }
  } catch {
    // Keep the default asset code.
  }

  let listener: Sep31WebhookListener;
  try {
    listener = await (options.createListener ?? httpWebhookListener)();
  } catch {
    return diagnostics;
  }

  const timeoutMs = options.timeoutMs ?? DEFAULT_WEBHOOK_TIMEOUT_MS;

  try {
    let transactionCreated = false;
    try {
      const response = await fetchImpl(`${base}/transactions`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          amount: '1',
          asset_code: assetCode,
          sender_id: 'stellar-toml-lint-sender',
          receiver_id: 'stellar-toml-lint-receiver',
          callback_url: listener.url,
        }),
      });
      transactionCreated = response.ok;
    } catch {
      transactionCreated = false;
    }

    // No test transfer means no callback was ever expected.
    if (!transactionCreated) return diagnostics;

    const delivery = await listener.waitForDelivery(timeoutMs);
    if (delivery === null) {
      if (timeoutSeverity !== undefined) {
        diagnostics.push({
          rule: WEBHOOK_DELIVERY_TIMEOUT_RULE,
          severity: timeoutSeverity,
          category: 'network',
          message: `DIRECT_PAYMENT_SERVER did not deliver a SEP-31 webhook to the callback URL within ${timeoutMs}ms of the test transaction`,
          path: 'DIRECT_PAYMENT_SERVER',
          helpUri: SEP31_SPEC,
          suggestion:
            'Deliver asynchronous status callbacks to the callback URL supplied with the transaction; partners cannot poll every transfer.',
        });
      }
      return diagnostics;
    }

    const signature = await verifyWebhookSignature(
      delivery.body,
      headerValue(delivery.headers, 'x-stellar-signature'),
      options.webhookSecret,
    );
    if (!signature.valid && signatureSeverity !== undefined) {
      const problem = signature.present
        ? `failed HMAC validation (${signature.reason ?? 'invalid signature'})`
        : 'carries no X-Stellar-Signature header';
      diagnostics.push({
        rule: MISSING_WEBHOOK_SIGNATURE_RULE,
        severity: signatureSeverity,
        category: 'network',
        message: `SEP-31 webhook callback ${problem}`,
        path: 'DIRECT_PAYMENT_SERVER',
        helpUri: SEP31_SPEC,
        suggestion:
          'Sign the raw callback body with HMAC-SHA256 and send the hex digest in the X-Stellar-Signature header so partners can authenticate it.',
      });
    }

    let payload: unknown;
    let parsed = true;
    try {
      payload = JSON.parse(delivery.body);
    } catch {
      parsed = false;
      payload = undefined;
    }
    const problem = parsed ? webhookPayloadProblem(payload) : 'the callback body is not valid JSON';
    if (problem !== undefined && payloadSeverity !== undefined) {
      diagnostics.push({
        rule: INVALID_WEBHOOK_PAYLOAD_RULE,
        severity: payloadSeverity,
        category: 'network',
        message: `SEP-31 webhook callback payload does not match the specification: ${problem}`,
        path: 'DIRECT_PAYMENT_SERVER',
        helpUri: SEP31_SPEC,
        suggestion:
          'Emit a JSON object carrying a "type" or a valid SEP-31 "status" (and the transaction id) on every callback.',
      });
    }
  } finally {
    await listener.close();
  }

  return diagnostics;
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const sep31WebhookRules: Rule[] = [
  {
    id: MISSING_WEBHOOK_SIGNATURE_RULE,
    category: 'network',
    severity: 'error',
    description:
      'SEP-31 status webhooks must carry a valid HMAC-SHA256 X-Stellar-Signature header',
    run() {},
  },
  {
    id: WEBHOOK_DELIVERY_TIMEOUT_RULE,
    category: 'network',
    severity: 'warning',
    description:
      'DIRECT_PAYMENT_SERVER should deliver status callbacks within the webhook timeout',
    run() {},
  },
  {
    id: INVALID_WEBHOOK_PAYLOAD_RULE,
    category: 'network',
    severity: 'warning',
    description: 'SEP-31 webhook payloads must match the documented event schema',
    run() {},
  },
];

export const sep31WebhookRuleIds: readonly string[] = sep31WebhookRules.map((rule) => rule.id);
