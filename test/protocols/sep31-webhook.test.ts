import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  INVALID_WEBHOOK_PAYLOAD_RULE,
  MISSING_WEBHOOK_SIGNATURE_RULE,
  SEP31_WEBHOOK_EVENT_TYPES,
  verifySep31Webhooks,
  verifyWebhookSignature,
  WEBHOOK_DELIVERY_TIMEOUT_RULE,
  webhookPayloadProblem,
  type Sep31WebhookDelivery,
  type Sep31WebhookListenerFactory,
} from '../../src/protocols/sep31-webhook-verifier.js';

const DIRECT_PAYMENT_SERVER = 'https://api.example.com/sep31';

const doc = {
  DIRECT_PAYMENT_SERVER,
  CURRENCIES: [{ code: 'USD', issuer: 'GDG3MQ5KRQHKY2AEVD46HMMJS6YQ2SIBYUTNEYLUJ4NQIKRMXFQORS3F' }],
};

function listenerFor(delivery: Sep31WebhookDelivery | null): {
  factory: Sep31WebhookListenerFactory;
  closed: () => boolean;
} {
  let closed = false;
  return {
    factory: async () => ({
      url: 'http://127.0.0.1:49152/sep31/webhook',
      waitForDelivery: async () => delivery,
      close: async () => {
        closed = true;
      },
    }),
    closed: () => closed,
  };
}

function transactionFetch(): typeof fetch {
  return (async (url: string | URL | Request) => {
    const target = String(url);
    if (target.endsWith('/info')) {
      return new Response(JSON.stringify({ receive: { USD: { enabled: true } } }), { status: 200 });
    }
    if (target.endsWith('/transactions')) {
      return new Response(JSON.stringify({ id: 'tx_31_001', status: 'pending_sender' }), {
        status: 201,
      });
    }
    return new Response(JSON.stringify({ error: 'not found' }), { status: 404 });
  }) as unknown as typeof fetch;
}

describe('SEP-31 webhook verifier (#391)', () => {
  const secret = 'shared-webhook-secret';
  const payload = JSON.stringify({
    type: 'customer_info_needed',
    transaction_id: 'tx_31_001',
    status: 'pending_customer_info_update',
  });
  const signature = createHmac('sha256', secret).update(payload).digest('hex');

  it('passes a correctly signed webhook delivery', async () => {
    const listener = listenerFor({
      method: 'POST',
      path: '/sep31/webhook',
      headers: { 'x-stellar-signature': `sha256=${signature}`, 'content-type': 'application/json' },
      body: payload,
    });

    const diagnostics = await verifySep31Webhooks(doc, transactionFetch(), {
      createListener: listener.factory,
      webhookSecret: secret,
    });

    expect(diagnostics).toEqual([]);
    expect(listener.closed()).toBe(true);
  });

  it('asserts sep31/missing-webhook-signature (error) when the callback is unsigned', async () => {
    const listener = listenerFor({
      method: 'POST',
      path: '/sep31/webhook',
      headers: { 'content-type': 'application/json' },
      body: payload,
    });

    const diagnostics = await verifySep31Webhooks(doc, transactionFetch(), {
      createListener: listener.factory,
      webhookSecret: secret,
    });

    const findings = diagnostics.filter((d) => d.rule === MISSING_WEBHOOK_SIGNATURE_RULE);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('error');
  });

  it('asserts sep31/missing-webhook-signature when the HMAC does not match the body', async () => {
    const listener = listenerFor({
      method: 'POST',
      path: '/sep31/webhook',
      headers: { 'x-stellar-signature': 'a'.repeat(64) },
      body: payload,
    });

    const diagnostics = await verifySep31Webhooks(doc, transactionFetch(), {
      createListener: listener.factory,
      webhookSecret: secret,
    });

    const finding = diagnostics.find((d) => d.rule === MISSING_WEBHOOK_SIGNATURE_RULE);
    expect(finding?.message).toContain('failed HMAC validation');
  });

  it('asserts sep31/webhook-delivery-timeout (warning) when no callback arrives', async () => {
    const listener = listenerFor(null);

    const diagnostics = await verifySep31Webhooks(doc, transactionFetch(), {
      createListener: listener.factory,
      timeoutMs: 20,
      webhookSecret: secret,
    });

    const findings = diagnostics.filter((d) => d.rule === WEBHOOK_DELIVERY_TIMEOUT_RULE);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('warning');
  });

  it('asserts sep31/webhook-payload-invalid (warning) for a schema mismatch', async () => {
    const invalidBody = JSON.stringify({ unexpected: true });
    const invalidSignature = createHmac('sha256', secret).update(invalidBody).digest('hex');
    const listener = listenerFor({
      method: 'POST',
      path: '/sep31/webhook',
      headers: { 'x-stellar-signature': invalidSignature },
      body: invalidBody,
    });

    const diagnostics = await verifySep31Webhooks(doc, transactionFetch(), {
      createListener: listener.factory,
      webhookSecret: secret,
    });

    const findings = diagnostics.filter((d) => d.rule === INVALID_WEBHOOK_PAYLOAD_RULE);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('warning');
  });

  it('stays silent when the test transaction cannot be created', async () => {
    const listener = listenerFor(null);
    const fetchImpl = (async () => new Response('{}', { status: 401 })) as unknown as typeof fetch;

    const diagnostics = await verifySep31Webhooks(doc, fetchImpl, {
      createListener: listener.factory,
    });

    expect(diagnostics).toEqual([]);
  });

  it('returns no diagnostics when DIRECT_PAYMENT_SERVER is not declared', async () => {
    const diagnostics = await verifySep31Webhooks({ CURRENCIES: [] });
    expect(diagnostics).toEqual([]);
  });

  it('validates signature shapes and payload schemas in isolation', async () => {
    await expect(verifyWebhookSignature('{}', undefined, secret)).resolves.toMatchObject({
      present: false,
      valid: false,
    });
    await expect(verifyWebhookSignature('{}', 'not-a-digest', secret)).resolves.toMatchObject({
      valid: false,
    });
    await expect(
      verifyWebhookSignature('{}', createHmac('sha256', secret).update('{}').digest('hex'), secret),
    ).resolves.toMatchObject({ valid: true });

    expect(webhookPayloadProblem({ status: 'not-a-status' })).toContain('not a valid SEP-31 status');
    expect(webhookPayloadProblem({ type: 'customer_info_needed' })).toBeUndefined();
    expect(SEP31_WEBHOOK_EVENT_TYPES.has('transaction_cleared')).toBe(true);
  });

  it('does not even start a listener when every webhook rule is off', async () => {
    const listener = listenerFor(null);

    const diagnostics = await verifySep31Webhooks(doc, transactionFetch(), {
      createListener: listener.factory,
      rules: {
        [WEBHOOK_DELIVERY_TIMEOUT_RULE]: 'off',
        [MISSING_WEBHOOK_SIGNATURE_RULE]: 'off',
        [INVALID_WEBHOOK_PAYLOAD_RULE]: 'off',
      },
    });

    expect(diagnostics).toEqual([]);
    expect(listener.closed()).toBe(false);
  });
});
