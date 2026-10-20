import { describe, expect, it } from 'vitest';
import {
  analyzeSep24PostMessages,
  checkSep24PostMessage,
  sep24PostMessageRules,
  type CapturedPostMessage,
  type PostMessageCaptureOptions,
  type Sep24PostMessageLauncher,
} from '../../src/protocols/sep24-postmessage.js';
import { verifySep24 } from '../../src/protocols/sep24.js';

const SEP24 = 'https://anchor.example.com/sep24';
const INTERACTIVE = 'https://anchor.example.com/interactive/session-1';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function launcherFor(
  events: readonly CapturedPostMessage[],
  seen: PostMessageCaptureOptions[] = [],
): Sep24PostMessageLauncher {
  return {
    async capture(options) {
      seen.push(options);
      return events;
    },
  };
}

function doc(): Record<string, unknown> {
  return { TRANSFER_SERVER_SEP0024: SEP24 };
}

describe('analyzeSep24PostMessages', () => {
  it('passes a compliant transaction-completed callback', () => {
    const diagnostics = analyzeSep24PostMessages([
      {
        direction: 'sent',
        targetOrigin: 'https://wallet.example.com',
        payload: {
          type: 'stellar:transaction_completed',
          transaction: { id: 'tx-1', status: 'completed' },
        },
      },
    ]);

    expect(diagnostics).toEqual([]);
  });

  it('accepts a JSON-serialized SEP-24 payload', () => {
    const diagnostics = analyzeSep24PostMessages([
      {
        targetOrigin: 'https://wallet.example.com',
        payload: JSON.stringify({ type: 'stellar:fee_acknowledged' }),
      },
    ]);

    expect(diagnostics).toEqual([]);
  });

  it('flags a wildcard targetOrigin with sep24/insecure-postmessage-wildcard', () => {
    const diagnostics = analyzeSep24PostMessages([
      {
        targetOrigin: '*',
        payload: { type: 'stellar:transaction_completed' },
      },
    ]);

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      rule: 'sep24/insecure-postmessage-wildcard',
      severity: 'warning',
      category: 'sep24',
      path: 'TRANSFER_SERVER_SEP0024',
    });
  });

  it('flags a malformed payload with sep24/malformed-postmessage-payload', () => {
    const diagnostics = analyzeSep24PostMessages([
      {
        targetOrigin: 'https://wallet.example.com',
        payload: { type: 'stellar:transaction_completed', transaction_id: 42 },
      },
    ]);

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      rule: 'sep24/malformed-postmessage-payload',
      severity: 'error',
      category: 'sep24',
      path: 'TRANSFER_SERVER_SEP0024',
    });
    expect(diagnostics[0]?.message).toContain('transaction_id');
  });

  it('ignores malformed callbacks that arrived from the wallet', () => {
    const diagnostics = analyzeSep24PostMessages([
      {
        direction: 'received',
        targetOrigin: '*',
        payload: 'not-json',
      },
    ]);

    expect(diagnostics).toEqual([]);
  });

  it('honours severity overrides', () => {
    const diagnostics = analyzeSep24PostMessages(
      [{ targetOrigin: '*', payload: { type: 'stellar:transaction_completed' } }],
      { rules: { 'sep24/insecure-postmessage-wildcard': 'error' } },
    );

    expect(diagnostics[0]?.severity).toBe('error');
  });

  it('honours --off', () => {
    const diagnostics = analyzeSep24PostMessages(
      [{ targetOrigin: '*', payload: { type: 'stellar:transaction_completed' } }],
      { rules: { 'sep24/insecure-postmessage-wildcard': 'off' } },
    );

    expect(diagnostics).toEqual([]);
  });
});

describe('checkSep24PostMessage', () => {
  it('captures an explicit interactive URL and analyzes the events', async () => {
    const seen: PostMessageCaptureOptions[] = [];
    const diagnostics = await checkSep24PostMessage(doc(), async () => jsonResponse({}), {
      url: INTERACTIVE,
      timeoutMs: 25,
      launcher: launcherFor(
        [{ targetOrigin: '*', payload: { type: 'stellar:transaction_completed' } }],
        seen,
      ),
    });

    expect(seen).toEqual([{ url: INTERACTIVE, timeoutMs: 25 }]);
    expect(diagnostics[0]?.rule).toBe('sep24/insecure-postmessage-wildcard');
  });

  it('discovers the interactive URL from /info and a deposit session', async () => {
    const requests: { url: string; init: RequestInit }[] = [];
    const fetchImpl = (async (input: string | URL | Request, init: RequestInit = {}) => {
      const url = String(input);
      requests.push({ url, init });
      if (url.endsWith('/info')) {
        return jsonResponse({
          deposit: { USD: { enabled: true } },
          withdraw: { USD: { enabled: true } },
        });
      }
      if (url.endsWith('/transactions/deposit/interactive')) {
        return jsonResponse({ id: 'tx-1', url: INTERACTIVE });
      }
      throw new Error(`unexpected request to ${url}`);
    }) as typeof fetch;

    const seen: PostMessageCaptureOptions[] = [];
    const diagnostics = await checkSep24PostMessage(doc(), fetchImpl, {
      launcher: launcherFor([], seen),
    });

    expect(seen[0]?.url).toBe(INTERACTIVE);
    expect(diagnostics).toEqual([]);

    const session = requests.find((request) =>
      request.url.endsWith('/transactions/deposit/interactive'),
    );
    expect(session?.init.method).toBe('POST');
    expect(JSON.parse(String(session?.init.body))).toEqual({ asset_code: 'USD', amount: '10' });
  });

  it('stays silent when no interactive URL can be discovered', async () => {
    let launched = false;
    const launcher: Sep24PostMessageLauncher = {
      async capture() {
        launched = true;
        return [];
      },
    };

    const diagnostics = await checkSep24PostMessage(doc(), async () => jsonResponse({}), {
      launcher,
    });

    expect(diagnostics).toEqual([]);
    expect(launched).toBe(false);
  });
});

describe('verifySep24', () => {
  it('stays silent without a transfer server or postMessage request', async () => {
    const diagnostics = await verifySep24({}, async () => jsonResponse({}), {
      verifyPostmessage: false,
    });

    expect(diagnostics).toEqual([]);
  });

  it('delegates to the postMessage verifier when enabled', async () => {
    const diagnostics = await verifySep24({}, async () => jsonResponse({}), {
      verifyPostmessage: true,
      postmessage: {
        url: INTERACTIVE,
        launcher: launcherFor([
          {
            targetOrigin: 'https://wallet.example.com',
            payload: { type: 'stellar:transaction_completed' },
          },
        ]),
      },
    });

    expect(diagnostics).toEqual([]);
  });
});

describe('sep24PostMessageRules', () => {
  it('registers the wildcard and malformed-payload rules', () => {
    expect(
      sep24PostMessageRules.map((rule) => ({
        id: rule.id,
        severity: rule.severity,
        category: rule.category,
      })),
    ).toEqual([
      {
        id: 'sep24/insecure-postmessage-wildcard',
        severity: 'warning',
        category: 'sep24',
      },
      {
        id: 'sep24/malformed-postmessage-payload',
        severity: 'error',
        category: 'sep24',
      },
    ]);
  });
});
