import { afterEach, describe, expect, it } from 'vitest';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';

import {
  deliverWebhooks,
  formatDiscordPayload,
  formatSlackPayload,
  isSupportedWebhookUrl,
  runLevel,
} from '../src/reporters/webhook.js';
import type { Diagnostic, LintResult, Severity } from '../src/types.js';

function createResult(
  counts: Partial<Record<Severity, number>>,
  diagnostics: Diagnostic[] = [],
): LintResult {
  const full: Record<Severity, number> = {
    error: counts.error ?? 0,
    warning: counts.warning ?? 0,
    info: counts.info ?? 0,
  };
  return { diagnostics, ok: full.error === 0, counts: full };
}

function createDiagnostic(
  rule: string,
  severity: Severity,
  extra: Partial<Diagnostic> = {},
): Diagnostic {
  return { rule, severity, category: 'general', message: `${rule} is not valid`, ...extra };
}

interface ReceivedRequest {
  method?: string;
  path?: string;
  contentType?: string;
  body: string;
}

interface MockWebhookServer {
  url: string;
  received: ReceivedRequest[];
  close: () => Promise<void>;
}

async function startMockServer(
  options: { status?: number; seq?: number[] } = {},
): Promise<MockWebhookServer> {
  const received: ReceivedRequest[] = [];
  const seq = [...(options.seq ?? [])];

  const server: Server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
    req.on('end', () => {
      received.push({
        method: req.method,
        path: req.url,
        contentType: req.headers['content-type'],
        body: Buffer.concat(chunks).toString('utf8'),
      });
      const status = seq.length > 0 ? (seq.shift() ?? 200) : (options.status ?? 200);
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end('{"ok":true}');
    });
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}/webhook`,
    received,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

const activeServers: MockWebhookServer[] = [];

async function mockServer(
  options: Parameters<typeof startMockServer>[0] = {},
): Promise<MockWebhookServer> {
  const server = await startMockServer(options);
  activeServers.push(server);
  return server;
}

afterEach(async () => {
  await Promise.all(activeServers.splice(0).map((s) => s.close()));
});

describe('webhook-reporter: Slack Block Kit cards', () => {
  it('formats results into a Slack Block Kit card with color coding and error breakdown', () => {
    const diagnostics: Diagnostic[] = [
      createDiagnostic('currencies/missing-issuer', 'error', {
        position: { line: 15, column: 1 },
      }),
      createDiagnostic('general/email', 'warning', {
        helpUri: 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0001.md',
      }),
    ];
    const run = [
      { name: 'stellar.toml', result: createResult({ error: 1, warning: 1 }, diagnostics) },
    ];

    const payload = formatSlackPayload(run);

    expect(payload.text).toContain('stellar.toml: 1 error, 1 warning');
    expect(payload.attachments).toHaveLength(1);
    expect(payload.attachments[0]?.color).toBe('#E01E5A'); // Red for error

    const blocks = payload.attachments[0]?.blocks ?? [];
    expect(blocks.some((b) => b['type'] === 'header')).toBe(true);
    expect(blocks.some((b) => b['type'] === 'section')).toBe(true);
    expect(blocks.some((b) => b['type'] === 'actions')).toBe(true);
  });

  it('mocks Slack webhook receiving Block Kit payload -> passes', async () => {
    const server = await mockServer();
    const run = [
      {
        name: 'stellar.toml',
        result: createResult({ error: 1 }, [createDiagnostic('general/required', 'error')]),
      },
    ];

    const [delivery] = await deliverWebhooks(run, { slack: server.url });

    expect(delivery).toBeDefined();
    expect(delivery?.channel).toBe('slack');
    expect(delivery?.ok).toBe(true);
    expect(delivery?.status).toBe(200);

    expect(server.received).toHaveLength(1);
    const req = server.received[0];
    expect(req?.method).toBe('POST');
    expect(req?.contentType).toContain('application/json');

    const parsed = JSON.parse(req?.body ?? '{}');
    expect(parsed.attachments).toBeDefined();
    expect(parsed.attachments[0].color).toBe('#E01E5A');
    expect(parsed.attachments[0].blocks).toBeDefined();
  });
});

describe('webhook-reporter: Discord Rich Embeds', () => {
  it('formats results into Discord Rich Embeds with color coding and fields', () => {
    const diagnostics: Diagnostic[] = [
      createDiagnostic('currencies/missing-issuer', 'error'),
      createDiagnostic('general/email', 'warning', {
        helpUri: 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0001.md',
      }),
    ];
    const run = [
      { name: 'stellar.toml', result: createResult({ error: 1, warning: 1 }, diagnostics) },
    ];

    const payload = formatDiscordPayload(run);

    expect(payload.embeds).toHaveLength(1);
    const embed = payload.embeds[0];
    expect(embed?.title).toContain('stellar.toml compliance — error');
    expect(embed?.color).toBe(0xe01e5a);
    expect(embed?.fields).toBeDefined();
    expect(embed?.fields.some((f) => f.name === 'Errors')).toBe(true);
    expect(embed?.fields.some((f) => f.name === 'Warnings')).toBe(true);
    expect(embed?.footer.text).toBe('stellar-toml-lint');
  });

  it('mocks Discord webhook receiving Rich Embed -> passes', async () => {
    const server = await mockServer();
    const run = [
      {
        name: 'stellar.toml',
        result: createResult({ warning: 2 }, [
          createDiagnostic('general/version', 'warning'),
          createDiagnostic('general/email', 'warning'),
        ]),
      },
    ];

    const [delivery] = await deliverWebhooks(run, { discord: server.url });

    expect(delivery).toBeDefined();
    expect(delivery?.channel).toBe('discord');
    expect(delivery?.ok).toBe(true);
    expect(delivery?.status).toBe(200);

    expect(server.received).toHaveLength(1);
    const req = server.received[0];
    expect(req?.method).toBe('POST');
    expect(req?.contentType).toContain('application/json');

    const parsed = JSON.parse(req?.body ?? '{}');
    expect(parsed.embeds).toBeDefined();
    expect(parsed.embeds[0].color).toBe(0xecb22e); // Yellow for warning
    expect(parsed.embeds[0].title).toContain('warning');
  });
});

describe('webhook-reporter: Delivery retries and URL validation', () => {
  it('retries on server error and succeeds', async () => {
    const server = await mockServer({ seq: [503, 200] });
    const run = [{ name: 'stellar.toml', result: createResult({ error: 0 }) }];

    const [delivery] = await deliverWebhooks(
      run,
      { slack: server.url },
      { sleepImpl: async () => {} },
    );

    expect(delivery?.ok).toBe(true);
    expect(delivery?.attempts).toBe(2);
    expect(server.received).toHaveLength(2);
  });

  it('validates supported webhook URLs', () => {
    expect(isSupportedWebhookUrl('https://hooks.slack.com/services/test')).toBe(true);
    expect(isSupportedWebhookUrl('http://127.0.0.1:9000/webhook')).toBe(true);
    expect(isSupportedWebhookUrl('ftp://example.com/webhook')).toBe(false);
    expect(isSupportedWebhookUrl('javascript:alert(1)')).toBe(false);
  });

  it('determines correct run severity level', () => {
    expect(runLevel({ error: 1, warning: 0, info: 0 })).toBe('error');
    expect(runLevel({ error: 0, warning: 1, info: 0 })).toBe('warning');
    expect(runLevel({ error: 0, warning: 0, info: 1 })).toBe('info');
    expect(runLevel({ error: 0, warning: 0, info: 0 })).toBe('info');
  });

  it('honours Retry-After header on 429 rate limit responses', async () => {
    let callCount = 0;
    const slept: number[] = [];
    const fetchMock = async () => {
      callCount++;
      if (callCount === 1) {
        return new Response('{"error":"rate_limited"}', {
          status: 429,
          headers: { 'retry-after': '0.5' },
        });
      }
      return new Response('{"ok":true}', { status: 200 });
    };

    const run = [{ name: 'stellar.toml', result: createResult({ error: 0 }) }];
    const [delivery] = await deliverWebhooks(
      run,
      { slack: 'https://hooks.slack.com/services/test' },
      {
        fetchImpl: fetchMock as unknown as typeof fetch,
        sleepImpl: async (ms) => void slept.push(ms),
      },
    );

    expect(delivery?.ok).toBe(true);
    expect(delivery?.attempts).toBe(2);
    expect(slept).toEqual([500]);
  });
});
