import { afterEach, describe, expect, it } from 'vitest';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  deliverWebhooks,
  formatDiscordPayload,
  formatSlackPayload,
  isSupportedWebhookUrl,
  runLevel,
} from '../src/reporters/webhook.js';
import type { Diagnostic, LintResult, Severity } from '../src/types.js';

const run = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, '..', 'dist', 'cli.js');
const fixture = (name: string): string => join(here, 'fixtures', name);

// ── fixtures ────────────────────────────────────────────────────────────────

function result(
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

function diagnostic(rule: string, severity: Severity, extra: Partial<Diagnostic> = {}): Diagnostic {
  return { rule, severity, category: 'general', message: `${rule} is not valid`, ...extra };
}

interface Received {
  method?: string;
  path?: string;
  contentType?: string;
  body: string;
}

interface TestServer {
  url: string;
  received: Received[];
  close: () => Promise<void>;
}

/** A throwaway endpoint: `seq` is consumed in order, `delayMs` applies to every reply. */
async function startServer(
  options: { status?: number; seq?: number[]; delayMs?: number } = {},
): Promise<TestServer> {
  const received: Received[] = [];
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
      const reply = (): void => {
        try {
          res.writeHead(status);
          res.end('{}');
        } catch {
          // The client may have timed out and gone away; nothing to answer.
        }
      };
      if (options.delayMs !== undefined) setTimeout(reply, options.delayMs);
      else reply();
    });
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}/hook`,
    received,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

const servers: TestServer[] = [];

async function server(options: Parameters<typeof startServer>[0] = {}): Promise<TestServer> {
  const started = await startServer(options);
  servers.push(started);
  return started;
}

afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => s.close()));
});

// ── payloads ────────────────────────────────────────────────────────────────

describe('webhook payloads', () => {
  it('rates a run with errors as red in both channels', () => {
    const clean = result({ warning: 1 });
    const failing = result({ error: 1 });

    expect(runLevel(clean.counts)).toBe('warning');
    expect(runLevel(failing.counts)).toBe('error');

    const slack = formatSlackPayload([{ name: 'stellar.toml', result: failing }]);
    const discord = formatDiscordPayload([{ name: 'stellar.toml', result: failing }]);

    expect(slack.attachments[0]?.color).toBe('#E01E5A');
    expect(discord.embeds[0]?.color).toBe(0xe01e5a);
  });

  it('rates a warnings-only run as yellow and a clean run as green', () => {
    const warnings = formatSlackPayload([{ name: 'stellar.toml', result: result({ warning: 2 }) }]);
    const clean = formatDiscordPayload([
      { name: 'stellar.toml', result: result({ info: 1 }, [diagnostic('general/info', 'info')]) },
    ]);

    expect(warnings.attachments[0]?.color).toBe('#ECB22E');
    expect(clean.embeds[0]?.color).toBe(0x2eb67d);
    expect(clean.embeds[0]?.title).toContain('info');
  });

  it('groups findings by rule, counts them, and orders by frequency', () => {
    const diagnostics = [
      diagnostic('currencies/missing-issuer', 'error', { position: { line: 12, column: 1 } }),
      diagnostic('currencies/missing-issuer', 'error', { position: { line: 30, column: 1 } }),
      diagnostic('general/email', 'warning', {
        helpUri: 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0001.md',
      }),
    ];
    const run: [{ name: string; result: LintResult }] = [
      { name: 'stellar.toml', result: result({ error: 2, warning: 1 }, diagnostics) },
    ];

    const slack = formatSlackPayload(run);
    const body = JSON.stringify(slack);

    // Counted once, with the count visible, most frequent first.
    expect(body).toContain('currencies/missing-issuer');
    expect(body).toContain('×2');
    expect(body.indexOf('missing-issuer')).toBeLessThan(body.indexOf('general/email'));
    // The first diagnostic's line number travels with the rule.
    expect(body).toContain('(line 12)');
    // A help URI becomes a Slack button and an inline Discord link.
    expect(slack.attachments[0]?.blocks.some((b) => b['type'] === 'actions')).toBe(true);
    expect(JSON.stringify(formatDiscordPayload(run))).toContain(
      '[spec](https://github.com/stellar',
    );
  });

  it('says so when there is nothing to report', () => {
    const clean: [{ name: string; result: LintResult }] = [
      { name: 'stellar.toml', result: result({}) },
    ];

    expect(JSON.stringify(formatSlackPayload(clean))).toContain('No findings');
    expect(JSON.stringify(formatDiscordPayload(clean))).toContain('No findings');
  });

  it('sums counts across files and names the scope', () => {
    const multi: { name: string; result: LintResult }[] = [
      { name: 'a.toml', result: result({ error: 1 }) },
      { name: 'b.toml', result: result({ warning: 3 }) },
    ];

    const slack = formatSlackPayload(multi);
    const discord = formatDiscordPayload(multi);

    expect(slack.text).toBe('2 files: 1 error, 3 warnings');
    expect(JSON.stringify(slack)).toContain('2 files');
    expect(discord.embeds[0]?.description).toBe('2 files: 1 error, 3 warnings');
  });

  it('keeps the Discord payload free of a timestamp so runs stay comparable', () => {
    const clean: [{ name: string; result: LintResult }] = [
      { name: 'stellar.toml', result: result({}) },
    ];

    expect(formatDiscordPayload(clean).embeds[0]).not.toHaveProperty('timestamp');
  });

  it('only accepts http(s) endpoints with a host', () => {
    expect(isSupportedWebhookUrl('https://hooks.slack.com/services/x')).toBe(true);
    expect(isSupportedWebhookUrl('http://127.0.0.1:8080/hook')).toBe(true);
    expect(isSupportedWebhookUrl('ftp://example.com/hook')).toBe(false);
    expect(isSupportedWebhookUrl('not a url')).toBe(false);
    expect(isSupportedWebhookUrl('file:///etc/passwd')).toBe(false);
  });
});

// ── delivery ────────────────────────────────────────────────────────────────

const quiet: [{ name: string; result: LintResult }] = [
  { name: 'stellar.toml', result: result({ error: 1 }, [diagnostic('general/required', 'error')]) },
];

describe('webhook delivery', () => {
  it('posts the Slack payload as JSON and reports success', async () => {
    const endpoint = await server();

    const [delivery] = await deliverWebhooks(quiet, { slack: endpoint.url });

    expect(delivery).toMatchObject({ channel: 'slack', ok: true, attempts: 1, status: 200 });
    expect(endpoint.received).toHaveLength(1);
    expect(endpoint.received[0]?.method).toBe('POST');
    expect(endpoint.received[0]?.contentType).toContain('application/json');
    expect(JSON.parse(endpoint.received[0]?.body ?? '{}')).toEqual(formatSlackPayload(quiet));
  });

  it('posts a Discord embed to the Discord endpoint', async () => {
    const endpoint = await server();

    const [delivery] = await deliverWebhooks(quiet, { discord: endpoint.url });

    expect(delivery?.channel).toBe('discord');
    expect(delivery?.ok).toBe(true);
    expect(Object.keys(JSON.parse(endpoint.received[0]?.body ?? '{}'))).toEqual(['embeds']);
  });

  it('retries a 5xx and succeeds, backing off between attempts', async () => {
    const endpoint = await server({ seq: [503, 200] });
    const slept: number[] = [];

    const [delivery] = await deliverWebhooks(
      quiet,
      { slack: endpoint.url },
      { sleepImpl: async (ms) => void slept.push(ms) },
    );

    expect(delivery).toMatchObject({ ok: true, attempts: 2, status: 200 });
    expect(endpoint.received).toHaveLength(2);
    expect(slept).toEqual([250]);
  });

  it('does not retry a 4xx — the payload will not fix itself', async () => {
    const endpoint = await server({ status: 400 });

    const [delivery] = await deliverWebhooks(quiet, { slack: endpoint.url });

    expect(delivery).toMatchObject({ ok: false, attempts: 1, status: 400, error: 'HTTP 400' });
    expect(endpoint.received).toHaveLength(1);
  });

  it('gives up after the retry budget on persistent 5xx', async () => {
    const endpoint = await server({ status: 500 });

    const [delivery] = await deliverWebhooks(
      quiet,
      { slack: endpoint.url },
      { retries: 1, sleepImpl: async () => {} },
    );

    expect(delivery).toMatchObject({ ok: false, attempts: 2, status: 500 });
    expect(endpoint.received).toHaveLength(2);
  });

  it('times out instead of hanging on a slow endpoint', async () => {
    const endpoint = await server({ delayMs: 3_000 });

    const [delivery] = await deliverWebhooks(
      quiet,
      { slack: endpoint.url },
      { timeoutMs: 150, retries: 0 },
    );

    expect(delivery?.ok).toBe(false);
    expect(delivery?.attempts).toBe(1);
    expect(delivery?.error).toBeTruthy();
  });

  it('reports a network failure rather than throwing', async () => {
    // Port 1 is never listening.
    const [delivery] = await deliverWebhooks(
      quiet,
      { slack: 'http://127.0.0.1:1/hook' },
      { retries: 1, sleepImpl: async () => {} },
    );

    expect(delivery?.ok).toBe(false);
    expect(delivery?.attempts).toBe(2);
    expect(delivery?.error).toBeTruthy();
    expect(delivery?.status).toBeUndefined();
  });

  it('sends to both channels, in a stable order, and keeps going when one fails', async () => {
    const good = await server();
    const bad = await server({ status: 500 });

    const deliveries = await deliverWebhooks(
      quiet,
      { slack: bad.url, discord: good.url },
      { retries: 0 },
    );

    expect(deliveries.map((d) => d.channel)).toEqual(['slack', 'discord']);
    expect(deliveries[0]?.ok).toBe(false);
    expect(deliveries[1]?.ok).toBe(true);
    expect(good.received).toHaveLength(1);
  });

  it('rejects an unsupported URL without calling the endpoint', async () => {
    const endpoint = await server();

    const [delivery] = await deliverWebhooks(quiet, { slack: 'ftp://example.com/hook' });

    expect(delivery).toMatchObject({ ok: false, attempts: 0 });
    expect(delivery?.error).toContain('http');
    expect(endpoint.received).toHaveLength(0);
  });

  it('does nothing at all when no endpoint is configured', async () => {
    await expect(deliverWebhooks(quiet, {})).resolves.toEqual([]);
  });
});

// ── CLI ─────────────────────────────────────────────────────────────────────

async function cli(args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  try {
    const { stdout, stderr } = await run('node', [CLI, ...args], {
      env: { ...process.env, NO_COLOR: '1' },
    });
    return { code: 0, stdout, stderr };
  } catch (error) {
    const e = error as { code?: number; stdout?: string; stderr?: string };
    return { code: e.code ?? 1, stdout: e.stdout ?? '', stderr: e.stderr ?? '' };
  }
}

// These exercise the built artifact, so they depend on `npm run build`.
describe('cli webhook flags', () => {
  it('posts a red card for a broken file and still exits 1', async () => {
    const endpoint = await server();

    const { code, stderr } = await cli([
      fixture('broken.toml'),
      '--webhook-slack',
      endpoint.url,
      '--webhook-discord',
      endpoint.url,
    ]);

    expect(code).toBe(1);
    expect(stderr).not.toContain('webhook failed');
    expect(endpoint.received).toHaveLength(2);
    expect(endpoint.received[0]?.body).toContain('#E01E5A');
    expect(endpoint.received[1]?.body).toContain('embeds');
  });

  it('warns on stderr but keeps the diagnostics verdict when delivery fails', async () => {
    const endpoint = await server({ status: 500 });

    const { code, stderr } = await cli([fixture('valid.toml'), '--webhook-slack', endpoint.url]);

    // A clean file on a broken alert endpoint is still a clean file.
    expect(code).toBe(0);
    expect(stderr).toContain('Warning: slack webhook failed');
  });

  it('rejects a non-http endpoint with a usage error', async () => {
    const { code, stderr } = await cli([fixture('valid.toml'), '--webhook-slack', 'ftp://x/y']);

    expect(code).toBe(2);
    expect(stderr).toContain('--webhook-slack expects an http or https URL');
  });

  it('rejects a flag without a value', async () => {
    const { code, stderr } = await cli([fixture('valid.toml'), '--webhook-discord']);

    expect(code).toBe(2);
    expect(stderr).toContain('--webhook-discord expects a value');
  });
});
