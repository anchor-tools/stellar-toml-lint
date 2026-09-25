import { afterEach, describe, expect, it } from 'vitest';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { MonitorDaemon } from '../src/monitor/daemon.js';

const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, '..', 'dist', 'cli.js');

// ── helpers ───────────────────────────────────────────────────

interface Received {
  method?: string;
  contentType?: string;
  body: string;
}

interface TestServer {
  url: string;
  received: Received[];
  close: () => Promise<void>;
}

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
        contentType: req.headers['content-type'],
        body: Buffer.concat(chunks).toString('utf8'),
      });
      const status = seq.length > 0 ? (seq.shift() ?? 200) : (options.status ?? 200);
      const reply = (): void => {
        try {
          res.writeHead(status);
          res.end('{}');
        } catch {
          /* client may have timed out */
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

// ── MonitorDaemon tests ───────────────────────────────────────

describe('MonitorDaemon', () => {
  it('fires a webhook when the response changes', async () => {
    const webhookReceived: Received[] = [];
    const webhookServer = createServer((req: IncomingMessage, res: ServerResponse) => {
      const chunks: Buffer[] = [];
      req.on('data', (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
      req.on('end', () => {
        webhookReceived.push({
          method: req.method,
          contentType: req.headers['content-type'],
          body: Buffer.concat(chunks).toString('utf8'),
        });
        res.writeHead(200);
        res.end('{}');
      });
    });
    await new Promise<void>((resolve) => webhookServer.listen(0, '127.0.0.1', resolve));
    const { port: wp } = webhookServer.address() as AddressInfo;
    const webhookUrl = `http://127.0.0.1:${wp}/webhook`;

    let callCount = 0;
    const source = createServer((_req: IncomingMessage, res: ServerResponse) => {
      callCount++;
      if (callCount === 1) {
        res.writeHead(200);
        res.end('VERSION="1.0.0"\n');
      } else {
        res.writeHead(200);
        res.end('VERSION="2.0.0"\n');
      }
    });
    await new Promise<void>((resolve) => source.listen(0, '127.0.0.1', resolve));
    const { port: sp } = source.address() as AddressInfo;
    const sourceUrl = `http://127.0.0.1:${sp}/stellar.toml`;

    const daemon = new MonitorDaemon({ url: sourceUrl, interval: 50, webhookUrl });
    await daemon.start();
    await new Promise((resolve) => setTimeout(resolve, 600));
    daemon.stop();
    webhookServer.close();
    source.close();

    expect(webhookReceived.length).toBeGreaterThanOrEqual(1);
    const parsed = JSON.parse(webhookReceived[0]!.body);
    expect(parsed).toHaveProperty('added_fields');
    expect(parsed).toHaveProperty('modified_fields');
    expect(parsed).toHaveProperty('deleted_fields');
    expect(parsed).toHaveProperty('timestamp');
    expect(parsed).toHaveProperty('url');
  });

  it('does not fire a webhook when the response is unchanged', async () => {
    const endpoint = await server();
    const source = createServer((_req: IncomingMessage, res: ServerResponse) => {
      res.writeHead(200);
      res.end('VERSION="1.0.0"\n');
    });
    await new Promise<void>((resolve) => source.listen(0, '127.0.0.1', resolve));
    const { port } = source.address() as AddressInfo;
    const sourceUrl = `http://127.0.0.1:${port}/stellar.toml`;

    const daemon = new MonitorDaemon({ url: sourceUrl, interval: 50, webhookUrl: endpoint.url });
    await daemon.start();
    await new Promise((resolve) => setTimeout(resolve, 300));
    daemon.stop();

    expect(endpoint.received).toHaveLength(0);
    source.close();
  });

  it('applies exponential backoff on network failures', async () => {
    let attemptCount = 0;
    const source = createServer((_req: IncomingMessage, res: ServerResponse) => {
      attemptCount++;
      res.writeHead(500);
      res.end('error');
    });
    await new Promise<void>((resolve) => source.listen(0, '127.0.0.1', resolve));
    const { port } = source.address() as AddressInfo;
    const sourceUrl = `http://127.0.0.1:${port}/stellar.toml`;

    const daemon = new MonitorDaemon({ url: sourceUrl, interval: 50 });
    await daemon.start();
    await new Promise((resolve) => setTimeout(resolve, 2000));
    daemon.stop();
    source.close();

    expect(attemptCount).toBeGreaterThan(1);
  });

  it('produces consistent hashes for the same data', () => {
    const daemon = new MonitorDaemon({ url: 'http://example.com' });
    const data = 'VERSION="1.0.0"\n';
    expect(daemon.computeHash(data)).toBe(daemon.computeHash(data));
    expect(daemon.computeHash(data)).toMatch(/^[a-f0-9]{64}$/);
  });

  it('produces different hashes for different data', () => {
    const daemon = new MonitorDaemon({ url: 'http://example.com' });
    expect(daemon.computeHash('a')).not.toBe(daemon.computeHash('b'));
  });

  it('computes diff correctly for added fields', () => {
    const daemon = new MonitorDaemon({ url: 'http://example.com' });
    const oldData = 'VERSION="1.0.0"\n';
    const newData = 'VERSION="1.0.0"\nNETWORK_PASSPHRASE="test"\n';
    const diff = daemon.computeDiff(oldData, newData);
    expect(diff.added).toContain('NETWORK_PASSPHRASE');
    expect(diff.modified).toEqual([]);
    expect(diff.deleted).toEqual([]);
  });

  it('computes diff correctly for modified fields', () => {
    const daemon = new MonitorDaemon({ url: 'http://example.com' });
    const oldData = 'VERSION="1.0.0"\n';
    const newData = 'VERSION="2.0.0"\n';
    const diff = daemon.computeDiff(oldData, newData);
    expect(diff.modified).toContain('VERSION');
    expect(diff.added).toEqual([]);
    expect(diff.deleted).toEqual([]);
  });

  it('computes diff correctly for deleted fields', () => {
    const daemon = new MonitorDaemon({ url: 'http://example.com' });
    const oldData = 'VERSION="1.0.0"\nNETWORK_PASSPHRASE="test"\n';
    const newData = 'VERSION="1.0.0"\n';
    const diff = daemon.computeDiff(oldData, newData);
    expect(diff.deleted).toContain('NETWORK_PASSPHRASE');
    expect(diff.added).toEqual([]);
    expect(diff.modified).toEqual([]);
  });

  it('diff result includes timestamp and url', () => {
    const daemon = new MonitorDaemon({ url: 'http://example.com' });
    const diff = daemon.computeDiff('a', 'b');
    expect(diff.timestamp).toBeTruthy();
    expect(diff.url).toBe('http://example.com');
  });
});

// ── CLI monitor tests ─────────────────────────────────────────

describe('cli --monitor', () => {
  it('starts and runs the monitor daemon', async () => {
    const source = createServer((_req: IncomingMessage, res: ServerResponse) => {
      res.writeHead(200);
      res.end('VERSION="1.0.0"\n');
    });
    await new Promise<void>((resolve) => source.listen(0, '127.0.0.1', resolve));
    const { port } = source.address() as AddressInfo;
    const sourceUrl = `http://127.0.0.1:${port}/stellar.toml`;

    const child = spawn('node', [CLI, sourceUrl, '--monitor', '--interval', '50'], {
      env: { ...process.env, NO_COLOR: '1' },
    });

    await new Promise((resolve) => setTimeout(resolve, 300));
    child.kill('SIGKILL');
    source.close();
  });
});
