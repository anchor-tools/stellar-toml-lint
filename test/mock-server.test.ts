import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AddressInfo } from 'node:net';
import { Keypair, Networks, TransactionBuilder, type Transaction } from '@stellar/stellar-base';
import { lint } from '../src/lint.js';
import { createMockServer, formatRoutingTable, type MockServer } from '../src/mock/server.js';

const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, '..', 'dist', 'cli.js');
const FIXTURE = join(here, 'fixtures', 'valid.toml');
const SOURCE = readFileSync(FIXTURE, 'utf8');
const DOC = lint(SOURCE).parsed ?? {};

const USDX_ISSUER = 'GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY';
const client = Keypair.random();

function listen(mock: MockServer): Promise<string> {
  return new Promise((resolve) => {
    mock.server.listen(0, '127.0.0.1', () => {
      const { port } = mock.server.address() as AddressInfo;
      resolve(`http://127.0.0.1:${port}`);
    });
  });
}

function close(mock: MockServer): Promise<void> {
  return new Promise((resolve) => {
    mock.server.closeAllConnections();
    mock.server.close(() => resolve());
  });
}

describe('mock server', () => {
  let mock: MockServer;
  let base: string;

  beforeAll(async () => {
    mock = createMockServer({ source: SOURCE, doc: DOC });
    base = await listen(mock);
  });

  afterAll(() => close(mock));

  it('serves the stellar.toml byte for byte with CORS and text/plain', async () => {
    const res = await fetch(`${base}/.well-known/stellar.toml`);
    expect(res.status).toBe(200);
    expect(res.headers.get('access-control-allow-origin')).toBe('*');
    expect(res.headers.get('content-type')).toMatch(/^text\/plain/);
    expect(await res.text()).toBe(SOURCE);
  });

  it('answers CORS pre-flight requests', async () => {
    const res = await fetch(`${base}/.well-known/stellar.toml`, { method: 'OPTIONS' });
    expect(res.status).toBe(204);
    expect(res.headers.get('access-control-allow-origin')).toBe('*');
  });

  it('returns a valid SEP-10 challenge transaction from /auth', async () => {
    const res = await fetch(`${base}/auth?account=${client.publicKey()}&home_domain=example.com`);
    expect(res.status).toBe(200);
    expect(res.headers.get('access-control-allow-origin')).toBe('*');

    const body = (await res.json()) as { transaction: string; network_passphrase: string };
    expect(body.network_passphrase).toBe(Networks.PUBLIC);

    const tx = TransactionBuilder.fromXDR(body.transaction, Networks.PUBLIC) as Transaction;
    const server = mock.signer.keypair;

    expect(tx.source).toBe(server.publicKey());
    expect(tx.sequence).toBe('0');

    const { minTime, maxTime } = tx.timeBounds ?? { minTime: '0', maxTime: '0' };
    expect(Number(maxTime) - Number(minTime)).toBe(900);

    const [auth, webAuthDomain] = tx.operations;
    expect(auth).toMatchObject({ type: 'manageData', name: 'example.com auth' });
    expect(auth?.source).toBe(client.publicKey());
    const nonce = (auth as { value: Buffer }).value;
    expect(nonce).toHaveLength(64);
    expect(Buffer.from(nonce.toString(), 'base64')).toHaveLength(48);

    expect(webAuthDomain).toMatchObject({ type: 'manageData', name: 'web_auth_domain' });
    expect(webAuthDomain?.source).toBe(server.publicKey());
    expect((webAuthDomain as { value: Buffer }).value.toString()).toBe('127.0.0.1');

    expect(tx.signatures).toHaveLength(1);
    expect(server.verify(tx.hash(), tx.signatures[0]!.signature())).toBe(true);
  });

  it('issues a fresh nonce for every challenge', async () => {
    const nonceOf = async (): Promise<string> => {
      const res = await fetch(`${base}/auth?account=${client.publicKey()}`);
      const { transaction } = (await res.json()) as { transaction: string };
      const tx = TransactionBuilder.fromXDR(transaction, Networks.PUBLIC) as Transaction;
      return String((tx.operations[0] as { value: Buffer }).value);
    };
    expect(await nonceOf()).not.toBe(await nonceOf());
  });

  it('rejects /auth without a valid account', async () => {
    expect((await fetch(`${base}/auth`)).status).toBe(400);
    expect((await fetch(`${base}/auth?account=GNOTANACCOUNT`)).status).toBe(400);
  });

  it('lists the fixture currencies in /sep24/info', async () => {
    const res = await fetch(`${base}/sep24/info`);
    expect(res.status).toBe(200);
    const info = (await res.json()) as {
      deposit: Record<string, { enabled: boolean }>;
      withdraw: Record<string, { enabled: boolean }>;
    };
    expect(Object.keys(info.deposit)).toEqual(['USDX', 'EXPL', 'native']);
    expect(Object.keys(info.withdraw)).toEqual(['USDX', 'EXPL', 'native']);
    expect(info.deposit.USDX?.enabled).toBe(true);
  });

  it('lists SEP-38 asset identifiers in /sep38/info', async () => {
    const info = (await (await fetch(`${base}/sep38/info`)).json()) as {
      assets: { asset: string }[];
    };
    expect(info.assets.map((a) => a.asset)).toEqual([
      `stellar:USDX:${USDX_ISSUER}`,
      'iso4217:USD',
      'stellar:native',
    ]);
  });

  it('quotes every other asset from /sep38/prices', async () => {
    const sell = encodeURIComponent('iso4217:USD');
    const res = await fetch(`${base}/sep38/prices?sell_asset=${sell}&sell_amount=100`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { buy_assets: { asset: string; price: string }[] };
    expect(body.buy_assets.map((a) => a.asset)).toEqual([
      `stellar:USDX:${USDX_ISSUER}`,
      'stellar:native',
    ]);
    expect(body.buy_assets[0]?.price).toBe('1.00');
  });

  it('rejects /sep38/prices for an undeclared asset', async () => {
    const res = await fetch(`${base}/sep38/prices?sell_asset=stellar:NOPE&sell_amount=1`);
    expect(res.status).toBe(400);
  });

  it('404s unknown paths as JSON', async () => {
    const res = await fetch(`${base}/nope`);
    expect(res.status).toBe(404);
    expect(await res.json()).toHaveProperty('error');
  });
});

describe('mock server signing key', () => {
  it('signs with SIGNING_KEY when given its secret', () => {
    const key = Keypair.random();
    const { signer } = createMockServer({
      source: '',
      doc: { SIGNING_KEY: key.publicKey() },
      signingSecret: key.secret(),
    });
    expect(signer).toEqual({ keypair: expect.anything(), matchesSigningKey: true });
    expect(signer.keypair.publicKey()).toBe(key.publicKey());
    expect(formatRoutingTable('http://localhost:1', signer)).toContain('signed by SIGNING_KEY');
  });

  it('falls back to an ephemeral key, and says so, for a mismatched secret', () => {
    const { signer } = createMockServer({
      source: '',
      doc: { SIGNING_KEY: Keypair.random().publicKey() },
      signingSecret: Keypair.random().secret(),
    });
    expect(signer.matchesSigningKey).toBe(false);
    expect(formatRoutingTable('http://localhost:1', signer)).toContain('ephemeral key');
  });
});

describe('--serve-mock', () => {
  it('prints the routing table, serves the file, and shuts down on SIGTERM', async () => {
    const child = spawn('node', [CLI, '--serve-mock', '0', FIXTURE], {
      env: { ...process.env, NO_COLOR: '1' },
    });
    let stdout = '';
    child.stdout.on('data', (chunk: Buffer) => {
      stdout += chunk.toString();
    });

    const base = await new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`no banner: ${stdout}`)), 10_000);
      child.stdout.on('data', () => {
        const match = /listening on (http:\/\/localhost:\d+)/.exec(stdout);
        if (match && stdout.includes('Ctrl+C')) {
          clearTimeout(timer);
          resolve(match[1] as string);
        }
      });
    });

    for (const path of ['/.well-known/stellar.toml', '/auth', '/sep24/info', '/sep38/prices']) {
      expect(stdout).toContain(`${base}${path}`);
    }
    const res = await fetch(`${base}/.well-known/stellar.toml`);
    expect(await res.text()).toBe(SOURCE);

    const code = await new Promise<number | null>((resolve) => {
      child.on('exit', resolve);
      child.kill('SIGTERM');
    });
    // Windows has no POSIX signals: `kill` terminates the process outright, so
    // the graceful-shutdown handler never runs and there is no exit code.
    expect(code).toBe(process.platform === 'win32' ? null : 0);
  });

  it('exits 2 for a missing file', async () => {
    const child = spawn('node', [CLI, '--serve-mock', '0', join(here, 'fixtures', 'nope.toml')]);
    const code = await new Promise<number | null>((resolve) => child.on('exit', resolve));
    expect(code).toBe(2);
  });
});
