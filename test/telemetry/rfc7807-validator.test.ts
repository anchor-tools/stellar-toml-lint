import { afterEach, describe, expect, it } from 'vitest';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { Keypair } from '@stellar/stellar-base';
import {
  buildErrorProbes,
  categorizeStatus,
  classifyErrorResponse,
  detectLeaks,
  ERROR_PROBES,
  renderErrorTaxonomyReport,
  Rfc7807ErrorValidator,
  summarizeTaxonomy,
} from '../../src/telemetry/rfc7807Validator.js';

const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))));
});

type Reply = { status: number; type: string; body: string };

/** Mock anchor whose replies are chosen per request. */
async function mockAnchor(
  reply: (method: string, url: string) => Reply,
  seen: string[] = [],
): Promise<string> {
  const server = createServer((req, res) => {
    seen.push(`${req.method} ${req.url}`);
    const r = reply(req.method ?? '', req.url ?? '');
    res.writeHead(r.status, { 'content-type': r.type });
    res.end(r.body);
  });
  servers.push(server);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

const problem = (status: number) => ({
  status,
  type: 'application/problem+json',
  body: JSON.stringify({
    type: 'https://anchor.example/errors/invalid-request',
    title: 'Invalid request',
    status,
    detail: 'asset_code is required',
    instance: '/sep6/deposit',
  }),
});

const codes = (r: Reply) =>
  classifyErrorResponse({ status: r.status, contentType: r.type, body: r.body }).findings.map(
    (f) => f.code,
  );

describe('categorizeStatus', () => {
  it('maps HTTP statuses onto the taxonomy', () => {
    expect(
      [200, 302, 400, 401, 403, 404, 410, 409, 422, 429, 500, 503, 418, 600].map(categorizeStatus),
    ).toEqual([
      'unexpected-success',
      'unexpected-success',
      'client-input',
      'authentication',
      'authorization',
      'not-found',
      'not-found',
      'conflict',
      'client-input',
      'rate-limited',
      'server',
      'server',
      'other',
      'other',
    ]);
  });
});

describe('classifyErrorResponse (#528)', () => {
  it('accepts compliant RFC 7807 Problem Details for 401/403/404/422', () => {
    for (const status of [401, 403, 404, 422]) {
      const c = classifyErrorResponse({
        status,
        contentType: 'application/problem+json; charset=utf-8',
        body: problem(status).body,
      });
      expect(c.format).toBe('rfc7807');
      expect(c.findings).toEqual([]);
    }
  });

  it('accepts the legacy SEP {"error": "..."} schema', () => {
    const c = classifyErrorResponse({
      status: 400,
      contentType: 'application/json',
      body: '{"error":"invalid account"}',
    });
    expect(c.format).toBe('sep-error');
    expect(c.category).toBe('client-input');
    expect(c.findings).toEqual([]);
    expect(codes({ status: 400, type: 'application/json', body: '{"error":" "}' })).toEqual([
      'errors/empty-error-message',
    ]);
  });

  it('validates Problem Details members', () => {
    const bad = JSON.stringify({ type: 'http://[bad', title: 5, status: '400', instance: 1 });
    expect(codes({ status: 400, type: 'application/problem+json', body: bad })).toEqual([
      'errors/problem-invalid-member',
      'errors/problem-invalid-member',
      'errors/problem-invalid-type-uri',
      'errors/problem-invalid-member',
      'errors/problem-missing-title',
      'errors/problem-missing-detail',
    ]);
    const mismatch = JSON.stringify({ title: 'x', detail: 'y', status: 500 });
    expect(codes({ status: 400, type: 'application/json', body: mismatch })).toEqual([
      'errors/problem-content-type',
      'errors/problem-status-mismatch',
    ]);
    expect(codes({ status: 400, type: '', body: mismatch })).toContain('errors/wrong-content-type');
    expect(
      codes({
        status: 400,
        type: 'application/problem+json',
        body: JSON.stringify({ title: 'x', detail: 'y', status: 4.5 }),
      }),
    ).toEqual(['errors/problem-invalid-member']);
  });

  it('flags unstructured JSON, HTML pages, plain text and empty bodies', () => {
    expect(codes({ status: 400, type: 'application/json', body: '{"message":"no"}' })).toEqual([
      'errors/unstructured-json',
    ]);
    expect(codes({ status: 400, type: 'application/json', body: '["no"]' })).toEqual([
      'errors/plain-text-error',
    ]);
    expect(codes({ status: 400, type: 'text/plain', body: '{"error":"x"}' })).toEqual([
      'errors/wrong-content-type',
    ]);
    expect(codes({ status: 404, type: 'text/html', body: '<h1>Not Found</h1>' })).toEqual([
      'errors/html-error-page',
    ]);
    expect(codes({ status: 404, type: '', body: '<!DOCTYPE html><p>x' })).toEqual([
      'errors/html-error-page',
    ]);
    expect(codes({ status: 400, type: 'text/plain', body: 'Bad Request' })).toEqual([
      'errors/plain-text-error',
    ]);
    expect(codes({ status: 401, type: '', body: '' })).toEqual(['errors/empty-body']);
  });

  it('flags invalid requests that were accepted or crashed the server', () => {
    expect(codes({ status: 200, type: 'application/json', body: '{"error":"x"}' })).toEqual([
      'errors/accepted-invalid-request',
    ]);
    expect(codes({ status: 500, type: 'application/json', body: '{"error":"internal"}' })).toEqual([
      'errors/server-error-on-invalid-input',
    ]);
  });
});

describe('detectLeaks', () => {
  it('reports stack traces from common runtimes', () => {
    const node =
      'Error: boom\n    at handler (/srv/app/index.js:10:5)\n    at next (/srv/app/router.js:2:1)';
    const python = 'Traceback (most recent call last):\n  File "app.py", line 3';
    const java = 'java.lang.NullPointerException\n\tat com.anchor.Deposit(Deposit.java:42)';
    const go = 'panic: runtime error\n\ngoroutine 1 [running]:';
    const ruby = "app/controllers/deposit.rb:12:in `create'";
    for (const body of [node, python, java, go, ruby]) {
      expect(detectLeaks(body).map((l) => l.kind)).toContain('stack-trace');
    }
    expect(detectLeaks('Exception in thread "main" x').map((l) => l.kind)).toContain('stack-trace');
  });

  it('reports secrets and credentials as critical', () => {
    const seed = Keypair.random().secret();
    const body = [
      `seed=${seed}`,
      'postgres://anchor:hunter2@db.internal:5432/anchor',
      'mongodb+srv://u:p@cluster0.example.net/db',
      'AKIAABCDEFGHIJKLMNOP',
      '-----BEGIN RSA PRIVATE KEY-----',
    ].join('\n');
    const leaks = detectLeaks(body);
    expect(leaks.map((l) => l.kind).sort()).toEqual([
      'cloud-credentials',
      'database-credentials',
      'database-credentials',
      'private-key',
      'stellar-secret-seed',
    ]);
    expect(leaks.every((l) => l.severity === 'error')).toBe(true);
    // Excerpts are redacted, never the full secret.
    expect(leaks.find((l) => l.kind === 'stellar-secret-seed')?.excerpt).not.toContain(seed);
  });

  it('ignores strings that only look like seeds', () => {
    expect(detectLeaks(`S${'A'.repeat(55)}`)).toEqual([]);
  });

  it('reports SQL errors, internal paths and debug pages', () => {
    expect(detectLeaks('ERROR: syntax error at or near "FROM"').map((l) => l.kind)).toEqual([
      'sql-error',
    ]);
    expect(detectLeaks('ORA-00942: table or view does not exist').map((l) => l.kind)).toEqual([
      'sql-error',
    ]);
    expect(
      detectLeaks('open /home/deploy/anchor/.env failed').map((l) => [l.kind, l.severity]),
    ).toEqual([['internal-path', 'warning']]);
    expect(detectLeaks('C:\\inetpub\\wwwroot\\web.config').map((l) => l.kind)).toEqual([
      'internal-path',
    ]);
    expect(detectLeaks('<title>Werkzeug Debugger</title>').map((l) => l.kind)).toEqual([
      'debug-page',
    ]);
    expect(detectLeaks('ok')).toEqual([]);
  });

  it('deduplicates repeated matches', () => {
    expect(detectLeaks('ORA-00001 ORA-00001')).toHaveLength(1);
  });

  it('turns leaks into critical findings', () => {
    const c = classifyErrorResponse({
      status: 500,
      contentType: 'text/plain',
      body: 'Error: db\n    at query (/usr/src/app/db.js:1:1)\npostgres://a:b@h/db',
    });
    const messages = c.findings.map((f) => f.message);
    expect(messages.some((m) => m.startsWith('CRITICAL: error response exposes stack trace'))).toBe(
      true,
    );
    expect(
      messages.some((m) => m.startsWith('CRITICAL: error response exposes database credentials')),
    ).toBe(true);
    expect(messages.some((m) => m.startsWith('Error response exposes internal path'))).toBe(true);
  });
});

describe('buildErrorProbes', () => {
  it('builds read-only GET probes for each declared endpoint', () => {
    const probes = buildErrorProbes({
      TRANSFER_SERVER: 'https://a/sep6/',
      ANCHOR_QUOTE_SERVER: 'https://a/sep38',
      WEB_AUTH_ENDPOINT: 'https://a/auth',
      KYC_SERVER: 'ftp://nope',
      DIRECT_PAYMENT_SERVER: 7,
    });
    expect(probes.map((p) => p.field)).toEqual([
      ...ERROR_PROBES.TRANSFER_SERVER!.map(() => 'TRANSFER_SERVER'),
      'ANCHOR_QUOTE_SERVER',
      'ANCHOR_QUOTE_SERVER',
      'WEB_AUTH_ENDPOINT',
    ]);
    expect(probes[0]?.url).toBe('https://a/sep6/deposit');
    expect(probes.at(-1)?.url).toBe('https://a/auth?account=GNOTAVALIDSTELLARACCOUNT');
  });
});

describe('Rfc7807ErrorValidator against mock servers', () => {
  it('passes an anchor that answers with Problem Details', async () => {
    const seen: string[] = [];
    const base = await mockAnchor(
      (_m, url) => problem(url.includes('nonexistent') ? 404 : 400),
      seen,
    );
    const report = await new Rfc7807ErrorValidator().audit({
      TRANSFER_SERVER: base,
      TRANSFER_SERVER_SEP0024: base,
      DIRECT_PAYMENT_SERVER: base,
      ANCHOR_QUOTE_SERVER: base,
      KYC_SERVER: base,
      WEB_AUTH_ENDPOINT: base,
    });
    expect(report.ok).toBe(true);
    expect(report.criticalLeaks).toBe(0);
    expect(report.categories['client-input']).toBeGreaterThan(0);
    expect(report.categories['not-found']).toBe(3);
    // Every probe was a GET: nothing that could mutate state.
    expect(seen.every((s) => s.startsWith('GET '))).toBe(true);
    expect(renderErrorTaxonomyReport(report)).toContain('✓ Error handling is machine-readable');
  });

  it('passes the legacy SEP error schema', async () => {
    const base = await mockAnchor(() => ({
      status: 400,
      type: 'application/json',
      body: '{"error":"bad request"}',
    }));
    expect((await new Rfc7807ErrorValidator().audit({ TRANSFER_SERVER: base })).ok).toBe(true);
  });

  it('fails an anchor that leaks stack traces and secrets', async () => {
    const seed = Keypair.random().secret();
    const base = await mockAnchor(() => ({
      status: 500,
      type: 'text/html',
      body: `<html><pre>Error: crash\n    at deposit (/var/www/anchor/sep6.js:88:13)\nSIGNING_SEED=${seed}</pre></html>`,
    }));
    const report = await new Rfc7807ErrorValidator().audit({ TRANSFER_SERVER: base });
    expect(report.ok).toBe(false);
    expect(report.criticalLeaks).toBeGreaterThanOrEqual(2 * ERROR_PROBES.TRANSFER_SERVER!.length);
    expect(report.categories.server).toBe(ERROR_PROBES.TRANSFER_SERVER!.length);
    const text = renderErrorTaxonomyReport(report);
    expect(text).toContain('CRITICAL');
    expect(text).toContain('critical information leak(s)');
    expect(text).not.toContain(seed);
  });

  it('truncates huge bodies and reports unreachable endpoints', async () => {
    const validator = new Rfc7807ErrorValidator({
      maxBodyBytes: 10,
      fetchImpl: async () => {
        const r = new Response(`${'x'.repeat(1000)} ORA-00942`, {
          status: 400,
          headers: { 'content-type': 'text/plain' },
        });
        return r;
      },
    });
    const result = await validator.run({
      field: 'F',
      description: 'd',
      path: '/',
      url: 'https://a/',
    });
    // Only the first 10 bytes are analysed, so the SQL error past the cut is not seen.
    expect(result.classification?.findings.map((f) => f.code)).toEqual(['errors/plain-text-error']);

    const down = new Rfc7807ErrorValidator({
      fetchImpl: async () => {
        throw new Error('ENOTFOUND');
      },
    });
    const report = await down.audit({ TRANSFER_SERVER: 'https://down.invalid' });
    expect(report.results[0]?.error).toBe('ENOTFOUND');
    expect(report.ok).toBe(true);
    expect(renderErrorTaxonomyReport(report)).toContain('! unreachable: ENOTFOUND');

    const weird = new Rfc7807ErrorValidator({
      fetchImpl: async () => {
        throw 'str';
      },
    });
    expect((await weird.run({ field: 'F', description: 'd', path: '/', url: 'u' })).error).toBe(
      'str',
    );
    const noType = new Rfc7807ErrorValidator({
      fetchImpl: async () => new Response('', { status: 404 }),
    });
    const r = await noType.run({ field: 'F', description: 'd', path: '/', url: 'u' });
    expect(r.classification?.format).toBe('empty');
  });

  it('renders empty and mixed reports', () => {
    expect(renderErrorTaxonomyReport(summarizeTaxonomy([]))).toContain('No SEP endpoints declared');
    const text = renderErrorTaxonomyReport(
      summarizeTaxonomy([
        {
          field: 'A',
          description: 'd',
          path: '/',
          url: 'u',
          classification: classifyErrorResponse({
            status: 400,
            contentType: 'text/plain',
            body: 'nope',
          }),
        },
      ]),
    );
    expect(text).toContain('HTTP 400 · client-input · plain-text');
    expect(text).toContain('✗ Error handling issues found');
    const none = renderErrorTaxonomyReport({
      ok: true,
      results: [{ field: 'A', description: 'd', path: '/', url: 'u', error: 'x' }],
      categories: {},
      criticalLeaks: 0,
    });
    expect(none).toContain('Categories: none');
  });
});
