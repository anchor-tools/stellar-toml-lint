import { describe, expect, it } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

import { lint } from '../src/lint.js';
import {
  browserCapabilities,
  createVirtualFileSystem,
  lintBrowser,
  lintBrowserDomain,
  lintBrowserFile,
  lintBrowserRun,
} from '../src/browser.js';
import type * as BrowserApi from '../src/browser.js';
import { connectWorker, handleMessage, installWorker } from '../src/worker.js';
import type { WorkerResponse } from '../src/worker.js';

const here = dirname(fileURLToPath(import.meta.url));
const srcDir = join(here, '..', 'src');
const fixture = (name: string): string => join(here, 'fixtures', name);

const valid = (): string => readFileSync(fixture('valid.toml'), 'utf8');
const broken = (): string => readFileSync(fixture('broken.toml'), 'utf8');

/** A response shaped like the one an anchor should serve. */
function goodResponse(body: string): Response {
  return new Response(body, {
    status: 200,
    headers: {
      'access-control-allow-origin': '*',
      'content-type': 'text/plain; charset=utf-8',
    },
  });
}

// ── the browser entry point ────────────────────────────────────────────────

describe('lintBrowser', () => {
  it('matches the Node entry point on the same source', async () => {
    await expect(lintBrowser(valid())).resolves.toEqual(lint(valid()));
    await expect(lintBrowser(broken())).resolves.toEqual(lint(broken()));
  });

  it('passes rule overrides and strict mode through', async () => {
    const source = readFileSync(fixture('warnings-only.toml'), 'utf8');

    const relaxed = await lintBrowser(source, { rules: { 'network/cors': 'off' } });
    const strict = await lintBrowser(source, { strict: true });

    expect(relaxed.counts).toEqual(lint(source).counts);
    expect(strict.ok).toBe(lint(source, { strict: true }).ok);
  });
});

describe('virtual file system', () => {
  it('reads, checks and lists what it was given', () => {
    const files = createVirtualFileSystem({
      'public/.well-known/stellar.toml': valid(),
      'other.toml': broken(),
    });

    expect(files.has('public/.well-known/stellar.toml')).toBe(true);
    expect(files.has('missing.toml')).toBe(false);
    expect(files.read('other.toml')).toBe(broken());
    expect(files.list()).toEqual(['public/.well-known/stellar.toml', 'other.toml']);
  });

  it('copies the input, so later edits cannot change a run midway', () => {
    const source: Record<string, string> = { 'stellar.toml': valid() };
    const files = createVirtualFileSystem(source);

    source['stellar.toml'] = broken();

    expect(files.read('stellar.toml')).toBe(valid());
  });

  it('lints a file by path', async () => {
    const files = createVirtualFileSystem({ 'stellar.toml': broken() });

    const result = await lintBrowserFile('stellar.toml', { files });

    expect(result).toEqual(lint(broken()));
  });

  it('names the missing path and what it did have', async () => {
    const files = createVirtualFileSystem({ 'a.toml': valid() });

    await expect(lintBrowserFile('b.toml', { files })).rejects.toThrow(
      /No content for "b\.toml".*Known files: a\.toml/,
    );
    await expect(lintBrowserFile('b.toml')).rejects.toThrow(/The file system is empty/);
  });

  it('lints several files as one run, in the order asked for', async () => {
    const files = createVirtualFileSystem({ 'a.toml': valid(), 'b.toml': broken() });

    const run = await lintBrowserRun(['b.toml', 'a.toml'], { files });

    expect(run.map((entry) => entry.name)).toEqual(['b.toml', 'a.toml']);
    expect(run[0]?.result.counts.error).toBeGreaterThan(0);
    expect(run[1]?.result.ok).toBe(true);
  });
});

describe('lintBrowserDomain', () => {
  it('reports nothing network-related for a correctly configured host', async () => {
    const result = await lintBrowserDomain('anchor.example', {
      // The SEP-6 /info route advertises the currencies valid.toml declares;
      // every other request (the file, the ORG_URL probe) gets the file.
      fetchImpl: async (input) =>
        String(input).endsWith('/info')
          ? new Response(
              JSON.stringify({
                deposit: { USDX: { enabled: true }, EXPL: { enabled: true } },
                withdraw: { USDX: { enabled: true } },
              }),
              {
                status: 200,
                headers: {
                  'access-control-allow-origin': '*',
                  'content-type': 'application/json',
                },
              },
            )
          : goodResponse(valid()),
    });

    const network = result.diagnostics.filter((d) => d.category === 'network');
    expect(network).toEqual([]);
  });

  it('keeps the CORS finding, which is the point of the browser path', async () => {
    const result = await lintBrowserDomain('anchor.example', {
      fetchImpl: async () =>
        new Response(valid(), { status: 200, headers: { 'content-type': 'text/plain' } }),
    });

    expect(result.diagnostics.map((d) => d.rule)).toContain('network/cors');
  });

  it('turns a fetch failure into a finding instead of throwing', async () => {
    const result = await lintBrowserDomain('anchor.example', {
      fetchImpl: async () => {
        throw new TypeError('Failed to fetch');
      },
    });

    const [first] = result.diagnostics;
    expect(first?.rule).toBe('network/unreachable');
    expect(first?.message).toContain('Failed to fetch');
  });

  it('stays silent about TLS rather than guessing a session', async () => {
    const result = await lintBrowserDomain('anchor.example', {
      fetchImpl: async () => goodResponse(valid()),
    });

    expect(result.diagnostics.filter((d) => d.rule.startsWith('security/'))).toEqual([]);
    expect(browserCapabilities.tlsAudit).toBe(false);
  });
});

// ── the worker protocol ────────────────────────────────────────────────────

describe('worker', () => {
  it('answers a lint request with the result, echoing the id', async () => {
    const response = await handleMessage({ type: 'lint', id: 'a1', content: broken() });

    expect(response.type).toBe('result');
    expect(response.id).toBe('a1');
    expect((response as { result: unknown }).result).toEqual(lint(broken()));
  });

  it('answers a ping, so a page can check the worker is alive', async () => {
    await expect(handleMessage({ type: 'ping', id: 7 })).resolves.toEqual({ type: 'pong', id: 7 });
  });

  it('answers malformed requests instead of throwing', async () => {
    const cases: unknown[] = [
      null,
      'lint please',
      { type: 'compile' },
      { type: 'lint' },
      { type: 'lint', content: 42 },
    ];

    for (const message of cases) {
      const response: WorkerResponse = await handleMessage(message);
      expect(response.type).toBe('error');
      expect((response as { message: string }).message).toBeTruthy();
    }
  });

  it('reports options it cannot read rather than failing silently', async () => {
    const options = {
      get files(): never {
        throw new Error('unreadable options');
      },
    };

    await expect(handleMessage({ type: 'lint', content: valid(), options })).resolves.toMatchObject(
      {
        type: 'error',
        message: 'unreadable options',
      },
    );
  });

  it('routes messages through a scope and posts the answer back', async () => {
    const posted: unknown[] = [];
    const scope = {
      onmessage: null as ((event: { data: unknown }) => void) | null,
      postMessage: (message: unknown) => void posted.push(message),
    };

    connectWorker(scope);
    scope.onmessage?.({ data: { type: 'lint', id: 3, content: valid() } });
    await new Promise((resolveTick) => setTimeout(resolveTick, 0));

    expect(posted).toHaveLength(1);
    expect(posted[0]).toMatchObject({ type: 'result', id: 3 });
  });

  it('does not install itself outside a worker scope', () => {
    expect(installWorker()).toBe(false);
  });
});

// ── the boundary the issue is about ────────────────────────────────────────

/** Static `import ... from '...'` specifiers — dynamic imports are deliberately lazy. */
function staticImportsOf(file: string): string[] {
  const source = readFileSync(file, 'utf8');
  const specifiers: string[] = [];
  const from = /(?:^|\n)\s*import\s+(?:type\s+)?[^;\n]*?from\s+['"]([^'"]+)['"]/g;
  const bare = /(?:^|\n)\s*import\s+['"]([^'"]+)['"]/g;

  for (const match of source.matchAll(from)) if (match[1]) specifiers.push(match[1]);
  for (const match of source.matchAll(bare)) if (match[1]) specifiers.push(match[1]);
  return specifiers;
}

/** Every local module reachable from `entries` through static imports. */
function moduleClosure(entries: string[]): Set<string> {
  const seen = new Set<string>();
  const queue = [...entries];

  while (queue.length > 0) {
    const file = queue.pop() as string;
    if (seen.has(file) || !existsSync(file)) continue;
    seen.add(file);

    for (const specifier of staticImportsOf(file)) {
      if (!specifier.startsWith('.')) continue;
      queue.push(resolve(dirname(file), specifier.replace(/\.js$/, '.ts')));
    }
  }

  return seen;
}

describe('browser boundary', () => {
  const closure = moduleClosure([join(srcDir, 'browser.ts'), join(srcDir, 'worker.ts')]);
  const files = [...closure];

  it('reaches the linter core', () => {
    expect(files.some((file) => file.endsWith('lint.ts'))).toBe(true);
  });

  it('never reaches the CLI, which is where the Node built-ins live', () => {
    expect(files.some((file) => file.endsWith('cli.ts'))).toBe(false);
  });

  it('has no static node: import anywhere in the graph', () => {
    const offenders = files.filter((file) =>
      /(?:^|\n)\s*import[^;\n]*from\s+['"]node:/.test(readFileSync(file, 'utf8')),
    );

    expect(offenders).toEqual([]);
  });

  it('keeps the one node: dependency it needs behind a dynamic import', () => {
    const tls = join(srcDir, 'tls.ts');
    const source = readFileSync(tls, 'utf8');

    expect(files).toContain(tls);
    expect(source).toContain("await import('node:tls')");
    expect(source).not.toMatch(/(?:^|\n)\s*import[^;\n]*from\s+['"]node:tls/);
  });

  it('publishes both subpaths with their own typings', () => {
    const pkg = JSON.parse(readFileSync(join(here, '..', 'package.json'), 'utf8')) as {
      exports: Record<string, { types: string; import: string }>;
    };

    for (const subpath of ['./browser', './worker']) {
      const entry = pkg.exports[subpath];
      expect(entry?.import).toContain('dist/');
      expect(entry?.types).toContain('dist/');
      // The tests run against the built artifact, so these should exist.
      expect(existsSync(join(here, '..', entry?.import ?? ''))).toBe(true);
      expect(existsSync(join(here, '..', entry?.types ?? ''))).toBe(true);
    }
  });
});

describe('browser bundle artifacts and sandbox', () => {
  const browserDist = join(here, '..', 'dist', 'browser');

  it('generates minified ESM, UMD, and Worker bundles with sourcemaps', () => {
    const requiredArtifacts = [
      'stellar-toml-lint.esm.min.js',
      'stellar-toml-lint.esm.min.js.map',
      'stellar-toml-lint.umd.min.js',
      'stellar-toml-lint.umd.min.js.map',
      'stellar-toml-lint.worker.min.js',
      'stellar-toml-lint.worker.min.js.map',
      'index.js',
      'index.umd.js',
      'worker.js',
      'index.d.ts',
      'worker.d.ts',
    ];

    for (const file of requiredArtifacts) {
      expect(existsSync(join(browserDist, file)), `missing bundle artifact: ${file}`).toBe(true);
    }
  });

  it('executes UMD bundle in an isolated browser sandbox environment', async () => {
    const umdFile = join(browserDist, 'stellar-toml-lint.umd.min.js');
    const code = readFileSync(umdFile, 'utf8');

    const sandbox: Record<string, unknown> = {
      console,
      Response,
      fetch,
      setTimeout,
      clearTimeout,
      TextEncoder,
      TextDecoder,
      URL,
      URLSearchParams,
    };
    sandbox['window'] = sandbox;
    sandbox['globalThis'] = sandbox;
    sandbox['self'] = sandbox;

    vm.createContext(sandbox);
    vm.runInContext(code, sandbox);

    const bundle = sandbox['stellarTomlLint'] as typeof BrowserApi;
    expect(bundle).toBeDefined();
    expect(typeof bundle.lintBrowser).toBe('function');
    expect(typeof bundle.createVirtualFileSystem).toBe('function');

    const validResult = await bundle.lintBrowser(valid());
    expect(validResult.ok).toBe(true);
    expect(validResult.counts.error).toBe(0);

    const brokenResult = await bundle.lintBrowser(broken());
    expect(brokenResult.ok).toBe(false);
    expect(brokenResult.counts.error).toBeGreaterThan(0);
  });

  it('runs ESM bundle and produces parity with source module', async () => {
    const esmPath = join(browserDist, 'index.js');
    const esm = (await import(esmPath)) as typeof BrowserApi;

    expect(typeof esm.lintBrowser).toBe('function');
    const result = await esm.lintBrowser(valid());
    expect(result.ok).toBe(true);
  });

  it('has no Node.js built-ins in browser bundle code', () => {
    for (const filename of ['stellar-toml-lint.esm.min.js', 'stellar-toml-lint.umd.min.js']) {
      const code = readFileSync(join(browserDist, filename), 'utf8');
      expect(code).not.toMatch(/from\s*['"]node:/);
      expect(code).not.toMatch(/require\(['"]node:/);
    }
  });
});
