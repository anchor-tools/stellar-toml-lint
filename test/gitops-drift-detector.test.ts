import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { execFile, execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import {
  DriftDetectionError,
  GitOpsDriftDetector,
  classifyDrift,
  fetchLiveToml,
  flattenToml,
  liveUrlForDomain,
  renderDriftJson,
  renderDriftLineDiff,
  renderDriftText,
} from '../src/gitops/driftDetector.js';
import { parse } from 'smol-toml';

const ISSUER = 'GCZJM35NKGVK47BB4SPBDV25477PZYIYPVVG453LPYFNXLS3FGHDXOCM';
const OLD_KEY = 'GBBHQ7H4V6RRORKYLHTCAWP6MOHNORRFJSDPXDFYDGJB2LPZUFPXUEW3';
const NEW_KEY = 'GAENZLGHJGJRCMX5VCHOLHQXU3EMCU5XWDNU4BGGJFNLI2EL354IVBK7';

const v1 = `VERSION = "2.0.0"
NETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"
SIGNING_KEY = "${OLD_KEY}"
TRANSFER_SERVER = "https://api.example.com/sep6"

[DOCUMENTATION]
ORG_NAME = "Example Anchor"

[[CURRENCIES]]
code = "USDC"
issuer = "${ISSUER}"
status = "live"
`;

/** Rotated signing key and a new currency. */
const v2 =
  v1.replace(OLD_KEY, NEW_KEY) +
  `
[[CURRENCIES]]
code = "EURC"
issuer = "${ISSUER}"
status = "test"
`;

/** Same document as v2 with different formatting, comments and ordering. */
const v2Reformatted = `# deployed by hand, reformatted
TRANSFER_SERVER='https://api.example.com/sep6'
SIGNING_KEY   = "${NEW_KEY}"
VERSION="2.0.0"
NETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"

[[CURRENCIES]]
status = "test"
code = "EURC"
issuer = "${ISSUER}"

[[CURRENCIES]]
issuer = "${ISSUER}"
code = "USDC"
status = "live"

[DOCUMENTATION]
ORG_NAME = "Example Anchor"
`;

const dirs: string[] = [];
function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'drift-'));
  dirs.push(dir);
  return dir;
}
afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

function gitRun(cwd: string, ...args: string[]): string {
  return execFileSync('git', args, {
    cwd,
    encoding: 'utf8',
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: 'Test',
      GIT_AUTHOR_EMAIL: 'test@example.invalid',
      GIT_COMMITTER_NAME: 'Test',
      GIT_COMMITTER_EMAIL: 'test@example.invalid',
      GIT_CONFIG_NOSYSTEM: '1',
      HOME: cwd,
    },
  });
}

/** A repo whose `.well-known/stellar.toml` went through each version in order. */
function repoWithHistory(versions: Array<[subject: string, content: string]>): string {
  const dir = tempDir();
  gitRun(dir, 'init', '-q', '-b', 'main');
  mkdirSync(join(dir, '.well-known'));
  for (const [subject, content] of versions) {
    writeFileSync(join(dir, '.well-known', 'stellar.toml'), content);
    gitRun(dir, 'add', '.');
    gitRun(dir, 'commit', '-q', '-m', subject);
  }
  return dir;
}

function fakeFetch(body: string, status = 200): typeof fetch {
  return (async () => new Response(body, { status })) as typeof fetch;
}

function detector(gitPath: string, live: string, extra = {}): GitOpsDriftDetector {
  return new GitOpsDriftDetector({
    domain: 'example.com',
    gitPath,
    fetch: fakeFetch(live),
    now: () => new Date('2026-11-20T00:00:00Z'),
    ...extra,
  });
}

describe('liveUrlForDomain', () => {
  it('builds the SEP-1 URL from a bare or prefixed domain', () => {
    expect(liveUrlForDomain('example.com')).toBe('https://example.com/.well-known/stellar.toml');
    expect(liveUrlForDomain('https://example.com/')).toBe(
      'https://example.com/.well-known/stellar.toml',
    );
  });

  it('rejects things that are not domains', () => {
    expect(() => liveUrlForDomain('not a domain')).toThrow(DriftDetectionError);
    expect(() => liveUrlForDomain('localhost')).toThrow(DriftDetectionError);
  });
});

describe('semantic diff', () => {
  it('ignores formatting, comments, key order and [[CURRENCIES]] order', () => {
    const a = flattenToml(parse(v2) as Record<string, unknown>);
    const b = flattenToml(parse(v2Reformatted) as Record<string, unknown>);
    expect(classifyDrift(a, b, a)).toEqual([]);
  });

  it('keys [[CURRENCIES]] by code and issuer', () => {
    const flat = flattenToml(parse(v1) as Record<string, unknown>);
    expect(flat.get(`CURRENCIES[code=USDC,issuer=${ISSUER}].status`)).toBe('live');
  });

  it('marks every difference diverged when there is no base', () => {
    const a = flattenToml(parse(v1) as Record<string, unknown>);
    const b = flattenToml(parse(v2) as Record<string, unknown>);
    const findings = classifyDrift(a, b);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((f) => f.driftType === 'diverged')).toBe(true);
  });
});

describe('GitOpsDriftDetector', () => {
  it('reports in sync when live matches HEAD semantically', async () => {
    const repo = repoWithHistory([
      ['initial', v1],
      ['feat: add EURC and rotate key', v2],
    ]);
    const report = await detector(repo, v2Reformatted).detect();

    expect(report.inSync).toBe(true);
    expect(report.status).toBe('in-sync');
    expect(report.findings).toEqual([]);
    expect(report.git.deployedMatch).toBe('exact');
    expect(report.git.deployed?.subject).toBe('feat: add EURC and rotate key');
    expect(report.git.unreleasedCommits).toEqual([]);
    expect(report.git.repoPath).toBe('.well-known/stellar.toml');
    expect(renderDriftText(report)).toContain('In sync');
  });

  it('detects unreleased commits when live still runs an older revision', async () => {
    const repo = repoWithHistory([
      ['initial', v1],
      ['feat: add EURC and rotate key', v2],
      ['docs: tweak org name', v2.replace('Example Anchor', 'Example Anchor Ltd')],
    ]);
    const report = await detector(repo, v1).detect();

    expect(report.inSync).toBe(false);
    expect(report.git.deployedMatch).toBe('exact');
    expect(report.git.deployed?.subject).toBe('initial');
    expect(report.git.unreleasedCommits.map((c) => c.subject)).toEqual([
      'docs: tweak org name',
      'feat: add EURC and rotate key',
    ]);
    expect(report.summary).toMatchObject({
      unreleased: report.summary.total,
      uncommitted: 0,
      diverged: 0,
    });

    const signing = report.findings.find((f) => f.path === 'SIGNING_KEY');
    expect(signing).toMatchObject({
      driftType: 'unreleased',
      kind: 'changed',
      git: NEW_KEY,
      live: OLD_KEY,
    });
    const eurc = report.findings.find((f) => f.path.startsWith('CURRENCIES[code=EURC'));
    expect(eurc).toMatchObject({ driftType: 'unreleased', kind: 'added', severity: 'warning' });
  });

  it('detects uncommitted out-of-band edits made on production', async () => {
    const repo = repoWithHistory([['initial', v1]]);
    const live = v1
      .replace('status = "live"', 'status = "dead"')
      .replace(
        '[DOCUMENTATION]',
        'FEDERATION_SERVER = "https://evil.example.net/federation"\n\n[DOCUMENTATION]',
      );
    const report = await detector(repo, live).detect();

    expect(report.inSync).toBe(false);
    expect(report.git.deployedMatch).toBe('closest');
    expect(report.summary).toEqual({ total: 2, unreleased: 0, uncommitted: 2, diverged: 0 });
    expect(report.findings.find((f) => f.path === 'FEDERATION_SERVER')).toMatchObject({
      driftType: 'uncommitted',
      kind: 'added',
      severity: 'error',
      live: 'https://evil.example.net/federation',
    });
    expect(report.findings.find((f) => f.path.endsWith('.status'))).toMatchObject({
      driftType: 'uncommitted',
      kind: 'changed',
      git: 'live',
      live: 'dead',
    });
  });

  it('separates unreleased, uncommitted and diverged changes in one comparison', async () => {
    const base = v1;
    const head = v1
      .replace(OLD_KEY, NEW_KEY) // unreleased
      .replace('https://api.example.com/sep6', 'https://git.example.com/sep6'); // diverged
    const repo = repoWithHistory([
      ['initial', base],
      ['feat: new key and transfer server', head],
    ]);
    const live = base
      .replace('Example Anchor', 'Hacked Anchor') // uncommitted
      .replace('https://api.example.com/sep6', 'https://prod.example.com/sep6'); // diverged
    const report = await detector(repo, live).detect();

    expect(report.git.deployed?.subject).toBe('initial');
    expect(report.git.deployedMatch).toBe('closest');
    const types = Object.fromEntries(report.findings.map((f) => [f.path, f.driftType]));
    expect(types).toEqual({
      SIGNING_KEY: 'unreleased',
      'DOCUMENTATION.ORG_NAME': 'uncommitted',
      TRANSFER_SERVER: 'diverged',
    });
  });

  it('compares the ref, not the working copy, and flags local edits', async () => {
    const repo = repoWithHistory([['initial', v1]]);
    writeFileSync(join(repo, '.well-known', 'stellar.toml'), v2);
    const report = await detector(repo, v1).detect();
    expect(report.inSync).toBe(true);
    expect(report.git.workingTreeDirty).toBe(true);
    expect(renderDriftText(report)).toContain('working copy has local changes');
  });

  it('honours --ref', async () => {
    const repo = repoWithHistory([
      ['initial', v1],
      ['feat: v2', v2],
    ]);
    const report = await detector(repo, v1, { ref: 'HEAD~1' }).detect();
    expect(report.inSync).toBe(true);
  });

  it('falls back to a plain two-way diff outside Git', async () => {
    const dir = tempDir();
    const file = join(dir, 'stellar.toml');
    writeFileSync(file, v1);
    const report = await detector(file, v2).detect();
    expect(report.git.deployedMatch).toBe('none');
    expect(report.summary.diverged).toBe(report.summary.total);
    expect(report.summary.total).toBeGreaterThan(0);
  });

  it('accepts a directory containing stellar.toml at its root', async () => {
    const dir = tempDir();
    writeFileSync(join(dir, 'stellar.toml'), v1);
    const report = await detector(dir, v1).detect();
    expect(report.inSync).toBe(true);
  });

  it('fails with git-file-not-found for a missing path', async () => {
    await expect(detector(join(tempDir(), 'nope'), v1).detect()).rejects.toMatchObject({
      code: 'git-file-not-found',
    });
  });

  it('fails instead of reporting drift when live TOML is invalid', async () => {
    const repo = repoWithHistory([['initial', v1]]);
    await expect(detector(repo, 'this is = = not toml').detect()).rejects.toMatchObject({
      code: 'unparseable-live',
    });
  });
});

describe('fetchLiveToml', () => {
  it('times out on a server that never answers', async () => {
    const hang: typeof fetch = (_url, init) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () =>
          reject(new DOMException('aborted', 'AbortError')),
        );
      });
    const started = Date.now();
    await expect(
      fetchLiveToml('https://example.com/.well-known/stellar.toml', { fetch: hang, timeoutMs: 50 }),
    ).rejects.toMatchObject({ code: 'timeout' });
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it('reports HTTP errors rather than returning empty content', async () => {
    await expect(
      fetchLiveToml('https://example.com/.well-known/stellar.toml', {
        fetch: fakeFetch('gone', 404),
      }),
    ).rejects.toMatchObject({ code: 'http', message: expect.stringContaining('HTTP 404') });
  });

  it('reports network failures', async () => {
    const broken = (async () => {
      throw new TypeError('fetch failed', {
        cause: new Error('getaddrinfo ENOTFOUND example.com'),
      });
    }) as typeof fetch;
    await expect(
      fetchLiveToml('https://example.com/.well-known/stellar.toml', { fetch: broken }),
    ).rejects.toMatchObject({ code: 'network', message: expect.stringContaining('ENOTFOUND') });
  });
});

describe('renderers', () => {
  it('produces a webhook-ready JSON alert without the raw sources', async () => {
    const repo = repoWithHistory([
      ['initial', v1],
      ['feat: v2', v2],
    ]);
    const report = await detector(repo, v1).detect();
    const alert = JSON.parse(renderDriftJson(report));
    expect(alert).toMatchObject({
      type: 'stellar-toml-drift',
      version: 1,
      status: 'drift',
      inSync: false,
      liveUrl: 'https://example.com/.well-known/stellar.toml',
      checkedAt: '2026-11-20T00:00:00.000Z',
      git: { ref: 'HEAD', deployedMatch: 'exact' },
    });
    expect(alert.git.unreleasedCommits).toHaveLength(1);
    expect(alert.sources).toBeUndefined();
  });

  it('renders a colorized git-style diff, and a plain one without color', async () => {
    const repo = repoWithHistory([
      ['initial', v1],
      ['feat: v2', v2],
    ]);
    const report = await detector(repo, v1).detect();
    const plain = renderDriftText(report);
    expect(plain).toContain('--- a/.well-known/stellar.toml (git HEAD)');
    expect(plain).toContain('+++ b/https://example.com/.well-known/stellar.toml (live)');
    expect(plain).toContain('@@ unreleased: committed to Git, not deployed');
    expect(plain).toContain(`-SIGNING_KEY = "${NEW_KEY}"`);
    expect(plain).toContain(`+SIGNING_KEY = "${OLD_KEY}"`);
    expect(plain).not.toContain('\x1b[');

    const colored = renderDriftText(report, { color: true });
    expect(colored).toContain('\x1b[31m-SIGNING_KEY');
    expect(colored).toContain('\x1b[32m+SIGNING_KEY');

    const lines = renderDriftLineDiff(report);
    expect(lines).toMatch(/^--- a\/\.well-known\/stellar\.toml/);
    expect(lines).toContain(`+SIGNING_KEY = "${OLD_KEY}"`);
  });
});

describe('detect-drift CLI', () => {
  const run = promisify(execFile);
  const CLI = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'cli.js');
  let server: Server;
  let base: string;
  let body = v1;
  let status = 200;
  let hang = false;

  beforeAll(async () => {
    server = createServer((_req, res) => {
      if (hang) return; // never respond
      res.writeHead(status, { 'content-type': 'text/plain' });
      res.end(body);
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/.well-known/stellar.toml`;
  });
  afterAll(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });
  afterEach(() => {
    body = v1;
    status = 200;
    hang = false;
  });

  async function cli(args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
    try {
      const { stdout, stderr } = await run('node', [CLI, 'detect-drift', ...args], {
        env: { ...process.env, NO_COLOR: '1' },
      });
      return { code: 0, stdout, stderr };
    } catch (error) {
      const failure = error as { code?: number; stdout?: string; stderr?: string };
      return {
        code: failure.code ?? 1,
        stdout: failure.stdout ?? '',
        stderr: failure.stderr ?? '',
      };
    }
  }

  it('exits 0 when in sync', async () => {
    const repo = repoWithHistory([['initial', v1]]);
    const result = await cli(['--url', base, '--git-path', repo]);
    expect(result.code).toBe(0);
    expect(result.stdout).toContain('In sync');
  });

  it('exits 1 on drift and prints a JSON alert', async () => {
    const repo = repoWithHistory([
      ['initial', v1],
      ['feat: v2', v2],
    ]);
    const result = await cli(['--url', base, '--git-path', repo, '--format', 'json']);
    expect(result.code).toBe(1);
    const alert = JSON.parse(result.stdout);
    expect(alert.status).toBe('drift');
    expect(alert.summary.unreleased).toBeGreaterThan(0);
  });

  it('exits 2 on a network timeout, with an error JSON envelope', async () => {
    hang = true;
    const repo = repoWithHistory([['initial', v1]]);
    const result = await cli([
      '--url',
      base,
      '--git-path',
      repo,
      '--timeout',
      '200',
      '--format',
      'json',
    ]);
    expect(result.code).toBe(2);
    expect(result.stderr).toContain('timeout:');
    expect(JSON.parse(result.stdout)).toMatchObject({
      status: 'error',
      error: { code: 'timeout' },
    });
  });

  it('exits 2 on an HTTP error', async () => {
    status = 503;
    const repo = repoWithHistory([['initial', v1]]);
    const result = await cli(['--url', base, '--git-path', repo]);
    expect(result.code).toBe(2);
    expect(result.stderr).toContain('HTTP 503');
  });

  it('exits 2 on usage errors', async () => {
    expect((await cli([])).code).toBe(2);
    expect((await cli(['--domain', 'example.com', '--bogus'])).code).toBe(2);
    expect((await cli(['--domain', 'example.com', '--format', 'xml'])).code).toBe(2);
    expect((await cli(['--domain', 'example.com', '--timeout', '-5'])).code).toBe(2);
  });
});
