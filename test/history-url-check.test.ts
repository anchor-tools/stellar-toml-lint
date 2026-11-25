import { createServer, type Server } from 'node:http';
import { afterEach, describe, expect, it } from 'vitest';
import { lint } from '../src/lint.js';
import { checkHistoryArchive } from '../src/rules/history-url-check.js';

const INVALID = 'validators/invalid-history-url';
const UNREACHABLE = 'validators/stellar-history-json-unreachable';
const METADATA = '/.well-known/stellar-history.json';

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(
    servers
      .splice(0)
      .map(
        (server) =>
          new Promise<void>((resolve, reject) =>
            server.close((error) => (error ? reject(error) : resolve())),
          ),
      ),
  );
});

function validatorSource(history: string): string {
  return ['[[VALIDATORS]]', 'ALIAS="core-1"', `HISTORY="${history}"`, ''].join('\n');
}

function historyDiagnostics(source: string) {
  return lint(source).diagnostics.filter((d) => d.rule === INVALID);
}

function docWith(history: unknown): Record<string, unknown> {
  return { VALIDATORS: [{ ALIAS: 'core-1', HISTORY: history }] };
}

/** A throwaway HTTP server whose routes are keyed by request path. */
async function startArchive(routes: Record<string, unknown>): Promise<string> {
  const server = createServer((req, res) => {
    if (!(req.url && req.url in routes)) {
      res.writeHead(404);
      res.end('not found');
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(routes[req.url]));
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

  const address = server.address();
  const port = typeof address === 'object' && address !== null ? address.port : 0;
  return `http://127.0.0.1:${port}`;
}

describe('validators/invalid-history-url', () => {
  it('accepts a standard archive root', () => {
    const source = validatorSource('https://history.example.com/prd/core-live/core_live_001/');
    expect(historyDiagnostics(source)).toEqual([]);
  });

  it('accepts the {0} template parameter', () => {
    expect(historyDiagnostics(validatorSource('https://history.example.com/{0}'))).toEqual([]);
  });

  it('flags a value that is not an absolute URL', () => {
    const [diagnostic] = historyDiagnostics(validatorSource('not a uri'));
    expect(diagnostic?.rule).toBe(INVALID);
    expect(diagnostic?.severity).toBe('error');
    expect(diagnostic?.path).toBe('VALIDATORS[0].HISTORY');
    expect(diagnostic?.message).toBe('VALIDATORS[0].HISTORY is not an absolute URL');
  });

  it('flags an unsupported template parameter', () => {
    const [diagnostic] = historyDiagnostics(validatorSource('https://history.example.com/{1}'));
    expect(diagnostic?.message).toContain('only {0} is supported');
  });

  it('flags unbalanced template braces', () => {
    const [diagnostic] = historyDiagnostics(validatorSource('https://history.example.com/{0'));
    expect(diagnostic?.message).toContain('unbalanced');
  });

  it('flags a template parameter in the host', () => {
    const [diagnostic] = historyDiagnostics(validatorSource('https://{0}.example.com/'));
    expect(diagnostic?.message).toContain('in the host');
  });

  it('stays silent when a validator declares no HISTORY', () => {
    expect(historyDiagnostics('[[VALIDATORS]]\nALIAS="core-1"\n')).toEqual([]);
  });

  it('supersedes the old absolute-URI warning', () => {
    // The removal of `validators/history` means one finding, not two.
    const rules = lint(validatorSource('not a uri')).diagnostics.map((d) => d.rule);
    expect(rules).not.toContain('validators/history');
    expect(rules).toContain(INVALID);
  });
});

describe('validators/stellar-history-json-unreachable', () => {
  it('passes when the archive serves version 1', async () => {
    // Real archives publish the metadata inside the archive directory, so the
    // request path is the archive root plus `.well-known/...`.
    const archive = '/prd/core-live/core_live_001';
    const origin = await startArchive({ [`${archive}${METADATA}`]: { version: 1 } });
    const diagnostics = await checkHistoryArchive(docWith(`${origin}${archive}/`));
    expect(diagnostics).toEqual([]);
  });

  it('flags a missing metadata file', async () => {
    const origin = await startArchive({});
    const [diagnostic] = await checkHistoryArchive(docWith(`${origin}/archive/`));
    expect(diagnostic?.rule).toBe(UNREACHABLE);
    expect(diagnostic?.severity).toBe('error');
    expect(diagnostic?.path).toBe('VALIDATORS[0].HISTORY');
    expect(diagnostic?.message).toBe(
      `VALIDATORS[0].HISTORY does not serve .well-known/stellar-history.json: it returned HTTP 404`,
    );
  });

  it('flags metadata that does not declare version 1', async () => {
    const origin = await startArchive({ [METADATA]: { version: 2 } });
    const [diagnostic] = await checkHistoryArchive(docWith(`${origin}/`));
    expect(diagnostic?.message).toContain('does not declare "version": 1');
  });

  it('resolves the {0} template against the server root', async () => {
    const origin = await startArchive({ [METADATA]: { version: 1 } });
    expect(await checkHistoryArchive(docWith(`${origin}/{0}`))).toEqual([]);
  });

  it('honours an --off override', async () => {
    const origin = await startArchive({});
    const diagnostics = await checkHistoryArchive(docWith(`${origin}/archive/`), fetch, {
      rules: { [UNREACHABLE]: 'off' },
    });
    expect(diagnostics).toEqual([]);
  });

  it('ignores validators without a HISTORY string', async () => {
    expect(await checkHistoryArchive(docWith(undefined))).toEqual([]);
  });
});
