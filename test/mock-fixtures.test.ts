import { afterEach, describe, expect, it } from 'vitest';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  createFixtureFetch,
  fixtureCandidates,
  MissingFixtureError,
} from '../src/mock-fixtures.js';
import { lintDomain } from '../src/lint.js';
import { checkHorizon } from '../src/rules/horizon-check.js';
import { checkNetworkAccounts } from '../src/network-checks.js';
import { checkSep38 } from '../src/rules/sep38-endpoints.js';

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(here, 'fixtures', 'network');

const SIGNING_KEY = 'GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS';
const ISSUER = 'GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY';
const PUBLIC_PASSPHRASE = 'Public Global Stellar Network ; September 2015';

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

describe('createFixtureFetch', () => {
  it('serves a fixture stored under the full hostname', async () => {
    const fetchImpl = createFixtureFetch(FIXTURES);
    const response = await fetchImpl('https://horizon.example.com');

    expect(response.status).toBe(200);
    expect(response.headers.get('x-mock-fixture')).toBe('horizon.example.com/index.json');
    const body = (await response.json()) as { current_protocol_version: number };
    expect(body.current_protocol_version).toBe(22);
  });

  it('falls back to the shorter host label', async () => {
    const fetchImpl = createFixtureFetch(FIXTURES);
    const response = await fetchImpl(`https://horizon.stellar.org/accounts/${SIGNING_KEY}`);

    expect(response.status).toBe(200);
    expect(response.headers.get('x-mock-fixture')).toBe(`horizon/accounts/${SIGNING_KEY}.json`);
    const body = (await response.json()) as { flags: { auth_required: boolean } };
    expect(body.flags.auth_required).toBe(true);
  });

  it('ignores the query string when matching a fixture', async () => {
    const fetchImpl = createFixtureFetch(FIXTURES);
    const response = await fetchImpl('https://quote.example.com/prices?sell_asset=stellar%3AXLM');

    expect(response.status).toBe(200);
    expect(response.headers.get('x-mock-fixture')).toBe('quote.example.com/prices.json');
  });

  it('honours status and headers from a fixture envelope', async () => {
    const fetchImpl = createFixtureFetch(FIXTURES);
    const response = await fetchImpl('https://quote.example.com/quote');

    expect(response.status).toBe(400);
    expect(response.headers.get('content-type')).toBe('application/problem+json');
    expect(await response.json()).toEqual({ error: 'SEP-10 authentication required' });
  });

  it('serves a string body verbatim for a text/plain response', async () => {
    const fetchImpl = createFixtureFetch(FIXTURES);
    const response = await fetchImpl('https://mock-anchor.example.com/.well-known/stellar.toml');

    expect(response.headers.get('content-type')).toContain('text/plain');
    expect(await response.text()).toContain('ORG_NAME="Mock Anchor"');
  });

  it('throws a descriptive error for a URL with no fixture', async () => {
    const fetchImpl = createFixtureFetch(FIXTURES);

    await expect(fetchImpl('https://nowhere.example.com/accounts/GABC')).rejects.toBeInstanceOf(
      MissingFixtureError,
    );

    const error = await fetchImpl('https://nowhere.example.com/accounts/GABC').catch(
      (caught: unknown) => caught,
    );
    expect(error).toBeInstanceOf(MissingFixtureError);
    const missing = error as MissingFixtureError;
    expect(missing.message).toContain(
      'No mock fixture for https://nowhere.example.com/accounts/GABC',
    );
    expect(missing.message).toContain('no external');
    expect(missing.tried).toContain('nowhere.example.com/accounts/GABC.json');
  });

  it('rejects a fixtures directory that does not exist', () => {
    expect(() => createFixtureFetch(join(FIXTURES, 'definitely-missing'))).toThrow(
      /does not exist/,
    );
  });
});

describe('fixtureCandidates', () => {
  it('maps a URL onto full-host and short-label paths', () => {
    expect(fixtureCandidates(new URL('https://horizon.stellar.org/accounts/GABC'))).toEqual([
      'horizon.stellar.org/accounts/GABC.json',
      'horizon.stellar.org/accounts/GABC',
      'horizon/accounts/GABC.json',
      'horizon/accounts/GABC',
    ]);
  });

  it('resolves a directory URL to index.json', () => {
    expect(fixtureCandidates(new URL('https://horizon.example.com'))).toEqual([
      'horizon.example.com/index.json',
      'horizon/index.json',
    ]);
  });

  it('neutralises a path that tries to escape the fixtures directory', () => {
    // The URL parser resolves `%2e%2e` dot segments, so the traversal never
    // reaches the filesystem and the candidates stay inside the directory.
    const candidates = fixtureCandidates(new URL('https://example.com/%2e%2e/%2e%2e/etc/passwd'));
    expect(candidates.every((candidate) => !candidate.includes('..'))).toBe(true);
    expect(candidates).toContain('example.com/etc/passwd.json');
  });
});

describe('network checks over fixtures', () => {
  it('evaluates Horizon against the local root document', async () => {
    const fetchImpl = createFixtureFetch(FIXTURES);
    const diagnostics = await checkHorizon(
      { HORIZON_URL: 'https://horizon.example.com' },
      fetchImpl,
    );
    expect(diagnostics).toEqual([]);
  });

  it('verifies accounts from local fixtures', async () => {
    const fetchImpl = createFixtureFetch(FIXTURES);
    const diagnostics = await checkNetworkAccounts(
      { SIGNING_KEY, NETWORK_PASSPHRASE: PUBLIC_PASSPHRASE },
      fetchImpl,
    );
    expect(diagnostics).toEqual([]);
  });

  it('evaluates SEP-38 endpoints against local fixtures', async () => {
    const fetchImpl = createFixtureFetch(FIXTURES);
    const diagnostics = await checkSep38(
      {
        ANCHOR_QUOTE_SERVER: 'https://quote.example.com',
        CURRENCIES: [{ code: 'USDX', issuer: ISSUER }],
      },
      fetchImpl,
    );
    expect(diagnostics).toEqual([]);
  });

  it('surfaces a missing fixture as a clear Horizon diagnostic', async () => {
    const fetchImpl = createFixtureFetch(FIXTURES);
    const diagnostics = await checkHorizon(
      { HORIZON_URL: 'https://nowhere.example.com' },
      fetchImpl,
    );

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.rule).toBe('network/horizon-unreachable');
    expect(diagnostics[0]?.message).toContain('No mock fixture');
  });

  it('never reaches the real network', async () => {
    const calls: string[] = [];
    globalThis.fetch = (async (input: Parameters<typeof fetch>[0]) => {
      calls.push(String(input));
      throw new Error('real network access is forbidden in fixture mode');
    }) as typeof fetch;

    const fetchImpl = createFixtureFetch(FIXTURES);
    await checkHorizon({ HORIZON_URL: 'https://horizon.example.com' }, fetchImpl);
    await checkNetworkAccounts({ SIGNING_KEY, NETWORK_PASSPHRASE: PUBLIC_PASSPHRASE }, fetchImpl);
    await checkSep38(
      {
        ANCHOR_QUOTE_SERVER: 'https://quote.example.com',
        CURRENCIES: [{ code: 'USDX', issuer: ISSUER }],
      },
      fetchImpl,
    );

    expect(calls).toEqual([]);
  });

  it('lints a mocked domain end to end without opening a TLS probe', async () => {
    const fetchImpl = createFixtureFetch(FIXTURES);
    const result = await lintDomain('mock-anchor.example.com', {}, fetchImpl);

    expect(result.diagnostics.filter((d) => d.rule.startsWith('network/'))).toEqual([]);
    expect(result.parsed?.VERSION).toBe('2.0.0');
  });
});
