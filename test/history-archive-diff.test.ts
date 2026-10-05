import { describe, expect, it } from 'vitest';
import {
  archiveState,
  ARCHIVE_HASH_MISMATCH_RULE,
  ARCHIVE_LAGGING_RULE,
  checkArchiveDiff,
} from '../src/history/archive-diff.js';

const ARCHIVE = 'https://history.example/archive/';
const HORIZON_ROOT = 'https://horizon.stellar.org/';
const DOC = { VALIDATORS: [{ HOST: 'core.example:11625', HISTORY: ARCHIVE }] };

function route(routes: Record<string, unknown | Error>): typeof fetch {
  const calls: string[] = [];
  const fetchImpl = (async (input: Parameters<typeof fetch>[0]) => {
    const url = new URL(String(input));
    const key = `${url.origin}${url.pathname}`;
    calls.push(key);
    const match = routes[key];
    if (match instanceof Error) throw match;
    if (match === undefined) return new Response('not found', { status: 404 });
    return new Response(JSON.stringify(match), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }) as typeof fetch;
  (fetchImpl as { calls?: string[] }).calls = calls;
  return fetchImpl;
}

function has(sequence: number, hash?: string): Record<string, unknown> {
  return {
    version: 1,
    latest_ledger: sequence,
    ...(hash === undefined ? {} : { latest_ledger_hash: hash }),
    history: { ledger: 'history/ledger/v1.2.0/' },
  };
}

function horizon(sequence: number): Record<string, unknown> {
  return { core_latest_ledger: sequence, history_latest_ledger: sequence };
}

const HAS_PATH = '/.well-known/stellar-history.json';

describe('archiveState', () => {
  it('reads the claimed ledger sequence and hash', () => {
    expect(archiveState(has(1000, 'abc'))).toEqual({ sequence: 1000, hash: 'abc' });
    expect(archiveState(has(1000))).toEqual({ sequence: 1000 });
  });

  it('is undefined for bodies without a sequence', () => {
    expect(archiveState({ version: 1 })).toBeUndefined();
    expect(archiveState('nope')).toBeUndefined();
  });
});

describe('checkArchiveDiff', () => {
  it('passes when the archive is synced with Horizon', async () => {
    const diagnostics = await checkArchiveDiff(
      DOC,
      route({
        [`${ARCHIVE.replace(/\/$/, '')}${HAS_PATH}`]: has(1000),
        [HORIZON_ROOT.replace(/\/$/, '') + '/']: horizon(1000),
      }),
    );
    expect(diagnostics).toEqual([]);
  });

  it('passes when the archive hash matches the ledger Horizon closed', async () => {
    const diagnostics = await checkArchiveDiff(
      DOC,
      route({
        [`${ARCHIVE.replace(/\/$/, '')}${HAS_PATH}`]: has(1000, 'same-hash'),
        [HORIZON_ROOT.replace(/\/$/, '') + '/']: horizon(1000),
        [`${HORIZON_ROOT.replace(/\/$/, '')}/ledgers/1000`]: { hash: 'same-hash' },
      }),
    );
    expect(diagnostics).toEqual([]);
  });

  it('reports an archive lagging by 1000 ledgers', async () => {
    const diagnostics = await checkArchiveDiff(
      DOC,
      route({
        [`${ARCHIVE.replace(/\/$/, '')}${HAS_PATH}`]: has(1000),
        [HORIZON_ROOT.replace(/\/$/, '') + '/']: horizon(2000),
      }),
    );
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      rule: ARCHIVE_LAGGING_RULE,
      severity: 'error',
      path: 'VALIDATORS[0].HISTORY',
    });
  });

  it('warns, not errors, between 128 and 512 ledgers of lag', async () => {
    const diagnostics = await checkArchiveDiff(
      DOC,
      route({
        [`${ARCHIVE.replace(/\/$/, '')}${HAS_PATH}`]: has(1800),
        [HORIZON_ROOT.replace(/\/$/, '') + '/']: horizon(2000),
      }),
    );
    expect(diagnostics[0]).toMatchObject({
      rule: ARCHIVE_LAGGING_RULE,
      severity: 'warning',
    });
  });

  it('stays silent at or below the 128-ledger window', async () => {
    const diagnostics = await checkArchiveDiff(
      DOC,
      route({
        [`${ARCHIVE.replace(/\/$/, '')}${HAS_PATH}`]: has(1880),
        [HORIZON_ROOT.replace(/\/$/, '') + '/']: horizon(2000),
      }),
    );
    expect(diagnostics).toEqual([]);
  });

  it('errors when the archive hash disagrees with Horizon', async () => {
    const diagnostics = await checkArchiveDiff(
      DOC,
      route({
        [`${ARCHIVE.replace(/\/$/, '')}${HAS_PATH}`]: has(1000, 'archive-hash'),
        [HORIZON_ROOT.replace(/\/$/, '') + '/']: horizon(1000),
        [`${HORIZON_ROOT.replace(/\/$/, '')}/ledgers/1000`]: { hash: 'network-hash' },
      }),
    );
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      rule: ARCHIVE_HASH_MISMATCH_RULE,
      severity: 'error',
      path: 'VALIDATORS[0].HISTORY',
    });
  });

  it('degrades to silence when Horizon is unreachable', async () => {
    const diagnostics = await checkArchiveDiff(
      DOC,
      route({
        [`${ARCHIVE.replace(/\/$/, '')}${HAS_PATH}`]: has(1000),
        [HORIZON_ROOT.replace(/\/$/, '') + '/']: new Error('offline'),
      }),
    );
    expect(diagnostics).toEqual([]);
  });

  it('degrades to silence when the archive has no root HAS', async () => {
    const diagnostics = await checkArchiveDiff(
      DOC,
      route({ [HORIZON_ROOT.replace(/\/$/, '') + '/']: horizon(1000) }),
    );
    expect(diagnostics).toEqual([]);
  });

  it('honours rule overrides', async () => {
    const diagnostics = await checkArchiveDiff(
      DOC,
      route({
        [`${ARCHIVE.replace(/\/$/, '')}${HAS_PATH}`]: has(1000),
        [HORIZON_ROOT.replace(/\/$/, '') + '/']: horizon(2000),
      }),
      { rules: { [ARCHIVE_LAGGING_RULE]: 'off' } },
    );
    expect(diagnostics).toEqual([]);
  });

  it('uses the Horizon derived from NETWORK_PASSPHRASE', async () => {
    const fetchImpl = route({
      [`${ARCHIVE.replace(/\/$/, '')}${HAS_PATH}`]: has(1000),
      ['https://horizon-testnet.stellar.org/']: horizon(5000),
    });
    const diagnostics = await checkArchiveDiff(
      {
        NETWORK_PASSPHRASE: 'Test SDF Network ; September 2015',
        VALIDATORS: [{ HISTORY: ARCHIVE }],
      },
      fetchImpl,
    );
    expect(diagnostics[0]).toMatchObject({ rule: ARCHIVE_LAGGING_RULE, severity: 'error' });
  });
});
