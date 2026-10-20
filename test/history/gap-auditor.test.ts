import { describe, expect, it } from 'vitest';
import {
  checkHistoryGaps,
  checkpointContaining,
  checkpointFilePath,
  checkpointsInRange,
  groupGaps,
  isCheckpointLedger,
  latestArchivedLedger,
  LEDGER_SEQUENCE_GAP_RULE,
} from '../../src/history/gap-auditor.js';

const ARCHIVE = 'https://history.example/archive/';
const HAS_PATH = '/archive/.well-known/stellar-history.json';

const doc = {
  VALIDATORS: [{ ALIAS: 'v1', PUBLIC_KEY: 'G', HISTORY: ARCHIVE }],
};

/**
 * A fake archive: the root HAS names `currentLedger`, and every checkpoint
 * file is served unless its ledger is in `missing`.
 */
function archive(
  currentLedger: number,
  missing: readonly number[] = [],
  options: { rejectHead?: boolean } = {},
): { fetchImpl: typeof fetch; requests: string[] } {
  const requests: string[] = [];
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input));
    const method = init?.method ?? 'GET';
    requests.push(`${method} ${url.pathname}`);
    if (url.pathname === HAS_PATH) {
      return Response.json({ version: 1, server: 'stellar-core', currentLedger });
    }
    if (method === 'HEAD' && options.rejectHead) return new Response(null, { status: 405 });
    const match = /\/ledger-([0-9a-f]{8})\.xdr\.gz$/.exec(url.pathname);
    if (match === null) return new Response('not found', { status: 404 });
    const ledger = Number.parseInt(match[1] as string, 16);
    if (missing.includes(ledger)) return new Response('not found', { status: 404 });
    return new Response(method === 'HEAD' ? null : new Uint8Array([0x1f]), {
      status: method === 'HEAD' ? 200 : 206,
    });
  }) as typeof fetch;
  return { fetchImpl, requests };
}

describe('checkpoint arithmetic', () => {
  it('names the 64-ledger boundaries stellar-core publishes', () => {
    expect(isCheckpointLedger(63)).toBe(true);
    expect(isCheckpointLedger(64)).toBe(false);
    expect(isCheckpointLedger(1087)).toBe(true);
    expect(checkpointContaining(1024)).toBe(1087);
    expect(checkpointContaining(1023)).toBe(1023);
  });

  it('builds stellar-core archive paths', () => {
    expect(checkpointFilePath('ledger', 1087)).toBe('ledger/00/00/04/ledger-0000043f.xdr.gz');
    expect(checkpointFilePath('history', 63)).toBe('history/00/00/00/history-0000003f.json');
  });

  it('walks back from the head across the requested range', () => {
    const checkpoints = checkpointsInRange(2047, 640);
    expect(checkpoints[0]).toBe(1471);
    expect(checkpoints.at(-1)).toBe(2047);
    expect(checkpoints).toHaveLength(10);
    // A head that is not a boundary has not been published as one yet.
    expect(checkpointsInRange(2050, 128).at(-1)).toBe(2047);
    expect(checkpointsInRange(10, 10_000)).toEqual([]);
  });

  it('reads currentLedger from a root HAS', () => {
    expect(latestArchivedLedger({ currentLedger: 4095 })).toBe(4095);
    expect(latestArchivedLedger({ latest_ledger: 127 })).toBe(127);
    expect(latestArchivedLedger('nope')).toBeUndefined();
  });

  it('folds consecutive missing checkpoints into one gap', () => {
    const gaps = groupGaps([
      { checkpoint: 1151, file: 'b' },
      { checkpoint: 1087, file: 'a' },
      { checkpoint: 2047, file: 'c' },
    ]);
    expect(gaps).toEqual([
      { firstLedger: 1024, lastLedger: 1151, checkpoints: [1087, 1151], firstMissingFile: 'a' },
      { firstLedger: 1984, lastLedger: 2047, checkpoints: [2047], firstMissingFile: 'c' },
    ]);
  });
});

describe('checkHistoryGaps', () => {
  it('passes a complete history index', async () => {
    const { fetchImpl, requests } = archive(4095);
    expect(await checkHistoryGaps(doc, fetchImpl, { ledgerRange: 4096 })).toEqual([]);
    // One HAS read plus one probe per checkpoint from 63 to 4095.
    expect(requests.filter((r) => r.startsWith('HEAD'))).toHaveLength(64);
  });

  it('flags the missing ledger 1024 checkpoint', async () => {
    const { fetchImpl } = archive(4095, [1087]);
    const diagnostics = await checkHistoryGaps(doc, fetchImpl, { ledgerRange: 4096 });
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      rule: LEDGER_SEQUENCE_GAP_RULE,
      severity: 'error',
      path: 'VALIDATORS[0].HISTORY',
    });
    expect(diagnostics[0]?.message).toContain('ledgers 1024–1087');
    expect(diagnostics[0]?.message).toContain('ledger/00/00/04/ledger-0000043f.xdr.gz');
    expect(diagnostics[0]?.message).toContain('cannot replay past ledger 1023');
  });

  it('reports separate gaps separately and merges adjacent ones', async () => {
    const { fetchImpl } = archive(4095, [1087, 1151, 3071]);
    const diagnostics = await checkHistoryGaps(doc, fetchImpl, { ledgerRange: 4096 });
    expect(diagnostics.map((d) => d.message.match(/ledgers (\d+–\d+)/)?.[1])).toEqual([
      '1024–1151',
      '3008–3071',
    ]);
    expect(diagnostics[0]?.message).toContain('2 consecutive checkpoints');
  });

  it('only audits the requested range', async () => {
    const { fetchImpl } = archive(4095, [1087]);
    expect(await checkHistoryGaps(doc, fetchImpl, { ledgerRange: 640 })).toEqual([]);
  });

  it('falls back to a ranged GET when the archive rejects HEAD', async () => {
    const { fetchImpl, requests } = archive(1023, [511], { rejectHead: true });
    const diagnostics = await checkHistoryGaps(doc, fetchImpl);
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.message).toContain('ledgers 448–511');
    expect(requests).toContain('GET /archive/ledger/00/00/01/ledger-000001ff.xdr.gz');
  });

  it('stays silent when the root HAS cannot be read', async () => {
    const fetchImpl = (async () => new Response('nope', { status: 500 })) as typeof fetch;
    expect(await checkHistoryGaps(doc, fetchImpl)).toEqual([]);
  });

  it('respects --off', async () => {
    const { fetchImpl } = archive(4095, [1087]);
    expect(
      await checkHistoryGaps(doc, fetchImpl, { rules: { [LEDGER_SEQUENCE_GAP_RULE]: 'off' } }),
    ).toEqual([]);
  });
});
