import { describe, expect, it } from 'vitest';
import {
  checkHistoryPublish,
  type HistoryCheckpoint,
  HISTORY_BROKEN_CHECKPOINT_CHAIN,
  HISTORY_MISSING_CATEGORY_ARCHIVE,
} from '../src/history/publish-validator.js';

const HISTORY = 'https://history.example/archive/';
const DOC = { VALIDATORS: [{ HOST: 'core.example:11625', HISTORY }] };

function checkpoints(): HistoryCheckpoint[] {
  return [
    { sequence: 1, hash: 'hash-1' },
    { sequence: 65, hash: 'hash-65', previousLedgerHash: 'hash-1' },
    { sequence: 129, hash: 'hash-129', previousLedgerHash: 'hash-65' },
  ];
}

function fetchArchive(missing?: string): typeof fetch {
  return (async (input: Parameters<typeof fetch>[0]) => {
    const path = new URL(String(input)).pathname;
    if (missing !== undefined && path.includes(`/${missing}-`)) {
      return new Response('not found', { status: 404 });
    }
    return new Response('xdr archive', { status: 200 });
  }) as typeof fetch;
}

describe('history publish validator', () => {
  it('passes when all three checkpoints contain every category', async () => {
    const diagnostics = await checkHistoryPublish(DOC, fetchArchive(), {
      checkpoints: checkpoints(),
    });
    expect(diagnostics).toEqual([]);
  });

  it('reports a missing category archive', async () => {
    const diagnostics = await checkHistoryPublish(DOC, fetchArchive('transactions'), {
      checkpoints: checkpoints(),
    });
    expect(diagnostics[0]).toMatchObject({
      rule: HISTORY_MISSING_CATEGORY_ARCHIVE,
      severity: 'error',
      path: 'VALIDATORS[0].HISTORY',
    });
  });

  it('reports a broken previous-ledger chain', async () => {
    const broken = checkpoints();
    const second = broken[1];
    if (second === undefined) throw new Error('fixture is missing its second checkpoint');
    broken[1] = { ...second, previousLedgerHash: 'wrong-hash' };
    const diagnostics = await checkHistoryPublish(DOC, fetchArchive(), {
      checkpoints: broken,
    });
    expect(diagnostics[0]?.rule).toBe(HISTORY_BROKEN_CHECKPOINT_CHAIN);
  });

  it('honours the missing-category override', async () => {
    const diagnostics = await checkHistoryPublish(DOC, fetchArchive('transactions'), {
      checkpoints: checkpoints(),
      rules: { [HISTORY_MISSING_CATEGORY_ARCHIVE]: 'off' },
    });
    expect(diagnostics).toEqual([]);
  });
});
