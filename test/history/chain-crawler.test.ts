import { describe, expect, it } from 'vitest';

import {
  BROKEN_CHECKPOINT_SEQUENCE_RULE,
  chainCrawlerRules,
  CHECKPOINT_LEDGER_HASH_MISMATCH_RULE,
  checkHistoryChain,
  crawlHistoryChain,
  DEFAULT_CRAWLED_CHECKPOINTS,
  parseHistoryCheckpoint,
} from '../../src/history/chain-crawler.js';
import { checkpointFilePath } from '../../src/history/gap-auditor.js';

const BASE = 'https://archive.example/history/';
const ROOT_URL = `${BASE}.well-known/stellar-history.json`;

function hash(ledger: number): string {
  return `H${ledger}`;
}

function has(ledger: number, previousHash = hash(ledger - 64), declaredHash = hash(ledger)) {
  return {
    currentLedger: ledger,
    ledgerHash: declaredHash,
    previousLedger: ledger - 64,
    previousLedgerHash: previousHash,
  };
}

function checkpointUrl(ledger: number): string {
  return new URL(checkpointFilePath('history', ledger), BASE).toString();
}

function archive(entries: Map<string, unknown>) {
  const calls: string[] = [];
  const fetchImpl = async (input: string | URL | Request): Promise<Response> => {
    const url = String(input);
    calls.push(url);
    const body = entries.get(url);
    if (body === undefined) return new Response('not found', { status: 404 });
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };
  return { fetchImpl: fetchImpl as typeof fetch, calls };
}

function validEntries(rootLedger = 639): Map<string, unknown> {
  const entries = new Map<string, unknown>();
  entries.set(ROOT_URL, has(rootLedger));
  for (let ledger = rootLedger; ledger > rootLedger - 5 * 64; ledger -= 64) {
    entries.set(checkpointUrl(ledger), has(ledger));
  }
  return entries;
}

describe('parseHistoryCheckpoint', () => {
  it('accepts stellar-core and looser HAS field spellings', () => {
    expect(
      parseHistoryCheckpoint({
        currentLedger: 639,
        currentLedgerHash: 'abc',
        previousLedgerHash: 'def',
        previousLedger: 575,
      }),
    ).toEqual({
      ledger: 639,
      hash: 'abc',
      previousHash: 'def',
      previousLedger: 575,
    });

    expect(
      parseHistoryCheckpoint({
        ledger: { sequence: 575, hash: 'old', previousHash: 'older' },
      }),
    ).toEqual({ ledger: 575, hash: 'old', previousHash: 'older' });
  });

  it('returns an empty record for a malformed body', () => {
    expect(parseHistoryCheckpoint('not a HAS')).toEqual({});
    expect(parseHistoryCheckpoint({})).toEqual({});
  });
});

describe('crawlHistoryChain', () => {
  it('crawls a valid checkpoint chain', async () => {
    const { fetchImpl, calls } = archive(validEntries());
    const audit = await crawlHistoryChain(BASE, fetchImpl, { maxCheckpoints: 3 });

    expect(audit.issues).toEqual([]);
    expect(audit.complete).toBe(true);
    expect(audit.rootLedger).toBe(639);
    expect(audit.checkpoints.map((entry) => entry.ledger)).toEqual([639, 575, 511, 447]);
    expect(calls).toHaveLength(4);
    expect(calls[0]).toBe(ROOT_URL);
    expect(calls[1]).toBe(checkpointUrl(575));
  });

  it('reports a missing intermediate checkpoint', async () => {
    const entries = validEntries();
    entries.delete(checkpointUrl(447));
    const { fetchImpl } = archive(entries);
    const audit = await crawlHistoryChain(BASE, fetchImpl, { maxCheckpoints: 3 });

    expect(audit.complete).toBe(false);
    expect(audit.issues).toHaveLength(1);
    expect(audit.issues[0]).toMatchObject({
      kind: 'broken-sequence',
      reason: 'missing',
      expected: 447,
      newer: 511,
    });
  });

  it('reports a checkpoint that is not 64 ledgers before its parent', async () => {
    const entries = new Map<string, unknown>([[ROOT_URL, has(639)]]);
    entries.set(checkpointUrl(575), has(600, hash(536)));
    const { fetchImpl } = archive(entries);
    const audit = await crawlHistoryChain(BASE, fetchImpl, { maxCheckpoints: 1 });

    expect(audit.issues).toContainEqual({
      kind: 'broken-sequence',
      reason: 'interval',
      expected: 575,
      actual: 600,
      newer: 639,
      url: checkpointUrl(575),
    });
  });

  it('reports a broken parent ledger hash', async () => {
    const entries = new Map<string, unknown>([[ROOT_URL, has(639, 'expected-parent-hash')]]);
    entries.set(checkpointUrl(575), has(575, hash(511)));
    const { fetchImpl } = archive(entries);
    const audit = await crawlHistoryChain(BASE, fetchImpl, { maxCheckpoints: 1 });

    expect(audit.issues).toContainEqual({
      kind: 'hash-mismatch',
      newer: 639,
      older: 575,
      expected: 'expected-parent-hash',
      actual: hash(575),
      url: checkpointUrl(575),
    });
  });

  it('reports a malformed checkpoint HAS', async () => {
    const entries = new Map<string, unknown>([[ROOT_URL, has(639)]]);
    entries.set(checkpointUrl(575), { hello: 'world' });
    const { fetchImpl } = archive(entries);
    const audit = await crawlHistoryChain(BASE, fetchImpl, { maxCheckpoints: 1 });

    expect(audit.issues[0]).toMatchObject({
      kind: 'broken-sequence',
      reason: 'malformed',
      expected: 575,
      newer: 639,
    });
  });

  it('skips the unpublished root ledger when it is not a boundary', async () => {
    const entries = new Map<string, unknown>([
      [ROOT_URL, has(650, 'hash-of-ledger-649')],
      [checkpointUrl(639), has(639)],
      [checkpointUrl(575), has(575)],
    ]);
    const { fetchImpl, calls } = archive(entries);
    const audit = await crawlHistoryChain(BASE, fetchImpl, { maxCheckpoints: 2 });

    expect(audit.issues).toEqual([]);
    expect(audit.rootLedger).toBe(650);
    expect(audit.checkpoints.map((entry) => entry.ledger)).toEqual([650, 639, 575]);
    expect(calls[1]).toBe(checkpointUrl(639));
  });

  it('stays silent when the root HAS cannot be read', async () => {
    const { fetchImpl } = archive(new Map());
    expect(await crawlHistoryChain(BASE, fetchImpl)).toEqual({
      checkpoints: [],
      issues: [],
      complete: false,
    });
  });

  it('defaults to ten older checkpoints', async () => {
    const entries = new Map<string, unknown>();
    for (let index = 0; index <= DEFAULT_CRAWLED_CHECKPOINTS; index++) {
      const ledger = 4095 - index * 64;
      entries.set(index === 0 ? ROOT_URL : checkpointUrl(ledger), has(ledger));
    }
    const { fetchImpl, calls } = archive(entries);
    const audit = await crawlHistoryChain(BASE, fetchImpl);
    expect(audit.issues).toEqual([]);
    expect(audit.complete).toBe(true);
    expect(audit.checkpoints).toHaveLength(DEFAULT_CRAWLED_CHECKPOINTS + 1);
    expect(calls).toHaveLength(DEFAULT_CRAWLED_CHECKPOINTS + 1);
  });
});

describe('checkHistoryChain', () => {
  it('passes a valid document', async () => {
    const { fetchImpl } = archive(validEntries());
    expect(
      await checkHistoryChain(
        { VALIDATORS: [{ PUBLIC_KEY: 'GABC', HISTORY: 'https://archive.example/history' }] },
        fetchImpl,
        { maxCheckpoints: 2 },
      ),
    ).toEqual([]);
  });

  it('emits broken-checkpoint-sequence for a missing link', async () => {
    const entries = validEntries();
    entries.delete(checkpointUrl(511));
    const { fetchImpl } = archive(entries);
    const diagnostics = await checkHistoryChain(
      { VALIDATORS: [{ PUBLIC_KEY: 'GABC', HISTORY: 'https://archive.example/history' }] },
      fetchImpl,
      { maxCheckpoints: 2 },
    );
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      rule: BROKEN_CHECKPOINT_SEQUENCE_RULE,
      severity: 'error',
      category: 'validators',
      path: 'VALIDATORS[0].HISTORY',
    });
    expect(diagnostics[0]?.message).toContain('ledger 511');
  });

  it('emits checkpoint-ledger-hash-mismatch as an error', async () => {
    const entries = new Map<string, unknown>([[ROOT_URL, has(639, 'wrong')]]);
    entries.set(checkpointUrl(575), has(575));
    const { fetchImpl } = archive(entries);
    const diagnostics = await checkHistoryChain(
      { VALIDATORS: [{ PUBLIC_KEY: 'GABC', HISTORY: 'https://archive.example/history' }] },
      fetchImpl,
      { maxCheckpoints: 1 },
    );
    expect(diagnostics[0]).toMatchObject({
      rule: CHECKPOINT_LEDGER_HASH_MISMATCH_RULE,
      severity: 'error',
    });
    expect(diagnostics[0]?.message).toContain('HAS chain is broken');
  });

  it('skips entries without HISTORY and malformed HISTORY URLs', async () => {
    const { fetchImpl, calls } = archive(validEntries());
    const diagnostics = await checkHistoryChain(
      {
        VALIDATORS: [{ PUBLIC_KEY: 'GABC' }, { PUBLIC_KEY: 'GDEF', HISTORY: 'not a url' }],
      },
      fetchImpl,
      { maxCheckpoints: 1 },
    );
    expect(diagnostics).toEqual([]);
    expect(calls).toEqual([]);
  });

  it('honours --off for both rules', async () => {
    const entries = validEntries();
    entries.delete(checkpointUrl(575));
    const { fetchImpl } = archive(entries);
    const diagnostics = await checkHistoryChain(
      { VALIDATORS: [{ PUBLIC_KEY: 'GABC', HISTORY: 'https://archive.example/history' }] },
      fetchImpl,
      {
        maxCheckpoints: 1,
        rules: {
          [BROKEN_CHECKPOINT_SEQUENCE_RULE]: 'off',
          [CHECKPOINT_LEDGER_HASH_MISMATCH_RULE]: 'off',
        },
      },
    );
    expect(diagnostics).toEqual([]);
  });

  it('is registered for --list-rules', () => {
    expect(chainCrawlerRules.map((rule) => rule.id)).toEqual([
      BROKEN_CHECKPOINT_SEQUENCE_RULE,
      CHECKPOINT_LEDGER_HASH_MISMATCH_RULE,
    ]);
  });
});
