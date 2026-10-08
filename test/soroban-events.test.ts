import { describe, expect, it } from 'vitest';
import { Address, xdr } from '@stellar/stellar-base';
import {
  EVENT_DATA_TYPE_INVALID_RULE,
  EVENT_TOPIC_MISMATCH_RULE,
  auditContractEvents,
  eventRules,
  verifyLiveEvents,
  verifySep41EventSpecs,
} from '../src/soroban/events.js';
import { codeEntryXdr, instanceEntryXdr, specEvent, specWasm } from './soroban-fixtures.js';

const CONTRACT = 'CACTZSQPCQSSZ5YG3PI3N7WO6JEERKEUHTPILKB4MBANF2K4D2UHKDDU';
const ACCOUNT = 'GDVEU3DD4KOFECV66VIHWEZOYX4ZKR3WV27L464SIIPOU2IUI3JCZA57';
const WASM_HASH = Buffer.alloc(32, 0x22);

const tokenWasm = specWasm([
  specEvent('transfer', ['from', 'to']),
  specEvent('mint', ['admin', 'to']),
  specEvent('burn', ['from']),
]);

function i128(value: string): xdr.ScVal {
  return xdr.ScVal.scvI128(
    new xdr.Int128Parts({ hi: xdr.Int64.fromString('0'), lo: xdr.Uint64.fromString(value) }),
  );
}

function liveEvent(topics: xdr.ScVal[], data: xdr.ScVal): { topics: string[]; value: string } {
  return {
    topics: topics.map((topic) => topic.toXDR('base64')),
    value: data.toXDR('base64'),
  };
}

/** An RPC stub answering `getLedgerEntries` and `getEvents`. */
function eventsRpc(events: unknown[]): typeof fetch {
  return (async (_url: string | URL | Request, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)) as { method: string; params: { keys: string[] } };
    if (body.method === 'getEvents') {
      return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { events } }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }
    const key = body.params.keys[0] as string;
    const kind = xdr.LedgerKey.fromXDR(key, 'base64').switch().name;
    const entryXdr =
      kind === 'contractCode'
        ? codeEntryXdr(tokenWasm, WASM_HASH)
        : instanceEntryXdr({ contractId: CONTRACT, wasmHash: WASM_HASH });
    return new Response(
      JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        result: { latestLedger: 1000, entries: [{ xdr: entryXdr, liveUntilLedgerSeq: 2000 }] },
      }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );
  }) as unknown as typeof fetch;
}

describe('soroban event schema extractor (#77)', () => {
  it('passes a contract whose spec matches the SEP-41 event conventions', () => {
    expect(verifySep41EventSpecs(tokenWasm, CONTRACT)).toEqual([]);
  });

  it('asserts soroban/event-topic-mismatch when a transfer uses non-standard topics', () => {
    const wasm = specWasm([specEvent('transfer', ['sender', 'receiver'])]);
    expect(verifySep41EventSpecs(wasm, CONTRACT)).toContainEqual(
      expect.objectContaining({ rule: EVENT_TOPIC_MISMATCH_RULE, severity: 'warning' }),
    );
  });

  it('asserts soroban/event-data-type-invalid when an amount is not an i128', () => {
    const wasm = specWasm([specEvent('transfer', ['from', 'to'], 'scSpecTypeString')]);
    expect(verifySep41EventSpecs(wasm, CONTRACT)).toContainEqual(
      expect.objectContaining({ rule: EVENT_DATA_TYPE_INVALID_RULE, severity: 'error' }),
    );
  });

  it('passes when live events match the SEP-41 shape', async () => {
    const events = [
      liveEvent(
        [
          xdr.ScVal.scvSymbol('transfer'),
          new Address(ACCOUNT).toScVal(),
          new Address(ACCOUNT).toScVal(),
        ],
        i128('100'),
      ),
    ];
    const diagnostics = await auditContractEvents(CONTRACT, 'https://rpc.test', eventsRpc(events));
    expect(diagnostics).toEqual([]);
  });

  it('asserts soroban/event-data-type-invalid on a string live amount', async () => {
    const events = [
      liveEvent(
        [
          xdr.ScVal.scvSymbol('transfer'),
          new Address(ACCOUNT).toScVal(),
          new Address(ACCOUNT).toScVal(),
        ],
        xdr.ScVal.scvString('100'),
      ),
    ];
    const diagnostics = await auditContractEvents(CONTRACT, 'https://rpc.test', eventsRpc(events));
    expect(diagnostics).toContainEqual(
      expect.objectContaining({ rule: EVENT_DATA_TYPE_INVALID_RULE, severity: 'error' }),
    );
  });

  it('asserts soroban/event-topic-mismatch on a live event with missing topics', () => {
    const diagnostics = verifyLiveEvents(
      [liveEvent([xdr.ScVal.scvSymbol('burn')], i128('1'))],
      CONTRACT,
    );
    expect(diagnostics).toContainEqual(
      expect.objectContaining({ rule: EVENT_TOPIC_MISMATCH_RULE, severity: 'warning' }),
    );
  });

  it('registers both rule definitions', () => {
    expect(eventRules.map((r) => ({ id: r.id, severity: r.severity }))).toEqual([
      { id: EVENT_TOPIC_MISMATCH_RULE, severity: 'warning' },
      { id: EVENT_DATA_TYPE_INVALID_RULE, severity: 'error' },
    ]);
  });
});
