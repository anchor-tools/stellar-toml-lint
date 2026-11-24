import { describe, expect, it } from 'vitest';
import { Address, StrKey, nativeToScVal, xdr } from '@stellar/stellar-base';
import { parse } from 'smol-toml';
import {
  CORE_EVENT_CONVENTIONS,
  COMMUNITY_EVENT_CONVENTIONS,
  EVENT_MISSING_TOPICS_RULE,
  EVENT_NESTED_DATA_RULE,
  EVENT_SECONDARY_TOPIC_RULE,
  EVENT_SPEC_MISSING_NAME_RULE,
  EVENT_SPEC_UNINDEXED_ADDRESS_RULE,
  EVENT_TOPIC_NOT_SYMBOL_RULE,
  EVENT_UNDECLARED_RULE,
  EVENT_UNINDEXED_ADDRESS_RULE,
  containerDepth,
  containsAddress,
  conventionFor,
  dataShapeOf,
  declaredEvent,
  eventActionName,
  eventRules,
  topicInfo,
  validateEvent,
  validateEventSpec,
  type EventRecord,
  type EventSpecDefinition,
} from '../src/soroban/eventRules.js';
import {
  DEFAULT_MAX_SIMULATED_FUNCTIONS,
  EVENT_EMITTING_FUNCTIONS,
  EventSchemaVerifier,
  auditTomlEvents,
  buildEventSimulationTransaction,
  eventVerifierRuleIds,
  eventVerifierRules,
  fetchEventContractWasm,
  parseContractEvent,
  parseContractSpec,
  parseEventSpecs,
  parseSimulatedEvents,
  simulationTargets,
  simulatedEventsOf,
  validateContractEvents,
  validateEventSpecs,
  type ContractFunctionSpec,
} from '../src/soroban/eventVerifier.js';
import { sorobanRuleIds } from '../src/soroban.js';

const CONTRACT = 'CACTZSQPCQSSZ5YG3PI3N7WO6JEERKEUHTPILKB4MBANF2K4D2UHKDDU';
const OTHER_CONTRACT = StrKey.encodeContract(Buffer.alloc(32, 7));
const ALICE = StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 1));
const BOB = StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 2));
const RPC = 'https://soroban-testnet.stellar.org';
const TESTNET_PASSPHRASE = 'Test SDF Network ; September 2015';

const symbol = (value: string): xdr.ScVal => xdr.ScVal.scvSymbol(value);
const text = (value: string): xdr.ScVal => xdr.ScVal.scvString(value);
const account = (value: string): xdr.ScVal => new Address(value).toScVal();
const amount = (value: number): xdr.ScVal => nativeToScVal(BigInt(value), { type: 'i128' });

function event(options: {
  topics: xdr.ScVal[];
  data: xdr.ScVal;
  type?: 'contract' | 'system' | 'diagnostic';
  contractId?: string | null;
}): EventRecord {
  const type = options.type ?? 'contract';
  const contractId =
    options.contractId === undefined
      ? CONTRACT
      : options.contractId === null
        ? null
        : options.contractId;
  return {
    ...(contractId !== null ? { contractId } : {}),
    type,
    topics: options.topics,
    data: options.data,
  };
}

/** Encodes a `ContractEvent` the way `simulateTransaction` returns one. */
function eventXdr(options: {
  topics: xdr.ScVal[];
  data: xdr.ScVal;
  type?: 'contract' | 'system' | 'diagnostic';
  contractId?: string | null;
}): string {
  const contractId =
    options.contractId === undefined
      ? StrKey.decodeContract(CONTRACT)
      : options.contractId === null
        ? null
        : StrKey.decodeContract(options.contractId);
  const type =
    options.type === 'system'
      ? xdr.ContractEventType.system()
      : options.type === 'diagnostic'
        ? xdr.ContractEventType.diagnostic()
        : xdr.ContractEventType.contract();

  return new xdr.ContractEvent({
    ext: xdr.ExtensionPoint.fromXDR(Buffer.alloc(4), 'raw'),
    contractId: contractId as unknown as xdr.ContractId,
    type,
    body: new xdr.ContractEventBody(
      0,
      new xdr.ContractEventV0({ topics: options.topics, data: options.data }),
    ),
  }).toXDR('base64');
}

/** Unsigned LEB128. */
function u32(value: number): Buffer {
  const bytes: number[] = [];
  let rest = value;
  do {
    let byte = rest & 0x7f;
    rest >>>= 7;
    if (rest !== 0) byte |= 0x80;
    bytes.push(byte);
  } while (rest !== 0);
  return Buffer.from(bytes);
}

function eventSpec(options: {
  name: string;
  prefixTopics?: string[];
  params?: { name: string; type: xdr.ScSpecTypeDef; topic?: boolean }[];
  dataFormat?: 'single' | 'vec' | 'map';
}): xdr.ScSpecEntry {
  const dataFormat =
    options.dataFormat === 'vec'
      ? xdr.ScSpecEventDataFormat.scSpecEventDataFormatVec()
      : options.dataFormat === 'map'
        ? xdr.ScSpecEventDataFormat.scSpecEventDataFormatMap()
        : xdr.ScSpecEventDataFormat.scSpecEventDataFormatSingleValue();

  return xdr.ScSpecEntry.scSpecEntryEventV0(
    new xdr.ScSpecEventV0({
      doc: '',
      lib: '',
      name: options.name,
      prefixTopics: options.prefixTopics ?? [options.name],
      params: (options.params ?? []).map(
        (param) =>
          new xdr.ScSpecEventParamV0({
            doc: '',
            name: param.name,
            type: param.type,
            location:
              param.topic === true
                ? xdr.ScSpecEventParamLocationV0.scSpecEventParamLocationTopicList()
                : xdr.ScSpecEventParamLocationV0.scSpecEventParamLocationData(),
          }),
      ),
      dataFormat,
    }),
  );
}

function functionSpec(name: string, inputs: xdr.ScSpecTypeDef[] = []): xdr.ScSpecEntry {
  return xdr.ScSpecEntry.scSpecEntryFunctionV0(
    new xdr.ScSpecFunctionV0({
      doc: '',
      name,
      inputs: inputs.map(
        (type, index) => new xdr.ScSpecFunctionInputV0({ doc: '', name: `arg${index}`, type }),
      ),
      outputs: [],
    }),
  );
}

function wasmWithSpec(entries: xdr.ScSpecEntry[]): Buffer {
  const payload = Buffer.concat(entries.map((entry) => entry.toXDR()));
  const name = Buffer.from('contractspecv0', 'utf8');
  const content = Buffer.concat([u32(name.length), name, payload]);
  const header = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
  return Buffer.concat([header, Buffer.from([0x00]), u32(content.length), content]);
}

const WASM_HEADER = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);

function rawWasm(sections: Buffer[]): Buffer {
  return Buffer.concat([WASM_HEADER, ...sections]);
}

function rawSection(id: number, payload: Buffer): Buffer {
  return Buffer.concat([Buffer.from([id]), u32(payload.length), payload]);
}

const A_TOKEN_WASM = wasmWithSpec([
  eventSpec({
    name: 'transfer',
    params: [
      { name: 'from', type: xdr.ScSpecTypeDef.scSpecTypeAddress(), topic: true },
      { name: 'to', type: xdr.ScSpecTypeDef.scSpecTypeAddress(), topic: true },
      { name: 'amount', type: xdr.ScSpecTypeDef.scSpecTypeI128() },
    ],
  }),
  eventSpec({
    name: 'mint',
    params: [
      { name: 'to', type: xdr.ScSpecTypeDef.scSpecTypeAddress(), topic: true },
      { name: 'amount', type: xdr.ScSpecTypeDef.scSpecTypeI128() },
    ],
  }),
  functionSpec('transfer', [
    xdr.ScSpecTypeDef.scSpecTypeAddress(),
    xdr.ScSpecTypeDef.scSpecTypeAddress(),
    xdr.ScSpecTypeDef.scSpecTypeI128(),
  ]),
  functionSpec('mint', [xdr.ScSpecTypeDef.scSpecTypeAddress(), xdr.ScSpecTypeDef.scSpecTypeI128()]),
  functionSpec('balance', [xdr.ScSpecTypeDef.scSpecTypeAddress()]),
  functionSpec('upgrade', [xdr.ScSpecTypeDef.scSpecTypeBytes()]),
]);

// ---------------------------------------------------------------------------
// RPC mocks
// ---------------------------------------------------------------------------

function instanceEntryXdr(contractId = CONTRACT): string {
  return xdr.LedgerEntryData.contractData(
    new xdr.ContractDataEntry({
      ext: xdr.ExtensionPoint.fromXDR(Buffer.alloc(4), 'raw'),
      contract: new Address(contractId).toScAddress(),
      key: xdr.ScVal.scvLedgerKeyContractInstance(),
      durability: xdr.ContractDataDurability.persistent(),
      val: xdr.ScVal.scvContractInstance(
        new xdr.ScContractInstance({
          executable: xdr.ContractExecutable.contractExecutableWasm(Buffer.alloc(32)),
          storage: [],
        }),
      ),
    }),
  ).toXDR('base64');
}

function codeEntryXdr(wasm: Buffer): string {
  return xdr.LedgerEntryData.contractCode(
    new xdr.ContractCodeEntry({
      ext: xdr.ContractCodeEntryExt.fromXDR(Buffer.alloc(4), 'raw'),
      hash: Buffer.alloc(32),
      code: wasm,
    }),
  ).toXDR('base64');
}

interface SimulateOptions {
  wasm?: Buffer | undefined;
  /** Events returned for every simulateTransaction call. */
  events?: unknown[];
  /** Return the events under `results[].events` instead of the top level. */
  nestedEvents?: boolean;
  latestLedger?: number;
}

function rpcMock(options: SimulateOptions = {}): {
  fetchImpl: typeof fetch;
  simulatedFunctions: () => string[];
} {
  const simulatedFunctions: string[] = [];
  const fetchImpl = (async (_url: string | URL | globalThis.Request, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)) as {
      method: string;
      params: { keys?: string[]; transaction?: string };
    };

    if (body.method === 'getLedgerEntries') {
      const key = body.params.keys?.[0] as string;
      const isCode = xdr.LedgerKey.fromXDR(key, 'base64').switch().name === 'contractCode';
      const entryXdr =
        isCode && options.wasm !== undefined
          ? codeEntryXdr(options.wasm)
          : isCode
            ? undefined
            : instanceEntryXdr();
      const entries =
        entryXdr === undefined
          ? []
          : [{ key, xdr: entryXdr, lastModifiedLedgerSeq: 1, liveUntilLedgerSeq: 200_000 }];
      return new Response(
        JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          result: { latestLedger: options.latestLedger ?? 100_000, entries },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }

    const envelope = xdr.TransactionEnvelope.fromXDR(body.params.transaction as string, 'base64');
    const operation = envelope.v1().tx().operations()[0]!;
    const fn = operation
      .body()
      .invokeHostFunctionOp()
      .hostFunction()
      .invokeContract()
      .functionName()
      .toString();
    simulatedFunctions.push(fn);

    const events = options.events ?? [];
    const result = options.nestedEvents
      ? { results: [{ auth: [], events, xdr: '' }] }
      : { results: [], events };
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }) as unknown as typeof fetch;

  return { fetchImpl, simulatedFunctions: () => simulatedFunctions };
}

const rulesOf = (diagnostics: { rule: string }[]): string[] =>
  diagnostics.map((diagnostic) => diagnostic.rule);

// ---------------------------------------------------------------------------
// Event decoding and classification
// ---------------------------------------------------------------------------

describe('topicInfo', () => {
  it('classifies every topic role a standard schema uses', () => {
    expect(topicInfo(symbol('transfer'), 0)).toEqual({
      index: 0,
      role: 'symbol',
      text: 'transfer',
    });
    expect(topicInfo(text('pool'), 1)).toEqual({ index: 1, role: 'string', text: 'pool' });
    expect(topicInfo(account(ALICE), 2)).toMatchObject({
      index: 2,
      role: 'address',
      address: ALICE,
    });
    expect(topicInfo(nativeToScVal(7, { type: 'u32' }), 3).role).toBe('integer');
    expect(topicInfo(nativeToScVal(Buffer.alloc(2), { type: 'bytes' }), 4).role).toBe('bytes');
    expect(topicInfo(xdr.ScVal.scvBool(true), 5).role).toBe('other');
  });

  it('leaves the address out when the SCAddress cannot be rendered', () => {
    const trap = {
      switch: () => ({ name: 'scvAddress' }),
      address: () => {
        throw new Error('bad address');
      },
    } as unknown as xdr.ScVal;
    expect(topicInfo(trap, 1)).toEqual({ index: 1, role: 'address' });
  });
});

describe('payload helpers', () => {
  it('reads the data shape', () => {
    expect(dataShapeOf(xdr.ScVal.scvVoid())).toBe('void');
    expect(dataShapeOf(amount(10))).toBe('scalar');
    expect(dataShapeOf(xdr.ScVal.scvVec([]))).toBe('vec');
    expect(dataShapeOf(xdr.ScVal.scvMap([]))).toBe('map');
  });

  it('measures container nesting', () => {
    expect(containerDepth(amount(10))).toBe(0);
    expect(containerDepth(xdr.ScVal.scvVec([amount(1), amount(2)]))).toBe(1);
    expect(containerDepth(xdr.ScVal.scvVec([xdr.ScVal.scvVec([amount(1)])]))).toBe(2);
    expect(
      containerDepth(
        xdr.ScVal.scvMap([
          new xdr.ScMapEntry({ key: symbol('k'), val: xdr.ScVal.scvVec([amount(1)]) }),
        ]),
      ),
    ).toBe(2);
  });

  it('finds an address nested anywhere in a payload', () => {
    expect(containsAddress(account(ALICE))).toBe(true);
    expect(containsAddress(amount(1))).toBe(false);
    expect(containsAddress(xdr.ScVal.scvVec([account(BOB)]))).toBe(true);
    expect(
      containsAddress(
        xdr.ScVal.scvMap([new xdr.ScMapEntry({ key: symbol('to'), val: account(ALICE) })]),
      ),
    ).toBe(true);
    expect(
      containsAddress(
        xdr.ScVal.scvMap([new xdr.ScMapEntry({ key: account(ALICE), val: amount(1) })]),
      ),
    ).toBe(true);
  });

  it('reads the action name and picks a convention', () => {
    expect(eventActionName([symbol('MINT')])).toBe('mint');
    expect(eventActionName([text('deposit')])).toBe('deposit');
    expect(eventActionName([account(ALICE)])).toBeUndefined();
    expect(eventActionName([])).toBeUndefined();

    expect(conventionFor('transfer').id).toBe('core');
    expect(conventionFor('deposit').id).toBe('community');
    expect(conventionFor(undefined).id).toBe('community');
    expect(CORE_EVENT_CONVENTIONS.allowsUnknownActions).toBe(false);
    expect(COMMUNITY_EVENT_CONVENTIONS.allowsUnknownActions).toBe(true);
  });

  it('finds a declared event by name and handles a missing action', () => {
    const specs: EventSpecDefinition[] = [
      {
        name: 'Transfer',
        prefixTopics: ['Transfer'],
        params: [],
        dataFormat: 'single',
      },
    ];
    expect(declaredEvent(specs, 'transfer')?.name).toBe('Transfer');
    expect(declaredEvent(specs, 'mint')).toBeUndefined();
    expect(declaredEvent(specs, undefined)).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Emitted-event validation
// ---------------------------------------------------------------------------

describe('validateEvent', () => {
  it('passes a standard SAC transfer', () => {
    expect(
      validateEvent(
        event({
          topics: [symbol('transfer'), account(ALICE), account(BOB)],
          data: amount(25),
        }),
      ),
    ).toEqual([]);
  });

  it('passes a SAC mint with a single recipient topic', () => {
    expect(
      validateEvent(event({ topics: [symbol('mint'), account(ALICE)], data: amount(25) })),
    ).toEqual([]);
  });

  it('reports an event with no topics', () => {
    const findings = validateEvent(event({ topics: [], data: amount(1) }));
    expect(findings.map((finding) => finding.rule)).toEqual([EVENT_MISSING_TOPICS_RULE]);
    expect(findings[0]?.severity).toBe('error');
  });

  it('reports a topic 0 that does not name the action', () => {
    const findings = validateEvent(
      event({ topics: [amount(1), account(ALICE), account(BOB)], data: amount(2) }),
    );
    expect(findings.map((finding) => finding.rule)).toContain(EVENT_TOPIC_NOT_SYMBOL_RULE);
  });

  it('reports a transfer whose recipient is only in the data payload', () => {
    const findings = validateEvent(
      event({
        topics: [symbol('transfer'), account(ALICE)],
        data: xdr.ScVal.scvVec([account(BOB), amount(5)]),
      }),
    );
    expect(rulesOf(findings)).toEqual([EVENT_UNINDEXED_ADDRESS_RULE]);
  });

  it('reports a transfer whose topic 2 is not an address', () => {
    const findings = validateEvent(
      event({ topics: [symbol('transfer'), account(ALICE), text('bob')], data: amount(5) }),
    );
    expect(rulesOf(findings)).toEqual([EVENT_UNINDEXED_ADDRESS_RULE]);
    expect(findings[0]?.message).toContain('topic 2 is a string value');
  });

  it('reports a missing address topic outright', () => {
    const findings = validateEvent(
      event({ topics: [symbol('mint'), amount(10)], data: amount(5) }),
    );
    expect(rulesOf(findings)).toContain(EVENT_UNINDEXED_ADDRESS_RULE);
  });

  it('reports a Core action whose data shape is unexpected', () => {
    const findings = validateEvent(
      event({
        topics: [symbol('mint'), account(ALICE)],
        data: xdr.ScVal.scvMap([new xdr.ScMapEntry({ key: symbol('amount'), val: amount(5) })]),
      }),
    );
    expect(rulesOf(findings)).toEqual([EVENT_NESTED_DATA_RULE]);
    expect(findings[0]?.message).toContain('expects scalar');
  });

  it('passes a Community deposit that indexes address and secondary identifier', () => {
    expect(
      validateEvent(
        event({
          topics: [symbol('deposit'), account(ALICE), symbol('USDC')],
          data: amount(50),
        }),
      ),
    ).toEqual([]);
  });

  it('requires a community event to index an address in topic 1', () => {
    const findings = validateEvent(
      event({ topics: [symbol('deposit'), text('alice')], data: amount(50) }),
    );
    expect(rulesOf(findings)).toEqual([EVENT_UNINDEXED_ADDRESS_RULE]);
    expect(findings[0]?.message).toContain('topic 1');
  });

  it('reports a community event with no address topic at all', () => {
    const findings = validateEvent(event({ topics: [symbol('deposit')], data: amount(50) }));
    expect(rulesOf(findings)).toEqual([EVENT_UNINDEXED_ADDRESS_RULE]);
  });

  it('reports a topic 2 that is not a usable secondary identifier', () => {
    const findings = validateEvent(
      event({
        topics: [symbol('deposit'), account(ALICE), xdr.ScVal.scvBool(true)],
        data: amount(50),
      }),
    );
    expect(rulesOf(findings)).toEqual([EVENT_SECONDARY_TOPIC_RULE]);
  });

  it('accepts a bytes secondary identifier', () => {
    expect(
      validateEvent(
        event({
          topics: [symbol('deposit'), account(ALICE), xdr.ScVal.scvBytes(Buffer.alloc(2))],
          data: amount(50),
        }),
      ),
    ).toEqual([]);
  });

  it('reports an event that carries its address only in the payload', () => {
    const findings = validateEvent(
      event({
        topics: [symbol('mint')],
        data: account(ALICE),
      }),
    );
    expect(rulesOf(findings)).toEqual([EVENT_UNINDEXED_ADDRESS_RULE, EVENT_UNINDEXED_ADDRESS_RULE]);
    expect(findings[1]?.message).toContain('only in its data payload');
  });

  it('reports data nested more than one container deep', () => {
    const findings = validateEvent(
      event({
        topics: [symbol('deposit'), account(ALICE)],
        data: xdr.ScVal.scvVec([xdr.ScVal.scvVec([amount(1)])]),
      }),
    );
    expect(rulesOf(findings)).toEqual([EVENT_NESTED_DATA_RULE]);
    expect(findings[0]?.message).toContain('2 levels deep');
  });
});

// ---------------------------------------------------------------------------
// Spec validation
// ---------------------------------------------------------------------------

describe('validateEventSpec', () => {
  const spec = (overrides: Partial<EventSpecDefinition> = {}): EventSpecDefinition => ({
    name: 'transfer',
    prefixTopics: ['transfer'],
    params: [
      { name: 'from', location: 'topic', type: 'scSpecTypeAddress', address: true },
      { name: 'amount', location: 'data', type: 'scSpecTypeI128', address: false },
    ],
    dataFormat: 'single',
    ...overrides,
  });

  it('passes a spec that names and indexes the event', () => {
    expect(validateEventSpec(spec())).toEqual([]);
  });

  it('reports a spec without its name as the first prefix topic', () => {
    expect(rulesOf(validateEventSpec(spec({ prefixTopics: [] })))).toEqual([
      EVENT_SPEC_MISSING_NAME_RULE,
    ]);
    expect(rulesOf(validateEventSpec(spec({ prefixTopics: ['other'] })))).toEqual([
      EVENT_SPEC_MISSING_NAME_RULE,
    ]);
  });

  it('reports a spec with no address parameter in its topic list', () => {
    expect(rulesOf(validateEventSpec(spec({ params: [] })))).toEqual([
      EVENT_SPEC_UNINDEXED_ADDRESS_RULE,
    ]);
  });

  it('turns spec findings into diagnostics with the contract id', () => {
    const diagnostics = validateEventSpecs(
      CONTRACT,
      [
        {
          name: 'transfer',
          prefixTopics: [],
          params: [],
          dataFormat: 'single',
        },
      ],
      { path: 'CURRENCIES[0].contract' },
    );
    expect(rulesOf(diagnostics)).toEqual([
      EVENT_SPEC_MISSING_NAME_RULE,
      EVENT_SPEC_UNINDEXED_ADDRESS_RULE,
    ]);
    expect(diagnostics[0]?.message).toContain(`Contract ${CONTRACT}`);
    expect(diagnostics[0]?.path).toBe('CURRENCIES[0].contract');
  });
});

// ---------------------------------------------------------------------------
// Spec and event parsing
// ---------------------------------------------------------------------------

describe('parseContractSpec', () => {
  it('reads events and function inputs from the spec section', () => {
    const spec = parseContractSpec(A_TOKEN_WASM);
    expect(spec?.events.map((entry) => entry.name)).toEqual(['transfer', 'mint']);
    expect(spec?.events[0]).toEqual({
      name: 'transfer',
      prefixTopics: ['transfer'],
      params: [
        { name: 'from', location: 'topic', type: 'scSpecTypeAddress', address: true },
        { name: 'to', location: 'topic', type: 'scSpecTypeAddress', address: true },
        { name: 'amount', location: 'data', type: 'scSpecTypeI128', address: false },
      ],
      dataFormat: 'single',
    });
    expect(spec?.functions.map((fn) => fn.name)).toEqual([
      'transfer',
      'mint',
      'balance',
      'upgrade',
    ]);
    expect(spec?.functions[0]?.inputs.map((input) => input.switch().name)).toEqual([
      'scSpecTypeAddress',
      'scSpecTypeAddress',
      'scSpecTypeI128',
    ]);
  });

  it('reads vec and map data formats', () => {
    const wasm = wasmWithSpec([
      eventSpec({ name: 'a', params: [], dataFormat: 'vec' }),
      eventSpec({ name: 'b', params: [], dataFormat: 'map' }),
    ]);
    expect(parseEventSpecs(wasm)?.map((entry) => entry.dataFormat)).toEqual(['vec', 'map']);
  });

  it('returns undefined for a non-WASM module or one without a spec', () => {
    expect(parseContractSpec(Buffer.from('not wasm'))).toBeUndefined();
    expect(
      parseContractSpec(Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00])),
    ).toBeUndefined();
  });

  it('skips non-custom and unrelated custom sections on the way to the spec', () => {
    const name = Buffer.from('other', 'utf8');
    const wasm = rawWasm([
      rawSection(1, Buffer.from([0x00])),
      rawSection(0, Buffer.concat([u32(name.length), name])),
      rawSection(
        0,
        Buffer.concat([
          u32(Buffer.byteLength('contractspecv0')),
          Buffer.from('contractspecv0'),
          eventSpec({ name: 'mint' }).toXDR(),
        ]),
      ),
    ]);
    expect(parseEventSpecs(wasm)?.map((spec) => spec.name)).toEqual(['mint']);
  });

  it('ignores spec entries that are not events or functions', () => {
    const wasm = wasmWithSpec([
      xdr.ScSpecEntry.scSpecEntryUdtStructV0(
        new xdr.ScSpecUdtStructV0({ doc: '', lib: '', name: 'Config', fields: [] }),
      ),
      eventSpec({ name: 'mint' }),
    ]);
    expect(parseEventSpecs(wasm)?.map((spec) => spec.name)).toEqual(['mint']);
  });

  it('returns undefined for an overlong section-size LEB128', () => {
    const wasm = rawWasm([Buffer.from([0x00, 0x80, 0x80, 0x80, 0x80, 0x80])]);
    expect(parseContractSpec(wasm)).toBeUndefined();
  });

  it('returns undefined when a section size runs past the module', () => {
    expect(parseContractSpec(rawWasm([Buffer.from([0x00])]))).toBeUndefined();
    expect(
      parseContractSpec(Buffer.concat([WASM_HEADER, Buffer.from([0x00]), u32(100)])),
    ).toBeUndefined();
  });

  it('returns undefined when the custom section name is truncated', () => {
    expect(parseContractSpec(rawWasm([rawSection(0, Buffer.from([0x80]))]))).toBeUndefined();
    expect(parseContractSpec(rawWasm([rawSection(0, Buffer.from([0x05, 0x61]))]))).toBeUndefined();
  });

  it('returns undefined when the spec payload is truncated mid-entry', () => {
    const entry = eventSpec({ name: 'transfer' }).toXDR();
    const payload = entry.subarray(0, entry.length - 6);
    const name = Buffer.from('contractspecv0', 'utf8');
    const content = Buffer.concat([u32(name.length), name, payload]);
    const wasm = rawWasm([rawSection(0, content)]);
    expect(parseContractSpec(wasm)).toBeUndefined();
  });
});

describe('parseContractEvent', () => {
  it('decodes the contract id, type, topics, and data', () => {
    const raw = eventXdr({
      topics: [symbol('transfer'), account(ALICE), account(BOB)],
      data: amount(5),
    });
    const record = parseContractEvent(raw);
    expect(record).toMatchObject({ contractId: CONTRACT, type: 'contract' });
    expect(record?.topics.map((topic) => topic.switch().name)).toEqual([
      'scvSymbol',
      'scvAddress',
      'scvAddress',
    ]);
    expect(record?.data.switch().name).toBe('scvI128');
  });

  it('omits the contract id for a system event', () => {
    expect(
      parseContractEvent(eventXdr({ topics: [symbol('fee')], data: amount(1), contractId: null })),
    ).toMatchObject({ type: 'contract' });
    expect(
      parseContractEvent(
        eventXdr({ topics: [symbol('fee')], data: amount(1), contractId: null, type: 'system' }),
      )?.contractId,
    ).toBeUndefined();
  });

  it('returns undefined for a value that is not ContractEvent XDR', () => {
    expect(parseContractEvent(undefined)).toBeUndefined();
    expect(parseContractEvent(42)).toBeUndefined();
    expect(parseContractEvent('not-base64-xdr')).toBeUndefined();
  });
});

describe('parseSimulatedEvents', () => {
  it('accepts base64 strings and { xdr } objects, skipping malformed entries', () => {
    const raw = eventXdr({ topics: [symbol('mint'), account(ALICE)], data: amount(3) });
    const events = parseSimulatedEvents([raw, { xdr: raw }, 'garbage', null, 7]);
    expect(events).toHaveLength(2);
    expect(events[0]?.contractId).toBe(CONTRACT);
  });

  it('returns an empty array for a non-array response', () => {
    expect(parseSimulatedEvents(undefined)).toEqual([]);
    expect(parseSimulatedEvents({ events: [] })).toEqual([]);
  });
});

describe('simulatedEventsOf', () => {
  it('reads top-level events and diagnostic events', () => {
    expect(simulatedEventsOf({ events: ['a'], diagnosticEvents: ['b'] })).toEqual(['a', 'b']);
  });

  it('reads events nested on results[] items', () => {
    expect(simulatedEventsOf({ results: [{ events: ['a'], diagnosticEvents: ['b'] }] })).toEqual([
      'a',
      'b',
    ]);
  });

  it('ignores a result with no events', () => {
    expect(simulatedEventsOf({ results: [null, 7, {}] })).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Simulation envelope construction
// ---------------------------------------------------------------------------

describe('simulationTargets', () => {
  const fn = (name: string): ContractFunctionSpec => ({ name, inputs: [] });

  it('prefers event-emitting entry points and excludes reads and upgrades', () => {
    const targets = simulationTargets([
      fn('balance'),
      fn('custom'),
      fn('mint'),
      fn('transfer'),
      fn('upgrade'),
    ]);
    expect(targets.map((target) => target.name)).toEqual(['mint', 'transfer', 'custom']);
  });

  it('honours the configured limit', () => {
    const targets = simulationTargets([fn('mint'), fn('transfer')], 1);
    expect(targets.map((target) => target.name)).toEqual(['mint']);
    expect(DEFAULT_MAX_SIMULATED_FUNCTIONS).toBe(6);
    expect(EVENT_EMITTING_FUNCTIONS.has('mint')).toBe(true);
  });
});

describe('buildEventSimulationTransaction', () => {
  it('builds an envelope with one argument per declared input', () => {
    const envelope = buildEventSimulationTransaction(
      CONTRACT,
      {
        name: 'transfer',
        inputs: [
          xdr.ScSpecTypeDef.scSpecTypeAddress(),
          xdr.ScSpecTypeDef.scSpecTypeAddress(),
          xdr.ScSpecTypeDef.scSpecTypeI128(),
        ],
      },
      { sourceAccount: ALICE },
    );
    const transaction = xdr.TransactionEnvelope.fromXDR(envelope, 'base64');
    const call = transaction
      .v1()
      .tx()
      .operations()[0]!
      .body()
      .invokeHostFunctionOp()
      .hostFunction()
      .invokeContract();
    expect(call.functionName().toString()).toBe('transfer');
    expect(call.args()).toHaveLength(3);
    expect(call.args().map((arg) => arg.switch().name)).toEqual([
      'scvAddress',
      'scvAddress',
      'scvI128',
    ]);
  });

  it('fills every supported SCVal type', () => {
    const types = [
      xdr.ScSpecTypeDef.scSpecTypeAddress(),
      xdr.ScSpecTypeDef.scSpecTypeBool(),
      xdr.ScSpecTypeDef.scSpecTypeU32(),
      xdr.ScSpecTypeDef.scSpecTypeI32(),
      xdr.ScSpecTypeDef.scSpecTypeU64(),
      xdr.ScSpecTypeDef.scSpecTypeI64(),
      xdr.ScSpecTypeDef.scSpecTypeU128(),
      xdr.ScSpecTypeDef.scSpecTypeI128(),
      xdr.ScSpecTypeDef.scSpecTypeSymbol(),
      xdr.ScSpecTypeDef.scSpecTypeString(),
      xdr.ScSpecTypeDef.scSpecTypeBytes(),
      xdr.ScSpecTypeDef.scSpecTypeVoid(),
    ];
    const envelope = buildEventSimulationTransaction(
      CONTRACT,
      { name: 'emit', inputs: types },
      { sourceAccount: ALICE },
    );
    const call = xdr.TransactionEnvelope.fromXDR(envelope, 'base64')
      .v1()
      .tx()
      .operations()[0]!
      .body()
      .invokeHostFunctionOp()
      .hostFunction()
      .invokeContract();
    expect(call.args().map((arg) => arg.switch().name)).toEqual([
      'scvAddress',
      'scvBool',
      'scvU32',
      'scvI32',
      'scvU64',
      'scvI64',
      'scvU128',
      'scvI128',
      'scvSymbol',
      'scvString',
      'scvBytes',
      'scvVoid',
    ]);
  });

  it('returns an empty string for an invalid contract address', () => {
    expect(buildEventSimulationTransaction('not-a-contract', { name: 'mint', inputs: [] })).toBe(
      '',
    );
  });
});

// ---------------------------------------------------------------------------
// Verifier behavior
// ---------------------------------------------------------------------------

describe('validateContractEvents', () => {
  it('validates only events emitted by the audited contract', () => {
    const diagnostics = validateContractEvents(
      CONTRACT,
      [
        event({ topics: [symbol('transfer'), account(ALICE)], data: amount(1) }),
        event({
          contractId: OTHER_CONTRACT,
          topics: [],
          data: amount(1),
        }),
        event({ type: 'system', topics: [], data: amount(1) }),
      ],
      [],
    );
    expect(rulesOf(diagnostics)).toEqual([EVENT_UNINDEXED_ADDRESS_RULE]);
  });

  it('reports an emission the spec does not declare', () => {
    const diagnostics = validateContractEvents(
      CONTRACT,
      [event({ topics: [symbol('deposit'), account(ALICE)], data: amount(1) })],
      [
        {
          name: 'transfer',
          prefixTopics: ['transfer'],
          params: [{ name: 'from', location: 'topic', type: 'scSpecTypeAddress', address: true }],
          dataFormat: 'single',
        },
      ],
    );
    expect(rulesOf(diagnostics)).toEqual([EVENT_UNDECLARED_RULE]);
    expect(diagnostics[0]?.message).toContain('`deposit`');
  });

  it('accepts a declared Community event', () => {
    const diagnostics = validateContractEvents(
      CONTRACT,
      [event({ topics: [symbol('deposit'), account(ALICE)], data: amount(1) })],
      [
        {
          name: 'deposit',
          prefixTopics: ['deposit'],
          params: [{ name: 'to', location: 'topic', type: 'scSpecTypeAddress', address: true }],
          dataFormat: 'single',
        },
      ],
    );
    expect(diagnostics).toEqual([]);
  });

  it('honours severity overrides', () => {
    const events = [event({ topics: [], data: amount(1) })];
    expect(validateContractEvents(CONTRACT, events)).toHaveLength(1);
    expect(
      validateContractEvents(CONTRACT, events, [], {
        rules: { [EVENT_MISSING_TOPICS_RULE]: 'off' },
      }),
    ).toEqual([]);
    expect(
      validateContractEvents(CONTRACT, events, [], {
        rules: { [EVENT_MISSING_TOPICS_RULE]: 'warning' },
      })[0],
    ).toMatchObject({ rule: EVENT_MISSING_TOPICS_RULE, severity: 'warning' });
  });

  it('attaches the configured path and the events spec link', () => {
    const [diagnostic] = validateContractEvents(
      CONTRACT,
      [event({ topics: [], data: amount(1) })],
      [],
      {
        path: 'CURRENCIES[0].contract',
      },
    );
    expect(diagnostic?.path).toBe('CURRENCIES[0].contract');
    expect(diagnostic?.helpUri).toContain('contract-development/events');
  });
});

describe('EventSchemaVerifier', () => {
  const verifier = new EventSchemaVerifier({ rpcUrl: RPC });

  it('diagnoses the spec statically', () => {
    const wasm = wasmWithSpec([
      eventSpec({
        name: 'custom',
        prefixTopics: [],
        params: [{ name: 'amount', type: xdr.ScSpecTypeDef.scSpecTypeI128() }],
      }),
    ]);
    const diagnostics = verifier.verifySpec(CONTRACT, wasm);
    expect(rulesOf(diagnostics)).toEqual([
      EVENT_SPEC_MISSING_NAME_RULE,
      EVENT_SPEC_UNINDEXED_ADDRESS_RULE,
    ]);
  });

  it('returns no diagnostics when the spec cannot be read', () => {
    expect(verifier.verifySpec(CONTRACT, Buffer.from('nope'))).toEqual([]);
  });

  it('parses simulated events through the public method', () => {
    const raw = eventXdr({ topics: [], data: amount(1) });
    expect(verifier.parseEvents([raw])).toHaveLength(1);
  });

  it('validates events through the public method', () => {
    const diagnostics = verifier.verifyEvents(CONTRACT, [event({ topics: [], data: amount(1) })]);
    expect(rulesOf(diagnostics)).toEqual([EVENT_MISSING_TOPICS_RULE]);
  });

  it('simulates a contract through the public method', async () => {
    const events = [eventXdr({ topics: [symbol('mint'), account(ALICE)], data: amount(1) })];
    const rpc = rpcMock({ events });
    const simulated = await verifier.simulate(CONTRACT, A_TOKEN_WASM, RPC, rpc.fetchImpl);
    expect(simulated).toHaveLength(1);
    expect(await verifier.simulate(CONTRACT, Buffer.from('nope'), RPC, rpc.fetchImpl)).toEqual([]);
  });
});

describe('verifyWasm', () => {
  it('audits the spec and the simulated emissions', async () => {
    const events = [eventXdr({ topics: [symbol('transfer'), account(ALICE)], data: amount(1) })];
    const rpc = rpcMock({ events });
    const verifier = new EventSchemaVerifier({ rpcUrl: RPC });
    const diagnostics = await verifier.verifyWasm(CONTRACT, A_TOKEN_WASM, rpc.fetchImpl);

    expect(rulesOf(diagnostics)).toEqual([EVENT_UNINDEXED_ADDRESS_RULE]);
    // `balance` and `upgrade` are not simulated; `mint` and `transfer` are.
    expect(rpc.simulatedFunctions()).toEqual(['transfer', 'mint']);
  });

  it('reads events the RPC nests under results[]', async () => {
    const events = [eventXdr({ topics: [], data: amount(1) })];
    const rpc = rpcMock({ events, nestedEvents: true });
    const verifier = new EventSchemaVerifier({ rpcUrl: RPC });
    expect(rulesOf(await verifier.verifyWasm(CONTRACT, A_TOKEN_WASM, rpc.fetchImpl))).toEqual([
      EVENT_MISSING_TOPICS_RULE,
    ]);
  });

  it('stops after the spec when specOnly is set', async () => {
    const rpc = rpcMock({ events: [eventXdr({ topics: [], data: amount(1) })] });
    const verifier = new EventSchemaVerifier({ rpcUrl: RPC, specOnly: true });
    expect(await verifier.verifyWasm(CONTRACT, A_TOKEN_WASM, rpc.fetchImpl)).toEqual([]);
    expect(rpc.simulatedFunctions()).toEqual([]);
  });

  it('stays silent when no RPC endpoint can be derived', async () => {
    const verifier = new EventSchemaVerifier({ specOnly: false });
    expect(await verifier.verifyWasm(CONTRACT, A_TOKEN_WASM)).toEqual([]);
  });

  it('stays silent when the simulation RPC fails', async () => {
    const verifier = new EventSchemaVerifier({ rpcUrl: RPC });
    const down = (async () => new Response('nope', { status: 503 })) as unknown as typeof fetch;
    expect(await verifier.verifyWasm(CONTRACT, A_TOKEN_WASM, down)).toEqual([]);

    const badJson = (async () =>
      new Response('not json', { status: 200 })) as unknown as typeof fetch;
    expect(await verifier.verifyWasm(CONTRACT, A_TOKEN_WASM, badJson)).toEqual([]);
  });

  it('skips an entry point whose envelope cannot be built', async () => {
    const rpc = rpcMock({ events: [eventXdr({ topics: [], data: amount(1) })] });
    const verifier = new EventSchemaVerifier({ rpcUrl: RPC });
    expect(await verifier.verifyWasm('not-a-contract', A_TOKEN_WASM, rpc.fetchImpl)).toEqual([]);
    expect(rpc.simulatedFunctions()).toEqual([]);
  });

  it('skips non-XDR and undecodable event entries', async () => {
    const rpc = rpcMock({ events: [42, 'garbage', eventXdr({ topics: [], data: amount(1) })] });
    const verifier = new EventSchemaVerifier({ rpcUrl: RPC });
    expect(rulesOf(await verifier.verifyWasm(CONTRACT, A_TOKEN_WASM, rpc.fetchImpl))).toEqual([
      EVENT_MISSING_TOPICS_RULE,
    ]);
  });

  it('simulates nothing when the entry-point budget is zero', async () => {
    const rpc = rpcMock({ events: [eventXdr({ topics: [], data: amount(1) })] });
    const verifier = new EventSchemaVerifier({ rpcUrl: RPC, maxSimulatedFunctions: 0 });
    expect(await verifier.verifyWasm(CONTRACT, A_TOKEN_WASM, rpc.fetchImpl)).toEqual([]);
    expect(rpc.simulatedFunctions()).toEqual([]);
  });
});

describe('fetchEventContractWasm', () => {
  const respond = (body: unknown): typeof fetch =>
    (async () =>
      new Response(typeof body === 'string' ? body : JSON.stringify(body), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })) as unknown as typeof fetch;

  it('returns undefined when the RPC is unavailable', async () => {
    const down = (async () => new Response('nope', { status: 503 })) as unknown as typeof fetch;
    expect(await fetchEventContractWasm(CONTRACT, RPC, down)).toBeUndefined();
  });

  it('returns undefined for malformed JSON or a missing entries array', async () => {
    expect(await fetchEventContractWasm(CONTRACT, RPC, respond('not json'))).toBeUndefined();
    expect(await fetchEventContractWasm(CONTRACT, RPC, respond({ result: {} }))).toBeUndefined();
  });

  it('returns undefined when the entry cannot be decoded', async () => {
    const fetchImpl = respond({ result: { entries: [{ xdr: 'AAAA' }] } });
    expect(await fetchEventContractWasm(CONTRACT, RPC, fetchImpl)).toBeUndefined();
  });

  it('returns undefined when the code entry cannot be decoded', async () => {
    let calls = 0;
    const fetchImpl = (async () => {
      calls++;
      const entries = calls === 1 ? [{ xdr: instanceEntryXdr() }] : [{ xdr: 'AAAA' }];
      return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { entries } }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as unknown as typeof fetch;
    expect(await fetchEventContractWasm(CONTRACT, RPC, fetchImpl)).toBeUndefined();
    expect(calls).toBe(2);
  });

  it('returns undefined for a non-WASM or missing code entry', async () => {
    const instanceOnly = respond({
      result: { entries: [{ xdr: instanceEntryXdr() }] },
    });
    // The instance names a WASM hash, but the follow-up lookup also returns the
    // contract-data entry, which is not a contract-code entry.
    expect(await fetchEventContractWasm(CONTRACT, RPC, instanceOnly)).toBeUndefined();

    const native = (async () => {
      const xdrValue = xdr.LedgerEntryData.contractData(
        new xdr.ContractDataEntry({
          ext: xdr.ExtensionPoint.fromXDR(Buffer.alloc(4), 'raw'),
          contract: new Address(CONTRACT).toScAddress(),
          key: xdr.ScVal.scvLedgerKeyContractInstance(),
          durability: xdr.ContractDataDurability.persistent(),
          val: xdr.ScVal.scvContractInstance(
            new xdr.ScContractInstance({
              executable: xdr.ContractExecutable.contractExecutableStellarAsset(),
              storage: [],
            }),
          ),
        }),
      ).toXDR('base64');
      return new Response(
        JSON.stringify({ jsonrpc: '2.0', id: 1, result: { entries: [{ xdr: xdrValue }] } }),
        {
          status: 200,
          headers: { 'content-type': 'application/json' },
        },
      );
    }) as unknown as typeof fetch;
    expect(await fetchEventContractWasm(CONTRACT, RPC, native)).toBeUndefined();
  });
});

describe('verifyContract', () => {
  it('fetches the deployed WASM and audits it', async () => {
    const events = [eventXdr({ topics: [], data: amount(1) })];
    const rpc = rpcMock({ wasm: A_TOKEN_WASM, events });
    const verifier = new EventSchemaVerifier({ rpcUrl: RPC });
    expect(rulesOf(await verifier.verifyContract(CONTRACT, rpc.fetchImpl))).toEqual([
      EVENT_MISSING_TOPICS_RULE,
    ]);
  });

  it('does not judge a contract whose WASM cannot be fetched', async () => {
    const rpc = rpcMock({ wasm: undefined });
    const verifier = new EventSchemaVerifier({ rpcUrl: RPC });
    expect(await verifier.verifyContract(CONTRACT, rpc.fetchImpl)).toEqual([]);
  });

  it('does not fetch anything without an RPC endpoint', async () => {
    let called = false;
    const fetchImpl = (async () => {
      called = true;
      return new Response('{}');
    }) as unknown as typeof fetch;
    const verifier = new EventSchemaVerifier();
    expect(await verifier.verifyContract(CONTRACT, fetchImpl)).toEqual([]);
    expect(called).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// stellar.toml integration
// ---------------------------------------------------------------------------

const TOML = [
  `NETWORK_PASSPHRASE = "${TESTNET_PASSPHRASE}"`,
  '',
  '[[CURRENCIES]]',
  'code = "USDC"',
  `contract = "${CONTRACT}"`,
].join('\n');

describe('auditTomlEvents', () => {
  it('audits the contracts advertised in stellar.toml', async () => {
    const doc = parse(TOML) as Record<string, unknown>;
    const events = [eventXdr({ topics: [], data: amount(1) })];
    const rpc = rpcMock({ wasm: A_TOKEN_WASM, events });

    expect(rulesOf(await auditTomlEvents(doc, rpc.fetchImpl))).toEqual([EVENT_MISSING_TOPICS_RULE]);
  });

  it('uses an explicit RPC endpoint over the passphrase', async () => {
    const doc = parse(TOML) as Record<string, unknown>;
    const rpc = rpcMock({ wasm: A_TOKEN_WASM });
    expect(await auditTomlEvents(doc, rpc.fetchImpl, { rpcUrl: RPC })).toEqual([]);
  });

  it('returns nothing when the network cannot be derived', async () => {
    const doc = parse(TOML) as Record<string, unknown>;
    const noPassphrase = { ...doc, NETWORK_PASSPHRASE: undefined };
    expect(await auditTomlEvents(noPassphrase)).toEqual([]);
  });

  it('returns nothing when the file advertises no contract', async () => {
    const doc = parse('NETWORK_PASSPHRASE = "' + TESTNET_PASSPHRASE + '"') as Record<
      string,
      unknown
    >;
    expect(await auditTomlEvents(doc, undefined, { rpcUrl: RPC })).toEqual([]);
  });

  it('also audits WEB_AUTH_CONTRACT_ID', async () => {
    const doc = parse(
      [`NETWORK_PASSPHRASE = "${TESTNET_PASSPHRASE}"`, `WEB_AUTH_CONTRACT_ID = "${CONTRACT}"`].join(
        '\n',
      ),
    ) as Record<string, unknown>;
    const events = [eventXdr({ topics: [], data: amount(1) })];
    const rpc = rpcMock({ wasm: A_TOKEN_WASM, events });

    const diagnostics = await auditTomlEvents(doc, rpc.fetchImpl);
    expect(rulesOf(diagnostics)).toEqual([EVENT_MISSING_TOPICS_RULE]);
    expect(diagnostics[0]?.path).toBe('WEB_AUTH_CONTRACT_ID');
  });
});

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

describe('rule registration', () => {
  it('registers every event rule with the Soroban rule set', () => {
    for (const rule of eventRules) {
      expect(sorobanRuleIds).toContain(rule.id);
      expect(eventVerifierRuleIds).toContain(rule.id);
    }
    expect(eventVerifierRules).toBe(eventRules);
  });

  it('marks every event rule as a network rule', () => {
    expect(eventRules.every((rule) => rule.category === 'network')).toBe(true);
    expect(eventRules.map((rule) => rule.id)).toContain(EVENT_NESTED_DATA_RULE);
  });
});
