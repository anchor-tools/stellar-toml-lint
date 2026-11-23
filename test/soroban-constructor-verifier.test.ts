import { describe, expect, it } from 'vitest';
import { Address, xdr } from '@stellar/stellar-base';
import { parse } from 'smol-toml';
import {
  CONSTRUCTOR_ARGUMENT_MISMATCH_RULE,
  CONSTRUCTOR_NO_REPLAY_PROTECTION_RULE,
  CONSTRUCTOR_UNINITIALIZED_RULE,
  ConstructorInvariantVerifier,
  auditConstructorInvariants,
  auditTomlConstructorInvariants,
  constructorArgumentTypeOf,
  expectedConstructorArgs,
  findInitializationSignature,
  initializationMarkerKeys,
  initializationStateOf,
  parseContractSpecFunctions,
  persistentInitializationMarker,
} from '../src/soroban/constructorVerifier.js';
import { persistentStorageKey } from '../src/soroban/ttlAuditor.js';
import { contractCodeKey, contractDataInstanceKey, sorobanRuleIds } from '../src/soroban.js';

const CONTRACT = 'CACTZSQPCQSSZ5YG3PI3N7WO6JEERKEUHTPILKB4MBANF2K4D2UHKDDU';
const ADMIN_ACCOUNT = 'GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS';
const RPC = 'https://soroban-testnet.stellar.org';
const NETWORK = 'Test SDF Network ; September 2015';
const LATEST = 1_000_000;
const WASM_HASH = Buffer.alloc(32, 7);

type FixtureType = 'integer' | 'address' | 'bool' | 'string';

const instanceKey = contractDataInstanceKey(CONTRACT);
const codeKey = contractCodeKey(WASM_HASH);

// ---------------------------------------------------------------------------
// WASM fixtures
// ---------------------------------------------------------------------------

/** Unsigned LEB128, the length and size encoding WASM sections use. */
function encodeU32(value: number): Buffer {
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

function specType(type: FixtureType): xdr.ScSpecTypeDef {
  switch (type) {
    case 'integer':
      return xdr.ScSpecTypeDef.scSpecTypeU32();
    case 'address':
      return xdr.ScSpecTypeDef.scSpecTypeAddress();
    case 'bool':
      return xdr.ScSpecTypeDef.scSpecTypeBool();
    case 'string':
      return xdr.ScSpecTypeDef.scSpecTypeString();
  }
}

function specFunction(
  name: string,
  inputs: { name: string; type: FixtureType }[] = [],
): xdr.ScSpecEntry {
  return xdr.ScSpecEntry.scSpecEntryFunctionV0(
    new xdr.ScSpecFunctionV0({
      doc: '',
      name,
      inputs: inputs.map(
        (input) =>
          new xdr.ScSpecFunctionInputV0({
            doc: '',
            name: input.name,
            type: specType(input.type),
          }),
      ),
      outputs: [],
    }),
  );
}

/** A minimal WASM module whose `contractspecv0` section declares the functions. */
function wasmWithSpec(functions: xdr.ScSpecEntry[]): Buffer {
  const payload = Buffer.concat(functions.map((entry) => entry.toXDR()));
  const name = Buffer.from('contractspecv0', 'utf8');
  const content = Buffer.concat([encodeU32(name.length), name, payload]);
  const header = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
  return Buffer.concat([header, Buffer.from([0x00]), encodeU32(content.length), content]);
}

function wasmWithoutSpec(): Buffer {
  return Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
}

function codeEntryXdr(wasm: Buffer): string {
  return xdr.LedgerEntryData.contractCode(
    new xdr.ContractCodeEntry({
      ext: xdr.ContractCodeEntryExt.fromXDR(Buffer.alloc(4), 'raw'),
      hash: WASM_HASH,
      code: wasm,
    }),
  ).toXDR('base64');
}

interface StorageFixture {
  key: xdr.ScVal;
  val: xdr.ScVal;
}

function instanceEntryXdr(storage: StorageFixture[] = []): string {
  return xdr.LedgerEntryData.contractData(
    new xdr.ContractDataEntry({
      ext: xdr.ExtensionPoint.fromXDR(Buffer.alloc(4), 'raw'),
      contract: new Address(CONTRACT).toScAddress(),
      key: xdr.ScVal.scvLedgerKeyContractInstance(),
      durability: xdr.ContractDataDurability.persistent(),
      val: xdr.ScVal.scvContractInstance(
        new xdr.ScContractInstance({
          executable: xdr.ContractExecutable.contractExecutableWasm(WASM_HASH),
          storage: storage.map((item) => new xdr.ScMapEntry(item)),
        }),
      ),
    }),
  ).toXDR('base64');
}

function persistentEntryXdr(key: xdr.ScVal, val: xdr.ScVal): string {
  return xdr.LedgerEntryData.contractData(
    new xdr.ContractDataEntry({
      ext: xdr.ExtensionPoint.fromXDR(Buffer.alloc(4), 'raw'),
      contract: new Address(CONTRACT).toScAddress(),
      key,
      durability: xdr.ContractDataDurability.persistent(),
      val,
    }),
  ).toXDR('base64');
}

// ---------------------------------------------------------------------------
// RPC fixtures
// ---------------------------------------------------------------------------

interface EntryMock {
  xdr?: string;
  liveUntilLedgerSeq?: number;
}

/** An RPC that answers `getLedgerEntries` from a key → entry map. */
function rpcWith(entries: Map<string, EntryMock>): typeof fetch {
  return (async (_url: string | URL | globalThis.Request, init?: RequestInit) => {
    const request = JSON.parse(String(init?.body)) as { params: { keys: string[] } };
    const found = request.params.keys
      .filter((key) => entries.has(key))
      .map((key) => ({ key, ...entries.get(key) }));
    return new Response(
      JSON.stringify({ jsonrpc: '2.0', id: 1, result: { latestLedger: LATEST, entries: found } }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );
  }) as unknown as typeof fetch;
}

function entriesFor(
  wasm: Buffer,
  instanceStorage: StorageFixture[] = [],
  extra: [string, EntryMock][] = [],
): Map<string, EntryMock> {
  const entries = new Map<string, EntryMock>();
  entries.set(instanceKey, {
    xdr: instanceEntryXdr(instanceStorage),
    liveUntilLedgerSeq: LATEST + 600_000,
  });
  entries.set(codeKey, { xdr: codeEntryXdr(wasm), liveUntilLedgerSeq: LATEST + 600_000 });
  for (const [key, entry] of extra) entries.set(key, entry);
  return entries;
}

function doc(options: { displayDecimals?: number } = {}): Record<string, unknown> {
  const lines = [
    `NETWORK_PASSPHRASE = "${NETWORK}"`,
    '[[CURRENCIES]]',
    'code = "USDC"',
    `contract = "${CONTRACT}"`,
  ];
  if (options.displayDecimals !== undefined) {
    lines.push(`display_decimals = ${options.displayDecimals}`);
  }
  return parse(lines.join('\n')) as Record<string, unknown>;
}

const rulesOf = (diagnostics: { rule: string }[]): string[] =>
  diagnostics.map((diagnostic) => diagnostic.rule);

const uninitializedKey = persistentStorageKey(CONTRACT, xdr.ScVal.scvSymbol('initialized'));

// ---------------------------------------------------------------------------
// Spec parsing
// ---------------------------------------------------------------------------

describe('parseContractSpecFunctions', () => {
  it('reads parameter names and type categories out of the spec section', () => {
    const wasm = wasmWithSpec([
      specFunction('__constructor', [
        { name: 'admin', type: 'address' },
        { name: 'decimals', type: 'integer' },
      ]),
      specFunction('transfer', [
        { name: 'to', type: 'address' },
        { name: 'amount', type: 'integer' },
      ]),
    ]);

    expect(parseContractSpecFunctions(wasm)).toEqual([
      {
        name: '__constructor',
        inputs: [
          { name: 'admin', type: 'address', specType: 'scSpecTypeAddress' },
          { name: 'decimals', type: 'integer', specType: 'scSpecTypeU32' },
        ],
        outputs: [],
      },
      {
        name: 'transfer',
        inputs: [
          { name: 'to', type: 'address', specType: 'scSpecTypeAddress' },
          { name: 'amount', type: 'integer', specType: 'scSpecTypeU32' },
        ],
        outputs: [],
      },
    ]);
  });

  it('returns undefined when the module has no spec section', () => {
    expect(parseContractSpecFunctions(wasmWithoutSpec())).toBeUndefined();
  });

  it('classifies integer and address spec types', () => {
    expect(constructorArgumentTypeOf(xdr.ScSpecTypeDef.scSpecTypeI128())).toBe('integer');
    expect(constructorArgumentTypeOf(xdr.ScSpecTypeDef.scSpecTypeAddress())).toBe('address');
    expect(constructorArgumentTypeOf(xdr.ScSpecTypeDef.scSpecTypeSymbol())).toBe('symbol');
    expect(constructorArgumentTypeOf(xdr.ScSpecTypeDef.scSpecTypeVal())).toBe('any');
  });
});

describe('findInitializationSignature', () => {
  const signature = (name: string) => ({ name, inputs: [], outputs: [] });

  it('prefers the Protocol 23 constructor over a custom initializer', () => {
    expect(
      findInitializationSignature([signature('initialize'), signature('__constructor')]),
    ).toMatchObject({ strategy: 'constructor', functionName: '__constructor' });
  });

  it('recognizes initialize and init initializers', () => {
    expect(findInitializationSignature([signature('initialize')])).toMatchObject({
      strategy: 'initializer',
      functionName: 'initialize',
    });
    expect(findInitializationSignature([signature('init')])).toMatchObject({
      strategy: 'initializer',
      functionName: 'init',
    });
  });

  it('returns undefined when the contract has no initialization entry point', () => {
    expect(findInitializationSignature([signature('transfer')])).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Storage parsing
// ---------------------------------------------------------------------------

describe('initializationStateOf', () => {
  it('finds initialization markers and their boolean values', () => {
    const state = initializationStateOf(
      instanceEntryXdr([
        { key: xdr.ScVal.scvSymbol('initialized'), val: xdr.ScVal.scvBool(true) },
        {
          key: xdr.ScVal.scvString('admin'),
          val: xdr.ScVal.scvAddress(new Address(ADMIN_ACCOUNT).toScAddress()),
        },
      ]),
    );

    expect(state.storageEntries).toBe(2);
    expect(state.storageKeys).toEqual(['initialized', 'admin']);
    expect(state.markers).toEqual([
      { name: 'initialized', source: 'instance', valueType: 'scvBool', booleanValue: true },
    ]);
  });

  it('returns empty state for malformed or non-instance entries', () => {
    expect(initializationStateOf('not-xdr')).toEqual({
      storageEntries: 0,
      storageKeys: [],
      markers: [],
    });
    expect(initializationStateOf(undefined)).toEqual({
      storageEntries: 0,
      storageKeys: [],
      markers: [],
    });
  });
});

describe('persistentInitializationMarker', () => {
  it('reads a boolean flag out of a persistent entry', () => {
    expect(
      persistentInitializationMarker(
        'initialized',
        persistentEntryXdr(xdr.ScVal.scvSymbol('initialized'), xdr.ScVal.scvBool(true)),
      ),
    ).toEqual({
      name: 'initialized',
      source: 'persistent',
      valueType: 'scvBool',
      booleanValue: true,
    });
  });

  it('reads non-boolean initialization state', () => {
    expect(
      persistentInitializationMarker(
        'initialized',
        persistentEntryXdr(
          xdr.ScVal.scvSymbol('initialized'),
          xdr.ScVal.scvAddress(new Address(ADMIN_ACCOUNT).toScAddress()),
        ),
      ),
    ).toEqual({ name: 'initialized', source: 'persistent', valueType: 'scvAddress' });
  });

  it('returns undefined for malformed entries', () => {
    expect(persistentInitializationMarker('initialized', 'nope')).toBeUndefined();
  });
});

describe('initializationMarkerKeys', () => {
  it('builds symbol and string persistent keys for every marker name', () => {
    const keys = initializationMarkerKeys(CONTRACT);
    expect(keys).toContainEqual({ key: uninitializedKey, name: 'initialized' });
    expect(keys).toHaveLength(10);
    expect(keys.every((candidate) => candidate.key.length > 0)).toBe(true);
  });
});

describe('expectedConstructorArgs', () => {
  it('derives an integer decimals expectation from display_decimals', () => {
    expect(expectedConstructorArgs(doc({ displayDecimals: 7 }), CONTRACT)).toEqual([
      {
        names: ['decimals', 'display_decimals', 'decimal_places'],
        type: 'integer',
        path: 'CURRENCIES[0].display_decimals',
      },
    ]);
  });

  it('ignores currencies for other contracts and files without decimals', () => {
    expect(expectedConstructorArgs(doc({ displayDecimals: 7 }), 'COTHER')).toEqual([]);
    expect(expectedConstructorArgs(doc(), CONTRACT)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

describe('auditConstructorInvariants', () => {
  it('is silent for a constructor-protected contract whose signature matches the file', async () => {
    const wasm = wasmWithSpec([
      specFunction('__constructor', [
        { name: 'admin', type: 'address' },
        { name: 'decimals', type: 'integer' },
      ]),
    ]);

    const diagnostics = await auditConstructorInvariants(
      CONTRACT,
      doc({ displayDecimals: 7 }),
      RPC,
      rpcWith(entriesFor(wasm)),
    );
    expect(diagnostics).toEqual([]);
  });

  it('errors for a custom initializer contract with no initialization state', async () => {
    const wasm = wasmWithSpec([
      specFunction('initialize', [{ name: 'decimals', type: 'integer' }]),
    ]);

    const diagnostics = await auditConstructorInvariants(
      CONTRACT,
      doc({ displayDecimals: 7 }),
      RPC,
      rpcWith(entriesFor(wasm)),
    );

    expect(rulesOf(diagnostics)).toEqual([CONSTRUCTOR_UNINITIALIZED_RULE]);
    expect(diagnostics[0]).toMatchObject({
      severity: 'error',
      category: 'network',
      path: 'CURRENCIES.contract',
    });
    expect(diagnostics[0]?.message).toContain('front-run');
  });

  it('is silent when a single-use boolean flag records completed initialization', async () => {
    const wasm = wasmWithSpec([
      specFunction('initialize', [{ name: 'decimals', type: 'integer' }]),
    ]);

    const diagnostics = await auditConstructorInvariants(
      CONTRACT,
      doc({ displayDecimals: 7 }),
      RPC,
      rpcWith(
        entriesFor(wasm, [
          { key: xdr.ScVal.scvSymbol('initialized'), val: xdr.ScVal.scvBool(true) },
        ]),
      ),
    );
    expect(diagnostics).toEqual([]);
  });

  it('recognizes a persistent boolean initialization flag', async () => {
    const wasm = wasmWithSpec([specFunction('init', [{ name: 'owner', type: 'address' }])]);

    const diagnostics = await auditConstructorInvariants(
      CONTRACT,
      doc(),
      RPC,
      rpcWith(
        entriesFor(
          wasm,
          [],
          [
            [
              uninitializedKey,
              {
                xdr: persistentEntryXdr(
                  xdr.ScVal.scvSymbol('initialized'),
                  xdr.ScVal.scvBool(true),
                ),
              },
            ],
          ],
        ),
      ),
    );
    expect(diagnostics).toEqual([]);
  });

  it('errors when the boolean flag is still false', async () => {
    const wasm = wasmWithSpec([specFunction('initialize')]);

    const diagnostics = await auditConstructorInvariants(
      CONTRACT,
      doc(),
      RPC,
      rpcWith(
        entriesFor(wasm, [
          { key: xdr.ScVal.scvSymbol('initialized'), val: xdr.ScVal.scvBool(false) },
        ]),
      ),
    );

    expect(rulesOf(diagnostics)).toEqual([CONSTRUCTOR_UNINITIALIZED_RULE]);
  });

  it('warns when state exists but no boolean replay-protection flag does', async () => {
    const wasm = wasmWithSpec([specFunction('initialize', [{ name: 'admin', type: 'address' }])]);

    const diagnostics = await auditConstructorInvariants(
      CONTRACT,
      doc(),
      RPC,
      rpcWith(
        entriesFor(wasm, [
          {
            key: xdr.ScVal.scvSymbol('admin'),
            val: xdr.ScVal.scvAddress(new Address(ADMIN_ACCOUNT).toScAddress()),
          },
        ]),
      ),
    );

    expect(rulesOf(diagnostics)).toEqual([CONSTRUCTOR_NO_REPLAY_PROTECTION_RULE]);
    expect(diagnostics[0]).toMatchObject({ severity: 'warning', category: 'network' });
    expect(diagnostics[0]?.message).toContain('admin');
  });

  it('errors when the constructor omits a decimal parameter the file declares', async () => {
    const wasm = wasmWithSpec([
      specFunction('__constructor', [{ name: 'admin', type: 'address' }]),
    ]);

    const diagnostics = await auditConstructorInvariants(
      CONTRACT,
      doc({ displayDecimals: 7 }),
      RPC,
      rpcWith(entriesFor(wasm)),
    );

    expect(rulesOf(diagnostics)).toEqual([CONSTRUCTOR_ARGUMENT_MISMATCH_RULE]);
    expect(diagnostics[0]?.message).toContain('decimals');
    expect(diagnostics[0]?.path).toBe('CURRENCIES[0].display_decimals');
  });

  it('errors when a declared parameter has the wrong type', async () => {
    const wasm = wasmWithSpec([
      specFunction('__constructor', [{ name: 'decimals', type: 'string' }]),
    ]);

    const diagnostics = await auditConstructorInvariants(
      CONTRACT,
      doc({ displayDecimals: 7 }),
      RPC,
      rpcWith(entriesFor(wasm)),
    );

    expect(rulesOf(diagnostics)).toEqual([CONSTRUCTOR_ARGUMENT_MISMATCH_RULE]);
    expect(diagnostics[0]?.message).toContain('scSpecTypeString');
  });

  it('checks caller-supplied admin and governance expectations', async () => {
    const wasm = wasmWithSpec([
      specFunction('__constructor', [
        { name: 'admin', type: 'address' },
        { name: 'quorum', type: 'integer' },
      ]),
    ]);

    const diagnostics = await auditConstructorInvariants(
      CONTRACT,
      doc(),
      RPC,
      rpcWith(entriesFor(wasm)),
      {
        constructorArgs: [
          { names: ['admin', 'owner'], type: 'address' },
          { names: ['quorum', 'threshold'], type: 'integer' },
        ],
      },
    );
    expect(diagnostics).toEqual([]);
  });

  it('reports a missing caller-supplied admin expectation', async () => {
    const wasm = wasmWithSpec([specFunction('__constructor')]);

    const diagnostics = await auditConstructorInvariants(
      CONTRACT,
      doc(),
      RPC,
      rpcWith(entriesFor(wasm)),
      { constructorArgs: [{ names: ['admin', 'owner'], type: 'address' }] },
    );

    expect(rulesOf(diagnostics)).toEqual([CONSTRUCTOR_ARGUMENT_MISMATCH_RULE]);
    expect(diagnostics[0]?.message).toContain('"admin"');
  });

  it('is silent for a contract with no initialization entry point', async () => {
    const wasm = wasmWithSpec([specFunction('transfer', [{ name: 'to', type: 'address' }])]);

    expect(
      await auditConstructorInvariants(CONTRACT, doc(), RPC, rpcWith(entriesFor(wasm))),
    ).toEqual([]);
  });

  it('is silent when the RPC is unreachable or the instance is missing', async () => {
    const down = (async () => {
      throw new Error('timeout');
    }) as unknown as typeof fetch;
    expect(await auditConstructorInvariants(CONTRACT, doc(), RPC, down)).toEqual([]);

    const empty = new Map<string, EntryMock>();
    expect(await auditConstructorInvariants(CONTRACT, doc(), RPC, rpcWith(empty))).toEqual([]);
  });

  it('is silent when the WASM has no readable spec', async () => {
    expect(
      await auditConstructorInvariants(
        CONTRACT,
        doc(),
        RPC,
        rpcWith(entriesFor(wasmWithoutSpec())),
      ),
    ).toEqual([]);
  });

  it('honours --off and --warn overrides', async () => {
    const wasm = wasmWithSpec([specFunction('initialize')]);
    const entries = () => rpcWith(entriesFor(wasm));

    const off = await auditConstructorInvariants(CONTRACT, doc(), RPC, entries(), {
      rules: { [CONSTRUCTOR_UNINITIALIZED_RULE]: 'off' },
    });
    expect(off).toEqual([]);

    const warn = await auditConstructorInvariants(CONTRACT, doc(), RPC, entries(), {
      rules: { [CONSTRUCTOR_UNINITIALIZED_RULE]: 'warning' },
    });
    expect(warn[0]?.severity).toBe('warning');
  });
});

describe('auditTomlConstructorInvariants', () => {
  it('audits the contracts the document declares', async () => {
    const wasm = wasmWithSpec([specFunction('initialize')]);
    const diagnostics = await auditTomlConstructorInvariants(doc(), rpcWith(entriesFor(wasm)));

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.rule).toBe(CONSTRUCTOR_UNINITIALIZED_RULE);
    expect(diagnostics[0]?.path).toBe('CURRENCIES[0].contract');
  });

  it('stays silent when no network can be derived and none is supplied', async () => {
    const offline = parse(
      ['[[CURRENCIES]]', 'code = "USDC"', `contract = "${CONTRACT}"`].join('\n'),
    ) as Record<string, unknown>;
    let calls = 0;
    const fetchSpy = (async () => {
      calls++;
      return new Response('{}');
    }) as unknown as typeof fetch;

    expect(await auditTomlConstructorInvariants(offline, fetchSpy)).toEqual([]);
    expect(calls).toBe(0);
  });

  it('accepts an explicit RPC override', async () => {
    const wasm = wasmWithSpec([specFunction('initialize')]);
    const diagnostics = await auditTomlConstructorInvariants(doc(), rpcWith(entriesFor(wasm)), {
      rpcUrl: RPC,
    });
    expect(rulesOf(diagnostics)).toEqual([CONSTRUCTOR_UNINITIALIZED_RULE]);
  });
});

describe('ConstructorInvariantVerifier', () => {
  it('verifies a single contract and a whole document', async () => {
    const wasm = wasmWithSpec([specFunction('initialize')]);
    const verifier = new ConstructorInvariantVerifier();

    const single = await verifier.verify(CONTRACT, doc(), RPC, rpcWith(entriesFor(wasm)));
    expect(rulesOf(single)).toEqual([CONSTRUCTOR_UNINITIALIZED_RULE]);

    const fromDocument = await verifier.verifyDocument(doc(), rpcWith(entriesFor(wasm)));
    expect(rulesOf(fromDocument)).toEqual([CONSTRUCTOR_UNINITIALIZED_RULE]);
  });
});

describe('rule registration', () => {
  it('registers every constructor invariant rule id', () => {
    for (const rule of [
      CONSTRUCTOR_UNINITIALIZED_RULE,
      CONSTRUCTOR_NO_REPLAY_PROTECTION_RULE,
      CONSTRUCTOR_ARGUMENT_MISMATCH_RULE,
    ]) {
      expect(sorobanRuleIds).toContain(rule);
    }
  });
});
