import { describe, expect, it } from 'vitest';
import { Address, xdr } from '@stellar/stellar-base';
import { lint } from '../src/lint.js';
import { allRules } from '../src/rules/index.js';
import {
  checkContractTtl,
  checkContracts,
  fetchSep41Metadata,
  sep41MetadataOf,
  specFunctionNames,
  sorobanRules,
  verifyContractOnChain,
  verifySep45ContractInterface,
} from '../src/soroban.js';

const CONTRACT = 'CACTZSQPCQSSZ5YG3PI3N7WO6JEERKEUHTPILKB4MBANF2K4D2UHKDDU';
const NETWORK = 'Test SDF Network ; September 2015';
const RPC = 'https://soroban-testnet.stellar.org';
const WASM = Buffer.alloc(32);

function instanceEntryXdr(contractId: string, stellarAsset = false): string {
  const executable = stellarAsset
    ? xdr.ContractExecutable.contractExecutableStellarAsset()
    : xdr.ContractExecutable.contractExecutableWasm(WASM);
  const entry = xdr.LedgerEntryData.contractData(
    new xdr.ContractDataEntry({
      ext: xdr.ExtensionPoint.fromXDR(Buffer.alloc(4), 'raw'),
      contract: new Address(contractId).toScAddress(),
      key: xdr.ScVal.scvLedgerKeyContractInstance(),
      durability: xdr.ContractDataDurability.persistent(),
      val: xdr.ScVal.scvContractInstance(new xdr.ScContractInstance({ executable, storage: [] })),
    }),
  );
  return entry.toXDR('base64');
}

/** The WASM bytes a contract-code entry carries. */
function codeEntryXdr(wasm: Buffer): string {
  const entry = xdr.LedgerEntryData.contractCode(
    new xdr.ContractCodeEntry({
      ext: xdr.ContractCodeEntryExt.fromXDR(Buffer.alloc(4), 'raw'),
      hash: Buffer.alloc(32),
      code: wasm,
    }),
  );
  return entry.toXDR('base64');
}

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

/**
 * A minimal WASM module whose `contractspecv0` custom section declares one
 * exported function per name — the shape a real Soroban contract ships.
 */
function wasmWithSpec(functions: string[]): Buffer {
  const entries = functions.map((name) =>
    xdr.ScSpecEntry.scSpecEntryFunctionV0(
      new xdr.ScSpecFunctionV0({ doc: '', name, inputs: [], outputs: [] }),
    ),
  );
  const payload = Buffer.concat(entries.map((entry) => entry.toXDR()));
  const name = Buffer.from('contractspecv0', 'utf8');
  const content = Buffer.concat([encodeU32(name.length), name, payload]);

  const header = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
  return Buffer.concat([header, Buffer.from([0x00]), encodeU32(content.length), content]);
}

/** A WASM module with no contract spec section at all. */
function wasmWithoutSpec(): Buffer {
  return Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
}

interface RpcOptions {
  latestLedger: number;
  instanceLive?: number;
  codeLive?: number;
  /** When true the instance lookup returns no entry (archived/expired). */
  missingInstance?: boolean;
  /** When true the code lookup returns no entry (WASM archived). */
  missingCode?: boolean;
  /** Build the instance entry with a Stellar-asset executable (no WASM). */
  stellarAsset?: boolean;
  /** WASM bytes the contract-code entry carries, for interface checks. */
  code?: Buffer;
}

function rpcMock(options: RpcOptions): { fetchImpl: typeof fetch; calls: () => number } {
  let calls = 0;
  const fetchImpl = (async (_url: string | URL | globalThis.Request, init?: RequestInit) => {
    calls++;
    const body = JSON.parse(String((init as RequestInit | undefined)?.body)) as {
      method: string;
      params: { keys: string[] };
    };
    expect(body.method).toBe('getLedgerEntries');

    const key = body.params.keys[0] as string;
    const ledgerKey = xdr.LedgerKey.fromXDR(key, 'base64');
    const isCode = ledgerKey.switch().name === 'contractCode';

    const liveUntil = isCode ? options.codeLive : options.instanceLive;
    const missing = isCode ? options.missingCode === true : options.missingInstance === true;
    const entry =
      liveUntil === undefined || missing
        ? undefined
        : {
            key,
            xdr: isCode
              ? options.code !== undefined
                ? codeEntryXdr(options.code)
                : ''
              : instanceEntryXdr(CONTRACT, options.stellarAsset === true),
            lastModifiedLedgerSeq: 1,
            liveUntilLedgerSeq: liveUntil,
          };

    return new Response(
      JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        result: { latestLedger: options.latestLedger, entries: entry === undefined ? [] : [entry] },
      }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );
  }) as unknown as typeof fetch;
  return { fetchImpl, calls: () => calls };
}

const EXPIRING_RULE = 'soroban/contract-ttl-expiring-soon';
const EXPIRED_RULE = 'soroban/contract-expired';
const UNAVAILABLE_RULE = 'soroban/contract-ttl-unavailable';
const NOT_FOUND_RULE = 'soroban/contract-not-found';
const EVICTED_RULE = 'soroban/contract-evicted';

describe('Soroban contract TTL audit', () => {
  it('is silent while the TTL is ample', async () => {
    const { fetchImpl } = rpcMock({
      latestLedger: 100_000,
      instanceLive: 200_000,
      codeLive: 200_000,
    });

    const diagnostics = await checkContractTtl(CONTRACT, RPC, fetchImpl);
    expect(diagnostics).toEqual([]);
  });

  it('warns when the contract expires within ~a day', async () => {
    const { fetchImpl, calls } = rpcMock({
      latestLedger: 100_000,
      instanceLive: 105_001,
      codeLive: 200_000,
    });

    const diagnostics = await checkContractTtl(CONTRACT, RPC, fetchImpl);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({ rule: EXPIRING_RULE, severity: 'warning', category: 'network' }),
    );
    // instance and WASM both queried
    expect(calls()).toBe(2);
  });

  it('errors when the effective TTL has already passed', async () => {
    const { fetchImpl } = rpcMock({
      latestLedger: 100_000,
      instanceLive: 100_000,
      codeLive: 200_000,
    });

    const diagnostics = await checkContractTtl(CONTRACT, RPC, fetchImpl);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({ rule: EXPIRED_RULE, severity: 'error' }),
    );
  });

  it('reports a contract with no instance entry as not found', async () => {
    const { fetchImpl } = rpcMock({ latestLedger: 100_000, missingInstance: true });

    const diagnostics = await checkContractTtl(CONTRACT, RPC, fetchImpl);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({ rule: NOT_FOUND_RULE, severity: 'error' }),
    );
  });

  it('reports a contract whose WASM entry is missing as evicted', async () => {
    const { fetchImpl } = rpcMock({
      latestLedger: 100_000,
      instanceLive: 200_000,
      codeLive: 200_000,
      missingCode: true,
    });

    const diagnostics = await checkContractTtl(CONTRACT, RPC, fetchImpl);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({ rule: EVICTED_RULE, severity: 'error' }),
    );
  });

  it('degrades to a warning when the RPC is unreachable', async () => {
    const fetchImpl = (async () => {
      throw new Error('Network offline');
    }) as unknown as typeof fetch;

    const diagnostics = await checkContractTtl(CONTRACT, RPC, fetchImpl);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({ rule: UNAVAILABLE_RULE, severity: 'warning' }),
    );
  });

  it('only checks the instance TTL when the executable is not WASM', async () => {
    const { fetchImpl, calls } = rpcMock({
      latestLedger: 100_000,
      instanceLive: 200_000,
      stellarAsset: true,
    });

    const diagnostics = await checkContractTtl(CONTRACT, RPC, fetchImpl);
    expect(diagnostics).toEqual([]);
    expect(calls()).toBe(1);
  });

  it('honours --off overrides', async () => {
    const { fetchImpl } = rpcMock({
      latestLedger: 100_000,
      instanceLive: 105_001,
      codeLive: 200_000,
    });

    const diagnostics = await checkContractTtl(CONTRACT, RPC, fetchImpl, {
      rules: { [EXPIRING_RULE]: 'off' },
    });
    expect(diagnostics).toEqual([]);
  });

  it('registers the expected rule ids and severities', () => {
    expect(sorobanRules.map((r) => ({ id: r.id, severity: r.severity }))).toEqual([
      { id: EXPIRING_RULE, severity: 'warning' },
      { id: EXPIRED_RULE, severity: 'error' },
      { id: UNAVAILABLE_RULE, severity: 'warning' },
      { id: NOT_FOUND_RULE, severity: 'error' },
      { id: EVICTED_RULE, severity: 'error' },
      { id: 'soroban/invalid-auth-contract-interface', severity: 'error' },
    ]);
  });
});

describe('verifyContractOnChain', () => {
  it('is clean for a deployed contract whose instance and WASM exist', async () => {
    const { fetchImpl, calls } = rpcMock({
      latestLedger: 100_000,
      instanceLive: 200_000,
      codeLive: 200_000,
    });

    expect(await verifyContractOnChain(CONTRACT, RPC, fetchImpl)).toEqual([]);
    expect(calls()).toBe(2);
  });

  it("ignores TTL, which is checkContractTtl's concern", async () => {
    const { fetchImpl } = rpcMock({
      latestLedger: 100_000,
      instanceLive: 100_010,
      codeLive: 200_000,
    });

    expect(await verifyContractOnChain(CONTRACT, RPC, fetchImpl)).toEqual([]);
  });

  it('reports soroban/contract-not-found for a missing instance entry', async () => {
    const { fetchImpl, calls } = rpcMock({ latestLedger: 100_000, missingInstance: true });

    const diagnostics = await verifyContractOnChain(CONTRACT, RPC, fetchImpl, {
      path: 'CURRENCIES[0].contract',
    });
    expect(diagnostics).toEqual([
      expect.objectContaining({
        rule: NOT_FOUND_RULE,
        severity: 'error',
        category: 'network',
        path: 'CURRENCIES[0].contract',
      }),
    ]);
    expect(diagnostics[0]?.message).toContain(CONTRACT);
    // No WASM lookup without an instance to name it.
    expect(calls()).toBe(1);
  });

  it('reports soroban/contract-evicted when the WASM is gone', async () => {
    const { fetchImpl } = rpcMock({
      latestLedger: 100_000,
      instanceLive: 200_000,
      codeLive: 200_000,
      missingCode: true,
    });

    expect(await verifyContractOnChain(CONTRACT, RPC, fetchImpl)).toEqual([
      expect.objectContaining({ rule: EVICTED_RULE, severity: 'error' }),
    ]);
  });

  it('degrades an RPC timeout to a warning instead of throwing', async () => {
    const fetchImpl = (async () => {
      throw new DOMException('The operation was aborted due to timeout', 'TimeoutError');
    }) as unknown as typeof fetch;

    const diagnostics = await verifyContractOnChain(CONTRACT, RPC, fetchImpl);
    expect(diagnostics).toEqual([
      expect.objectContaining({ rule: UNAVAILABLE_RULE, severity: 'warning' }),
    ]);
  });

  it('bounds every RPC request with an abort signal', async () => {
    let signal: AbortSignal | null | undefined;
    const fetchImpl = (async (_url: string, init?: RequestInit) => {
      signal = init?.signal;
      throw new Error('offline');
    }) as unknown as typeof fetch;

    await verifyContractOnChain(CONTRACT, RPC, fetchImpl);
    expect(signal).toBeInstanceOf(AbortSignal);
  });

  it('degrades a non-200 RPC answer to a warning', async () => {
    const fetchImpl = (async () =>
      new Response('bad gateway', { status: 502 })) as unknown as typeof fetch;

    expect(await verifyContractOnChain(CONTRACT, RPC, fetchImpl)).toEqual([
      expect.objectContaining({ rule: UNAVAILABLE_RULE, severity: 'warning' }),
    ]);
  });

  it('honours --off on the not-found rule', async () => {
    const { fetchImpl } = rpcMock({ latestLedger: 100_000, missingInstance: true });

    const diagnostics = await verifyContractOnChain(CONTRACT, RPC, fetchImpl, {
      rules: { [NOT_FOUND_RULE]: 'off' },
    });
    expect(diagnostics).toEqual([]);
  });
});

function contractsSource(): string {
  return [
    `NETWORK_PASSPHRASE="${NETWORK}"`,
    '',
    `WEB_AUTH_CONTRACT_ID="${CONTRACT}"`,
    '',
    '[[CURRENCIES]]',
    'code="TOKEN"',
    `contract="${CONTRACT}"`,
  ].join('\n');
}

describe('checkContracts', () => {
  it('audits every contract declared in the file', async () => {
    const parsed = lint(contractsSource()).parsed ?? {};
    const { fetchImpl, calls } = rpcMock({
      latestLedger: 100_000,
      instanceLive: 200_000,
      codeLive: 200_000,
    });

    const diagnostics = await checkContracts(parsed, fetchImpl);
    expect(diagnostics).toEqual([]);
    // TTL: two targets (CURRENCIES contract and WEB_AUTH_CONTRACT_ID) x two
    // lookups, the currency's SEP-41 metadata read, plus the auth contract's
    // instance and code reads for the SEP-45 interface check.
    expect(calls()).toBe(7);
  });

  it('points each not-found finding at the field that declared the contract', async () => {
    const parsed = lint(contractsSource()).parsed ?? {};
    const { fetchImpl } = rpcMock({ latestLedger: 100_000, missingInstance: true });

    const diagnostics = await checkContracts(parsed, fetchImpl);
    expect(diagnostics.map((d) => [d.rule, d.path])).toEqual([
      [NOT_FOUND_RULE, 'CURRENCIES[0].contract'],
      [NOT_FOUND_RULE, 'WEB_AUTH_CONTRACT_ID'],
    ]);
  });

  it('is silent with no contracts declared', async () => {
    const parsed = lint('NETWORK_PASSPHRASE="Test SDF Network ; September 2015"').parsed ?? {};
    const { fetchImpl, calls } = rpcMock({ latestLedger: 100_000 });

    expect(await checkContracts(parsed, fetchImpl)).toEqual([]);
    expect(calls()).toBe(0);
  });

  it('is silent on an unknown network without an explicit RPC', async () => {
    const parsed = lint(contractsSource().replace(NETWORK, 'Private Herder Network')).parsed ?? {};
    const { fetchImpl, calls } = rpcMock({ latestLedger: 100_000 });

    expect(await checkContracts(parsed, fetchImpl)).toEqual([]);
    expect(calls()).toBe(0);
  });

  it('accepts an explicit RPC override for unknown networks', async () => {
    const parsed = lint(contractsSource().replace(NETWORK, 'Private Herder Network')).parsed ?? {};
    const ofCallback: unknown[] = [];
    const fetchImpl = (async (url: string | URL | globalThis.Request, init?: RequestInit) => {
      ofCallback.push(url, init);
      const key = (
        JSON.parse(String((init as RequestInit | undefined)?.body)) as {
          params: { keys: string[] };
        }
      ).params.keys[0] as string;
      const ledgerKey = xdr.LedgerKey.fromXDR(key, 'base64');
      const isCode = ledgerKey.switch().name === 'contractCode';
      const entry = {
        key,
        xdr: isCode ? '' : instanceEntryXdr(CONTRACT),
        lastModifiedLedgerSeq: 1,
        liveUntilLedgerSeq: 200_000,
      };
      return new Response(
        JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          result: { latestLedger: 100_000, entries: [entry] },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }) as unknown as typeof fetch;

    const diagnostics = await checkContracts(parsed, fetchImpl, {
      rpcUrl: 'http://localhost:8000/rpc',
    });
    expect(diagnostics).toEqual([]);
    expect(ofCallback[0]?.toString()).toBe('http://localhost:8000/rpc');
  });
});

const AUTH_INTERFACE_RULE = 'soroban/invalid-auth-contract-interface';

describe('verifySep45ContractInterface', () => {
  it('is silent for a contract that exports web_auth_verify', async () => {
    const { fetchImpl, calls } = rpcMock({
      latestLedger: 100_000,
      instanceLive: 200_000,
      codeLive: 200_000,
      code: wasmWithSpec(['web_auth_verify', '__constructor']),
    });

    expect(await verifySep45ContractInterface(CONTRACT, RPC, fetchImpl)).toEqual([]);
    // instance + code, nothing more.
    expect(calls()).toBe(2);
  });

  it('errors for a generic token contract without the auth function', async () => {
    const { fetchImpl } = rpcMock({
      latestLedger: 100_000,
      instanceLive: 200_000,
      codeLive: 200_000,
      code: wasmWithSpec(['transfer', 'balance', 'mint']),
    });

    const diagnostics = await verifySep45ContractInterface(CONTRACT, RPC, fetchImpl);
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      rule: AUTH_INTERFACE_RULE,
      severity: 'error',
      category: 'network',
      path: 'WEB_AUTH_CONTRACT_ID',
    });
    expect(diagnostics[0]?.message).toContain('web_auth_verify');
  });

  it('stays silent when the WASM carries no spec section', async () => {
    const { fetchImpl } = rpcMock({
      latestLedger: 100_000,
      instanceLive: 200_000,
      codeLive: 200_000,
      code: wasmWithoutSpec(),
    });

    expect(await verifySep45ContractInterface(CONTRACT, RPC, fetchImpl)).toEqual([]);
  });

  it('stays silent when the contract instance is unavailable', async () => {
    const { fetchImpl } = rpcMock({ latestLedger: 100_000, missingInstance: true });
    expect(await verifySep45ContractInterface(CONTRACT, RPC, fetchImpl)).toEqual([]);
  });

  it('stays silent when the RPC is unreachable', async () => {
    const fetchImpl = (async () => {
      throw new Error('Network offline');
    }) as unknown as typeof fetch;

    expect(await verifySep45ContractInterface(CONTRACT, RPC, fetchImpl)).toEqual([]);
  });

  it('honours --off and --warn overrides', async () => {
    const wasm = wasmWithSpec(['transfer']);
    const off = rpcMock({ latestLedger: 1, instanceLive: 2, codeLive: 2, code: wasm });
    expect(
      await verifySep45ContractInterface(CONTRACT, RPC, off.fetchImpl, {
        rules: { [AUTH_INTERFACE_RULE]: 'off' },
      }),
    ).toEqual([]);

    const warn = rpcMock({ latestLedger: 1, instanceLive: 2, codeLive: 2, code: wasm });
    const diagnostics = await verifySep45ContractInterface(CONTRACT, RPC, warn.fetchImpl, {
      rules: { [AUTH_INTERFACE_RULE]: 'warning' },
    });
    expect(diagnostics[0]?.severity).toBe('warning');
  });

  it('runs the interface check from checkContracts', async () => {
    const parsed = lint(contractsSource()).parsed ?? {};
    const { fetchImpl } = rpcMock({
      latestLedger: 100_000,
      instanceLive: 200_000,
      codeLive: 200_000,
      code: wasmWithSpec(['transfer']),
    });

    const diagnostics = await checkContracts(parsed, fetchImpl);
    // One error for the auth contract; the currency token's TTL is healthy.
    expect(diagnostics.filter((d) => d.rule === AUTH_INTERFACE_RULE)).toHaveLength(1);
  });
});

describe('specFunctionNames', () => {
  it('reads function names out of the contractspecv0 custom section', () => {
    expect(specFunctionNames(wasmWithSpec(['web_auth_verify', 'transfer']))).toEqual([
      'web_auth_verify',
      'transfer',
    ]);
  });

  it('returns undefined when the module has no spec section', () => {
    expect(specFunctionNames(wasmWithoutSpec())).toBeUndefined();
  });
});

interface TokenMetadata {
  decimal?: number;
  name?: string;
  symbol?: string;
}

/** SEP-41 metadata as the token SDK stores it: a `METADATA` map of symbol keys. */
function metadataMap(metadata: TokenMetadata): xdr.ScMapEntry[] {
  const entries: xdr.ScMapEntry[] = [];
  // ScMap keys are kept sorted, as the host requires.
  if (metadata.decimal !== undefined) {
    entries.push(
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol('decimal'),
        val: xdr.ScVal.scvU32(metadata.decimal),
      }),
    );
  }
  if (metadata.name !== undefined) {
    entries.push(
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol('name'),
        val: xdr.ScVal.scvString(metadata.name),
      }),
    );
  }
  if (metadata.symbol !== undefined) {
    entries.push(
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol('symbol'),
        val: xdr.ScVal.scvString(metadata.symbol),
      }),
    );
  }
  return entries;
}

function tokenInstanceXdr(
  metadata: TokenMetadata,
  options: { stellarAsset?: boolean; topLevel?: boolean } = {},
): string {
  const executable = options.stellarAsset
    ? xdr.ContractExecutable.contractExecutableStellarAsset()
    : xdr.ContractExecutable.contractExecutableWasm(WASM);
  const storage = options.topLevel
    ? metadataMap(metadata)
    : [
        new xdr.ScMapEntry({
          key: xdr.ScVal.scvSymbol('METADATA'),
          val: xdr.ScVal.scvMap(metadataMap(metadata)),
        }),
      ];
  const entry = xdr.LedgerEntryData.contractData(
    new xdr.ContractDataEntry({
      ext: xdr.ExtensionPoint.fromXDR(Buffer.alloc(4), 'raw'),
      contract: new Address(CONTRACT).toScAddress(),
      key: xdr.ScVal.scvLedgerKeyContractInstance(),
      durability: xdr.ContractDataDurability.persistent(),
      val: xdr.ScVal.scvContractInstance(new xdr.ScContractInstance({ executable, storage })),
    }),
  );
  return entry.toXDR('base64');
}

/** An RPC whose contract instance carries `instanceXdr`, live well past the latest ledger. */
function tokenRpc(instanceXdr: string): typeof fetch {
  return (async (_url: string | URL | globalThis.Request, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)) as { params: { keys: string[] } };
    const key = body.params.keys[0] as string;
    const isCode = xdr.LedgerKey.fromXDR(key, 'base64').switch().name === 'contractCode';
    const entry = {
      key,
      xdr: isCode ? codeEntryXdr(wasmWithoutSpec()) : instanceXdr,
      lastModifiedLedgerSeq: 1,
      liveUntilLedgerSeq: 200_000,
    };
    return new Response(
      JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        result: { latestLedger: 100_000, entries: [entry] },
      }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );
  }) as unknown as typeof fetch;
}

function tokenSource(fields: string[]): Record<string, unknown> {
  const source = [
    `NETWORK_PASSPHRASE="${NETWORK}"`,
    '',
    '[[CURRENCIES]]',
    `contract="${CONTRACT}"`,
    ...fields,
  ].join('\n');
  return lint(source).parsed ?? {};
}

const SYMBOL_RULE = 'soroban/symbol-mismatch';
const DECIMALS_RULE = 'soroban/decimals-mismatch';
const NAME_RULE = 'soroban/name-mismatch';

describe('SEP-41 metadata', () => {
  it('reads the METADATA map from instance storage', () => {
    expect(
      sep41MetadataOf(tokenInstanceXdr({ decimal: 7, name: 'USD Coin', symbol: 'USDC' })),
    ).toEqual({
      decimal: 7,
      name: 'USD Coin',
      symbol: 'USDC',
      stellarAsset: false,
    });
  });

  it('reads metadata stored at the top level of instance storage', () => {
    expect(
      sep41MetadataOf(tokenInstanceXdr({ decimal: 6, symbol: 'XYZ' }, { topLevel: true })),
    ).toEqual({ decimal: 6, symbol: 'XYZ', stellarAsset: false });
  });

  it('returns undefined for an instance with no metadata or unparseable XDR', () => {
    expect(sep41MetadataOf(instanceEntryXdr(CONTRACT))).toBeUndefined();
    expect(sep41MetadataOf('not xdr')).toBeUndefined();
    expect(sep41MetadataOf(undefined)).toBeUndefined();
  });

  it('fetches metadata over getLedgerEntries', async () => {
    const fetchImpl = tokenRpc(tokenInstanceXdr({ decimal: 7, symbol: 'USDC' }));
    expect(await fetchSep41Metadata(CONTRACT, RPC, fetchImpl)).toEqual({
      decimal: 7,
      symbol: 'USDC',
      stellarAsset: false,
    });
  });

  it('returns undefined when the RPC is unreachable', async () => {
    const fetchImpl = (async () => {
      throw new Error('offline');
    }) as unknown as typeof fetch;
    expect(await fetchSep41Metadata(CONTRACT, RPC, fetchImpl)).toBeUndefined();
  });

  it('passes cleanly when symbol, decimal, and name match the file', async () => {
    const doc = tokenSource(['code="USDC"', 'display_decimals=7', 'name="USD Coin"']);
    const fetchImpl = tokenRpc(tokenInstanceXdr({ decimal: 7, name: 'USD Coin', symbol: 'USDC' }));

    expect(await checkContracts(doc, fetchImpl)).toEqual([]);
  });

  it('reports soroban/decimals-mismatch when decimal disagrees with display_decimals', async () => {
    const doc = tokenSource(['code="USDC"', 'display_decimals=7']);
    const fetchImpl = tokenRpc(tokenInstanceXdr({ decimal: 6, symbol: 'USDC' }));

    const diagnostics = await checkContracts(doc, fetchImpl);
    expect(diagnostics).toEqual([
      expect.objectContaining({
        rule: DECIMALS_RULE,
        severity: 'error',
        path: 'CURRENCIES[0].display_decimals',
        message: `CURRENCIES[0].display_decimals is 7, but contract ${CONTRACT} reports decimal 6`,
      }),
    ]);
    expect(diagnostics[0]?.suggestion).toContain('Set display_decimals to 6');
  });

  it('reports soroban/symbol-mismatch when symbol disagrees with code', async () => {
    const doc = tokenSource(['code="USDC"', 'display_decimals=7']);
    const fetchImpl = tokenRpc(tokenInstanceXdr({ decimal: 7, symbol: 'XYZ' }));

    const diagnostics = await checkContracts(doc, fetchImpl);
    expect(diagnostics).toEqual([
      expect.objectContaining({
        rule: SYMBOL_RULE,
        severity: 'error',
        path: 'CURRENCIES[0].code',
        message: `CURRENCIES[0].code is "USDC", but contract ${CONTRACT} reports symbol "XYZ"`,
      }),
    ]);
  });

  it('warns with soroban/name-mismatch when name disagrees', async () => {
    const doc = tokenSource(['code="USDC"', 'name="USD Coin"']);
    const fetchImpl = tokenRpc(tokenInstanceXdr({ name: 'Test Token', symbol: 'USDC' }));

    expect(await checkContracts(doc, fetchImpl)).toEqual([
      expect.objectContaining({ rule: NAME_RULE, severity: 'warning', path: 'CURRENCIES[0].name' }),
    ]);
  });

  it('does not compare name for a Stellar Asset Contract, whose name is CODE:ISSUER', async () => {
    const doc = tokenSource(['code="USDC"', 'name="USD Coin"', 'display_decimals=7']);
    const fetchImpl = tokenRpc(
      tokenInstanceXdr(
        {
          decimal: 7,
          name: 'USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN',
          symbol: 'USDC',
        },
        { stellarAsset: true },
      ),
    );

    expect(await checkContracts(doc, fetchImpl)).toEqual([]);
  });

  it('skips fields the file leaves unset', async () => {
    const doc = tokenSource(['code="USDC"']);
    const fetchImpl = tokenRpc(tokenInstanceXdr({ decimal: 6, name: 'Other', symbol: 'USDC' }));

    expect(await checkContracts(doc, fetchImpl)).toEqual([]);
  });

  it('honours severity overrides', async () => {
    const doc = tokenSource(['code="USDC"', 'display_decimals=7', 'name="USD Coin"']);
    const fetchImpl = tokenRpc(tokenInstanceXdr({ decimal: 6, name: 'Other', symbol: 'USDC' }));

    const diagnostics = await checkContracts(doc, fetchImpl, {
      rules: { [DECIMALS_RULE]: 'warning', [NAME_RULE]: 'off' },
    });
    expect(diagnostics).toEqual([
      expect.objectContaining({ rule: DECIMALS_RULE, severity: 'warning' }),
    ]);
  });

  it('registers the metadata rules for --list-rules', () => {
    const ids = allRules.map((rule) => rule.id);
    expect(ids).toEqual(expect.arrayContaining([SYMBOL_RULE, DECIMALS_RULE, NAME_RULE]));
  });
});
