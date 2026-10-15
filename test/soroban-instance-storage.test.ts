import { describe, expect, it } from 'vitest';
import { Address, xdr } from '@stellar/stellar-base';
import {
  auditContractInstanceStorage,
  auditTomlInstanceStorage,
  instanceStorageAuditorRules,
  CORRUPTED_ENTRY_RULE,
  DATA_MISMATCH_RULE,
} from '../src/soroban/instance-storage-auditor.js';

const CONTRACT = 'CACTZSQPCQSSZ5YG3PI3N7WO6JEERKEUHTPILKB4MBANF2K4D2UHKDDU';
const NETWORK = 'Test SDF Network ; September 2015';
const RPC = 'https://soroban-testnet.stellar.org';
const WASM = Buffer.alloc(32);

function instanceEntryXdr(storage: xdr.ScMapEntry[], stellarAsset = false): string {
  const executable = stellarAsset
    ? xdr.ContractExecutable.contractExecutableStellarAsset()
    : xdr.ContractExecutable.contractExecutableWasm(WASM);
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

function codeEntryXdr(): string {
  const entry = xdr.LedgerEntryData.contractCode(
    new xdr.ContractCodeEntry({
      ext: xdr.ContractCodeEntryExt.fromXDR(Buffer.alloc(4), 'raw'),
      hash: Buffer.alloc(32),
      code: Buffer.alloc(32),
    }),
  );
  return entry.toXDR('base64');
}

function makeStorage(entries: { key: string; val: xdr.ScVal }[]): xdr.ScMapEntry[] {
  return entries.map((e) =>
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol(e.key),
      val: e.val,
    }),
  );
}

interface RpcOptions {
  latestLedger: number;
  instanceLive?: number;
  instanceXdr?: string;
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

    if (isCode) {
      return new Response(
        JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          result: { latestLedger: options.latestLedger, entries: [] },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }

    const entry = options.instanceXdr
      ? {
          key,
          xdr: options.instanceXdr,
          lastModifiedLedgerSeq: 1,
          liveUntilLedgerSeq: options.instanceLive,
        }
      : undefined;

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

describe('Soroban instance storage auditor', () => {
  it('passes for valid instance storage with matching decimal', async () => {
    const storage = makeStorage([
      { key: 'decimal', val: xdr.ScVal.scvU32(7) },
      { key: 'admin', val: xdr.ScVal.scvAddress(new Address('GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF').toScAddress()) },
    ]);
    const instanceXdr = instanceEntryXdr(storage);

    const { fetchImpl } = rpcMock({
      latestLedger: 100_000,
      instanceLive: 200_000,
      instanceXdr,
    });

    const diagnostics = await auditContractInstanceStorage(CONTRACT, RPC, 7, fetchImpl);
    expect(diagnostics).toEqual([]);
  });

  it('reports soroban/instance-storage-data-mismatch when decimal disagrees with display_decimals', async () => {
    const storage = makeStorage([
      { key: 'decimal', val: xdr.ScVal.scvU32(6) },
    ]);
    const instanceXdr = instanceEntryXdr(storage);

    const { fetchImpl } = rpcMock({
      latestLedger: 100_000,
      instanceLive: 200_000,
      instanceXdr,
    });

    const diagnostics = await auditContractInstanceStorage(CONTRACT, RPC, 7, fetchImpl);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: DATA_MISMATCH_RULE,
        severity: 'error',
        category: 'network',
      }),
    );
    expect(diagnostics[0]?.message).toContain('decimal');
  });

  it('reports soroban/corrupted-instance-storage-entry when admin is not an Address', async () => {
    const storage = makeStorage([
      { key: 'admin', val: xdr.ScVal.scvString('not-an-address') },
    ]);
    const instanceXdr = instanceEntryXdr(storage);

    const { fetchImpl } = rpcMock({
      latestLedger: 100_000,
      instanceLive: 200_000,
      instanceXdr,
    });

    const diagnostics = await auditContractInstanceStorage(CONTRACT, RPC, undefined, fetchImpl);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: CORRUPTED_ENTRY_RULE,
        severity: 'error',
        category: 'network',
      }),
    );
    expect(diagnostics[0]?.message).toContain('admin');
  });

  it('reports soroban/corrupted-instance-storage-entry when decimal is not U32', async () => {
    const storage = makeStorage([
      { key: 'decimal', val: xdr.ScVal.scvString('7') },
    ]);
    const instanceXdr = instanceEntryXdr(storage);

    const { fetchImpl } = rpcMock({
      latestLedger: 100_000,
      instanceLive: 200_000,
      instanceXdr,
    });

    const diagnostics = await auditContractInstanceStorage(CONTRACT, RPC, 7, fetchImpl);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: CORRUPTED_ENTRY_RULE,
        severity: 'error',
        category: 'network',
      }),
    );
    expect(diagnostics[0]?.message).toContain('decimal');
  });

  it('warns when admin key is missing', async () => {
    const storage = makeStorage([
      { key: 'decimal', val: xdr.ScVal.scvU32(7) },
    ]);
    const instanceXdr = instanceEntryXdr(storage);

    const { fetchImpl } = rpcMock({
      latestLedger: 100_000,
      instanceLive: 200_000,
      instanceXdr,
    });

    const diagnostics = await auditContractInstanceStorage(CONTRACT, RPC, 7, fetchImpl);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: CORRUPTED_ENTRY_RULE,
        severity: 'warning',
        category: 'network',
      }),
    );
    expect(diagnostics[0]?.message).toContain('admin');
  });

  it('reports error when instance entry is missing', async () => {
    const { fetchImpl } = rpcMock({
      latestLedger: 100_000,
      instanceLive: undefined,
      instanceXdr: undefined,
    });

    const diagnostics = await auditContractInstanceStorage(CONTRACT, RPC, 7, fetchImpl);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: CORRUPTED_ENTRY_RULE,
        severity: 'error',
        category: 'network',
      }),
    );
  });

  it('degrades to error when RPC is unreachable', async () => {
    const fetchImpl = (async () => {
      throw new Error('Network offline');
    }) as unknown as typeof fetch;

    const diagnostics = await auditContractInstanceStorage(CONTRACT, RPC, 7, fetchImpl);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: CORRUPTED_ENTRY_RULE,
        severity: 'error',
        category: 'network',
      }),
    );
  });

  it('registers the expected rule ids and severities', () => {
    expect(instanceStorageAuditorRules.map((r) => ({ id: r.id, severity: r.severity }))).toEqual([
      { id: CORRUPTED_ENTRY_RULE, severity: 'error' },
      { id: DATA_MISMATCH_RULE, severity: 'error' },
    ]);
  });
});