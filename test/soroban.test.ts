import { describe, expect, it } from 'vitest';
import { Address, xdr } from '@stellar/stellar-base';
import { lint } from '../src/lint.js';
import { checkContractTtl, checkContracts, sorobanRules } from '../src/soroban.js';

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
            xdr: isCode ? '' : instanceEntryXdr(CONTRACT, options.stellarAsset === true),
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

  it('errors when the instance entry is missing (archived)', async () => {
    const { fetchImpl } = rpcMock({ latestLedger: 100_000, missingInstance: true });

    const diagnostics = await checkContractTtl(CONTRACT, RPC, fetchImpl);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({ rule: EXPIRED_RULE, severity: 'error' }),
    );
  });

  it('errors when the WASM entry is missing (archived)', async () => {
    const { fetchImpl } = rpcMock({
      latestLedger: 100_000,
      instanceLive: 200_000,
      codeLive: 200_000,
      missingCode: true,
    });

    const diagnostics = await checkContractTtl(CONTRACT, RPC, fetchImpl);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({ rule: EXPIRED_RULE, severity: 'error' }),
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
    ]);
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
    // two targets (CURRENCIES contract and WEB_AUTH_CONTRACT_ID) x two lookups
    expect(calls()).toBe(4);
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
