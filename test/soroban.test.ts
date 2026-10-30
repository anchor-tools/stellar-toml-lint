import { describe, expect, it } from 'vitest';
import { Address, xdr } from '@stellar/stellar-base';
import { lint } from '../src/lint.js';
import {
  checkContractTtl,
  checkContracts,
  specFunctionNames,
  sorobanRules,
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
      { id: 'soroban/invalid-auth-contract-interface', severity: 'error' },
      { id: 'soroban/unprotected-upgrade-function', severity: 'error' },
      { id: 'soroban/single-signer-upgrade-admin', severity: 'warning' },
      { id: 'soroban/supply-invariant-violation', severity: 'error' },
      { id: 'soroban/excessive-static-memory-pages', severity: 'warning' },
      { id: 'soroban/high-cyclomatic-complexity', severity: 'warning' },
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
    // TTL: two targets (CURRENCIES contract and WEB_AUTH_CONTRACT_ID) x two
    // lookups, plus the auth contract's instance and code reads for the SEP-45
    // interface check.
    expect(calls()).toBe(6);
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

import {
  auditUpgradeSecurity,
  UNPROTECTED_UPGRADE_RULE,
  SINGLE_SIGNER_UPGRADE_ADMIN_RULE,
} from '../src/soroban/upgrade-auditor.js';

import {
  auditSupplyInvariant,
  SUPPLY_INVARIANT_RULE,
  horizonAmountToStroops,
  stroopsToAmountString,
} from '../src/soroban/supply-invariant.js';

const ADMIN_ACCOUNT = 'GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS';

function instanceEntryXdrWithAdmin(contractId: string, adminAddr?: string): string {
  const executable = xdr.ContractExecutable.contractExecutableWasm(WASM);
  const storage: xdr.ScMapEntry[] = [];
  if (adminAddr) {
    storage.push(
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol('admin'),
        val: xdr.ScVal.scvAddress(new Address(adminAddr).toScAddress()),
      }),
    );
  }
  const entry = xdr.LedgerEntryData.contractData(
    new xdr.ContractDataEntry({
      ext: xdr.ExtensionPoint.fromXDR(Buffer.alloc(4), 'raw'),
      contract: new Address(contractId).toScAddress(),
      key: xdr.ScVal.scvLedgerKeyContractInstance(),
      durability: xdr.ContractDataDurability.persistent(),
      val: xdr.ScVal.scvContractInstance(new xdr.ScContractInstance({ executable, storage })),
    }),
  );
  return entry.toXDR('base64');
}

function supplyEntryXdr(contractId: string, stroops: bigint): string {
  const hi = new xdr.Int64(stroops >> 64n);
  const lo = new xdr.Uint64(stroops & 0xffffffffffffffffn);
  const val = xdr.ScVal.scvI128(new xdr.Int128Parts({ hi, lo }));
  const entry = xdr.LedgerEntryData.contractData(
    new xdr.ContractDataEntry({
      ext: xdr.ExtensionPoint.fromXDR(Buffer.alloc(4), 'raw'),
      contract: new Address(contractId).toScAddress(),
      key: xdr.ScVal.scvSymbol('Supply'),
      durability: xdr.ContractDataDurability.persistent(),
      val,
    }),
  );
  return entry.toXDR('base64');
}

describe('Smart Contract Upgrade Auditor', () => {
  it('is silent when contract has no upgrade functions', async () => {
    const fetchImpl = (async (url: string | URL | globalThis.Request) => {
      const u = url.toString();
      if (u.includes('getLedgerEntries')) {
        return new Response(
          JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            result: {
              latestLedger: 100_000,
              entries: [
                {
                  key: 'k',
                  xdr: instanceEntryXdrWithAdmin(CONTRACT, ADMIN_ACCOUNT),
                  liveUntilLedgerSeq: 200_000,
                },
              ],
            },
          }),
          { status: 200 },
        );
      }
      return new Response(JSON.stringify({}), { status: 404 });
    }) as unknown as typeof fetch;

    const diagnostics = await auditUpgradeSecurity(
      CONTRACT,
      RPC,
      'https://horizon.stellar.org',
      fetchImpl,
    );
    expect(diagnostics).toEqual([]);
  });

  it('emits unprotected-upgrade-function when upgrade function is present but no admin set', async () => {
    const fetchImpl = (async (url: string | URL | globalThis.Request, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { params?: { keys?: string[] } };
      const key = body.params?.keys?.[0] ?? '';
      const isCode = key.includes('contractCode') || key.length < 50;

      return new Response(
        JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          result: {
            latestLedger: 100_000,
            entries: [
              {
                key,
                xdr: isCode
                  ? codeEntryXdr(wasmWithSpec(['upgrade', 'transfer']))
                  : instanceEntryXdrWithAdmin(CONTRACT),
                liveUntilLedgerSeq: 200_000,
              },
            ],
          },
        }),
        { status: 200 },
      );
    }) as unknown as typeof fetch;

    const diagnostics = await auditUpgradeSecurity(
      CONTRACT,
      RPC,
      'https://horizon.stellar.org',
      fetchImpl,
    );
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.rule).toBe(UNPROTECTED_UPGRADE_RULE);
    expect(diagnostics[0]?.severity).toBe('error');
  });

  it('emits single-signer-upgrade-admin when upgrade admin is single signer', async () => {
    const fetchImpl = (async (url: string | URL | globalThis.Request, init?: RequestInit) => {
      const u = url.toString();
      if (u.includes('/accounts/')) {
        return new Response(
          JSON.stringify({
            num_signers: 1,
            thresholds: { high_threshold: 1 },
          }),
          { status: 200 },
        );
      }
      const body = JSON.parse(String(init?.body ?? '{}')) as { params?: { keys?: string[] } };
      const key = body.params?.keys?.[0] ?? '';
      const isCode = key.includes('contractCode') || key.length < 50;

      return new Response(
        JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          result: {
            latestLedger: 100_000,
            entries: [
              {
                key,
                xdr: isCode
                  ? codeEntryXdr(wasmWithSpec(['upgrade', 'transfer']))
                  : instanceEntryXdrWithAdmin(CONTRACT, ADMIN_ACCOUNT),
                liveUntilLedgerSeq: 200_000,
              },
            ],
          },
        }),
        { status: 200 },
      );
    }) as unknown as typeof fetch;

    const diagnostics = await auditUpgradeSecurity(
      CONTRACT,
      RPC,
      'https://horizon.stellar.org',
      fetchImpl,
    );
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.rule).toBe(SINGLE_SIGNER_UPGRADE_ADMIN_RULE);
    expect(diagnostics[0]?.severity).toBe('warning');
  });

  it('is silent when upgrade admin is multisig', async () => {
    const fetchImpl = (async (url: string | URL | globalThis.Request, init?: RequestInit) => {
      const u = url.toString();
      if (u.includes('/accounts/')) {
        return new Response(
          JSON.stringify({
            num_signers: 3,
            thresholds: { high_threshold: 2 },
          }),
          { status: 200 },
        );
      }
      const body = JSON.parse(String(init?.body ?? '{}')) as { params?: { keys?: string[] } };
      const key = body.params?.keys?.[0] ?? '';
      const isCode = key.includes('contractCode') || key.length < 50;

      return new Response(
        JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          result: {
            latestLedger: 100_000,
            entries: [
              {
                key,
                xdr: isCode
                  ? codeEntryXdr(wasmWithSpec(['set_wasm', 'transfer']))
                  : instanceEntryXdrWithAdmin(CONTRACT, ADMIN_ACCOUNT),
                liveUntilLedgerSeq: 200_000,
              },
            ],
          },
        }),
        { status: 200 },
      );
    }) as unknown as typeof fetch;

    const diagnostics = await auditUpgradeSecurity(
      CONTRACT,
      RPC,
      'https://horizon.stellar.org',
      fetchImpl,
    );
    expect(diagnostics).toEqual([]);
  });
});

describe('Token Supply Invariant Verifier', () => {
  it('converts amounts to stroops correctly', () => {
    expect(horizonAmountToStroops('100.0000000')).toBe(1_000_000_000n);
    expect(stroopsToAmountString(1_000_000_000n)).toBe('100.0000000');
  });

  it('is silent when Soroban SAC supply matches Horizon classic asset supply within consistent ledger window', async () => {
    const fetchImpl = (async (url: string | URL | globalThis.Request) => {
      const u = url.toString();
      if (u.includes('/assets')) {
        return new Response(
          JSON.stringify({
            _embedded: { records: [{ amount: '1000.0000000' }] },
          }),
          { status: 200 },
        );
      }
      if (u === 'https://horizon.stellar.org') {
        return new Response(JSON.stringify({ history_latest_ledger: 100_002 }), { status: 200 });
      }
      return new Response(
        JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          result: {
            latestLedger: 100_000,
            entries: [
              {
                key: 'k',
                xdr: supplyEntryXdr(CONTRACT, 10_000_000_000n),
                liveUntilLedgerSeq: 200_000,
              },
            ],
          },
        }),
        { status: 200 },
      );
    }) as unknown as typeof fetch;

    const diagnostics = await auditSupplyInvariant(
      CONTRACT,
      'USDC',
      ADMIN_ACCOUNT,
      RPC,
      'https://horizon.stellar.org',
      fetchImpl,
    );
    expect(diagnostics).toEqual([]);
  });

  it('emits supply-invariant-violation when SAC supply diverges from Horizon issued amount', async () => {
    const fetchImpl = (async (url: string | URL | globalThis.Request) => {
      const u = url.toString();
      if (u.includes('/assets')) {
        return new Response(
          JSON.stringify({
            _embedded: { records: [{ amount: '500.0000000' }] },
          }),
          { status: 200 },
        );
      }
      if (u === 'https://horizon.stellar.org') {
        return new Response(JSON.stringify({ history_latest_ledger: 100_001 }), { status: 200 });
      }
      return new Response(
        JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          result: {
            latestLedger: 100_000,
            entries: [
              {
                key: 'k',
                xdr: supplyEntryXdr(CONTRACT, 10_000_000_000n), // 1000.0000000 vs 500.0000000
                liveUntilLedgerSeq: 200_000,
              },
            ],
          },
        }),
        { status: 200 },
      );
    }) as unknown as typeof fetch;

    const diagnostics = await auditSupplyInvariant(
      CONTRACT,
      'USDC',
      ADMIN_ACCOUNT,
      RPC,
      'https://horizon.stellar.org',
      fetchImpl,
    );
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.rule).toBe(SUPPLY_INVARIANT_RULE);
    expect(diagnostics[0]?.severity).toBe('error');
    expect(diagnostics[0]?.message).toContain(
      'Soroban SAC total_supply (1000.0000000) does not match Horizon classic issued supply (500.0000000)',
    );
  });

  it('fails safely when ledger close window consistency cannot be established', async () => {
    const fetchImpl = (async (url: string | URL | globalThis.Request) => {
      const u = url.toString();
      if (u.includes('/assets')) {
        return new Response(
          JSON.stringify({
            _embedded: { records: [{ amount: '500.0000000' }] },
          }),
          { status: 200 },
        );
      }
      if (u === 'https://horizon.stellar.org') {
        return new Response(
          JSON.stringify({ history_latest_ledger: 105_000 }), // 5000 ledgers apart!
          { status: 200 },
        );
      }
      return new Response(
        JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          result: {
            latestLedger: 100_000,
            entries: [
              {
                key: 'k',
                xdr: supplyEntryXdr(CONTRACT, 10_000_000_000n),
                liveUntilLedgerSeq: 200_000,
              },
            ],
          },
        }),
        { status: 200 },
      );
    }) as unknown as typeof fetch;

    const diagnostics = await auditSupplyInvariant(
      CONTRACT,
      'USDC',
      ADMIN_ACCOUNT,
      RPC,
      'https://horizon.stellar.org',
      fetchImpl,
    );
    expect(diagnostics).toEqual([]);
  });

  it('fails safely on Horizon or RPC network failures', async () => {
    const fetchImpl = (async () => {
      throw new Error('Network error');
    }) as unknown as typeof fetch;

    const diagnostics = await auditSupplyInvariant(
      CONTRACT,
      'USDC',
      ADMIN_ACCOUNT,
      RPC,
      'https://horizon.stellar.org',
      fetchImpl,
    );
    expect(diagnostics).toEqual([]);
  });
});
