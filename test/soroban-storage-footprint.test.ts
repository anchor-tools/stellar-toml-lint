import { describe, expect, it } from 'vitest';
import { xdr } from '@stellar/stellar-base';
import {
  HIGH_STORAGE_FOOTPRINT_RULE,
  TTL_EXPIRING_SOON_RULE,
  TTL_EXPIRING_THRESHOLD_LEDGERS,
  auditContractStorageFootprint,
  auditTomlStorageFootprint,
  calculateProjectedRent,
  calculateStorageFootprint,
  estimateTtlExpiration,
  getContractStorageFootprint,
  storageFootprintRules,
} from '../src/soroban/storage-footprint.js';
import { codeEntryXdr, instanceEntryXdr } from './soroban-fixtures.js';

const CONTRACT = 'CACTZSQPCQSSZ5YG3PI3N7WO6JEERKEUHTPILKB4MBANF2K4D2UHKDDU';
const WASM_HASH = Buffer.alloc(32, 0x55);
const RPC = 'https://rpc.test';

function mockStorageRpc(options: {
  latestLedger: number;
  instanceLiveUntil?: number;
  codeLiveUntil?: number;
  wasmSize?: number;
}): typeof fetch {
  const wasm = Buffer.alloc(options.wasmSize ?? 1024, 0x01);
  const instanceXdr = instanceEntryXdr({ contractId: CONTRACT, wasmHash: WASM_HASH });
  const codeXdr = codeEntryXdr(wasm, WASM_HASH);

  return (async (_url: string | URL | Request, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)) as { params: { keys: string[] } };
    const key = body.params.keys[0] as string;
    const kind = xdr.LedgerKey.fromXDR(key, 'base64').switch().name;

    if (kind === 'contractCode') {
      return new Response(
        JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          result: {
            latestLedger: options.latestLedger,
            entries:
              options.codeLiveUntil !== undefined
                ? [{ xdr: codeXdr, liveUntilLedgerSeq: options.codeLiveUntil }]
                : [],
          },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }

    return new Response(
      JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        result: {
          latestLedger: options.latestLedger,
          entries:
            options.instanceLiveUntil !== undefined
              ? [{ xdr: instanceXdr, liveUntilLedgerSeq: options.instanceLiveUntil }]
              : [],
        },
      }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );
  }) as unknown as typeof fetch;
}

describe('soroban storage footprint analyzer (#75)', () => {
  it('calculates storage footprint and projected rent costs accurately', () => {
    const total = calculateStorageFootprint(256, 1024);
    expect(total).toBe(1280);

    const rent = calculateProjectedRent(100_000, 100_000, 0.000025);
    expect(rent).toBe(2.5);
  });

  it('estimates TTL expiration and flags expiring soon within 30 days', () => {
    const healthy = estimateTtlExpiration(1000, 1000 + TTL_EXPIRING_THRESHOLD_LEDGERS + 1000);
    expect(healthy.isExpiringSoon).toBe(false);
    expect(healthy.remainingLedgers).toBe(TTL_EXPIRING_THRESHOLD_LEDGERS + 1000);

    const expiring = estimateTtlExpiration(1000, 1000 + TTL_EXPIRING_THRESHOLD_LEDGERS - 10);
    expect(expiring.isExpiringSoon).toBe(true);
    expect(expiring.remainingDays).toBeLessThanOrEqual(30);
  });

  it('passes a healthy contract with sufficient TTL and low storage footprint', async () => {
    const fetchImpl = mockStorageRpc({
      latestLedger: 1_000_000,
      instanceLiveUntil: 1_000_000 + TTL_EXPIRING_THRESHOLD_LEDGERS + 50_000,
      codeLiveUntil: 1_000_000 + TTL_EXPIRING_THRESHOLD_LEDGERS + 50_000,
      wasmSize: 1024,
    });

    const diagnostics = await auditContractStorageFootprint(CONTRACT, RPC, fetchImpl);
    expect(diagnostics).toEqual([]);
  });

  it('asserts soroban/ttl-expiring-soon when TTL is within 30 days', async () => {
    const fetchImpl = mockStorageRpc({
      latestLedger: 1_000_000,
      instanceLiveUntil: 1_000_000 + 10_000, // ~14 hours left
      codeLiveUntil: 1_000_000 + 10_000,
      wasmSize: 1024,
    });

    const diagnostics = await auditContractStorageFootprint(CONTRACT, RPC, fetchImpl);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: TTL_EXPIRING_SOON_RULE,
        severity: 'error',
      }),
    );
  });

  it('asserts soroban/high-storage-footprint when total bytes exceed threshold', async () => {
    const fetchImpl = mockStorageRpc({
      latestLedger: 1_000_000,
      instanceLiveUntil: 1_000_000 + TTL_EXPIRING_THRESHOLD_LEDGERS + 50_000,
      codeLiveUntil: 1_000_000 + TTL_EXPIRING_THRESHOLD_LEDGERS + 50_000,
      wasmSize: 100 * 1024, // 100 KB exceeds default 64 KB
    });

    const diagnostics = await auditContractStorageFootprint(CONTRACT, RPC, fetchImpl, {
      maxStorageBytes: 64 * 1024,
    });

    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: HIGH_STORAGE_FOOTPRINT_RULE,
        severity: 'warning',
      }),
    );
  });

  it('fetches contract footprint status structure with getContractStorageFootprint', async () => {
    const fetchImpl = mockStorageRpc({
      latestLedger: 1000,
      instanceLiveUntil: 2000,
      codeLiveUntil: 2000,
      wasmSize: 2048,
    });

    const footprint = await getContractStorageFootprint(CONTRACT, RPC, fetchImpl);
    expect(footprint).toBeDefined();
    expect(footprint?.totalBytes).toBeGreaterThan(2000);
    expect(footprint?.instanceTtl?.remainingLedgers).toBe(1000);
  });

  it('audits declared contracts in a stellar.toml document', async () => {
    const fetchImpl = mockStorageRpc({
      latestLedger: 1_000_000,
      instanceLiveUntil: 1_000_000 + 100, // expiring soon
      codeLiveUntil: 1_000_000 + 100,
    });

    const doc = {
      NETWORK_PASSPHRASE: 'Test SDF Network ; September 2015',
      CURRENCIES: [{ code: 'TEST', contract: CONTRACT }],
    };

    const diagnostics = await auditTomlStorageFootprint(doc, fetchImpl);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: TTL_EXPIRING_SOON_RULE,
        severity: 'error',
      }),
    );
  });

  it('registers all storage footprint rule definitions', () => {
    expect(storageFootprintRules.map((r) => ({ id: r.id, severity: r.severity }))).toEqual([
      { id: TTL_EXPIRING_SOON_RULE, severity: 'error' },
      { id: HIGH_STORAGE_FOOTPRINT_RULE, severity: 'warning' },
    ]);
  });
});
