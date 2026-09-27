import { describe, expect, it } from 'vitest';
import { xdr } from '@stellar/stellar-base';
import {
  LOCKED_ADMIN_RULE,
  SINGLE_SIGNER_RULE,
  adminAuditorRules,
  auditContractAdmin,
  readAdminKey,
} from '../src/soroban/admin-auditor.js';
import {
  adminStorage,
  codeEntryXdr,
  instanceEntryXdr,
  specFunction,
  specWasm,
} from './soroban-fixtures.js';

const CONTRACT = 'CACTZSQPCQSSZ5YG3PI3N7WO6JEERKEUHTPILKB4MBANF2K4D2UHKDDU';
const ACCOUNT = 'GDVEU3DD4KOFECV66VIHWEZOYX4ZKR3WV27L464SIIPOU2IUI3JCZA57';
const WASM_HASH = Buffer.alloc(32, 0x33);
const RPC = 'https://rpc.test';
const HORIZON = 'https://horizon.test';

const upgradeWasm = specWasm([specFunction('upgrade'), specFunction('transfer')]);
const plainWasm = specWasm([specFunction('transfer')]);

interface HorizonAccount {
  masterKeyWeight: number;
  signers: { key: string; weight: number }[];
  medThreshold?: number;
  highThreshold?: number;
}

/** An RPC + Horizon stub for the admin auditor. */
function adminFetch(
  wasm: Buffer,
  account: HorizonAccount,
  storage: xdr.ScMapEntry[] = [adminStorage('admin', ACCOUNT)],
): typeof fetch {
  return (async (url: string | URL | Request, init?: RequestInit) => {
    if (init === undefined || init.body === undefined) {
      return new Response(
        JSON.stringify({
          master_key_weight: account.masterKeyWeight,
          thresholds: {
            med_threshold: account.medThreshold ?? 1,
            high_threshold: account.highThreshold ?? 1,
          },
          signers: account.signers,
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }
    const body = JSON.parse(String(init.body)) as { params: { keys: string[] } };
    const key = body.params.keys[0] as string;
    const kind = xdr.LedgerKey.fromXDR(key, 'base64').switch().name;
    const entryXdr =
      kind === 'contractCode'
        ? codeEntryXdr(wasm, WASM_HASH)
        : instanceEntryXdr({ contractId: CONTRACT, wasmHash: WASM_HASH, storage });
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

describe('soroban admin auditor (#78)', () => {
  it('reads the admin address out of the contract instance storage', () => {
    const instance = instanceEntryXdr({
      contractId: CONTRACT,
      wasmHash: WASM_HASH,
      storage: [adminStorage('owner', ACCOUNT)],
    });
    expect(readAdminKey(instance)).toEqual({ name: 'owner', address: ACCOUNT, kind: 'account' });
  });

  it('passes an admin backed by a healthy multi-signature account', async () => {
    const diagnostics = await auditContractAdmin(
      CONTRACT,
      RPC,
      adminFetch(upgradeWasm, {
        masterKeyWeight: 1,
        signers: [
          { key: ACCOUNT, weight: 1 },
          { key: 'GDVEU3DD4KOFECV66VIHWEZOYX4ZKR3WV27L464SIIPOU2IUI3JCZA57', weight: 1 },
          { key: 'GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H', weight: 1 },
        ],
      }),
      { horizonUrl: HORIZON },
    );

    expect(diagnostics).toEqual([]);
  });

  it('asserts soroban/single-signer-contract-admin for a single-key admin', async () => {
    const diagnostics = await auditContractAdmin(
      CONTRACT,
      RPC,
      adminFetch(plainWasm, {
        masterKeyWeight: 1,
        signers: [{ key: ACCOUNT, weight: 1 }],
      }),
      { horizonUrl: HORIZON },
    );

    expect(diagnostics).toContainEqual(
      expect.objectContaining({ rule: SINGLE_SIGNER_RULE, severity: 'warning' }),
    );
  });

  it('asserts soroban/locked-admin-key when an upgradeable contract is frozen', async () => {
    const diagnostics = await auditContractAdmin(
      CONTRACT,
      RPC,
      adminFetch(upgradeWasm, {
        masterKeyWeight: 0,
        signers: [],
      }),
      { horizonUrl: HORIZON },
    );

    expect(diagnostics).toContainEqual(
      expect.objectContaining({ rule: LOCKED_ADMIN_RULE, severity: 'warning' }),
    );
  });

  it('stays silent when the contract exposes no admin key', async () => {
    const diagnostics = await auditContractAdmin(
      CONTRACT,
      RPC,
      adminFetch(plainWasm, { masterKeyWeight: 1, signers: [] }, []),
      { horizonUrl: HORIZON },
    );
    expect(diagnostics).toEqual([]);
  });

  it('registers both rule definitions', () => {
    expect(adminAuditorRules.map((r) => ({ id: r.id, severity: r.severity }))).toEqual([
      { id: SINGLE_SIGNER_RULE, severity: 'warning' },
      { id: LOCKED_ADMIN_RULE, severity: 'warning' },
    ]);
  });
});
