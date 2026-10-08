import { describe, expect, it } from 'vitest';
import { xdr } from '@stellar/stellar-base';
import {
  MISSING_AUTH_PARAMETER_RULE,
  UNSAFE_UNAUTHORIZED_MINT_RULE,
  auditContractAuth,
  auditTomlContractAuth,
  authAuditorRules,
  verifyContractAuth,
} from '../src/soroban/auth-auditor.js';
import { codeEntryXdr, instanceEntryXdr, specWasm } from './soroban-fixtures.js';

const CONTRACT = 'CACTZSQPCQSSZ5YG3PI3N7WO6JEERKEUHTPILKB4MBANF2K4D2UHKDDU';
const WASM_HASH = Buffer.alloc(32, 0x77);
const RPC = 'https://rpc.test';

function makeSpecFunction(
  name: string,
  inputs: { name: string; type: string }[] = [],
): xdr.ScSpecEntry {
  const params = inputs.map(
    (input) =>
      new xdr.ScSpecFunctionInputV0({
        doc: '',
        name: input.name,
        type:
          input.type === 'scSpecTypeAddress'
            ? xdr.ScSpecTypeDef.scSpecTypeAddress()
            : input.type === 'scSpecTypeString'
              ? xdr.ScSpecTypeDef.scSpecTypeString()
              : input.type === 'scSpecTypeU32'
                ? xdr.ScSpecTypeDef.scSpecTypeU32()
                : xdr.ScSpecTypeDef.scSpecTypeI128(),
      }),
  );
  return xdr.ScSpecEntry.scSpecEntryFunctionV0(
    new xdr.ScSpecFunctionV0({ doc: '', name, inputs: params, outputs: [] }),
  );
}

function mockAuthRpc(wasm: Buffer): typeof fetch {
  const instanceXdr = instanceEntryXdr({ contractId: CONTRACT, wasmHash: WASM_HASH });
  const codeXdr = codeEntryXdr(wasm, WASM_HASH);

  return (async (_url: string | URL | Request, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)) as { params: { keys: string[] } };
    const key = body.params.keys[0] as string;
    const kind = xdr.LedgerKey.fromXDR(key, 'base64').switch().name;
    const entryXdr = kind === 'contractCode' ? codeXdr : instanceXdr;

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

describe('soroban cross-contract authorization auditor (#76)', () => {
  it('passes a contract with correct Address auth parameters', async () => {
    const wasm = specWasm([
      makeSpecFunction('mint', [
        { name: 'to', type: 'scSpecTypeAddress' },
        { name: 'amount', type: 'scSpecTypeI128' },
      ]),
      makeSpecFunction('transfer', [
        { name: 'from', type: 'scSpecTypeAddress' },
        { name: 'to', type: 'scSpecTypeAddress' },
        { name: 'amount', type: 'scSpecTypeI128' },
      ]),
      makeSpecFunction('burn', [
        { name: 'from', type: 'scSpecTypeAddress' },
        { name: 'amount', type: 'scSpecTypeI128' },
      ]),
      makeSpecFunction('set_admin', [{ name: 'new_admin', type: 'scSpecTypeAddress' }]),
    ]);

    const diagnostics = await auditContractAuth(CONTRACT, RPC, mockAuthRpc(wasm));
    expect(diagnostics).toEqual([]);
  });

  it('asserts soroban/unsafe-unauthorized-mint on an unparameterized mint function', async () => {
    const wasm = specWasm([
      makeSpecFunction('mint', []), // unparameterized mint
    ]);

    const diagnostics = verifyContractAuth(wasm, CONTRACT);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: UNSAFE_UNAUTHORIZED_MINT_RULE,
        severity: 'error',
      }),
    );
  });

  it('asserts soroban/unsafe-unauthorized-mint when mint takes no Address parameter', async () => {
    const wasm = specWasm([makeSpecFunction('mint', [{ name: 'amount', type: 'scSpecTypeI128' }])]);

    const diagnostics = verifyContractAuth(wasm, CONTRACT);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: UNSAFE_UNAUTHORIZED_MINT_RULE,
        severity: 'error',
      }),
    );
  });

  it('asserts soroban/missing-auth-parameter when set_admin lacks Address parameter', async () => {
    const wasm = specWasm([
      makeSpecFunction('set_admin', [{ name: 'flag', type: 'scSpecTypeU32' }]),
    ]);

    const diagnostics = verifyContractAuth(wasm, CONTRACT);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: MISSING_AUTH_PARAMETER_RULE,
        severity: 'error',
      }),
    );
  });

  it('asserts soroban/missing-auth-parameter when transfer lacks Address parameter', async () => {
    const wasm = specWasm([
      makeSpecFunction('transfer', [{ name: 'amount', type: 'scSpecTypeI128' }]),
    ]);

    const diagnostics = verifyContractAuth(wasm, CONTRACT);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: MISSING_AUTH_PARAMETER_RULE,
        severity: 'error',
      }),
    );
  });

  it('asserts soroban/missing-auth-parameter when burn lacks Address parameter', async () => {
    const wasm = specWasm([makeSpecFunction('burn', [{ name: 'amount', type: 'scSpecTypeI128' }])]);

    const diagnostics = verifyContractAuth(wasm, CONTRACT);
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: MISSING_AUTH_PARAMETER_RULE,
        severity: 'error',
      }),
    );
  });

  it('stays silent for WASM missing contractspecv0 or non-contract modules', () => {
    const emptyWasm = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
    const diagnostics = verifyContractAuth(emptyWasm, CONTRACT);
    expect(diagnostics).toEqual([]);
  });

  it('audits declared contracts in a stellar.toml document', async () => {
    const wasm = specWasm([makeSpecFunction('mint', [])]);

    const doc = {
      NETWORK_PASSPHRASE: 'Test SDF Network ; September 2015',
      CURRENCIES: [{ code: 'TEST', contract: CONTRACT }],
    };

    const diagnostics = await auditTomlContractAuth(doc, mockAuthRpc(wasm));
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: UNSAFE_UNAUTHORIZED_MINT_RULE,
        severity: 'error',
      }),
    );
  });

  it('registers all authorization auditor rule definitions', () => {
    expect(authAuditorRules.map((r) => ({ id: r.id, severity: r.severity }))).toEqual([
      { id: MISSING_AUTH_PARAMETER_RULE, severity: 'error' },
      { id: UNSAFE_UNAUTHORIZED_MINT_RULE, severity: 'error' },
    ]);
  });
});
