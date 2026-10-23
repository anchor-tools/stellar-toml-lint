import { describe, expect, it } from 'vitest';
import { StrKey, xdr } from '@stellar/stellar-base';
import { lint } from '../src/lint.js';
import { allRules } from '../src/rules/index.js';
import {
  BYTE_MISMATCH_RULE,
  PARITY_NETWORKS,
  SPEC_DRIFT_RULE,
  auditContractParity,
  auditTomlContractParity,
  extractSpecFunctions,
  verifyParity,
} from '../src/soroban/parity-verifier.js';
import {
  codeEntryXdr,
  instanceEntryXdr,
  rpcFetch,
  specFunction,
  specWasm,
} from './soroban-fixtures.js';

const CONTRACT = 'CACTZSQPCQSSZ5YG3PI3N7WO6JEERKEUHTPILKB4MBANF2K4D2UHKDDU';
const AUTH_CONTRACT = StrKey.encodeContract(Buffer.alloc(32, 2));

function specWasmWithDoc(name: string, doc: string): Buffer {
  return specWasm([
    xdr.ScSpecEntry.scSpecEntryFunctionV0(
      new xdr.ScSpecFunctionV0({ doc, name, inputs: [], outputs: [] }),
    ),
  ]);
}

function networkFetch(
  wasmByNetwork: Partial<Record<string, Buffer>>,
  unreachable: readonly string[] = [],
): typeof fetch {
  const stubs = new Map<string, typeof fetch>();
  for (const target of PARITY_NETWORKS) {
    const wasm = wasmByNetwork[target.name];
    if (wasm === undefined) continue;
    const wasmHash = Buffer.alloc(32, target.name.length);
    stubs.set(
      target.rpcUrl,
      rpcFetch(instanceEntryXdr({ contractId: CONTRACT, wasmHash }), codeEntryXdr(wasm, wasmHash))
        .fetchImpl,
    );
  }

  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const target = PARITY_NETWORKS.find((candidate) => candidate.rpcUrl === url);
    if (target === undefined) throw new TypeError('unexpected RPC URL');
    if (unreachable.includes(target.name)) throw new TypeError('fetch failed');

    const stub = stubs.get(url);
    if (stub === undefined) {
      return new Response(JSON.stringify({ result: { latestLedger: 100, entries: [] } }), {
        status: 200,
      });
    }
    return stub(input, init);
  }) as unknown as typeof fetch;
}

describe('multi-network Soroban parity verifier (#284)', () => {
  it('reads exported functions from contractspecv0', () => {
    expect(
      extractSpecFunctions(specWasm([specFunction('transfer'), specFunction('burn')])),
    ).toEqual({
      functions: [
        { name: 'transfer', signature: '->' },
        { name: 'burn', signature: '->' },
      ],
      malformed: false,
    });
  });

  it('passes matching deployments', () => {
    const wasm = specWasm([specFunction('transfer')]);
    expect(
      verifyParity(CONTRACT, [
        { network: 'mainnet', wasm },
        { network: 'testnet', wasm },
      ]),
    ).toEqual([]);
  });

  it('warns when bytecode differs but the interface is the same', () => {
    const diagnostics = verifyParity(CONTRACT, [
      { network: 'mainnet', wasm: specWasmWithDoc('transfer', '') },
      { network: 'testnet', wasm: specWasmWithDoc('transfer', 'updated docs') },
    ]);

    expect(diagnostics).toEqual([
      expect.objectContaining({ rule: BYTE_MISMATCH_RULE, severity: 'warning' }),
    ]);
  });

  it('errors when the exported interface drifts', () => {
    const diagnostics = verifyParity(CONTRACT, [
      { network: 'mainnet', wasm: specWasm([specFunction('transfer')]) },
      { network: 'testnet', wasm: specWasm([specFunction('burn')]) },
    ]);

    expect(diagnostics).toContainEqual(
      expect.objectContaining({ rule: SPEC_DRIFT_RULE, severity: 'error' }),
    );
  });

  it('queries every known network and ignores absent or unreachable deployments', async () => {
    const wasm = specWasm([specFunction('transfer')]);
    const diagnostics = await auditContractParity(
      CONTRACT,
      networkFetch({ mainnet: wasm, testnet: wasm }, ['futurenet']),
    );

    expect(diagnostics).toEqual([]);
  });

  it('audits every contract declared by the file', async () => {
    const source = [
      'NETWORK_PASSPHRASE="Test SDF Network ; September 2015"',
      '',
      '[[CURRENCIES]]',
      'code="TOKEN"',
      `contract="${CONTRACT}"`,
      '',
      `WEB_AUTH_CONTRACT_ID="${AUTH_CONTRACT}"`,
    ].join('\n');
    const doc = lint(source).parsed ?? {};
    const wasm = specWasm([specFunction('transfer')]);

    const diagnostics = await auditTomlContractParity(
      doc,
      networkFetch({ mainnet: wasm, testnet: wasm }),
    );

    expect(diagnostics).toEqual([]);
  });

  it('registers both rule definitions', () => {
    const ids = allRules.map((rule) => rule.id);
    expect(ids).toEqual(expect.arrayContaining([BYTE_MISMATCH_RULE, SPEC_DRIFT_RULE]));
  });
});
