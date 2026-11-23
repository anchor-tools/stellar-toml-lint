import { describe, expect, it } from 'vitest';
import { Address, xdr } from '@stellar/stellar-base';
import { parse } from 'smol-toml';
import {
  CrossContractReentrancyValidator,
  NON_ATOMIC_CROSS_CALL_RULE,
  RECURSIVE_CONTRACT_CALL_RULE,
  REENTRANCY_MISSING_GUARD_RULE,
  analyzeReentrancy,
  auditWasmReentrancy,
} from '../src/soroban/reentrancyValidator.js';
import { fetchContractWasm, sorobanRuleIds } from '../src/soroban.js';
import { checkContracts } from '../src/rules/soroban.js';

const CONTRACT = 'CACTZSQPCQSSZ5YG3PI3N7WO6JEERKEUHTPILKB4MBANF2K4D2UHKDDU';
const RPC = 'https://soroban-testnet.stellar.org';

// ---------------------------------------------------------------------------
// A tiny WASM assembler for import/call ordering fixtures
// ---------------------------------------------------------------------------

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

function name(text: string): Buffer {
  const bytes = Buffer.from(text, 'utf8');
  return Buffer.concat([u32(bytes.length), bytes]);
}

function vec(items: Buffer[]): Buffer {
  return Buffer.concat([u32(items.length), ...items]);
}

function section(id: number, payload: Buffer): Buffer {
  return Buffer.concat([Buffer.from([id]), u32(payload.length), payload]);
}

function body(instructions: number[]): Buffer {
  const code = Buffer.concat([u32(0), Buffer.from(instructions), Buffer.from([0x0b])]);
  return Buffer.concat([u32(code.length), code]);
}

/** `call <funcIndex>`. */
const call = (index: number): number[] => [0x10, ...u32(index)];

/**
 * Builds a module whose exports are named in insertion order. `bodies` receives
 * the imported-function count so a fixture can address its own defined
 * functions (`imports + j`).
 */
function wasmModule(
  imported: string[],
  exports: Record<string, (imports: number) => number[]>,
): Buffer {
  const names = Object.keys(exports);
  const typeSection = section(1, vec([Buffer.from([0x60, 0x00, 0x00])]));
  const importSection =
    imported.length === 0
      ? undefined
      : section(
          2,
          vec(
            imported.map((field) =>
              Buffer.concat([name('env'), name(field), Buffer.from([0x00]), u32(0)]),
            ),
          ),
        );
  const functionSection = section(3, vec(names.map(() => u32(0))));
  const exportSection = section(
    7,
    vec(
      names.map((n, i) => Buffer.concat([name(n), Buffer.from([0x00]), u32(imported.length + i)])),
    ),
  );
  const codeSection = section(10, vec(names.map((n) => body(exports[n]!(imported.length)))));

  const header = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
  return Buffer.concat([
    header,
    typeSection,
    ...(importSection === undefined ? [] : [importSection]),
    functionSection,
    exportSection,
    codeSection,
  ]);
}

const HOST = ['call', 'try_call', 'put_contract_data', 'del_contract_data', 'get_contract_data'];
const CALL = 0;
const TRY_CALL = 1;
const PUT = 2;
const DEL = 3;

const rulesOf = (diagnostics: { rule: string }[]) => diagnostics.map((d) => d.rule);

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

describe('analyzeReentrancy', () => {
  it('flags an external call followed by a storage write without a prior lock', () => {
    const wasm = wasmModule(HOST, {
      transfer: () => [...call(CALL), ...call(PUT)],
    });
    const analysis = analyzeReentrancy(wasm);

    expect(analysis?.functions[0]).toMatchObject({
      name: 'transfer',
      externalCalls: ['call'],
      lockedBeforeExternalCall: false,
      writesAfterExternalCall: true,
      fallibleExternalCall: false,
    });
  });

  it('accepts a lock (storage write) taken before the external call', () => {
    const wasm = wasmModule(HOST, {
      transfer: () => [...call(PUT), ...call(CALL)],
    });
    const analysis = analyzeReentrancy(wasm);

    expect(analysis?.functions[0]).toMatchObject({
      lockedBeforeExternalCall: true,
      writesAfterExternalCall: false,
    });
  });

  it('records try_call as a fallible external call', () => {
    const wasm = wasmModule(HOST, {
      swap: () => [...call(TRY_CALL), ...call(PUT)],
    });
    expect(analyzeReentrancy(wasm)?.functions[0]).toMatchObject({
      externalCalls: ['try_call'],
      fallibleExternalCall: true,
      writesAfterExternalCall: true,
    });
  });

  it('builds the internal call graph and detects self-recursion', () => {
    const wasm = wasmModule(HOST, {
      loop: (imports) => call(imports),
    });
    const analysis = analyzeReentrancy(wasm);

    expect(analysis?.callGraph).toEqual([{ from: 0, to: 0 }]);
    expect(analysis?.recursiveCycles).toEqual([[0]]);
  });

  it('detects mutual recursion', () => {
    const wasm = wasmModule(HOST, {
      a: (imports) => call(imports + 1),
      b: (imports) => call(imports),
    });
    const analysis = analyzeReentrancy(wasm);

    expect(analysis?.recursiveCycles).toHaveLength(1);
    expect((analysis?.recursiveCycles[0] ?? []).sort()).toEqual([0, 1]);
  });

  it('returns undefined for bytes that are not a module', () => {
    expect(analyzeReentrancy(Buffer.from('not wasm'))).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

describe('auditWasmReentrancy', () => {
  it('errors on interactions-before-effects', () => {
    const wasm = wasmModule(HOST, { transfer: () => [...call(CALL), ...call(PUT)] });
    const diagnostics = auditWasmReentrancy(CONTRACT, wasm);

    expect(rulesOf(diagnostics)).toEqual([REENTRANCY_MISSING_GUARD_RULE]);
    expect(diagnostics[0]).toMatchObject({ severity: 'error', category: 'network' });
    expect(diagnostics[0]?.message).toContain('function `transfer`');
  });

  it('passes a contract that locks before calling out', () => {
    const wasm = wasmModule(HOST, {
      transfer: () => [...call(PUT), ...call(CALL), ...call(DEL)],
    });
    expect(auditWasmReentrancy(CONTRACT, wasm)).toEqual([]);
  });

  it('warns when state is written after a fallible try_call', () => {
    const wasm = wasmModule(HOST, { swap: () => [...call(TRY_CALL), ...call(PUT)] });
    const diagnostics = auditWasmReentrancy(CONTRACT, wasm);

    expect(rulesOf(diagnostics)).toEqual([
      REENTRANCY_MISSING_GUARD_RULE,
      NON_ATOMIC_CROSS_CALL_RULE,
    ]);
    expect(diagnostics[1]).toMatchObject({ severity: 'warning' });
  });

  it('errors on recursion that reaches an external call', () => {
    const wasm = wasmModule(HOST, {
      loop: (imports) => [...call(CALL), ...call(imports)],
    });
    const diagnostics = auditWasmReentrancy(CONTRACT, wasm);

    expect(rulesOf(diagnostics)).toEqual([RECURSIVE_CONTRACT_CALL_RULE]);
    expect(diagnostics[0]?.message).toContain('call graph is recursive (loop)');
  });

  it('does not flag pure internal recursion with no external call', () => {
    const wasm = wasmModule(HOST, { loop: (imports) => call(imports) });
    expect(auditWasmReentrancy(CONTRACT, wasm)).toEqual([]);
  });

  it('honours rule overrides', () => {
    const wasm = wasmModule(HOST, { transfer: () => [...call(CALL), ...call(PUT)] });
    expect(
      auditWasmReentrancy(CONTRACT, wasm, {
        rules: { [REENTRANCY_MISSING_GUARD_RULE]: 'off' },
      }),
    ).toEqual([]);
  });
});

describe('CrossContractReentrancyValidator', () => {
  it('audits a set of contracts and keeps findings per contract', () => {
    const vulnerable = wasmModule(HOST, { transfer: () => [...call(CALL), ...call(PUT)] });
    const safe = wasmModule(HOST, { transfer: () => [...call(PUT), ...call(CALL)] });
    const diagnostics = new CrossContractReentrancyValidator().audit([
      { id: CONTRACT, wasm: vulnerable },
      { id: 'CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE', wasm: safe },
    ]);

    expect(rulesOf(diagnostics)).toEqual([REENTRANCY_MISSING_GUARD_RULE]);
    expect(diagnostics[0]?.message).toContain(CONTRACT);
  });
});

// ---------------------------------------------------------------------------
// Deployment integration
// ---------------------------------------------------------------------------

const WASM_HASH = Buffer.alloc(32, 9);

function instanceEntryXdr(): string {
  return xdr.LedgerEntryData.contractData(
    new xdr.ContractDataEntry({
      ext: xdr.ExtensionPoint.fromXDR(Buffer.alloc(4), 'raw'),
      contract: new Address(CONTRACT).toScAddress(),
      key: xdr.ScVal.scvLedgerKeyContractInstance(),
      durability: xdr.ContractDataDurability.persistent(),
      val: xdr.ScVal.scvContractInstance(
        new xdr.ScContractInstance({
          executable: xdr.ContractExecutable.contractExecutableWasm(WASM_HASH),
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
      hash: WASM_HASH,
      code: wasm,
    }),
  ).toXDR('base64');
}

function rpcServing(wasm: Buffer): typeof fetch {
  return (async (_url: string | URL | globalThis.Request, init?: RequestInit) => {
    const request = JSON.parse(String(init?.body)) as { params: { keys: string[] } };
    const key = request.params.keys[0] as string;
    const isCode = xdr.LedgerKey.fromXDR(key, 'base64').switch().name === 'contractCode';
    const entryXdr = isCode ? codeEntryXdr(wasm) : instanceEntryXdr();
    return new Response(
      JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        result: {
          latestLedger: 100_000,
          entries: [{ key, xdr: entryXdr, lastModifiedLedgerSeq: 1, liveUntilLedgerSeq: 200_000 }],
        },
      }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );
  }) as unknown as typeof fetch;
}

describe('reentrancy integration', () => {
  const doc = parse(
    [
      'NETWORK_PASSPHRASE = "Test SDF Network ; September 2015"',
      '[[CURRENCIES]]',
      'code = "USDC"',
      `contract = "${CONTRACT}"`,
    ].join('\n'),
  ) as Record<string, unknown>;

  it('fetches the deployed WASM and reports the vulnerable ordering', async () => {
    const wasm = wasmModule(HOST, { transfer: () => [...call(CALL), ...call(PUT)] });
    const fetched = await fetchContractWasm(CONTRACT, RPC, rpcServing(wasm));
    expect(fetched).toBeDefined();

    const diagnostics = await checkContracts(doc, rpcServing(wasm), {
      rpcUrl: RPC,
      horizonUrl: 'http://horizon.invalid',
      auditReentrancy: true,
    });
    expect(rulesOf(diagnostics)).toContain(REENTRANCY_MISSING_GUARD_RULE);
  });

  it('stays silent when the flag is off', async () => {
    const wasm = wasmModule(HOST, { transfer: () => [...call(CALL), ...call(PUT)] });
    const diagnostics = await checkContracts(doc, rpcServing(wasm), {
      rpcUrl: RPC,
      horizonUrl: 'http://horizon.invalid',
    });
    expect(rulesOf(diagnostics)).not.toContain(REENTRANCY_MISSING_GUARD_RULE);
  });

  it('registers every rule id', () => {
    for (const rule of [
      REENTRANCY_MISSING_GUARD_RULE,
      NON_ATOMIC_CROSS_CALL_RULE,
      RECURSIVE_CONTRACT_CALL_RULE,
    ]) {
      expect(sorobanRuleIds).toContain(rule);
    }
  });
});
