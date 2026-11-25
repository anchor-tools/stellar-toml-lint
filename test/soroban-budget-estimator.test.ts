import { describe, expect, it } from 'vitest';
import { Address, xdr } from '@stellar/stellar-base';
import { parse } from 'smol-toml';
import {
  DEFAULT_MAX_CYCLOMATIC_COMPLEXITY,
  EXCESSIVE_STATIC_MEMORY_RULE,
  HIGH_CYCLOMATIC_COMPLEXITY_RULE,
  budgetDiagnostics,
  estimateWasmBudget,
} from '../src/soroban/budget-estimator.js';
import { checkContracts } from '../src/rules/soroban.js';
import { auditContractBudget, sorobanRuleIds } from '../src/soroban.js';

const CONTRACT = 'CACTZSQPCQSSZ5YG3PI3N7WO6JEERKEUHTPILKB4MBANF2K4D2UHKDDU';
const RPC = 'https://soroban-testnet.stellar.org';

// ---------------------------------------------------------------------------
// A tiny WASM assembler — just enough sections to describe a token contract
// ---------------------------------------------------------------------------

/** Unsigned LEB128. */
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

/** A function body: no locals, the given instructions, then `end`. */
function body(instructions: number[]): Buffer {
  const code = Buffer.concat([u32(0), Buffer.from(instructions), Buffer.from([0x0b])]);
  return Buffer.concat([u32(code.length), code]);
}

/** `if` over a constant condition with an empty block: one decision point. */
const IF_BLOCK = [0x41, 0x01, 0x04, 0x40, 0x0b];

interface ModuleOptions {
  minPages: number;
  maxPages?: number;
  /** Exported function name → number of `if` decision points in its body. */
  functions: Record<string, number>;
  /** Number of imported host functions (shifts function indices). */
  imports?: number;
  /** Byte length of one active data segment, if any. */
  dataBytes?: number;
  /** Raw body instructions that override the generated ones, by name. */
  rawBodies?: Record<string, number[]>;
}

function wasmModule(options: ModuleOptions): Buffer {
  const names = Object.keys(options.functions);
  const imports = options.imports ?? 0;

  const typeSection = section(1, vec([Buffer.from([0x60, 0x00, 0x00])])); // () -> ()
  const importSection = section(
    2,
    vec(
      Array.from({ length: imports }, (_, i) =>
        Buffer.concat([name('x'), name(`h${i}`), Buffer.from([0x00]), u32(0)]),
      ),
    ),
  );
  const functionSection = section(3, vec(names.map(() => u32(0))));
  const limits =
    options.maxPages === undefined
      ? Buffer.concat([Buffer.from([0x00]), u32(options.minPages)])
      : Buffer.concat([Buffer.from([0x01]), u32(options.minPages), u32(options.maxPages)]);
  const memorySection = section(5, vec([limits]));
  const exportSection = section(
    7,
    vec(names.map((n, i) => Buffer.concat([name(n), Buffer.from([0x00]), u32(imports + i)]))),
  );
  const codeSection = section(
    10,
    vec(
      names.map((n) =>
        body(
          options.rawBodies?.[n] ??
            Array.from({ length: options.functions[n] ?? 0 }, () => IF_BLOCK).flat(),
        ),
      ),
    ),
  );
  const sections = [typeSection];
  if (imports > 0) sections.push(importSection);
  sections.push(functionSection, memorySection, exportSection, codeSection);
  if (options.dataBytes !== undefined) {
    // flags 0 = active in memory 0, offset `i32.const 1024`, then the bytes.
    const segment = Buffer.concat([
      u32(0),
      Buffer.from([0x41, 0x80, 0x08, 0x0b]),
      u32(options.dataBytes),
      Buffer.alloc(options.dataBytes),
    ]);
    sections.push(section(11, vec([segment])));
  }

  const header = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
  return Buffer.concat([header, ...sections]);
}

/** A well-behaved SEP-41 token: small memory, simple entry points. */
function standardToken(): Buffer {
  return wasmModule({
    minPages: 2,
    imports: 3,
    dataBytes: 512,
    functions: { balance: 1, transfer: 3, transfer_from: 4, approve: 2, decimals: 0, init: 0 },
  });
}

// ---------------------------------------------------------------------------
// RPC mock — the same getLedgerEntries shape the other contract checks use
// ---------------------------------------------------------------------------

function instanceEntryXdr(): string {
  return xdr.LedgerEntryData.contractData(
    new xdr.ContractDataEntry({
      ext: xdr.ExtensionPoint.fromXDR(Buffer.alloc(4), 'raw'),
      contract: new Address(CONTRACT).toScAddress(),
      key: xdr.ScVal.scvLedgerKeyContractInstance(),
      durability: xdr.ContractDataDurability.persistent(),
      val: xdr.ScVal.scvContractInstance(
        new xdr.ScContractInstance({
          executable: xdr.ContractExecutable.contractExecutableWasm(Buffer.alloc(32)),
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
      hash: Buffer.alloc(32),
      code: wasm,
    }),
  ).toXDR('base64');
}

function rpcServing(wasm: Buffer | undefined): typeof fetch {
  return (async (_url: string | URL | globalThis.Request, init?: RequestInit) => {
    const request = JSON.parse(String(init?.body)) as { params: { keys: string[] } };
    const key = request.params.keys[0] as string;
    const isCode = xdr.LedgerKey.fromXDR(key, 'base64').switch().name === 'contractCode';
    const entryXdr = isCode
      ? wasm === undefined
        ? undefined
        : codeEntryXdr(wasm)
      : instanceEntryXdr();
    const entries =
      entryXdr === undefined
        ? []
        : [{ key, xdr: entryXdr, lastModifiedLedgerSeq: 1, liveUntilLedgerSeq: 200_000 }];
    return new Response(
      JSON.stringify({ jsonrpc: '2.0', id: 1, result: { latestLedger: 100_000, entries } }),
      {
        status: 200,
        headers: { 'content-type': 'application/json' },
      },
    );
  }) as unknown as typeof fetch;
}

const rulesOf = (diagnostics: { rule: string }[]) => diagnostics.map((d) => d.rule);

// ---------------------------------------------------------------------------

describe('estimateWasmBudget', () => {
  it('reads memory limits, static data, and SEP-41 complexity from a token module', () => {
    const estimate = estimateWasmBudget(standardToken());

    expect(estimate).toEqual({
      memory: { minPages: 2, maxPages: undefined },
      staticDataBytes: 512,
      // `init` is not a SEP-41 function, so it is not measured. Imported host
      // functions shift the indices, which must not misattribute bodies.
      complexity: { balance: 2, transfer: 4, transfer_from: 5, approve: 3, decimals: 1 },
    });
  });

  it('reads a declared maximum', () => {
    const estimate = estimateWasmBudget(wasmModule({ minPages: 1, maxPages: 32, functions: {} }));
    expect(estimate?.memory).toEqual({ minPages: 1, maxPages: 32 });
  });

  it('counts each br_if and each extra br_table target as a decision point', () => {
    const wasm = wasmModule({
      minPages: 1,
      functions: { transfer: 0 },
      rawBodies: {
        // block, br_if 0, br_table [0 0] default 0, end
        transfer: [
          0x02, 0x40, 0x41, 0x00, 0x0d, 0x00, 0x41, 0x00, 0x0e, 0x02, 0x00, 0x00, 0x00, 0x0b,
        ],
      },
    });
    expect(estimateWasmBudget(wasm)?.complexity).toEqual({ transfer: 1 + 1 + 2 });
  });

  it('leaves out a function that uses an instruction it cannot decode', () => {
    const wasm = wasmModule({
      minPages: 1,
      functions: { balance: 1, transfer: 0 },
      rawBodies: { transfer: [0xfd, 0x00] }, // SIMD prefix — not used by Soroban
    });
    expect(estimateWasmBudget(wasm)?.complexity).toEqual({ balance: 2 });
  });

  it('returns undefined for bytes that are not a WASM module', () => {
    expect(estimateWasmBudget(Buffer.from('not wasm'))).toBeUndefined();
    expect(estimateWasmBudget(standardToken().subarray(0, 20))).toBeUndefined();
  });
});

describe('budgetDiagnostics', () => {
  it('passes a standard token contract', () => {
    const estimate = estimateWasmBudget(standardToken())!;
    expect(budgetDiagnostics(CONTRACT, estimate)).toEqual([]);
  });

  it('flags a module that reserves more than 10 memory pages', () => {
    const estimate = estimateWasmBudget(wasmModule({ minPages: 17, functions: { balance: 0 } }))!;
    const diagnostics = budgetDiagnostics(CONTRACT, estimate);

    expect(rulesOf(diagnostics)).toEqual([EXCESSIVE_STATIC_MEMORY_RULE]);
    expect(diagnostics[0]).toMatchObject({ severity: 'warning', category: 'network' });
    expect(diagnostics[0]?.message).toContain('17 WASM memory pages (1088 KiB)');
  });

  it('does not flag exactly 10 pages', () => {
    const estimate = estimateWasmBudget(wasmModule({ minPages: 10, functions: {} }))!;
    expect(budgetDiagnostics(CONTRACT, estimate)).toEqual([]);
  });

  it('flags a SEP-41 function above the complexity limit', () => {
    const decisions = DEFAULT_MAX_CYCLOMATIC_COMPLEXITY; // complexity = decisions + 1
    const estimate = estimateWasmBudget(
      wasmModule({ minPages: 1, functions: { transfer: decisions, balance: 1 } }),
    )!;
    const diagnostics = budgetDiagnostics(CONTRACT, estimate);

    expect(rulesOf(diagnostics)).toEqual([HIGH_CYCLOMATIC_COMPLEXITY_RULE]);
    expect(diagnostics[0]?.message).toContain('`transfer` has cyclomatic complexity 51');
  });

  it('honours custom limits and rule overrides', () => {
    const estimate = estimateWasmBudget(wasmModule({ minPages: 12, functions: { transfer: 5 } }))!;

    expect(
      budgetDiagnostics(CONTRACT, estimate, {
        maxStaticMemoryPages: 16,
        maxCyclomaticComplexity: 3,
      }).map((d) => d.rule),
    ).toEqual([HIGH_CYCLOMATIC_COMPLEXITY_RULE]);
    expect(
      budgetDiagnostics(CONTRACT, estimate, {
        rules: { [EXCESSIVE_STATIC_MEMORY_RULE]: 'error' },
      })[0],
    ).toMatchObject({ rule: EXCESSIVE_STATIC_MEMORY_RULE, severity: 'error' });
    expect(
      budgetDiagnostics(CONTRACT, estimate, { rules: { [EXCESSIVE_STATIC_MEMORY_RULE]: 'off' } }),
    ).toEqual([]);
  });
});

describe('auditContractBudget', () => {
  it('passes a standard token contract fetched from the RPC', async () => {
    expect(await auditContractBudget(CONTRACT, RPC, rpcServing(standardToken()))).toEqual([]);
  });

  it('flags excessive memory pages on a deployed contract', async () => {
    const wasm = wasmModule({ minPages: 20, functions: { balance: 0 } });
    expect(rulesOf(await auditContractBudget(CONTRACT, RPC, rpcServing(wasm)))).toEqual([
      EXCESSIVE_STATIC_MEMORY_RULE,
    ]);
  });

  it('stays silent when the code entry or the RPC is unavailable', async () => {
    expect(await auditContractBudget(CONTRACT, RPC, rpcServing(undefined))).toEqual([]);
    const down = (async () => new Response('nope', { status: 503 })) as unknown as typeof fetch;
    expect(await auditContractBudget(CONTRACT, RPC, down)).toEqual([]);
  });

  it('runs as part of checkContracts for every declared contract', async () => {
    const doc = parse(
      [
        'NETWORK_PASSPHRASE = "Test SDF Network ; September 2015"',
        '[[CURRENCIES]]',
        'code = "USDC"',
        `contract = "${CONTRACT}"`,
      ].join('\n'),
    ) as Record<string, unknown>;
    const wasm = wasmModule({ minPages: 20, functions: { balance: 0 } });

    const diagnostics = await checkContracts(doc, rpcServing(wasm), {
      rpcUrl: RPC,
      horizonUrl: 'http://horizon.invalid',
    });
    expect(rulesOf(diagnostics)).toContain(EXCESSIVE_STATIC_MEMORY_RULE);
  });

  it('registers both rule ids', () => {
    expect(sorobanRuleIds).toContain(EXCESSIVE_STATIC_MEMORY_RULE);
    expect(sorobanRuleIds).toContain(HIGH_CYCLOMATIC_COMPLEXITY_RULE);
  });
});
