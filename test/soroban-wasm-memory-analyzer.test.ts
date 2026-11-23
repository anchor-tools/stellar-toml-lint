import { describe, expect, it } from 'vitest';
import {
  DEFAULT_MAX_INITIAL_PAGES,
  DEFAULT_MAX_STACK_SLOTS,
  WasmMemoryHazardAnalyzer,
  analyzeWasmMemory,
  recursionCycles,
  renderMemoryHazardReport,
  wasmMemoryRuleIds,
} from '../src/soroban/wasmMemoryAnalyzer.js';
import { parseWasmModule } from '../src/soroban/wasmModule.js';
import { I32, OP, buildWasm, funcType, u32 } from './fixtures/wasm-build.js';

const VOID = funcType([], []);

function module(options: {
  pages?: number;
  maxPages?: number;
  functions?: { code: number[]; locals?: [number, number][] }[];
  exports?: { name: string; index: number }[];
}): Uint8Array {
  const functions = options.functions ?? [{ code: [] }];
  return buildWasm({
    types: [VOID],
    ...(options.pages !== undefined ? { memoryPages: options.pages } : {}),
    ...(options.maxPages !== undefined ? { memoryMaxPages: options.maxPages } : {}),
    functions: functions.map((fn) => ({
      type: 0,
      ...(fn.locals !== undefined ? { locals: fn.locals } : {}),
      code: fn.code,
    })),
    exports: (options.exports ?? functions.map((_, index) => ({ name: `f${index}`, index }))).map(
      (entry) => ({ name: entry.name, kind: 0x00 as const, index: entry.index }),
    ),
    functionNames: functions.map((_, index) => `f${index}`),
  });
}

const call = (target: number): number[] => [OP.CALL, ...u32(target)];
const loop = (...body: number[]): number[] => [OP.LOOP, 0x40, ...body, 0x0b];

describe('soroban WASM memory hazard analyzer', () => {
  it('accepts a small, bounded, loop-free contract', () => {
    const report = analyzeWasmMemory(module({ pages: 2, maxPages: 16 }));
    expect(report.valid).toBe(true);
    expect(report.findings).toEqual([]);
    expect(report.memory.initialPages).toBe(2);
    expect(report.memory.maximumPages).toBe(16);
    expect(report.memory.bounded).toBe(true);
  });

  it('flags memory with no declared maximum', () => {
    const report = analyzeWasmMemory(module({ pages: 1 }));
    expect(report.findings).toContainEqual(
      expect.objectContaining({
        code: 'soroban/wasm-unbounded-memory',
        severity: 'warning',
      }),
    );
  });

  it('flags an excessive initial memory', () => {
    const report = analyzeWasmMemory(
      module({ pages: DEFAULT_MAX_INITIAL_PAGES + 1, maxPages: 200 }),
    );
    expect(report.findings).toContainEqual(
      expect.objectContaining({ code: 'soroban/wasm-excessive-initial-memory' }),
    );
  });

  it('finds direct self-recursion with a call-site offset', () => {
    const wasm = module({ pages: 1, maxPages: 2, functions: [{ code: call(0) }] });
    const report = analyzeWasmMemory(wasm);
    const finding = report.findings.find((entry) => entry.code === 'soroban/wasm-recursive-call');
    expect(finding).toBeDefined();
    expect(finding?.function).toBe('f0');
    expect(finding?.offset).toBeGreaterThan(0);
    expect(report.recursion[0]?.functions).toEqual(['f0', 'f0']);
  });

  it('finds mutual recursion across two functions', () => {
    const wasm = module({
      pages: 1,
      maxPages: 2,
      functions: [{ code: call(1) }, { code: call(0) }],
    });
    const report = analyzeWasmMemory(wasm);
    expect(report.recursion).toHaveLength(1);
    expect(report.recursion[0]?.functions).toEqual(['f0', 'f1']);
    expect(report.findings.filter((f) => f.code === 'soroban/wasm-recursive-call')).toHaveLength(1);
  });

  it('does not confuse a plain call chain with recursion', () => {
    const wasm = module({
      pages: 1,
      maxPages: 2,
      functions: [{ code: call(1) }, { code: [] }],
    });
    expect(analyzeWasmMemory(wasm).recursion).toEqual([]);
  });

  it('flags a loop with no exit and accepts one with a conditional branch', () => {
    const unbounded = analyzeWasmMemory(
      module({ pages: 1, maxPages: 2, functions: [{ code: loop() }] }),
    );
    expect(unbounded.findings).toContainEqual(
      expect.objectContaining({ code: 'soroban/wasm-unbounded-loop', function: 'f0' }),
    );

    const bounded = analyzeWasmMemory(
      module({
        pages: 1,
        maxPages: 2,
        functions: [{ code: loop(OP.BR_IF, 0x00) }],
      }),
    );
    expect(bounded.findings.map((finding) => finding.code)).not.toContain(
      'soroban/wasm-unbounded-loop',
    );
  });

  it('flags a loop whose only exit is an unconditional return', () => {
    const report = analyzeWasmMemory(
      module({ pages: 1, maxPages: 2, functions: [{ code: loop(OP.RETURN) }] }).slice(0),
    );
    expect(report.findings.map((finding) => finding.code)).not.toContain(
      'soroban/wasm-unbounded-loop',
    );
  });

  it('flags a large stack frame', () => {
    const report = analyzeWasmMemory(
      module({
        pages: 1,
        maxPages: 2,
        functions: [{ code: [], locals: [[DEFAULT_MAX_STACK_SLOTS + 1, I32]] }],
      }),
    );
    expect(report.findings).toContainEqual(
      expect.objectContaining({
        code: 'soroban/wasm-large-stack-frame',
        function: 'f0',
      }),
    );
  });

  it('records memory.grow sites with their function and offset', () => {
    const wasm = module({
      pages: 1,
      maxPages: 2,
      functions: [{ code: [0x41, 0x01, OP.MEMORY_GROW, 0x00] }],
    });
    const report = analyzeWasmMemory(wasm);
    expect(report.memory.growOps).toBe(1);
    expect(report.memory.growOffsets[0]?.function).toBe('f0');
    expect(report.memory.growOffsets[0]?.offset).toBeGreaterThan(0);
  });

  it('reports a malformed binary instead of throwing', () => {
    const report = analyzeWasmMemory(
      Uint8Array.from([0x00, 0x61, 0x73, 0x6e, 0x01, 0x00, 0x00, 0x00]),
    );
    expect(report.valid).toBe(false);
    expect(report.error).toContain('not a WebAssembly binary');
    expect(report.findings[0]?.code).toBe('soroban/wasm-invalid-binary');
  });

  it('names functions from the name section and exports', () => {
    const parsed = parseWasmModule(
      module({
        pages: 1,
        maxPages: 2,
        functions: [{ code: [] }],
        exports: [{ name: 'mint', index: 0 }],
      }),
    );
    expect(parsed.functions[0]?.name).toBe('f0');
  });

  it('exposes a class wrapper and renders findings', () => {
    const analyzer = new WasmMemoryHazardAnalyzer({ maxInitialPages: 1 });
    const report = analyzer.analyze(module({ pages: 2, maxPages: 4 }));
    expect(report.findings[0]?.code).toBe('soroban/wasm-excessive-initial-memory');
    const text = renderMemoryHazardReport(report);
    expect(text).toContain('WASM memory audit');
    expect(text).toContain('soroban/wasm-excessive-initial-memory');
    expect(text).toContain('Fix:');
  });

  it('registers every rule id it can emit', () => {
    expect(wasmMemoryRuleIds).toContain('soroban/wasm-recursive-call');
    expect(new Set(wasmMemoryRuleIds).size).toBe(wasmMemoryRuleIds.length);
  });

  it('finds no cycle in an empty call graph', () => {
    expect(recursionCycles(parseWasmModule(module({ pages: 1, maxPages: 2 })))).toEqual([]);
  });
});
