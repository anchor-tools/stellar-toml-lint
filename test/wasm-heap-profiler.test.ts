import { describe, expect, it } from 'vitest';
import {
  DEFAULT_LEAK_THRESHOLD_BYTES,
  WasmHeapProfiler,
  type HeapProfile,
} from '../src/wasm/heapProfiler.js';
import { PointerLedger } from '../src/wasm/pointerLedger.js';
import { isWasmMemory, wasmRuntime } from '../src/wasm/wasmApi.js';
import { OP, buildWasm, funcType } from './fixtures/wasm-build.js';

const PAGE = 65_536;

/** A plugin whose allocator has reached its high-water mark. */
function stableModule(): Uint8Array {
  return buildWasm({
    types: [funcType([], [])],
    memoryPages: 1,
    functions: [{ type: 0, code: [OP.NOP] }],
    exports: [
      { name: 'memory', kind: 0x02, index: 0 },
      { name: 'run', kind: 0x00, index: 0 },
    ],
  });
}

/** A plugin that grows one page per invocation and never frees it. */
function leakingModule(): Uint8Array {
  return buildWasm({
    types: [funcType([], [])],
    memoryPages: 1,
    functions: [
      {
        type: 0,
        code: [0x41, 0x01, OP.MEMORY_GROW, 0x00, OP.DROP],
      },
    ],
    exports: [
      { name: 'memory', kind: 0x02, index: 0 },
      { name: 'run', kind: 0x00, index: 0 },
    ],
  });
}

async function profile(
  module: Uint8Array,
  iterations: number,
  profiler = new WasmHeapProfiler(),
): Promise<HeapProfile> {
  const runtime = wasmRuntime();
  const instance = await runtime.instantiate(await runtime.compile(module), {});
  const memory = instance.exports['memory'];
  if (!isWasmMemory(memory)) throw new Error('fixture must export memory');
  const run = instance.exports['run'] as () => void;

  return profiler.profile(
    () => {
      run();
    },
    () => memory.buffer.byteLength,
    iterations,
  );
}

describe('WasmHeapProfiler', () => {
  it('calls a stable module stable and reports exact zero growth', async () => {
    const result = await profile(stableModule(), 20);

    expect(result.verdict).toBe('stable');
    expect(result.leaked).toBe(false);
    expect(result.baselineBytes).toBe(PAGE);
    expect(result.finalBytes).toBe(PAGE);
    expect(result.totalDeltaBytes).toBe(0);
    expect(result.growthPerIterationBytes).toBe(0);
    expect(result.plateauedAtIteration).toBe(1);
    expect(result.samples).toHaveLength(20);
  });

  it('detects a module that grows one page per iteration, in bytes', async () => {
    const result = await profile(leakingModule(), 25);

    expect(result.verdict).toBe('leaking');
    expect(result.leaked).toBe(true);
    expect(result.monotonicGrowth).toBe(true);
    expect(result.totalDeltaBytes).toBe(25 * PAGE);
    expect(result.growthPerIterationBytes).toBe(PAGE);
    expect(result.plateauedAtIteration).toBeNull();
    expect(result.samples.map((sample) => sample.deltaBytes)).toEqual(
      Array.from({ length: 25 }, () => PAGE),
    );
    expect(result.peakBytes).toBe(26 * PAGE);
  });

  it('renders a growth curve without a chart dependency', async () => {
    const leaking = await profile(leakingModule(), 12);
    const svg = new WasmHeapProfiler().renderGrowthCurve(leaking);

    expect(svg).toContain('<svg');
    expect(svg).toContain('<polyline');
    expect(svg).toContain('growing');
    expect(svg).toContain('#d1242f');
    expect(svg.endsWith('\n')).toBe(true);
  });

  it('formats the numbers a reviewer needs', async () => {
    const leaking = await profile(leakingModule(), 5);
    const report = new WasmHeapProfiler().formatReport(leaking);

    expect(report).toContain('WASM heap profile — leaking');
    expect(report).toContain('delta            327680 B');
    expect(report).toContain('growth           65536 B/iteration');
  });

  it('reports dangling host pointers and their byte total', async () => {
    const ledger = new PointerLedger();
    ledger.allocate(0x10, 32, 'schema buffer');
    ledger.allocate(0x20, 8, 'scratch');
    ledger.free(0x20);

    const profiler = new WasmHeapProfiler({ pointerLedger: ledger });
    const result = await profile(stableModule(), 5, profiler);

    expect(result.danglingPointers).toEqual([{ pointer: 0x10, bytes: 32, label: 'schema buffer' }]);
    expect(result.danglingBytes).toBe(32);
    expect(profiler.formatReport(result)).toContain('dangling         1 pointer(s), 32 B');
  });

  it('treats growth below the threshold as a stabilising allocator', () => {
    const profiler = new WasmHeapProfiler({ leakThresholdBytes: DEFAULT_LEAK_THRESHOLD_BYTES });
    const readings = [100, 300, 1_000, 1_000, 1_000, 1_000, 1_000, 1_000, 1_000, 1_000];
    const samples = readings.map((bytes, index) => ({
      iteration: index + 1,
      bytes,
      deltaBytes: index === 0 ? 0 : bytes - (readings[index - 1] as number),
    }));

    const analyzed = profiler.analyze(samples, 100);
    expect(analyzed.leaked).toBe(false);
    expect(analyzed.verdict).toBe('stable');
  });

  it('rejects a nonsensical iteration count', async () => {
    await expect(
      new WasmHeapProfiler().profile(
        () => undefined,
        () => 0,
        0,
      ),
    ).rejects.toThrow(/positive integer/);
  });
});
