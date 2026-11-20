import { describe, expect, it } from 'vitest';
import {
  MAX_WASM_MEMORY_BYTES,
  WasmPointerError,
  WasmPointerProtector,
  type WasmMemoryHandle,
} from '../../src/wasm/pointerProtector.js';
import { wasmRuntime } from '../../src/wasm/wasmApi.js';

const runtime = wasmRuntime();

class FakeMemory implements WasmMemoryHandle {
  buffer: ArrayBuffer;
  pages: number;

  constructor(pages = 1) {
    this.pages = pages;
    this.buffer = new ArrayBuffer(pages * 65_536);
  }

  grow(delta: number): number {
    if (this.pages + delta > 65_536) return -1;
    const previous = this.pages;
    this.pages += delta;
    const next = new ArrayBuffer(this.pages * 65_536);
    new Uint8Array(next).set(new Uint8Array(this.buffer));
    this.buffer = next;
    return previous;
  }
}

function capture(error: unknown): WasmPointerError {
  expect(error).toBeInstanceOf(WasmPointerError);
  return error as WasmPointerError;
}

describe('WasmPointerProtector bounds', () => {
  it('round-trips bytes and strings', () => {
    const protector = new WasmPointerProtector(new FakeMemory());
    const window = protector.writeBytes(16, Uint8Array.from([1, 2, 3]));
    expect(window).toEqual({ pointer: 16, length: 3, end: 19 });
    expect([...protector.readBytes(16, 3)]).toEqual([1, 2, 3]);
    expect(protector.readString(16, 3)).toHaveLength(3);

    const staged = protector.stageString('hello');
    expect(staged.pointer).toBe(0);
    expect(protector.readString(staged.pointer, staged.length)).toBe('hello');
  });
});

describe('WasmPointerProtector validation', () => {
  const protector = new WasmPointerProtector(new FakeMemory());

  it('rejects negative pointers', () => {
    try {
      protector.assert(-1);
      expect.unreachable('expected a throw');
    } catch (error) {
      expect(capture(error).code).toBe('pointer/negative');
    }
  });

  it('rejects fractional pointers and lengths', () => {
    try {
      protector.assert(1.5);
      expect.unreachable('expected a throw');
    } catch (error) {
      expect(capture(error).code).toBe('pointer/non-integer');
    }
    try {
      protector.assert(0, 2.5);
      expect.unreachable('expected a throw');
    } catch (error) {
      expect(capture(error).code).toBe('pointer/non-integer');
    }
  });

  it('rejects slices past the end of memory with the sizes in the message', () => {
    try {
      protector.assert(65_500, 100);
      expect.unreachable('expected a throw');
    } catch (error) {
      const failure = capture(error);
      expect(failure.code).toBe('pointer/out-of-bounds');
      expect(failure.message).toContain('65536');
      expect(failure.pointer).toBe(65_500);
      expect(failure.length).toBe(100);
    }
  });

  it('allows an empty slice at the end of memory but not past it', () => {
    expect(protector.assert(65_536, 0)).toEqual({ pointer: 65_536, length: 0, end: 65_536 });
    expect(() => protector.assert(65_537, 0)).toThrow(WasmPointerError);
  });

  it('rejects addresses above the 32-bit address space', () => {
    const huge = new WasmPointerProtector({ buffer: new ArrayBuffer(65_536) });
    try {
      huge.assert(2 ** 33, 0);
      expect.unreachable('expected a throw');
    } catch (error) {
      expect(capture(error).code).toBe('pointer/out-of-bounds');
    }
  });

  it('enforces alignment when configured', () => {
    const aligned = new WasmPointerProtector(new FakeMemory(), { alignment: 4 });
    expect(aligned.assert(8, 4).end).toBe(12);
    try {
      aligned.assert(6, 4);
      expect.unreachable('expected a throw');
    } catch (error) {
      expect(capture(error).code).toBe('pointer/misaligned');
    }
  });
});

describe('WasmPointerProtector growth', () => {
  it('grows memory for a staged payload larger than the initial allocation', () => {
    const memory = new FakeMemory(1);
    const protector = new WasmPointerProtector(memory);
    expect(protector.byteLength).toBe(65_536);

    const payload = new Uint8Array(65_536 + 32).fill(7);
    const window = protector.stage(payload);
    expect(memory.pages).toBe(2);
    expect(window.end).toBe(payload.byteLength);
    expect(protector.readBytes(0, payload.byteLength)).toEqual(payload);
  });

  it('refuses payloads above the configured ceiling', () => {
    const protector = new WasmPointerProtector(new FakeMemory(1), {
      maxMemoryBytes: 2 * 65_536,
    });
    expect(protector.ensureCapacity(2 * 65_536).grownPages).toBe(1);
    try {
      protector.ensureCapacity(3 * 65_536);
      expect.unreachable('expected a throw');
    } catch (error) {
      expect(capture(error).code).toBe('pointer/allocation-too-large');
    }
    expect(MAX_WASM_MEMORY_BYTES).toBe(4 * 1024 * 1024 * 1024);
  });

  it('reports a fixed memory that cannot grow', () => {
    const protector = new WasmPointerProtector({ buffer: new ArrayBuffer(65_536) });
    try {
      protector.ensureCapacity(70_000);
      expect.unreachable('expected a throw');
    } catch (error) {
      expect(capture(error).code).toBe('pointer/out-of-bounds');
    }
  });
});

describe('WasmPointerProtector traps', () => {
  const protector = new WasmPointerProtector(new FakeMemory());

  it('converts a raw WebAssembly trap into a diagnostic error', () => {
    try {
      protector.invoke('run', () => {
        throw new runtime.RuntimeError('memory access out of bounds');
      });
      expect.unreachable('expected a throw');
    } catch (error) {
      const failure = capture(error);
      expect(failure.code).toBe('pointer/trap');
      expect(failure.message).toContain('run');
      expect(failure.message).toContain('memory access out of bounds');
      expect(failure.memoryBytes).toBe(65_536);
    }
  });

  it('passes ordinary JavaScript errors through untouched', () => {
    const original = new Error('business logic');
    try {
      protector.invoke('run', () => {
        throw original;
      });
      expect.unreachable('expected a throw');
    } catch (error) {
      expect(error).toBe(original);
    }
  });

  it('translates async invocations too', async () => {
    await expect(
      protector.invokeAsync('parse', () => Promise.reject(new runtime.RuntimeError('unreachable'))),
    ).rejects.toBeInstanceOf(WasmPointerError);
  });
});
