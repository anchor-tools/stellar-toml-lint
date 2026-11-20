/**
 * Host → WASM pointer validation and trap translation.
 *
 * Every string and buffer handed to a WebAssembly export crosses a boundary
 * where JavaScript's numbers are not checked at all. A negative offset, a
 * fractional length, or a slice that runs past `memory.buffer.byteLength` turns
 * into an unhelpful `RuntimeError: memory access out of bounds` deep inside the
 * guest — or, worse, silently reads adjacent memory.
 *
 * `WasmPointerProtector` validates offsets, lengths, and slices against the
 * current linear memory before constructing a view, grows memory when a staged
 * payload no longer fits, and wraps invocations so a raw WASM trap becomes a
 * `WasmPointerError` that names the pointer, length, and memory size involved.
 */

import { isWasmRuntimeError } from './wasmApi.js';

/** WASM linear memory is allocated in 64 KiB pages. */
export const WASM_PAGE_SIZE = 65_536;

/** Largest linear memory a 32-bit WASM module can address. */
export const MAX_WASM_PAGES = 65_536;

export const MAX_WASM_MEMORY_BYTES = MAX_WASM_PAGES * WASM_PAGE_SIZE;

const MAX_WASM_OFFSET = 0xffff_ffff;

export type WasmPointerCode =
  | 'pointer/non-integer'
  | 'pointer/negative'
  | 'pointer/out-of-bounds'
  | 'pointer/misaligned'
  | 'pointer/allocation-too-large'
  | 'pointer/trap';

export interface WasmPointerDetails {
  pointer?: number;
  length?: number;
  memoryBytes?: number;
}

export class WasmPointerError extends Error {
  readonly code: WasmPointerCode;
  readonly pointer: number | undefined;
  readonly length: number | undefined;
  readonly memoryBytes: number | undefined;

  constructor(code: WasmPointerCode, message: string, details: WasmPointerDetails = {}) {
    super(message);
    this.name = 'WasmPointerError';
    this.code = code;
    this.pointer = details.pointer;
    this.length = details.length;
    this.memoryBytes = details.memoryBytes;
  }
}

/**
 * Structural view of a WebAssembly.Memory. `grow` is optional so a fixed
 * buffer (a mock, or a memory without a maximum) can still be validated.
 */
export interface WasmMemoryHandle {
  readonly buffer: ArrayBuffer;
  grow?(pages: number): number;
}

export interface PointerWindow {
  pointer: number;
  length: number;
  end: number;
}

export interface PointerProtectorOptions {
  /** Required alignment in bytes; 0 (the default) disables the check. */
  alignment?: number;
  /** First byte `stage()` may write to; defaults to 0. */
  heapBase?: number;
  /** Hard cap for linear memory; defaults to the 4 GiB WASM maximum. */
  maxMemoryBytes?: number;
}

export interface GrowthResult {
  grownPages: number;
  bytes: number;
}

function formatBytes(bytes: number): string {
  return `${bytes} byte${bytes === 1 ? '' : 's'}`;
}

export class WasmPointerProtector {
  private readonly source: WasmMemoryHandle | (() => WasmMemoryHandle);
  private readonly alignment: number;
  private readonly heapBase: number;
  private readonly maxMemoryBytes: number;
  private watermark: number;

  constructor(
    memory: WasmMemoryHandle | (() => WasmMemoryHandle),
    options: PointerProtectorOptions = {},
  ) {
    this.source = memory;
    this.alignment = options.alignment ?? 0;
    this.heapBase = options.heapBase ?? 0;
    this.maxMemoryBytes = Math.min(
      options.maxMemoryBytes ?? MAX_WASM_MEMORY_BYTES,
      MAX_WASM_MEMORY_BYTES,
    );
    this.watermark = this.heapBase;
  }

  private memory(): WasmMemoryHandle {
    return typeof this.source === 'function' ? this.source() : this.source;
  }

  get byteLength(): number {
    return this.memory().buffer.byteLength;
  }

  private assertInteger(value: number, field: string): void {
    if (!Number.isSafeInteger(value)) {
      throw new WasmPointerError(
        'pointer/non-integer',
        `${field} ${String(value)} is not a safe integer; WASM expects a 32-bit offset or length.`,
        { memoryBytes: this.byteLength },
      );
    }
    if (value < 0) {
      throw new WasmPointerError(
        'pointer/negative',
        `${field} ${value} is negative; WASM offsets and lengths must be unsigned.`,
        { memoryBytes: this.byteLength },
      );
    }
  }

  /**
   * Validates a `[pointer, pointer + length)` slice against the live memory.
   * Throws a `WasmPointerError` instead of letting a typed-array constructor
   * or a guest access fault.
   */
  assert(pointer: number, length = 0): PointerWindow {
    const memoryBytes = this.byteLength;
    this.assertInteger(pointer, 'Pointer');
    this.assertInteger(length, 'Length');

    if (pointer > MAX_WASM_OFFSET) {
      throw new WasmPointerError(
        'pointer/out-of-bounds',
        `Pointer ${pointer} exceeds the 32-bit WASM address space.`,
        { pointer, length, memoryBytes },
      );
    }

    const end = pointer + length;
    if (end > memoryBytes) {
      throw new WasmPointerError(
        'pointer/out-of-bounds',
        `Buffer slice [${pointer}, ${end}) exceeds the current WASM memory of ${formatBytes(memoryBytes)}.`,
        { pointer, length, memoryBytes },
      );
    }

    if (this.alignment > 0 && pointer % this.alignment !== 0) {
      throw new WasmPointerError(
        'pointer/misaligned',
        `Pointer ${pointer} is not aligned to ${this.alignment} bytes.`,
        { pointer, length, memoryBytes },
      );
    }

    return { pointer, length, end };
  }

  /** Alias for `assert`, named for callers that prefer "validate". */
  validate(pointer: number, length = 0): PointerWindow {
    return this.assert(pointer, length);
  }

  /**
   * Grows linear memory until `requiredBytes` fit. Returns how many pages were
   * added. A buffer that cannot grow, or a request past the 4 GiB ceiling,
   * fails with a diagnostic instead of a guest trap.
   */
  ensureCapacity(requiredBytes: number): GrowthResult {
    this.assertInteger(requiredBytes, 'Required capacity');
    if (requiredBytes > this.maxMemoryBytes) {
      throw new WasmPointerError(
        'pointer/allocation-too-large',
        `Requested ${formatBytes(requiredBytes)}, above the configured ${formatBytes(this.maxMemoryBytes)} memory limit.`,
        { memoryBytes: this.byteLength },
      );
    }

    const available = this.byteLength;
    if (requiredBytes <= available) return { grownPages: 0, bytes: available };

    const pages = Math.ceil((requiredBytes - available) / WASM_PAGE_SIZE);
    const memory = this.memory();
    if (typeof memory.grow !== 'function') {
      throw new WasmPointerError(
        'pointer/out-of-bounds',
        `Need ${formatBytes(requiredBytes)} but only ${formatBytes(available)} are available and this memory cannot grow.`,
        { length: requiredBytes, memoryBytes: available },
      );
    }

    const previous = memory.grow(pages);
    if (previous === -1) {
      throw new WasmPointerError(
        'pointer/allocation-too-large',
        `Growing WASM memory by ${pages} page(s) failed; the ${formatBytes(this.maxMemoryBytes)} limit is exhausted.`,
        { length: requiredBytes, memoryBytes: available },
      );
    }

    return { grownPages: pages, bytes: this.byteLength };
  }

  /** Copies `length` bytes out of guest memory. */
  readBytes(pointer: number, length: number): Uint8Array {
    const window = this.assert(pointer, length);
    const view = new Uint8Array(this.memory().buffer, window.pointer, window.length);
    return view.slice();
  }

  /** Copies host bytes into guest memory at a validated pointer. */
  writeBytes(pointer: number, bytes: Uint8Array): PointerWindow {
    const window = this.assert(pointer, bytes.byteLength);
    new Uint8Array(this.memory().buffer, window.pointer, window.length).set(bytes);
    return window;
  }

  /**
   * Ensures the payload fits, then writes it at the current heap watermark
   * (starting at `heapBase`). Compressed or trailing payloads that outgrow the
   * initial allocation are accommodated by growing memory first.
   */
  stage(bytes: Uint8Array): PointerWindow {
    const required = this.watermark + bytes.byteLength;
    if (!Number.isSafeInteger(required)) {
      throw new WasmPointerError(
        'pointer/allocation-too-large',
        `Staging ${formatBytes(bytes.byteLength)} at ${this.watermark} overflows the address space.`,
        { pointer: this.watermark, length: bytes.byteLength, memoryBytes: this.byteLength },
      );
    }
    this.ensureCapacity(required);
    const window = this.assert(this.watermark, bytes.byteLength);
    if (window.length > 0) {
      new Uint8Array(this.memory().buffer, window.pointer, window.length).set(bytes);
    }
    this.watermark = window.end;
    return window;
  }

  /** UTF-8 encodes `text`, stages it, and returns its guest window. */
  stageString(text: string): PointerWindow {
    return this.stage(new TextEncoder().encode(text));
  }

  readString(pointer: number, length: number): string {
    return new TextDecoder().decode(this.readBytes(pointer, length));
  }

  /** Resets the staging watermark, e.g. after a guest allocator reset. */
  reset(): void {
    this.watermark = this.heapBase;
  }

  get stagedBytes(): number {
    return this.watermark - this.heapBase;
  }

  /**
   * Runs a WASM export and converts raw runtime traps into a
   * `WasmPointerError` carrying the call label and current memory size.
   * Ordinary JavaScript errors pass through untouched.
   */
  invoke<T>(label: string, call: () => T): T {
    try {
      return call();
    } catch (error) {
      throw this.translate(label, error);
    }
  }

  async invokeAsync<T>(label: string, call: () => Promise<T>): Promise<T> {
    try {
      return await call();
    } catch (error) {
      throw this.translate(label, error);
    }
  }

  private translate(label: string, error: unknown): unknown {
    if (error instanceof WasmPointerError) return error;
    const detail = error instanceof Error ? error.message : String(error);
    const trapped =
      isWasmRuntimeError(error) ||
      /memory access out of bounds|RuntimeError|unreachable/i.test(detail);
    if (!trapped) return error;

    return new WasmPointerError(
      'pointer/trap',
      `${label} trapped in WebAssembly: ${detail} (linear memory is ${formatBytes(this.byteLength)}). ` +
        'A pointer or length handed to the guest was outside its memory.',
      { memoryBytes: this.byteLength },
    );
  }
}
