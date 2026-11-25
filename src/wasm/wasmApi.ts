/**
 * Structural types for the WebAssembly JavaScript API.
 *
 * The package compiles against `lib: ["ES2022"]`, which has no DOM/WebWorker
 * lib to declare `WebAssembly` for us. Declaring the handful of members the
 * sandbox uses locally keeps that narrow lib intact — pulling in the DOM lib to
 * borrow the namespace would saddle every consumer with browser globals.
 */
export interface WasmModuleLike {
  readonly __module: unique symbol;
}

export interface WasmImportDescriptor {
  module: string;
  name: string;
  kind: string;
}

export interface WasmInstanceLike {
  readonly exports: Record<string, unknown>;
}

export interface WasmMemoryLike {
  readonly buffer: ArrayBuffer;
}

export interface WasmGlobalLike {
  value: number | bigint;
}

export interface WasmRuntimeLike {
  compile(bytes: Uint8Array): Promise<WasmModuleLike>;
  instantiate(
    module: WasmModuleLike,
    imports: Record<string, Record<string, unknown>>,
  ): Promise<WasmInstanceLike>;
  Module: { imports(module: WasmModuleLike): WasmImportDescriptor[] };
  RuntimeError: new (message?: string) => Error;
}

const runtime = (globalThis as unknown as { WebAssembly?: WasmRuntimeLike }).WebAssembly;

export function wasmRuntime(): WasmRuntimeLike {
  if (runtime === undefined) {
    throw new Error('WebAssembly is not available in this runtime.');
  }
  return runtime;
}

export function isWasmRuntimeError(error: unknown): error is Error {
  return runtime !== undefined && error instanceof runtime.RuntimeError;
}

export function isWasmMemory(value: unknown): value is WasmMemoryLike {
  return (
    typeof value === 'object' &&
    value !== null &&
    'buffer' in value &&
    (value as { buffer: unknown }).buffer instanceof ArrayBuffer
  );
}

export function isWasmGlobal(value: unknown): value is WasmGlobalLike {
  return typeof value === 'object' && value !== null && 'value' in value && 'valueOf' in value;
}
