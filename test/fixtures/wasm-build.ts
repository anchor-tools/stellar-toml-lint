/**
 * A miniature WASM assembler for the sandbox fixtures.
 *
 * The tests need modules with precise import signatures and bodies — one that
 * writes to fd 1, one that probes `path_open`, one that never halts — and
 * hand-writing those as byte arrays is unreadable. This builder emits just the
 * sections those fixtures use, following the same shape as the assembler in
 * `test/soroban-budget-estimator.test.ts`.
 */

export const I32 = 0x7f;
export const I64 = 0x7e;

export const OP = {
  UNREACHABLE: 0x00,
  NOP: 0x01,
  BLOCK: 0x02,
  LOOP: 0x03,
  BR: 0x0c,
  BR_IF: 0x0d,
  RETURN: 0x0f,
  CALL: 0x10,
  DROP: 0x1a,
  I32_LOAD: 0x28,
  I32_STORE: 0x36,
  MEMORY_GROW: 0x40,
} as const;

/** Unsigned LEB128. */
export function u32(value: number): number[] {
  const bytes: number[] = [];
  let rest = value;
  do {
    let byte = rest & 0x7f;
    rest >>>= 7;
    if (rest !== 0) byte |= 0x80;
    bytes.push(byte);
  } while (rest !== 0);
  return bytes;
}

/** Signed LEB128, enough for the small i32/i64 constants used here. */
export function sleb(value: number): number[] {
  const bytes: number[] = [];
  let rest = value;
  for (;;) {
    const byte = rest & 0x7f;
    rest >>= 7;
    const signBit = (byte & 0x40) !== 0;
    if ((rest === 0 && !signBit) || (rest === -1 && signBit)) {
      bytes.push(byte);
      return bytes;
    }
    bytes.push(byte | 0x80);
  }
}

export function i32Const(value: number): number[] {
  return [0x41, ...sleb(value)];
}

export function i64Const(value: number): number[] {
  return [0x42, ...sleb(value)];
}

export function name(text: string): number[] {
  const bytes = [...new TextEncoder().encode(text)];
  return [...u32(bytes.length), ...bytes];
}

function vec(items: number[][]): number[] {
  return [...u32(items.length), ...items.flat()];
}

function section(id: number, payload: number[]): number[] {
  return [id, ...u32(payload.length), ...payload];
}

export function funcType(params: number[], results: number[]): number[] {
  return [0x60, ...u32(params.length), ...params, ...u32(results.length), ...results];
}

export interface WasmImport {
  module: string;
  name: string;
  type: number;
}

export interface WasmFunction {
  type: number;
  /** [count, value type] pairs for locals beyond the parameters. */
  locals?: [number, number][];
  code: number[];
}

export interface WasmExport {
  name: string;
  /** 0x00 function, 0x02 memory. */
  kind: 0x00 | 0x02;
  index: number;
}

export interface WasmModuleOptions {
  types: number[][];
  imports?: WasmImport[];
  memoryPages?: number;
  data?: { offset: number; bytes: number[] | string }[];
  functions?: WasmFunction[];
  exports?: WasmExport[];
}

export function buildWasm(options: WasmModuleOptions): Uint8Array {
  const imports = options.imports ?? [];
  const functions = options.functions ?? [];
  const out: number[] = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

  out.push(...section(1, vec(options.types)));

  if (imports.length > 0) {
    out.push(
      ...section(
        2,
        vec(
          imports.map((entry) => [
            ...name(entry.module),
            ...name(entry.name),
            0x00,
            ...u32(entry.type),
          ]),
        ),
      ),
    );
  }

  if (functions.length > 0) {
    out.push(...section(3, vec(functions.map((fn) => u32(fn.type)))));
  }

  if (options.memoryPages !== undefined) {
    out.push(...section(5, vec([[0x00, ...u32(options.memoryPages)]])));
  }

  if (options.exports !== undefined && options.exports.length > 0) {
    out.push(
      ...section(
        7,
        vec(options.exports.map((entry) => [...name(entry.name), entry.kind, ...u32(entry.index)])),
      ),
    );
  }

  // Section order is fixed by the spec: code (10) precedes data (11).
  if (functions.length > 0) {
    out.push(
      ...section(
        10,
        vec(
          functions.map((fn) => {
            const locals = fn.locals ?? [];
            const body = [...u32(locals.length), ...locals.flat(), ...fn.code, 0x0b];
            return [...u32(body.length), ...body];
          }),
        ),
      ),
    );
  }

  const data = options.data ?? [];
  if (data.length > 0) {
    out.push(
      ...section(
        11,
        vec(
          data.map((segment) => {
            const bytes =
              typeof segment.bytes === 'string'
                ? [...new TextEncoder().encode(segment.bytes)]
                : segment.bytes;
            return [0x00, ...i32Const(segment.offset), 0x0b, ...u32(bytes.length), ...bytes];
          }),
        ),
      ),
    );
  }

  return Uint8Array.from(out);
}

/** A WASI import signature: (i32, i32, i32, i32) -> i32. */
export const WASI_IO_TYPE = funcType([I32, I32, I32, I32], [I32]);

/** A function body that calls `fn` with the given arguments. */
export function call(fn: number, args: number[][]): number[] {
  return [...args.flat(), OP.CALL, ...u32(fn)];
}

/** A function body that calls `fn` with the given arguments and drops its result. */
export function callDropped(fn: number, args: number[][]): number[] {
  return [...call(fn, args), OP.DROP];
}
