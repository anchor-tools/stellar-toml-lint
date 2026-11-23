/**
 * Fuel metering for untrusted WebAssembly modules.
 *
 * WebAssembly gives a host no way to interrupt a guest loop: `WebAssembly`
 * exposes memory and exports, not a step counter, so a plugin that writes
 * `loop br 0` hangs the JS thread that instantiated it. The only portable
 * defence is to put the counter in the module itself. This module rewrites the
 * binary so that every function entry and every loop iteration decrements a
 * mutable `i32` global and traps with `unreachable` when it reaches zero.
 *
 * The global is seeded from the constant-expression initialiser, which means
 * the budget is fixed at instrumentation time — one instance per run — and the
 * remaining fuel can be read back through an exported global instead of a host
 * callback, so a sandboxed module cannot reset its own meter.
 *
 * Only the instruction stream is touched: section payloads, indices, and
 * offsets are not relocated, because the injected sequence contains no branch
 * targets. A module using a proposal this walker cannot decode (SIMD, atomics,
 * exception handling) is rejected rather than instrumented on a guess.
 */
import { FuelMeterError } from './errors.js';

/** Name of the exported global that reports the remaining budget. */
export const FUEL_EXPORT_NAME = '__stellar_toml_lint_fuel_remaining';

/** The default budget: enough for a real validator pass, not for a fork bomb. */
export const DEFAULT_FUEL = 5_000_000;

export interface InstrumentedModule {
  bytes: Uint8Array;
  /** Index of the injected global in the module's global index space. */
  fuelGlobalIndex: number;
  /** Number of loop instructions carrying a fuel check. */
  loopsMetered: number;
}

const WASM_MAGIC = [0x00, 0x61, 0x73, 0x6d];
const WASM_VERSION = 1;

class Cursor {
  constructor(
    readonly bytes: Uint8Array,
    public pos = 0,
  ) {}

  get done(): boolean {
    return this.pos >= this.bytes.length;
  }

  byte(): number {
    if (this.done) throw new FuelMeterError('Malformed WebAssembly: truncated section.');
    return this.bytes[this.pos++] as number;
  }

  /** Unsigned LEB128, at most 32 bits. */
  u32(): number {
    let result = 0;
    let shift = 0;
    for (;;) {
      const byte = this.byte();
      result |= (byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) return result >>> 0;
      shift += 7;
      if (shift > 35) throw new FuelMeterError('Malformed WebAssembly: oversized LEB128.');
    }
  }

  /** Signed LEB128, at most 64 bits, returned as a number when it fits. */
  sleb(): bigint {
    let result = 0n;
    let shift = 0n;
    let byte: number;
    do {
      byte = this.byte();
      result |= BigInt(byte & 0x7f) << shift;
      shift += 7n;
    } while ((byte & 0x80) !== 0);

    if ((byte & 0x40) !== 0) result |= -1n << shift;
    return result;
  }

  /** Copies `length` raw bytes without interpreting them. */
  take(length: number): Uint8Array {
    if (length < 0 || this.pos + length > this.bytes.length) {
      throw new FuelMeterError('Malformed WebAssembly: section runs past the end of the module.');
    }
    const slice = this.bytes.subarray(this.pos, this.pos + length);
    this.pos += length;
    return slice;
  }

  name(): void {
    this.take(this.u32());
  }
}

function uleb(value: number): number[] {
  const out: number[] = [];
  let rest = value >>> 0;
  do {
    let byte = rest & 0x7f;
    rest >>>= 7;
    if (rest !== 0) byte |= 0x80;
    out.push(byte);
  } while (rest !== 0);
  return out;
}

function u32Bytes(value: number): number[] {
  return uleb(value);
}

function concat(parts: number[][]): number[] {
  return parts.flat();
}

/** The sequence that spends one unit of fuel and traps once the budget is gone. */
function fuelCheck(globalIndex: number): number[] {
  return [
    0x23, // global.get
    ...uleb(globalIndex),
    0x41,
    0x01, // i32.const 1
    0x6b, // i32.sub
    0x24, // global.set
    ...uleb(globalIndex),
    0x23, // global.get
    ...uleb(globalIndex),
    0x45, // i32.eqz
    0x04,
    0x40, // if (empty block type)
    0x00, // unreachable
    0x0b, // end
  ];
}

/** Skips a block type: empty, a value type, or a type index (s33). */
function skipBlockType(c: Cursor): number[][] {
  const byte = c.bytes[c.pos];
  if (byte === 0x40 || (byte !== undefined && byte >= 0x7b && byte <= 0x7f)) {
    c.pos += 1;
    return [[byte]];
  }
  const start = c.pos;
  c.sleb();
  return [[...c.bytes.subarray(start, c.pos)]];
}

function skipLimits(c: Cursor): number[][] {
  const flags = c.byte();
  const out: number[][] = [[flags]];
  out.push(uleb(c.u32()));
  if ((flags & 0x01) !== 0) out.push(uleb(c.u32()));
  return out;
}

function skipMemArg(c: Cursor): number[][] {
  return [uleb(c.u32()), uleb(c.u32())];
}

/**
 * Advances past one instruction's immediates, returning the raw bytes so the
 * caller can copy them unchanged.
 */
function skipImmediates(c: Cursor, opcode: number): number[][] {
  if (opcode >= 0x45 && opcode <= 0xc4) return [];
  if (opcode >= 0x28 && opcode <= 0x3e) return skipMemArg(c);

  switch (opcode) {
    case 0x00:
    case 0x01:
    case 0x05:
    case 0x0b:
    case 0x0f:
    case 0x1a:
    case 0x1b:
    case 0xd1:
      return [];
    case 0x02:
    case 0x03:
    case 0x04:
      return skipBlockType(c);
    case 0x0c:
    case 0x0d:
    case 0x10:
    case 0x12:
    case 0x20:
    case 0x21:
    case 0x22:
    case 0x23:
    case 0x24:
    case 0x25:
    case 0x26:
    case 0xd2:
      return [uleb(c.u32())];
    case 0x0e: {
      const count = c.u32();
      const out: number[][] = [uleb(count)];
      for (let i = 0; i <= count; i++) out.push(uleb(c.u32()));
      return out;
    }
    case 0x11:
    case 0x13:
      return [uleb(c.u32()), uleb(c.u32())];
    case 0x14:
    case 0x15:
      return [uleb(c.u32())];
    case 0x1c: {
      const count = c.u32();
      const out: number[][] = [uleb(count)];
      out.push([...c.take(count)]);
      return out;
    }
    case 0x3f:
    case 0x40:
      return [[c.byte()]];
    case 0x41:
    case 0x42: {
      const start = c.pos;
      c.sleb();
      return [[...c.bytes.subarray(start, c.pos)]];
    }
    case 0x43:
      return [[...c.take(4)]];
    case 0x44:
      return [[...c.take(8)]];
    case 0xd0: {
      const start = c.pos;
      c.sleb();
      return [[...c.bytes.subarray(start, c.pos)]];
    }
    case 0xfc: {
      const sub = c.u32();
      const out: number[][] = [uleb(sub)];
      if (sub === 8 || sub === 9 || sub === 12 || sub === 13) out.push(uleb(c.u32()));
      else if (sub === 10 || sub === 11 || sub === 14) out.push(uleb(c.u32()), uleb(c.u32()));
      else if (sub >= 15 && sub <= 17) out.push(uleb(c.u32()));
      return out;
    }
    case 0x1f:
    case 0xfd:
    case 0xfe:
      throw new FuelMeterError(
        `Cannot meter a module using the 0x${opcode.toString(16)} proposal; run it on a runtime with fuel metering support.`,
      );
    default:
      throw new FuelMeterError(`Cannot decode WebAssembly opcode 0x${opcode.toString(16)}.`);
  }
}

/** Rewrites a function body, injecting a fuel check at entry and each loop. */
function meterBody(code: Uint8Array, globalIndex: number): { body: number[]; loops: number } {
  const c = new Cursor(code);
  const localsCount = c.u32();
  const locals: number[][] = [uleb(localsCount)];
  for (let i = 0; i < localsCount; i++) locals.push(uleb(c.u32()), [c.byte()]);

  const out: number[] = concat(locals);
  const check = fuelCheck(globalIndex);
  out.push(...check);

  let loops = 0;
  while (!c.done) {
    const opcode = c.byte();
    out.push(opcode);
    const immediates = skipImmediates(c, opcode);
    out.push(...concat(immediates));
    if (opcode === 0x03) {
      // `loop` carries its block type; the check belongs inside the body, so it
      // goes after the block type rather than before the opcode.
      out.push(...check);
      loops++;
    }
  }

  return { body: out, loops };
}

function section(id: number, payload: number[]): number[] {
  return [id, ...u32Bytes(payload.length), ...payload];
}

/** Reads the module's section list without interpreting payloads. */
function readSections(bytes: Uint8Array): { id: number; payload: Uint8Array }[] {
  if (bytes.length < 8) throw new FuelMeterError('Not a WebAssembly module: too short.');
  for (let i = 0; i < 4; i++) {
    if (bytes[i] !== WASM_MAGIC[i])
      throw new FuelMeterError('Not a WebAssembly module: bad magic.');
  }
  const c = new Cursor(bytes, 8);
  const sections: { id: number; payload: Uint8Array }[] = [];
  while (!c.done) {
    const id = c.byte();
    const size = c.u32();
    sections.push({ id, payload: c.take(size) });
  }
  return sections;
}

function countImportedGlobals(payload: Uint8Array): number {
  const c = new Cursor(payload);
  const count = c.u32();
  let globals = 0;
  for (let i = 0; i < count; i++) {
    c.name();
    c.name();
    const kind = c.byte();
    switch (kind) {
      case 0x00:
        c.u32();
        break;
      case 0x01: {
        c.byte(); // element type
        skipLimits(c);
        break;
      }
      case 0x02:
        skipLimits(c);
        break;
      case 0x03:
        globals++;
        c.byte();
        c.byte();
        break;
      default:
        throw new FuelMeterError(`Unknown import kind 0x${kind.toString(16)}.`);
    }
  }
  return globals;
}

function countDefinedGlobals(payload: Uint8Array): number {
  const c = new Cursor(payload);
  const count = c.u32();
  for (let i = 0; i < count; i++) {
    c.byte();
    c.byte();
    c.sleb(); // init expr constant
    if (c.byte() !== 0x0b)
      throw new FuelMeterError('Malformed WebAssembly: unclosed global initialiser.');
  }
  return count;
}

/**
 * Instruments a module so that execution is bounded by `fuel` steps.
 *
 * Each function entry costs one unit and each loop iteration costs one, so the
 * budget bounds work rather than wall-clock time: the same input always burns
 * the same fuel, which is what makes the limit testable.
 */
export function injectFuelMeter(
  module: Uint8Array,
  fuel: number = DEFAULT_FUEL,
): InstrumentedModule {
  if (!Number.isSafeInteger(fuel) || fuel <= 0) {
    throw new FuelMeterError('Fuel must be a positive integer.');
  }

  const sections = readSections(module);
  const importSection = sections.find((s) => s.id === 2);
  const globalSection = sections.find((s) => s.id === 6);
  const importedGlobals = importSection ? countImportedGlobals(importSection.payload) : 0;
  const definedGlobals = globalSection ? countDefinedGlobals(globalSection.payload) : 0;
  const fuelGlobalIndex = importedGlobals + definedGlobals;

  // i32, mutable, initialised to the budget.
  const fuelGlobal: number[] = [0x7f, 0x01, 0x41, ...uleb(fuel), 0x0b];

  let loopsMetered = 0;
  const out: number[] = [...WASM_MAGIC, WASM_VERSION, 0, 0, 0];

  let globalWritten = false;
  let exportWritten = false;

  const writeGlobal = (): void => {
    if (globalWritten) return;
    globalWritten = true;
    let payload: number[];
    if (globalSection) {
      const c = new Cursor(globalSection.payload);
      c.u32();
      payload = [
        ...uleb(definedGlobals + 1),
        ...globalSection.payload.subarray(c.pos),
        ...fuelGlobal,
      ];
    } else {
      payload = [...uleb(1), ...fuelGlobal];
    }
    out.push(...section(6, payload));
  };

  const writeExport = (): void => {
    if (exportWritten) return;
    exportWritten = true;
    const name = [...new TextEncoder().encode(FUEL_EXPORT_NAME)];
    const entry = [...uleb(name.length), ...name, 0x03, ...uleb(fuelGlobalIndex)];
    const existing = sections.find((s) => s.id === 7);
    let payload: number[];
    if (existing) {
      const c = new Cursor(existing.payload);
      const count = c.u32();
      payload = [...uleb(count + 1), ...existing.payload.subarray(c.pos), ...entry];
    } else {
      payload = [...uleb(1), ...entry];
    }
    out.push(...section(7, payload));
  };

  for (const { id, payload } of sections) {
    if (id > 6 && !globalWritten) writeGlobal();
    if (id > 7 && !exportWritten) writeExport();

    if (id === 6) {
      writeGlobal();
      continue;
    }
    if (id === 7) {
      // Emitted here so its count can carry the extra export, but only after
      // the global section: the format requires section 6 before 7.
      writeGlobal();
      writeExport();
      continue;
    }
    if (id !== 10) {
      out.push(...section(id, [...payload]));
      continue;
    }

    const c = new Cursor(payload);
    const bodyCount = c.u32();
    const bodies: number[][] = [uleb(bodyCount)];
    for (let i = 0; i < bodyCount; i++) {
      const size = c.u32();
      const body = c.take(size);
      const metered = meterBody(body, fuelGlobalIndex);
      loopsMetered += metered.loops;
      bodies.push(uleb(metered.body.length), metered.body);
    }
    out.push(...section(10, concat(bodies)));
  }

  if (!globalWritten) writeGlobal();
  if (!exportWritten) writeExport();

  return {
    bytes: Uint8Array.from(out),
    fuelGlobalIndex,
    loopsMetered,
  };
}
