/**
 * A small, dependency-free WebAssembly reader.
 *
 * The Soroban security audits need more from a contract binary than a byte
 * scan: the import list (which host functions a contract calls), the type and
 * function sections (to name functions and their callers), the memory limits,
 * the data strings, and every function body's instructions with byte offsets
 * so a finding can point at the exact instruction.
 *
 * This module parses those sections directly. It is deliberately permissive:
 * an instruction prefix it does not model stops the walk of that body rather
 * than desynchronising the following ones, and an undecodable section throws
 * `WasmModuleError` so the caller can report an invalid binary.
 */

/** Raised when the bytes are not a WebAssembly module this reader understands. */
export class WasmModuleError extends Error {
  /** Byte offset at which parsing stopped. */
  readonly offset: number;

  constructor(message: string, offset: number) {
    super(`${message} (at byte ${offset})`);
    this.name = 'WasmModuleError';
    this.offset = offset;
  }
}

/** One value type, as encoded in the binary. */
export type WasmValueType = number;

/** A function type: `(params) -> results`. */
export interface WasmFuncType {
  form: number;
  params: WasmValueType[];
  results: WasmValueType[];
}

/** Limits on a table or memory. */
export interface WasmLimits {
  minimum: number;
  maximum?: number;
  shared: boolean;
  memory64: boolean;
}

export type WasmImportKind = 'function' | 'table' | 'memory' | 'global';
export type WasmExportKind = 'function' | 'table' | 'memory' | 'global';

/** One entry of the import section. */
export interface WasmImport {
  /** Absolute function/table/memory/global index, counting earlier imports. */
  index: number;
  module: string;
  field: string;
  kind: WasmImportKind;
  /** Type index for function imports. */
  typeIndex?: number;
  limits?: WasmLimits;
}

/** One entry of the export section. */
export interface WasmExport {
  name: string;
  kind: WasmExportKind;
  index: number;
}

/** One instruction the walker recorded. */
export interface WasmInstruction {
  /** Absolute byte offset of the opcode in the module. */
  offset: number;
  opcode: number;
  /** Sub-opcode for `0xFB`/`0xFC`/`0xFD`/`0xFE` prefixes. */
  subOpcode?: number;
  /** Nesting depth of structured control instructions at this point. */
  depth: number;
}

/** A `call` instruction, resolved to the callee's function index. */
export interface WasmCall {
  target: number;
  offset: number;
}

/** A `loop` block and whether its body can leave it. */
export interface WasmLoop {
  /** Offset of the `loop` opcode. */
  offset: number;
  /** Offset of the matching `end`. */
  endOffset: number;
  /** Number of conditional branches/returns/unreachable inside the body. */
  exits: number;
}

/** One defined function body. */
export interface WasmFunction {
  /** Absolute function index (imports come first). */
  index: number;
  name: string;
  typeIndex: number;
  /** Number of declared locals, not counting parameters. */
  locals: number;
  instructions: WasmInstruction[];
  calls: WasmCall[];
  loops: WasmLoop[];
  /** Offsets of `memory.grow` instructions. */
  memoryGrow: number[];
  /** True when the walk stopped early at an unmodelled instruction prefix. */
  truncated: boolean;
}

/** A data segment with the bytes it initializes. */
export interface WasmDataSegment {
  /** True for a passive segment. */
  passive: boolean;
  bytes: Buffer;
}

/** The parsed module. */
export interface WasmModule {
  version: number;
  types: WasmFuncType[];
  imports: WasmImport[];
  /** Function type indices, in defined-function order. */
  functionTypes: number[];
  memories: WasmLimits[];
  exports: WasmExport[];
  functions: WasmFunction[];
  data: WasmDataSegment[];
  /** Printable strings found in active/passive data segments. */
  strings: string[];
  /** Every custom section, by name. */
  customSections: Map<string, Buffer>;
}

/** A bounds-checked little-endian reader over the module bytes. */
class Reader {
  offset = 0;

  constructor(readonly bytes: Buffer) {}

  get length(): number {
    return this.bytes.length;
  }

  eof(): boolean {
    return this.offset >= this.bytes.length;
  }

  u8(): number {
    if (this.offset >= this.bytes.length) {
      throw new WasmModuleError('unexpected end of binary', this.offset);
    }
    return this.bytes[this.offset++] as number;
  }

  /** Unsigned LEB128, at most 32 bits. */
  u32(): number {
    let result = 0;
    let shift = 0;
    for (let i = 0; i < 5; i++) {
      const byte = this.u8();
      result += (byte & 0x7f) * 2 ** shift;
      if ((byte & 0x80) === 0) {
        if (result > 0xffffffff)
          throw new WasmModuleError('LEB128 value overflows u32', this.offset);
        return result;
      }
      shift += 7;
    }
    throw new WasmModuleError('LEB128 value is too long', this.offset);
  }

  /** Signed LEB128, at most 64 bits. */
  s64(): bigint {
    let result = 0n;
    let shift = 0n;
    for (let i = 0; i < 10; i++) {
      const byte = this.u8();
      result |= BigInt(byte & 0x7f) << shift;
      shift += 7n;
      if ((byte & 0x80) === 0) {
        if ((byte & 0x40) !== 0) result -= 1n << shift;
        return result;
      }
    }
    throw new WasmModuleError('LEB128 value is too long', this.offset);
  }

  /** Signed LEB128, used for block types and `i32.const`. */
  s32(): number {
    return Number(BigInt.asIntN(32, this.s64()));
  }

  /** A length-prefixed UTF-8 name. */
  name(): string {
    const length = this.u32();
    if (this.offset + length > this.bytes.length) {
      throw new WasmModuleError('name runs past the end of the module', this.offset);
    }
    const value = this.bytes.subarray(this.offset, this.offset + length).toString('utf8');
    this.offset += length;
    return value;
  }

  /** A length-prefixed byte string. */
  slice(length: number): Buffer {
    if (this.offset + length > this.bytes.length) {
      throw new WasmModuleError('payload runs past the end of the module', this.offset);
    }
    const value = this.bytes.subarray(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }

  skip(length: number): void {
    if (this.offset + length > this.bytes.length) {
      throw new WasmModuleError('payload runs past the end of the module', this.offset);
    }
    this.offset += length;
  }
}

const KIND_BY_ID: Record<number, WasmImportKind> = {
  0x00: 'function',
  0x01: 'table',
  0x02: 'memory',
  0x03: 'global',
};

function importKind(id: number): WasmImportKind {
  const kind = KIND_BY_ID[id];
  if (kind === undefined) throw new Error(`unknown import kind 0x${id.toString(16)}`);
  return kind;
}

function readLimits(reader: Reader): WasmLimits {
  const flags = reader.u8();
  if ((flags & ~0x07) !== 0) {
    throw new WasmModuleError(`unsupported limits flags 0x${flags.toString(16)}`, reader.offset);
  }
  const shared = (flags & 0x02) !== 0;
  const memory64 = (flags & 0x04) !== 0;
  const minimum = memory64 ? Number(reader.s64()) : reader.u32();
  const maximum =
    (flags & 0x01) !== 0 ? (memory64 ? Number(reader.s64()) : reader.u32()) : undefined;
  return {
    minimum,
    ...(maximum !== undefined ? { maximum } : {}),
    shared,
    memory64,
  };
}

function readTableType(reader: Reader): void {
  reader.u8(); // element type
  readLimits(reader);
}

function readGlobalType(reader: Reader): void {
  reader.u8(); // value type
  reader.u8(); // mutability
}

const VALUE_TYPES = new Set([0x7f, 0x7e, 0x7d, 0x7c, 0x7b, 0x70, 0x6f]);

/** Reads a block type: `0x40`, a value type, or a type index. */
function skipBlockType(reader: Reader): void {
  const byte = reader.bytes[reader.offset];
  if (byte === undefined) throw new WasmModuleError('missing block type', reader.offset);
  if (byte === 0x40 || VALUE_TYPES.has(byte)) {
    reader.offset++;
    return;
  }
  reader.s64();
}

/** Reads a `memarg`: alignment and offset, both unsigned LEB128. */
function skipMemarg(reader: Reader): void {
  reader.u32();
  reader.u32();
}

/** Skips one SIMD immediate, following the shape of the SIMD proposal. */
function skipSimdImmediate(reader: Reader, subOpcode: number): void {
  if (subOpcode <= 0x0b) return skipMemarg(reader);
  if (subOpcode === 0x0c || subOpcode === 0x0d) return reader.skip(16);
  if (subOpcode >= 0x15 && subOpcode <= 0x22) return reader.skip(1);
  if (subOpcode >= 0x54 && subOpcode <= 0x5b) {
    skipMemarg(reader);
    reader.skip(1);
    return;
  }
  if (subOpcode === 0x5c || subOpcode === 0x5d) return skipMemarg(reader);
}

function skipAtomicImmediate(reader: Reader, subOpcode: number): void {
  if (subOpcode === 0x03) {
    reader.skip(1); // fence: consistency model
    return;
  }
  skipMemarg(reader);
}

/** A control-flow frame while walking one function body. */
interface ControlFrame {
  kind: 'block' | 'loop' | 'if';
  offset: number;
  exits: number;
}

/**
 * Walks one function body, recording calls, loops, growth operators and the
 * offsets of every instruction.
 */
function scanBody(
  reader: Reader,
  end: number,
  index: number,
  name: string,
  typeIndex: number,
  locals: number,
): WasmFunction {
  const instructions: WasmInstruction[] = [];
  const calls: WasmCall[] = [];
  const loops: WasmLoop[] = [];
  const memoryGrow: number[] = [];
  const frames: ControlFrame[] = [];
  let truncated = false;

  const noteExit = (): void => {
    for (const frame of frames) frame.exits++;
  };

  try {
    while (reader.offset < end) {
      const offset = reader.offset;
      const opcode = reader.u8();

      if (opcode === 0x02 || opcode === 0x03 || opcode === 0x04) {
        skipBlockType(reader);
        frames.push({
          kind: opcode === 0x02 ? 'block' : opcode === 0x03 ? 'loop' : 'if',
          offset,
          exits: 0,
        });
        instructions.push({ offset, opcode, depth: frames.length - 1 });
        continue;
      }

      if (opcode === 0x0b) {
        const frame = frames.pop();
        if (frame?.kind === 'loop') {
          loops.push({ offset: frame.offset, endOffset: offset, exits: frame.exits });
        }
        instructions.push({ offset, opcode, depth: frames.length });
        if (frames.length === 0) return finish();
        continue;
      }

      if (opcode === 0x00 || opcode === 0x0f || opcode === 0x0d || opcode === 0x0e) {
        // unreachable / return / br_if / br_table can leave a loop body.
        noteExit();
      }

      if (opcode === 0x10) {
        const target = reader.u32();
        calls.push({ target, offset });
      } else if (opcode === 0x11 || opcode === 0x13) {
        reader.u32(); // type index
        reader.u32(); // table index
      } else if (opcode === 0x0c || opcode === 0x0d) {
        reader.u32(); // branch depth
      } else if (opcode === 0x0e) {
        const labels = reader.u32();
        for (let i = 0; i <= labels; i++) reader.u32();
      } else if (opcode >= 0x20 && opcode <= 0x26) {
        reader.u32(); // local/global/table index
      } else if (opcode === 0x1c) {
        const types = reader.u32();
        for (let i = 0; i < types; i++) reader.u8();
      } else if (opcode >= 0x28 && opcode <= 0x3e) {
        skipMemarg(reader);
      } else if (opcode === 0x3f || opcode === 0x40) {
        if (opcode === 0x40) memoryGrow.push(offset);
        reader.u32(); // memory index
      } else if (opcode === 0x41) {
        reader.s32();
      } else if (opcode === 0x42) {
        reader.s64();
      } else if (opcode === 0x43) {
        reader.skip(4);
      } else if (opcode === 0x44) {
        reader.skip(8);
      } else if (opcode === 0xd0) {
        const byte = reader.bytes[reader.offset];
        if (byte !== undefined && VALUE_TYPES.has(byte)) reader.offset++;
        else reader.s64(); // heap type
      } else if (opcode === 0xd2) {
        reader.u32(); // function index
      } else if (opcode === 0xfc) {
        const subOpcode = reader.u32();
        if (subOpcode === 8) {
          reader.u32(); // data index
          reader.u32(); // memory index
        } else if (
          subOpcode === 9 ||
          subOpcode === 13 ||
          subOpcode === 15 ||
          subOpcode === 16 ||
          subOpcode === 17
        ) {
          reader.u32();
        } else if (subOpcode === 10) {
          reader.u32();
          reader.u32();
        } else if (subOpcode === 11) {
          reader.u32();
        } else if (subOpcode === 12 || subOpcode === 14) {
          reader.u32();
          reader.u32();
        } else if (subOpcode === 18) {
          reader.u32();
        }
        instructions.push({ offset, opcode, subOpcode, depth: frames.length });
        continue;
      } else if (opcode === 0xfd) {
        const subOpcode = reader.u32();
        skipSimdImmediate(reader, subOpcode);
        instructions.push({ offset, opcode, subOpcode, depth: frames.length });
        continue;
      } else if (opcode === 0xfe) {
        const subOpcode = reader.u32();
        skipAtomicImmediate(reader, subOpcode);
        instructions.push({ offset, opcode, subOpcode, depth: frames.length });
        continue;
      } else if (opcode === 0xfb) {
        // GC instructions carry immediates this reader does not model.
        truncated = true;
        break;
      }

      instructions.push({ offset, opcode, depth: frames.length });
    }

    throw new WasmModuleError('function body is missing its end opcode', reader.offset);
  } catch (error) {
    if (error instanceof WasmModuleError) {
      // A body we cannot finish still yields the calls, loops and growth
      // operators found before the unmodelled instruction.
      truncated = true;
      reader.offset = end;
      const fn = finish();
      fn.truncated = true;
      return fn;
    }
    throw error;
  }

  function finish(): WasmFunction {
    return {
      index,
      name,
      typeIndex,
      locals,
      instructions,
      calls,
      loops,
      memoryGrow,
      truncated,
    };
  }
}

/** Extracts printable ASCII strings of at least `minimum` characters. */
export function printableStrings(bytes: Buffer, minimum = 4): string[] {
  const found: string[] = [];
  let current = '';
  for (const byte of bytes) {
    if (byte >= 0x20 && byte <= 0x7e) {
      current += String.fromCharCode(byte);
    } else {
      if (current.length >= minimum) found.push(current);
      current = '';
    }
  }
  if (current.length >= minimum) found.push(current);
  return found;
}

const MAGIC = [0x00, 0x61, 0x73, 0x6d];

/**
 * Parses a WebAssembly module.
 *
 * Throws `WasmModuleError` when the header, a section boundary or a core
 * section is malformed. Function-body instructions the walker does not model
 * only truncate that body, flagged by `WasmFunction.truncated`.
 */
export function parseWasmModule(input: Uint8Array): WasmModule {
  const bytes = Buffer.isBuffer(input) ? input : Buffer.from(input);
  if (bytes.length < 8) throw new WasmModuleError('binary is shorter than the module header', 0);
  for (let i = 0; i < MAGIC.length; i++) {
    if (bytes[i] !== MAGIC[i]) {
      throw new WasmModuleError('not a WebAssembly binary (bad \\0asm magic)', i);
    }
  }
  if (bytes[4] !== 0x01) {
    throw new WasmModuleError(`unsupported WebAssembly version ${bytes[4]}`, 4);
  }

  const reader = new Reader(bytes);
  reader.offset = 8;
  const version = bytes[4] as number;

  const types: WasmFuncType[] = [];
  const imports: WasmImport[] = [];
  const functionTypes: number[] = [];
  const memories: WasmLimits[] = [];
  const exports: WasmExport[] = [];
  const data: WasmDataSegment[] = [];
  const customSections = new Map<string, Buffer>();
  const bodies: { typeIndex: number; locals: number; start: number; end: number }[] = [];
  let importedFunctions = 0;

  while (!reader.eof()) {
    const id = reader.u8();
    const size = reader.u32();
    const payloadStart = reader.offset;
    const payloadEnd = payloadStart + size;
    if (payloadEnd > bytes.length) {
      throw new WasmModuleError('section runs past the end of the module', payloadStart);
    }

    if (id === 0) {
      const sectionReader = new Reader(bytes.subarray(payloadStart, payloadEnd));
      const name = sectionReader.name();
      customSections.set(name, bytes.subarray(payloadStart, payloadEnd));
      reader.offset = payloadEnd;
      continue;
    }

    const section = new Reader(bytes.subarray(payloadStart, payloadEnd));
    switch (id) {
      case 1: {
        const count = section.u32();
        for (let i = 0; i < count; i++) {
          const form = section.u8();
          const params = section.u32();
          const paramTypes: number[] = [];
          for (let p = 0; p < params; p++) paramTypes.push(section.u8());
          const results = section.u32();
          const resultTypes: number[] = [];
          for (let r = 0; r < results; r++) resultTypes.push(section.u8());
          types.push({ form, params: paramTypes, results: resultTypes });
        }
        break;
      }
      case 2: {
        const count = section.u32();
        for (let i = 0; i < count; i++) {
          const module = section.name();
          const field = section.name();
          const kind = importKind(section.u8());
          const entry: WasmImport = { index: 0, module, field, kind };
          if (kind === 'function') {
            entry.typeIndex = section.u32();
            entry.index = importedFunctions++;
          } else if (kind === 'table') {
            readTableType(section);
            entry.index = 0;
          } else if (kind === 'memory') {
            entry.limits = readLimits(section);
            memories.push(entry.limits);
            entry.index = memories.length - 1;
          } else {
            readGlobalType(section);
            entry.index = 0;
          }
          imports.push(entry);
        }
        break;
      }
      case 3: {
        const count = section.u32();
        for (let i = 0; i < count; i++) functionTypes.push(section.u32());
        break;
      }
      case 5: {
        const count = section.u32();
        for (let i = 0; i < count; i++) memories.push(readLimits(section));
        break;
      }
      case 7: {
        const names: string[] = [];
        const count = section.u32();
        for (let i = 0; i < count; i++) {
          names.push(section.name());
          const kindByte = section.u8();
          const kind = KIND_BY_ID[kindByte];
          if (kind === undefined) throw new Error(`unknown export kind 0x${kindByte.toString(16)}`);
          exports.push({ name: names[i] as string, kind, index: section.u32() });
        }
        break;
      }
      case 10: {
        const count = section.u32();
        for (let i = 0; i < count; i++) {
          const bodySize = section.u32();
          const bodyStart = payloadStart + section.offset;
          const bodyEnd = bodyStart + bodySize;
          if (bodyEnd > payloadEnd) {
            throw new WasmModuleError('function body runs past the code section', bodyStart);
          }
          const bodyReader = new Reader(bytes.subarray(bodyStart, bodyEnd));
          const localGroups = bodyReader.u32();
          let locals = 0;
          for (let g = 0; g < localGroups; g++) {
            locals += bodyReader.u32();
            bodyReader.u8(); // value type
          }
          bodies.push({
            typeIndex: functionTypes[i] ?? 0,
            locals,
            start: bodyStart + bodyReader.offset,
            end: bodyEnd,
          });
          section.offset = bodyEnd - payloadStart;
        }
        break;
      }
      case 11: {
        const count = section.u32();
        for (let i = 0; i < count; i++) {
          const flags = section.u32();
          if (flags === 0) {
            // active, memory 0: offset expression
            skipConstExpr(section);
            const length = section.u32();
            data.push({ passive: false, bytes: section.slice(length) });
          } else if (flags === 1) {
            const length = section.u32();
            data.push({ passive: true, bytes: section.slice(length) });
          } else {
            // active with an explicit memory index (or a declarative segment)
            section.u32();
            skipConstExpr(section);
            const length = section.u32();
            data.push({ passive: flags === 3, bytes: section.slice(length) });
          }
        }
        break;
      }
      default:
        break;
    }
    reader.offset = payloadEnd;
  }

  const nameSection = customSections.get('name');
  const names =
    nameSection === undefined ? new Map<number, string>() : parseNameSection(nameSection);

  const exportNames = new Map<number, string>();
  for (const entry of exports) {
    if (entry.kind === 'function' && !exportNames.has(entry.index)) {
      exportNames.set(entry.index, entry.name);
    }
  }

  const functions: WasmFunction[] = [];
  for (let i = 0; i < bodies.length; i++) {
    const body = bodies[i] as { typeIndex: number; locals: number; start: number; end: number };
    const index = importedFunctions + i;
    const name = names.get(index) ?? exportNames.get(index) ?? `func[${index}]`;
    const bodyReader = new Reader(bytes);
    bodyReader.offset = body.start;
    functions.push(scanBody(bodyReader, body.end, index, name, body.typeIndex, body.locals));
  }

  const strings = [...new Set(data.flatMap((segment) => printableStrings(segment.bytes)))];

  return {
    version,
    types,
    imports,
    functionTypes,
    memories,
    exports,
    functions,
    data,
    strings,
    customSections,
  };
}

/** Skips an initializer expression that ends with `end` (0x0B). */
function skipConstExpr(reader: Reader): void {
  let depth = 0;
  for (;;) {
    const opcode = reader.u8();
    if (opcode === 0x0b) {
      if (depth === 0) return;
      depth--;
      continue;
    }
    if (opcode === 0x02 || opcode === 0x03 || opcode === 0x04) {
      skipBlockType(reader);
      depth++;
    } else if (opcode === 0x41) {
      reader.s32();
    } else if (opcode === 0x42) {
      reader.s64();
    } else if (opcode === 0x43) {
      reader.skip(4);
    } else if (opcode === 0x44) {
      reader.skip(8);
    } else if (opcode === 0xd0) {
      reader.s64();
    } else if (opcode === 0xd2) {
      reader.u32();
    } else if (opcode === 0x10) {
      reader.u32();
    } else if (opcode >= 0x20 && opcode <= 0x26) {
      reader.u32();
    } else if (opcode === 0xfc || opcode === 0xfd || opcode === 0xfe || opcode === 0xfb) {
      reader.u32();
    }
  }
}

/** Reads the function-name subsection of a `name` custom section. */
function parseNameSection(section: Buffer): Map<number, string> {
  const names = new Map<number, string>();
  const reader = new Reader(section);
  try {
    reader.name(); // "name"
    while (!reader.eof()) {
      const id = reader.u8();
      const size = reader.u32();
      const end = reader.offset + size;
      if (id === 1) {
        const count = reader.u32();
        for (let i = 0; i < count; i++) {
          const index = reader.u32();
          names.set(index, reader.name());
        }
      }
      reader.offset = end;
    }
  } catch {
    // A malformed name section only costs us function names.
  }
  return names;
}

/** The function a call index refers to, when the module defines it. */
export function functionByIndex(module: WasmModule, index: number): WasmFunction | undefined {
  return module.functions.find((fn) => fn.index === index);
}

/** The imported host function a call index refers to, when it is one. */
export function importedFunction(module: WasmModule, index: number): WasmImport | undefined {
  return module.imports.find((entry) => entry.kind === 'function' && entry.index === index);
}

/** The names of the functions an entry imports from its host module. */
export function importedFunctionNames(module: WasmModule): string[] {
  return module.imports.filter((entry) => entry.kind === 'function').map((entry) => entry.field);
}
