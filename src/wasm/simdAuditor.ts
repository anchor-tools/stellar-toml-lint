/**
 * WebAssembly SIMD capability and memory-growth auditor.
 *
 * A module compiled with the SIMD proposal (`v128` and the `0xFD` opcode
 * prefix) is roughly 4x faster for hashing and parsing, but it fails to
 * instantiate in older mobile browsers and restricted embedded runtimes. The
 * same goes for memory: a module that calls `memory.grow` without a declared
 * maximum can balloon mid-request.
 *
 * `WasmSimdAuditor` parses the binary itself — no external disassembler — walks
 * every function body instruction by instruction, records `0xFD` opcodes, and
 * audits the memory section and `memory.grow` uses. It also probes the runtime
 * with a tiny SIMD module through `WebAssembly.validate` and, when SIMD is
 * present, recommends a dual SIMD/MVP build with the flags to produce it.
 */

import { WASM_PAGE_BYTES } from './heapProfiler.js';

export type SimdFindingCode =
  | 'wasm/invalid-binary'
  | 'simd/instructions-detected'
  | 'simd/unsupported-runtime'
  | 'memory/unbounded-growth';

export interface SimdFinding {
  code: SimdFindingCode;
  severity: 'error' | 'warning';
  message: string;
  suggestion: string;
}

export interface SimdInstruction {
  /** SIMD sub-opcode following the 0xFD prefix. */
  opcode: number;
  name: string;
  count: number;
}

export interface MemoryGrowthAudit {
  memories: number;
  initialPages: number;
  maximumPages?: number;
  initialBytes: number;
  maximumBytes?: number;
  /** `memory.grow` instruction count in the code section. */
  growOps: number;
  /** `memory.size` instruction count. */
  sizeOps: number;
  /** True when the memory section declares a maximum. */
  bounded: boolean;
}

export interface SimdAuditReport {
  file?: string;
  valid: boolean;
  sizeBytes: number;
  simd: boolean;
  instructions: SimdInstruction[];
  simdOpCount: number;
  memory: MemoryGrowthAudit;
  runtimeSupportsSimd: boolean;
  dualBuildRecommended: boolean;
  findings: SimdFinding[];
  fallback: string[];
  error?: string;
}

export interface SimdRuntimeLike {
  validate?(bytes: Uint8Array): boolean;
}

export interface SimdAuditOptions {
  file?: string;
  runtime?: SimdRuntimeLike;
}

/**
 * Smallest module whose only instruction is `v128.const`. `validate()` on it
 * answers the SIMD-capability question without compiling anything bigger.
 */
export const SIMD_PROBE_MODULE = Uint8Array.from([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic + version
  0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // type: () -> ()
  0x03, 0x02, 0x01, 0x00, // function: one function of type 0
  0x0a, 0x17, 0x01, 0x15, 0x00, // code: one body of 21 bytes, no locals
  0xfd, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // v128.const
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x1a, // drop
  0x0b, // end
]);

const SIMD_NAMES: Record<number, string> = {
  0x00: 'v128.load',
  0x01: 'v128.load8x8_s',
  0x02: 'v128.load8x8_u',
  0x03: 'v128.load16x4_s',
  0x04: 'v128.load16x4_u',
  0x05: 'v128.load32x2_s',
  0x06: 'v128.load32x2_u',
  0x07: 'v128.load8_splat',
  0x08: 'v128.load16_splat',
  0x09: 'v128.load32_splat',
  0x0a: 'v128.load64_splat',
  0x0b: 'v128.store',
  0x0c: 'v128.const',
  0x0d: 'i8x16.shuffle',
  0x0e: 'i8x16.swizzle',
  0x0f: 'i8x16.splat',
  0x10: 'i16x8.splat',
  0x11: 'i32x4.splat',
  0x12: 'i64x2.splat',
  0x13: 'f32x4.splat',
  0x14: 'f64x2.splat',
  0x15: 'i8x16.extract_lane_s',
  0x16: 'i8x16.extract_lane_u',
  0x17: 'i8x16.replace_lane',
  0x18: 'i16x8.extract_lane_s',
  0x19: 'i16x8.extract_lane_u',
  0x1a: 'i16x8.replace_lane',
  0x1b: 'i32x4.extract_lane',
  0x1c: 'i32x4.replace_lane',
  0x1d: 'i64x2.extract_lane',
  0x1e: 'i64x2.replace_lane',
  0x1f: 'f32x4.extract_lane',
  0x20: 'f32x4.replace_lane',
  0x21: 'f64x2.extract_lane',
  0x22: 'f64x2.replace_lane',
  0x54: 'v128.load8_lane',
  0x55: 'v128.load16_lane',
  0x56: 'v128.load32_lane',
  0x57: 'v128.load64_lane',
  0x58: 'v128.store8_lane',
  0x59: 'v128.store16_lane',
  0x5a: 'v128.store32_lane',
  0x5b: 'v128.store64_lane',
  0x5c: 'v128.load32_zero',
  0x5d: 'v128.load64_zero',
};

export class WasmScanError extends Error {
  readonly kind: 'invalid' | 'truncated';

  constructor(kind: 'invalid' | 'truncated', message: string) {
    super(message);
    this.name = 'WasmScanError';
    this.kind = kind;
  }
}

export interface WasmScanResult {
  sections: { id: number; size: number }[];
  memories: { minPages: number; maxPages?: number; shared: boolean }[];
  simdOpcodes: { opcode: number; count: number }[];
  growOps: number;
  sizeOps: number;
  functionBodies: number;
}

function truncated(what: string): WasmScanError {
  return new WasmScanError('truncated', `WASM binary ends inside ${what}`);
}

function invalid(what: string): WasmScanError {
  return new WasmScanError('invalid', what);
}

function readByte(bytes: Uint8Array, pos: number, limit: number): number {
  if (pos >= limit) throw truncated('an immediate operand');
  return bytes[pos] as number;
}

function readVarUint(
  bytes: Uint8Array,
  start: number,
  limit: number,
  maxBytes = 5,
): { value: number; pos: number } {
  let value = 0;
  let shift = 0;
  let pos = start;
  for (let i = 0; i < maxBytes; i++) {
    const byte = readByte(bytes, pos, limit);
    pos++;
    value += (byte & 0x7f) * 2 ** shift;
    if ((byte & 0x80) === 0) return { value, pos };
    shift += 7;
  }
  throw invalid('LEB128 integer is longer than its allowed width');
}

function readVarInt(
  bytes: Uint8Array,
  start: number,
  limit: number,
  maxBytes = 5,
): { value: number; pos: number } {
  let value = 0;
  let shift = 0;
  let pos = start;
  let byte = 0;
  for (let i = 0; i < maxBytes; i++) {
    byte = readByte(bytes, pos, limit);
    pos++;
    value |= (byte & 0x7f) << shift;
    shift += 7;
    if ((byte & 0x80) === 0) break;
    if (i === maxBytes - 1) throw invalid('signed LEB128 integer is too long');
  }
  if (shift < 32 && (byte & 0x40) !== 0) value |= -1 << shift;
  return { value, pos };
}

function skipMemarg(bytes: Uint8Array, pos: number, limit: number): number {
  const align = readVarUint(bytes, pos, limit);
  const offset = readVarUint(bytes, align.pos, limit, 10);
  return offset.pos;
}

const SINGLE_BYTE_BLOCK_TYPES = new Set([0x40, 0x7f, 0x7e, 0x7d, 0x7c, 0x7b, 0x70, 0x6f]);

function skipBlockType(bytes: Uint8Array, pos: number, limit: number): number {
  const first = readByte(bytes, pos, limit);
  if (SINGLE_BYTE_BLOCK_TYPES.has(first)) return pos + 1;
  // A negative type index: re-read the byte as signed LEB128.
  return readVarInt(bytes, pos, limit).pos;
}

function skipSimdImmediate(
  subOpcode: number,
  bytes: Uint8Array,
  pos: number,
  limit: number,
): number {
  if (subOpcode <= 0x0b) return skipMemarg(bytes, pos, limit);
  if (subOpcode === 0x0c || subOpcode === 0x0d) return pos + 16;
  if (subOpcode >= 0x15 && subOpcode <= 0x22) return pos + 1;
  if (subOpcode >= 0x54 && subOpcode <= 0x5b) {
    // memarg followed by a lane index byte
    return skipMemarg(bytes, pos, limit) + 1;
  }
  if (subOpcode === 0x5c || subOpcode === 0x5d) return skipMemarg(bytes, pos, limit);
  return pos;
}

function skipSimdOpcode(bytes: Uint8Array, pos: number, limit: number, state: ScanState): number {
  const sub = readVarUint(bytes, pos, limit);
  state.simd.set(sub.value, (state.simd.get(sub.value) ?? 0) + 1);
  return skipSimdImmediate(sub.value, bytes, sub.pos, limit);
}

interface ScanState {
  simd: Map<number, number>;
  growOps: number;
  sizeOps: number;
  functionBodies: number;
}

function scanFunctionBody(
  bytes: Uint8Array,
  start: number,
  end: number,
  state: ScanState,
): void {
  state.functionBodies++;
  let pos = start;

  // Local declarations: vec(local count, value type).
  const localGroups = readVarUint(bytes, pos, end);
  pos = localGroups.pos;
  for (let i = 0; i < localGroups.value; i++) {
    const count = readVarUint(bytes, pos, end);
    pos = count.pos + 1;
  }

  let depth = 0;
  while (pos < end) {
    const opcode = readByte(bytes, pos, end);
    pos++;

    if (opcode === 0x0b) {
      if (depth === 0) return;
      depth--;
      continue;
    }

    if (opcode === 0x02 || opcode === 0x03 || opcode === 0x04) {
      depth++;
      pos = skipBlockType(bytes, pos, end);
      continue;
    }

    if (opcode === 0x0e) {
      const labels = readVarUint(bytes, pos, end);
      pos = labels.pos;
      for (let i = 0; i <= labels.value; i++) {
        pos = readVarUint(bytes, pos, end).pos;
      }
      continue;
    }

    if (
      opcode === 0x0c ||
      opcode === 0x0d ||
      opcode === 0x10 ||
      opcode === 0x12 ||
      opcode === 0x14 ||
      opcode === 0x20 ||
      opcode === 0x21 ||
      opcode === 0x22 ||
      opcode === 0x23 ||
      opcode === 0x24 ||
      opcode === 0x25 ||
      opcode === 0x26 ||
      opcode === 0xd2
    ) {
      pos = readVarUint(bytes, pos, end).pos;
      continue;
    }

    if (opcode === 0x11 || opcode === 0x13) {
      pos = readVarUint(bytes, pos, end).pos;
      pos = readVarUint(bytes, pos, end).pos;
      continue;
    }

    if (opcode === 0x1c) {
      const types = readVarUint(bytes, pos, end);
      pos = types.pos + types.value;
      continue;
    }

    if (opcode >= 0x28 && opcode <= 0x3e) {
      pos = skipMemarg(bytes, pos, end);
      continue;
    }

    if (opcode === 0x3f || opcode === 0x40) {
      if (opcode === 0x3f) state.sizeOps++;
      else state.growOps++;
      pos += 1; // memory index
      continue;
    }

    if (opcode === 0x41 || opcode === 0x42) {
      pos = readVarInt(bytes, pos, end).pos;
      continue;
    }

    if (opcode === 0x43) {
      pos += 4;
      continue;
    }

    if (opcode === 0x44) {
      pos += 8;
      continue;
    }

    if (opcode === 0xd0) {
      pos += 1;
      continue;
    }

    if (opcode === 0xfc) {
      const sub = readVarUint(bytes, pos, end);
      pos = sub.pos;
      switch (sub.value) {
        case 8:
          pos = readVarUint(bytes, pos, end).pos + 1;
          break;
        case 9:
        case 13:
        case 15:
        case 16:
        case 17:
          pos = readVarUint(bytes, pos, end).pos;
          break;
        case 10:
        case 11:
          pos += sub.value === 11 ? 1 : 2;
          break;
        case 12:
        case 14:
          pos = readVarUint(bytes, pos, end).pos;
          pos = readVarUint(bytes, pos, end).pos;
          break;
        default:
          break;
      }
      continue;
    }

    if (opcode === 0xfd) {
      pos = skipSimdOpcode(bytes, pos, end, state);
      continue;
    }

    if (opcode === 0xfe) {
      const sub = readVarUint(bytes, pos, end);
      pos = sub.value === 0x03 ? sub.pos + 1 : skipMemarg(bytes, sub.pos, end);
      continue;
    }

    if (opcode === 0xfb) {
      // GC instructions carry immediates this scanner does not model; stop
      // walking the body rather than desynchronising on the next byte.
      return;
    }
  }

  throw truncated('a function body (missing 0x0B end opcode)');
}

/** Parses sections and walks every function body. Throws `WasmScanError`. */
export function scanWasmBinary(bytes: Uint8Array): WasmScanResult {
  if (bytes.byteLength < 8) throw truncated('the module header');
  const magic = [0x00, 0x61, 0x73, 0x6d];
  for (let i = 0; i < magic.length; i++) {
    if (bytes[i] !== magic[i]) throw invalid('not a WebAssembly binary (bad \\0asm magic)');
  }
  if (bytes[4] !== 0x01 || bytes[5] !== 0x00) {
    throw invalid(`unsupported WebAssembly binary version ${bytes[4]}.${bytes[5]}`);
  }

  const state: ScanState = { simd: new Map(), growOps: 0, sizeOps: 0, functionBodies: 0 };
  const memories: WasmScanResult['memories'] = [];
  const sections: WasmScanResult['sections'] = [];

  let pos = 8;
  while (pos < bytes.byteLength) {
    const id = readByte(bytes, pos, bytes.byteLength);
    const declared = readVarUint(bytes, pos + 1, bytes.byteLength);
    const start = declared.pos;
    const end = start + declared.value;
    if (end > bytes.byteLength) throw truncated(`section ${id}`);

    sections.push({ id, size: declared.value });

    if (id === 5) {
      const count = readVarUint(bytes, start, end);
      let cursor = count.pos;
      for (let i = 0; i < count.value; i++) {
        const flags = readVarUint(bytes, cursor, end);
        cursor = flags.pos;
        const min = readVarUint(bytes, cursor, end);
        cursor = min.pos;
        const hasMax = (flags.value & 0x01) !== 0;
        const shared = (flags.value & 0x02) !== 0;
        let maxPages: number | undefined;
        if (hasMax) {
          const max = readVarUint(bytes, cursor, end);
          cursor = max.pos;
          maxPages = max.value;
        }
        memories.push({
          minPages: min.value,
          ...(maxPages !== undefined ? { maxPages } : {}),
          shared,
        });
      }
    } else if (id === 10) {
      const count = readVarUint(bytes, start, end);
      let cursor = count.pos;
      for (let i = 0; i < count.value; i++) {
        const size = readVarUint(bytes, cursor, end);
        const bodyStart = size.pos;
        const bodyEnd = bodyStart + size.value;
        if (bodyEnd > end) throw truncated('a function body');
        scanFunctionBody(bytes, bodyStart, bodyEnd, state);
        cursor = bodyEnd;
      }
    }

    pos = end;
  }

  return {
    sections,
    memories,
    simdOpcodes: [...state.simd.entries()]
      .map(([opcode, count]) => ({ opcode, count }))
      .sort((a, b) => b.count - a.count || a.opcode - b.opcode),
    growOps: state.growOps,
    sizeOps: state.sizeOps,
    functionBodies: state.functionBodies,
  };
}

const runtimeWithSimd = (): SimdRuntimeLike | undefined =>
  (globalThis as unknown as { WebAssembly?: SimdRuntimeLike }).WebAssembly;

/** Probes SIMD support with `WebAssembly.validate` on a tiny v128 module. */
export function detectSimdSupport(runtime: SimdRuntimeLike | undefined = runtimeWithSimd()): boolean {
  if (typeof runtime?.validate !== 'function') return false;
  try {
    return runtime.validate(SIMD_PROBE_MODULE);
  } catch {
    return false;
  }
}

function emptyMemoryAudit(): MemoryGrowthAudit {
  return {
    memories: 0,
    initialPages: 0,
    initialBytes: 0,
    growOps: 0,
    sizeOps: 0,
    bounded: false,
  };
}

/** Audits SIMD instructions, runtime support, and memory-growth behaviour. */
export function auditWasmBinary(bytes: Uint8Array, options: SimdAuditOptions = {}): SimdAuditReport {
  const runtimeSupportsSimd = detectSimdSupport(options.runtime);
  const findings: SimdFinding[] = [];

  let scan: WasmScanResult;
  try {
    scan = scanWasmBinary(bytes);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    findings.push({
      code: 'wasm/invalid-binary',
      severity: 'error',
      message: `Not a parseable WebAssembly binary: ${detail}`,
      suggestion: 'Rebuild the artifact and confirm --file points at the compiled .wasm, not a source map.',
    });
    return {
      ...(options.file !== undefined ? { file: options.file } : {}),
      valid: false,
      sizeBytes: bytes.byteLength,
      simd: false,
      instructions: [],
      simdOpCount: 0,
      memory: emptyMemoryAudit(),
      runtimeSupportsSimd,
      dualBuildRecommended: false,
      findings,
      fallback: renderSimdFallback(),
      error: detail,
    };
  }

  const memorySection = scan.memories[0];
  const initialPages = memorySection?.minPages ?? 0;
  const maximumPages = memorySection?.maxPages;
  const memory: MemoryGrowthAudit = {
    memories: scan.memories.length,
    initialPages,
    ...(maximumPages !== undefined ? { maximumPages } : {}),
    initialBytes: initialPages * WASM_PAGE_BYTES,
    ...(maximumPages !== undefined ? { maximumBytes: maximumPages * WASM_PAGE_BYTES } : {}),
    growOps: scan.growOps,
    sizeOps: scan.sizeOps,
    bounded: maximumPages !== undefined,
  };

  const instructions: SimdInstruction[] = scan.simdOpcodes.map(({ opcode, count }) => ({
    opcode,
    name: SIMD_NAMES[opcode] ?? `simd.0x${opcode.toString(16)}`,
    count,
  }));
  const simdOpCount = instructions.reduce((sum, instruction) => sum + instruction.count, 0);
  const simd = simdOpCount > 0;

  if (simd) {
    findings.push({
      code: 'simd/instructions-detected',
      severity: 'warning',
      message:
        `Module contains ${simdOpCount} SIMD instruction(s) ` +
        `(${instructions.map((instruction) => `${instruction.name} ×${instruction.count}`).join(', ')}); ` +
        'engines without the SIMD proposal cannot instantiate it.',
      suggestion:
        'Ship a dual build — a SIMD artifact and a non-SIMD (MVP) artifact — and select one with WebAssembly.validate().',
    });
    if (!runtimeSupportsSimd) {
      findings.push({
        code: 'simd/unsupported-runtime',
        severity: 'error',
        message: 'The current runtime rejected the SIMD probe module, so this module cannot load here.',
        suggestion: 'Serve the MVP fallback artifact to this runtime instead of the SIMD build.',
      });
    }
  }

  if (scan.growOps > 0 && maximumPages === undefined) {
    findings.push({
      code: 'memory/unbounded-growth',
      severity: 'warning',
      message:
        `Module calls memory.grow ${scan.growOps} time(s) but declares no memory maximum, ` +
        'so a single input can reallocate the whole heap.',
      suggestion: 'Add a maximum to the memory section and enforce a host-side input budget.',
    });
  }

  return {
    ...(options.file !== undefined ? { file: options.file } : {}),
    valid: true,
    sizeBytes: bytes.byteLength,
    simd,
    instructions,
    simdOpCount,
    memory,
    runtimeSupportsSimd,
    dualBuildRecommended: simd,
    findings,
    fallback: renderSimdFallback(),
  };
}

/** Build flags and detection snippet for a SIMD + MVP dual build. */
export function renderSimdFallback(): string[] {
  return [
    'Dual-compilation build:',
    '  Rust: -C target-feature=+simd128 (SIMD) and -C target-feature=-simd128 (MVP)',
    '  Emscripten: -msimd128 (SIMD) and -mno-simd128 (MVP)',
    'Runtime feature detection:',
    '  const simd = WebAssembly.validate(SIMD_PROBE_MODULE);',
    '  const artifact = simd ? "linter.simd.wasm" : "linter.mvp.wasm";',
    'Keep the MVP artifact on every edge cache; SIMD is still missing on older iOS Safari and some embedded runtimes.',
  ];
}

export function renderSimdReport(report: SimdAuditReport): string {
  const lines: string[] = [];
  const name = report.file ?? 'module';
  if (!report.valid) {
    lines.push(`${name} — not a valid WebAssembly binary (${report.sizeBytes} bytes)`);
    for (const finding of report.findings) {
      lines.push(`  ${finding.severity}  ${finding.code}  ${finding.message}`);
      lines.push(`         fix: ${finding.suggestion}`);
    }
    return `${lines.join('\n')}\n`;
  }

  lines.push(
    `${name} — ${report.sizeBytes} bytes, ${report.memory.memories} memory, ` +
      `${report.simd ? `SIMD (${report.simdOpCount} instructions)` : 'no SIMD'}`,
  );
  for (const instruction of report.instructions) {
    lines.push(`  ${instruction.name} ×${instruction.count}`);
  }

  const max =
    report.memory.maximumPages === undefined
      ? 'unbounded'
      : `${report.memory.maximumPages} pages (${report.memory.maximumBytes} bytes)`;
  lines.push(
    `  memory: initial ${report.memory.initialPages} pages (${report.memory.initialBytes} bytes), ` +
      `max ${max}, memory.grow ×${report.memory.growOps}, memory.size ×${report.memory.sizeOps}`,
  );
  lines.push(
    `  runtime SIMD support: ${report.runtimeSupportsSimd ? 'yes' : 'no'} ` +
      `| dual build recommended: ${report.dualBuildRecommended ? 'yes' : 'no'}`,
  );

  if (report.findings.length > 0) {
    lines.push('');
    for (const finding of report.findings) {
      lines.push(`  ${finding.severity}  ${finding.code}  ${finding.message}`);
      lines.push(`         fix: ${finding.suggestion}`);
    }
  }
  if (report.dualBuildRecommended) {
    lines.push('');
    for (const line of report.fallback) lines.push(`  ${line}`);
  }
  return `${lines.join('\n')}\n`;
}
