/**
 * Static resource estimate for a deployed Soroban contract's WASM.
 *
 * Soroban meters every invocation against per-transaction CPU-instruction and
 * memory limits, and a contract that reserves a large linear memory up front
 * or routes its entry points through deeply branching code is the one that
 * aborts in a wallet under load. This module reads the module's own sections —
 * never executing anything — to project that overhead before it hits the
 * chain:
 *
 * - the Memory section's minimum/maximum page counts (64 KiB per page),
 * - the Data section's total initialiser bytes (the static heap footprint),
 * - and the cyclomatic complexity of each exported SEP-41 token function,
 *   counted from the branch instructions in its body.
 *
 * Like the other contract checks it only runs under `--check-contracts`,
 * degrades silently when the RPC or the module cannot be read, and registers
 * its rule ids for `--list-rules` and `--off`.
 */
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { specUrl } from '../spec.js';

export const EXCESSIVE_STATIC_MEMORY_RULE = 'soroban/excessive-static-memory-pages';
export const HIGH_CYCLOMATIC_COMPLEXITY_RULE = 'soroban/high-cyclomatic-complexity';

/** WASM linear memory is allocated in 64 KiB pages. */
export const WASM_PAGE_BYTES = 65_536;

/** More than 10 pages (640 KiB) reserved at instantiation is flagged. */
export const DEFAULT_MAX_STATIC_MEMORY_PAGES = 10;

/**
 * Compiled WASM inlines helpers into their callers, so an entry point scores
 * far higher than the Rust function it came from. The default is set well
 * above the classic source-level thresholds (10–20) for that reason.
 */
export const DEFAULT_MAX_CYCLOMATIC_COMPLEXITY = 50;

/** The SEP-41 token interface functions whose complexity is measured. */
export const SEP41_FUNCTIONS = [
  'allowance',
  'approve',
  'balance',
  'transfer',
  'transfer_from',
  'burn',
  'burn_from',
  'decimals',
  'name',
  'symbol',
] as const;

export interface MemoryLimits {
  /** Pages reserved at instantiation. */
  minPages: number;
  /** Declared growth ceiling, or `undefined` when the memory is unbounded. */
  maxPages: number | undefined;
}

export interface BudgetEstimate {
  /** The module's linear memory, or `undefined` when it declares none. */
  memory: MemoryLimits | undefined;
  /** Total bytes copied into memory by data segments at instantiation. */
  staticDataBytes: number;
  /**
   * Cyclomatic complexity per exported SEP-41 function. A function whose body
   * uses an instruction this decoder does not know is left out rather than
   * guessed at.
   */
  complexity: Record<string, number>;
}

export interface BudgetOptions {
  rules?: RuleOverrides;
  maxStaticMemoryPages?: number;
  maxCyclomaticComplexity?: number;
}

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules?: RuleOverrides,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

// ---------------------------------------------------------------------------
// Byte reader
// ---------------------------------------------------------------------------

/** Thrown internally when the module ends early or holds a malformed value. */
class MalformedWasm extends Error {}

/** Thrown internally for an opcode the complexity walk cannot skip safely. */
class UnknownOpcode extends Error {}

class Reader {
  constructor(
    private readonly bytes: Buffer,
    public pos = 0,
    private readonly end = bytes.length,
  ) {}

  get done(): boolean {
    return this.pos >= this.end;
  }

  byte(): number {
    if (this.pos >= this.end) throw new MalformedWasm();
    return this.bytes[this.pos++] as number;
  }

  skip(count: number): void {
    if (count < 0 || this.pos + count > this.end) throw new MalformedWasm();
    this.pos += count;
  }

  /** Unsigned LEB128, at most 32 bits. */
  u32(): number {
    let value = 0;
    let shift = 0;
    for (;;) {
      const byte = this.byte();
      value |= (byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) return value >>> 0;
      shift += 7;
      if (shift > 28) throw new MalformedWasm();
    }
  }

  /** Signed LEB128 of up to `bits` bits; only its extent matters here. */
  signed(bits: number): void {
    let shift = 0;
    for (;;) {
      const byte = this.byte();
      shift += 7;
      if ((byte & 0x80) === 0) return;
      if (shift >= bits + 7) throw new MalformedWasm();
    }
  }
}

// ---------------------------------------------------------------------------
// Sections
// ---------------------------------------------------------------------------

const SECTION_IMPORT = 2;
const SECTION_MEMORY = 5;
const SECTION_EXPORT = 7;
const SECTION_CODE = 10;
const SECTION_DATA = 11;

const IMPORT_KIND_FUNC = 0x00;
const EXPORT_KIND_FUNC = 0x00;

/** Payload `[start, end)` of each non-custom section, keyed by section id. */
function sectionsOf(wasm: Buffer): Map<number, { start: number; end: number }> {
  if (wasm.length < 8 || wasm.readUInt32BE(0) !== 0x0061736d) throw new MalformedWasm();
  const sections = new Map<number, { start: number; end: number }>();
  const reader = new Reader(wasm, 8);
  while (!reader.done) {
    const id = reader.byte();
    const size = reader.u32();
    const start = reader.pos;
    reader.skip(size);
    if (id !== 0) sections.set(id, { start, end: reader.pos });
  }
  return sections;
}

function readerFor(
  wasm: Buffer,
  section: { start: number; end: number } | undefined,
): Reader | undefined {
  return section === undefined ? undefined : new Reader(wasm, section.start, section.end);
}

function readName(reader: Reader, wasm: Buffer): string {
  const length = reader.u32();
  const start = reader.pos;
  reader.skip(length);
  return wasm.toString('utf8', start, start + length);
}

/** `limits`: a flags byte, the minimum, and the maximum when bit 0 is set. */
function readLimits(reader: Reader): MemoryLimits {
  const flags = reader.byte();
  const minPages = reader.u32();
  const maxPages = (flags & 0x01) !== 0 ? reader.u32() : undefined;
  return { minPages, maxPages };
}

/** Skips an import descriptor, returning whether it imported a function. */
function skipImportDescriptor(reader: Reader): boolean {
  const kind = reader.byte();
  switch (kind) {
    case IMPORT_KIND_FUNC:
      reader.u32(); // type index
      return true;
    case 0x01: // table: reftype + limits
      reader.byte();
      readLimits(reader);
      return false;
    case 0x02: // memory
      readLimits(reader);
      return false;
    case 0x03: // global: valtype + mutability
      reader.byte();
      reader.byte();
      return false;
    default:
      throw new MalformedWasm();
  }
}

function importedFunctionCount(wasm: Buffer, reader: Reader | undefined): number {
  if (reader === undefined) return 0;
  let functions = 0;
  const count = reader.u32();
  for (let i = 0; i < count; i++) {
    readName(reader, wasm); // module
    readName(reader, wasm); // field
    if (skipImportDescriptor(reader)) functions++;
  }
  return functions;
}

function memoryOf(reader: Reader | undefined): MemoryLimits | undefined {
  if (reader === undefined) return undefined;
  const count = reader.u32();
  return count > 0 ? readLimits(reader) : undefined;
}

function exportedFunctions(wasm: Buffer, reader: Reader | undefined): Map<string, number> {
  const exports = new Map<string, number>();
  if (reader === undefined) return exports;
  const count = reader.u32();
  for (let i = 0; i < count; i++) {
    const name = readName(reader, wasm);
    const kind = reader.byte();
    const index = reader.u32();
    if (kind === EXPORT_KIND_FUNC) exports.set(name, index);
  }
  return exports;
}

/** Skips a constant initialiser expression up to and including `end`. */
function skipConstExpr(reader: Reader): void {
  for (;;) {
    const opcode = reader.byte();
    if (opcode === 0x0b) return;
    skipImmediates(reader, opcode);
  }
}

function staticDataBytesOf(reader: Reader | undefined): number {
  if (reader === undefined) return 0;
  let total = 0;
  const count = reader.u32();
  for (let i = 0; i < count; i++) {
    const flags = reader.u32();
    if (flags === 2) reader.u32(); // explicit memory index
    if (flags !== 1) skipConstExpr(reader); // active segments carry an offset
    const length = reader.u32();
    reader.skip(length);
    // Passive segments (flag 1) are copied only by an explicit memory.init.
    if (flags !== 1) total += length;
  }
  return total;
}

// ---------------------------------------------------------------------------
// Instruction walk
// ---------------------------------------------------------------------------

/** `blocktype`: empty (0x40), a single value type, or a signed type index. */
function skipBlockType(reader: Reader): void {
  const first = reader.byte();
  if (first === 0x40 || (first >= 0x6f && first <= 0x7f)) return;
  reader.pos--;
  reader.signed(33);
}

/** Skips the immediates of `opcode`, or throws for an opcode it does not know. */
function skipImmediates(reader: Reader, opcode: number): void {
  if (opcode >= 0x45 && opcode <= 0xc4) return; // numeric ops: no immediates
  if (opcode >= 0x28 && opcode <= 0x3e) {
    reader.u32(); // memarg align
    reader.u32(); // memarg offset
    return;
  }
  switch (opcode) {
    case 0x00: // unreachable
    case 0x01: // nop
    case 0x05: // else
    case 0x0b: // end
    case 0x0f: // return
    case 0x1a: // drop
    case 0x1b: // select
    case 0xd1: // ref.is_null
      return;
    case 0x02: // block
    case 0x03: // loop
    case 0x04: // if
      skipBlockType(reader);
      return;
    case 0x0c: // br
    case 0x0d: // br_if
    case 0x10: // call
    case 0x20: // local.get
    case 0x21: // local.set
    case 0x22: // local.tee
    case 0x23: // global.get
    case 0x24: // global.set
    case 0x25: // table.get
    case 0x26: // table.set
    case 0xd2: // ref.func
      reader.u32();
      return;
    case 0x0e: {
      // br_table: a vector of labels plus the default
      const labels = reader.u32();
      for (let i = 0; i <= labels; i++) reader.u32();
      return;
    }
    case 0x11: // call_indirect: type index + table index
      reader.u32();
      reader.u32();
      return;
    case 0x1c: {
      // typed select: a vector of value types
      const types = reader.u32();
      reader.skip(types);
      return;
    }
    case 0x3f: // memory.size
    case 0x40: // memory.grow
    case 0xd0: // ref.null
      reader.byte();
      return;
    case 0x41: // i32.const
      reader.signed(32);
      return;
    case 0x42: // i64.const
      reader.signed(64);
      return;
    case 0x43: // f32.const
      reader.skip(4);
      return;
    case 0x44: // f64.const
      reader.skip(8);
      return;
    case 0xfc:
      skipPrefixed(reader);
      return;
    default:
      throw new UnknownOpcode();
  }
}

/** The 0xFC prefix: saturating truncations, bulk memory, and table ops. */
function skipPrefixed(reader: Reader): void {
  const sub = reader.u32();
  if (sub <= 7) return; // trunc_sat
  switch (sub) {
    case 8: // memory.init: data index + memory
      reader.u32();
      reader.byte();
      return;
    case 9: // data.drop
    case 13: // elem.drop
    case 15: // table.grow
    case 16: // table.size
    case 17: // table.fill
      reader.u32();
      return;
    case 10: // memory.copy
      reader.byte();
      reader.byte();
      return;
    case 11: // memory.fill
      reader.byte();
      return;
    case 12: // table.init
    case 14: // table.copy
      reader.u32();
      reader.u32();
      return;
    default:
      throw new UnknownOpcode();
  }
}

/**
 * McCabe complexity of one function body: one path, plus one for every
 * decision point — each `if`, each `br_if`, and each extra target of a
 * `br_table`.
 */
function complexityOf(reader: Reader): number {
  const localGroups = reader.u32();
  for (let i = 0; i < localGroups; i++) {
    reader.u32(); // count
    reader.byte(); // value type
  }

  let complexity = 1;
  while (!reader.done) {
    const opcode = reader.byte();
    if (opcode === 0x04 || opcode === 0x0d) {
      complexity++;
    } else if (opcode === 0x0e) {
      const start = reader.pos;
      complexity += reader.u32(); // n labels + default = n extra paths
      reader.pos = start;
    }
    skipImmediates(reader, opcode);
  }
  return complexity;
}

function complexityByName(
  wasm: Buffer,
  reader: Reader | undefined,
  targets: Map<string, number>,
  importedFunctions: number,
): Record<string, number> {
  const result: Record<string, number> = {};
  if (reader === undefined || targets.size === 0) return result;

  const byIndex = new Map<number, string>();
  for (const [name, index] of targets) byIndex.set(index - importedFunctions, name);

  const count = reader.u32();
  for (let i = 0; i < count; i++) {
    const size = reader.u32();
    const bodyStart = reader.pos;
    reader.skip(size);
    const name = byIndex.get(i);
    if (name === undefined) continue;
    try {
      result[name] = complexityOf(new Reader(wasm, bodyStart, bodyStart + size));
    } catch (error) {
      if (!(error instanceof UnknownOpcode) && !(error instanceof MalformedWasm)) throw error;
    }
  }
  return result;
}

/**
 * Reads the static resource profile of a WASM module, or `undefined` when the
 * module cannot be parsed.
 */
export function estimateWasmBudget(wasm: Buffer): BudgetEstimate | undefined {
  try {
    const sections = sectionsOf(wasm);
    const importedFunctions = importedFunctionCount(
      wasm,
      readerFor(wasm, sections.get(SECTION_IMPORT)),
    );
    const memory = memoryOf(readerFor(wasm, sections.get(SECTION_MEMORY)));
    const staticDataBytes = staticDataBytesOf(readerFor(wasm, sections.get(SECTION_DATA)));

    const sep41 = new Set<string>(SEP41_FUNCTIONS);
    const exported = exportedFunctions(wasm, readerFor(wasm, sections.get(SECTION_EXPORT)));
    const targets = new Map([...exported].filter(([name]) => sep41.has(name)));
    const complexity = complexityByName(
      wasm,
      readerFor(wasm, sections.get(SECTION_CODE)),
      targets,
      importedFunctions,
    );

    return { memory, staticDataBytes, complexity };
  } catch (error) {
    if (error instanceof MalformedWasm || error instanceof UnknownOpcode) return undefined;
    throw error;
  }
}

/** Turns an estimate into diagnostics for `contractId`. */
export function budgetDiagnostics(
  contractId: string,
  estimate: BudgetEstimate,
  options: BudgetOptions = {},
): Diagnostic[] {
  const diagnostics: Diagnostic[] = [];
  const maxPages = options.maxStaticMemoryPages ?? DEFAULT_MAX_STATIC_MEMORY_PAGES;
  const maxComplexity = options.maxCyclomaticComplexity ?? DEFAULT_MAX_CYCLOMATIC_COMPLEXITY;

  const memory = estimate.memory;
  if (memory !== undefined && memory.minPages > maxPages) {
    const severity = severityFor(EXCESSIVE_STATIC_MEMORY_RULE, 'warning', options.rules);
    if (severity !== undefined) {
      const kib = (memory.minPages * WASM_PAGE_BYTES) / 1024;
      diagnostics.push({
        rule: EXCESSIVE_STATIC_MEMORY_RULE,
        severity,
        category: 'network',
        message: `Contract ${contractId} reserves ${memory.minPages} WASM memory pages (${kib} KiB) at instantiation, above the ${maxPages}-page budget; static data segments add ${estimate.staticDataBytes} bytes`,
        path: 'CURRENCIES.contract',
        helpUri: specUrl('general-information'),
        suggestion:
          'Lower the initial linear memory (for example a smaller stack size) so each invocation stays inside the Soroban memory limit.',
      });
    }
  }

  const severity = severityFor(HIGH_CYCLOMATIC_COMPLEXITY_RULE, 'warning', options.rules);
  if (severity !== undefined) {
    for (const [name, score] of Object.entries(estimate.complexity)) {
      if (score <= maxComplexity) continue;
      diagnostics.push({
        rule: HIGH_CYCLOMATIC_COMPLEXITY_RULE,
        severity,
        category: 'network',
        message: `Contract ${contractId} SEP-41 function \`${name}\` has cyclomatic complexity ${score}, above the limit of ${maxComplexity}`,
        path: 'CURRENCIES.contract',
        helpUri: specUrl('general-information'),
        suggestion:
          'Simplify the branching in this entry point so its instruction cost stays predictable under the Soroban CPU budget.',
      });
    }
  }

  return diagnostics;
}

/** Diagnostics for a module's bytes; silent when the module cannot be parsed. */
export function auditWasmBudget(
  contractId: string,
  wasm: Buffer,
  options: BudgetOptions = {},
): Diagnostic[] {
  const estimate = estimateWasmBudget(wasm);
  return estimate === undefined ? [] : budgetDiagnostics(contractId, estimate, options);
}

export const budgetEstimatorRules: Rule[] = [
  {
    id: EXCESSIVE_STATIC_MEMORY_RULE,
    category: 'network',
    severity: 'warning',
    description:
      'A Soroban contract reserves more than 10 WASM memory pages (640 KiB) at instantiation',
    run() {},
  },
  {
    id: HIGH_CYCLOMATIC_COMPLEXITY_RULE,
    category: 'network',
    severity: 'warning',
    description: 'An exported SEP-41 function of a Soroban contract has high cyclomatic complexity',
    run() {},
  },
];
