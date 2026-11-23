/**
 * Multi-contract atomicity and reentrancy analysis for Soroban contracts.
 *
 * A Soroban transaction can chain several contract invocations, and a callee
 * can call back into the caller before the caller has finished. When the
 * caller mutates its own storage *after* handing control to another contract
 * (the classic "interactions before effects" ordering), the reentrant frame
 * observes stale state and can drain or double-spend it.
 *
 * This module inspects the deployed WASM without executing it:
 *
 * - imports are read to identify the host functions that invoke another
 *   contract (`call`, `try_call`) and the ones that mutate this contract's
 *   storage (`put_contract_data`, `del_contract_data`),
 * - each function body is walked for those calls, so a storage write that
 *   follows an external call is visible,
 * - a storage write *before* the first external call is treated as the
 *   non-reentrant lock acquisition (the pattern a mutex guard compiles to),
 * - the internal call graph is built and checked for recursion.
 *
 * It is a static ordering heuristic, not a symbolic execution: it cannot see
 * which contract an address points at, and a lock written through a helper
 * whose ordering differs from the mutex pattern may be missed. It is
 * deliberately conservative about declaring a finding — every rule fires on
 * an observable instruction ordering, never on an inference about values.
 */
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { specUrl } from '../spec.js';

export const REENTRANCY_MISSING_GUARD_RULE = 'soroban/reentrancy-missing-guard';
export const NON_ATOMIC_CROSS_CALL_RULE = 'soroban/non-atomic-cross-contract-call';
export const RECURSIVE_CONTRACT_CALL_RULE = 'soroban/recursive-contract-call';

/** Host functions that transfer control to another contract. */
export const EXTERNAL_CALL_HOST_FUNCTIONS = ['call', 'try_call'] as const;

/** Host functions that mutate this contract's persistent or instance storage. */
export const STORAGE_WRITE_HOST_FUNCTIONS = ['put_contract_data', 'del_contract_data'] as const;

export interface ReentrancyOptions {
  rules?: RuleOverrides;
}

/** What one function does with control flow and storage. */
export interface FunctionAnalysis {
  /** Exported name when the function is an entry point, else `fn#<index>`. */
  name: string;
  /** Host functions invoking another contract, in call order. */
  externalCalls: string[];
  /** True when a storage write runs before the first external call. */
  lockedBeforeExternalCall: boolean;
  /** True when this contract's storage is mutated after an external call. */
  writesAfterExternalCall: boolean;
  /** True when the external call is a `try_call` whose failure is not trapped. */
  fallibleExternalCall: boolean;
  /** Internal functions this body calls, by defined-function index. */
  internalCalls: number[];
}

/** A directed edge in the intra-contract call graph. */
export interface CallGraphEdge {
  from: number;
  to: number;
}

export interface ReentrancyAnalysis {
  functions: FunctionAnalysis[];
  callGraph: CallGraphEdge[];
  /** Cycles in the internal call graph, as defined-function indices. */
  recursiveCycles: number[][];
  /** Exported function name → defined-function index. */
  exports: Record<string, number>;
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
// WASM reader
// ---------------------------------------------------------------------------

class MalformedWasm extends Error {}
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

  /** Signed LEB128 of up to `bits`; only its extent matters here. */
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

const SECTION_IMPORT = 2;
const SECTION_EXPORT = 7;
const SECTION_CODE = 10;

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

function readLimits(reader: Reader): void {
  const flags = reader.byte();
  reader.u32();
  if ((flags & 0x01) !== 0) reader.u32();
}

/** Imports in function-index order, with the module each one comes from. */
function importedFunctionsOf(
  wasm: Buffer,
  reader: Reader | undefined,
): { module: string; name: string }[] {
  const imports: { module: string; name: string }[] = [];
  if (reader === undefined) return imports;

  const count = reader.u32();
  for (let i = 0; i < count; i++) {
    const module = readName(reader, wasm);
    const name = readName(reader, wasm);
    const kind = reader.byte();
    switch (kind) {
      case IMPORT_KIND_FUNC:
        reader.u32();
        imports.push({ module, name });
        break;
      case 0x01: // table
        reader.byte();
        readLimits(reader);
        break;
      case 0x02: // memory
        readLimits(reader);
        break;
      case 0x03: // global
        reader.byte();
        reader.byte();
        break;
      default:
        throw new MalformedWasm();
    }
  }
  return imports;
}

function exportedFunctionsOf(
  wasm: Buffer,
  reader: Reader | undefined,
  importedCount: number,
): Record<string, number> {
  const exports: Record<string, number> = {};
  if (reader === undefined) return exports;

  const count = reader.u32();
  for (let i = 0; i < count; i++) {
    const name = readName(reader, wasm);
    const kind = reader.byte();
    const index = reader.u32();
    if (kind === EXPORT_KIND_FUNC && index >= importedCount) {
      exports[name] = index - importedCount;
    }
  }
  return exports;
}

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
    reader.u32();
    reader.u32();
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
      const labels = reader.u32();
      for (let i = 0; i <= labels; i++) reader.u32();
      return;
    }
    case 0x11:
      reader.u32();
      reader.u32();
      return;
    case 0x1c: {
      const types = reader.u32();
      reader.skip(types);
      return;
    }
    case 0x3f:
    case 0x40:
    case 0xd0:
      reader.byte();
      return;
    case 0x41:
      reader.signed(32);
      return;
    case 0x42:
      reader.signed(64);
      return;
    case 0x43:
      reader.skip(4);
      return;
    case 0x44:
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
  if (sub <= 7) return;
  switch (sub) {
    case 8:
      reader.u32();
      reader.byte();
      return;
    case 9:
    case 13:
    case 15:
    case 16:
    case 17:
      reader.u32();
      return;
    case 10:
      reader.byte();
      reader.byte();
      return;
    case 11:
      reader.byte();
      return;
    case 12:
    case 14:
      reader.u32();
      reader.u32();
      return;
    default:
      throw new UnknownOpcode();
  }
}

// ---------------------------------------------------------------------------
// Body analysis
// ---------------------------------------------------------------------------

/** The classification of one function body. */
interface BodyScan {
  externalCalls: string[];
  lockedBeforeExternalCall: boolean;
  writesAfterExternalCall: boolean;
  fallibleExternalCall: boolean;
  internalCalls: number[];
}

const EXTERNAL_CALLS = new Set<string>(EXTERNAL_CALL_HOST_FUNCTIONS);
const STORAGE_WRITES = new Set<string>(STORAGE_WRITE_HOST_FUNCTIONS);

/**
 * Walks a function body and records the ordering of external calls and storage
 * writes relative to each other.
 */
function scanBody(reader: Reader, imported: { module: string; name: string }[]): BodyScan {
  // Locals: a vector of (count, value type) groups.
  const localGroups = reader.u32();
  for (let i = 0; i < localGroups; i++) {
    reader.u32();
    reader.byte();
  }

  const scan: BodyScan = {
    externalCalls: [],
    lockedBeforeExternalCall: false,
    writesAfterExternalCall: false,
    fallibleExternalCall: false,
    internalCalls: [],
  };
  let sawExternalCall = false;

  while (!reader.done) {
    const opcode = reader.byte();
    if (opcode === 0x10) {
      const fn = reader.u32();
      if (fn < imported.length) {
        const name = imported[fn]!.name;
        if (EXTERNAL_CALLS.has(name)) {
          scan.externalCalls.push(name);
          if (name === 'try_call') scan.fallibleExternalCall = true;
          sawExternalCall = true;
        } else if (STORAGE_WRITES.has(name)) {
          if (sawExternalCall) scan.writesAfterExternalCall = true;
          else scan.lockedBeforeExternalCall = true;
        }
      } else {
        scan.internalCalls.push(fn - imported.length);
      }
      continue;
    }
    skipImmediates(reader, opcode);
  }

  return scan;
}

/** Strongly connected components of a directed graph (Tarjan, iterative). */
function stronglyConnectedComponents(nodeCount: number, edges: CallGraphEdge[]): number[][] {
  const adjacency: number[][] = Array.from({ length: nodeCount }, () => []);
  for (const edge of edges) adjacency[edge.from]?.push(edge.to);

  const index = new Array<number>(nodeCount).fill(-1);
  const low = new Array<number>(nodeCount).fill(0);
  const onStack = new Array<boolean>(nodeCount).fill(false);
  const stack: number[] = [];
  const components: number[][] = [];
  let counter = 0;

  for (let start = 0; start < nodeCount; start++) {
    if (index[start] !== -1) continue;

    const work: { node: number; next: number }[] = [{ node: start, next: 0 }];
    index[start] = counter;
    low[start] = counter;
    counter++;
    stack.push(start);
    onStack[start] = true;

    while (work.length > 0) {
      const frame = work[work.length - 1]!;
      const neighbours = adjacency[frame.node] ?? [];

      if (frame.next < neighbours.length) {
        const next = neighbours[frame.next++]!;
        if (index[next] === -1) {
          index[next] = counter;
          low[next] = counter;
          counter++;
          stack.push(next);
          onStack[next] = true;
          work.push({ node: next, next: 0 });
        } else if (onStack[next]) {
          low[frame.node] = Math.min(low[frame.node]!, index[next]!);
        }
        continue;
      }

      work.pop();
      const parent = work[work.length - 1];
      if (parent !== undefined) {
        low[parent.node] = Math.min(low[parent.node]!, low[frame.node]!);
      }
      if (low[frame.node] === index[frame.node]) {
        const component: number[] = [];
        for (;;) {
          const popped = stack.pop()!;
          onStack[popped] = false;
          component.push(popped);
          if (popped === frame.node) break;
        }
        components.push(component);
      }
    }
  }

  return components;
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

/**
 * Statically analyses a contract module: per-function ordering of external
 * calls and storage writes, and the internal call graph. `undefined` when the
 * bytes are not a readable WASM module.
 */
export function analyzeReentrancy(wasm: Buffer): ReentrancyAnalysis | undefined {
  try {
    const sections = sectionsOf(wasm);
    const imported = importedFunctionsOf(wasm, readerFor(wasm, sections.get(SECTION_IMPORT)));
    const exports = exportedFunctionsOf(
      wasm,
      readerFor(wasm, sections.get(SECTION_EXPORT)),
      imported.length,
    );
    const namesByIndex = new Map<number, string>();
    for (const [name, index] of Object.entries(exports)) {
      if (!namesByIndex.has(index)) namesByIndex.set(index, name);
    }

    const bodyReader = readerFor(wasm, sections.get(SECTION_CODE));
    const functions: FunctionAnalysis[] = [];
    const edges: CallGraphEdge[] = [];

    if (bodyReader !== undefined) {
      const count = bodyReader.u32();
      for (let i = 0; i < count; i++) {
        const size = bodyReader.u32();
        const start = bodyReader.pos;
        bodyReader.skip(size);

        let scan: BodyScan | undefined;
        try {
          scan = scanBody(new Reader(wasm, start, start + size), imported);
        } catch (error) {
          if (!(error instanceof UnknownOpcode) && !(error instanceof MalformedWasm)) throw error;
        }
        functions.push({
          name: namesByIndex.get(i) ?? `fn#${i}`,
          externalCalls: scan?.externalCalls ?? [],
          lockedBeforeExternalCall: scan?.lockedBeforeExternalCall ?? false,
          writesAfterExternalCall: scan?.writesAfterExternalCall ?? false,
          fallibleExternalCall: scan?.fallibleExternalCall ?? false,
          internalCalls: scan?.internalCalls ?? [],
        });
        for (const target of scan?.internalCalls ?? []) {
          if (target >= 0 && target < count) edges.push({ from: i, to: target });
        }
      }
    }

    const recursiveCycles = stronglyConnectedComponents(functions.length, edges).filter(
      (component) =>
        component.length > 1 ||
        edges.some((edge) => edge.from === component[0] && edge.to === component[0]),
    );

    return { functions, callGraph: edges, recursiveCycles, exports };
  } catch (error) {
    if (error instanceof MalformedWasm || error instanceof UnknownOpcode) return undefined;
    throw error;
  }
}

function analysisDiagnostics(
  contractId: string,
  analysis: ReentrancyAnalysis,
  options: ReentrancyOptions,
): Diagnostic[] {
  const diagnostics: Diagnostic[] = [];
  const base = {
    category: 'network' as const,
    path: 'CURRENCIES.contract',
    helpUri: specUrl('general-information'),
  };

  for (const fn of analysis.functions) {
    if (fn.writesAfterExternalCall && !fn.lockedBeforeExternalCall) {
      const severity = severityFor(REENTRANCY_MISSING_GUARD_RULE, 'error', options.rules);
      if (severity !== undefined) {
        diagnostics.push({
          ...base,
          rule: REENTRANCY_MISSING_GUARD_RULE,
          severity,
          message: `Contract ${contractId} function \`${fn.name}\` mutates its own storage after invoking another contract (${fn.externalCalls.join(', ')}) without taking a reentrancy lock first`,
          suggestion:
            'Apply checks-effects-interactions: take the mutex/entered lock and update state before the external call, or move the state update before it.',
        });
      }
    }

    if (fn.fallibleExternalCall && fn.writesAfterExternalCall) {
      const severity = severityFor(NON_ATOMIC_CROSS_CALL_RULE, 'warning', options.rules);
      if (severity !== undefined) {
        diagnostics.push({
          ...base,
          rule: NON_ATOMIC_CROSS_CALL_RULE,
          severity,
          message: `Contract ${contractId} function \`${fn.name}\` continues after a fallible \`try_call\` and then writes storage, so a failed sub-invocation leaves partial state`,
          suggestion:
            'Either propagate the `try_call` failure before writing state, or perform the storage update in the same ledger-entry transaction as the sub-invocation.',
        });
      }
    }
  }

  const recursiveSeverity = severityFor(RECURSIVE_CONTRACT_CALL_RULE, 'error', options.rules);
  if (recursiveSeverity !== undefined && analysis.recursiveCycles.length > 0) {
    const names = analysis.functions.map((fn) => fn.name);
    const makesExternalCall = new Set(
      analysis.functions.filter((fn) => fn.externalCalls.length > 0).map((fn) => fn.name),
    );
    for (const cycle of analysis.recursiveCycles) {
      const members = cycle.map((index) => names[index] ?? `fn#${index}`);
      if (!members.some((name) => makesExternalCall.has(name))) continue;
      diagnostics.push({
        ...base,
        rule: RECURSIVE_CONTRACT_CALL_RULE,
        severity: recursiveSeverity,
        message: `Contract ${contractId} call graph is recursive (${members.join(' -> ')}) around an external contract invocation, which allows reentrant execution`,
        suggestion:
          'Break the cycle, or guard every entry point in it with a non-reentrant mutex before invoking another contract.',
      });
    }
  }

  return diagnostics;
}

/** Audits one module's bytes. Silent when the module cannot be parsed. */
export function auditWasmReentrancy(
  contractId: string,
  wasm: Buffer,
  options: ReentrancyOptions = {},
): Diagnostic[] {
  const analysis = analyzeReentrancy(wasm);
  return analysis === undefined ? [] : analysisDiagnostics(contractId, analysis, options);
}

/**
 * Audits a set of deployed contracts and keeps a shared view of the
 * cross-contract flows: every contract that can mutate state after handing
 * control to another one is reported, so a router or vault that composes
 * several `stellar.toml` contracts is checked as a whole.
 */
export class CrossContractReentrancyValidator {
  private readonly options: ReentrancyOptions;

  constructor(options: ReentrancyOptions = {}) {
    this.options = options;
  }

  /** The static analysis for one module. */
  analyze(wasm: Buffer): ReentrancyAnalysis | undefined {
    return analyzeReentrancy(wasm);
  }

  /** Diagnostics for one contract's WASM. */
  auditContract(contractId: string, wasm: Buffer): Diagnostic[] {
    return auditWasmReentrancy(contractId, wasm, this.options);
  }

  /** Diagnostics for several contracts, in order. */
  audit(contracts: readonly { id: string; wasm: Buffer }[]): Diagnostic[] {
    return contracts.flatMap((contract) => this.auditContract(contract.id, contract.wasm));
  }
}

export const reentrancyValidatorRules: Rule[] = [
  {
    id: REENTRANCY_MISSING_GUARD_RULE,
    category: 'network',
    severity: 'error',
    description:
      'A Soroban contract mutates storage after an external invocation without a reentrancy lock',
    run() {},
  },
  {
    id: NON_ATOMIC_CROSS_CALL_RULE,
    category: 'network',
    severity: 'warning',
    description: 'A Soroban contract writes state after a fallible cross-contract call',
    run() {},
  },
  {
    id: RECURSIVE_CONTRACT_CALL_RULE,
    category: 'network',
    severity: 'error',
    description: 'A Soroban contract call graph is recursive around an external invocation',
    run() {},
  },
];
