/**
 * Static memory-hazard analysis for Soroban contract WASM.
 *
 * A Soroban contract runs inside a bounded host: growing memory without a
 * declared maximum, recursing, spinning in a loop with no exit, or reserving a
 * huge stack frame can abort the invocation (or the whole transaction) after
 * the caller has already paid for it. This analyzer reads the binary itself and
 * reports those hazards with the function name and bytecode offset.
 */

import type { Rule } from '../types.js';
import {
  WasmModuleError,
  parseWasmModule,
  type WasmFunction,
  type WasmModule,
} from './wasmModule.js';

/** Bytes in one 64 KiB WebAssembly page. */
export const WASM_PAGE_BYTES = 65_536;

/** A module may start with at most this many pages before it needs review. */
export const DEFAULT_MAX_INITIAL_PAGES = 64;

/** Declared locals above this count are treated as a large stack frame. */
export const DEFAULT_MAX_STACK_SLOTS = 64;

export type MemoryHazardCode =
  | 'soroban/wasm-invalid-binary'
  | 'soroban/wasm-unbounded-memory'
  | 'soroban/wasm-excessive-initial-memory'
  | 'soroban/wasm-recursive-call'
  | 'soroban/wasm-unbounded-loop'
  | 'soroban/wasm-large-stack-frame';

export interface MemoryHazardFinding {
  code: MemoryHazardCode;
  severity: 'error' | 'warning';
  message: string;
  suggestion: string;
  function?: string;
  offset?: number;
}

export interface MemoryLimitsReport {
  memories: number;
  initialPages: number;
  maximumPages?: number;
  initialBytes: number;
  maximumBytes?: number;
  bounded: boolean;
  growOps: number;
  growOffsets: { function: string; offset: number }[];
}

export interface FunctionHazardReport {
  index: number;
  name: string;
  locals: number;
  calls: number;
  loopCount: number;
  unboundedLoops: number;
  memoryGrow: number;
  recursive: boolean;
}

export interface RecursionCycle {
  functions: string[];
  /** Call-site offsets that make up the cycle, in order. */
  offsets: number[];
}

export interface MemoryHazardReport {
  file?: string;
  valid: boolean;
  sizeBytes: number;
  error?: string;
  memory: MemoryLimitsReport;
  functions: FunctionHazardReport[];
  recursion: RecursionCycle[];
  findings: MemoryHazardFinding[];
}

export interface MemoryHazardOptions {
  file?: string;
  maxInitialPages?: number;
  maxStackSlots?: number;
}

/** Analyzes a WASM binary for memory and control-flow hazards. */
export function analyzeWasmMemory(
  bytes: Uint8Array,
  options: MemoryHazardOptions = {},
): MemoryHazardReport {
  const maxInitialPages = options.maxInitialPages ?? DEFAULT_MAX_INITIAL_PAGES;
  const maxStackSlots = options.maxStackSlots ?? DEFAULT_MAX_STACK_SLOTS;
  const base = { ...(options.file !== undefined ? { file: options.file } : {}) };

  let module: WasmModule;
  try {
    module = parseWasmModule(bytes);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      ...base,
      valid: false,
      sizeBytes: bytes.byteLength,
      error: message,
      memory: emptyMemoryReport(),
      functions: [],
      recursion: [],
      findings: [
        {
          code: 'soroban/wasm-invalid-binary',
          severity: 'error',
          message: `The contract binary cannot be parsed: ${message}`,
          suggestion:
            'Rebuild the contract with a current Soroban SDK and verify the deployed bytes are a valid WASM module.',
          ...(error instanceof WasmModuleError ? { offset: error.offset } : {}),
        },
      ],
    };
  }

  const memory = memoryReport(module);
  const recursion = recursionCycles(module);
  const recursiveNames = new Set(recursion.flatMap((cycle) => cycle.functions));
  const functions = module.functions.map((fn) => functionReport(fn, recursiveNames));
  const findings: MemoryHazardFinding[] = [];

  if (!memory.bounded) {
    findings.push({
      code: 'soroban/wasm-unbounded-memory',
      severity: 'warning',
      message:
        memory.memories === 0
          ? 'The module declares no memory, so any allocation will trap at runtime.'
          : `The module declares ${memory.initialPages} initial page(s) but no maximum, so allocation can grow without a bound.`,
      suggestion:
        'Declare a maximum memory size in the contract and cap allocations; the Soroban host aborts when the limit is exceeded.',
    });
  }

  if (memory.initialPages > maxInitialPages) {
    findings.push({
      code: 'soroban/wasm-excessive-initial-memory',
      severity: 'warning',
      message: `The module starts with ${memory.initialPages} pages (${formatBytes(memory.initialBytes)}), above the ${maxInitialPages}-page review threshold.`,
      suggestion:
        'Reduce static memory and allocate lazily; large initial memories make instantiation and deployment expensive.',
    });
  }

  for (const cycle of recursion) {
    const [first] = cycle.offsets;
    findings.push({
      code: 'soroban/wasm-recursive-call',
      severity: 'error',
      message: `Recursive call cycle: ${cycle.functions.join(' -> ')}. Recursion can exhaust the host stack and abort the transaction.`,
      suggestion:
        'Rewrite the recursion as an explicit loop with bounded depth, or enforce a hard call-depth limit before recursing.',
      ...(cycle.functions[0] !== undefined ? { function: cycle.functions[0] } : {}),
      ...(first !== undefined ? { offset: first } : {}),
    });
  }

  for (const fn of module.functions) {
    if (fn.locals > maxStackSlots) {
      findings.push({
        code: 'soroban/wasm-large-stack-frame',
        severity: 'warning',
        message: `${fn.name} declares ${fn.locals} locals, above the ${maxStackSlots}-slot review threshold.`,
        suggestion:
          'Move large values to memory or split the function; a large frame per call makes deep call chains overflow sooner.',
        function: fn.name,
      });
    }

    for (const loop of fn.loops) {
      if (loop.exits === 0) {
        findings.push({
          code: 'soroban/wasm-unbounded-loop',
          severity: 'warning',
          message: `${fn.name} has a loop at offset ${loop.offset} with no branch, return or trap that can leave it.`,
          suggestion:
            'Add a bounded exit condition (a `br_if` or `return`) so the loop cannot spin until the host runs out of fuel.',
          function: fn.name,
          offset: loop.offset,
        });
      }
    }
  }

  return {
    ...base,
    valid: true,
    sizeBytes: bytes.byteLength,
    memory,
    functions,
    recursion,
    findings,
  };
}

/** Renders a memory audit as a human-readable report. */
export function renderMemoryHazardReport(report: MemoryHazardReport): string {
  const lines: string[] = [];
  const label = report.file === undefined ? 'contract' : report.file;
  lines.push(`WASM memory audit: ${label}`);
  lines.push(`  Binary: ${report.valid ? 'valid' : 'INVALID'} (${formatBytes(report.sizeBytes)})`);
  if (report.error !== undefined) lines.push(`  Error: ${report.error}`);
  if (report.valid) {
    const { memory } = report;
    lines.push(
      `  Memory: ${memory.memories} memor${memory.memories === 1 ? 'y' : 'ies'}, ` +
        `${memory.initialPages} initial page(s) (${formatBytes(memory.initialBytes)}), ` +
        (memory.maximumPages === undefined
          ? 'no maximum'
          : `maximum ${memory.maximumPages} page(s) (${formatBytes(memory.maximumBytes ?? 0)})`),
    );
    lines.push(`  memory.grow: ${memory.growOps} site(s)`);
    for (const site of memory.growOffsets) {
      lines.push(`    ${site.function} @ ${site.offset}`);
    }
    lines.push(`  Functions: ${report.functions.length}`);
    for (const fn of report.functions) {
      const flags: string[] = [];
      if (fn.recursive) flags.push('recursive');
      if (fn.unboundedLoops > 0) flags.push(`${fn.unboundedLoops} unbounded loop(s)`);
      if (fn.memoryGrow > 0) flags.push(`${fn.memoryGrow} grow site(s)`);
      if (fn.locals > DEFAULT_MAX_STACK_SLOTS) flags.push(`${fn.locals} locals`);
      if (flags.length > 0) lines.push(`    ${fn.name}: ${flags.join(', ')}`);
    }
  }

  if (report.findings.length === 0) {
    lines.push('  No memory hazards found.');
    return `${lines.join('\n')}\n`;
  }

  lines.push(`  Findings (${report.findings.length}):`);
  for (const finding of report.findings) {
    const where =
      finding.function !== undefined
        ? ` [${finding.function}${finding.offset !== undefined ? ` @ ${finding.offset}` : ''}]`
        : finding.offset !== undefined
          ? ` [@ ${finding.offset}]`
          : '';
    lines.push(`    ${finding.severity.toUpperCase()} ${finding.code}${where}`);
    lines.push(`      ${finding.message}`);
    lines.push(`      Fix: ${finding.suggestion}`);
  }
  return `${lines.join('\n')}\n`;
}

/** The rule ids the memory analyzer can emit. */
export const wasmMemoryRuleIds = [
  'soroban/wasm-invalid-binary',
  'soroban/wasm-unbounded-memory',
  'soroban/wasm-excessive-initial-memory',
  'soroban/wasm-recursive-call',
  'soroban/wasm-unbounded-loop',
  'soroban/wasm-large-stack-frame',
] as const;

function emptyMemoryReport(): MemoryLimitsReport {
  return {
    memories: 0,
    initialPages: 0,
    initialBytes: 0,
    bounded: false,
    growOps: 0,
    growOffsets: [],
  };
}

function memoryReport(module: WasmModule): MemoryLimitsReport {
  const initialPages = module.memories.reduce((sum, memory) => sum + memory.minimum, 0);
  const maximumPages =
    module.memories.length > 0 && module.memories.every((memory) => memory.maximum !== undefined)
      ? module.memories.reduce((sum, memory) => sum + (memory.maximum ?? 0), 0)
      : undefined;
  const growOffsets = module.functions.flatMap((fn) =>
    fn.memoryGrow.map((offset) => ({ function: fn.name, offset })),
  );
  return {
    memories: module.memories.length,
    initialPages,
    ...(maximumPages !== undefined ? { maximumPages } : {}),
    initialBytes: initialPages * WASM_PAGE_BYTES,
    ...(maximumPages !== undefined ? { maximumBytes: maximumPages * WASM_PAGE_BYTES } : {}),
    bounded: module.memories.length > 0 && module.memories.every((m) => m.maximum !== undefined),
    growOps: growOffsets.length,
    growOffsets,
  };
}

function functionReport(fn: WasmFunction, recursiveNames: Set<string>): FunctionHazardReport {
  const recursive = recursiveNames.has(fn.name);
  return {
    index: fn.index,
    name: fn.name,
    locals: fn.locals,
    calls: fn.calls.length,
    loopCount: fn.loops.length,
    unboundedLoops: fn.loops.filter((loop) => loop.exits === 0).length,
    memoryGrow: fn.memoryGrow.length,
    recursive,
  };
}

/**
 * Finds every recursive call cycle (including self-recursion) in the call
 * graph. Calls into imported host functions are ignored: they cannot call back
 * into the module.
 */
export function recursionCycles(module: WasmModule): RecursionCycle[] {
  const byIndex = new Map<number, WasmFunction>();
  for (const fn of module.functions) byIndex.set(fn.index, fn);

  const edges = new Map<number, { target: number; offset: number }[]>();
  for (const fn of module.functions) {
    edges.set(
      fn.index,
      fn.calls.filter((call) => byIndex.has(call.target)),
    );
  }

  // Tarjan's strongly connected components.
  let nextIndex = 0;
  const indices = new Map<number, number>();
  const lowlinks = new Map<number, number>();
  const onStack = new Set<number>();
  const stack: number[] = [];
  const components: number[][] = [];

  const strongConnect = (node: number): void => {
    indices.set(node, nextIndex);
    lowlinks.set(node, nextIndex);
    nextIndex++;
    stack.push(node);
    onStack.add(node);

    for (const edge of edges.get(node) ?? []) {
      const target = edge.target;
      if (!indices.has(target)) {
        strongConnect(target);
        lowlinks.set(node, Math.min(lowlinks.get(node) ?? 0, lowlinks.get(target) ?? 0));
      } else if (onStack.has(target)) {
        lowlinks.set(node, Math.min(lowlinks.get(node) ?? 0, indices.get(target) ?? 0));
      }
    }

    if (lowlinks.get(node) === indices.get(node)) {
      const component: number[] = [];
      for (;;) {
        const member = stack.pop();
        if (member === undefined) break;
        onStack.delete(member);
        component.push(member);
        if (member === node) break;
      }
      components.push(component);
    }
  };

  for (const fn of module.functions) {
    if (!indices.has(fn.index)) strongConnect(fn.index);
  }

  const cycles: RecursionCycle[] = [];
  for (const component of components) {
    const members = new Set(component);
    const selfLoop =
      component.length === 1 &&
      (edges.get(component[0]!) ?? []).some((e) => e.target === component[0]);
    if (component.length === 1 && !selfLoop) continue;

    const start = component[0]!;
    const path: number[] = [];
    const offsets: number[] = [];
    const visited = new Set<number>();
    const walk = (node: number): boolean => {
      path.push(node);
      visited.add(node);
      for (const edge of edges.get(node) ?? []) {
        if (!members.has(edge.target)) continue;
        if (edge.target === start || visited.has(edge.target)) {
          offsets.push(edge.offset);
          return true;
        }
        if (walk(edge.target)) {
          offsets.unshift(edge.offset);
          return true;
        }
      }
      path.pop();
      visited.delete(node);
      return false;
    };
    walk(start);
    // Rotate the cycle to its lowest function index so the report is stable.
    const lowest = path.indexOf(Math.min(...path));
    const orderedPath = lowest > 0 ? [...path.slice(lowest), ...path.slice(0, lowest)] : path;
    const orderedOffsets =
      lowest > 0 ? [...offsets.slice(lowest), ...offsets.slice(0, lowest)] : offsets;
    const names = orderedPath.map((index) => byIndex.get(index)?.name ?? `func[${index}]`);
    if (selfLoop && names.length === 1) names.push(names[0] as string);
    cycles.push({ functions: names, offsets: orderedOffsets });
  }

  return cycles;
}

function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${bytes} B`;
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const wasmMemoryRules: Rule[] = [
  {
    id: 'soroban/wasm-invalid-binary',
    category: 'network',
    severity: 'error',
    description: 'A deployed Soroban contract WASM binary cannot be parsed',
    run() {},
  },
  {
    id: 'soroban/wasm-unbounded-memory',
    category: 'network',
    severity: 'warning',
    description: 'A Soroban contract can grow memory without a declared maximum',
    run() {},
  },
  {
    id: 'soroban/wasm-excessive-initial-memory',
    category: 'network',
    severity: 'warning',
    description: 'A Soroban contract reserves a large initial memory',
    run() {},
  },
  {
    id: 'soroban/wasm-recursive-call',
    category: 'network',
    severity: 'error',
    description:
      'A Soroban contract contains a recursive call cycle that can exhaust the host stack',
    run() {},
  },
  {
    id: 'soroban/wasm-unbounded-loop',
    category: 'network',
    severity: 'warning',
    description: 'A Soroban contract contains a loop with no branch or return that can leave it',
    run() {},
  },
  {
    id: 'soroban/wasm-large-stack-frame',
    category: 'network',
    severity: 'warning',
    description: 'A Soroban contract function declares an unusually large stack frame',
    run() {},
  },
];

/** Object wrapper around `analyzeWasmMemory`, for callers that prefer a class. */
export class WasmMemoryHazardAnalyzer {
  constructor(private readonly options: MemoryHazardOptions = {}) {}

  analyze(bytes: Uint8Array): MemoryHazardReport {
    return analyzeWasmMemory(bytes, this.options);
  }
}
