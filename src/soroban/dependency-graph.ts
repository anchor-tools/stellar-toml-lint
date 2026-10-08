/**
 * Which contracts a contract calls, drawn as a graph.
 *
 * A currency entry in `stellar.toml` names one contract, but that contract is
 * rarely the whole system: a token wrapper calls an oracle, a pool contract
 * calls two tokens, a bridge calls a gateway the anchor never audited. Those
 * edges are invisible in the file, so an anchor upgrading one contract cannot
 * see what breaks downstream, and a dependency whose TTL lapsed mid-flight
 * fails a user transaction that the anchor's own code has nothing to do with.
 *
 * The edges are read out of the deployed WASM rather than executed: a module's
 * import table names, per imported function, the module it comes from, and a
 * contract that statically links another contract imports it under a module
 * name that decodes as a contract address. Host modules (`vm`, `ledger`,
 * `storage`, …) are the Soroban environment and carry no edges. Each decoded
 * address is then asked the question the file's own contracts are asked — is
 * there a live instance on this network? — which is what turns a diagram into
 * a check.
 *
 * Traversal is breadth-first and bounded (`maxContracts`), because one
 * transitive dependency set can be arbitrarily large and every hop is an RPC
 * round trip. Like the other network-bound checks, an endpoint that does not
 * answer produces no findings.
 */
import { StrKey } from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';
import { isString, isUrl } from '../predicates.js';
import { contractCurrenciesOf } from '../rules/currencies.js';
import { webAuthContractIdOf } from '../rules/general.js';
import {
  contractDataInstanceKey,
  fetchContractWasm,
  queryLedgerEntry,
  readLeb128,
} from '../soroban.js';
import { decompressWasm } from './wasm-auditor.js';
import { networkTargetFor } from './multi-network.js';
import type { ContractPresence } from './multi-network.js';

const UNRESOLVED_DEPENDENCY_RULE = 'soroban/unresolved-contract-dependency';
const CIRCULAR_DEPENDENCY_RULE = 'soroban/circular-contract-dependency';

const DEPENDENCY_HELP_URI =
  'https://developers.stellar.org/docs/learn/fundamentals/contract-basic-anatomy';

/** How many contracts one run traverses before it says it stopped. */
const MAX_CONTRACTS = 32;

/** The WASM section id of the import section. */
const IMPORT_SECTION = 2;

/** The four external kinds a WASM import can declare. */
export type WasmImportKind = 'function' | 'table' | 'memory' | 'global';

/** One entry of a module's import table. */
export interface WasmImport {
  module: string;
  name: string;
  kind: WasmImportKind;
}

/** A contract another contract imports, and the functions it imports. */
export interface ContractEdge {
  /** The importing contract. */
  from: string;
  /** The imported contract, decoded from the import module name. */
  to: string;
  /** Function names imported from that module, sorted for stable output. */
  functions: string[];
}

export interface DependencyNode {
  id: string;
  /** The `stellar.toml` path that declared it, when the file declared it. */
  path: string | undefined;
  /** How many imports the module declared, host ones included. */
  imports: number;
  /** Contracts imported from, in traversal order. */
  dependencies: string[];
  /** Whether the contract is live on the network that was checked. */
  presence: ContractPresence;
  /** `true` for a contract named in `stellar.toml`, `false` when discovered. */
  declared: boolean;
  /** Set when the WASM could not be read, so its own edges are unknown. */
  unreadable: boolean;
}

export interface DependencyGraph {
  /** `mainnet`/`testnet`/`futurenet` when the traced network was recognised. */
  network: string | undefined;
  rpcUrl: string | undefined;
  nodes: DependencyNode[];
  edges: ContractEdge[];
  /** Import cycles, each written as the path that closes it. */
  cycles: string[][];
  /** `true` when `maxContracts` was reached and edges remain unexplored. */
  truncated: boolean;
}

/**
 * The entries of a module's import section.
 *
 * A malformed module yields whatever parsed before the fault — an unreadable
 * import table is not a finding about the file, so it must not throw.
 */
export function readWasmImports(wasm: Buffer): WasmImport[] {
  if (wasm.length < 8 || wasm.readUInt32BE(0) !== 0x0061736d) return [];

  let pos = 8;
  while (pos < wasm.length) {
    const id = wasm[pos] as number;
    const size = readLeb128(wasm, pos + 1);
    if (size === undefined) return [];
    const start = size.next;
    const end = start + size.value;
    if (end > wasm.length) return [];
    if (id === IMPORT_SECTION) return parseImportSection(wasm, start, end);
    pos = end;
  }
  return [];
}

/** Reads one length-prefixed UTF-8 WASM identifier. */
function readName(
  wasm: Buffer,
  pos: number,
  end: number,
): { value: string; next: number } | undefined {
  const length = readLeb128(wasm, pos);
  if (length === undefined) return undefined;
  const stop = length.next + length.value;
  if (stop > end) return undefined;
  return { value: wasm.toString('utf8', length.next, stop), next: stop };
}

/** Skips a WASM limits clause: a flag byte, a minimum, and a maximum if flagged. */
function skipLimits(wasm: Buffer, pos: number, end: number): number | undefined {
  const flag = wasm[pos];
  if (flag === undefined || pos >= end) return undefined;
  const min = readLeb128(wasm, pos + 1);
  if (min === undefined) return undefined;
  if ((flag & 1) === 0) return min.next;
  return readLeb128(wasm, min.next)?.next;
}

const IMPORT_KINDS = ['function', 'table', 'memory', 'global'] as const;

/**
 * Walks one import section: a vector of `{module, name, kind, descriptor}`.
 *
 * Only the two names matter here, so the descriptor after the kind is skipped
 * by its fixed shape rather than decoded — a function takes a type index, a
 * table a reference type plus limits, memory limits, a global a value type and
 * a mutability flag.
 */
function parseImportSection(wasm: Buffer, start: number, end: number): WasmImport[] {
  const imports: WasmImport[] = [];
  const count = readLeb128(wasm, start);
  if (count === undefined) return imports;
  let pos = count.next;

  for (let index = 0; index < count.value; index++) {
    const module = readName(wasm, pos, end);
    if (module === undefined) return imports;
    const name = readName(wasm, module.next, end);
    if (name === undefined) return imports;
    const kindByte = wasm[name.next] as number;
    const kind = IMPORT_KINDS[kindByte];
    if (kind === undefined) return imports;
    imports.push({ module: module.value, name: name.value, kind });

    let cursor = name.next + 1;
    if (kind === 'function') {
      const typeIndex = readLeb128(wasm, cursor);
      if (typeIndex === undefined) return imports;
      cursor = typeIndex.next;
    } else if (kind === 'table') {
      const limits = skipLimits(wasm, cursor + 1, end);
      if (limits === undefined) return imports;
      cursor = limits;
    } else if (kind === 'memory') {
      const limits = skipLimits(wasm, cursor, end);
      if (limits === undefined) return imports;
      cursor = limits;
    } else {
      cursor += 2;
      if (cursor > end) return imports;
    }
    pos = cursor;
  }
  return imports;
}

/**
 * The contract address an import module name refers to, or `undefined` for a
 * host module.
 *
 * Toolchains write the target in one of three shapes: the StrKey address
 * itself, the address after a `:` or `/` separator (`contract:C…`), or the raw
 * 32-byte hash in hex. Anything else is a Soroban host module and imports no
 * edge — decoding only what genuinely reads as an address is what keeps this
 * from inventing dependencies out of `vm` and `ledger`.
 */
export function contractIdOfModule(module: string): string | undefined {
  for (const part of module.split(/[:/]/)) {
    const value = part.trim().toUpperCase();
    if (value.length === 0) continue;
    if (StrKey.isValidContract(value)) {
      return StrKey.encodeContract(StrKey.decodeContract(value));
    }
    if (/^[0-9A-F]{64}$/.test(value)) {
      return StrKey.encodeContract(Buffer.from(value, 'hex'));
    }
  }
  return undefined;
}

/** The edges declared by an already-parsed import table. */
export function edgesFromImports(
  contractId: string,
  imports: readonly WasmImport[],
  aliases: Readonly<Record<string, string>> = {},
): ContractEdge[] {
  const byTarget = new Map<string, string[]>();
  for (const entry of imports) {
    const target = aliases[entry.module] ?? contractIdOfModule(entry.module);
    if (target === undefined) continue;
    const functions = byTarget.get(target);
    if (functions === undefined) byTarget.set(target, [entry.name]);
    else if (!functions.includes(entry.name)) functions.push(entry.name);
  }
  return [...byTarget.entries()]
    .map(([to, functions]) => ({ from: contractId, to, functions: functions.sort() }))
    .sort((left, right) => left.to.localeCompare(right.to));
}

/** The edges one contract's WASM declares. */
export function contractEdges(
  contractId: string,
  wasm: Buffer,
  aliases: Readonly<Record<string, string>> = {},
): ContractEdge[] {
  // A deployed code entry can hold gzipped bytes, which are not a module until
  // they are inflated; `readWasmImports` reads one section table, so it gets the
  // inflated form.
  return edgesFromImports(contractId, readWasmImports(decompressWasm(wasm)), aliases);
}

/** Options for {@link traceDependencyGraph}. */
export interface TraceOptions {
  rules?: RuleOverrides;
  /** The RPC of the network being traced. */
  rpcUrl?: string;
  /** The network's passphrase, used only to name it in the output. */
  passphrase?: unknown;
  fetchImpl?: typeof fetch;
  /** Import module name → contract address, for SDKs with their own naming. */
  aliases?: Readonly<Record<string, string>>;
  /** Contracts to visit; defaults to 32. */
  maxContracts?: number;
  /** Reads a contract's WASM; replaced in tests to stay hermetic. */
  readWasm?: (contractId: string) => Promise<Buffer | undefined>;
  /** Asks whether a contract is live; replaced in tests to stay hermetic. */
  presence?: (contractId: string) => Promise<ContractPresence>;
}

/** Asks one network's RPC whether a contract instance is live. */
async function probePresence(
  contractId: string,
  rpcUrl: string | undefined,
  fetchImpl: typeof fetch,
): Promise<ContractPresence> {
  if (rpcUrl === undefined || !isUrl(rpcUrl)) return 'unknown';
  const entry = await queryLedgerEntry(rpcUrl, contractDataInstanceKey(contractId), fetchImpl);
  if (entry === undefined) return 'unknown';
  return entry.liveUntil === undefined ? 'absent' : 'deployed';
}

/**
 * Traces `roots` and everything they import — one to two RPC queries per
 * contract. What is beyond `maxContracts` is left out and the graph reports
 * itself as truncated rather than looking complete.
 */
export async function traceDependencyGraph(
  roots: readonly { id: string; path?: string }[],
  options: TraceOptions = {},
): Promise<DependencyGraph> {
  const limit = options.maxContracts ?? MAX_CONTRACTS;
  const fetchImpl = options.fetchImpl ?? fetch;
  const readWasm =
    options.readWasm ??
    ((id: string) =>
      options.rpcUrl === undefined
        ? Promise.resolve(undefined)
        : fetchContractWasm(id, options.rpcUrl, fetchImpl));
  const presence =
    options.presence ?? ((id: string) => probePresence(id, options.rpcUrl, fetchImpl));

  const nodes = new Map<string, DependencyNode>();
  const edges: ContractEdge[] = [];
  const queue: { id: string; path: string | undefined; declared: boolean }[] = roots.map(
    ({ id, path }) => ({ id, path, declared: true }),
  );
  const pending = new Set(queue.map((entry) => entry.id));

  while (queue.length > 0) {
    if (nodes.size >= limit) {
      // Everything still queued went unexplored; stop rather than keep paying.
      break;
    }
    const visit = queue.shift();
    if (visit === undefined || nodes.has(visit.id)) continue;
    pending.delete(visit.id);

    const live = await presence(visit.id);
    const base: DependencyNode = {
      id: visit.id,
      path: visit.path,
      imports: 0,
      dependencies: [],
      presence: live,
      declared: visit.declared,
      unreadable: false,
    };
    // A contract that is not live has no readable imports, so there is nothing
    // to follow — the finding about it comes from the edge that reached it.
    if (live !== 'deployed') {
      nodes.set(visit.id, base);
      continue;
    }

    const wasm = await readWasm(visit.id);
    if (wasm === undefined) {
      nodes.set(visit.id, { ...base, unreadable: true });
      continue;
    }

    const imports = readWasmImports(wasm);
    const found = edgesFromImports(visit.id, imports, options.aliases);
    nodes.set(visit.id, {
      ...base,
      imports: imports.length,
      dependencies: found.map((edge) => edge.to),
    });
    edges.push(...found);
    for (const edge of found) {
      if (nodes.has(edge.to) || pending.has(edge.to)) continue;
      pending.add(edge.to);
      queue.push({ id: edge.to, path: undefined, declared: false });
    }
  }

  const reached = new Set(nodes.keys());
  for (const node of nodes.values()) {
    node.dependencies = node.dependencies.filter((to) => reached.has(to));
  }

  return {
    network: networkTargetFor(options.passphrase)?.name,
    rpcUrl: options.rpcUrl,
    nodes: [...nodes.values()],
    edges,
    cycles: findCycles(edges.filter((edge) => reached.has(edge.from) && reached.has(edge.to))),
    truncated: queue.length > 0,
  };
}

/**
 * Every import cycle in the graph, each written as the path that closes it
 * (`[a, b, a]` for `a → b → a`), so a contract that imports itself appears as
 * `[a, a]`.
 *
 * Depth-first search with a colour map: a back edge to a node still on the
 * stack closes a cycle. Cycles are rotated to start at their smallest address
 * so `a→b→a` and `b→a→b` are reported once.
 */
export function findCycles(edges: readonly ContractEdge[]): string[][] {
  const adjacency = new Map<string, string[]>();
  for (const edge of edges) {
    const targets = adjacency.get(edge.from);
    if (targets === undefined) adjacency.set(edge.from, [edge.to]);
    else if (!targets.includes(edge.to)) targets.push(edge.to);
  }

  const state = new Map<string, 'visiting' | 'done'>();
  const stack: string[] = [];
  const seen = new Set<string>();
  const cycles: string[][] = [];

  const visit = (id: string): void => {
    state.set(id, 'visiting');
    stack.push(id);
    for (const target of adjacency.get(id) ?? []) {
      if (state.get(target) === 'visiting') {
        const rotated = rotateToMinimum(stack.slice(stack.indexOf(target)));
        const closed = [...rotated, rotated[0] as string];
        const key = closed.join('>');
        if (!seen.has(key)) {
          seen.add(key);
          cycles.push(closed);
        }
      } else if (state.get(target) === undefined) {
        visit(target);
      }
    }
    stack.pop();
    state.set(id, 'done');
  };

  for (const id of [...adjacency.keys()].sort()) {
    if (state.get(id) === undefined) visit(id);
  }
  return cycles.sort((left, right) => left.join('>').localeCompare(right.join('>')));
}

/** Rotates a cycle so it starts at its lexicographically smallest member. */
function rotateToMinimum(cycle: readonly string[]): string[] {
  if (cycle.length === 0) return [];
  let minimum = 0;
  for (let index = 1; index < cycle.length; index++) {
    if ((cycle[index] as string) < (cycle[minimum] as string)) minimum = index;
  }
  return [...cycle.slice(minimum), ...cycle.slice(0, minimum)];
}

function severityFor(
  rule: string,
  fallback: Severity,
  rules?: RuleOverrides,
): Severity | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' || override === 'info'
    ? override
    : fallback;
}

function finding(
  rule: string,
  fallback: Severity,
  message: string,
  path: string | undefined,
  suggestion: string,
  rules?: RuleOverrides,
): Diagnostic[] {
  const severity = severityFor(rule, fallback, rules);
  if (severity === undefined) return [];
  return [
    {
      rule,
      severity,
      category: 'network',
      message,
      ...(path === undefined ? {} : { path }),
      helpUri: DEPENDENCY_HELP_URI,
      suggestion,
    },
  ];
}

/** Shortens an address for diagram labels without making it ambiguous. */
function shortId(contractId: string): string {
  return contractId.length <= 16 ? contractId : `${contractId.slice(0, 6)}…${contractId.slice(-4)}`;
}

/** The graph as JSON, the machine-readable half of the output. */
export function graphToJson(graph: DependencyGraph): string {
  return `${JSON.stringify(
    {
      network: graph.network ?? null,
      rpcUrl: graph.rpcUrl ?? null,
      truncated: graph.truncated,
      contracts: graph.nodes.map((node) => ({
        id: node.id,
        ...(node.path === undefined ? {} : { path: node.path }),
        declared: node.declared,
        presence: node.presence,
        imports: node.imports,
        dependsOn: node.dependencies,
        unreadable: node.unreadable,
      })),
      edges: graph.edges.map((edge) => ({
        from: edge.from,
        to: edge.to,
        functions: edge.functions,
      })),
      cycles: graph.cycles,
    },
    null,
    2,
  )}\n`;
}

/**
 * The graph as Mermaid.
 *
 * Nodes are declared before edges so a contract with no edges still appears,
 * and the two classes let the picture carry the findings rather than only the
 * topology.
 */
export function graphToMermaid(graph: DependencyGraph): string {
  const ids = new Map(graph.nodes.map((node, index) => [node.id, `c${index}`]));
  const lines: string[] = ['graph LR'];

  for (const node of graph.nodes) {
    const label = [
      shortId(node.id),
      node.declared ? 'declared' : 'dependency',
      node.presence === 'deployed' ? undefined : node.presence,
    ]
      .filter(isString)
      .join(' · ');
    lines.push(`  ${ids.get(node.id) as string}["${label}"]`);
  }
  for (const edge of graph.edges) {
    const from = ids.get(edge.from);
    const to = ids.get(edge.to);
    if (from === undefined || to === undefined) continue;
    const shown = edge.functions.slice(0, 3).join(', ');
    const rest = edge.functions.length > 3 ? ` +${edge.functions.length - 3}` : '';
    lines.push(`  ${from} -->|${shown}${rest}| ${to}`);
  }

  const classOf = (predicate: (node: DependencyNode) => boolean): string[] =>
    graph.nodes
      .filter(predicate)
      .map((node) => ids.get(node.id))
      .filter((id): id is string => id !== undefined);

  const unresolved = classOf((node) => !node.declared && node.presence === 'absent');
  const circular = classOf((node) => graph.cycles.some((cycle) => cycle.includes(node.id)));

  if (unresolved.length > 0) {
    lines.push('  classDef unresolved stroke:#d33,stroke-width:2px');
    lines.push(`  class ${unresolved.join(',')} unresolved`);
  }
  if (circular.length > 0) {
    lines.push('  classDef circular stroke:#e80');
    lines.push(`  class ${circular.join(',')} circular`);
  }
  return `${lines.join('\n')}\n`;
}

/** Renders a graph in either output format. */
export function renderDependencyGraph(graph: DependencyGraph, format: 'json' | 'mermaid'): string {
  return format === 'json' ? graphToJson(graph) : graphToMermaid(graph);
}

/** Every contract a file declares, in the order it declares them. */
export function declaredContractRoots(
  doc: Record<string, unknown>,
): { id: string; path: string }[] {
  const auth = webAuthContractIdOf(doc);
  return [
    ...contractCurrenciesOf(doc).map(({ id, path }) => ({ id, path })),
    ...(auth === undefined ? [] : [auth]),
  ];
}

/** The Soroban RPC for the network the file declares. */
export function rpcUrlForDocument(doc: Record<string, unknown>): string | undefined {
  return networkTargetFor(doc.NETWORK_PASSPHRASE)?.rpcUrl;
}

/** The graph a file's contracts imply, or `undefined` when it has none. */
export async function graphForDocument(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: TraceOptions = {},
): Promise<DependencyGraph | undefined> {
  const roots = declaredContractRoots(doc);
  const rpcUrl = options.rpcUrl ?? rpcUrlForDocument(doc);
  if (roots.length === 0 || rpcUrl === undefined) return undefined;
  return traceDependencyGraph(roots, {
    ...options,
    rpcUrl,
    fetchImpl,
    passphrase: options.passphrase ?? doc.NETWORK_PASSPHRASE,
  });
}

/** The findings for a traced graph: missing dependencies and import cycles. */
export function dependencyDiagnostics(
  graph: DependencyGraph,
  options: TraceOptions = {},
): Diagnostic[] {
  const byId = new Map(graph.nodes.map((node) => [node.id, node]));
  const diagnostics: Diagnostic[] = [];
  const reported = new Set<string>();

  for (const edge of graph.edges) {
    const dependency = byId.get(edge.to);
    const importer = byId.get(edge.from);
    // Only a confirmed absence is a finding: `unknown` is an RPC that did not
    // answer, and a contract the file declares has its own rule already.
    if (
      dependency === undefined ||
      dependency.declared ||
      dependency.presence !== 'absent' ||
      reported.has(dependency.id)
    ) {
      continue;
    }
    reported.add(dependency.id);
    diagnostics.push(
      ...finding(
        UNRESOLVED_DEPENDENCY_RULE,
        'error',
        `Contract ${edge.from} imports ${dependency.id}, which has no instance on ${graph.network ?? 'the network this file declares'}`,
        importer?.path,
        `${edge.functions.join(', ')} cannot resolve on chain. Deploy ${dependency.id} there, or point ${edge.from} at a deployment that exists.`,
        options.rules,
      ),
    );
  }

  for (const cycle of graph.cycles) {
    const declared = cycle
      .map((id) => byId.get(id)?.path)
      .find((pathValue): pathValue is string => pathValue !== undefined);
    diagnostics.push(
      ...finding(
        CIRCULAR_DEPENDENCY_RULE,
        'warning',
        `Contract dependency cycle: ${cycle.join(' → ')}`,
        declared,
        'Contracts in a cycle pin each other: upgrading one means deploying the whole loop together, and one expired TTL breaks every caller in it.',
        options.rules,
      ),
    );
  }

  return diagnostics;
}

/**
 * The `--check-contracts` entry point for dependencies: trace what the file's
 * contracts import and report what is not there.
 */
export async function checkContractDependencies(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: TraceOptions = {},
): Promise<Diagnostic[]> {
  const graph = await graphForDocument(doc, fetchImpl, options);
  return graph === undefined ? [] : dependencyDiagnostics(graph, options);
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const dependencyGraphRules: Rule[] = [
  {
    id: UNRESOLVED_DEPENDENCY_RULE,
    category: 'network',
    severity: 'error',
    description: 'A contract imports another contract that is not deployed on this network',
    run() {},
  },
  {
    id: CIRCULAR_DEPENDENCY_RULE,
    category: 'network',
    severity: 'warning',
    description: 'Contracts import each other in a cycle, so they must be upgraded together',
    run() {},
  },
];

/** Rule ids emitted by {@link checkContractDependencies}. */
export const dependencyGraphRuleIds: readonly string[] = dependencyGraphRules.map(
  (rule) => rule.id,
);
