import { describe, expect, it } from 'vitest';
import { StrKey } from '@stellar/stellar-base';
import { allRules } from '../src/rules/index.js';
import {
  checkContractDependencies,
  contractEdges,
  contractIdOfModule,
  declaredContractRoots,
  dependencyDiagnostics,
  findCycles,
  graphForDocument,
  graphToMermaid,
  graphToJson,
  readWasmImports,
  traceDependencyGraph,
  type ContractEdge,
  type DependencyGraph,
  type DependencyNode,
} from '../src/soroban/dependency-graph.js';
import {
  NETWORK_TARGETS,
  networkTargetFor,
  type ContractPresence,
} from '../src/soroban/multi-network.js';
import { contractDataInstanceKey } from '../src/soroban.js';

const UNRESOLVED = 'soroban/unresolved-contract-dependency';
const CIRCULAR = 'soroban/circular-contract-dependency';

const MAINNET = 'Public Global Stellar Network ; September 2015';
const TESTNET = 'Test SDF Network ; September 2015';
const PRIVATE_NET = 'Private Anchor Net ; January 2026';

const WRAPPER = StrKey.encodeContract(Buffer.alloc(32, 1));
const ORACLE = StrKey.encodeContract(Buffer.alloc(32, 2));
const TOKEN_B = StrKey.encodeContract(Buffer.alloc(32, 3));
const MISSING = StrKey.encodeContract(Buffer.alloc(32, 4));
const AUTH = StrKey.encodeContract(Buffer.alloc(32, 5));

const MAINNET_RPC = (networkTargetFor(MAINNET) ?? NETWORK_TARGETS[0])?.rpcUrl as string;

/** Unsigned LEB128, the length encoding WASM uses. */
function leb(value: number): Buffer {
  const bytes: number[] = [];
  let rest = value;
  do {
    let byte = rest & 0x7f;
    rest >>>= 7;
    if (rest !== 0) byte |= 0x80;
    bytes.push(byte);
  } while (rest !== 0);
  return Buffer.from(bytes);
}

/** A WASM name: its byte length followed by its UTF-8 bytes. */
function encodedName(text: string): Buffer {
  const bytes = Buffer.from(text, 'utf8');
  return Buffer.concat([leb(bytes.length), bytes]);
}

const KIND_BYTES = { function: 0, table: 1, memory: 2, global: 3 } as const;

/** One import entry, with the descriptor its external kind requires. */
function importEntry(
  module: string,
  name: string,
  kind: keyof typeof KIND_BYTES = 'function',
): Buffer {
  const descriptor =
    kind === 'function'
      ? leb(0) // type index
      : kind === 'table'
        ? Buffer.from([0x70, 0x00, 0x01]) // reference type, limits flag, minimum
        : kind === 'memory'
          ? Buffer.from([0x00, 0x01]) // limits flag, minimum
          : Buffer.from([0x7f, 0x00]); // value type, mutability
  return Buffer.concat([
    encodedName(module),
    encodedName(name),
    Buffer.from([KIND_BYTES[kind]]),
    descriptor,
  ]);
}

/** A minimal module whose only section is an import table of these entries. */
function wasmWithImports(entries: readonly Buffer[]): Buffer {
  const header = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
  const body = Buffer.concat([leb(entries.length), ...entries]);
  return Buffer.concat([header, Buffer.from([0x02]), leb(body.length), body]);
}

/** Host imports every Soroban contract carries, which import no edge. */
const HOST: readonly Buffer[] = [
  importEntry('vm', 'get_current_contract'),
  importEntry('storage', 'put'),
];

function importsFrom(target: string, functions: readonly string[]): Buffer[] {
  return functions.map((functionName) => importEntry(target, functionName));
}

function document(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    NETWORK_PASSPHRASE: MAINNET,
    CURRENCIES: [{ code: 'USD', contract: WRAPPER }],
    ...overrides,
  };
}

/**
 * A network stand-in: import tables per contract plus which contracts are live.
 * The `live` map defaults to deployed everywhere, so a test only names the
 * contract it is about.
 */
function network(
  wasm: Record<string, readonly Buffer[]>,
  live: Record<string, ContractPresence> = {},
): {
  readWasm: (contractId: string) => Promise<Buffer | undefined>;
  presence: (contractId: string) => Promise<ContractPresence>;
  visited: string[];
} {
  const visited: string[] = [];
  return {
    readWasm: async (contractId) => {
      const entries = wasm[contractId];
      return entries === undefined ? undefined : wasmWithImports(entries);
    },
    presence: async (contractId) => {
      visited.push(contractId);
      return live[contractId] ?? 'deployed';
    },
    visited,
  };
}

function nodeOf(graph: DependencyGraph, id: string): DependencyNode {
  const node = graph.nodes.find((one) => one.id === id);
  if (node === undefined) throw new Error(`${id} is not in the graph`);
  return node;
}

/** The label a node is drawn with, as `graphToMermaid` writes it. */
function labelOf(contractId: string, suffix: string): string {
  return `${contractId.slice(0, 6)}…${contractId.slice(-4)} · ${suffix}`;
}

describe('soroban WASM import table reader', () => {
  it('reads module, field, and kind for every external kind', () => {
    const wasm = wasmWithImports([
      importEntry('vm', 'get_ledger_version'),
      importEntry('env', 'memgrow', 'memory'),
      importEntry('funcref', 'tbl', 'table'),
      importEntry('globals', 'value', 'global'),
    ]);

    expect(readWasmImports(wasm)).toEqual([
      { module: 'vm', name: 'get_ledger_version', kind: 'function' },
      { module: 'env', name: 'memgrow', kind: 'memory' },
      { module: 'funcref', name: 'tbl', kind: 'table' },
      { module: 'globals', name: 'value', kind: 'global' },
    ]);
  });

  it('reads nothing from a module with no import section or a bad header', () => {
    expect(readWasmImports(Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]))).toEqual(
      [],
    );
    expect(readWasmImports(Buffer.from('not wasm at all'))).toEqual([]);
  });

  it('returns nothing rather than throwing on a truncated import table', () => {
    const whole = wasmWithImports(HOST);
    expect(readWasmImports(whole.subarray(0, whole.length - 2))).toEqual([]);

    const header = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
    const body = Buffer.concat([leb(4), importEntry('vm', 'a')]);
    const shortSection = Buffer.concat([header, Buffer.from([0x02]), leb(body.length - 4), body]);
    expect(readWasmImports(shortSection)).toEqual([]);
  });
});

describe('soroban contract dependency graph', () => {
  it('recognises an address in the shapes toolchains emit, and nothing else', () => {
    expect(contractIdOfModule(WRAPPER)).toBe(WRAPPER);
    expect(contractIdOfModule(WRAPPER.toLowerCase())).toBe(WRAPPER);
    expect(contractIdOfModule(`contract:${ORACLE}`)).toBe(ORACLE);
    expect(contractIdOfModule(Buffer.alloc(32, 2).toString('hex'))).toBe(ORACLE);
    expect(contractIdOfModule('vm')).toBeUndefined();
    expect(contractIdOfModule('storage')).toBeUndefined();
    expect(contractIdOfModule('CABCNOTANADDRESS')).toBeUndefined();
  });

  it('groups one edge per imported contract with its function names', () => {
    const wasm = wasmWithImports([
      ...HOST,
      ...importsFrom(ORACLE, ['price', 'decimal']),
      ...importsFrom(TOKEN_B, ['transfer']),
    ]);

    expect(contractEdges(WRAPPER, wasm)).toEqual([
      { from: WRAPPER, to: ORACLE, functions: ['decimal', 'price'] },
      { from: WRAPPER, to: TOKEN_B, functions: ['transfer'] },
    ] as ContractEdge[]);
  });

  it('maps module names through caller-supplied aliases', () => {
    const wasm = wasmWithImports([importEntry('oracle', 'price')]);
    expect(contractEdges(WRAPPER, wasm, { oracle: ORACLE })).toEqual([
      { from: WRAPPER, to: ORACLE, functions: ['price'] },
    ]);
  });

  it('follows imports transitively and marks which contracts the file declared', async () => {
    const fixture = network({
      [WRAPPER]: [...HOST, ...importsFrom(ORACLE, ['price'])],
      [ORACLE]: importsFrom(TOKEN_B, ['transfer']),
      [TOKEN_B]: HOST,
    });

    const graph = await traceDependencyGraph([{ id: WRAPPER, path: 'CURRENCIES[0].contract' }], {
      readWasm: fixture.readWasm,
      presence: fixture.presence,
      rpcUrl: MAINNET_RPC,
    });

    expect(graph.nodes.map((node) => node.id)).toEqual([WRAPPER, ORACLE, TOKEN_B]);
    expect(nodeOf(graph, WRAPPER)).toMatchObject({
      declared: true,
      path: 'CURRENCIES[0].contract',
      dependencies: [ORACLE],
      imports: HOST.length + 1,
    });
    expect(nodeOf(graph, TOKEN_B)).toMatchObject({ declared: false, dependencies: [] });
    expect(graph.edges).toHaveLength(2);
    expect(graph.cycles).toEqual([]);
    expect(graph.truncated).toBe(false);
    expect(fixture.visited).toEqual([WRAPPER, ORACLE, TOKEN_B]);
  });

  it('reports itself truncated instead of pretending it finished', async () => {
    const ids = [1, 2, 3, 4, 5].map((one) => StrKey.encodeContract(Buffer.alloc(32, one)));
    const chain: Record<string, Buffer[]> = {};
    ids.forEach((id, index) => {
      const next = ids[index + 1];
      chain[id] = next === undefined ? [] : importsFrom(next, ['call']);
    });
    const fixture = network(chain);

    const graph = await traceDependencyGraph([{ id: ids[0] as string }], {
      readWasm: fixture.readWasm,
      presence: fixture.presence,
      maxContracts: 2,
    });

    expect(graph.nodes.map((node) => node.id)).toEqual([ids[0], ids[1]]);
    expect(graph.truncated).toBe(true);
    // The unvisited tail is absent from the graph, so nothing is claimed about it.
    expect(dependencyDiagnostics(graph)).toEqual([]);
  });

  it('marks a contract whose WASM could not be read as opaque', async () => {
    const fixture = network({}, { [WRAPPER]: 'deployed' });
    const graph = await traceDependencyGraph([{ id: WRAPPER }], {
      readWasm: fixture.readWasm,
      presence: fixture.presence,
    });
    expect(nodeOf(graph, WRAPPER)).toMatchObject({ unreadable: true, dependencies: [] });
    expect(dependencyDiagnostics(graph)).toEqual([]);
  });

  it('names the network the trace ran against', async () => {
    const fixture = network({ [WRAPPER]: HOST });
    const graph = await traceDependencyGraph([{ id: WRAPPER }], {
      readWasm: fixture.readWasm,
      presence: fixture.presence,
      passphrase: TESTNET,
    });
    expect(graph.network).toBe('testnet');
  });

  it('finds cycles, once each, including a contract that imports itself', () => {
    const edge = (from: string, to: string): ContractEdge => ({
      from,
      to,
      functions: ['call'],
    });
    const hasEdge = (edges: readonly ContractEdge[], from: string, to: string): boolean =>
      edges.some((one) => one.from === from && one.to === to);
    /** A closed walk: every step is an edge, and it ends where it started. */
    const closes = (cycle: readonly string[], edges: readonly ContractEdge[]): boolean => {
      for (let index = 0; index < cycle.length - 1; index++) {
        if (!hasEdge(edges, cycle[index] as string, cycle[index + 1] as string)) return false;
      }
      return cycle[0] === cycle[cycle.length - 1];
    };
    const smallest = [WRAPPER, ORACLE].sort()[0] as string;
    const other = smallest === WRAPPER ? ORACLE : WRAPPER;

    expect(findCycles([edge(WRAPPER, ORACLE), edge(ORACLE, WRAPPER)])).toEqual([
      [smallest, other, smallest],
    ]);
    expect(findCycles([edge(WRAPPER, WRAPPER)])).toEqual([[WRAPPER, WRAPPER]]);
    expect(findCycles([edge(WRAPPER, ORACLE), edge(ORACLE, TOKEN_B)])).toEqual([]);

    const tangled = [
      edge(ORACLE, WRAPPER),
      edge(WRAPPER, TOKEN_B),
      edge(TOKEN_B, ORACLE),
      edge(TOKEN_B, WRAPPER),
    ];
    const cycles = findCycles(tangled);
    expect(cycles).toHaveLength(2);
    for (const cycle of cycles) {
      expect(closes(cycle, tangled)).toBe(true);
      // Each cycle is rotated to its own smallest member, so rotations of one
      // loop are never reported twice.
      expect(cycle[0]).toBe([...cycle].sort()[0]);
    }
    expect(new Set(cycles.map((cycle) => cycle.join('>')).values()).size).toBe(2);
  });

  it('errors on a dependency that is not deployed where its importer is', async () => {
    const fixture = network(
      { [WRAPPER]: [...HOST, ...importsFrom(MISSING, ['mint'])] },
      { [MISSING]: 'absent' },
    );
    const graph = await traceDependencyGraph([{ id: WRAPPER, path: 'CURRENCIES[0].contract' }], {
      readWasm: fixture.readWasm,
      presence: fixture.presence,
      passphrase: MAINNET,
    });

    const diagnostics = dependencyDiagnostics(graph);
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      rule: UNRESOLVED,
      severity: 'error',
      path: 'CURRENCIES[0].contract',
      message: `Contract ${WRAPPER} imports ${MISSING}, which has no instance on mainnet`,
    });
    expect(diagnostics[0]?.suggestion).toContain('mint');
  });

  it('reports a missing dependency once, however many contracts import it', async () => {
    const fixture = network(
      {
        [WRAPPER]: importsFrom(MISSING, ['mint']),
        [ORACLE]: importsFrom(MISSING, ['burn']),
        [TOKEN_B]: importsFrom(MISSING, ['transfer']),
      },
      { [MISSING]: 'absent' },
    );
    const graph = await traceDependencyGraph(
      [
        { id: WRAPPER, path: 'CURRENCIES[0].contract' },
        { id: ORACLE, path: 'CURRENCIES[1].contract' },
        { id: TOKEN_B, path: 'CURRENCIES[2].contract' },
      ],
      { readWasm: fixture.readWasm, presence: fixture.presence },
    );

    expect(graph.edges).toHaveLength(3);
    expect(dependencyDiagnostics(graph)).toHaveLength(1);
  });

  it('warns once per cycle and attaches the declared path that owns it', async () => {
    const fixture = network({
      [WRAPPER]: importsFrom(ORACLE, ['price']),
      [ORACLE]: importsFrom(WRAPPER, ['set_price']),
    });
    const graph = await traceDependencyGraph([{ id: WRAPPER, path: 'CURRENCIES[0].contract' }], {
      readWasm: fixture.readWasm,
      presence: fixture.presence,
    });

    const diagnostics = dependencyDiagnostics(graph);
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      rule: CIRCULAR,
      severity: 'warning',
      path: 'CURRENCIES[0].contract',
    });
    const cycle = (graph.cycles[0] ?? []) as string[];
    expect(diagnostics[0]?.message).toBe(`Contract dependency cycle: ${cycle.join(' → ')}`);
  });

  it('diagnoses nothing while the network is not answering', async () => {
    const fixture = network(
      { [WRAPPER]: importsFrom(MISSING, ['mint']) },
      { [MISSING]: 'unknown', [WRAPPER]: 'unknown' },
    );
    const graph = await traceDependencyGraph([{ id: WRAPPER }], {
      readWasm: fixture.readWasm,
      presence: fixture.presence,
    });
    expect(dependencyDiagnostics(graph)).toEqual([]);
  });

  it('leaves a contract the file declares to the rules that own it', async () => {
    const fixture = network({}, { [WRAPPER]: 'absent' });
    const graph = await traceDependencyGraph([{ id: WRAPPER, path: 'CURRENCIES[0].contract' }], {
      readWasm: fixture.readWasm,
      presence: fixture.presence,
    });
    expect(nodeOf(graph, WRAPPER)).toMatchObject({ declared: true, presence: 'absent' });
    expect(dependencyDiagnostics(graph)).toEqual([]);
  });

  it('honours --off and --warn for each rule', async () => {
    const fixture = network(
      {
        [WRAPPER]: [...importsFrom(ORACLE, ['price']), ...importsFrom(MISSING, ['mint'])],
        [ORACLE]: importsFrom(WRAPPER, ['set_price']),
      },
      { [MISSING]: 'absent' },
    );
    const graph = await traceDependencyGraph([{ id: WRAPPER }], {
      readWasm: fixture.readWasm,
      presence: fixture.presence,
    });
    expect(
      dependencyDiagnostics(graph)
        .map((one) => one.rule)
        .sort(),
    ).toEqual([CIRCULAR, UNRESOLVED]);

    expect(
      dependencyDiagnostics(graph, { rules: { [CIRCULAR]: 'off' } }).map((one) => one.rule),
    ).toEqual([UNRESOLVED]);
    expect(
      dependencyDiagnostics(graph, { rules: { [UNRESOLVED]: 'warning' } }).find(
        (one) => one.rule === UNRESOLVED,
      )?.severity,
    ).toBe('warning');
  });
});

describe('soroban dependency graph output formats', () => {
  async function fixture(): Promise<DependencyGraph> {
    const networkFixture = network(
      {
        [WRAPPER]: importsFrom(ORACLE, ['price']),
        [ORACLE]: importsFrom(MISSING, ['mint']),
      },
      { [MISSING]: 'absent' },
    );
    return traceDependencyGraph([{ id: WRAPPER, path: 'CURRENCIES[0].contract' }], {
      readWasm: networkFixture.readWasm,
      presence: networkFixture.presence,
      passphrase: MAINNET,
    });
  }

  it('emits JSON a consumer can parse back into the same graph', async () => {
    const graph = await fixture();
    const parsed = JSON.parse(graphToJson(graph)) as Record<string, unknown>;

    expect(parsed).toMatchObject({ network: 'mainnet', truncated: false });
    expect(parsed.contracts).toHaveLength(3);
    expect(parsed.contracts).toContainEqual(
      expect.objectContaining({ id: MISSING, declared: false, presence: 'absent' }),
    );
    expect(parsed.edges).toEqual([
      { from: WRAPPER, to: ORACLE, functions: ['price'] },
      { from: ORACLE, to: MISSING, functions: ['mint'] },
    ]);
    expect(parsed.cycles).toEqual([]);
  });

  it('emits a Mermaid graph that declares every node before its edges', async () => {
    const graph = await fixture();
    const lines = graphToMermaid(graph).trim().split('\n');

    expect(lines[0]).toBe('graph LR');
    expect(lines[1]).toBe(`  c0["${labelOf(WRAPPER, 'declared')}"]`);
    expect(lines[3]).toBe(`  c2["${labelOf(MISSING, 'dependency · absent')}"]`);
    expect(lines).toContain('  c0 -->|price| c1');
    expect(lines).toContain('  class c2 unresolved');

    const firstEdge = lines.findIndex((line) => line.includes('-->'));
    const lastNode = lines.reduce(
      (last, line, index) => (/^\s+c\d+\["/.test(line) ? index : last),
      -1,
    );
    expect(lastNode).toBeLessThan(firstEdge);
  });

  it('styles the contracts in a cycle', async () => {
    const networkFixture = network({
      [WRAPPER]: importsFrom(ORACLE, ['price']),
      [ORACLE]: importsFrom(WRAPPER, ['set_price']),
    });
    const graph = await traceDependencyGraph([{ id: WRAPPER }], {
      readWasm: networkFixture.readWasm,
      presence: networkFixture.presence,
    });
    expect(graphToMermaid(graph)).toContain('  class c0,c1 circular');
  });
});

describe('soroban dependency check against a document', () => {
  it('collects roots from CURRENCIES and WEB_AUTH_CONTRACT_ID', () => {
    expect(declaredContractRoots(document({ WEB_AUTH_CONTRACT_ID: AUTH }))).toEqual([
      { id: WRAPPER, path: 'CURRENCIES[0].contract' },
      { id: AUTH, path: 'WEB_AUTH_CONTRACT_ID' },
    ]);
  });

  it('stops when the file declares no contracts or no known network', async () => {
    expect(await graphForDocument(document({ NETWORK_PASSPHRASE: PRIVATE_NET }))).toBeUndefined();
    expect(await graphForDocument(document({ CURRENCIES: [] }))).toBeUndefined();
    expect(await checkContractDependencies(document({ CURRENCIES: [] }))).toEqual([]);
  });

  it('traces the network the file declares, over the injected fetch', async () => {
    const graph = await graphForDocument(
      document(),
      (async () => {
        throw new TypeError('fetch failed');
      }) as unknown as typeof fetch,
      {
        readWasm: async () => wasmWithImports([...HOST, ...importsFrom(ORACLE, ['price'])]),
        presence: async (contractId) => (contractId === ORACLE ? 'absent' : 'deployed'),
      },
    );

    expect(graph?.rpcUrl).toBe(MAINNET_RPC);
    expect(graph?.nodes.map((node) => node.id)).toEqual([WRAPPER, ORACLE]);
    expect(dependencyDiagnostics(graph as DependencyGraph)).toMatchObject([
      { rule: UNRESOLVED, path: 'CURRENCIES[0].contract' },
    ]);
  });

  it('asks the Soroban RPC about each contract it discovers', async () => {
    const keys: string[] = [];
    const fetchImpl = (async (_input: string | URL | Request, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as { params: { keys: string[] } };
      const key = body.params.keys[0] as string;
      keys.push(key);
      return new Response(
        JSON.stringify({
          result: { latestLedger: 100, entries: [{ liveUntilLedgerSeq: 500_000 }] },
        }),
        { status: 200 },
      );
    }) as unknown as typeof fetch;

    const diagnostics = await checkContractDependencies(document(), fetchImpl, {
      readWasm: async (contractId) =>
        wasmWithImports(contractId === WRAPPER ? importsFrom(ORACLE, ['price']) : HOST),
    });

    // Both the declared contract and the dependency it names are probed, and
    // since both answer live nothing is reported.
    expect(keys).toEqual([contractDataInstanceKey(WRAPPER), contractDataInstanceKey(ORACLE)]);
    expect(diagnostics).toEqual([]);
  });

  it('reports a dependency the RPC says is not there', async () => {
    const fetchImpl = (async (_input: string | URL | Request, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as { params: { keys: string[] } };
      const live = body.params.keys[0] === contractDataInstanceKey(WRAPPER);
      return new Response(
        JSON.stringify({
          result: {
            latestLedger: 100,
            entries: live ? [{ liveUntilLedgerSeq: 500_000 }] : [],
          },
        }),
        { status: 200 },
      );
    }) as unknown as typeof fetch;

    const diagnostics = await checkContractDependencies(document(), fetchImpl, {
      readWasm: async () => wasmWithImports(importsFrom(ORACLE, ['price'])),
    });

    expect(diagnostics).toMatchObject([
      {
        rule: UNRESOLVED,
        severity: 'error',
        path: 'CURRENCIES[0].contract',
        message: `Contract ${WRAPPER} imports ${ORACLE}, which has no instance on mainnet`,
      },
    ]);
  });
});

describe('rule registration', () => {
  it('registers both rules so --list-rules and --off know them', () => {
    const ids = allRules.map((rule) => rule.id);
    expect(ids).toContain(UNRESOLVED);
    expect(ids).toContain(CIRCULAR);
  });
});
