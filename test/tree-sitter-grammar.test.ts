/**
 * Grammar invariants that hold without the tree-sitter CLI (#539).
 *
 * `scripts/build-tree-sitter-grammar.mjs` runs `generate`, the corpus tests,
 * and an optional WASM build, but it exits 0 when no CLI is installed — which
 * is the state CI and a fresh clone are in, because `tree-sitter-cli` is
 * deliberately *not* a dependency (its postinstall downloads a native binary,
 * and the repo's Malware and supply-chain job rejects that). So the questions
 * this file answers are the ones that can be answered from the checked-in
 * artefacts alone:
 *
 *   - Is `src/parser.c` still the parser that `grammar.js` describes? A stale
 *     generated file is the failure mode of a source-shipped grammar: the
 *     grammar looks fine in review and does something else at run time.
 *   - Do the five SEP-1 primitives actually exist as *named nodes*, which is
 *     what `queries/tags.scm` and every consumer of `node-types.json` binds to?
 *   - Do the queries only mention nodes the grammar can emit? An unknown node
 *     type in a `.scm` is a silent no-op in Neovim and a hard error in Helix.
 *   - Is the WASM binding's entry point the symbol the generated parser
 *     actually defines, and does the scanner allocate anything it must free?
 *
 * `grammar.js` is loaded through `require` with the tree-sitter DSL placed on
 * `globalThis`: the file is CommonJS and its nearest `package.json` declares no
 * `type`, so Node loads it as a plain module — but `grammar()`, `seq()` and the
 * rest exist only inside the CLI, so the test supplies shims that record the
 * rule graph instead of compiling a parser. The shape of that graph is the
 * thing under test, not its behaviour.
 */
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { StrKey, Keypair } from '@stellar/stellar-base';
import { describe, expect, it } from 'vitest';

import { isAccountId, isContractId, isMuxedAccountId } from '../src/predicates.js';

const here = dirname(fileURLToPath(import.meta.url));
const grammarDir = join(here, '..', 'grammars', 'tree-sitter-stellar-toml');
const repoRoot = join(here, '..');
const requireGrammarFile = createRequire(import.meta.url);

function read(...parts: string[]): string {
  return readFileSync(join(grammarDir, ...parts), 'utf8');
}

// ---------------------------------------------------------------------------
// the DSL shim
// ---------------------------------------------------------------------------

/** Every DSL call becomes the same shape, so the walkers below stay small. */
interface DslCall {
  readonly kind: string;
  readonly args: readonly unknown[];
}

interface DslRef {
  readonly $ref: string;
}

function isCall(value: unknown): value is DslCall {
  return (
    typeof value === 'object' &&
    value !== null &&
    'kind' in value &&
    'args' in value &&
    typeof (value as DslCall).kind === 'string'
  );
}

function isRef(value: unknown): value is DslRef {
  return typeof value === 'object' && value !== null && '$ref' in value;
}

function call(kind: string) {
  return (...args: unknown[]): DslCall => ({ kind, args });
}

interface GrammarDefinition {
  readonly name: string;
  readonly externals: (dollar: unknown) => unknown[];
  readonly extras: (dollar: unknown) => unknown[];
  readonly rules: Record<string, (dollar: unknown) => unknown>;
}

/** The rule graph, with every rule body already expanded. */
interface LoadedGrammar {
  readonly definition: GrammarDefinition;
  readonly bodies: Readonly<Record<string, unknown>>;
  readonly externalsBody: unknown;
}

/** `$` hands back a marker for any rule it is asked for, named or not. */
const dollar: Record<string, DslRef> = new Proxy(
  {},
  { get: (_target, property) => ({ $ref: String(property) }) },
);

function loadGrammar(): LoadedGrammar {
  let captured: GrammarDefinition | undefined;
  const globals = globalThis as Record<string, unknown>;
  const token = Object.assign(call('token'), { immediate: call('immediate') });
  const prec = Object.assign(call('prec'), { left: call('prec'), right: call('prec') });
  const previous = new Map<string, unknown>();
  const dsl: Record<string, unknown> = {
    grammar: (definition: GrammarDefinition) => {
      captured = definition;
      return definition;
    },
    seq: call('seq'),
    choice: call('choice'),
    token,
    prec,
    repeat: call('repeat'),
    optional: call('optional'),
    alias: call('alias'),
    field: call('field'),
  };

  for (const [name, value] of Object.entries(dsl)) {
    previous.set(name, globals[name]);
    globals[name] = value;
  }

  let loaded: LoadedGrammar | undefined;
  try {
    // `grammar.js` is CommonJS and its own `package.json` declares no `type`,
    // so Node loads it untransformed; it is required once, so the module cache
    // never has to be cleared.
    requireGrammarFile(join(grammarDir, 'grammar.js'));
    if (captured !== undefined) {
      // The rule bodies are functions of `$`, and the shims only exist while
      // the module is loading — so expand them here rather than on demand.
      const bodies: Record<string, unknown> = {};
      for (const [name, rule] of Object.entries(captured.rules)) {
        bodies[name] = rule(dollar);
      }
      loaded = {
        definition: captured,
        bodies,
        externalsBody: captured.externals(dollar),
      };
    }
  } finally {
    for (const [name, value] of previous) {
      if (value === undefined) delete globals[name];
      else globals[name] = value;
    }
  }

  if (loaded === undefined) {
    throw new Error('grammar.js did not call grammar() — the shim is out of date');
  }
  return loaded;
}

/** Rule names reachable from a rule body, e.g. `string` inside `_inline_value`. */
function collectRefs(value: unknown, into = new Set<string>()): Set<string> {
  if (isRef(value)) {
    into.add(value.$ref);
    return into;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectRefs(item, into);
    return into;
  }
  if (isCall(value)) {
    for (const arg of value.args) collectRefs(arg, into);
  }
  return into;
}

/**
 * The regular expression a token rule accepts, as a source string.
 *
 * Only the leaves that can appear in a *token* are handled; a rule that
 * references another rule throws, because then the question is about the
 * grammar's structure and not about one token's shape.
 */
function shapeOf(value: unknown): string {
  if (value instanceof RegExp) return value.source;
  if (typeof value === 'string') return value.replace(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`);
  if (!isCall(value)) throw new Error(`cannot build a shape from ${String(value)}`);

  const last = value.args[value.args.length - 1];
  switch (value.kind) {
    case 'seq':
      return value.args.map(shapeOf).join('');
    case 'choice':
      return `(?:${value.args.map(shapeOf).join('|')})`;
    case 'optional':
      return `(?:${shapeOf(last)})?`;
    case 'repeat':
      return `(?:${shapeOf(last)})*`;
    // `token`, `prec`, `field`, `alias`, `immediate`: wrappers with no effect
    // on the language the inner node accepts.
    default:
      return shapeOf(last);
  }
}

// ---------------------------------------------------------------------------
// corpus
// ---------------------------------------------------------------------------

/** One `=====`-delimited case: its title, its source, and its expected tree. */
interface CorpusCase {
  file: string;
  title: string;
  source: string;
  tree: string;
}

function parseCorpus(file: string): CorpusCase[] {
  const text = read('test', 'corpus', file);
  const cases: CorpusCase[] = [];
  // Splitting on the fenced lines leaves alternating title and body chunks:
  // a case is a title, its source, then optionally `---` and the expected tree.
  // `\r?` in both splitters because a runner whose git checks text files out as
  // CRLF still has to find the fences — the corpus is LF in the repo, and a
  // split that silently returned nothing would report an empty grammar.
  const chunks = text.split(/^={10,}[ \t]*\r?\n/gm);
  for (let i = 1; i + 1 < chunks.length; i += 2) {
    const body = (chunks[i + 1] ?? '').split(/^---[ \t]*\r?\n/gm);
    cases.push({
      file,
      title: (chunks[i] ?? '').trim(),
      source: body[0] ?? '',
      tree: body[1] ?? '',
    });
  }
  return cases;
}

function allCorpusCases(): CorpusCase[] {
  return [
    'anchor.txt',
    'compliant-anchor.txt',
    'contracts.txt',
    'near-misses.txt',
    'production-anchor.txt',
    'values.txt',
  ].flatMap(parseCorpus);
}

// ---------------------------------------------------------------------------

const grammar = loadGrammar();
const grammarJson = JSON.parse(read('src', 'grammar.json')) as {
  name: string;
  externals: { name: string }[];
  rules: Record<string, unknown>;
};
const nodeTypes = JSON.parse(read('src', 'node-types.json')) as {
  type: string;
  named: boolean;
  fields?: Record<string, { types: { type: string }[] }>;
}[];
const parserC = read('src', 'parser.c');
const scannerC = read('src', 'scanner.c');
const bindingC = read('bindings', 'wasm', 'binding.c');

/** The five names #539 asks the grammar to define. */
const SEP1_NODES = ['public_key', 'asset_code', 'contract_id', 'sep_table', 'currency_entry'];

/** A token rule as a whole-string matcher, e.g. `"G[A-Z2-7]{55}"`. */
function tokenMatcher(name: string): RegExp {
  return new RegExp(`^${shapeOf(grammar.bodies[name])}$`);
}

describe('tree-sitter grammar: generated artifacts are current', () => {
  it('names the grammar the way the generated parser does', () => {
    expect(grammarJson.name).toBe(grammar.definition.name);
    expect(grammar.definition.name).toBe('stellar_toml');
  });

  it('has a generated rule for every rule grammar.js defines, and no extra', () => {
    // The realistic staleness: someone edits `grammar.js`, the review passes,
    // and `parser.c` still describes the old grammar. Adding, renaming or
    // dropping a rule moves both of these lists, so the pair catches it; a
    // change *inside* a rule body does not, which is what
    // `scripts/build-tree-sitter-grammar.mjs` is for.
    expect(Object.keys(grammarJson.rules).sort()).toEqual(Object.keys(grammar.bodies).sort());
  });

  it('declares the same external tokens the parser was generated with', () => {
    expect(grammarJson.externals.map((entry) => entry.name).sort()).toEqual(
      [...collectRefs(grammar.externalsBody)].sort(),
    );
  });

  it('emits the SEP-1 nodes in the compiled parser, not only in the JSON', () => {
    const symbols = parserC.match(
      /static const char \* const ts_symbol_names\[\] = \{([\s\S]*?)\};/,
    );
    expect(symbols).not.toBeNull();
    for (const node of SEP1_NODES) {
      expect(symbols?.[1]).toContain(`"${node}"`);
    }
  });
});

describe('tree-sitter grammar: the five SEP-1 primitives are nodes', () => {
  it('lists every one as a named node type', () => {
    const named = nodeTypes.filter((entry) => entry.named).map((entry) => entry.type);
    for (const node of SEP1_NODES) {
      expect(named).toContain(node);
    }
  });

  it('offers sep_table and currency_entry as a header name', () => {
    // A query says `(table name: (sep_table))`; that only parses if `name` is
    // a field of `table` that can actually hold the node.
    const fieldTypes = (type: string, field: string): string[] =>
      (nodeTypes.find((entry) => entry.type === type)?.fields?.[field]?.types ?? []).map(
        (entry) => entry.type,
      );

    expect(fieldTypes('table', 'name')).toContain('sep_table');
    expect(fieldTypes('array_table', 'name')).toContain('currency_entry');
    // Vendor tables are still tables, so the plain key must stay an option.
    expect(fieldTypes('table', 'name')).toContain('bare_key');
    expect(fieldTypes('array_table', 'name')).toContain('bare_key');
  });

  it('accepts a checksum-valid account id as public_key', () => {
    const publicShape = tokenMatcher('public_key');
    const account = Keypair.random().publicKey();

    // A key the SDK itself signs with, so the shape below is tested against a
    // real StrKey and not against something typed out by hand.
    expect(isAccountId(account)).toBe(true);
    expect(account).toHaveLength(56);
    expect(publicShape.test(`"${account}"`)).toBe(true);
    expect(publicShape.test(`"${'G'.repeat(56)}"`)).toBe(true);
    expect(publicShape.test(`"${'G'.repeat(55)}"`)).toBe(false);
    expect(publicShape.test(`"${'G'.repeat(57)}"`)).toBe(false);
  });

  it('accepts a muxed address, which is longer rather than differently prefixed', () => {
    const publicShape = tokenMatcher('public_key');
    // A med25519 preimage is the 32-byte key plus an 8-byte id, so the string
    // is 69 characters: longer than an account id, and a different shape.
    const muxed = `"${StrKey.encodeMed25519PublicKey(
      Buffer.concat([Keypair.random().rawPublicKey(), Buffer.alloc(8, 1)]),
    )}"`;

    expect(muxed).toHaveLength(71);
    expect(isMuxedAccountId(muxed.slice(1, -1))).toBe(true);
    expect(publicShape.test(muxed)).toBe(true);
    expect(publicShape.test(`"M${'A'.repeat(55)}"`)).toBe(false);
    expect(publicShape.test(`"M${'A'.repeat(67)}"`)).toBe(false);
  });

  it('splits contract ids from account ids on the version byte', () => {
    const contractShape = tokenMatcher('contract_id');
    const accountShape = tokenMatcher('public_key');
    const contract = StrKey.encodeContract(Buffer.alloc(32, 7));

    expect(isContractId(contract)).toBe(true);
    expect(contractShape.test(`"${contract}"`)).toBe(true);
    expect(accountShape.test(`"${contract}"`)).toBe(false);
    expect(contractShape.test(`"${Keypair.random().publicKey()}"`)).toBe(false);
  });

  it('bounds an asset code at the twelve characters SEP-1 allows', () => {
    const assetShape = tokenMatcher('asset_code');
    for (const code of ['"A"', '"USD"', '"USDC"', '"ABC123"', '"ABCDEFGHIJKL"']) {
      expect(assetShape.test(code)).toBe(true);
    }
    // Too long, or not upper-case alphanumeric: an ordinary string.
    for (const code of ['"ABCDEFGHIJKLM"', '"usdc"', '"US DC"', '"USD-"', '""']) {
      expect(assetShape.test(code)).toBe(false);
    }
  });

  it('recognises a shape it cannot verify, and leaves the checksum to the linter', () => {
    // This is the documented division of labour: the parser is fast and
    // permissive, `src/predicates.ts` is the one that knows CRC16. A typo that
    // stays inside base32 still highlights, and still fails the lint.
    const publicShape = tokenMatcher('public_key');
    const valid = 'GC5MEN6ZAK7IPVMSMKXH2FKKGL6UTKW66V6ORPJNPCULDDIMYALEHB5K';
    const badChecksum = `${valid.slice(0, -1)}L`;
    const outsideAlphabet = `${valid.slice(0, -1)}1`;

    expect(isAccountId(valid)).toBe(true);
    expect(publicShape.test(`"${badChecksum}"`)).toBe(true);
    expect(isAccountId(badChecksum)).toBe(false);
    // RFC 4648 base32 has no 0, 1, 8 or 9, so that class of typo is a *shape*
    // error and the grammar catches it: `near-misses.txt` keeps this value a
    // plain string.
    expect(publicShape.test(`"${outsideAlphabet}"`)).toBe(false);
    expect(isAccountId(outsideAlphabet)).toBe(false);
  });
});

describe('tree-sitter grammar: queries bind to nodes that exist', () => {
  const knownTypes = new Set([
    ...nodeTypes.map((entry) => entry.type),
    // `_line_ending_or_eof` and friends are anonymous; a query never names them.
  ]);

  function stripComments(scm: string): string {
    return scm
      .split('\n')
      .filter((line) => !line.trimStart().startsWith(';'))
      .join('\n');
  }

  /**
   * A query's patterns, minus the two things that look like nodes: comments and
   * the string literals inside a `#match?` predicate — `"^(code|issuer|…)$"`
   * otherwise reads as a node type called `code`.
   */
  function queryBody(scm: string): string {
    return stripComments(scm).replace(/"(?:[^"\\]|\\.)*"/g, '""');
  }

  function queryNodeTypes(scm: string): string[] {
    return [...queryBody(scm).matchAll(/\(\s*([a-z][a-z0-9_]*)/g)].map((match) => match[1] ?? '');
  }

  function queryCaptures(scm: string): Set<string> {
    return new Set(
      [...queryBody(scm).matchAll(/@([a-z][a-z0-9_.]*)/g)].map((match) => match[1] ?? ''),
    );
  }

  it('uses only node types the grammar emits', () => {
    for (const file of ['highlights.scm', 'folds.scm', 'tags.scm']) {
      for (const type of queryNodeTypes(read('queries', file))) {
        expect(knownTypes.has(type), `${file}: ${type}`).toBe(true);
      }
    }
  });

  it('uses only fields the named node actually carries', () => {
    const fieldsByType = new Map(
      nodeTypes.map((entry) => [entry.type, new Set(Object.keys(entry.fields ?? {}))]),
    );
    for (const file of ['highlights.scm', 'folds.scm', 'tags.scm']) {
      const body = queryBody(read('queries', file));
      for (const match of body.matchAll(/\(\s*([a-z][a-z0-9_]*)\s+([a-z][a-z0-9_]*)\s*:/g)) {
        const [type, field] = [match[1] ?? '', match[2] ?? ''];
        expect(fieldsByType.get(type)?.has(field), `${file}: ${type}.${field}`).toBe(true);
      }
    }
  });

  it('declares the capture vocabulary it uses, so editors are not silently deaf', () => {
    // An unknown capture name is dropped without a warning by the highlighter,
    // so the header comment is the contract: whatever is used must be listed.
    for (const file of ['highlights.scm', 'folds.scm', 'tags.scm']) {
      const scm = read('queries', file);
      const declared = new Set(
        (scm.match(/^; Captures: (.*)$/m)?.[1] ?? '')
          .split(/\s+/)
          .filter(Boolean)
          .map((name) => name.replace(/^@/, '')),
      );
      expect([...queryCaptures(scm)].sort()).toEqual([...declared].sort());
    }
  });

  it('only folds and tags what the consumer can act on', () => {
    expect([...queryCaptures(read('queries', 'folds.scm'))]).toEqual(['fold']);
    expect([...queryCaptures(read('queries', 'tags.scm'))].sort()).toEqual([
      'definition',
      'name',
      'reference',
    ]);
  });
});

describe('tree-sitter grammar: the corpus covers the acceptance list', () => {
  const cases = allCorpusCases();

  it('has at least one real-world anchor file, with every SEP-1 endpoint in it', () => {
    const production = cases.filter((entry) => entry.file === 'production-anchor.txt');
    expect(production.length).toBeGreaterThan(0);
    const source = production.map((entry) => entry.source).join('\n');
    for (const key of [
      'FEDERATION_SERVER',
      'AUTH_SERVER',
      'TRANSFER_SERVER',
      'TRANSFER_SERVER_SEP0024',
      'KYC_SERVER',
      'DIRECT_PAYMENT_SERVER',
      'ANCHOR_QUOTE_SERVER',
      'HORIZON_URL',
      'NETWORK_PASSPHRASE',
      'SIGNING_KEY',
    ]) {
      expect(source).toContain(`${key} =`);
    }
  });

  it('exercises every SEP-1 node in a corpus expectation', () => {
    // A node nothing parses is a node nothing maintains: the generated tree is
    // the only place the CLI proves the node can appear.
    const trees = cases.map((entry) => entry.tree).join('\n');
    for (const node of SEP1_NODES) {
      expect(trees).toContain(`(${node})`);
    }
  });

  it('keeps the near-misses out of the SEP-1 nodes', () => {
    const nearMiss = cases.find((entry) => entry.title.startsWith('Values that only look'));
    expect(nearMiss).toBeDefined();
    // `CODE = "GONE"` is a genuine 4-character asset code and is expected;
    // everything shaped like a StrKey must stay an ordinary string.
    expect(nearMiss?.tree).not.toContain('(public_key)');
    expect(nearMiss?.tree).not.toContain('(contract_id)');
    expect(nearMiss?.tree).toContain('(asset_code)');
    expect(nearMiss?.source).toContain('CONTRACT_LOOKALIKE');
  });

  it('uses only checksum-valid StrKeys outside the near-miss file', () => {
    // A hand-typed key passes a parse test and still teaches the editor the
    // wrong thing: the one that shipped in `contracts.txt` was 108 characters
    // of filler, a shape no `M` address has. `near-misses.txt` is exempt
    // because fake shapes are its subject.
    let checked = 0;
    for (const entry of cases.filter((one) => one.file !== 'near-misses.txt')) {
      for (const match of entry.source.matchAll(/(?<![A-Z2-7])[GCM][A-Z2-7]{55,68}(?![A-Z2-7])/g)) {
        const key = match[0] ?? '';
        const valid =
          key.startsWith('M') && key.length === 69
            ? isMuxedAccountId(key)
            : key.startsWith('C')
              ? isContractId(key)
              : isAccountId(key);
        expect(valid, `${entry.file}: ${key}`).toBe(true);
        checked += 1;
      }
    }
    expect(checked).toBeGreaterThan(10);
  });

  it('titles every case it contains', () => {
    expect(cases.length).toBeGreaterThanOrEqual(6);
    for (const entry of cases) {
      expect(entry.title).not.toBe('');
      expect(entry.source).not.toBe('');
    }
  });
});

describe('tree-sitter grammar: the WASM binding is a complete, leak-free pair', () => {
  const entryPoint = `tree_sitter_${grammar.definition.name.replace(/-/g, '_')}`;

  it('exports the entry point the generated parser defines', () => {
    // The JS host reads `exports[<name>]`; a rename in grammar.js that misses
    // binding.c produces a module that instantiates and then has no language.
    expect(entryPoint).toBe('tree_sitter_stellar_toml');
    expect(parserC).toContain(`const TSLanguage *${entryPoint}(void)`);
    expect(bindingC).toContain(`const TSLanguage *${entryPoint}(void);`);
  });

  it('provides all five external-scanner symbols the ABI requires', () => {
    // `destroy` without `create` is harmless; `create` without `destroy` is the
    // leak, and tree-sitter calls both by a fixed name.
    for (const symbol of [
      'external_scanner_create',
      'external_scanner_destroy',
      'external_scanner_serialize',
      'external_scanner_deserialize',
      'external_scanner_scan',
    ]) {
      expect(scannerC).toContain(`tree_sitter_stellar_toml_${symbol}`);
    }
  });

  it('allocates no scanner state, so there is nothing to leak per parse', () => {
    const create = scannerC.match(
      /void \*tree_sitter_stellar_toml_external_scanner_create\(void\)\s*\{([^}]*)\}/,
    );
    expect(create?.[1]).toContain('return NULL');
    // A stateless scanner also has nothing to serialise, which is what keeps
    // incremental reparse of a live editor buffer correct.
    expect(scannerC).toMatch(/external_scanner_serialize\([^)]*\)\s*\{\s*return 0;\s*\}/);
  });

  it('ships the grammar as source: no wasm artefact and no CLI in the lockfile', () => {
    // `tree-sitter-cli`'s postinstall downloads a binary from GitHub, which the
    // Malware and supply-chain job rejects. The grammar dir may declare it as a
    // dev dependency for a human with a toolchain; nothing may *install* it.
    const lockfile = readFileSync(join(repoRoot, 'package-lock.json'), 'utf8');
    expect(lockfile).not.toContain('tree-sitter-cli');
    expect(lockfile).not.toContain('web-tree-sitter');
    expect(read('package.json')).toContain('tree-sitter-cli');
  });
});
