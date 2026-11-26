/**
 * The pluggable semantic rule engine.
 *
 * `src/rules/` is the built-in catalog: a fixed list, run sequentially against
 * the parsed document. That works while the catalog is ours to edit, but a
 * hundred checks deep, the people who need a new one are usually the least
 * willing to patch `src/rules/index.ts`. This engine is the other half: a rule
 * subscribes to node entry and exit hooks, and the loader hands it to `lint()`
 * beside the built-ins.
 *
 * Three properties are worth stating up front, because they are why this is an
 * engine rather than one more call to `rule.run(ctx)`:
 *
 * - **One traversal, every rule.** The document is walked once and each node is
 *   offered to every visitor that asked for its kind, so the hundred-and-first
 *   rule costs a function call per node instead of another walk.
 * - **A plugin cannot end the run.** `create` and every hook are called inside a
 *   guard, so a rule that throws — on one node or on all of them — loses its own
 *   findings and nothing else. Failures collapse into one `internal/plugin-error`
 *   warning per rule rather than one per node, so a buggy plugin stays visible
 *   without burying the file.
 * - **Severity is the user's, not the plugin's.** `--off`, `--error`, `--warn`
 *   and `.stellartomlrc.json` resolve a plugin's severity exactly as they resolve
 *   a built-in's, which is what makes a third-party rule operable.
 */
import type {
  Diagnostic,
  LintOptions,
  Position,
  RuleCategory,
  RuleOverrides,
  Severity,
} from '../types.js';

/** The node shapes the visitor reports. */
export type AstNodeKind = 'document' | 'table' | 'array-table' | 'currency' | 'key-value';

/** Fields shared by every node. */
export interface AstNodeBase {
  kind: AstNodeKind;
  /**
   * Dotted path in the notation `Diagnostic.path` uses: `VERSION`,
   * `DOCUMENTATION.ORG_URL`, `CURRENCIES[1].issuer`.
   */
  path: string;
  /** The last segment of {@link AstNodeBase.path}; empty for the document. */
  name: string;
  /** Where the node starts, when the run had a file to locate it in. */
  position?: Position;
}

/** The root of the document. */
export interface AstDocumentNode extends AstNodeBase {
  kind: 'document';
  path: '';
  name: '';
  /** Every top-level value in the file. */
  values: Readonly<Record<string, unknown>>;
}

/**
 * A table: a `[DOCUMENTATION]` section, one entry of a `[[VALIDATORS]]` array,
 * or an inline `{ ... }` table used as a value.
 */
export interface AstTableNode extends AstNodeBase {
  kind: 'table' | 'array-table';
  /** Position within a repeated `[[NAME]]`; absent for a plain `[NAME]`. */
  index?: number;
  /** The table's own fields, exactly as the TOML parsed them. */
  values: Readonly<Record<string, unknown>>;
}

/**
 * One `[[CURRENCIES]]` entry.
 *
 * Currencies are what third-party rules are usually about — an asset's code, its
 * issuer, whether it is regulated — so this node carries the identity fields read
 * off the table. Its `path`, `index` and `values` are the object `visitTable` was
 * handed too: a currency *is* an array-table entry, and a rule written against
 * tables already sees it. `kind` says `currency` so a rule sorting assets never
 * has to match on the key name.
 */
export interface AstCurrencyNode extends AstNodeBase {
  kind: 'currency';
  index: number;
  values: Readonly<Record<string, unknown>>;
  code?: string;
  issuer?: string;
  contract?: string;
  status?: string;
}

/** A key whose value is not a table: a string, a number, a date, or a list. */
export interface AstKeyValueNode extends AstNodeBase {
  kind: 'key-value';
  /** Path of the table this key sits under; `''` for the top level. */
  parent: string;
  value: unknown;
}

/** Any node a visitor can be handed. */
export type AstNode = AstDocumentNode | AstTableNode | AstCurrencyNode | AstKeyValueNode;

/** A node that holds fields, which is everything except the leaves. */
export type AstContainerNode = AstDocumentNode | AstTableNode | AstCurrencyNode;

/** A table-shaped node, which `visitTable` is given for a currency as well. */
export type AstAnyTableNode = AstTableNode | AstCurrencyNode;

/**
 * The hooks one rule wants. Every member is optional: a rule that only cares
 * about assets implements `visitCurrency` and is never called for anything else.
 *
 * `visitX` fires before the node's children and `leaveX` after them, so a rule
 * can accumulate over a table's keys and summarise on the way out. The node
 * given to `visitX` and `leaveX` is the same object.
 */
export interface AstVisitor {
  visitDocument?(node: AstDocumentNode): void;
  visitTable?(node: AstAnyTableNode): void;
  visitCurrency?(node: AstCurrencyNode): void;
  visitKeyValue?(node: AstKeyValueNode): void;
  leaveDocument?(node: AstDocumentNode): void;
  leaveTable?(node: AstAnyTableNode): void;
  leaveCurrency?(node: AstCurrencyNode): void;
  leaveKeyValue?(node: AstKeyValueNode): void;
}

/**
 * A finding as a plugin reports it.
 *
 * `rule` and `category` are absent on purpose: both come from the rule's own
 * metadata, so a plugin cannot mislabel a finding and the engine can attribute it
 * to the right severity override.
 */
export type PluginReport = Omit<Diagnostic, 'rule' | 'category' | 'severity'> & {
  severity?: Severity;
};

/** What {@link SemanticRule.create} is given to build a visitor with. */
export interface PluginContext {
  /** The parsed document, the same object the built-in rules see. */
  doc: Readonly<Record<string, unknown>>;
  /** The source `doc` was parsed from, for rules that care about bytes. */
  source: string;
  /** The options this run was called with, e.g. `domain` and `checkNetwork`. */
  options: LintOptions;
  /** The root node, for a rule that wants the whole document at once. */
  ast: AstDocumentNode;
  /** Resolve a dotted path to a line and column, when the file has one. */
  locate(path: string): Position | undefined;
  /** Record one finding against this rule. */
  report(finding: PluginReport): void;
}

/**
 * A pluggable check.
 *
 * `create` runs once per lint call, so a visitor may keep state across the nodes
 * of one run without leaking it into the next.
 */
export interface SemanticRule {
  /** `<namespace>/<name>`, e.g. `acme/regulated-needs-attestation`. */
  id: string;
  category: RuleCategory;
  /** Severity used unless the user overrides it. */
  severity: Severity;
  /** One line, in the voice `--list-rules` uses. */
  description: string;
  create(ctx: PluginContext): AstVisitor;
}

/**
 * The categories a diagnostic may carry. A plugin picks one of these so the
 * reporters group its findings with the built-ins instead of beside them.
 *
 * `as const` keeps the members in the type, which is what lets a test ask the
 * compiler whether `types.ts` has grown a category this list does not have; a
 * plain annotation would widen it to the full union and answer yes by definition.
 */
export const KNOWN_CATEGORIES = [
  'file',
  'general',
  'documentation',
  'principals',
  'currencies',
  'validators',
  'network',
  'security',
  'policy',
  'sep12',
  'gitops',
] as const satisfies readonly RuleCategory[];

const SEVERITIES: readonly string[] = ['error', 'warning', 'info'];

/** `general/kebab-case`, matching the ids the built-in catalog uses. */
const RULE_ID = /^[a-z][a-z0-9-]*\/[a-z][a-z0-9-]*$/;

/** One rule's visitor, resolved against the severity its findings take. */
interface ActiveRule {
  rule: SemanticRule;
  visitor: AstVisitor;
}

/**
 * One hook the walk will call, plus the rule that owns it.
 *
 * The visitor is carried alongside because `hook.call(visitor, node)` keeps the
 * contract that `this` inside a hook is the visitor, the same as any object
 * method.
 */
interface Listener<N extends AstNode> {
  entry: ActiveRule;
  hook: (node: N) => void;
}

/**
 * The rules to call for each node kind, in the order they were registered.
 *
 * Built once per run so a node costs one array walk rather than a test against
 * every registered rule: a document with 1,000 keys and a policy of 120 rules
 * that each listen for one kind dispatches 120,000 hooks, not 240,000 switch
 * arms. A rule with no hook for a kind is not in that kind's list at all.
 */
interface Dispatch {
  documentEnter: Listener<AstDocumentNode>[];
  documentLeave: Listener<AstDocumentNode>[];
  tableEnter: Listener<AstAnyTableNode>[];
  tableLeave: Listener<AstAnyTableNode>[];
  currencyEnter: Listener<AstCurrencyNode>[];
  currencyLeave: Listener<AstCurrencyNode>[];
  keyValueEnter: Listener<AstKeyValueNode>[];
  keyValueLeave: Listener<AstKeyValueNode>[];
}

/** A rule that threw, and how often. */
interface RuleFailure {
  ruleId: string;
  /** Message from the first throw, which is usually the only kind there is. */
  message: string;
  /** Nodes the rule failed on, so one bad rule does not print a wall. */
  count: number;
}

/** Everything one traversal needs, gathered once per run. */
interface WalkState {
  dispatch: Dispatch;
  failures: Map<string, RuleFailure>;
  locate?: (path: string) => Position | undefined;
  /**
   * Containers on the current path. Parsed TOML cannot repeat one — but the
   * engine is public API, and a caller-built document with a shared or cyclic
   * table would otherwise recurse until the stack gave out.
   */
  open: Set<object>;
}

export interface EngineInput {
  /** The parsed document to walk. */
  doc: Record<string, unknown>;
  /** The source `doc` came from. */
  source: string;
  /** Per-rule severity overrides — the same map `lint()` takes. */
  rules?: RuleOverrides;
  /** The run's options, handed to each plugin unchanged. */
  options?: LintOptions;
  /** Resolves a node path to a position; `SourceIndex.get` fits. */
  locate?: (path: string) => Position | undefined;
}

/**
 * Runs {@link SemanticRule}s over a parsed document in a single traversal.
 *
 * ```ts
 * const engine = new SemanticRuleEngine([myRule]);
 * const diagnostics = engine.run({ doc, source });
 * ```
 */
export class SemanticRuleEngine {
  private readonly rules: SemanticRule[] = [];

  constructor(rules: Iterable<SemanticRule> = []) {
    for (const rule of rules) this.addRule(rule);
  }

  /** Registers a rule. Throws {@link PluginRuleError} on a bad shape or a duplicate id. */
  addRule(rule: SemanticRule): this {
    const checked = assertSemanticRule(rule, `rule ${idOf(rule)}`);
    if (this.rules.some((existing) => existing.id === checked.id)) {
      throw new PluginRuleError(`rule ${checked.id}`, ['another rule already uses this id']);
    }
    this.rules.push(checked);
    return this;
  }

  /** Registered rule ids, in the order their hooks are called. */
  get ruleIds(): string[] {
    return this.rules.map((rule) => rule.id);
  }

  get size(): number {
    return this.rules.length;
  }

  /**
   * Walks `input.doc` once and returns what the rules reported, plus one warning
   * per rule that threw. The caller merges these into its own findings; the
   * ordering is left to `finalize`.
   */
  run(input: EngineInput): Diagnostic[] {
    const overrides = input.rules ?? {};
    const diagnostics: Diagnostic[] = [];
    const failures = new Map<string, RuleFailure>();
    const ast: AstDocumentNode = {
      kind: 'document',
      path: '',
      name: '',
      values: input.doc,
      position: input.locate?.(''),
    };
    const active: ActiveRule[] = [];

    for (const rule of this.rules) {
      // The user's choice beats the plugin's, on every finding: that is what makes
      // a third-party rule operable with the same flags as a built-in.
      const override = overrides[rule.id];
      if (override === 'off') continue;

      const ctx: PluginContext = {
        doc: input.doc,
        source: input.source,
        options: input.options ?? {},
        ast,
        locate: (path: string): Position | undefined => input.locate?.(path),
        report: (finding: PluginReport): void => {
          if (typeof finding.message !== 'string' || finding.message === '') {
            throw new TypeError('report() needs a non-empty message');
          }
          diagnostics.push({
            ...finding,
            rule: rule.id,
            category: rule.category,
            severity: override ?? finding.severity ?? rule.severity,
          });
        },
      };

      let visitor: unknown;
      try {
        visitor = rule.create(ctx);
      } catch (error) {
        record(failures, rule.id, error);
        continue;
      }
      if (typeof visitor !== 'object' || visitor === null) {
        record(failures, rule.id, new TypeError('create() must return a visitor object'));
        continue;
      }
      active.push({ rule, visitor });
    }

    walk({ dispatch: dispatchFor(active), failures, locate: input.locate, open: new Set() }, ast);
    return [...diagnostics, ...failureDiagnostics(failures)];
  }
}

/**
 * Offers `node` to every rule listening for its kind, descends into its fields,
 * and offers it to them again on the way out.
 *
 * The rule loop sits *inside* the node visit rather than around the walk: that is
 * what makes the traversal shared. Bracketing still holds for every rule,
 * because its `visitX` runs before the descent and its `leaveX` after, and one
 * rule's hooks never interleave with another's node handling in a way a visitor
 * can observe — each rule sees its own enter, its children, its exit.
 */
function walk(state: WalkState, node: AstNode): void {
  // Narrowed once, here, so the descent below can hand `childrenOf` a container
  // without restating the kind test.
  const container = isContainerNode(node) ? node : undefined;

  if (container !== undefined) {
    if (state.open.has(container.values)) return;
    state.open.add(container.values);
  }

  enter(state, node);

  if (container !== undefined) {
    for (const [name, value] of Object.entries(container.values)) {
      for (const child of childrenOf(container, name, value, state.locate)) walk(state, child);
    }
  }

  leave(state, node);

  if (container !== undefined) state.open.delete(container.values);
}

function enter(state: WalkState, node: AstNode): void {
  const d = state.dispatch;
  switch (node.kind) {
    case 'document':
      fire(d.documentEnter, node, state.failures);
      break;
    case 'table':
    case 'array-table':
      fire(d.tableEnter, node, state.failures);
      break;
    case 'currency':
      fire(d.currencyEnter, node, state.failures);
      break;
    case 'key-value':
      fire(d.keyValueEnter, node, state.failures);
      break;
  }
}

function leave(state: WalkState, node: AstNode): void {
  const d = state.dispatch;
  switch (node.kind) {
    case 'document':
      fire(d.documentLeave, node, state.failures);
      break;
    case 'table':
    case 'array-table':
      fire(d.tableLeave, node, state.failures);
      break;
    case 'currency':
      fire(d.currencyLeave, node, state.failures);
      break;
    case 'key-value':
      fire(d.keyValueLeave, node, state.failures);
      break;
  }
}

/** True for a node that holds fields, which is everything except a leaf. */
function isContainerNode(node: AstNode): node is AstContainerNode {
  return node.kind !== 'key-value';
}

/** Every node that `name = value` contributes under `parent`. */
function childrenOf(
  parent: AstContainerNode,
  name: string,
  value: unknown,
  locate: WalkState['locate'],
): AstNode[] {
  const path = joinPath(parent.path, name);
  if (Array.isArray(value)) {
    const tables = value.filter(isPlainObject);
    // A list of tables — `[[VALIDATORS]]`, and the inline form wallets also
    // write — is one node per entry. A list of strings is a value, so it stays
    // a single key a rule can inspect whole.
    if (value.length > 0 && tables.length === value.length) {
      return tables.map((item, index) =>
        isCurrencyKey(parent, name)
          ? currencyNode(`${path}[${index}]`, name, index, item, locate)
          : tableNode(`${path}[${index}]`, name, index, item, locate),
      );
    }
    return [keyValueNode(parent.path, path, name, value, locate)];
  }
  if (isPlainObject(value)) return [tableNode(path, name, undefined, value, locate)];
  return [keyValueNode(parent.path, path, name, value, locate)];
}

/** `CURRENCIES` is a currency list only at the top level, which is where SEP-1 puts it. */
function isCurrencyKey(parent: AstContainerNode, name: string): boolean {
  return parent.path === '' && name === 'CURRENCIES';
}

function joinPath(parent: string, name: string): string {
  return parent === '' ? name : `${parent}.${name}`;
}

function tableNode(
  path: string,
  name: string,
  index: number | undefined,
  values: Record<string, unknown>,
  locate: WalkState['locate'],
): AstTableNode {
  return {
    kind: index === undefined ? 'table' : 'array-table',
    path,
    name,
    ...(index === undefined ? {} : { index }),
    values,
    ...positionField(path, locate),
  };
}

function currencyNode(
  path: string,
  name: string,
  index: number,
  values: Record<string, unknown>,
  locate: WalkState['locate'],
): AstCurrencyNode {
  return {
    kind: 'currency',
    path,
    name,
    index,
    values,
    ...positionField(path, locate),
    code: text(values.code),
    issuer: text(values.issuer),
    contract: text(values.contract),
    status: text(values.status),
  };
}

function keyValueNode(
  parent: string,
  path: string,
  name: string,
  value: unknown,
  locate: WalkState['locate'],
): AstKeyValueNode {
  return {
    kind: 'key-value',
    path,
    name,
    parent,
    value,
    ...positionField(path, locate),
  };
}

/**
 * A node's position, when the run has a file to locate it in.
 *
 * `SourceIndex` records every table header, array entry and key it can see, so
 * most nodes answer on their exact path and an inline table's contents fall back
 * to the key that holds them. Spreading keeps `exactOptionalPropertyTypes`
 * honest about the difference between "on line 12" and "we do not know".
 */
function positionField(path: string, locate: WalkState['locate']): { position?: Position } {
  const position = locate?.(path);
  return position === undefined ? {} : { position };
}

/**
 * Buckets every registered hook by the node kind it is called for.
 *
 * The currency lists also carry a rule's table hook, before its currency hook,
 * because a currency is an array-table entry: a rule written against tables has
 * to be offered it, and it has to be offered on the way in first and the way out
 * last, so a rule that brackets on either kind still sees a balanced pair. Both
 * hooks stay in one list, which keeps the rules in registration order across
 * kinds in a way two separate lists would not.
 */
function dispatchFor(active: readonly ActiveRule[]): Dispatch {
  const d: Dispatch = {
    documentEnter: [],
    documentLeave: [],
    tableEnter: [],
    tableLeave: [],
    currencyEnter: [],
    currencyLeave: [],
    keyValueEnter: [],
    keyValueLeave: [],
  };
  for (const entry of active) {
    const visitor = entry.visitor;
    push(d.documentEnter, entry, visitor.visitDocument);
    push(d.tableEnter, entry, visitor.visitTable);
    push(d.currencyEnter, entry, visitor.visitTable);
    push(d.currencyEnter, entry, visitor.visitCurrency);
    push(d.keyValueEnter, entry, visitor.visitKeyValue);
    push(d.documentLeave, entry, visitor.leaveDocument);
    push(d.currencyLeave, entry, visitor.leaveCurrency);
    push(d.currencyLeave, entry, visitor.leaveTable);
    push(d.tableLeave, entry, visitor.leaveTable);
    push(d.keyValueLeave, entry, visitor.leaveKeyValue);
  }
  return d;
}

function push<N extends AstNode>(
  listeners: Listener<N>[],
  entry: ActiveRule,
  hook: ((node: N) => void) | undefined,
): void {
  if (hook !== undefined) listeners.push({ entry, hook });
}

/**
 * Offers `node` to every rule that asked for its kind.
 *
 * A hook is only ever read out of the list built for the node it was declared
 * for, which is what proves `visitCurrency` is never handed a table; the type
 * parameter states that per list, since one shared `AstNode` parameter would let
 * any hook be handed any node.
 */
function fire<N extends AstNode>(
  listeners: readonly Listener<N>[],
  node: N,
  failures: Map<string, RuleFailure>,
): void {
  for (let index = 0; index < listeners.length; index++) {
    const listener = listeners[index]!;
    try {
      listener.hook.call(listener.entry.visitor, node);
    } catch (error) {
      record(failures, listener.entry.rule.id, error);
    }
  }
}

function record(failures: Map<string, RuleFailure>, ruleId: string, error: unknown): void {
  const existing = failures.get(ruleId);
  const message = error instanceof Error ? error.message : String(error);
  if (existing === undefined) failures.set(ruleId, { ruleId, message, count: 1 });
  else existing.count += 1;
}

function failureDiagnostics(failures: Map<string, RuleFailure>): Diagnostic[] {
  return [...failures.values()].map((failure) => ({
    rule: 'internal/plugin-error',
    severity: 'warning' as const,
    category: 'file' as const,
    message:
      `Plugin rule ${failure.ruleId} failed on ${failure.count} ` +
      `${failure.count === 1 ? 'node' : 'nodes'}: ${failure.message}`,
    helpUri: 'https://github.com/anchor-tools/stellar-toml-lint/issues',
    suggestion: 'Report this to the plugin author; the rest of the run is unaffected.',
  }));
}

function text(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

function idOf(candidate: unknown): string {
  if (typeof candidate === 'object' && candidate !== null && 'id' in candidate) {
    return String(candidate.id);
  }
  return String(candidate);
}

/**
 * A candidate rule as data, checked field by field.
 *
 * None of it is fussiness: a plugin that loads with a missing `category`
 * produces a diagnostic the SARIF and JUnit reporters cannot group, which is a
 * worse failure than refusing the rule at the door and saying why.
 */
export function ruleProblems(candidate: unknown): string[] {
  if (typeof candidate !== 'object' || candidate === null) {
    return ['a rule must be an object with id, category, severity, description and create'];
  }
  const rule = candidate as Readonly<Record<string, unknown>>;
  const problems: string[] = [];

  const id = rule.id;
  if (typeof id !== 'string') problems.push('`id` must be a string');
  else if (!RULE_ID.test(id)) {
    problems.push(`\`id\` must be "<namespace>/<name>" in lower kebab-case, got "${id}"`);
  }

  if (
    typeof rule.category !== 'string' ||
    !KNOWN_CATEGORIES.some((known) => known === rule.category)
  ) {
    problems.push(`\`category\` must be one of ${KNOWN_CATEGORIES.join(', ')}`);
  }

  if (typeof rule.severity !== 'string' || !SEVERITIES.includes(rule.severity)) {
    problems.push(`\`severity\` must be one of ${SEVERITIES.join(', ')}`);
  }

  if (typeof rule.description !== 'string' || rule.description.trim() === '') {
    problems.push('`description` must be a non-empty string');
  }

  if (typeof rule.create !== 'function') problems.push('`create` must be a function');

  return problems;
}

/** Thrown when a plugin rule is refused, naming where it came from. */
export class PluginRuleError extends Error {
  readonly origin: string;
  readonly problems: readonly string[];

  constructor(origin: string, problems: readonly string[]) {
    super(`${origin} is not a usable rule: ${problems.join('; ')}`);
    this.name = 'PluginRuleError';
    this.origin = origin;
    this.problems = problems;
  }
}

/** Narrows one unknown export to a {@link SemanticRule}, or throws. */
export function assertSemanticRule(candidate: unknown, origin: string): SemanticRule {
  const problems = ruleProblems(candidate);
  if (problems.length > 0) throw new PluginRuleError(origin, problems);
  return candidate as SemanticRule;
}

/** True for the node `visitCurrency` is given. */
export function isCurrencyNode(node: AstNode): node is AstCurrencyNode {
  return node.kind === 'currency';
}

/**
 * A TOML table's parsed shape: an object that is neither a list nor a date.
 *
 * `smol-toml` returns a `Date` subclass for every date-time and `typeof` calls
 * that an object — walking one as a table would offer a rule zero keys and report
 * a silent pass on the very field the plugin was written to check.
 */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === 'object' && value !== null && !Array.isArray(value) && !(value instanceof Date)
  );
}
