/**
 * CST traversal and conversion helpers.
 *
 * Two jobs live here:
 *
 * 1. A visitor API — {@link walk} — so rules can inspect typed nodes with
 *    their source coordinates instead of hand-rolling offsets.
 * 2. The value evaluator — {@link evaluateDocument} — which turns the tree
 *    into the plain JavaScript object every existing rule already consumes.
 *    Semantic problems (a duplicate key, a table declared twice) become
 *    {@link CstError}s with precise line/column positions.
 */
import { SourcePositions } from './lexer.js';
import { CstParseError } from './parser.js';
import type {
  CstComment,
  CstDocument,
  CstEntry,
  CstError,
  CstInlineTableValue,
  CstKey,
  CstKeySegment,
  CstTrivia,
  CstValue,
} from './parser.js';

/** Every node the visitor can be handed. */
export type CstNode = CstDocument | CstEntry | CstKey | CstKeySegment | CstValue;

/**
 * Callbacks for {@link walk}.
 *
 * `enter` runs before a node's children and may return `false` to prune the
 * branch; `leave` runs after them. The typed hooks are conveniences for the
 * common case of only caring about one node kind.
 */
export interface CstVisitor {
  enter?(node: CstNode): boolean | void;
  leave?(node: CstNode): void;
  document?(node: CstDocument): void;
  entry?(node: CstEntry): void;
  key?(node: CstKey): void;
  keySegment?(node: CstKeySegment): void;
  value?(node: CstValue): void;
}

/** The child nodes of `node`, in source order. */
function childrenOf(node: CstNode): CstNode[] {
  switch (node.kind) {
    case 'document':
      return node.entries;
    case 'key-value':
      return [node.key, node.value].filter((child): child is CstKey | CstValue => child !== null);
    case 'table':
    case 'array-table':
      return node.key !== null ? [node.key] : [];
    case 'key':
      return node.segments;
    case 'key-segment':
      return [];
    case 'array':
      return node.items.map((item) => item.value);
    case 'inline-table': {
      const nodes: CstNode[] = [];
      for (const entry of node.entries) {
        if (entry.key !== null) nodes.push(entry.key);
        if (entry.value !== null) nodes.push(entry.value);
      }
      return nodes;
    }
    default:
      return [];
  }
}

/** Dispatches the kind-specific hooks for one node. */
function dispatch(node: CstNode, visitor: CstVisitor): void {
  switch (node.kind) {
    case 'document':
      visitor.document?.(node);
      break;
    case 'key-value':
    case 'table':
    case 'array-table':
      visitor.entry?.(node);
      break;
    case 'key':
      visitor.key?.(node);
      break;
    case 'key-segment':
      visitor.keySegment?.(node);
      break;
    default:
      visitor.value?.(node);
      break;
  }
}

/**
 * Depth-first traversal of a subtree.
 *
 * Children are visited in source order; `enter` may return `false` to skip a
 * node's children without skipping the node itself.
 */
export function walk(node: CstNode, visitor: CstVisitor): void {
  const descend = (current: CstNode): void => {
    dispatch(current, visitor);
    if (visitor.enter?.(current) === false) return;
    for (const child of childrenOf(current)) descend(child);
    visitor.leave?.(current);
  };
  descend(node);
}

/** Every key-value entry in the document, in source order. */
export function keyValueEntries(document: CstDocument): Extract<CstEntry, { kind: 'key-value' }>[] {
  return document.entries.filter(
    (entry): entry is Extract<CstEntry, { kind: 'key-value' }> => entry.kind === 'key-value',
  );
}

/** Every table header in the document, in source order. */
export function tableEntries(
  document: CstDocument,
): Extract<CstEntry, { kind: 'table' | 'array-table' }>[] {
  return document.entries.filter(
    (entry): entry is Extract<CstEntry, { kind: 'table' | 'array-table' }> =>
      entry.kind === 'table' || entry.kind === 'array-table',
  );
}

/**
 * Every comment in the document, in source order.
 *
 * Comments live as trivia wherever they appeared — before a key, after a
 * value, or nested inside an array — so this walks the whole tree rather than
 * only the entry-level attachments, which is what makes "no comment was
 * dropped" checkable.
 */
export function collectComments(document: CstDocument): CstComment[] {
  const comments: CstComment[] = [];

  const addTrivia = (trivia: CstTrivia[]): void => {
    for (const piece of trivia) {
      if (piece.kind !== 'comment') continue;
      comments.push({
        kind: 'comment',
        text: piece.text,
        start: piece.start,
        end: piece.end,
        line: piece.line,
        column: piece.column,
      });
    }
  };

  const addKey = (key: CstKey | null): void => {
    if (key === null) return;
    for (const segment of key.segments) {
      addTrivia(segment.leading);
      addTrivia(segment.trailing);
    }
  };

  const addValue = (value: CstValue | null): void => {
    if (value === null) return;
    if (value.kind === 'array') {
      for (const item of value.items) {
        addTrivia(item.leading);
        addValue(item.value);
        addTrivia(item.trailing);
      }
      addTrivia(value.closeLeading);
    } else if (value.kind === 'inline-table') {
      for (const entry of value.entries) {
        addTrivia(entry.leading);
        addKey(entry.key);
        addTrivia(entry.keyTrailing);
        addTrivia(entry.valueLeading);
        addValue(entry.value);
        addTrivia(entry.trailing);
      }
      addTrivia(value.closeLeading);
    }
  };

  for (const entry of document.entries) {
    addTrivia(entry.leading);
    if (entry.kind === 'key-value') {
      addKey(entry.key);
      addTrivia(entry.keyTrailing);
      addTrivia(entry.valueLeading);
      addValue(entry.value);
    } else {
      addTrivia(entry.keyLeading);
      addKey(entry.key);
      addTrivia(entry.keyTrailing);
    }
    addTrivia(entry.trailing);
  }
  addTrivia(document.trailing);
  return comments;
}

/** The node whose span contains `offset`, deepest match first. */
export function nodeAtOffset(document: CstDocument, offset: number): CstNode | undefined {
  let best: CstNode | undefined;

  const consider = (node: CstNode): void => {
    if (offset >= node.start && offset <= node.end) best = node;
  };

  walk(document, {
    enter(node) {
      consider(node);
    },
  });

  return best;
}

/** The result of evaluating a CST into plain JavaScript values. */
export interface EvaluationResult {
  value: Record<string, unknown>;
  errors: CstError[];
}

/** Reports a semantic problem at a key's position. */
type Fail = (message: string, key: CstKey) => void;

/** Converts a CST value into the JavaScript primitive it denotes. */
function materialize(value: CstValue, fail: Fail): unknown {
  switch (value.kind) {
    case 'string':
      return value.value;
    case 'integer':
    case 'float':
      return value.value;
    case 'boolean':
      return value.value;
    case 'datetime':
      return value.value;
    case 'invalid':
      return undefined;
    case 'array':
      return value.items.map((item) => materialize(item.value, fail));
    case 'inline-table':
      return materializeInlineTable(value, fail);
  }
}

/**
 * Builds the object an inline table denotes.
 *
 * Inline tables may use dotted keys (`{ a.b = 1 }`), so the same nesting rules
 * as top-level assignments apply — just scoped to the braces.
 */
function materializeInlineTable(value: CstInlineTableValue, fail: Fail): Record<string, unknown> {
  const table: Record<string, unknown> = {};

  for (const entry of value.entries) {
    if (entry.key === null || entry.value === null) continue;
    const names = entry.key.segments.map((segment) => segment.name);
    let node = table;

    for (let i = 0; i < names.length; i++) {
      const name = names[i] ?? '';
      const last = i === names.length - 1;
      if (last) {
        if (Object.prototype.hasOwnProperty.call(node, name)) {
          fail(`duplicate key ${name} in inline table`, entry.key);
          break;
        }
        node[name] = materialize(entry.value, fail);
        continue;
      }

      let child = node[name];
      if (child === undefined) {
        child = {};
        node[name] = child;
      } else if (child === null || typeof child !== 'object' || Array.isArray(child)) {
        fail(`cannot redefine ${name} as a table`, entry.key);
        break;
      }
      node = child as Record<string, unknown>;
    }
  }

  return table;
}

/**
 * Evaluates a CST into the plain object the linter's rules expect.
 *
 * Semantic errors are returned rather than thrown; the caller decides whether
 * a document is good enough to lint. The evaluation mirrors TOML's rules for
 * tables, arrays of tables, dotted keys, and inline tables closely enough that
 * the parsed shape is interchangeable with the previous parser.
 */
export function evaluateDocument(document: CstDocument): EvaluationResult {
  const root: Record<string, unknown> = {};
  const errors: CstError[] = [];
  const positions = new SourcePositions(document.source);

  const report = (message: string, key: CstKey | null): void => {
    const start = key?.start ?? 0;
    const end = key?.end ?? start;
    const position = positions.at(start);
    errors.push({ message, start, end, line: position.line, column: position.column });
  };

  // Bookkeeping lives in weak maps keyed by the container, so arrays of
  // tables and inline tables are tracked without inventing path strings.
  const assigned = new WeakMap<object, Set<string>>();
  const declared = new WeakMap<object, Set<string>>();
  const dotted = new WeakMap<object, Set<string>>();
  const inlineTables = new WeakSet<object>();

  const mark = (map: WeakMap<object, Set<string>>, container: object, name: string): void => {
    const set = map.get(container);
    if (set === undefined) map.set(container, new Set([name]));
    else set.add(name);
  };

  const has = (map: WeakMap<object, Set<string>>, container: object, name: string): boolean =>
    map.get(container)?.has(name) === true;

  let current: Record<string, unknown> = root;

  for (const entry of document.entries) {
    if (entry.kind !== 'key-value') {
      const target = resolveTable(entry.key, entry.kind === 'array-table');
      if (target !== null) current = target;
      continue;
    }

    if (entry.key === null || entry.value === null) continue;

    const names = entry.key.segments.map((segment) => segment.name);
    let node = current;

    for (let i = 0; i < names.length; i++) {
      const name = names[i] ?? '';
      const last = i === names.length - 1;

      if (last) {
        if (Object.prototype.hasOwnProperty.call(node, name)) {
          report(`duplicate key ${name}`, entry.key);
          break;
        }
        node[name] = materialize(entry.value, (message, key) => report(message, key));
        mark(assigned, node, name);
        continue;
      }

      let child = node[name];
      if (child === undefined) {
        child = {};
        node[name] = child;
        mark(dotted, node, name);
      } else if (child === null || typeof child !== 'object' || Array.isArray(child)) {
        report(`cannot redefine ${name} as a table`, entry.key);
        break;
      } else if (inlineTables.has(child)) {
        report(`cannot extend inline table ${name}`, entry.key);
        break;
      }
      node = child as Record<string, unknown>;
    }
  }

  return { value: root, errors };

  /** Walks or creates the table a `[header]` / `[[header]]` points at. */
  function resolveTable(key: CstKey | null, isArray: boolean): Record<string, unknown> | null {
    if (key === null) return null;
    const names = key.segments.map((segment) => segment.name);
    let node: Record<string, unknown> = root;

    for (let i = 0; i < names.length; i++) {
      const name = names[i] ?? '';
      const last = i === names.length - 1;
      const existing = node[name];

      if (existing === undefined) {
        if (last && isArray) {
          const list: unknown[] = [];
          node[name] = list;
          const element: Record<string, unknown> = {};
          list.push(element);
          node = element;
          continue;
        }
        const element: Record<string, unknown> = {};
        node[name] = element;
        node = element;
        continue;
      }

      if (existing === null || typeof existing !== 'object') {
        report(`cannot redefine ${name} as a table`, key);
        return null;
      }

      if (last && isArray) {
        if (!Array.isArray(existing)) {
          report(`cannot redefine ${name} as an array of tables`, key);
          return null;
        }
        const element: Record<string, unknown> = {};
        existing.push(element);
        node = element;
        continue;
      }

      if (last && Array.isArray(existing)) {
        // `[a.b]` after `[[a.b]]` applies to the most recent element.
        const element = existing[existing.length - 1];
        if (element === null || typeof element !== 'object') {
          report(`cannot redefine ${name} as a table`, key);
          return null;
        }
        node = element as Record<string, unknown>;
        continue;
      }

      if (last) {
        if (has(declared, node, name) || has(assigned, node, name) || has(dotted, node, name)) {
          report(`table ${name} is already defined`, key);
          return null;
        }
        if (inlineTables.has(existing)) {
          report(`cannot extend inline table ${name}`, key);
          return null;
        }
        mark(declared, node, name);
      }

      node = existing as Record<string, unknown>;
    }

    return node;
  }
}

/** Evaluates a CST, throwing {@link CstParseError} on the first problem. */
export function toValue(document: CstDocument): Record<string, unknown> {
  const result = evaluateDocument(document);
  const error = result.errors[0];
  if (error !== undefined) throw new CstParseError(error);
  return result.value;
}
