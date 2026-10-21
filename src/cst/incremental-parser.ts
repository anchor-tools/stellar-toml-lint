/**
 * Incremental CST reparsing for the language server.
 *
 * A full reparse plus a full rule sweep on every keystroke is wasted work when
 * the edit touched three lines of a 5,000-line `stellar.toml`. This engine
 * keeps the previous `CstDocument` per URI, computes the line and offset delta
 * a `textDocument/didChange` introduced, reparses only the affected span,
 * splices the fresh entries into the cached tree (shifting the offsets of
 * everything after the edit), and re-runs only the rules whose category covers
 * a mutated section — plus the always-on categories (`general`, `file`,
 * `network`, …) that can read any part of the document. Diagnostics produced
 * by rules that did not re-run are carried over, with their positions shifted
 * when lines were inserted or removed above them.
 *
 * The merge is conservative: whenever anything looks ambiguous — a BOM, a
 * previously broken document, a slice that fails to reparse, an edit that may
 * change which suppression pragmas apply — the engine falls back to a full
 * parse and the full rule sweep, exactly what the non-incremental path does.
 * The incremental path is an optimisation, never a second source of truth.
 *
 * One caveat is documented where it matters: the `line`/`column` fields of
 * trivia and comment objects inside *shifted* nodes are left stale. Nothing in
 * the lint or LSP path reads them (positions are derived from offsets via
 * `SourcePositions`, and suppression pragmas are recovered from the raw
 * source); a full reparse — which happens routinely — recomputes them.
 */
import { finalize, lint } from '../lint.js';
import { isSuppressed, parseSuppressions } from '../comments.js';
import { allRules } from '../rules/index.js';
import { SourceIndex } from '../source-index.js';
import { parseCst } from './parser.js';
import type {
  CstComment,
  CstDocument,
  CstEntry,
  CstInlineEntry,
  CstKey,
  CstTokenSpan,
  CstTrivia,
  CstValue,
} from './parser.js';
import { evaluateDocument } from './visitor.js';
import type { EvaluationResult } from './visitor.js';
import type {
  Diagnostic,
  Position,
  Rule,
  RuleCategory,
  RuleContext,
  RuleOverrides,
} from '../types.js';

/** Where an edit began and how far it reached, in both old and new text. */
export interface LineDelta {
  /** 0-based first line that differs. */
  startLine: number;
  /** 0-based line at which the old text agrees again (exclusive end of the changed range). */
  oldEndLine: number;
  /** 0-based line at which the new text agrees again (exclusive end of the changed range). */
  newEndLine: number;
  /** Offset in the previous text where the change begins. */
  startOffset: number;
  /** Offset in the previous text just past the change. */
  oldEndOffset: number;
  /** Offset in the new text just past the change. */
  newEndOffset: number;
  /** `newLineCount - oldLineCount`. */
  lineDelta: number;
  /** True when the two texts are identical. */
  unchanged: boolean;
}

/** What one incremental (or fallback full) reparse did. */
export interface ReparseResult {
  /** Diagnostics for the new text, sorted like `lint()` sorts them. */
  diagnostics: Diagnostic[];
  /** True when the cached CST was reused and only the edit span reparsed. */
  incremental: boolean;
  /** Paths of top-level entries that were reparsed (empty on a full reparse). */
  reparsedPaths: string[];
  /** Ids of the rules that were executed this round. */
  rulesExecuted: string[];
  /** Milliseconds spent computing the result. */
  latencyMs: number;
}

/** Tuning knobs; every field has a sensible default. */
export interface IncrementalParserOptions {
  /** Rule severity overrides, forwarded to the rule loop. */
  rules?: RuleOverrides;
}

interface DocumentState {
  text: string;
  document: CstDocument;
  diagnostics: Diagnostic[];
}

/**
 * Categories always executed. `general`, `file`, `policy`, `codemod` and
 * `monitor` rules read arbitrary parts of the document; `network` rules are
 * almost all empty `run()` stubs whose real work is the CLI's async probes,
 * so executing them costs nothing and keeps their ids visible.
 */
const ALWAYS_RUN: ReadonlySet<RuleCategory> = new Set<RuleCategory>([
  'general',
  'file',
  'policy',
  'codemod',
  'monitor',
  'network',
]);

/** Top-level section a rule category reads, for the categories that are section-scoped. */
const CATEGORY_SECTION: Partial<Record<RuleCategory, string>> = {
  documentation: 'DOCUMENTATION',
  principals: 'PRINCIPALS',
  currencies: 'CURRENCIES',
  validators: 'VALIDATORS',
  sep24: 'CURRENCIES',
  sep12: 'CURRENCIES',
  fees: 'CURRENCIES',
};

/**
 * Sections whose interiors a section-scoped rule selection may trust.
 *
 * Any other touched table (`SERVERS`, a proprietary extension, a typo) makes
 * the engine run every rule instead: rules read root-level and unfamiliar
 * tables in ways this map does not model, and guessing narrower is how
 * findings go stale.
 */
const KNOWN_SECTIONS: ReadonlySet<string> = new Set([
  'DOCUMENTATION',
  'PRINCIPALS',
  'CURRENCIES',
  'VALIDATORS',
]);

/**
 * Per-URI incremental reparsing engine.
 *
 * Feed it the new full text on every change (the server advertises full-document
 * sync); it derives the delta itself, so a client that sends ranged changes can
 * be supported later without changing this API.
 */
export class IncrementalParser {
  private readonly states = new Map<string, DocumentState>();
  private readonly options: IncrementalParserOptions;

  constructor(options: IncrementalParserOptions = {}) {
    this.options = options;
  }

  /** Drops the cached state for `uri` (on `textDocument/didClose`). */
  close(uri: string): void {
    this.states.delete(uri);
  }

  /** Forgets every document (tests, and a defensive reset). */
  clear(): void {
    this.states.clear();
  }

  /** Reparses `uri` to `text`, incrementally when the previous state allows it. */
  update(uri: string, text: string): ReparseResult {
    const started = now();
    const previous = this.states.get(uri);

    if (previous === undefined) return this.fullReparse(uri, text, started);
    if (previous.text === text) {
      return {
        diagnostics: previous.diagnostics,
        incremental: true,
        reparsedPaths: [],
        rulesExecuted: [],
        latencyMs: now() - started,
      };
    }

    const incremental = this.tryIncremental(uri, previous, text, started);
    return incremental ?? this.fullReparse(uri, text, started);
  }

  /** Last known diagnostics for `uri`, for pull-based consumers. */
  diagnostics(uri: string): Diagnostic[] {
    return this.states.get(uri)?.diagnostics ?? [];
  }

  /** Full parse + full rule sweep; the correctness fallback. */
  private fullReparse(uri: string, text: string, started: number): ReparseResult {
    const result = lint(text, this.options);
    this.states.set(uri, {
      text,
      document: parseCst(text),
      diagnostics: result.diagnostics,
    });
    return {
      diagnostics: result.diagnostics,
      incremental: false,
      reparsedPaths: [],
      rulesExecuted: allRules.map((rule) => rule.id),
      latencyMs: now() - started,
    };
  }

  /**
   * Attempts the incremental path; returns `undefined` when the edit cannot be
   * handled incrementally and the caller should fall back to a full reparse.
   */
  private tryIncremental(
    uri: string,
    previous: DocumentState,
    text: string,
    started: number,
  ): ReparseResult | undefined {
    // `lint` strips a BOM before parsing, so a BOM'd document's offsets and
    // positions would disagree with a tree parsed from the raw text. BOMs are
    // rare — reparse instead of reconciling the one-column skew.
    if (previous.text.charCodeAt(0) === 0xfeff || text.charCodeAt(0) === 0xfeff) return undefined;

    // A document that did not parse cleanly has no trustworthy entry spans to
    // diff against — reparse it whole. A previous `file/parse` diagnostic means
    // the rules never ran last round (syntax *or* semantic short-circuit), so
    // there is nothing sound to carry forward either.
    if (previous.document.errors.length > 0) return undefined;
    if (previous.diagnostics.some((d) => d.rule === 'file/parse')) return undefined;

    const delta = computeLineDelta(previous.text, text);
    if (delta.unchanged) {
      return {
        diagnostics: previous.diagnostics,
        incremental: true,
        reparsedPaths: [],
        rulesExecuted: [],
        latencyMs: now() - started,
      };
    }

    // An edit that touches a `#` may add or remove a suppression pragma, and
    // pragmas apply by line number across the whole file — the one case a
    // section-scoped re-run cannot reason about. Reparse the world.
    if (regionHasComment(previous.text, delta.startOffset, delta.oldEndOffset)) return undefined;
    if (regionHasComment(text, delta.startOffset, delta.newEndOffset)) return undefined;

    // Suppressed findings are dropped before they are ever stored, so once any
    // pragma exists a line-count change can move a finding across a
    // suppression boundary with no stored finding left to re-filter. Fall back
    // to the full path, which re-runs every rule and applies the pragmas to
    // fresh findings. With no pragmas — or with the line count unchanged, so
    // no line crossed any boundary — the fast paths below are exact.
    if (delta.lineDelta !== 0 && parseSuppressions(text).size > 0) return undefined;

    const oldStarts = lineStarts(previous.text);
    const touched = touchedEntries(previous.document, delta, oldStarts);

    // Trivia-only edit: no entry's text changed, so every previous diagnostic
    // stays true — its position just moves with the lines below the edit.
    if (touched.length === 0) {
      const suppressions = parseSuppressions(text);
      const diagnostics = shiftDiagnostics(previous.diagnostics, delta).filter(
        (d) => !isSuppressed(suppressions, d.position?.line, d.rule),
      );
      this.states.set(uri, {
        text,
        document: shiftAfter(previous.document, text, delta),
        diagnostics,
      });
      return {
        diagnostics,
        incremental: true,
        reparsedPaths: [],
        rulesExecuted: [],
        latencyMs: now() - started,
      };
    }

    const regionStart = Math.min(...touched.map((t) => t.entry.start));
    const regionEndOld = Math.max(...touched.map((t) => t.entry.end));
    const offsetShift = delta.newEndOffset - delta.oldEndOffset;
    const regionEndNew = regionEndOld + offsetShift;
    if (regionEndNew < regionStart) return undefined;

    const slice = text.slice(regionStart, regionEndNew);
    const reparsed = parseCst(slice);
    // A slice that does not parse means the edit crossed a boundary this
    // engine does not try to understand (a multi-line string left open, a
    // deletion that cut into a token). Reparse instead of guessing.
    if (reparsed.errors.length > 0) return undefined;

    const before: CstEntry[] = [];
    const after: CstEntry[] = [];
    for (const entry of previous.document.entries) {
      if (entry.end <= regionStart) before.push(entry);
      else if (entry.start >= regionEndOld) after.push(entry);
    }

    const merged: CstDocument = {
      kind: 'document',
      source: text,
      bom: false,
      entries: [
        ...before,
        ...reparsed.entries.map((entry) => shiftEntry(entry, regionStart)),
        ...after.map((entry) => shiftEntry(entry, offsetShift)),
      ],
      trailing: shiftTrivia(previous.document.trailing, offsetShift),
      errors: [],
      start: 0,
      end: text.length,
    };

    // A semantic error introduced by the edit (duplicate key, redefined
    // table) is reported by the full path as `file/parse` with the error's
    // exact position — fall back so the message and short-circuit behaviour
    // stay exactly `lint()`'s.
    const evaluation = evaluateDocument(merged);
    if (evaluation.errors.length > 0) return undefined;

    const rootKeyTouched = touched.some((t) => t.prefix === '' && t.entry.kind === 'key-value');
    const sections = sectionsOf(touched.map((t) => t.path));
    const sectionScoped =
      !rootKeyTouched && [...sections].every((section) => KNOWN_SECTIONS.has(section));
    const rulesExecuted =
      sectionScoped ? selectRules(sections, previous.diagnostics) : [...allRules];
    const diagnostics = runRules(
      merged,
      text,
      rulesExecuted,
      evaluation,
      delta,
      previous.diagnostics,
      this.options,
    );

    this.states.set(uri, { text, document: merged, diagnostics });
    return {
      diagnostics,
      incremental: true,
      reparsedPaths: touched.map((t) => t.path),
      rulesExecuted: rulesExecuted.map((rule) => rule.id),
      latencyMs: now() - started,
    };
  }
}

/**
 * Runs `rules` against `document`, then merges in the previous diagnostics
 * that belong to rules which did not re-run, shifting their positions when
 * the edit moved lines. The merged list is filtered through the current
 * suppression pragmas and sorted exactly as `lint()` sorts it.
 */
function runRules(
  document: CstDocument,
  source: string,
  rules: Rule[],
  evaluation: EvaluationResult,
  delta: LineDelta,
  previousDiagnostics: Diagnostic[],
  options: IncrementalParserOptions,
): Diagnostic[] {
  const parsed = evaluation.value;
  const index = new SourceIndex(source, document);
  const suppressions = parseSuppressions(source);
  const overrides = options.rules ?? {};
  const fresh: Diagnostic[] = [];
  const executed = new Set(rules.map((rule) => rule.id));

  for (const rule of rules) {
    if (overrides[rule.id] === 'off') continue;
    const ctx: RuleContext = {
      doc: parsed,
      cst: document,
      source,
      options,
      locate: (path: string): Position | undefined => index.get(path),
      report: (d) => {
        const override = overrides[d.rule];
        const severity = override && override !== 'off' ? override : (d.severity ?? rule.severity);
        fresh.push({ ...d, severity });
      },
    };
    try {
      rule.run(ctx);
    } catch (error) {
      // A crashing rule must not take down the editor session — report it and
      // move on, the same bargain `lint()` strikes.
      fresh.push({
        rule: 'internal/rule-error',
        severity: 'warning',
        category: 'file',
        message: `Rule ${rule.id} failed to run: ${errorMessage(error)}`,
        helpUri: 'https://github.com/anchor-tools/stellar-toml-lint/issues',
        suggestion: 'Please report this file (with secrets removed) as a bug.',
      });
    }
  }

  // Crash reports are never carried: they describe the rule's state last
  // round, and the rule either re-runs now or a full reparse regenerates it.
  const carried = previousDiagnostics.filter(
    (d) => d.rule !== 'internal/rule-error' && !executed.has(d.rule),
  );
  const merged = [...fresh, ...shiftDiagnostics(carried, delta)];
  const kept = merged.filter((d) => !isSuppressed(suppressions, d.position?.line, d.rule));
  return finalize(kept, options, parsed).diagnostics;
}

/**
 * Computes the line and offset span that differs between two texts.
 *
 * Compares line arrays from both ends to skip the common prefix and suffix,
 * then measures the offsets of what remains. A single-keystroke edit yields a
 * one-line delta; a paste yields the pasted range. When the common suffix ends
 * the text, `newEndOffset - oldEndOffset` equals the document's length delta,
 * which is how post-edit content gets its offset shift.
 */
export function computeLineDelta(oldText: string, newText: string): LineDelta {
  if (oldText === newText) {
    return {
      startLine: 0,
      oldEndLine: 0,
      newEndLine: 0,
      startOffset: 0,
      oldEndOffset: 0,
      newEndOffset: 0,
      lineDelta: 0,
      unchanged: true,
    };
  }

  const oldLines = oldText.split('\n');
  const newLines = newText.split('\n');

  let prefix = 0;
  const maxPrefix = Math.min(oldLines.length, newLines.length);
  while (prefix < maxPrefix && oldLines[prefix] === newLines[prefix]) prefix++;

  let suffix = 0;
  const maxSuffix = Math.min(oldLines.length - prefix, newLines.length - prefix);
  while (
    suffix < maxSuffix &&
    oldLines[oldLines.length - 1 - suffix] === newLines[newLines.length - 1 - suffix]
  ) {
    suffix++;
  }

  return {
    startLine: prefix,
    oldEndLine: oldLines.length - suffix,
    newEndLine: newLines.length - suffix,
    startOffset: offsetOfLine(oldText, prefix),
    oldEndOffset: offsetOfLine(oldText, oldLines.length - suffix),
    newEndOffset: offsetOfLine(newText, newLines.length - suffix),
    lineDelta: newLines.length - oldLines.length,
    unchanged: false,
  };
}

/** Offset of the first character of `line` (0-based); end of text when past it. */
function offsetOfLine(text: string, line: number): number {
  if (line <= 0) return 0;
  let offset = 0;
  for (let i = 0; i < line; i++) {
    const next = text.indexOf('\n', offset);
    if (next < 0) return text.length;
    offset = next + 1;
  }
  return offset;
}

/** Offsets at which each 0-based line begins. */
function lineStarts(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) === 0x0a) starts.push(i + 1);
  }
  return starts;
}

/** 0-based line containing `offset`. */
function lineOf(starts: number[], offset: number): number {
  let low = 0;
  let high = starts.length - 1;
  while (low < high) {
    const mid = (low + high + 1) >> 1;
    if ((starts[mid] ?? 0) <= offset) low = mid;
    else high = mid - 1;
  }
  return low;
}

/** True when `[start, end)` of `text` contains a `#` (a comment or pragma). */
function regionHasComment(text: string, start: number, end: number): boolean {
  return text.slice(start, end).includes('#');
}

/** One top-level entry the edit intersected, with its table scope. */
interface TouchedEntry {
  entry: CstEntry;
  /** Fully qualified path, e.g. `CURRENCIES[0].code`. */
  path: string;
  /** Enclosing table scope; `''` for a root-level key. */
  prefix: string;
}

/** Top-level entries whose line span intersects the edited line range. */
function touchedEntries(
  document: CstDocument,
  delta: LineDelta,
  oldStarts: number[],
): TouchedEntry[] {
  const touched: TouchedEntry[] = [];
  let prefix = '';
  const arrayCounts = new Map<string, number>();

  for (const entry of document.entries) {
    const path = entryPath(prefix, entry, arrayCounts);
    const entryPrefix = prefix;
    if (entry.kind === 'table' || entry.kind === 'array-table') prefix = path;

    const startLine = lineOf(oldStarts, entry.start);
    const endLine = lineOf(oldStarts, Math.max(entry.end - 1, entry.start));
    if (startLine <= delta.oldEndLine && endLine >= delta.startLine) {
      touched.push({ entry, path, prefix: entryPrefix });
    }
  }

  return touched;
}

/** Fully qualified path of `entry`, advancing `arrayCounts` for array-tables. */
function entryPath(prefix: string, entry: CstEntry, arrayCounts: Map<string, number>): string {
  if (entry.kind === 'table' || entry.kind === 'array-table') {
    const name = entry.key?.path ?? '';
    if (entry.kind === 'array-table') {
      const next = arrayCounts.get(name) ?? 0;
      arrayCounts.set(name, next + 1);
      return `${name}[${next}]`;
    }
    return name;
  }
  const key = entry.key?.path ?? '';
  return prefix === '' ? key : `${prefix}.${key}`;
}

/** Top-level section names a set of changed paths belongs to. */
function sectionsOf(paths: string[]): Set<string> {
  const sections = new Set<string>();
  for (const path of paths) {
    const top = path.split(/[.[]/, 1)[0];
    if (top !== undefined && top !== '') sections.add(top);
  }
  return sections;
}

/**
 * Rules to re-run after `sections` changed: the always-on categories, every
 * rule whose category reads one of the touched sections, plus any rule that
 * previously reported a diagnostic inside a touched section (so a fix that
 * clears a finding re-runs the rule that produced it).
 */
function selectRules(sections: Set<string>, previousDiagnostics: Diagnostic[]): Rule[] {
  const selected: Rule[] = [];

  for (const rule of allRules) {
    if (ALWAYS_RUN.has(rule.category)) {
      selected.push(rule);
      continue;
    }
    const section = CATEGORY_SECTION[rule.category];
    if (section !== undefined && sections.has(section)) {
      selected.push(rule);
      continue;
    }
    const touchedPreviously = previousDiagnostics.some(
      (d) => d.rule === rule.id && pathInSections(d.path, sections),
    );
    if (touchedPreviously) selected.push(rule);
  }

  return selected;
}

/** True when `path` lies inside one of `sections`. */
function pathInSections(path: string | undefined, sections: Set<string>): boolean {
  if (path === undefined) return false;
  const top = path.split(/[.[]/, 1)[0];
  return top !== undefined && sections.has(top);
}

/**
 * Shifts the positions of diagnostics that sit below the edited lines.
 *
 * `Diagnostic.position` is 1-based while `LineDelta`'s lines are 0-based; the
 * `<= oldEndLine` comparison deliberately mixes them, which — because
 * `oldEndLine` is an exclusive 0-based end — is exactly "strictly before the
 * first changed line" in either base.
 */
function shiftDiagnostics(diagnostics: Diagnostic[], delta: LineDelta): Diagnostic[] {
  if (delta.lineDelta === 0) return diagnostics;
  return diagnostics.map((d) => {
    if (d.position === undefined || d.position.line <= delta.oldEndLine) return d;
    return {
      ...d,
      position: { line: d.position.line + delta.lineDelta, column: d.position.column },
    };
  });
}

/**
 * A copy of `document` whose text has been swapped for `text` after a
 * trivia-only edit: entries before the edit keep their offsets, entries from
 * the edit onward shift by the document's length delta.
 */
function shiftAfter(document: CstDocument, text: string, delta: LineDelta): CstDocument {
  const shift = delta.newEndOffset - delta.oldEndOffset;
  const entries: CstEntry[] = [];
  for (const entry of document.entries) {
    entries.push(entry.start >= delta.oldEndOffset ? shiftEntry(entry, shift) : entry);
  }
  let trailing = document.trailing;
  if (trailing.start >= delta.oldEndOffset) {
    trailing = shiftTrivia(document.trailing, shift);
  }
  return { ...document, source: text, end: text.length, entries, trailing };
}

/** Adds `delta` to every offset inside `trivia`. */
function shiftTrivia(list: CstTrivia[], delta: number): CstTrivia[] {
  return list.map((t) => ({ ...t, start: t.start + delta, end: t.end + delta }));
}

/** Adds `delta` to every offset inside a comment. */
function shiftComment(comment: CstComment, delta: number): CstComment {
  return { ...comment, start: comment.start + delta, end: comment.end + delta };
}

/** Adds `delta` to every offset inside a token span (or passes `null` through). */
function shiftSpan(span: CstTokenSpan | null, delta: number): CstTokenSpan | null {
  return span === null ? null : { ...span, start: span.start + delta, end: span.end + delta };
}

/** Adds `delta` to every offset inside a dotted key. */
function shiftKey(key: CstKey, delta: number): CstKey {
  return {
    ...key,
    start: key.start + delta,
    end: key.end + delta,
    segments: key.segments.map((segment) => ({
      ...segment,
      start: segment.start + delta,
      end: segment.end + delta,
      leading: shiftTrivia(segment.leading, delta),
      trailing: shiftTrivia(segment.trailing, delta),
    })),
  };
}

/** Adds `delta` to every offset inside a value, recursing through arrays and inline tables. */
function shiftValue(value: CstValue, delta: number): CstValue {
  if (value.kind === 'array') {
    return {
      ...value,
      start: value.start + delta,
      end: value.end + delta,
      open: shiftSpan(value.open, delta),
      items: value.items.map((item) => ({
        leading: shiftTrivia(item.leading, delta),
        value: shiftValue(item.value, delta),
        trailing: shiftTrivia(item.trailing, delta),
        comma: shiftSpan(item.comma, delta),
      })),
      closeLeading: shiftTrivia(value.closeLeading, delta),
      close: shiftSpan(value.close, delta),
    };
  }
  if (value.kind === 'inline-table') {
    return {
      ...value,
      start: value.start + delta,
      end: value.end + delta,
      open: shiftSpan(value.open, delta),
      entries: value.entries.map((entry) => shiftInlineEntry(entry, delta)),
      closeLeading: shiftTrivia(value.closeLeading, delta),
      close: shiftSpan(value.close, delta),
    };
  }
  return { ...value, start: value.start + delta, end: value.end + delta };
}

/** Adds `delta` to every offset inside one `key = value` of an inline table. */
function shiftInlineEntry(entry: CstInlineEntry, delta: number): CstInlineEntry {
  return {
    ...entry,
    leading: shiftTrivia(entry.leading, delta),
    key: entry.key === null ? null : shiftKey(entry.key, delta),
    keyTrailing: shiftTrivia(entry.keyTrailing, delta),
    equals: shiftSpan(entry.equals, delta),
    valueLeading: shiftTrivia(entry.valueLeading, delta),
    value: entry.value === null ? null : shiftValue(entry.value, delta),
    trailing: shiftTrivia(entry.trailing, delta),
    comma: shiftSpan(entry.comma, delta),
  };
}

/**
 * Adds `delta` to every offset inside an entry: span, trivia, comments, key,
 * value, punctuation, and any recovered text's bounds.
 */
function shiftEntry(entry: CstEntry, delta: number): CstEntry {
  const shared = {
    leading: shiftTrivia(entry.leading, delta),
    trailing: shiftTrivia(entry.trailing, delta),
    leadingComments: entry.leadingComments.map((comment) => shiftComment(comment, delta)),
    trailingComment:
      entry.trailingComment === undefined
        ? undefined
        : shiftComment(entry.trailingComment, delta),
    start: entry.start + delta,
    end: entry.end + delta,
    recovery: entry.recovery,
    errors: entry.errors.map((error) => ({
      ...error,
      start: error.start + delta,
      end: error.end + delta,
    })),
  };

  if (entry.kind === 'key-value') {
    return {
      ...shared,
      kind: 'key-value',
      key: entry.key === null ? null : shiftKey(entry.key, delta),
      keyTrailing: shiftTrivia(entry.keyTrailing, delta),
      equals: shiftSpan(entry.equals, delta),
      valueLeading: shiftTrivia(entry.valueLeading, delta),
      value: entry.value === null ? null : shiftValue(entry.value, delta),
    };
  }

  return {
    ...shared,
    kind: entry.kind,
    open: shiftSpan(entry.open, delta),
    keyLeading: shiftTrivia(entry.keyLeading, delta),
    key: entry.key === null ? null : shiftKey(entry.key, delta),
    keyTrailing: shiftTrivia(entry.keyTrailing, delta),
    close: shiftSpan(entry.close, delta),
  };
}

/** String form of a thrown value, mirroring `lint()`'s crash reporting. */
function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return typeof error === 'string' ? error : String(error);
}

/** Milliseconds since an arbitrary epoch, for `latencyMs`. */
function now(): number {
  return typeof performance !== 'undefined' ? performance.now() : Date.now();
}
