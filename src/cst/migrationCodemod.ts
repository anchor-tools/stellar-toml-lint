/**
 * The schema migration codemod: deprecated SEP-1 fields rewritten in place.
 *
 * A `stellar.toml` is a production config that people edit by hand, so the
 * engine is built around three promises:
 *
 * 1. **The file's own formatting survives.** Rules emit half-open offsets into
 *    the *original* source and the engine splices them, so quoting, spacing,
 *    blank lines, and the comments attached above a field are never
 *    re-rendered. This is the same property `canonicalSortCodemod` depends on,
 *    reached from the other direction: that codemod permutes CST entries, this
 *    one rewrites text ranges the CST located.
 * 2. **A preview cannot disagree with the write.** `--dry-run` and apply mode
 *    run the identical plan; only the `writeFile` call differs. The diff is the
 *    shared {@link formatUnifiedDiff} output, so what CI asserts is what a
 *    human reviews.
 * 3. **A bad result is refused, not written.** After applying the plan the
 *    engine lints the rewritten source and compares it with the lint of the
 *    original. If the migration introduced an error — a successor field that
 *    turns out to break a same-domain check, say — the file is left exactly as
 *    it was and the reason is reported. That is the rollback safeguard, and it
 *    is why the codemod can be pointed at a directory of live configs.
 *
 * Steps that reach for overlapping text are dropped rather than applied in
 * some order the engine invented, because the two rules disagreeing about one
 * statement means one of them is wrong about the file.
 */
import { parseCst } from './parser.js';
import type {
  CstDocument,
  CstEntry,
  CstKeyValueEntry,
  CstTableEntry,
  CstTrivia,
} from './parser.js';
import type { OffsetTextEdit } from '../fix.js';
import { lint } from '../lint.js';
import { formatUnifiedDiff } from '../line-diff.js';
import { MIGRATION_RULES } from './codemodRules/index.js';
import type { MigrationContext, MigrationRule, MigrationStep } from './codemodRules/index.js';

export interface MigrationOptions {
  /** Rules to run; the registry in `codemodRules/` when omitted. */
  rules?: readonly MigrationRule[];
  /** Rule ids to leave out, e.g. `['legacy-field-alias']`. */
  skipRules?: readonly string[];
  /** Lint the result and refuse it when it is worse than the input. Default `true`. */
  validate?: boolean;
  /** Domain handed to the validator, so the same-domain checks still apply. */
  domain?: string;
}

export interface MigrationCounts {
  errors: number;
  warnings: number;
}

export interface MigrationResult {
  /** False when the source has syntax errors, which is why nothing ran. */
  parsed: boolean;
  changed: boolean;
  /** What will be (or was) rewritten, in rule order. */
  steps: MigrationStep[];
  /** Why a rule that matched did nothing, or why two rules collided. */
  notes: string[];
  /** The migrated source, or the original when nothing applied or validation refused. */
  output: string;
  /** False when {@link refusal} explains a rewrite that was thrown away. */
  validated: boolean;
  refusal?: string;
  /** Diagnostic counts either side of the rewrite, for the report. */
  validation?: { before: MigrationCounts; after: MigrationCounts };
}

/**
 * The trivia that belongs to an entry rather than to the gap above it.
 *
 * The cut is the last blank line, exactly as `canonicalSortCodemod` draws it:
 * a `newline` at the start of the run or directly after another `newline` ends
 * the separator. Both codemods have to agree about which comment annotates
 * which key, or moving a field in one command would strand its documentation
 * in the other.
 */
function attachedTrivia(entry: CstEntry): CstTrivia[] {
  let cut = -1;
  for (let i = 0; i < entry.leading.length; i++) {
    if (entry.leading[i]?.kind !== 'newline') continue;
    const previous = i === 0 ? 'newline' : entry.leading[i - 1]?.kind;
    if (previous === 'newline') cut = i + 1;
  }
  const attached = cut === -1 ? entry.leading : entry.leading.slice(cut);
  return attached.some((trivia) => trivia.kind === 'comment') ? attached : [];
}

/** The statement's own text: attached comments through the newline that ends the line. */
function statementRange(entry: CstEntry): { start: number; end: number } {
  const start = attachedTrivia(entry)[0]?.start ?? entry.start;
  let end = entry.end;
  for (const trivia of entry.trailing) {
    end = trivia.end;
    if (trivia.kind === 'newline') break;
  }
  return { start, end };
}

function isTable(entry: CstEntry): entry is CstTableEntry {
  return entry.kind === 'table' || entry.kind === 'array-table';
}

function leafOf(path: string): string {
  const dot = path.lastIndexOf('.');
  return dot === -1 ? path : path.slice(dot + 1);
}

/** The entries before the first table header, where the global fields live. */
function preamble(document: CstDocument): CstKeyValueEntry[] {
  const entries: CstKeyValueEntry[] = [];
  for (const entry of document.entries) {
    if (isTable(entry)) break;
    if (entry.key === null || entry.errors.length > 0) continue;
    if (entry.key.path.includes('.')) continue;
    entries.push(entry);
  }
  return entries;
}

/**
 * Indexes the document by table, so a rule can ask "is `ORG_NAME` already set
 * in `[DOCUMENTATION]`?" without walking the tree again.
 */
function sectionsOf(document: CstDocument): Map<string, CstKeyValueEntry[]> {
  const bySection = new Map<string, CstKeyValueEntry[]>();
  let section = '';
  for (const entry of document.entries) {
    if (isTable(entry)) {
      if (entry.key === null || entry.errors.length > 0) continue;
      section = entry.key.path.toUpperCase();
      if (!bySection.has(section)) bySection.set(section, []);
      continue;
    }
    if (entry.key === null || entry.errors.length > 0) continue;
    if (!bySection.has(section)) bySection.set(section, []);
    bySection.get(section)?.push(entry);
  }
  return bySection;
}

/** The offset just past the last line belonging to `section`, or `undefined` when it has none. */
function sectionEnd(document: CstDocument, section: string): number | undefined {
  const want = section.toUpperCase();
  let end: number | undefined;
  let current = '';
  for (const entry of document.entries) {
    if (isTable(entry)) {
      if (entry.key === null || entry.errors.length > 0) continue;
      current = entry.key.path.toUpperCase();
      if (current === want) end = statementRange(entry).end;
      continue;
    }
    if (current !== want || entry.key === null || entry.errors.length > 0) continue;
    end = statementRange(entry).end;
  }
  return end;
}

/**
 * What the linter says about a source, plus whether it still parses.
 *
 * Parsing is checked against the CST rather than the lint output, because a
 * syntax error is a fact about the bytes and `lint` also reports it as a
 * diagnostic — counting one is not the same as trusting the rest of a
 * half-parsed document.
 */
function countsOf(
  source: string,
  domain?: string,
): MigrationCounts & { parses: boolean; errorRules: string[] } {
  const result = lint(source, domain === undefined ? {} : { domain });
  const errors = result.diagnostics.filter((diagnostic) => diagnostic.severity === 'error');
  return {
    errors: result.counts.error ?? 0,
    warnings: result.counts.warning ?? 0,
    parses: parseCst(source).errors.length === 0,
    errorRules: [...new Set(errors.map((diagnostic) => diagnostic.rule))],
  };
}

function editOrder(a: OffsetTextEdit, b: OffsetTextEdit): number {
  return a.start - b.start || a.end - b.end;
}

function overlaps(accepted: readonly OffsetTextEdit[], edits: readonly OffsetTextEdit[]): boolean {
  return edits.some(
    (edit) =>
      accepted.some((other) => edit.start < other.end && other.start < edit.end) ||
      (edit.start === edit.end &&
        accepted.some((other) => other.start < edit.start && edit.start < other.end)),
  );
}

/**
 * Splices edits into the source in one ascending pass.
 *
 * Two rules can legitimately insert at the same offset — both moving a field
 * into a `[DOCUMENTATION]` the file does not have — and the order their text
 * appears in must be the order they were planned, not the order an array
 * happened to be sorted in. So insertions are merged per offset first, then
 * everything is applied left to right, which is also what lets a deletion and
 * an insertion share the end of the file without either of them reading past
 * a length that has already changed.
 */
function applyEdits(source: string, edits: readonly OffsetTextEdit[]): string {
  const insertions = new Map<number, string>();
  const replacements: OffsetTextEdit[] = [];

  for (const edit of edits) {
    if (edit.start === edit.end) {
      insertions.set(edit.start, `${insertions.get(edit.start) ?? ''}${edit.text}`);
      continue;
    }
    replacements.push(edit);
  }

  type Op =
    | { at: number; kind: 'insert'; text: string }
    | { at: number; kind: 'replace'; end: number; text: string };

  // An insert and a replace that start at the same offset keep both edits: the
  // text goes in first, then the range it now precedes is rewritten.
  const ops: Op[] = [
    ...[...insertions].map(([at, text]): Op => ({ at, kind: 'insert', text })),
    ...replacements.map((edit): Op => ({
      at: edit.start,
      kind: 'replace',
      end: edit.end,
      text: edit.text,
    })),
  ].sort((a, b) => a.at - b.at || (a.kind === 'insert' ? -1 : 1));

  let output = '';
  let cursor = 0;
  for (const op of ops) {
    // An operation inside a range another edit already rewrote is a collision
    // the overlap check should have caught; skipping it keeps the output
    // honest rather than splicing at a stale offset.
    if (op.at < cursor) continue;
    output += source.slice(cursor, op.at);
    if (op.kind === 'replace') {
      output += op.text;
      cursor = op.end;
      continue;
    }
    output += op.text;
    cursor = op.at;
  }
  return `${output}${source.slice(cursor)}`;
}

/**
 * Gives each moved block the line break it has to have to be its own line.
 *
 * A cut can take the file's final newline away with it, and `[DOCUMENTATION]`
 * written directly after `KEY = "value"` is a parse error rather than a
 * migration. The separator has to be measured against the text that will
 * actually precede the block once every cut is applied — the original prefix
 * still holds the statement being moved, and blank lines multiplied with each
 * move. Only the first block landing at an offset is touched; every other one
 * follows a statement that already ends in a newline, and a new table header
 * additionally gets the blank line above it that every header in a
 * hand-written file has.
 */
function lineSeparated(
  source: string,
  edits: readonly OffsetTextEdit[],
  headers: WeakMap<OffsetTextEdit, string>,
): OffsetTextEdit[] {
  const landed = new Set<number>();

  return edits.map((edit) => {
    if (edit.start !== edit.end) return edit;
    const at = edit.start;
    if (landed.has(at)) return edit;
    landed.add(at);

    const before = prefixAfterCuts(source, edits, at);
    if (before.length === 0 || before.endsWith('\n\n')) return edit;
    if (before.endsWith('\n')) {
      if (!headers.has(edit)) return edit;
      return { ...edit, text: `\n${edit.text}` };
    }
    return { ...edit, text: `\n\n${edit.text}` };
  });
}

/** The text before `at` once every edit that ends at or before it has been applied. */
function prefixAfterCuts(source: string, edits: readonly OffsetTextEdit[], at: number): string {
  const before = edits.filter((edit) => edit.start !== edit.end && edit.end <= at).sort(editOrder);
  let text = '';
  let cursor = 0;
  for (const edit of before) {
    text += source.slice(cursor, edit.start) + edit.text;
    cursor = edit.end;
  }
  return `${text}${source.slice(cursor, at)}`;
}

/**
 * Applies the rule registry to a document and validates the answer.
 *
 * The same instance can process many files; nothing is carried between runs.
 */
export class SchemaMigrationCodemod {
  constructor(private readonly rules: readonly MigrationRule[] = MIGRATION_RULES) {}

  run(source: string, options: MigrationOptions = {}): MigrationResult {
    const document = parseCst(source);
    if (document.errors.length > 0) {
      return {
        parsed: false,
        changed: false,
        steps: [],
        notes: [],
        output: source,
        validated: false,
        refusal: 'file does not parse; nothing was migrated',
      };
    }

    const skip = new Set(options.skipRules ?? []);
    const notes: string[] = [];
    const preambleEntries = preamble(document);
    const sections = sectionsOf(document);
    // A section the file does not have gets its header written once, by the
    // first move that targets it. The document is not re-parsed between rules,
    // so `sectionEnd` keeps reporting the header as missing; the header ships as
    // its own edit, tagged here, so a second move into the same new section has
    // its copy dropped — and a move that is dropped for colliding writes nothing
    // at all, header included.
    const headers = new WeakMap<OffsetTextEdit, string>();
    const createdSections = new Set<string>();
    const context: MigrationContext = {
      document,
      rootKey: (name) => {
        const want = name.toUpperCase();
        return preambleEntries.find((entry) => entry.key?.path.toUpperCase() === want);
      },
      hasField: (section, field) => {
        const want = field.toUpperCase();
        const entries =
          section === '' ? preambleEntries : (sections.get(section.toUpperCase()) ?? []);
        return entries.some(
          (entry) => entry.key !== null && leafOf(entry.key.path).toUpperCase() === want,
        );
      },
      valueSpan: (entry) => {
        const value = entry.value;
        if (value === null || value === undefined) return undefined;
        return {
          start: value.start,
          end: value.end,
          text: document.source.slice(value.start, value.end),
        };
      },
      moveStatement: (entry, { section, renameTo }) => {
        const range = statementRange(entry);
        let text = document.source.slice(range.start, range.end);
        const key = entry.key;
        if (key === null) return undefined;
        if (renameTo !== undefined) {
          const from = key.start - range.start;
          const to = key.end - range.start;
          text = text.slice(0, from) + renameTo + text.slice(to);
        }
        // A statement lifted off the last line of a file that has no final
        // newline would otherwise arrive at its new home without one, and two
        // migrations into the same table would be written onto each other.
        const body = text.endsWith('\n') ? text : `${text}\n`;
        const end = sectionEnd(document, section);
        const at = end ?? document.source.length;
        if (end !== undefined)
          return [
            { start: range.start, end: range.end, text: '' },
            { start: at, end: at, text: body },
          ];
        const header: OffsetTextEdit = { start: at, end: at, text: `[${section}]\n` };
        headers.set(header, section.toUpperCase());
        return [
          { start: range.start, end: range.end, text: '' },
          header,
          { start: at, end: at, text: body },
        ];
      },
      note: (message) => notes.push(message),
    };

    const steps: MigrationStep[] = [];
    const accepted: OffsetTextEdit[] = [];

    for (const rule of options.rules ?? this.rules) {
      if (skip.has(rule.id)) continue;
      for (const step of rule.plan(context)) {
        const sorted = [...step.edits].sort(editOrder);
        if (overlaps(accepted, sorted)) {
          notes.push(`${step.path}: another rule already rewrites it, left for the next run`);
          continue;
        }
        accepted.push(
          ...sorted.filter((edit) => {
            const section = headers.get(edit);
            if (section === undefined) return true;
            const fresh = !createdSections.has(section);
            createdSections.add(section);
            return fresh;
          }),
        );
        steps.push(step);
      }
    }

    if (steps.length === 0) {
      return { parsed: true, changed: false, steps, notes, output: source, validated: true };
    }

    const output = applyEdits(source, lineSeparated(source, accepted, headers));
    const result: MigrationResult = {
      parsed: true,
      changed: output !== source,
      steps,
      notes,
      output,
      validated: true,
    };

    if (options.validate === false || !result.changed) return result;

    const before = countsOf(source, options.domain);
    const after = countsOf(output, options.domain);
    result.validation = {
      before: { errors: before.errors, warnings: before.warnings },
      after: { errors: after.errors, warnings: after.warnings },
    };

    if (!after.parses) {
      return {
        ...result,
        output: source,
        changed: false,
        validated: false,
        refusal: 'migration produced a file that no longer parses; rolled back',
      };
    }

    if (after.errors > before.errors) {
      const old = new Set(before.errorRules);
      const caused = after.errorRules.filter((rule) => !old.has(rule));
      return {
        ...result,
        output: source,
        changed: false,
        validated: false,
        // Naming the rules that appeared is what makes the refusal a to-do
        // list: `general/auth-requires-signing-key` says the file needs a
        // SIGNING_KEY before the endpoint rename can be safe.
        refusal: `migration would add ${after.errors - before.errors} error(s)${
          caused.length === 0 ? '' : `: ${caused.join(', ')}`
        }; rolled back`,
      };
    }

    return result;
  }

  /** The git-style diff a `--dry-run` prints, or `''` when there is nothing to do. */
  diff(path: string, source: string, options: MigrationOptions = {}, color = false): string {
    const result = this.run(source, options);
    if (!result.changed) return '';
    return formatUnifiedDiff(path, source, result.output, { color });
  }
}

/** {@link SchemaMigrationCodemod.run} without constructing one. */
export function migrateSchema(source: string, options: MigrationOptions = {}): MigrationResult {
  return new SchemaMigrationCodemod().run(source, options);
}
