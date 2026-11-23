/**
 * CST-based orphaned key and dead table scanner.
 *
 * Two things make this a scanner rather than a second copy of the
 * section-scoped `unknown-field` rules. First, it reads the *concrete syntax
 * tree*, so a
 * finding knows the exact entry it points at and can be pruned without
 * re-rendering the file: quoting, attached comments and blank-line rhythm
 * survive, exactly as they do in `canonicalSortCodemod`. Second, it looks at
 * table *headers*, which a rule set scoped to the parsed value model never
 * sees — `[[CURRENCY]]` is invisible to a linter that only reads
 * `doc.CURRENCIES`, and the block it introduces silently configures nothing.
 *
 * The false-positive discipline is the point of the whole module. A
 * `stellar.toml` is a production config, and keys like `X_ACME_WEBHOOK` are how
 * anchors pass settings to their own software:
 *
 * - Nothing under an unrecognised table is reported. The table itself is
 *   reported once; flagging twelve keys below it would be twelve ways to say
 *   the same thing, and twelve times the pressure to disable the check.
 * - Vendor extensions (`X_…` by default) are accepted before any comparison.
 * - `--allow-key` accepts an exact name, a dotted path, a table name, or a
 *   `PREFIX_*` pattern, so a custom section can be blessed in one line.
 * - A suggestion is only offered when the spelling is a near-miss, using the
 *   same threshold as the preset typo hints in `src/levenshtein.ts`.
 *
 * Pruning then splits by whether the intent is known. A near-miss is a
 * misspelling, so it is *renamed* — deleting it would drop a setting the anchor
 * meant to configure. An unrecognised name with no near match is genuinely
 * orphaned, so it is removed. An unrecognised table with entries is never
 * deleted wholesale; that is a data-loss decision, not a cleanup.
 */
import { parseCst, printCst } from './parser.js';
import type { CstDocument, CstKeyValueEntry, CstTableEntry } from './parser.js';
import { SourcePositions } from './lexer.js';
import { nearestMatch } from '../levenshtein.js';
import { aliasOf, aliasTarget } from './codemodRules/legacyAliases.js';
import {
  KNOWN_CURRENCY_FIELDS,
  KNOWN_DOCUMENTATION_FIELDS,
  KNOWN_GLOBAL_FIELDS,
  KNOWN_PRINCIPAL_FIELDS,
  KNOWN_SERVER_FIELDS,
  KNOWN_VALIDATOR_FIELDS,
} from '../spec.js';

/**
 * Every table this project recognises, and the fields each one defines.
 *
 * Read from the SEP-1 catalogs in `src/spec.ts` rather than restated here, so
 * a field added to the spec is recognised by the scanner, the schema, and
 * autocompletion at the same commit.
 */
export const RECOGNIZED_SECTIONS: Readonly<Record<string, readonly string[]>> = {
  DOCUMENTATION: [...KNOWN_DOCUMENTATION_FIELDS],
  PRINCIPALS: [...KNOWN_PRINCIPAL_FIELDS],
  CURRENCIES: [...KNOWN_CURRENCY_FIELDS],
  VALIDATORS: [...KNOWN_VALIDATOR_FIELDS],
  SERVERS: [...KNOWN_SERVER_FIELDS],
};

/** Root-level fields, minus the names that are really table headers. */
const ROOT_FIELDS: readonly string[] = [...KNOWN_GLOBAL_FIELDS].filter(
  (name) => !(name in RECOGNIZED_SECTIONS),
);

/** Prefixes that mark a key as a deliberate vendor extension. */
export const DEFAULT_EXTENSION_PREFIXES: readonly string[] = ['X_'];

/** The command every "this is a schema move, not a cleanup" hint points at. */
const MIGRATE_COMMAND = 'stellar-toml-lint migrate';

export type OrphanKind = 'unknown-key' | 'unknown-table';

/** One thing in the file that matches no SEP-1 field and no allowance. */
export interface OrphanFinding {
  kind: OrphanKind;
  /** Table the key sits in; `''` for the document root. */
  section: string;
  /** Name as decoded from the file, quotes removed. */
  written: string;
  /** Dotted path as written, which is what `--allow-key` patterns match. */
  path: string;
  /** Canonical spelling, only when the name is a near-miss for one. */
  suggestion?: string;
  /**
   * Canonical dotted path for a legacy spelling that `migrate` owns.
   *
   * The distinction is what keeps `--prune-orphaned` from destroying a
   * setting: a typo is repaired by renaming it where it sits, while
   * `ORGANIZATION_NAME` is repaired by moving it into the table that defines
   * `ORG_NAME` — a schema change, not a cleanup. A finding that carries this
   * is never deleted.
   */
  migrateTo?: string;
  line: number;
  column: number;
  /** Index into `CstDocument.entries`, the unit `prune` acts on. */
  entryIndex: number;
  message: string;
}

export interface OrphanScanOptions {
  /**
   * Names, dotted paths, table names, or `PREFIX_*` patterns accepted as
   * intentional. Compared case-insensitively, because `x_acme_id` and
   * `X_ACME_ID` are the same key written twice.
   */
  allowKeys?: readonly string[];
  /** Extension prefixes; `X_` when omitted. */
  extensionPrefixes?: readonly string[];
}

export interface OrphanScanResult {
  /** Findings in source order. */
  findings: OrphanFinding[];
  /** False when the source has parse errors, which is why nothing was read. */
  parsed: boolean;
  /** How many would-be findings were dropped by an allowance. */
  allowed: number;
}

/** What `prune` did, per entry, so a report can say "renamed" not "fixed". */
export interface PruneAction {
  kind: 'removed' | 'renamed';
  section: string;
  written: string;
  suggestion?: string;
}

export interface OrphanPruneResult {
  output: string;
  parsed: boolean;
  changed: boolean;
  actions: PruneAction[];
  /** Why something reported was left on disk. */
  warnings: string[];
}

/**
 * Whether any spelling of the entry is on the allow-list.
 *
 * Every name a user might bless is tried: as written, as a bare leaf, as the
 * dotted path the file means (`DOCUMENTATION.ORG_NAME` for a key inside
 * `[DOCUMENTATION]` as much as for one written with a dotted key), and as the
 * canonical path a finding would be migrated to. A pattern ending in `*`
 * matches any of them by prefix, so blessing a vendor section is one line.
 */
function isAllowed(patterns: readonly string[], needles: readonly (string | undefined)[]): boolean {
  const candidates = needles
    .filter((needle): needle is string => needle !== undefined)
    .map((needle) => needle.toLowerCase());
  for (const pattern of patterns) {
    const want = pattern.toLowerCase();
    if (want.length === 0) continue;
    const glob = want.endsWith('*') ? want.slice(0, -1) : undefined;
    for (const needle of candidates) {
      if (want === needle) return true;
      if (glob !== undefined && glob.length > 0 && needle.startsWith(glob)) return true;
    }
  }
  return false;
}

function hasExtensionPrefix(name: string, prefixes: readonly string[]): boolean {
  const upper = name.toUpperCase();
  return prefixes.some((prefix) => upper.startsWith(prefix.toUpperCase()));
}

/** The table a section path names, for a key written as `TABLE.field`. */
function sectionOfDottedKey(path: string): string {
  const head = path.split('.')[0] ?? path;
  return head.toUpperCase();
}

/** Fields defined for a section, or `undefined` when the section is unknown. */
function fieldsFor(section: string): readonly string[] | undefined {
  return RECOGNIZED_SECTIONS[section.toUpperCase()];
}

/** A plural table name reduced to the form an author forgets the `S` on. */
function singularStem(name: string): string {
  return name.toUpperCase().endsWith('S') ? name.slice(0, -1) : name;
}

/**
 * The section a written table name was meant to be, allowing for the one
 * mistake the edit distance cannot see: `[[CURRENCY]]` is three edits from
 * `[[CURRENCIES]]`, which is outside the threshold for a name that short, yet
 * is what anchors type most often. Folding both sides to a singular stem
 * before comparing keeps the threshold honest about the plural itself.
 */
function nearestSectionMatch(name: string): string | undefined {
  const sections = Object.keys(RECOGNIZED_SECTIONS);
  const direct = nearestMatch(sections, name);
  if (direct !== undefined) return direct;

  const stems = new Map<string, string>();
  for (const section of sections) {
    const stem = singularStem(section).toUpperCase();
    if (!stems.has(stem)) stems.set(stem, section);
  }
  const stem = nearestMatch(stems.keys(), singularStem(name).toUpperCase());
  return stem === undefined ? undefined : stems.get(stem);
}

/**
 * The table a root-level key was meant to sit in, exact spelling first and
 * near-miss second.
 *
 * `ORG_TWITTER` at the document root and `ORG_TWTTER` beside it are both
 * fields of `[DOCUMENTATION]` — one spelled right, one not. Either way the
 * file is asking for a schema move, so the scanner hands it to `migrate`
 * instead of offering it to `--prune-orphaned`, which would delete a setting
 * the anchor meant to publish.
 *
 * Only `[DOCUMENTATION]` is searched, because that is the only table the
 * codemod can move a root key into. A root-level `code` is a currency field
 * written in the wrong place, and pointing the author at `migrate` for it
 * would be a promise the tool cannot keep.
 */
function homeOfMisplacedKey(
  name: string,
): { section: string; field: string; exact: boolean } | undefined {
  const upper = name.toUpperCase();
  const sections = Object.entries(RECOGNIZED_SECTIONS).filter(
    ([section]) => section.toUpperCase() === 'DOCUMENTATION',
  );

  for (const [section, fields] of sections) {
    const exact = fields.find((field) => field.toUpperCase() === upper);
    if (exact !== undefined) return { section, field: exact, exact: true };
  }
  for (const [section, fields] of sections) {
    const near = nearestMatch(fields, name);
    if (near !== undefined) return { section, field: near, exact: false };
  }
  return undefined;
}

/** How a name relates to the canonical path a schema move would put it at. */
type MoveKind = 'legacy' | 'exact' | 'near-miss';

function message(
  kind: OrphanKind,
  written: string,
  suggestion?: string,
  migrateTo?: string,
  move?: MoveKind,
): string {
  if (migrateTo !== undefined) {
    const dot = migrateTo.lastIndexOf('.');
    const sectionName = migrateTo.slice(0, dot);
    const fieldName = migrateTo.slice(dot + 1);
    const command = `\`${MIGRATE_COMMAND}\``;
    if (move === 'legacy') {
      return `${written} is a legacy spelling of ${migrateTo}; run ${command} to move it`;
    }
    if (move === 'exact') {
      return `${written} belongs in [${sectionName}]; run ${command} to move it`;
    }
    return `${written} belongs in ${migrateTo}; run ${command} once it is spelled ${fieldName}`;
  }
  if (kind === 'unknown-table') {
    return suggestion === undefined
      ? `[[${written}]] / [${written}] matches no table SEP-1 defines`
      : `[${written}] is not a table SEP-1 defines; the closest is [${suggestion}]`;
  }
  return suggestion === undefined
    ? `${written} configures nothing any SEP defines`
    : `${written} is not a field any SEP defines; the closest is ${suggestion}`;
}

/**
 * Walks the CST and reports keys and table headers that match no known SEP
 * field, with a near-miss suggestion when the spelling looks like a typo.
 */
export class OrphanedKeyScanner {
  scan(source: string, options: OrphanScanOptions = {}): OrphanScanResult {
    const document = parseCst(source);
    if (document.errors.length > 0) {
      return { findings: [], parsed: false, allowed: 0 };
    }
    const { findings, allowed } = this.walk(document, options);
    return { findings, parsed: true, allowed };
  }

  /**
   * Findings for an already-parsed document, so a caller that has the tree for
   * other reasons does not pay for a second parse.
   */
  findIn(document: CstDocument, options: OrphanScanOptions = {}): OrphanFinding[] {
    return this.walk(document, options).findings;
  }

  private walk(
    document: CstDocument,
    options: OrphanScanOptions,
  ): { findings: OrphanFinding[]; allowed: number } {
    const allow = options.allowKeys ?? [];
    const prefixes = options.extensionPrefixes ?? DEFAULT_EXTENSION_PREFIXES;
    const positions = new SourcePositions(document.source);
    const findings: OrphanFinding[] = [];
    let allowed = 0;
    /** Table names already reported, so the keys under them stay quiet. */
    const deadSections = new Set<string>();
    let section = '';

    document.entries.forEach((entry, index) => {
      const position = positions.at(entry.start);

      if (entry.kind === 'table' || entry.kind === 'array-table') {
        const table = entry as CstTableEntry;
        if (table.key === null || table.errors.length > 0) return;
        const name = table.key.path.toUpperCase();
        section = name;
        deadSections.delete(name);
        if (fieldsFor(name) !== undefined) return;
        if (isAllowed(allow, [table.key.path, name])) {
          allowed++;
          return;
        }
        const suggestion = nearestSectionMatch(name);
        findings.push({
          kind: 'unknown-table',
          section: '',
          written: table.key.path,
          path: table.key.path,
          ...(suggestion === undefined ? {} : { suggestion }),
          line: position.line,
          column: position.column,
          entryIndex: index,
          message: message('unknown-table', table.key.path, suggestion),
        });
        deadSections.add(name);
        return;
      }

      const keyValue = entry as CstKeyValueEntry;
      if (keyValue.key === null || keyValue.errors.length > 0) return;
      const path = keyValue.key.path;
      const leaf = path.includes('.') ? sectionOfDottedKey(path) : path.toUpperCase();
      const ownSection = path.includes('.') ? sectionOfDottedKey(path) : section;

      // A key written as `DOCUMENTATION.ORG_NAME` is the same field as the one
      // inside `[DOCUMENTATION]`, and a key under a table already reported is
      // covered by that finding.
      if (path.includes('.')) {
        const known = fieldsFor(ownSection);
        if (known === undefined) return;
        const name = path.slice(path.lastIndexOf('.') + 1).toUpperCase();
        if (hasExtensionPrefix(name, prefixes)) return;
        if (isAllowed(allow, [path, name, `${ownSection}.${path}`])) {
          allowed++;
          return;
        }
        const field = path.slice(path.lastIndexOf('.') + 1);
        if (known.some((candidate) => candidate.toUpperCase() === name)) return;
        const legacy = aliasOf(field);
        const suggestion =
          nearestMatch(known, field) ??
          (legacy !== undefined && legacy.section.toUpperCase() === ownSection.toUpperCase()
            ? legacy.field
            : undefined);
        findings.push({
          kind: 'unknown-key',
          section: ownSection,
          written: field,
          path,
          ...(suggestion === undefined ? {} : { suggestion }),
          line: position.line,
          column: position.column,
          entryIndex: index,
          message: message('unknown-key', field, suggestion),
        });
        return;
      }

      if (hasExtensionPrefix(leaf, prefixes)) return;
      if (deadSections.has(ownSection)) return;
      if (section !== '' && fieldsFor(section) === undefined) {
        // Inside an unrecognised table: reported once at the header.
        return;
      }

      const known = section === '' ? ROOT_FIELDS : (fieldsFor(section) ?? []);
      if (known.some((candidate) => candidate.toUpperCase() === leaf)) return;

      // Two names are not orphans but schema mistakes, and the codemod owns
      // both: a documented legacy spelling, and a field written at the root
      // instead of inside the table that defines it. Carrying `migrateTo` is
      // what keeps `--prune-orphaned` from deleting a setting the anchor meant
      // to publish, since the repair is a move, not a rename in place.
      const alias = aliasOf(path);
      const aliasInPlace =
        alias !== undefined && alias.section.toUpperCase() === section.toUpperCase();
      const misplaced =
        alias === undefined && section === '' ? homeOfMisplacedKey(path) : undefined;
      let migrateTo: string | undefined;
      let move: MoveKind | undefined;
      if (alias !== undefined && !aliasInPlace) {
        migrateTo = aliasTarget(alias);
        move = 'legacy';
      } else if (misplaced !== undefined) {
        migrateTo = `${misplaced.section}.${misplaced.field}`;
        move = misplaced.exact ? 'exact' : 'near-miss';
      }

      if (
        isAllowed(allow, [path, leaf, migrateTo, section === '' ? undefined : `${section}.${path}`])
      ) {
        allowed++;
        return;
      }

      const candidate =
        nearestMatch(known, path) ??
        (alias !== undefined ? alias.field : undefined) ??
        misplaced?.field;
      // A field written at the root in its correct spelling is told where it
      // belongs rather than being offered a rename to the word it already has.
      const suggestion =
        candidate !== undefined && candidate.toUpperCase() === path.toUpperCase()
          ? undefined
          : candidate;

      findings.push({
        kind: 'unknown-key',
        section,
        written: path,
        path,
        suggestion,
        migrateTo,
        line: position.line,
        column: position.column,
        entryIndex: index,
        message: message('unknown-key', path, suggestion, migrateTo, move),
      });
    });

    return { findings, allowed };
  }
}

/**
 * Applies the scanner's suggestions to a file: near-miss spellings are renamed,
 * anything else that matched no schema is removed with the comments attached to
 * it, and a table nobody recognises is left alone when it still holds data.
 *
 * A file that does not parse is returned untouched — pruning a document whose
 * structure the parser had to guess at is how a cleanup becomes a corruption.
 */
export function pruneOrphans(source: string, options: OrphanScanOptions = {}): OrphanPruneResult {
  const document = parseCst(source);
  if (document.errors.length > 0) {
    return {
      output: source,
      parsed: false,
      changed: false,
      actions: [],
      warnings: ['file does not parse; nothing was pruned'],
    };
  }

  const findings = new OrphanedKeyScanner().findIn(document, options);
  const actions: PruneAction[] = [];
  const warnings: string[] = [];
  const removed: number[] = [];

  for (const finding of findings) {
    const entry = document.entries[finding.entryIndex];
    if (entry === undefined) continue;

    if (finding.migrateTo !== undefined) {
      const command = `\`${MIGRATE_COMMAND}\``;
      const suggestion = finding.suggestion;
      // `migrate` moves a statement by name, so it can act on a documented
      // alias or a correctly spelled field in the wrong place. A misspelling
      // of one is beyond it, and a file left in that state has no exit: so
      // prune repairs the half it owns — the spelling — and the warning then
      // names a move `migrate` will actually make.
      if (suggestion === undefined || aliasOf(finding.written) !== undefined) {
        warnings.push(
          `${finding.written}: belongs in ${finding.migrateTo}, which is a schema move — run ${command}`,
        );
        continue;
      }
      if (fieldNamed(document, finding.section, suggestion, finding.entryIndex)) {
        warnings.push(`${finding.written}: ${suggestion} is already set, left in place`);
        continue;
      }
      renameKey(document, finding.entryIndex, suggestion);
      actions.push({
        kind: 'renamed',
        section: finding.section,
        written: finding.written,
        suggestion,
      });
      warnings.push(
        `${suggestion}: belongs in ${finding.migrateTo}, which is a schema move — run ${command} to move it`,
      );
      continue;
    }

    if (finding.kind === 'unknown-table') {
      if (finding.suggestion === undefined) {
        warnings.push(`${finding.written}: no table to rename it to, left in place`);
        continue;
      }
      if (tableNamed(document, finding.suggestion, finding.entryIndex)) {
        warnings.push(
          `${finding.written}: [${finding.suggestion}] is already in the file, left in place`,
        );
        continue;
      }
      if (sectionHasBody(document, finding.entryIndex)) {
        renameTable(document, finding.entryIndex, finding.suggestion);
        actions.push({
          kind: 'renamed',
          section: '',
          written: finding.written,
          suggestion: finding.suggestion,
        });
        continue;
      }
      removed.push(finding.entryIndex);
      actions.push({ kind: 'removed', section: '', written: finding.written });
      continue;
    }

    if (finding.suggestion !== undefined) {
      if (fieldNamed(document, finding.section, finding.suggestion, finding.entryIndex)) {
        warnings.push(
          `${finding.written}: ${finding.section === '' ? '' : `[${finding.section}] `}${finding.suggestion} is already set, left in place`,
        );
        continue;
      }
      renameKey(document, finding.entryIndex, finding.suggestion);
      actions.push({
        kind: 'renamed',
        section: finding.section,
        written: finding.written,
        suggestion: finding.suggestion,
      });
      continue;
    }
    removed.push(finding.entryIndex);
    actions.push({ kind: 'removed', section: finding.section, written: finding.written });
  }

  // Descending, so an earlier splice never shifts a later index. The entry's
  // `leading` trivia goes with it, which is what removes the comment that
  // documented the key nobody recognises any more.
  for (const index of [...removed].sort((a, b) => b - a)) {
    document.entries.splice(index, 1);
  }

  const output = printCst(document);
  return {
    output,
    parsed: true,
    changed: output !== source,
    actions,
    warnings,
  };
}

/** {@link OrphanedKeyScanner.scan} without constructing one. */
export function detectOrphans(source: string, options: OrphanScanOptions = {}): OrphanScanResult {
  return new OrphanedKeyScanner().scan(source, options);
}

/**
 * Whether another header already uses `name`.
 *
 * Renaming `[[CURRENCY]]` to `[[CURRENCIES]]` in a file that already has a
 * `[[CURRENCIES]]` block would merge two anchors' worth of settings into one
 * entry, so the guess is dropped instead of applied.
 */
function tableNamed(document: CstDocument, name: string, exceptIndex: number): boolean {
  const want = name.toUpperCase();
  return document.entries.some(
    (entry, index) =>
      index !== exceptIndex &&
      (entry.kind === 'table' || entry.kind === 'array-table') &&
      entry.key !== null &&
      entry.key.path.toUpperCase() === want,
  );
}

/**
 * Whether `section` already defines `name` on some other entry, counting both
 * the in-table and the dotted (`TABLE.field`) spelling of the same key.
 */
function fieldNamed(
  document: CstDocument,
  section: string,
  name: string,
  exceptIndex: number,
): boolean {
  const want = name.toUpperCase();
  const owner = section.toUpperCase();
  let current = '';
  return document.entries.some((entry, index) => {
    if (entry.kind === 'table' || entry.kind === 'array-table') {
      if (entry.key !== null) current = entry.key.path.toUpperCase();
      return false;
    }
    const key = (entry as CstKeyValueEntry).key;
    if (index === exceptIndex || key === null) return false;
    const path = key.path.toUpperCase();
    const head = path.includes('.') ? path.slice(0, path.indexOf('.')) : current;
    const leaf = path.slice(path.lastIndexOf('.') + 1);
    return head === owner && leaf === want;
  });
}

/** Whether a table header owns at least one key-value entry before the next header. */
function sectionHasBody(document: CstDocument, headerIndex: number): boolean {
  for (let index = headerIndex + 1; index < document.entries.length; index++) {
    const entry = document.entries[index];
    if (entry === undefined) continue;
    if (entry.kind === 'table' || entry.kind === 'array-table') return false;
    return true;
  }
  return false;
}

/** Rewrites the last segment of a key, keeping the quoting style it was written in. */
function renameKey(document: CstDocument, entryIndex: number, to: string): void {
  const entry = document.entries[entryIndex];
  if (entry === undefined || entry.kind !== 'key-value') return;
  const key = (entry as CstKeyValueEntry).key;
  const segment = key?.segments.at(-1);
  if (key === null || key === undefined || segment === undefined) return;
  segment.text = segment.quoted ? `${segment.text[0] ?? '"'}${to}${segment.text.slice(-1)}` : to;
  segment.name = to;
  key.path = key.segments.map((part) => part.name).join('.');
}

/** Renames a `[table]` / `[[table]]` header, which is where a typo'd section lives. */
function renameTable(document: CstDocument, entryIndex: number, to: string): void {
  const entry = document.entries[entryIndex];
  if (entry === undefined) return;
  const key = (entry as CstTableEntry).key;
  const segment = key?.segments.at(-1);
  if (key === null || key === undefined || segment === undefined) return;
  segment.text = segment.quoted ? `"${to}"` : to;
  segment.name = to;
  key.path = key.segments.map((part) => part.name).join('.');
}
