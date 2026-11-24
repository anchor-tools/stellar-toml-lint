/**
 * The migration rules the codemod runs, and the shape they share.
 *
 * A rule is a matcher: it looks at the parsed document and says what would
 * change, in offsets, without touching anything. The engine in
 * `../migrationCodemod.js` owns parsing, statement geometry, overlap
 * detection, and post-migration validation, so a rule only has to answer two
 * questions — does this file still contain the thing I know how to fix, and
 * what is the fix?
 *
 * Every rule here is derived from something the linter already asserts —
 * `DEPRECATED_FIELDS`, `general/deprecated-field`, the field catalogs in
 * `src/spec.ts` — so a migration cannot call a field legacy unless the project
 * has already said so in a rule a user can read. The one exception is
 * `legacyAliases.ts`, whose list is spelled out because no data source in this
 * repository knows what an anchor typed five years ago.
 */
import type { CstDocument, CstKeyValueEntry } from '../parser.js';
import type { OffsetTextEdit } from '../../fix.js';

/** What a step does to the file, in the words a reviewer sees in `--dry-run`. */
export type MigrationAction = 'rename-key' | 'rewrite-value' | 'move-into-table';

export interface MigrationStep {
  /** {@link MigrationRule.id} that produced this step. */
  rule: string;
  /** Dotted path the step touches, as written. */
  path: string;
  action: MigrationAction;
  /** One line, e.g. `AUTH_SERVER → WEB_AUTH_ENDPOINT (the SEP-3 … is deprecated)`. */
  description: string;
  /** Edits into the *unmodified* source; the engine refuses overlapping steps. */
  edits: OffsetTextEdit[];
}

export interface MigrationContext {
  /** The parsed document. Rules never mutate it. */
  document: CstDocument;
  /**
   * The root-level entry written as `name = …`, matched case-insensitively.
   *
   * "Root" means before the first table header, which is what makes a
   * deprecated *global* field unconfusable with the same word inside
   * `[DOCUMENTATION]`.
   */
  rootKey(name: string): CstKeyValueEntry | undefined;
  /** Whether `field` is set in `section` (`''` for the root), so a move never creates a duplicate. */
  hasField(section: string, field: string): boolean;
  /**
   * Edits that cut a statement out of where it is and re-insert it inside
   * `section`, optionally renamed.
   *
   * The statement moves as *text*, byte for byte — quoting, spacing, its
   * trailing comment, and the comments attached above it all travel with it —
   * and `section`'s header is created at the end of the file when the document
   * has none. Inserting a header anywhere else would re-parent every root key
   * written after it.
   */
  moveStatement(
    entry: CstKeyValueEntry,
    options: { section: string; renameTo?: string },
  ): OffsetTextEdit[] | undefined;
  /** Where a statement's value is, and the text written there, quotes included. */
  valueSpan(entry: CstKeyValueEntry): { start: number; end: number; text: string } | undefined;
  /**
   * Records why a rule that matched did nothing, surfaced next to the steps.
   * A silent skip is how a migration ends up half-done without anyone
   * noticing.
   */
  note(message: string): void;
}

export interface MigrationRule {
  /** Stable identifier, printed in the plan and in `--json` output. */
  id: string;
  /** Why the change is safe to make automatically. */
  reason: string;
  /** Steps for this document; empty when the rule does not apply. */
  plan(context: MigrationContext): MigrationStep[];
}
