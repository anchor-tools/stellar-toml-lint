/**
 * Field names anchors have been seen writing for a field SEP-1 spells
 * differently.
 *
 * This is the one migration table that is not derived from something the
 * linter already asserts, because nothing in this repository records what a
 * `stellar.toml` looked like before the `[DOCUMENTATION]` table was written
 * down. Two consequences, both deliberate:
 *
 * - The list is short, and every entry names a field `src/spec.ts` already
 *   catalogues, so it can be reviewed line by line rather than trusted
 *   wholesale. Adding to it is a specification claim.
 * - It is data, not code: the orphan scanner reads it for its "did you mean"
 *   hints (#545) and the codemod reads it for rewrites (#537), so a name added
 *   here stops being reported as an orphan in the same commit that teaches the
 *   migration what to do about it.
 */
import type { MigrationContext, MigrationRule, MigrationStep } from './types.js';

/** A legacy spelling and the field it stands for. */
export interface FieldAlias {
  /** Table the canonical field lives in; `''` is the document root. */
  section: string;
  /** Canonical field name as SEP-1 writes it. */
  field: string;
}

/**
 * Legacy spellings, keyed by the name as written and matched
 * case-insensitively. Both spellings of "organization" are here because both
 * were typed into real config files.
 */
export const LEGACY_FIELD_ALIASES: Readonly<Record<string, FieldAlias>> = {
  ORGANIZATION_NAME: { section: 'DOCUMENTATION', field: 'ORG_NAME' },
  ORGANISATION_NAME: { section: 'DOCUMENTATION', field: 'ORG_NAME' },
};

/** Dotted canonical path for an alias, e.g. `DOCUMENTATION.ORG_NAME`. */
export function aliasTarget(alias: FieldAlias): string {
  return alias.section === '' ? alias.field : `${alias.section}.${alias.field}`;
}

/**
 * The alias for a name as written, case-insensitively, or `undefined`.
 *
 * The scanner uses this to tell a typo apart from a legacy spelling: a typo is
 * repaired by renaming it in place, while an alias is repaired by
 * `stellar-toml-lint migrate`, which knows which table the field belongs in.
 */
export function aliasOf(name: string): FieldAlias | undefined {
  return LEGACY_FIELD_ALIASES[name.toUpperCase()];
}

/**
 * Moves a legacy alias onto the canonical field SEP-1 defines, renaming it on
 * the way in.
 *
 * Only the document-root form is migrated. An alias that already sits inside
 * its own table is a one-word rename with no structure to respect, which is
 * the orphan scanner's `--prune-orphaned` job, not a schema migration.
 */
const legacyAliases: MigrationRule = {
  id: 'legacy-field-alias',
  reason: 'the name is a legacy spelling of a field SEP-1 defines differently',
  plan(context: MigrationContext): MigrationStep[] {
    const steps: MigrationStep[] = [];

    for (const [legacy, alias] of Object.entries(LEGACY_FIELD_ALIASES)) {
      const entry = context.rootKey(legacy);
      if (entry === undefined) continue;
      if (context.hasField(alias.section, alias.field)) {
        context.note(
          `${legacy}: ${aliasTarget(alias)} is already set, left ${legacy} in place for you to delete`,
        );
        continue;
      }
      const edits = context.moveStatement(entry, {
        section: alias.section,
        renameTo: alias.field,
      });
      if (edits === undefined) continue;

      steps.push({
        rule: 'legacy-field-alias',
        path: legacy,
        action: 'move-into-table',
        description: `${legacy} moved into [${alias.section}] as ${alias.field}`,
        edits,
      });
    }

    return steps;
  },
};

/** The alias rule, exported for the registry. */
export const LEGACY_ALIAS_RULES: readonly MigrationRule[] = [legacyAliases];
