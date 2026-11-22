/**
 * The migration rule registry.
 *
 * Ordered by how certain each rule is about what the author meant: an alias
 * first, because it only fires on a name that configures nothing, then the
 * deprecated-field rules. Ordering matters only when two rules reach for the
 * same statement — the engine keeps the first edit it sees and reports the
 * collision rather than applying both.
 *
 * A new rule file joins here; the codemod never enumerates rule names.
 */
import { DEPRECATED_FIELD_RULES } from './deprecatedFields.js';
import { LEGACY_ALIAS_RULES } from './legacyAliases.js';
import type { MigrationRule } from './types.js';

export type { MigrationAction, MigrationContext, MigrationRule, MigrationStep } from './types.js';
export { LEGACY_FIELD_ALIASES, aliasOf, aliasTarget } from './legacyAliases.js';
export type { FieldAlias } from './legacyAliases.js';
export { SUCCESSOR_FIELD } from './deprecatedFields.js';

export const MIGRATION_RULES: readonly MigrationRule[] = [
  ...LEGACY_ALIAS_RULES,
  ...DEPRECATED_FIELD_RULES,
];
