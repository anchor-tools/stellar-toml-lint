/**
 * Codemod entry point.
 *
 * `migrate.ts` carries the `--migrate` targets; `federation-upgrade.ts` carries
 * the standalone `--migrate-federation` transform. Re-exporting both here gives
 * the CLI and embedders one import path, so adding a codemod does not require
 * touching every call site.
 */

export {
  migrate,
  migrateSep41,
  migrateV2,
  detectConflicts,
  generateDiff,
  dryRun,
  runMigration,
} from './migrate.js';
export type { MigrationConflict, MigrationResult, MigrationTarget } from './migrate.js';

export {
  upgradeFederationDeclaration,
  canonicalFederationServer,
  legacyLookupFlags,
  federationUpgradeRules,
  FEDERATION_UPGRADE_APPLIED_RULE,
  FEDERATION_UPGRADE_SKIPPED_RULE,
  FEDERATION_SERVER_INVALID_RULE,
  FEDERATION_SERVER_UNREACHABLE_RULE,
} from './federation-upgrade.js';
export type {
  FederationLookupFlags,
  FederationUpgradeOptions,
  FederationUpgradeResult,
} from './federation-upgrade.js';
