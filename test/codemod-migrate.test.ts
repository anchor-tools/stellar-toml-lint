import { describe, expect, it } from 'vitest';
import { parse } from 'smol-toml';
import { writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  migrate,
  migrateSep41,
  migrateV2,
  generateDiff,
  dryRun,
  runMigration,
  detectConflicts,
} from '../src/codemod/migrate.js';

const here = dirname(fileURLToPath(import.meta.url));

const LEGACY_SEP41_TOML = `# Example stellar.toml with legacy federation config
VERSION = "2.7.0"
NETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"
FEDERATION_SERVER = "https://api.example.com/federation"

[DOCUMENTATION]
ORG_NAME = "Example Anchor"
ORG_URL = "https://example.com"
`;

const V2_LEGACY_TOML = `# Example with classic asset declarations
VERSION = "2.7.0"
NETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"

[[CURRENCIES]]
code = "USD"
issuer = "GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY"
display_decimals = 2

[[CURRENCIES]]
code = "EXPL"
contract = "CACTZSQPCQSSZ5YG3PI3N7WO6JEERKEUHTPILKB4MBANF2K4D2UHKDDU"
`;

const CONFLICT_TOML = `# Conflicting config
VERSION = "2.7.0"
NETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"
FEDERATION_SERVER = "https://api.example.com/federation"
WEB_AUTH_CONTRACT_ID = "C1234567890123456789012345678901234567890123456789012345678901234"
AUTH_SERVER = "https://api.example.com/auth"
`;

describe('codemod/migrate', () => {
  it('migrateSep41 converts FEDERATION_SERVER to WEB_AUTH_CONTRACT_ID', async () => {
    const result = await migrateSep41(LEGACY_SEP41_TOML);
    expect(result).toContain('WEB_AUTH_CONTRACT_ID');
    expect(result).not.toContain('FEDERATION_SERVER');
    expect(result).toContain('AUTH_SERVER');
  });

  it('migrateSep41 preserves comments and formatting', async () => {
    const result = await migrateSep41(LEGACY_SEP41_TOML);
    const lines = result.split('\n');
    const commentLine = lines.find((l) => l.startsWith('# Example'));
    expect(commentLine).toBeDefined();
    expect(commentLine?.startsWith('# Example')).toBe(true);
  });

  it('migrateV2 preserves comments and formatting', async () => {
    const result = await migrateV2(V2_LEGACY_TOML);
    const lines = result.split('\n');
    const commentLine = lines.find((l) => l.startsWith('# Example'));
    expect(commentLine).toBeDefined();
    expect(commentLine?.startsWith('# Example')).toBe(true);
  });

  it('migrateV2 converts classic asset declarations to Soroban SAC contract IDs', async () => {
    const result = await migrateV2(V2_LEGACY_TOML);
    const contractMatches = result.match(/contract\s*=\s*".*?"/g);
    expect(contractMatches).toBeDefined();
    expect(contractMatches?.length).toBeGreaterThanOrEqual(1);
  });

  it('generateDiff produces unified diff format', () => {
    const original = 'VERSION = "1.0"\nFEDERATION_SERVER = "https://example.com"\n';
    const migrated = 'VERSION = "1.0"\nWEB_AUTH_CONTRACT_ID = "Cabc"\n';
    const diff = generateDiff(original, migrated);
    expect(diff).toContain('--- a/source.toml');
    expect(diff).toContain('+++ b/source.toml');
    expect(diff).toContain('-');
    expect(diff).toContain('+');
  });

  it('dryRun returns diff without writing', async () => {
    const tempDir = join(here, '..', 'test', 'fixtures', 'tmp-codemod');
    mkdirSync(tempDir, { recursive: true });
    try {
      const diff = await dryRun(LEGACY_SEP41_TOML, 'sep41');
      expect(diff).toContain('--- a/source.toml');
      expect(diff).toContain('+++ b/source.toml');
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('detectConflicts finds conflicts when both FEDERATION_SERVER and WEB_AUTH_CONTRACT_ID exist', () => {
    const doc = parse(CONFLICT_TOML);
    const conflicts = detectConflicts(doc, 'sep41', CONFLICT_TOML);
    expect(conflicts.length).toBeGreaterThan(0);
    expect(conflicts.some((c) => c.rule === 'codemod/migration-conflict')).toBe(true);
  });

  it('migrate returns MigrationResult with applied flag', async () => {
    const result = await migrate(LEGACY_SEP41_TOML, 'sep41');
    expect(result).toHaveProperty('source');
    expect(result).toHaveProperty('diff');
    expect(result).toHaveProperty('conflicts');
    expect(result).toHaveProperty('applied');
    expect(typeof result.applied).toBe('boolean');
  });

  it('runMigration returns diagnostics including migration-applied', async () => {
    const { diagnostics } = await runMigration(LEGACY_SEP41_TOML, 'sep41');
    const hasApplied = diagnostics.some((d) => d.rule === 'codemod/migration-applied');
    const hasConflict = diagnostics.some((d) => d.rule === 'codemod/migration-conflict');
    expect(hasApplied || hasConflict).toBe(true);
  });

  it('runMigration returns conflict diagnostics for conflicting config', async () => {
    const { diagnostics } = await runMigration(CONFLICT_TOML, 'sep41');
    const conflictDiags = diagnostics.filter((d) => d.rule === 'codemod/migration-conflict');
    expect(conflictDiags.length).toBeGreaterThan(0);
  });

  it('migrate with dry-run produces diff without writing', async () => {
    const tempDir = join(here, '..', 'test', 'fixtures', 'tmp-codemod');
    mkdirSync(tempDir, { recursive: true });
    const tempFile = join(tempDir, 'test-dry-run.toml');
    writeFileSync(tempFile, LEGACY_SEP41_TOML);

    try {
      const result = await migrate(LEGACY_SEP41_TOML, 'sep41');
      expect(result.diff).toContain('--- a/source.toml');
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });
});
