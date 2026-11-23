import { afterAll, describe, expect, it } from 'vitest';
import { spawn } from 'node:child_process';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { SchemaMigrationCodemod, migrateSchema } from '../src/cst/migrationCodemod.js';
import {
  LEGACY_FIELD_ALIASES,
  MIGRATION_RULES,
  SUCCESSOR_FIELD,
} from '../src/cst/codemodRules/index.js';
import { DEPRECATED_FIELDS, KNOWN_GLOBAL_FIELDS, KNOWN_DOCUMENTATION_FIELDS } from '../src/spec.js';
import { parseCst } from '../src/cst/parser.js';
import { lint } from '../src/lint.js';

const run = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, '..', 'dist', 'cli.js');

const SIGNING_KEY = 'GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS';

/** The identity of each step: which rule did what to which path. */
function planOf(result: { steps: { rule: string; action: string; path: string }[] }): string[] {
  return result.steps.map((step) => `${step.rule}:${step.action}:${step.path}`);
}

function lines(...text: string[]): string {
  return `${text.join('\n')}\n`;
}

/**
 * A `stellar.toml` as an anchor wrote one in 2019: the legacy organization
 * name at the root, the deprecated SEP-3 and SEP-6 servers, a plain-HTTP
 * federation endpoint, and the documentation fields sitting outside their
 * table.
 */
const LEGACY = lines(
  '# Acme anchor config, written 2019.',
  'VERSION = "1.0.0"',
  'NETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"',
  'ORGANIZATION_NAME = "Acme Cash"',
  'ORG_URL = "https://acme.example"',
  'FEDERATION_SERVER = "http://federation.acme.example/federation"',
  `AUTH_SERVER = "https://auth.acme.example/auth"`,
  'DEPOSIT_SERVER = "https://deposit.acme.example/sep6"',
  `SIGNING_KEY = "${SIGNING_KEY}"`,
);

describe('migration rule registry', () => {
  it('names a successor for every field the linter deprecates', () => {
    for (const deprecated of Object.keys(DEPRECATED_FIELDS)) {
      const successor = SUCCESSOR_FIELD[deprecated];
      expect(successor, deprecated).toBeDefined();
      expect(KNOWN_GLOBAL_FIELDS.has(successor ?? ''), successor).toBe(true);
    }
  });

  it('maps every legacy alias onto a field SEP-1 actually defines', () => {
    for (const [legacy, alias] of Object.entries(LEGACY_FIELD_ALIASES)) {
      expect([...KNOWN_DOCUMENTATION_FIELDS], legacy).toContain(alias.field);
    }
  });

  it('has at least one test fixture that fires every rule', () => {
    const sources = [
      LEGACY,
      lines('VERSION = "1.0.0"', 'ORGANIZATION_NAME = "Acme"'),
      lines('ORG_URL = "https://acme.example"'),
      lines('FEDERATION_SERVER = "http://acme.example/fed"'),
      lines('DEPOSIT_SERVER = "https://acme.example"', `SIGNING_KEY = "${SIGNING_KEY}"`),
    ];
    const fired = new Set(
      sources.flatMap((source) => migrateSchema(source).steps.map((step) => step.rule)),
    );
    for (const rule of MIGRATION_RULES) {
      expect(fired.has(rule.id), rule.id).toBe(true);
    }
  });
});

describe('legacy-field-alias', () => {
  it('moves ORGANIZATION_NAME into [DOCUMENTATION] as ORG_NAME', () => {
    const result = migrateSchema(lines('NETWORK_PASSPHRASE = "x"', 'ORGANIZATION_NAME = "Acme"'));

    expect(planOf(result)).toEqual(['legacy-field-alias:move-into-table:ORGANIZATION_NAME']);
    expect(result.output).toBe(
      lines('NETWORK_PASSPHRASE = "x"', '', '[DOCUMENTATION]', 'ORG_NAME = "Acme"'),
    );
  });

  it('accepts the British spelling too', () => {
    const result = migrateSchema(lines('ORGANISATION_NAME = "Acme Ltd"'));
    expect(result.output).toContain('ORG_NAME = "Acme Ltd"');
  });

  it('carries the comment that documents the field with it', () => {
    const result = migrateSchema(
      lines('# The name shown in the wallet.', 'ORGANIZATION_NAME = "Acme"', 'VERSION = "1.0.0"'),
    );
    expect(result.output).toBe(
      lines(
        'VERSION = "1.0.0"',
        '',
        '[DOCUMENTATION]',
        '# The name shown in the wallet.',
        'ORG_NAME = "Acme"',
      ),
    );
  });

  it('leaves the alias in place when the canonical field is already set', () => {
    const source = lines('ORGANIZATION_NAME = "Old"', '[DOCUMENTATION]', 'ORG_NAME = "New"');
    const result = migrateSchema(source);

    expect(result.changed).toBe(false);
    expect(result.notes).toContain(
      'ORGANIZATION_NAME: DOCUMENTATION.ORG_NAME is already set, left ORGANIZATION_NAME in place for you to delete',
    );
  });

  it('does not touch an alias already inside its own table', () => {
    const result = migrateSchema(lines('[DOCUMENTATION]', 'ORGANIZATION_NAME = "Acme"'));
    expect(result.steps).toEqual([]);
  });
});

describe('deprecated-root-field', () => {
  it('renames the key and leaves the value and spacing alone', () => {
    const source = lines(
      'AUTH_SERVER   =   "https://auth.acme.example/auth"',
      `SIGNING_KEY = "${SIGNING_KEY}"`,
    );
    const result = migrateSchema(source);

    expect(planOf(result)).toEqual(['deprecated-root-field:rename-key:AUTH_SERVER']);
    expect(result.output).toBe(
      lines(
        'WEB_AUTH_ENDPOINT   =   "https://auth.acme.example/auth"',
        `SIGNING_KEY = "${SIGNING_KEY}"`,
      ),
    );
  });

  it('says what the migration still cannot supply', () => {
    const source = lines(
      `SIGNING_KEY = "${SIGNING_KEY}"`,
      'AUTH_SERVER = "https://auth.acme.example/auth"',
    );
    const step = migrateSchema(source).steps.find((entry) => entry.path === 'AUTH_SERVER');

    expect(step?.description).toContain('the SEP-3 Compliance Protocol is deprecated');
    expect(step?.description).toContain('KYC_SERVER');
  });

  it('renames DEPOSIT_SERVER to TRANSFER_SERVER', () => {
    const source = lines(
      `SIGNING_KEY = "${SIGNING_KEY}"`,
      'DEPOSIT_SERVER = "https://acme.example/sep6"',
    );
    expect(migrateSchema(source).output).toContain('TRANSFER_SERVER = "https://acme.example/sep6"');
  });

  it('refuses to leave two auth endpoints behind', () => {
    const source = lines(
      'AUTH_SERVER = "https://a.example"',
      'WEB_AUTH_ENDPOINT = "https://b.example"',
    );
    const result = migrateSchema(source);

    expect(result.changed).toBe(false);
    expect(result.steps).toEqual([]);
    expect(result.notes[0]).toContain('WEB_AUTH_ENDPOINT is already set');
  });

  it('rolls back when the successor needs something the file does not have', () => {
    const source = lines('AUTH_SERVER = "https://auth.acme.example/auth"');
    const result = migrateSchema(source);

    expect(result.changed).toBe(false);
    expect(result.validated).toBe(false);
    expect(result.refusal).toContain('general/auth-requires-signing-key');
    expect(result.output).toBe(source);
  });

  it('can be told not to validate, which is how the guard earns its keep', () => {
    const source = lines('AUTH_SERVER = "https://auth.acme.example/auth"');
    const result = migrateSchema(source, { validate: false });

    expect(result.changed).toBe(true);
    expect(lint(result.output, {}).counts.error).toBe(1);
  });
});

describe('federation-server-scheme', () => {
  it('rewrites the scheme and nothing else', () => {
    const result = migrateSchema(
      lines('FEDERATION_SERVER = "http://federation.acme.example/f?x=1"'),
    );
    expect(planOf(result)).toEqual(['federation-server-scheme:rewrite-value:FEDERATION_SERVER']);
    expect(result.output).toBe(
      lines('FEDERATION_SERVER = "https://federation.acme.example/f?x=1"'),
    );
  });

  it('keeps the quoting style the anchor wrote', () => {
    const result = migrateSchema("FEDERATION_SERVER = 'http://acme.example/fed'\n");
    expect(result.output).toBe("FEDERATION_SERVER = 'https://acme.example/fed'\n");
  });

  it('ignores an endpoint that is already HTTPS', () => {
    expect(migrateSchema(lines('FEDERATION_SERVER = "https://acme.example/fed"')).changed).toBe(
      false,
    );
  });

  it('ignores a value that is not a string', () => {
    expect(migrateSchema(lines('FEDERATION_SERVER = 42')).steps).toEqual([]);
  });
});

describe('documentation-field-at-root', () => {
  it('moves several root fields under one new header', () => {
    const result = migrateSchema(lines('ORG_NAME = "Acme"', 'ORG_URL = "https://acme.example"'));

    expect(planOf(result)).toEqual([
      'documentation-field-at-root:move-into-table:ORG_NAME',
      'documentation-field-at-root:move-into-table:ORG_URL',
    ]);
    expect(result.output.match(/\[DOCUMENTATION\]/g)).toHaveLength(1);
    // Both root statements moved, so the new header starts the file rather than
    // arriving behind a blank line that used to separate two keys.
    expect(result.output).toBe(
      lines('[DOCUMENTATION]', 'ORG_NAME = "Acme"', 'ORG_URL = "https://acme.example"'),
    );
  });

  it('appends the new table rather than re-parenting the keys after it', () => {
    const source = lines(
      'NETWORK_PASSPHRASE = "Test SDF Network ; September 2015"',
      'ORG_URL = "https://acme.example"',
      '',
      '[[CURRENCIES]]',
      'code = "USD"',
      `issuer = "${SIGNING_KEY}"`,
    );
    const result = migrateSchema(source);

    expect(result.output).toBe(
      lines(
        'NETWORK_PASSPHRASE = "Test SDF Network ; September 2015"',
        '',
        '[[CURRENCIES]]',
        'code = "USD"',
        `issuer = "${SIGNING_KEY}"`,
        '',
        '[DOCUMENTATION]',
        'ORG_URL = "https://acme.example"',
      ),
    );
  });

  it('leaves a root field whose table already defines it', () => {
    const source = lines(
      'ORG_URL = "https://root.example"',
      '',
      '[DOCUMENTATION]',
      'ORG_URL = "https://table.example"',
    );
    const result = migrateSchema(source);

    expect(result.changed).toBe(false);
    expect(result.notes).toContain(
      'ORG_URL: already set in [DOCUMENTATION], left the root copy in place',
    );
  });

  it('does not move fields that are already in [DOCUMENTATION]', () => {
    const source = lines(
      '[DOCUMENTATION]',
      'ORG_NAME = "Acme"',
      'ORG_URL = "https://acme.example"',
    );
    expect(migrateSchema(source).changed).toBe(false);
  });
});

describe('whole-file migration', () => {
  it('brings a 2019 anchor config up to date in one pass', () => {
    const result = migrateSchema(LEGACY);

    expect(result.changed).toBe(true);
    expect(result.validated).toBe(true);
    expect(result.refusal).toBeUndefined();
    expect(planOf(result)).toEqual([
      'legacy-field-alias:move-into-table:ORGANIZATION_NAME',
      'deprecated-root-field:rename-key:AUTH_SERVER',
      'deprecated-root-field:rename-key:DEPOSIT_SERVER',
      'federation-server-scheme:rewrite-value:FEDERATION_SERVER',
      'documentation-field-at-root:move-into-table:ORG_URL',
    ]);
    expect(result.output).toContain('# Acme anchor config, written 2019.');
    expect(result.output).toContain(`SIGNING_KEY = "${SIGNING_KEY}"`);
  });

  it('leaves no deprecation warning behind and still parses', () => {
    const output = migrateSchema(LEGACY).output;
    const rules = lint(output, {}).diagnostics.map((diagnostic) => diagnostic.rule);

    expect(parseCst(output).errors).toEqual([]);
    expect(rules).not.toContain('general/deprecated-field');
    expect(lint(output, {}).counts.error ?? 0).toBe(0);
  });

  it('is a fixpoint: the second run has nothing to do', () => {
    const once = migrateSchema(LEGACY).output;
    const twice = migrateSchema(once);

    expect(twice.changed).toBe(false);
    expect(twice.steps).toEqual([]);
    expect(twice.output).toBe(once);
  });

  it('exits clean on a file with no applicable migrations', () => {
    const modern = lines(
      'VERSION = "1.0.0"',
      'NETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"',
      'WEB_AUTH_ENDPOINT = "https://auth.acme.example/auth"',
      `SIGNING_KEY = "${SIGNING_KEY}"`,
      '',
      '[DOCUMENTATION]',
      'ORG_NAME = "Acme"',
      'ORG_URL = "https://acme.example"',
    );
    const result = migrateSchema(modern);

    expect(result.parsed).toBe(true);
    expect(result.changed).toBe(false);
    expect(result.validated).toBe(true);
    expect(result.refusal).toBeUndefined();
    expect(result.output).toBe(modern);
  });

  it('refuses a file it cannot parse instead of guessing', () => {
    const result = migrateSchema('VERSION = \n');

    expect(result.parsed).toBe(false);
    expect(result.refusal).toBe('file does not parse; nothing was migrated');
    expect(result.steps).toEqual([]);
  });

  it('keeps a file without a final newline valid TOML after moving its last line', () => {
    const source = `SIGNING_KEY = "${SIGNING_KEY}"\nORG_URL = "https://acme.example"`;
    const result = migrateSchema(source);

    expect(result.changed).toBe(true);
    expect(parseCst(result.output).errors).toEqual([]);
    expect(result.output).toBe(
      `SIGNING_KEY = "${SIGNING_KEY}"\n\n[DOCUMENTATION]\nORG_URL = "https://acme.example"\n`,
    );
  });

  it('skips a rule the caller asks it to leave alone', () => {
    const result = migrateSchema(LEGACY, { skipRules: ['federation-server-scheme'] });

    expect(planOf(result)).not.toContain(
      'federation-server-scheme:rewrite-value:FEDERATION_SERVER',
    );
    expect(result.output).toContain(
      'FEDERATION_SERVER = "http://federation.acme.example/federation"',
    );
  });
});

describe('diff', () => {
  const codemod = new SchemaMigrationCodemod();

  it('is empty when nothing would change', () => {
    expect(codemod.diff('x.toml', lines('VERSION = "1.0.0"'))).toBe('');
  });

  it('is the git-style preview of exactly what apply would write', () => {
    const diff = codemod.diff('stellar.toml', LEGACY);

    expect(diff).toContain('--- a/stellar.toml');
    expect(diff).toContain('+++ b/stellar.toml');
    expect(diff).toContain('-AUTH_SERVER = "https://auth.acme.example/auth"');
    expect(diff).toContain('+WEB_AUTH_ENDPOINT = "https://auth.acme.example/auth"');
  });
});

const temps: string[] = [];

afterAll(async () => {
  await Promise.all(temps.map((dir) => rm(dir, { recursive: true, force: true })));
});

async function workspace(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'migrate-cli-'));
  temps.push(dir);
  return dir;
}

interface Run {
  code: number;
  stdout: string;
  stderr: string;
}

async function cli(args: string[], input?: string): Promise<Run> {
  if (input !== undefined) return cliStdin(args, input);
  try {
    const { stdout, stderr } = await run('node', [CLI, ...args], {
      env: { ...process.env, NO_COLOR: '1' },
    });
    return { code: 0, stdout, stderr };
  } catch (error) {
    const e = error as { code?: number; stdout?: string; stderr?: string };
    return { code: e.code ?? 1, stdout: e.stdout ?? '', stderr: e.stderr ?? '' };
  }
}

function cliStdin(args: string[], input: string): Promise<Run> {
  return new Promise((resolvePromise) => {
    const child = spawn('node', [CLI, ...args], { env: { ...process.env, NO_COLOR: '1' } });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });
    child.on('close', (code) => resolvePromise({ code: code ?? 1, stdout, stderr }));
    child.stdin.end(input);
  });
}

describe('cli migrate', () => {
  it('lists every migration from the registry', async () => {
    const { code, stdout } = await cli(['migrate', '--help']);

    expect(code).toBe(0);
    for (const rule of MIGRATION_RULES) expect(stdout).toContain(rule.id);
  });

  it('rejects an unknown migration rule', async () => {
    const { code, stderr } = await cli(['migrate', '--skip-rule', 'no-such-rule']);

    expect(code).toBe(2);
    expect(stderr).toContain('Unknown migration rule');
  });

  it('prints a diff and changes nothing under --dry-run', async () => {
    const dir = await workspace();
    const path = join(dir, 'stellar.toml');
    await writeFile(path, LEGACY);

    const { code, stdout } = await cli(['migrate', '--dry-run', path]);

    expect(code).toBe(1);
    expect(stdout).toContain(`+++ ${path}`);
    expect(stdout).toContain(`${path}: ORG_URL moved from the document root into [DOCUMENTATION]`);
    expect(await readFile(path, 'utf8')).toBe(LEGACY);
  });

  it('rewrites the file and then has nothing left to say', async () => {
    const dir = await workspace();
    const path = join(dir, 'stellar.toml');
    await writeFile(path, LEGACY);

    const applied = await cli(['migrate', path]);
    expect(applied.code).toBe(0);
    expect(applied.stdout).toContain(`${path}: migrated`);

    const second = await cli(['migrate', path]);
    expect(second.code).toBe(0);
    expect(second.stdout).toContain('No deprecated fields to migrate.');
    expect(await readFile(path, 'utf8')).toBe(migrateSchema(LEGACY).output);
  });

  it('exits 1 and writes nothing when the migration is rolled back', async () => {
    const dir = await workspace();
    const path = join(dir, 'stellar.toml');
    const source = lines('ORGANIZATION_NAME = "Acme"', 'ORGANISATION_NAME = "Acme Ltd"');
    await writeFile(path, source);

    const { code, stderr } = await cli(['migrate', path]);

    expect(code).toBe(1);
    expect(stderr).toContain('rolled back');
    expect(await readFile(path, 'utf8')).toBe(source);
  });

  it('exits 1 on a file that does not parse', async () => {
    const dir = await workspace();
    const path = join(dir, 'stellar.toml');
    await writeFile(path, 'VERSION =\n');

    const { code, stderr } = await cli(['migrate', path]);

    expect(code).toBe(1);
    expect(stderr).toContain('file does not parse');
  });

  it('exits 2 when the file is missing', async () => {
    const { code, stderr } = await cli(['migrate', './definitely-not-here.toml']);
    expect(code).toBe(2);
    expect(stderr).not.toBe('');
  });

  it('reports the plan as machine-readable JSON', async () => {
    const dir = await workspace();
    const path = join(dir, 'stellar.toml');
    await writeFile(path, LEGACY);

    const { code, stdout } = await cli(['migrate', '--dry-run', '--json', path]);
    const report = JSON.parse(stdout) as { pending: number; files: { steps: unknown[] }[] };

    expect(code).toBe(1);
    expect(stdout.trimEnd().endsWith('}')).toBe(true);
    expect(report.pending).toBe(1);
    expect(report.files[0]?.steps).toHaveLength(5);
  });

  it('migrates stdin without touching a file', async () => {
    const { code, stdout } = await cli(['migrate', '-'], LEGACY);

    expect(code).toBe(0);
    expect(stdout).toContain('[DOCUMENTATION]');
    expect(stdout).toContain('ORG_NAME = "Acme Cash"');
  });

  it('honours --skip-rule on disk', async () => {
    const dir = await workspace();
    const path = join(dir, 'stellar.toml');
    await writeFile(path, LEGACY);

    await cli(['migrate', '--skip-rule', 'federation-server-scheme', path]);

    expect(await readFile(path, 'utf8')).toContain('FEDERATION_SERVER = "http://');
  });
});
