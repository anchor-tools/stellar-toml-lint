import { afterAll, describe, expect, it } from 'vitest';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import {
  DEFAULT_EXTENSION_PREFIXES,
  OrphanedKeyScanner,
  RECOGNIZED_SECTIONS,
  detectOrphans,
  pruneOrphans,
} from '../src/cst/orphanedKeyScanner.js';
import type { OrphanFinding } from '../src/cst/orphanedKeyScanner.js';
import {
  KNOWN_CURRENCY_FIELDS,
  KNOWN_DOCUMENTATION_FIELDS,
  KNOWN_GLOBAL_FIELDS,
  KNOWN_PRINCIPAL_FIELDS,
  KNOWN_SERVER_FIELDS,
  KNOWN_VALIDATOR_FIELDS,
} from '../src/spec.js';

const run = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, '..', 'dist', 'cli.js');
const scanner = new OrphanedKeyScanner();

const SIGNING_KEY = 'GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS';

function lines(...text: string[]): string {
  return `${text.join('\n')}\n`;
}

function paths(findings: OrphanFinding[]): string[] {
  return findings.map((finding) => finding.path);
}

/** A file that sets every field every SEP this project knows about. */
function everythingFile(): string {
  const entry = (fields: Iterable<string>): string =>
    [...fields].map((field) => `${field} = "v"`).join('\n');
  return lines(
    entry([...KNOWN_GLOBAL_FIELDS].filter((name) => !(name in RECOGNIZED_SECTIONS))),
    '',
    '[DOCUMENTATION]',
    entry(KNOWN_DOCUMENTATION_FIELDS),
    '',
    '[[PRINCIPALS]]',
    entry(KNOWN_PRINCIPAL_FIELDS),
    '',
    '[[CURRENCIES]]',
    entry(KNOWN_CURRENCY_FIELDS),
    '',
    '[[VALIDATORS]]',
    entry(KNOWN_VALIDATOR_FIELDS),
    '',
    '[SERVERS]',
    entry(KNOWN_SERVER_FIELDS),
  );
}

describe('OrphanedKeyScanner', () => {
  it('finds nothing in a file that only uses fields the SEPs define', () => {
    expect(scanner.scan(everythingFile()).findings).toEqual([]);
  });

  it('reports a root key no SEP defines, with no suggestion to mislead', () => {
    const [finding] = scanner.scan(lines('SUPPORT_SERVER = "https://acme.example"')).findings ?? [];

    expect(finding?.kind).toBe('unknown-key');
    expect(finding?.suggestion).toBeUndefined();
    expect(finding?.message).toBe('SUPPORT_SERVER configures nothing any SEP defines');
  });

  it('points at the offending line and column', () => {
    const source = lines('VERSION = "1.0.0"', '', '[DOCUMENTATION]', 'ORG_TWTTER = "@acme"');
    const [finding] = scanner.scan(source).findings ?? [];

    expect(finding?.line).toBe(4);
    expect(finding?.column).toBe(1);
    expect(finding?.section).toBe('DOCUMENTATION');
  });

  it('suggests the canonical spelling for a typo', () => {
    const [finding] = scanner.scan(lines('[DOCUMENTATION]', 'ORG_TWTTER = "@acme"')).findings ?? [];

    expect(finding?.suggestion).toBe('ORG_TWITTER');
    expect(finding?.message).toBe(
      'ORG_TWTTER is not a field any SEP defines; the closest is ORG_TWITTER',
    );
  });

  it('reads a dotted key as the field it writes', () => {
    const [finding] = scanner.scan(lines('DOCUMENTATION.ORG_NAM = "Acme"')).findings ?? [];

    expect(finding?.written).toBe('ORG_NAM');
    expect(finding?.path).toBe('DOCUMENTATION.ORG_NAM');
    expect(finding?.section).toBe('DOCUMENTATION');
    expect(finding?.suggestion).toBe('ORG_NAME');
  });

  it('suggests the plural for a table typed in the singular', () => {
    const [finding] =
      scanner.scan(lines('[[CURRENCY]]', 'code = "USD"', `issuer = "${SIGNING_KEY}"`)).findings ??
      [];

    expect(finding?.kind).toBe('unknown-table');
    expect(finding?.suggestion).toBe('CURRENCIES');
    expect(finding?.message).toBe(
      '[CURRENCY] is not a table SEP-1 defines; the closest is [CURRENCIES]',
    );
  });

  it('names an unrecognised table once instead of every key under it', () => {
    const result = scanner.scan(lines('[ACME_INTERNAL]', 'a = 1', 'b = 2', 'c = 3'));

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.kind).toBe('unknown-table');
  });

  it('accepts vendor extensions without being told', () => {
    const result = scanner.scan(
      lines('X_ACME_WEBHOOK = "https://acme.example"', '[DOCUMENTATION]', 'X_ACME_ID = 7'),
    );
    expect(result.findings).toEqual([]);
    expect(DEFAULT_EXTENSION_PREFIXES).toEqual(['X_']);
  });

  it('takes a different extension prefix when the anchor uses one', () => {
    const result = scanner.scan(lines('ACME_WEBHOOK = "x"', 'X_ACME_ID = 7'), {
      extensionPrefixes: ['ACME_'],
    });

    expect(paths(result.findings)).toEqual(['X_ACME_ID']);
  });

  it('gives up on a file it cannot parse instead of guessing', () => {
    const result = scanner.scan('VERSION =\n');

    expect(result.parsed).toBe(false);
    expect(result.findings).toEqual([]);
  });
});

describe('allow-list', () => {
  const source = lines('ACME_ROUTING_KEY = "x"', '', '[DOCUMENTATION]', 'ORG_HOURS = "9to5"');

  it('accepts a bare key name', () => {
    const result = scanner.scan(source, { allowKeys: ['ACME_ROUTING_KEY'] });
    expect(paths(result.findings)).toEqual(['ORG_HOURS']);
    expect(result.allowed).toBe(1);
  });

  it('accepts a dotted path', () => {
    const result = scanner.scan(source, { allowKeys: ['DOCUMENTATION.ORG_HOURS'] });
    expect(paths(result.findings)).toEqual(['ACME_ROUTING_KEY']);
  });

  it('accepts a table name, which blesses the whole section', () => {
    const table = lines('[ACME]', 'a = 1', 'b = 2');
    expect(scanner.scan(table, { allowKeys: ['ACME'] }).findings).toEqual([]);
  });

  it('accepts a PREFIX_* glob', () => {
    const result = scanner.scan(source, { allowKeys: ['ACME_*', 'ORG_*'] });
    expect(result.findings).toEqual([]);
    expect(result.allowed).toBe(2);
  });

  it('matches case-insensitively', () => {
    expect(scanner.scan(source, { allowKeys: ['acme_routing_key'] }).findings).toHaveLength(1);
  });

  it('counts an allowance that covers a schema move', () => {
    const result = scanner.scan(lines('ORGANIZATION_NAME = "Acme"'), {
      allowKeys: ['DOCUMENTATION.ORG_NAME'],
    });

    expect(result.findings).toEqual([]);
    expect(result.allowed).toBe(1);
  });
});

describe('schema moves', () => {
  it('sends a legacy spelling to migrate rather than offering to delete it', () => {
    const [finding] = scanner.scan(lines('ORGANIZATION_NAME = "Acme"')).findings ?? [];

    expect(finding?.migrateTo).toBe('DOCUMENTATION.ORG_NAME');
    expect(finding?.message).toBe(
      'ORGANIZATION_NAME is a legacy spelling of DOCUMENTATION.ORG_NAME; run `stellar-toml-lint migrate` to move it',
    );
  });

  it('sends a correctly spelled field in the wrong place to migrate', () => {
    const [finding] = scanner.scan(lines('ORG_TWITTER = "@acme"')).findings ?? [];

    expect(finding?.migrateTo).toBe('DOCUMENTATION.ORG_TWITTER');
    expect(finding?.suggestion).toBeUndefined();
    expect(finding?.message).toBe(
      'ORG_TWITTER belongs in [DOCUMENTATION]; run `stellar-toml-lint migrate` to move it',
    );
  });

  it('asks for the spelling to be fixed first when it is a near-miss', () => {
    const [finding] = scanner.scan(lines('ORG_TWTTER = "@acme"')).findings ?? [];

    expect(finding?.migrateTo).toBe('DOCUMENTATION.ORG_TWITTER');
    expect(finding?.message).toContain('once it is spelled ORG_TWITTER');
  });

  it('does not promise a move migrate cannot make', () => {
    // `code` is a currency field, and no migration moves a root key into
    // [[CURRENCIES]] — so it is reported as an orphan, not as a schema move.
    const [finding] = scanner.scan(lines('code = "USD"')).findings ?? [];

    expect(finding?.migrateTo).toBeUndefined();
  });
});

describe('pruneOrphans', () => {
  it('deletes what no SEP defines, taking its comment with it', () => {
    const source = lines('VERSION = "1.0.0"', '# where we take calls', 'SUPPORT_SERVER = "x"');
    const result = pruneOrphans(source);

    expect(result.actions).toEqual([{ kind: 'removed', section: '', written: 'SUPPORT_SERVER' }]);
    expect(result.output).toBe(lines('VERSION = "1.0.0"'));
  });

  it('renames a typo instead of deleting the setting', () => {
    const result = pruneOrphans(lines('[DOCUMENTATION]', 'ORG_TWTTER = "@acme"'));

    expect(result.actions[0]).toEqual({
      kind: 'renamed',
      section: 'DOCUMENTATION',
      written: 'ORG_TWTTER',
      suggestion: 'ORG_TWITTER',
    });
    expect(result.output).toBe(lines('[DOCUMENTATION]', 'ORG_TWITTER = "@acme"'));
  });

  it('keeps the quoting style of a key it renames', () => {
    const result = pruneOrphans(lines('[DOCUMENTATION]', '"ORG_TWTTER" = "@acme"'));
    expect(result.output).toBe(lines('[DOCUMENTATION]', '"ORG_TWITTER" = "@acme"'));
  });

  it('renames a table header without changing its kind', () => {
    const source = lines('[[CURRENCY]]', 'code = "USD"');
    const result = pruneOrphans(source);

    expect(result.output).toBe(lines('[[CURRENCIES]]', 'code = "USD"'));
    expect(result.actions[0]?.kind).toBe('renamed');
  });

  it('leaves an unrecognised table alone when it still holds data it cannot place', () => {
    const result = pruneOrphans(lines('[ACME]', 'thing = 1'));

    expect(result.changed).toBe(false);
    expect(result.warnings).toEqual(['ACME: no table to rename it to, left in place']);
  });

  it('will not merge two blocks by renaming one onto the other', () => {
    const source = lines('[[CURRENCIES]]', 'code = "USD"', '', '[[CURRENCY]]', 'code = "EUR"');
    const result = pruneOrphans(source);

    expect(result.changed).toBe(false);
    expect(result.warnings).toEqual([
      'CURRENCY: [CURRENCIES] is already in the file, left in place',
    ]);
  });

  it('will not rename a key onto a field the file already sets', () => {
    const source = lines('[DOCUMENTATION]', 'ORG_TWITTER = "@real"', 'ORG_TWTTER = "@typo"');
    const result = pruneOrphans(source);

    expect(result.changed).toBe(false);
    expect(result.warnings).toEqual([
      'ORG_TWTTER: [DOCUMENTATION] ORG_TWITTER is already set, left in place',
    ]);
  });

  it('refuses to delete a legacy alias, because migrate owns the move', () => {
    const source = lines('ORGANIZATION_NAME = "Acme"');
    const result = pruneOrphans(source);

    expect(result.changed).toBe(false);
    expect(result.output).toBe(source);
    expect(result.warnings[0]).toContain(
      'which is a schema move — run `stellar-toml-lint migrate`',
    );
  });

  it('fixes the spelling it owns and hands the move back', () => {
    const source = lines(`SIGNING_KEY = "${SIGNING_KEY}"`, 'ORG_TWTTER = "@acme"');
    const result = pruneOrphans(source);

    expect(result.actions).toEqual([
      { kind: 'renamed', section: '', written: 'ORG_TWTTER', suggestion: 'ORG_TWITTER' },
    ]);
    expect(result.warnings[0]).toContain('ORG_TWITTER: belongs in DOCUMENTATION.ORG_TWITTER');
    expect(result.output).toContain('ORG_TWITTER = "@acme"');
  });

  it('returns an unparseable file untouched', () => {
    const source = 'VERSION =\n';
    const result = pruneOrphans(source);

    expect(result.parsed).toBe(false);
    expect(result.output).toBe(source);
    expect(result.warnings).toEqual(['file does not parse; nothing was pruned']);
  });

  it('is a fixpoint', () => {
    const source = lines(
      'VERSION = "1.0.0"',
      'SUPPORT_SERVER = "x"',
      '',
      '[DOCUMENTATION]',
      'ORG_TWTTER = "@acme"',
      '',
      '[[CURRENCY]]',
      'code = "USD"',
    );
    const once = pruneOrphans(source);
    const twice = pruneOrphans(once.output);

    expect(twice.changed).toBe(false);
    expect(detectOrphans(once.output).findings).toEqual([]);
  });

  it('respects the allow-list', () => {
    const source = lines('ACME_ROUTING_KEY = "x"');
    expect(pruneOrphans(source, { allowKeys: ['ACME_*'] }).changed).toBe(false);
    expect(pruneOrphans(source).changed).toBe(true);
  });
});

const temps: string[] = [];

afterAll(async () => {
  await Promise.all(temps.map((dir) => rm(dir, { recursive: true, force: true })));
});

async function workspace(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'orphans-cli-'));
  temps.push(dir);
  return dir;
}

interface Run {
  code: number;
  stdout: string;
  stderr: string;
}

async function cli(args: string[]): Promise<Run> {
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

const ANCHOR = lines(
  'VERSION = "1.0.0"',
  'NETWORK_PASSPHRASE = "Test SDF Network ; September 2015"',
  `SIGNING_KEY = "${SIGNING_KEY}"`,
  'ACME_ROUTING_KEY = "secret"',
  'SUPPORT_SERVER = "https://acme.example/support"',
  '',
  '[DOCUMENTATION]',
  'ORG_NAME = "Acme"',
  'ORG_TWTTER = "@acme"',
  '',
  '[[CURRENCY]]',
  `issuer = "${SIGNING_KEY}"`,
);

describe('cli --detect-orphans', () => {
  it('reports findings and exits 1', async () => {
    const dir = await workspace();
    const path = join(dir, 'stellar.toml');
    await writeFile(path, ANCHOR);

    const { code, stdout } = await cli(['--detect-orphans', path]);

    expect(code).toBe(1);
    expect(stdout).toContain('SUPPORT_SERVER configures nothing any SEP defines');
    expect(stdout).toContain('general/unknown-table');
  });

  it('answers in the format --format asks for', async () => {
    const dir = await workspace();
    const path = join(dir, 'stellar.toml');
    await writeFile(path, ANCHOR);

    const { stdout } = await cli(['--detect-orphans', '--format', 'json', path]);
    const report = JSON.parse(stdout) as {
      counts: { warning: number };
      diagnostics: { rule: string; path?: string }[];
    };

    expect(report.counts.warning).toBe(4);
    expect(report.diagnostics.map((d) => d.path)).toEqual([
      'ACME_ROUTING_KEY',
      'SUPPORT_SERVER',
      'ORG_TWTTER',
      'CURRENCY',
    ]);
  });

  it('exits 0 on a file with nothing orphaned', async () => {
    const dir = await workspace();
    const path = join(dir, 'stellar.toml');
    await writeFile(path, everythingFile());

    const { code, stdout } = await cli(['--detect-orphans', path]);

    expect(code).toBe(0);
    expect(stdout).toContain('No SEP-1 issues found.');
  });

  it('prints pure JSON when nothing is orphaned', async () => {
    const dir = await workspace();
    const path = join(dir, 'stellar.toml');
    await writeFile(path, lines('VERSION = "1.0.0"'));

    const { stdout } = await cli(['--detect-orphans', '--format', 'json', path]);

    expect(() => JSON.parse(stdout)).not.toThrow();
  });

  it('takes --allow-key on the command line', async () => {
    const dir = await workspace();
    const path = join(dir, 'stellar.toml');
    await writeFile(path, ANCHOR);

    const { code, stdout, stderr } = await cli([
      '--detect-orphans',
      '--allow-key',
      'ACME_*',
      '--allow-key',
      'SUPPORT_SERVER',
      '--allow-key',
      'DOCUMENTATION.ORG_TWTTER',
      path,
    ]);

    expect(code).toBe(1);
    // The count of what was blessed goes to stderr so the report on stdout
    // stays exactly the report.
    expect(stderr).toContain('3 key(s) matched the allow-list');
    expect(stdout).toContain('1 problem');
    expect(stdout).toContain('[CURRENCY] is not a table SEP-1 defines');
  });

  it('reads knownKeys from the project config', async () => {
    const dir = await workspace();
    const path = join(dir, 'stellar.toml');
    await writeFile(path, ANCHOR);
    await writeFile(
      join(dir, '.stellartomlrc.json'),
      JSON.stringify(
        { knownKeys: ['ACME_*', 'SUPPORT_SERVER', 'ORG_TWTTER', 'CURRENCY'] },
        null,
        2,
      ),
    );

    const { code, stdout } = await cli(['--detect-orphans', '--format', 'json', path]);

    expect(code).toBe(0);
    expect(JSON.parse(stdout).counts.warning).toBe(0);
  });

  it('refuses --domain, which would imply a fetch', async () => {
    const { code, stderr } = await cli(['--detect-orphans', '--domain', 'acme.example', 'x.toml']);

    expect(code).toBe(2);
    expect(stderr).toContain('cannot be combined with --domain');
  });
});

describe('cli --prune-orphaned', () => {
  it('shows the diff and writes nothing under --dry-run', async () => {
    const dir = await workspace();
    const path = join(dir, 'stellar.toml');
    await writeFile(path, ANCHOR);

    const { code, stdout } = await cli(['--prune-orphaned', '--dry-run', path]);

    expect(code).toBe(1);
    expect(stdout).toContain(`+++ ${path}`);
    expect(stdout).toContain('renamed CURRENCY to CURRENCIES');
    expect(await readFile(path, 'utf8')).toBe(ANCHOR);
  });

  it('applies the safe fixes, reports the ones it will not make, and settles', async () => {
    const dir = await workspace();
    const path = join(dir, 'stellar.toml');
    await writeFile(path, ANCHOR);

    const applied = await cli(['--prune-orphaned', path]);
    expect(applied.code).toBe(0);
    expect(applied.stdout).toContain('removed SUPPORT_SERVER (no SEP defines it)');

    const after = await readFile(path, 'utf8');
    expect(after).toContain('ORG_TWITTER = "@acme"');
    expect(after).toContain('[[CURRENCIES]]');
    expect(after).not.toContain('SUPPORT_SERVER');

    const second = await cli(['--prune-orphaned', path]);
    expect(second.code).toBe(0);
    expect(await readFile(path, 'utf8')).toBe(after);
  });

  it('leaves the file for migrate when a finding is a schema move', async () => {
    const dir = await workspace();
    const path = join(dir, 'stellar.toml');
    const source = lines('ORGANIZATION_NAME = "Acme"');
    await writeFile(path, source);

    const { code, stderr } = await cli(['--prune-orphaned', path]);

    expect(code).toBe(0);
    expect(stderr).toContain('stellar-toml-lint migrate');
    expect(await readFile(path, 'utf8')).toBe(source);
  });

  it('prunes every file a glob matches', async () => {
    const dir = await workspace();
    for (const name of ['a.toml', 'b.toml']) {
      await writeFile(join(dir, name), lines('SUPPORT_SERVER = "x"', 'VERSION = "1.0.0"'));
    }

    const { code, stdout } = await cli(['--prune-orphaned', join(dir, '*.toml')]);

    expect(code).toBe(0);
    expect(stdout).toContain('removed');
    for (const name of ['a.toml', 'b.toml']) {
      expect(await readFile(join(dir, name), 'utf8')).not.toContain('SUPPORT_SERVER');
    }
  });

  it('exits 1 on a file it cannot read structurally', async () => {
    const dir = await workspace();
    const path = join(dir, 'stellar.toml');
    await writeFile(path, 'VERSION =\n');

    const { code, stderr } = await cli(['--prune-orphaned', path]);

    expect(code).toBe(1);
    expect(stderr).toContain('file does not parse');
  });
});
