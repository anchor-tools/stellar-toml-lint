import { describe, expect, it } from 'vitest';
import { execFile } from 'node:child_process';
import { mkdtemp, writeFile, rm, readFile } from 'node:fs/promises';
import { promisify } from 'node:util';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { compareToml, countDifferences, formatDiff, hasBreakingChanges } from '../src/diff.js';

const run = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, '..', 'dist', 'cli.js');
const fixture = (name: string): string => join(here, 'fixtures', name);

const ACCOUNT_A = 'GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS';
const ACCOUNT_B = 'GC7T6T56DX23PT7Q6WGCTIJT5O6TP6SJ47RP73JCA3ISLVCCVMGHNSDI';
const ACCOUNT_C = 'GBXHQL5SHDWJJ2WQXJZOVQBVVIFXLFQQFIKVWMU6XA7YZVMVMB5APS5D';
const CONTRACT_A = 'CACTZSQPCQSSZ5YG3PI3N7WO6JEERKEUHTPILKB4MBANF2K4D2UHKDDU';
const CONTRACT_B = 'CAZ2T5YG3PI3N7WO6JEERKEUHTPILKB4MBANF2K4D2UHKDDUXYZ2ABCD';

function doc(body: string): string {
  return [
    'VERSION="2.7.0"',
    'NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"',
    'SIGNING_KEY="' + ACCOUNT_A + '"',
    'FEDERATION_SERVER="https://api.example.com/federation"',
    '',
    '[DOCUMENTATION]',
    'ORG_NAME="Example"',
    'ORG_URL="https://example.com"',
    'ORG_DESCRIPTION="Example"',
    'ORG_LOGO="https://example.com/logo.png"',
    'ORG_OFFICIAL_EMAIL="ops@example.com"',
    '',
    body,
  ].join('\n');
}

async function cli(args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
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

describe('compareToml', () => {
  it('returns no differences for identical documents', async () => {
    const text = await readFile(fixture('valid.toml'), 'utf8');
    expect(compareToml(text, text)).toEqual([]);
    expect(hasBreakingChanges([])).toBe(false);
  });

  it('flags a removed currency code as breaking', () => {
    const base = doc(
      [
        '[[CURRENCIES]]',
        'code="USDX"',
        'issuer="' + ACCOUNT_B + '"',
        'is_unlimited=true',
        'status="live"',
        '',
        '[[CURRENCIES]]',
        'code="EXPL"',
        'issuer="' + ACCOUNT_C + '"',
        'is_unlimited=true',
        'status="live"',
      ].join('\n'),
    );
    const target = doc(
      [
        '[[CURRENCIES]]',
        'code="EXPL"',
        'issuer="' + ACCOUNT_C + '"',
        'is_unlimited=true',
        'status="live"',
      ].join('\n'),
    );

    const diffs = compareToml(base, target);
    expect(hasBreakingChanges(diffs)).toBe(true);
    const removed = diffs.find((d) => d.path === 'CURRENCIES[USDX]');
    expect(removed).toBeDefined();
    expect(removed?.severity).toBe('BREAKING');
    expect(removed?.message).toContain('removed');
  });

  it('flags a changed issuer as breaking (not remove+add)', () => {
    const base = doc(
      '[[CURRENCIES]]\ncode="USDX"\nissuer="' + ACCOUNT_B + '"\nis_unlimited=true\nstatus="live"',
    );
    const target = doc(
      '[[CURRENCIES]]\ncode="USDX"\nissuer="' + ACCOUNT_C + '"\nis_unlimited=true\nstatus="live"',
    );

    const diffs = compareToml(base, target);
    const issuer = diffs.find((d) => d.path === 'CURRENCIES[USDX].issuer');
    expect(issuer?.severity).toBe('BREAKING');
    expect(issuer?.breaking).toBe(true);
    expect(diffs.some((d) => d.path === 'CURRENCIES[USDX]' && d.severity === 'BREAKING')).toBe(
      false,
    );
  });

  it('flags a mutated contract ID as breaking', () => {
    const base = doc(
      '[[CURRENCIES]]\ncode="EXPL"\ncontract="' + CONTRACT_A + '"\nfixed_number=1\nstatus="live"',
    );
    const target = doc(
      '[[CURRENCIES]]\ncode="EXPL"\ncontract="' + CONTRACT_B + '"\nfixed_number=1\nstatus="live"',
    );

    const diffs = compareToml(base, target);
    const contract = diffs.find((d) => d.path === 'CURRENCIES[EXPL].contract');
    expect(contract?.severity).toBe('BREAKING');
  });

  it('flags live-to-dead status as breaking', () => {
    const base = doc(
      '[[CURRENCIES]]\ncode="USDX"\nissuer="' + ACCOUNT_B + '"\nis_unlimited=true\nstatus="live"',
    );
    const target = doc(
      '[[CURRENCIES]]\ncode="USDX"\nissuer="' + ACCOUNT_B + '"\nis_unlimited=true\nstatus="dead"',
    );

    const diffs = compareToml(base, target);
    const status = diffs.find((d) => d.path === 'CURRENCIES[USDX].status');
    expect(status?.severity).toBe('BREAKING');
  });

  it('flags changed issuance rules as breaking', () => {
    const base = doc(
      '[[CURRENCIES]]\ncode="USDX"\nissuer="' + ACCOUNT_B + '"\nis_unlimited=true\nstatus="live"',
    );
    const target = doc(
      '[[CURRENCIES]]\ncode="USDX"\nissuer="' + ACCOUNT_B + '"\nfixed_number=100\nstatus="live"',
    );

    const diffs = compareToml(base, target);
    const issuance = diffs.filter((d) => d.path.startsWith('CURRENCIES[USDX].'));
    expect(issuance.some((d) => d.severity === 'BREAKING' && d.path.includes('is_unlimited'))).toBe(
      true,
    );
    expect(issuance.some((d) => d.severity === 'BREAKING' && d.path.includes('fixed_number'))).toBe(
      true,
    );
  });

  it('flags a mutated validator PUBLIC_KEY as breaking', () => {
    const base = doc(
      '[[VALIDATORS]]\nALIAS="node-a"\nPUBLIC_KEY="' + ACCOUNT_B + '"\nHOST="a.example.com:11625"',
    );
    const target = doc(
      '[[VALIDATORS]]\nALIAS="node-a"\nPUBLIC_KEY="' + ACCOUNT_C + '"\nHOST="a.example.com:11625"',
    );

    const diffs = compareToml(base, target);
    const key = diffs.find((d) => d.path === 'VALIDATORS[node-a].PUBLIC_KEY');
    expect(key?.severity).toBe('BREAKING');
    expect(hasBreakingChanges(diffs)).toBe(true);
  });

  it('flags a removed validator as breaking', () => {
    const base = doc(
      '[[VALIDATORS]]\nALIAS="node-a"\nPUBLIC_KEY="' + ACCOUNT_B + '"\nHOST="a.example.com:11625"',
    );
    const target = doc('VERSION_NOTE="no validators"');

    const diffs = compareToml(base, target);
    const removed = diffs.find((d) => d.path === 'VALIDATORS[node-a]');
    expect(removed?.severity).toBe('BREAKING');
  });

  it('flags a changed SIGNING_KEY as breaking', () => {
    const base = doc('');
    const target = base.replace(ACCOUNT_A, ACCOUNT_B);

    const diffs = compareToml(base, target);
    const signing = diffs.find((d) => d.path === 'SIGNING_KEY');
    expect(signing?.severity).toBe('BREAKING');
  });

  it('flags a removed SEP endpoint as breaking', () => {
    const base = doc('');
    const target = base.replace('FEDERATION_SERVER="https://api.example.com/federation"\n', '');

    const diffs = compareToml(base, target);
    const endpoint = diffs.find((d) => d.path === 'FEDERATION_SERVER');
    expect(endpoint?.severity).toBe('BREAKING');
  });

  it('treats added currency and validator as non-breaking INFO', () => {
    const base = doc('');
    const target = doc(
      [
        '[[CURRENCIES]]',
        'code="NEW"',
        'issuer="' + ACCOUNT_B + '"',
        'is_unlimited=true',
        'status="live"',
        '',
        '[[VALIDATORS]]',
        'ALIAS="node-b"',
        'PUBLIC_KEY="' + ACCOUNT_C + '"',
        'HOST="b.example.com:11625"',
      ].join('\n'),
    );

    const diffs = compareToml(base, target);
    expect(hasBreakingChanges(diffs)).toBe(false);
    expect(diffs.every((d) => d.severity === 'INFO')).toBe(true);
    expect(diffs.some((d) => d.path === 'CURRENCIES[NEW]')).toBe(true);
    expect(diffs.some((d) => d.path === 'VALIDATORS[node-b]')).toBe(true);
  });

  it('treats mutated ORG_DESCRIPTION as a non-breaking WARNING', () => {
    const base = doc('');
    const target = base.replace('ORG_DESCRIPTION="Example"', 'ORG_DESCRIPTION="Updated copy"');

    const diffs = compareToml(base, target);
    const desc = diffs.find((d) => d.path === 'DOCUMENTATION.ORG_DESCRIPTION');
    expect(desc?.severity).toBe('WARNING');
    expect(desc?.breaking).toBe(false);
    expect(hasBreakingChanges(diffs)).toBe(false);
  });

  it('throws on malformed TOML so callers can exit 2', () => {
    expect(() => compareToml('not = valid = toml', 'VERSION="1"')).toThrow();
  });

  it('counts and formats differences with severity labels', () => {
    const base = doc(
      '[[CURRENCIES]]\ncode="USDX"\nissuer="' + ACCOUNT_B + '"\nis_unlimited=true\nstatus="live"',
    );
    const target = doc(
      '[[CURRENCIES]]\ncode="USDX"\nissuer="' + ACCOUNT_B + '"\nis_unlimited=true\nstatus="dead"',
    );
    const diffs = compareToml(base, target);

    const counts = countDifferences(diffs);
    expect(counts.BREAKING).toBeGreaterThan(0);

    const plain = formatDiff(diffs, { base: 'old.toml', target: 'new.toml' });
    expect(plain).toContain('BREAKING');
    expect(plain).toContain('CURRENCIES[USDX].status');
    expect(plain).toContain('breaking');
    expect(plain).toContain('Diff: old.toml -> new.toml');

    const none = formatDiff([], { base: 'a.toml', target: 'b.toml' });
    expect(none).toContain('No differences');
  });
});

describe('cli --diff', () => {
  it('exits 1 on breaking changes', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'stellar-diff-'));
    try {
      const base = join(dir, 'base.toml');
      const target = join(dir, 'target.toml');
      await writeFile(
        base,
        doc(
          '[[CURRENCIES]]\ncode="USDX"\nissuer="' +
            ACCOUNT_B +
            '"\nis_unlimited=true\nstatus="live"',
        ),
      );
      await writeFile(
        target,
        doc(
          '[[CURRENCIES]]\ncode="USDX"\nissuer="' +
            ACCOUNT_C +
            '"\nis_unlimited=true\nstatus="live"',
        ),
      );

      const { code, stdout } = await cli(['--diff', base, target]);
      expect(code).toBe(1);
      expect(stdout).toContain('BREAKING');
      expect(stdout).toContain('CURRENCIES[USDX].issuer');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('exits 0 for additive-only changes', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'stellar-diff-'));
    try {
      const base = join(dir, 'base.toml');
      const target = join(dir, 'target.toml');
      await writeFile(base, doc(''));
      await writeFile(
        target,
        doc(
          '[[CURRENCIES]]\ncode="NEW"\nissuer="' +
            ACCOUNT_B +
            '"\nis_unlimited=true\nstatus="live"',
        ),
      );

      const { code, stdout } = await cli(['--diff', base, target]);
      expect(code).toBe(0);
      expect(stdout).toContain('INFO');
      expect(stdout).not.toContain('BREAKING');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('exits 0 when files are identical', async () => {
    const { code, stdout } = await cli(['--diff', fixture('valid.toml'), fixture('valid.toml')]);
    expect(code).toBe(0);
    expect(stdout).toContain('No differences');
  });

  it('exits 2 when a file is missing', async () => {
    const { code, stderr } = await cli([
      '--diff',
      fixture('valid.toml'),
      join(tmpdir(), 'definitely-missing.toml'),
    ]);
    expect(code).toBe(2);
    expect(stderr).toContain('Could not find');
  });

  it('exits 2 when --diff is missing its second argument', async () => {
    const { code, stderr } = await cli(['--diff', fixture('valid.toml')]);
    expect(code).toBe(2);
    expect(stderr).toContain('--diff expects a value');
  });

  it('exits 0 with a WARNING for mutated ORG_DESCRIPTION', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'stellar-diff-'));
    try {
      const base = join(dir, 'base.toml');
      const target = join(dir, 'target.toml');
      await writeFile(base, doc(''));
      await writeFile(
        target,
        doc('').replace('ORG_DESCRIPTION="Example"', 'ORG_DESCRIPTION="New"'),
      );
      const { code, stdout } = await cli(['--diff', base, target]);
      expect(code).toBe(0);
      expect(stdout).toContain('WARNING');
      expect(stdout).toContain('DOCUMENTATION.ORG_DESCRIPTION');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
