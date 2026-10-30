import { afterAll, describe, expect, it } from 'vitest';
import { execFile } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { allRules } from '../src/rules/index.js';
import { PRESETS, PRESET_NAMES, resolvePreset } from '../src/presets.js';
import type { RuleOverrides, Severity } from '../src/types.js';

const run = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, '..', 'dist', 'cli.js');

const temps: string[] = [];

afterAll(async () => {
  await Promise.all(temps.map((dir) => rm(dir, { recursive: true, force: true })));
});

/**
 * The three roles the presets exist for, each a file the role would plausibly
 * publish: the validator's carries a `[[CURRENCIES]]` table it has no use for,
 * the anchor's names a transfer server without listing anything to transfer, and
 * the issuer's declares a SEP-31 server with no documentation behind it.
 *
 * They are written to a temp directory rather than kept in `test/fixtures/`,
 * because the glob tests there count every file under that directory — a
 * fixture whose whole purpose is to fail would change their numbers.
 */
const VALIDATOR_TOML = `VERSION="2.7.0"
NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"

[DOCUMENTATION]
ORG_NAME="Example Node Operator"
ORG_URL="https://example.com"
ORG_DESCRIPTION="Operates two validator nodes."
ORG_LOGO="https://example.com/logo.png"
ORG_OFFICIAL_EMAIL="ops@example.com"

[[VALIDATORS]]
ALIAS="example-us"
HOST="core.example.com:11625"
PUBLIC_KEY="GC7T6T56DX23PT7Q6WGCTIJT5O6TP6SJ47RP73JCA3ISLVCCVMGHNSDI"
HISTORY="https://history.example.com/prd/core-live/core_live_001/"

[[VALIDATORS]]
ALIAS="example-eu"
HOST="core.example.com:11625"
PUBLIC_KEY="GBXHQL5SHDWJJ2WQXJZOVQBVVIFXLFQQFIKVWMU6XA7YZVMVMB5APS5D"
HISTORY="https://history.example.com/prd/core-live/core_live_002/"

[[CURRENCIES]]
code="NOPE"
issuer="GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY"
fixed_number=1000
is_unlimited=true
`;

const ANCHOR_TOML = `VERSION="2.7.0"
NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"
TRANSFER_SERVER="https://api.example.com/sep6"
TRANSFER_SERVER_SEP0024="https://api.example.com/sep24"
WEB_AUTH_ENDPOINT="https://api.example.com/auth"
SIGNING_KEY="GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS"
`;

const ISSUER_TOML = `VERSION="2.7.0"
NETWORK_PASSPHRASE="Public Global Stellar Network ; September 2015"
DIRECT_PAYMENT_SERVER="https://api.example.com/sep31"

[[CURRENCIES]]
code="CRDT"
issuer="GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY"
display_decimals=2
name="Example Credit"
is_unlimited=true
status="live"
`;

/** Writes `source` as a `stellar.toml` in a fresh temp directory. */
async function fixture(source: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'stellartoml-preset-'));
  temps.push(dir);
  const path = join(dir, 'stellar.toml');
  await writeFile(path, source);
  return path;
}

/** Runs the built CLI, capturing the exit code instead of throwing. */
async function cli(
  args: string[],
  cwd?: string,
): Promise<{ code: number; stdout: string; stderr: string }> {
  try {
    const { stdout, stderr } = await run('node', [CLI, ...args], {
      env: { ...process.env, NO_COLOR: '1' },
      ...(cwd === undefined ? {} : { cwd }),
    });
    return { code: 0, stdout, stderr };
  } catch (error) {
    const e = error as { code?: number; stdout?: string; stderr?: string };
    return { code: e.code ?? 1, stdout: e.stdout ?? '', stderr: e.stderr ?? '' };
  }
}

/** Lints `path` as JSON and returns the exit code with every finding. */
async function diagnose(
  path: string,
  args: string[] = [],
  cwd?: string,
): Promise<{ code: number; diagnostics: { rule: string; severity: Severity }[] }> {
  const { code, stdout } = await cli([path, '-f', 'json', ...args], cwd);
  return {
    code,
    diagnostics: (JSON.parse(stdout) as { diagnostics: { rule: string; severity: Severity }[] })
      .diagnostics,
  };
}

/** The first severity reported for `rule`, or `undefined` when it stayed quiet. */
function severityOf(
  diagnostics: { rule: string; severity: Severity }[],
  rule: string,
): Severity | undefined {
  return diagnostics.find((d) => d.rule === rule)?.severity;
}

/** The severity a rule ends up at: the preset's, or the registry default. */
function effective(rules: RuleOverrides, id: string): Severity | 'off' {
  return rules[id] ?? defaultSeverity(id);
}

/** The registry's default severity for `id`, which a preset overrides. */
function defaultSeverity(id: string): Severity {
  const rule = allRules.find((candidate) => candidate.id === id);
  if (rule === undefined) throw new Error(`No such rule: ${id}`);
  return rule.severity;
}

/** Captures the error `resolvePreset` throws, since it throws synchronously. */
function rejection(name: string): Error {
  try {
    resolvePreset(name);
  } catch (error) {
    return error as Error;
  }
  throw new Error(`resolvePreset(${JSON.stringify(name)}) did not throw`);
}

describe('presets', () => {
  it('exposes a bundle for every advertised name, and no others', () => {
    expect(Object.keys(PRESETS).sort()).toEqual([...PRESET_NAMES].sort());
    for (const name of PRESET_NAMES) {
      expect(PRESETS[name].name).toBe(name);
      expect(PRESETS[name].summary).not.toBe('');
    }
  });

  it('only names rules the registry knows', () => {
    // The bundles are assembled from `allRules`, but several entries name rules
    // one at a time; a rename must fail here rather than leave a dead entry.
    const known = new Set(allRules.map((rule) => rule.id));
    for (const name of PRESET_NAMES) {
      for (const id of Object.keys(PRESETS[name].rules)) {
        expect(known.has(id), `${name} references the unknown rule ${id}`).toBe(true);
      }
    }
  });

  it('gives every rule a real severity, and freezes the shared bundles', () => {
    for (const name of PRESET_NAMES) {
      const rules: RuleOverrides = PRESETS[name].rules;
      expect(Object.isFrozen(rules)).toBe(true);
      for (const setting of Object.values(rules)) {
        expect(['off', 'error', 'warning', 'info']).toContain(setting);
      }
    }
  });

  it('keeps the bundles independent of one another', () => {
    // A spread at the call site is a copy, but a write that reached the shared
    // object would corrupt every later run of the same preset.
    const copy = { ...PRESETS.validator.rules };
    copy['validators/duplicate-host'] = 'off';
    expect(PRESETS.validator.rules['validators/duplicate-host']).toBe('error');

    expect(() => {
      (PRESETS.validator.rules as RuleOverrides)['validators/host'] = 'off';
    }).toThrow(TypeError);
  });
});

describe('resolvePreset', () => {
  it('returns the bundle for each name', () => {
    for (const name of PRESET_NAMES) expect(resolvePreset(name)).toBe(PRESETS[name]);
  });

  it('lists the available presets for an unknown name', () => {
    const error = rejection('bank');
    expect(error.message).toContain('Unknown preset "bank"');
    for (const name of PRESET_NAMES) expect(error.message).toContain(name);
    // A name on its own says nothing; the summary is what makes the list
    // answer "which one did I mean?" without opening --help.
    for (const name of PRESET_NAMES) expect(error.message).toContain(PRESETS[name].summary);
  });

  it('suggests the closest name for a typo', () => {
    expect(rejection('valdator').message).toMatch(/Did you mean: validator\?/);
    expect(rejection('issuerr').message).toMatch(/Did you mean: issuer\?/);
  });

  it('says nothing about a near match when nothing is near', () => {
    expect(rejection('kubernetes-operator').message).not.toContain('Did you mean');
  });
});

describe('the validator preset', () => {
  const rules = PRESETS.validator.rules;

  it('switches off every currency rule', () => {
    const currency = allRules.filter((rule) => rule.category === 'currencies');
    expect(currency.length).toBeGreaterThan(0);
    for (const rule of currency) expect(rules[rule.id]).toBe('off');
  });

  it('switches off the anchor service rules', () => {
    for (const id of [
      'general/auth-requires-signing-key',
      'general/sep24-requires-auth',
      'general/transfer-server-needs-currencies',
      'sep12/invalid-customer-type-syntax',
      'sep38/prices-endpoint-error',
      'network/sep6-info-error',
    ]) {
      expect(rules[id], id).toBe('off');
    }
  });

  it('leaves the validator checks on, and fails on a duplicate host', () => {
    for (const id of ['validators/alias', 'validators/host', 'validators/public-key']) {
      expect(effective(rules, id), id).toBe('error');
    }
    // A shared HOST or ALIAS is a quorum bug rather than a style note, so the
    // preset raises the two duplicate rules from warning to error.
    expect(rules['validators/duplicate-host']).toBe('error');
    expect(rules['validators/duplicate-alias']).toBe('error');
    expect(defaultSeverity('validators/duplicate-host')).toBe('warning');
    expect(defaultSeverity('validators/duplicate-alias')).toBe('warning');
  });
});

describe('the anchor-sep24 preset', () => {
  const rules = PRESETS['anchor-sep24'].rules;

  it('enforces the SEP-24, SEP-10, and currency requirements at error', () => {
    for (const id of [
      'general/sep24-requires-auth',
      'general/auth-requires-signing-key',
      'general/kyc-requires-auth',
      'general/sep38-requires-auth',
      'general/transfer-server-needs-currencies',
      'general/sep45-completeness',
      'currencies/missing-anchor-asset-type',
      'currencies/anchored-asset-fields',
      'currencies/missing-anchor-asset-code',
    ]) {
      expect(effective(rules, id), id).toBe('error');
    }
  });

  it('raises the requirements that ship as warnings', () => {
    for (const id of [
      'general/transfer-server-needs-currencies',
      'general/sep45-completeness',
      'currencies/anchored-asset-fields',
      'currencies/missing-anchor-asset-code',
    ]) {
      expect(defaultSeverity(id)).toBe('warning');
      expect(rules[id], id).toBe('error');
    }
  });

  it('switches off the validator checks', () => {
    const validator = allRules.filter((rule) => rule.category === 'validators');
    expect(validator.length).toBeGreaterThan(0);
    for (const rule of validator) expect(rules[rule.id]).toBe('off');
  });

  it('leaves the general file checks alone', () => {
    for (const id of ['general/version', 'general/https-endpoints', 'file/max-size']) {
      expect(rules[id], id).toBeUndefined();
      expect(effective(rules, id)).toBe(defaultSeverity(id));
    }
  });
});

describe('the issuer preset', () => {
  const rules = PRESETS.issuer.rules;

  it('enforces documentation and currency completeness at error', () => {
    for (const id of [
      'documentation/present',
      'documentation/recommended-fields',
      'currencies/anchored-asset-fields',
      'currencies/missing-anchor-asset-code',
    ]) {
      expect(effective(rules, id), id).toBe('error');
      expect(defaultSeverity(id)).toBe('warning');
    }
  });

  it('keeps the collateral and issuance checks at error', () => {
    // `currencies/collateral-consistency` is what guards the collateral lists,
    // and `currencies/issuance-exclusive` the supply model; the preset raises
    // nothing about them because they already fail a build.
    for (const id of ['currencies/collateral-consistency', 'currencies/issuance-exclusive']) {
      expect(rules[id], id).toBeUndefined();
      expect(effective(rules, id)).toBe('error');
    }
  });

  it('switches off the anchor service rules', () => {
    expect(rules['general/sep31-requires-kyc']).toBe('off');
    expect(rules['network/sep6-missing-asset']).toBe('off');
    expect(rules['sep38/prices-endpoint-error']).toBe('off');
  });
});

describe('cli --preset', () => {
  it('suppresses the currency rules for a validator operator', async () => {
    const path = await fixture(VALIDATOR_TOML);

    const before = await diagnose(path);
    expect(severityOf(before.diagnostics, 'currencies/issuance-exclusive')).toBe('error');
    expect(before.code).toBe(1);

    const after = await diagnose(path, ['--preset', 'validator']);
    for (const { rule } of after.diagnostics) {
      expect(rule.startsWith('currencies/'), `${rule} survived the preset`).toBe(false);
    }
    // The validator's own problems are still reported — at error, because a
    // shared host is a quorum bug rather than a style note.
    expect(severityOf(after.diagnostics, 'validators/duplicate-host')).toBe('error');
    expect(after.code).toBe(1);
  });

  it('enforces the anchor requirements for a SEP-24 anchor', async () => {
    const path = await fixture(ANCHOR_TOML);

    const before = await diagnose(path);
    expect(severityOf(before.diagnostics, 'general/transfer-server-needs-currencies')).toBe(
      'warning',
    );
    expect(before.code).toBe(0);

    const after = await diagnose(path, ['--preset', 'anchor-sep24']);
    expect(severityOf(after.diagnostics, 'general/transfer-server-needs-currencies')).toBe('error');
    expect(after.code).toBe(1);
  });

  it('enforces documentation completeness and silences the services for an issuer', async () => {
    const path = await fixture(ISSUER_TOML);

    const before = await diagnose(path);
    expect(severityOf(before.diagnostics, 'documentation/present')).toBe('warning');
    expect(severityOf(before.diagnostics, 'general/sep31-requires-kyc')).toBe('error');

    const after = await diagnose(path, ['--preset', 'issuer']);
    expect(severityOf(after.diagnostics, 'documentation/present')).toBe('error');
    expect(severityOf(after.diagnostics, 'general/sep31-requires-kyc')).toBeUndefined();
  });

  it('lets an explicit --error override the preset, in either order', async () => {
    const path = await fixture(VALIDATOR_TOML);

    for (const args of [
      ['--preset', 'validator', '--error', 'currencies/issuance-exclusive'],
      ['--error', 'currencies/issuance-exclusive', '--preset', 'validator'],
    ]) {
      const result = await diagnose(path, args);
      expect(severityOf(result.diagnostics, 'currencies/issuance-exclusive'), args.join(' ')).toBe(
        'error',
      );
      expect(result.code).toBe(1);
    }
  });

  it('lets an explicit --off override a rule the preset raised', async () => {
    const path = await fixture(ANCHOR_TOML);

    const raised = await cli([path, '--preset', 'anchor-sep24']);
    expect(raised.code).toBe(1);

    const lowered = await cli([
      path,
      '--preset',
      'anchor-sep24',
      '--off',
      'general/transfer-server-needs-currencies',
    ]);
    expect(lowered.code).toBe(0);
  });

  it('overrides the configuration file, like any other flag', async () => {
    const path = await fixture(VALIDATOR_TOML);
    const dir = dirname(path);
    await writeFile(
      join(dir, '.stellartomlrc.json'),
      JSON.stringify({ rules: { 'validators/duplicate-host': 'off' } }),
    );

    const withoutPreset = await diagnose(path, [], dir);
    expect(severityOf(withoutPreset.diagnostics, 'validators/duplicate-host')).toBeUndefined();

    const withPreset = await diagnose(path, ['--preset', 'validator'], dir);
    expect(severityOf(withPreset.diagnostics, 'validators/duplicate-host')).toBe('error');
  });

  it('exits 2 with the available presets for an unknown name', async () => {
    const { code, stderr } = await cli(['--preset', 'valdator']);
    expect(code).toBe(2);
    expect(stderr).toContain('Unknown preset "valdator"');
    for (const name of PRESET_NAMES) expect(stderr).toContain(name);
    expect(stderr).toMatch(/Did you mean: validator\?/);
    // Nothing was linted: a usage error never produces a report.
    expect(stderr).toContain('Run with --help for usage.');
  });

  it('exits 2 when --preset has no value', async () => {
    const { code, stderr } = await cli(['--preset']);
    expect(code).toBe(2);
    expect(stderr).toContain('expects a value');
  });

  it('documents every preset in --help', async () => {
    const { code, stdout } = await cli(['--help']);
    expect(code).toBe(0);
    expect(stdout).toContain('--preset');
    for (const name of PRESET_NAMES) expect(stdout).toContain(name);
  });
});
