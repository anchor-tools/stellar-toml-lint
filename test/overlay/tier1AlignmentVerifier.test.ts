import { describe, expect, it } from 'vitest';
import { execFile } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { Keypair } from '@stellar/stellar-base';
import { parse } from 'smol-toml';
import {
  DEFAULT_THRESHOLD_PERCENT,
  TIER1_INDEPENDENT_QUORUM,
  TIER1_LOW_REPRESENTATION,
  TIER1_NARROW_AGREEMENT,
  TIER1_PARTIAL_ORGANIZATION,
  TIER1_QUORUM_UNDECLARED,
  TIER1_SPLIT_QUORUM,
  TIER1_THRESHOLD_INVALID,
  TIER1_UNRESOLVED_VALIDATOR,
  TIER1_UNVERIFIED_VALIDATOR,
  Tier1QuorumAlignmentVerifier,
  isSatisfied,
  parseQuorumConfig,
  renderTier1AlignmentReport,
  thresholdFromPercent,
  tier1AlignmentRuleIds,
  tier1AlignmentRules,
  type Tier1AlignmentReport,
} from '../../src/overlay/tier1AlignmentVerifier.js';
import {
  DEFAULT_TIER1_CATALOG,
  MAX_TIER1_ORGANIZATIONS,
  TIER1_CATALOG_VERSION,
  parseTier1Catalog,
  type Tier1Catalog,
} from '../../src/overlay/tier1Catalog.js';
import { allRules } from '../../src/rules/index.js';

const ORGS = DEFAULT_TIER1_CATALOG.organizations;
const keysOf = (index: number) => ORGS[index]!.validators.map((node) => node.publicKey);
const ownKeys = [Keypair.random(), Keypair.random(), Keypair.random()].map((k) => k.publicKey());

/** One inner set per catalog organization, listing every validator. */
function orgSets(orgIndexes: number[], keysFor: (index: number) => string[] = keysOf): string {
  return orgIndexes
    .map(
      (index) =>
        `[QUORUM_SET.org${index}]\nTHRESHOLD_PERCENT = 67\nVALIDATORS = [${keysFor(index)
          .map((key) => `"${key}"`)
          .join(', ')}]\n`,
    )
    .join('\n');
}

function explicit(percent: number, orgIndexes: number[], extra = ''): Record<string, unknown> {
  return parse(
    `${extra}\n[QUORUM_SET]\nTHRESHOLD_PERCENT = ${percent}\n\n${orgSets(orgIndexes)}`,
  ) as Record<string, unknown>;
}

const ALL = ORGS.map((_, index) => index);

function verify(doc: Record<string, unknown>, catalog?: Tier1Catalog): Tier1AlignmentReport {
  return new Tier1QuorumAlignmentVerifier(catalog === undefined ? {} : { catalog }).verify(doc);
}

const rules = (report: Tier1AlignmentReport) => report.diagnostics.map((d) => d.rule);

describe('Tier-1 catalog', () => {
  it('bundles a valid snapshot of the Tier-1 organizations', () => {
    const parsed = parseTier1Catalog(JSON.parse(JSON.stringify(DEFAULT_TIER1_CATALOG)));
    expect(parsed.organizations.map((org) => org.homeDomain)).toContain('stellar.org');
    expect(parsed.organizations.every((org) => org.validators.length >= 3)).toBe(true);
    expect(parsed.source).toBe(DEFAULT_TIER1_CATALOG.source);
  });

  it('accepts newly registered validators with a since date', () => {
    const parsed = parseTier1Catalog({
      version: TIER1_CATALOG_VERSION,
      updated: '2026-11-01',
      organizations: [
        {
          name: 'New Org',
          homeDomain: 'New.Example',
          validators: [{ name: 'n1', publicKey: ownKeys[0], since: '2026-10-30' }],
        },
      ],
    });
    expect(parsed.organizations[0]).toEqual({
      name: 'New Org',
      homeDomain: 'new.example',
      validators: [{ name: 'n1', publicKey: ownKeys[0], since: '2026-10-30' }],
    });
    expect(parsed.source).toBeUndefined();
  });

  it('rejects malformed catalogs with every problem listed', () => {
    expect(() => parseTier1Catalog([])).toThrow('must be a JSON object');
    const error = (() => {
      try {
        parseTier1Catalog({
          version: 2,
          updated: 'not a date',
          source: '',
          organizations: [
            'nope',
            { name: 'A', homeDomain: 'a.example', validators: [] },
            {
              name: 'a',
              homeDomain: '',
              validators: [
                'node',
                { name: 'x', publicKey: 'GNOTAKEY' },
                { name: 'y', publicKey: ownKeys[1], since: 'later' },
                { name: 'z', publicKey: ownKeys[1] },
                { name: 'w' },
              ],
            },
          ],
        });
      } catch (caught) {
        return (caught as Error).message;
      }
      return '';
    })();
    for (const fragment of [
      'version must be 1',
      'updated must be an ISO-8601 date',
      'source must be a non-empty string',
      'organizations[0] must be an object',
      'organizations[1].validators must be a non-empty array',
      'organizations[2].name duplicates another organization',
      'organizations[2].homeDomain must be a non-empty string',
      'organizations[2].validators[0] must be an object',
      'organizations[2].validators[1].publicKey is not a valid G... public key',
      'organizations[2].validators[2].since must be an ISO-8601 date',
      'organizations[2].validators[3].publicKey is already listed under a',
      'organizations[2].validators[4].publicKey must be a non-empty string',
    ]) {
      expect(error).toContain(fragment);
    }
  });

  it('bounds the number of organizations', () => {
    expect(() =>
      parseTier1Catalog({ version: 1, updated: '2026-01-01', organizations: [] }),
    ).toThrow('organizations must be a non-empty array');
    const many = Array.from({ length: MAX_TIER1_ORGANIZATIONS + 1 }, (_, i) => ({
      name: `org${i}`,
      homeDomain: `org${i}.example`,
      validators: [{ name: 'n', publicKey: Keypair.random().publicKey() }],
    }));
    expect(() =>
      parseTier1Catalog({ version: 1, updated: '2026-01-01', organizations: many }),
    ).toThrow(`at most ${MAX_TIER1_ORGANIZATIONS}`);
    expect(
      () =>
        new Tier1QuorumAlignmentVerifier({
          catalog: { version: 1, updated: '2026-01-01', organizations: many },
        }),
    ).toThrow(`at most ${MAX_TIER1_ORGANIZATIONS} are supported`);
  });
});

describe('quorum configuration parsing', () => {
  it('rounds thresholds like stellar-core', () => {
    expect(thresholdFromPercent(3, 67)).toBe(3);
    expect(thresholdFromPercent(6, 67)).toBe(5);
    expect(thresholdFromPercent(4, 50)).toBe(2);
    expect(DEFAULT_THRESHOLD_PERCENT).toBe(67);
  });

  it('resolves $NAME references, trailing comments and nested inner sets', () => {
    const doc = parse(`
[[VALIDATORS]]
NAME = "own_a"
PUBLIC_KEY = "${ownKeys[0]}"

[[VALIDATORS]]
ALIAS = "own_b"
PUBLIC_KEY = "${ownKeys[1]}"

[QUORUM_SET]
VALIDATORS = ["$own_a", "$own_b", "${ownKeys[2]} my third node"]

[QUORUM_SET.inner]
THRESHOLD_PERCENT = 51
VALIDATORS = ["${keysOf(0)[0]}"]

[QUORUM_SET.inner.deeper]
VALIDATORS = ["${keysOf(0)[1]}"]
`) as Record<string, unknown>;
    const config = parseQuorumConfig(doc);
    expect(config.source).toBe('explicit');
    expect(config.root?.validators).toEqual(ownKeys);
    expect(config.root?.threshold).toBe(thresholdFromPercent(4, 67));
    expect(config.root?.innerSets[0]?.path).toBe('QUORUM_SET.inner');
    expect(config.root?.innerSets[0]?.threshold).toBe(thresholdFromPercent(2, 51));
    expect(config.root?.innerSets[0]?.innerSets[0]?.path).toBe('QUORUM_SET.inner.deeper');
    expect(config.unresolved).toEqual([]);
  });

  it('records unresolved entries and invalid thresholds', () => {
    const doc = parse(`
[QUORUM_SET]
THRESHOLD_PERCENT = 150
VALIDATORS = ["$missing", "GNOTAKEY", "", 7]
[QUORUM_SET.empty]
VALIDATORS = []
`) as Record<string, unknown>;
    const config = parseQuorumConfig(doc);
    expect(config.unresolved.map((entry) => entry.path)).toEqual([
      'QUORUM_SET.VALIDATORS[0]',
      'QUORUM_SET.VALIDATORS[1]',
      'QUORUM_SET.VALIDATORS[2]',
      'QUORUM_SET.VALIDATORS[3]',
    ]);
    expect(config.invalidThresholds.map((entry) => entry.path)).toEqual([
      'QUORUM_SET.empty',
      'QUORUM_SET.THRESHOLD_PERCENT',
    ]);
  });

  it('stops descending past the nesting limit', () => {
    const doc = parse(`
[QUORUM_SET]
VALIDATORS = ["${ownKeys[0]}"]
[QUORUM_SET.a.b.c.d.e]
VALIDATORS = ["${ownKeys[1]}"]
`) as Record<string, unknown>;
    const config = parseQuorumConfig(doc);
    let depth = 0;
    let node = config.root;
    while (node?.innerSets[0] !== undefined) {
      node = node.innerSets[0];
      depth++;
    }
    expect(depth).toBe(4);
  });

  it('builds the automatic quorum from HOME_DOMAINS and QUALITY', () => {
    const tier1Validators = ORGS.flatMap((org) =>
      org.validators.map(
        (node) =>
          `[[VALIDATORS]]\nNAME = "${node.name}"\nHOME_DOMAIN = "${org.homeDomain}"\nPUBLIC_KEY = "${node.publicKey}"\n`,
      ),
    ).join('\n');
    const homeDomains = ORGS.map(
      (org) => `[[HOME_DOMAINS]]\nHOME_DOMAIN = "${org.homeDomain}"\nQUALITY = "HIGH"\n`,
    ).join('\n');
    const doc = parse(`${homeDomains}
[[HOME_DOMAINS]]
HOME_DOMAIN = "BROKEN"

${tier1Validators}
[[VALIDATORS]]
NAME = "own"
QUALITY = "medium"
PUBLIC_KEY = "${ownKeys[0]}"

[[VALIDATORS]]
NAME = "unrated"
PUBLIC_KEY = "${ownKeys[1]}"

[[VALIDATORS]]
NAME = "no key"
`) as Record<string, unknown>;
    const config = parseQuorumConfig(doc);
    expect(config.source).toBe('automatic');
    expect(config.root?.innerSets).toHaveLength(ORGS.length + 1);
    const lower = config.root?.innerSets.at(-1);
    expect(lower?.path).toBe('VALIDATORS.lower-quality');
    expect(lower?.innerSets[0]?.validators).toEqual([ownKeys[0]]);
    expect(config.declared).toHaveLength(ORGS.flatMap((org) => org.validators).length + 2);

    const report = verify(doc);
    expect(report.ok).toBe(true);
    expect(report.source).toBe('automatic');
    expect(report.nonTier1Validators).toBe(1);
  });

  it('reports no quorum for a plain stellar.toml', () => {
    const doc = parse(`[[VALIDATORS]]\nALIAS = "a"\nPUBLIC_KEY = "${ownKeys[0]}"\n`) as Record<
      string,
      unknown
    >;
    expect(parseQuorumConfig(doc).source).toBe('none');
    expect(parseQuorumConfig({ VALIDATORS: 'oops' }).declared).toEqual([]);
    const report = verify(doc);
    expect(rules(report)).toEqual([TIER1_QUORUM_UNDECLARED]);
    expect(report.minTier1OrganizationsToAgree).toBeNull();
    expect(report.ok).toBe(true);
  });

  it('evaluates satisfiability recursively', () => {
    const set = {
      path: 'Q',
      threshold: 2,
      validators: ['A'],
      innerSets: [{ path: 'Q.1', threshold: 1, validators: ['B'], innerSets: [] }],
    };
    expect(isSatisfied(set, new Set(['A', 'B']))).toBe(true);
    expect(isSatisfied(set, new Set(['A']))).toBe(false);
    expect(isSatisfied({ path: 'E', threshold: 0, validators: [], innerSets: [] }, new Set())).toBe(
      false,
    );
  });
});

describe('Tier1QuorumAlignmentVerifier', () => {
  it('accepts a compliant slice that needs broad Tier-1 agreement', () => {
    const report = verify(explicit(67, ALL));
    expect(report.ok).toBe(true);
    expect(report.diagnostics).toEqual([]);
    expect(report.representedOrganizations).toBe(ORGS.length);
    expect(report.representationRatio).toBe(1);
    expect(report.minTier1OrganizationsToAgree).toBe(thresholdFromPercent(ORGS.length, 67));
    expect(report.coreQuorumOrganizations).toBe(Math.ceil((ORGS.length * 2) / 3));
    expect(report.quorumSets[1]).toMatchObject({
      tier1Validators: 3,
      validators: 3,
      tier1Ratio: 1,
    });
    expect(report.quorumSets[0]).toMatchObject({
      path: 'QUORUM_SET',
      validators: 0,
      tier1Ratio: 0,
    });
  });

  it('flags a slice that can agree without any Tier-1 organization', () => {
    const doc = parse(`
[QUORUM_SET]
VALIDATORS = [${ownKeys.map((key) => `"${key}"`).join(', ')}]
${orgSets([0])}
`) as Record<string, unknown>;
    const report = verify(doc);
    expect(report.ok).toBe(false);
    expect(report.minTier1OrganizationsToAgree).toBe(0);
    expect(rules(report)).toContain(TIER1_INDEPENDENT_QUORUM);
    expect(rules(report)).toContain(TIER1_LOW_REPRESENTATION);
    expect(report.quorumSets[0]).toMatchObject({ validators: 3, tier1Validators: 0 });
  });

  it('flags a split quorum whose Tier-1 agreement need not overlap the core', () => {
    const report = verify(explicit(30, ALL));
    expect(report.minTier1OrganizationsToAgree).toBe(2);
    expect(rules(report)).toEqual([TIER1_SPLIT_QUORUM]);
    expect(report.ok).toBe(false);
  });

  it('warns when a minority of Tier-1 organizations is enough', () => {
    const report = verify(explicit(50, ALL));
    expect(report.minTier1OrganizationsToAgree).toBe(3);
    expect(rules(report)).toEqual([TIER1_NARROW_AGREEMENT]);
    expect(report.ok).toBe(true);
  });

  it('warns about low representation and partially listed organizations', () => {
    const doc = parse(`
[QUORUM_SET]
THRESHOLD_PERCENT = 100
${orgSets([0, 1, 2], (index) => (index === 2 ? keysOf(2).slice(0, 2) : keysOf(index)))}
`) as Record<string, unknown>;
    const report = verify(doc);
    expect(rules(report)).toEqual([
      TIER1_NARROW_AGREEMENT,
      TIER1_LOW_REPRESENTATION,
      TIER1_PARTIAL_ORGANIZATION,
    ]);
    const lobstr = report.organizations.find((org) => org.homeDomain === 'lobstr.co');
    expect(lobstr).toMatchObject({ inSlice: 2, total: 5 });
  });

  it('does not count an unverified key that claims a Tier-1 home domain', () => {
    const doc = explicit(
      67,
      ALL,
      `[[VALIDATORS]]\nNAME = "sdf_new"\nHOME_DOMAIN = "stellar.org"\nPUBLIC_KEY = "${ownKeys[0]}"\n\n[[VALIDATORS]]\nNAME = "sdf_1"\nHOME_DOMAIN = "stellar.org"\nPUBLIC_KEY = "${keysOf(0)[0]}"\n\n[[VALIDATORS]]\nNAME = "elsewhere"\nHOME_DOMAIN = "own.example"\nPUBLIC_KEY = "${ownKeys[1]}"\n`,
    );
    const report = verify(doc);
    expect(report.unverifiedValidators).toEqual([ownKeys[0]]);
    expect(rules(report)).toEqual([TIER1_UNVERIFIED_VALIDATOR]);
    expect(report.diagnostics[0]?.message).toContain('sdf_new');

    // Once the operator adds the new node to the catalog, it is trusted.
    const catalog: Tier1Catalog = {
      ...DEFAULT_TIER1_CATALOG,
      organizations: DEFAULT_TIER1_CATALOG.organizations.map((org, index) =>
        index === 0
          ? { ...org, validators: [...org.validators, { name: 'sdf_new', publicKey: ownKeys[0]! }] }
          : org,
      ),
    };
    expect(verify(doc, catalog).diagnostics).toEqual([]);
  });

  it('reports unresolved references and unsatisfiable sets', () => {
    const doc = parse(`
[QUORUM_SET]
VALIDATORS = ["$nobody"]
`) as Record<string, unknown>;
    const report = verify(doc);
    expect(report.minTier1OrganizationsToAgree).toBeNull();
    expect(rules(report)).toEqual([
      TIER1_UNRESOLVED_VALIDATOR,
      TIER1_THRESHOLD_INVALID,
      TIER1_THRESHOLD_INVALID,
      TIER1_LOW_REPRESENTATION,
    ]);
    expect(report.ok).toBe(false);
  });

  it('names an unverified validator by key when it has no NAME and skips junk entries', () => {
    const doc = {
      HOME_DOMAINS: [1],
      VALIDATORS: [7, { HOME_DOMAIN: 'lobstr.co', PUBLIC_KEY: ownKeys[2] }],
      QUORUM_SET: { VALIDATORS: [ownKeys[2]] },
    };
    const report = verify(doc);
    expect(report.unverifiedValidators).toEqual([ownKeys[2]]);
    const message = report.diagnostics.find((d) => d.rule === TIER1_UNVERIFIED_VALIDATOR)?.message;
    expect(message).toContain(`Validator ${ownKeys[2]} claims Tier-1 home domain lobstr.co`);
    expect(parseQuorumConfig({ HOME_DOMAINS: [1], VALIDATORS: [7] }).source).toBe('none');
  });

  it('works with a catalog that has no source or organizations', () => {
    const report = verify(explicit(67, ALL), {
      version: TIER1_CATALOG_VERSION,
      updated: '2026-01-01',
      organizations: [],
    });
    expect(report.catalog).toEqual({ updated: '2026-01-01', organizations: 0 });
    expect(report.representationRatio).toBe(0);
    expect(report.minTier1OrganizationsToAgree).toBe(0);
  });

  it('honours rule overrides', () => {
    const doc = explicit(30, ALL);
    const off = new Tier1QuorumAlignmentVerifier({ rules: { [TIER1_SPLIT_QUORUM]: 'off' } });
    expect(off.verify(doc).diagnostics).toEqual([]);
    const warn = new Tier1QuorumAlignmentVerifier({ rules: { [TIER1_SPLIT_QUORUM]: 'warning' } });
    const report = warn.verify(doc);
    expect(report.diagnostics[0]?.severity).toBe('warning');
    expect(report.ok).toBe(true);
  });

  it('registers every rule id', () => {
    const ids = allRules.map((rule) => rule.id);
    for (const id of tier1AlignmentRuleIds) expect(ids).toContain(id);
    expect(tier1AlignmentRules).toHaveLength(9);
    for (const rule of tier1AlignmentRules) {
      expect(() => rule.run({} as never)).not.toThrow();
    }
  });
});

describe('renderTier1AlignmentReport', () => {
  it('draws representation bars and the verdict', () => {
    const text = renderTier1AlignmentReport(verify(explicit(67, ALL)));
    expect(text).toContain('quorum source: explicit [QUORUM_SET]');
    expect(text).toContain('✔ Stellar Development Foundation');
    expect(text).toContain('███ 3/3');
    expect(text).toContain('representation: 6/6 organizations (100%)');
    expect(text).toContain('QUORUM_SET.org0: 3/3 validators are Tier-1 (100%)');
    expect(text).toContain('agreement: needs 5 Tier-1 organization(s) to agree (core quorum: 4)');
    expect(text).toContain('verdict: ALIGNED');
  });

  it('marks missing and partial organizations and misalignment', () => {
    const doc = parse(`
[[VALIDATORS]]
NAME = "sdf_new"
HOME_DOMAIN = "stellar.org"
PUBLIC_KEY = "${ownKeys[0]}"

[QUORUM_SET]
VALIDATORS = ["$sdf_new", "${ownKeys[1]}", "${keysOf(2)[0]}"]
`) as Record<string, unknown>;
    const text = renderTier1AlignmentReport(verify(doc));
    expect(text).toContain('✘ SatoshiPay');
    expect(text).toContain('⚠ LOBSTR');
    expect(text).toContain('░░░░ 1/5');
    expect(text).toContain('non-Tier-1 validators in slice: 2');
    expect(text).toContain(`unverified Tier-1 claims: ${ownKeys[0]}`);
    expect(text).toContain('verdict: MISALIGNED');
  });

  it('labels automatic, missing and unsatisfiable quorums', () => {
    const automatic = renderTier1AlignmentReport(
      verify(
        parse(`[[VALIDATORS]]\nQUALITY = "HIGH"\nPUBLIC_KEY = "${keysOf(0)[0]}"\n`) as Record<
          string,
          unknown
        >,
      ),
    );
    expect(automatic).toContain('automatic quorum from QUALITY-rated [[VALIDATORS]]');
    const none = renderTier1AlignmentReport(verify({}));
    expect(none).toContain('quorum source: none');
    expect(none).not.toContain('agreement:');
    const never = renderTier1AlignmentReport(
      verify(parse(`[QUORUM_SET]\nVALIDATORS = []\n`) as Record<string, unknown>),
    );
    expect(never).toContain('agreement: the quorum set can never be satisfied');
  });
});

describe('--verify-tier1-alignment', () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const CLI = join(here, '..', '..', 'dist', 'cli.js');
  const run = promisify(execFile);

  async function cli(args: string[]) {
    try {
      const { stdout, stderr } = await run('node', [CLI, ...args], {
        env: { ...process.env, NO_COLOR: '1' },
      });
      return { code: 0, stdout, stderr };
    } catch (error) {
      const e = error as { code: number; stdout: string; stderr: string };
      return { code: e.code, stdout: e.stdout, stderr: e.stderr };
    }
  }

  it('fails a slice that can agree without Tier-1 and prints the report', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'tier1-'));
    try {
      const file = join(dir, 'stellar-core.toml');
      await writeFile(
        file,
        `[QUORUM_SET]\nVALIDATORS = [${ownKeys.map((key) => `"${key}"`).join(', ')}]\n`,
      );
      const result = await cli([file, '--verify-tier1-alignment', '--format', 'json']);
      expect(result.code).toBe(1);
      expect(result.stdout).toContain(TIER1_INDEPENDENT_QUORUM);
      expect(result.stderr).toContain('verdict: MISALIGNED');

      const catalog = join(dir, 'catalog.json');
      await writeFile(catalog, JSON.stringify({ version: 1, organizations: [] }));
      const bad = await cli([file, '--verify-tier1-alignment', '--tier1-catalog', catalog]);
      expect(bad.code).toBe(2);
      expect(bad.stderr).toContain('Invalid Tier-1 catalog');

      await writeFile(catalog, JSON.stringify(DEFAULT_TIER1_CATALOG));
      const custom = await cli([file, '--verify-tier1-alignment', '--tier1-catalog', catalog]);
      expect(custom.stderr).toContain('Tier-1 quorum alignment (catalog 2026-11-23');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
