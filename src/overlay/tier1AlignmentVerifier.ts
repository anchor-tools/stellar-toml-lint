/**
 * SCP quorum slice Tier-1 validator alignment verifier.
 *
 * An anchor that runs its own validators chooses the quorum set those nodes
 * trust. If that set does not require broad agreement across the Tier-1
 * organizations that form the network's consensus core, the anchor's nodes can
 * reach agreement on values the core never accepts: they split from the
 * network while still appearing healthy.
 *
 * The verifier reads the quorum configuration from the linted TOML file, in
 * either of the two forms stellar-core understands:
 *
 * - an explicit `[QUORUM_SET]` table (`THRESHOLD_PERCENT`, `VALIDATORS`, and
 *   nested inner sets such as `[QUORUM_SET.1]`), where validators are `G...`
 *   keys or `$NAME` references to `[[VALIDATORS]]` entries; or
 * - automatic quorum generation from `[[VALIDATORS]]` entries that carry a
 *   `QUALITY` (directly or through `[[HOME_DOMAINS]]`): every `HIGH` or
 *   `CRITICAL` organization becomes an inner set with a simple-majority
 *   threshold, and the top level needs 67% of those organizations. `MEDIUM`
 *   and `LOW` organizations are folded into one additional member.
 *
 * It then cross-references every validator against a Tier-1 catalog
 * ({@link DEFAULT_TIER1_CATALOG} or an operator-supplied one) and answers:
 *
 * 1. Which Tier-1 organizations are represented, and how completely.
 * 2. What proportion of each quorum (inner) set is Tier-1.
 * 3. The smallest number of Tier-1 organizations whose validators must agree
 *    before the slice is satisfied, assuming every non-Tier-1 validator in the
 *    slice cooperates. Zero means the slice can agree with no Tier-1 input at
 *    all; a number that cannot intersect a Tier-1 core quorum (two thirds of
 *    the organizations) means the slice can diverge from the core.
 *
 * The audit is offline and deterministic.
 */

import { StrKey } from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';
import {
  DEFAULT_TIER1_CATALOG,
  MAX_TIER1_ORGANIZATIONS,
  type Tier1Catalog,
  type Tier1Organization,
} from './tier1Catalog.js';

/** The slice can be satisfied without any Tier-1 organization agreeing. */
export const TIER1_INDEPENDENT_QUORUM = 'overlay/tier1-independent-quorum';
/** The slice can be satisfied by Tier-1 organizations that need not overlap a core quorum. */
export const TIER1_SPLIT_QUORUM = 'overlay/tier1-split-quorum';
/** The slice is satisfied by a minority of the Tier-1 organizations. */
export const TIER1_NARROW_AGREEMENT = 'overlay/tier1-narrow-agreement';
/** Fewer than two thirds of the Tier-1 organizations appear in the slice. */
export const TIER1_LOW_REPRESENTATION = 'overlay/tier1-low-representation';
/** A Tier-1 organization is represented by less than a majority of its validators. */
export const TIER1_PARTIAL_ORGANIZATION = 'overlay/tier1-partial-organization';
/** A validator claims a Tier-1 home domain but its key is not in the catalog. */
export const TIER1_UNVERIFIED_VALIDATOR = 'overlay/tier1-unverified-validator';
/** A `$NAME` reference or key in the quorum set cannot be resolved. */
export const TIER1_UNRESOLVED_VALIDATOR = 'overlay/tier1-unresolved-validator';
/** A threshold is out of range or can never be met. */
export const TIER1_THRESHOLD_INVALID = 'overlay/tier1-threshold-invalid';
/** No quorum configuration was found to evaluate. */
export const TIER1_QUORUM_UNDECLARED = 'overlay/tier1-quorum-undeclared';

/** stellar-core's default `THRESHOLD_PERCENT`. */
export const DEFAULT_THRESHOLD_PERCENT = 67;

/** A quorum set: `threshold` of its validators and inner sets must agree. */
export interface QuorumSetNode {
  /** Dotted location in the source, e.g. `QUORUM_SET.1`. */
  path: string;
  threshold: number;
  /** Resolved `G...` node ids. */
  validators: string[];
  innerSets: QuorumSetNode[];
}

/** A validator declared in `[[VALIDATORS]]`. */
export interface DeclaredValidator {
  name?: string;
  publicKey: string;
  homeDomain?: string;
  quality?: string;
}

export interface ParsedQuorumConfig {
  source: 'explicit' | 'automatic' | 'none';
  root?: QuorumSetNode;
  declared: DeclaredValidator[];
  /** References that did not resolve to a key, with their location. */
  unresolved: { path: string; entry: string }[];
  /** Threshold problems found while parsing. */
  invalidThresholds: { path: string; message: string }[];
}

export interface Tier1OrganizationCoverage {
  name: string;
  homeDomain: string;
  /** Validators of this organization present anywhere in the slice. */
  inSlice: number;
  /** Validators the catalog lists for this organization. */
  total: number;
}

export interface QuorumSetCoverage {
  path: string;
  threshold: number;
  members: number;
  validators: number;
  tier1Validators: number;
  /** Tier-1 share of the direct validators (0..1); 0 when there are none. */
  tier1Ratio: number;
}

export interface Tier1AlignmentReport {
  ok: boolean;
  source: ParsedQuorumConfig['source'];
  catalog: { updated: string; organizations: number; source?: string };
  organizations: Tier1OrganizationCoverage[];
  representedOrganizations: number;
  /** Represented share of the catalog organizations (0..1). */
  representationRatio: number;
  quorumSets: QuorumSetCoverage[];
  /** Tier-1 organizations needed to satisfy the slice; `null` if unsatisfiable. */
  minTier1OrganizationsToAgree: number | null;
  /** Organizations in a Tier-1 core quorum: two thirds of the catalog. */
  coreQuorumOrganizations: number;
  unverifiedValidators: string[];
  nonTier1Validators: number;
  diagnostics: Diagnostic[];
}

export interface Tier1AlignmentOptions {
  rules?: RuleOverrides;
  catalog?: Tier1Catalog;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function text(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed === '' ? undefined : trimmed;
}

/** stellar-core's rounding: the smallest count that reaches `percent`. */
export function thresholdFromPercent(size: number, percent: number): number {
  return Math.ceil((size * percent) / 100);
}

function readDeclared(doc: Record<string, unknown>): DeclaredValidator[] {
  const validators = doc.VALIDATORS;
  if (!Array.isArray(validators)) return [];
  const out: DeclaredValidator[] = [];
  for (const entry of validators) {
    if (!isRecord(entry)) continue;
    const publicKey = text(entry.PUBLIC_KEY);
    if (publicKey === undefined) continue;
    const name = text(entry.NAME) ?? text(entry.ALIAS);
    const homeDomain = text(entry.HOME_DOMAIN)?.toLowerCase();
    const quality = text(entry.QUALITY)?.toUpperCase();
    out.push({
      publicKey,
      ...(name === undefined ? {} : { name }),
      ...(homeDomain === undefined ? {} : { homeDomain }),
      ...(quality === undefined ? {} : { quality }),
    });
  }
  return out;
}

function readHomeDomainQualities(doc: Record<string, unknown>): Map<string, string> {
  const qualities = new Map<string, string>();
  const homeDomains = doc.HOME_DOMAINS;
  if (!Array.isArray(homeDomains)) return qualities;
  for (const entry of homeDomains) {
    if (!isRecord(entry)) continue;
    const domain = text(entry.HOME_DOMAIN)?.toLowerCase();
    const quality = text(entry.QUALITY)?.toUpperCase();
    if (domain !== undefined && quality !== undefined) qualities.set(domain, quality);
  }
  return qualities;
}

function parseExplicitSet(
  table: Record<string, unknown>,
  path: string,
  byName: Map<string, string>,
  config: ParsedQuorumConfig,
  depth: number,
): QuorumSetNode {
  const validators: string[] = [];
  const rawValidators = Array.isArray(table.VALIDATORS) ? table.VALIDATORS : [];
  rawValidators.forEach((raw: unknown, index) => {
    const entry = text(raw);
    if (entry === undefined) {
      config.unresolved.push({ path: `${path}.VALIDATORS[${index}]`, entry: String(raw) });
      return;
    }
    // stellar-core allows a trailing comment after the key: "GABC... sdf1".
    const token = entry.replace(/\s.*$/s, '');
    const key = token.startsWith('$') ? byName.get(token.slice(1)) : token;
    if (key === undefined || !StrKey.isValidEd25519PublicKey(key)) {
      config.unresolved.push({ path: `${path}.VALIDATORS[${index}]`, entry });
      return;
    }
    validators.push(key);
  });

  const innerSets: QuorumSetNode[] = [];
  if (depth < 4) {
    for (const [key, value] of Object.entries(table)) {
      if (key === 'VALIDATORS' || key === 'THRESHOLD_PERCENT' || !isRecord(value)) continue;
      innerSets.push(parseExplicitSet(value, `${path}.${key}`, byName, config, depth + 1));
    }
  }

  const members = validators.length + innerSets.length;
  let percent = DEFAULT_THRESHOLD_PERCENT;
  if (table.THRESHOLD_PERCENT !== undefined) {
    const raw = Number(table.THRESHOLD_PERCENT);
    if (!Number.isInteger(raw) || raw < 1 || raw > 100) {
      config.invalidThresholds.push({
        path: `${path}.THRESHOLD_PERCENT`,
        message: `THRESHOLD_PERCENT must be an integer from 1 to 100, got ${String(table.THRESHOLD_PERCENT)}`,
      });
    } else {
      percent = raw;
    }
  }
  if (members === 0) {
    config.invalidThresholds.push({
      path,
      message: 'quorum set has no resolvable validators or inner sets, so it can never agree',
    });
  }
  return { path, threshold: thresholdFromPercent(members, percent), validators, innerSets };
}

function buildAutomaticSet(
  declared: DeclaredValidator[],
  qualities: Map<string, string>,
): QuorumSetNode | undefined {
  const high = new Map<string, string[]>();
  const lower = new Map<string, string[]>();
  for (const validator of declared) {
    const domain = validator.homeDomain ?? validator.publicKey;
    const quality =
      validator.quality ??
      (validator.homeDomain === undefined ? undefined : qualities.get(validator.homeDomain));
    if (quality === undefined) continue;
    const bucket = quality === 'HIGH' || quality === 'CRITICAL' ? high : lower;
    bucket.set(domain, [...(bucket.get(domain) ?? []), validator.publicKey]);
  }
  if (high.size === 0 && lower.size === 0) return undefined;

  const orgSet = (domain: string, keys: string[], path: string): QuorumSetNode => ({
    path: `${path}.${domain}`,
    threshold: Math.floor(keys.length / 2) + 1,
    validators: keys,
    innerSets: [],
  });
  const innerSets = [...high.entries()].map(([domain, keys]) => orgSet(domain, keys, 'VALIDATORS'));
  if (lower.size > 0) {
    const lowerSets = [...lower.entries()].map(([domain, keys]) =>
      orgSet(domain, keys, 'VALIDATORS.lower-quality'),
    );
    innerSets.push({
      path: 'VALIDATORS.lower-quality',
      threshold: thresholdFromPercent(lowerSets.length, DEFAULT_THRESHOLD_PERCENT),
      validators: [],
      innerSets: lowerSets,
    });
  }
  return {
    path: 'VALIDATORS',
    threshold: thresholdFromPercent(innerSets.length, DEFAULT_THRESHOLD_PERCENT),
    validators: [],
    innerSets,
  };
}

/** Reads the quorum configuration from a parsed TOML document. */
export function parseQuorumConfig(doc: Record<string, unknown>): ParsedQuorumConfig {
  const declared = readDeclared(doc);
  const config: ParsedQuorumConfig = {
    source: 'none',
    declared,
    unresolved: [],
    invalidThresholds: [],
  };
  if (isRecord(doc.QUORUM_SET)) {
    const byName = new Map<string, string>();
    for (const validator of declared) {
      if (validator.name !== undefined) byName.set(validator.name, validator.publicKey);
    }
    config.source = 'explicit';
    config.root = parseExplicitSet(doc.QUORUM_SET, 'QUORUM_SET', byName, config, 0);
    return config;
  }
  const automatic = buildAutomaticSet(declared, readHomeDomainQualities(doc));
  if (automatic !== undefined) {
    config.source = 'automatic';
    config.root = automatic;
  }
  return config;
}

/** True when `available` validators satisfy the quorum set. */
export function isSatisfied(set: QuorumSetNode, available: ReadonlySet<string>): boolean {
  if (set.threshold <= 0) return false;
  let agreeing = 0;
  for (const key of set.validators) if (available.has(key)) agreeing++;
  for (const inner of set.innerSets) if (isSatisfied(inner, available)) agreeing++;
  return agreeing >= set.threshold;
}

function collectKeys(set: QuorumSetNode, into: Set<string>): Set<string> {
  for (const key of set.validators) into.add(key);
  for (const inner of set.innerSets) collectKeys(inner, into);
  return into;
}

function collectSets(set: QuorumSetNode, into: QuorumSetNode[]): QuorumSetNode[] {
  into.push(set);
  for (const inner of set.innerSets) collectSets(inner, into);
  return into;
}

/** Calls `visit` for every `size`-element subset of `items` until it returns true. */
function someSubset<T>(items: readonly T[], size: number, visit: (subset: T[]) => boolean) {
  const chosen: T[] = [];
  const walk = (start: number): boolean => {
    if (chosen.length === size) return visit(chosen);
    for (let index = start; index <= items.length - (size - chosen.length); index++) {
      chosen.push(items[index] as T);
      if (walk(index + 1)) return true;
      chosen.pop();
    }
    return false;
  };
  return walk(0);
}

function severityFor(
  rule: string,
  fallback: Severity,
  rules: RuleOverrides | undefined,
): Severity | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override ?? fallback;
}

/** Cross-references a quorum configuration against the Tier-1 catalog. */
export class Tier1QuorumAlignmentVerifier {
  private readonly rules: RuleOverrides | undefined;
  private readonly catalog: Tier1Catalog;

  constructor(options: Tier1AlignmentOptions = {}) {
    this.rules = options.rules;
    this.catalog = options.catalog ?? DEFAULT_TIER1_CATALOG;
    if (this.catalog.organizations.length > MAX_TIER1_ORGANIZATIONS) {
      throw new Error(
        `Tier-1 catalog lists ${this.catalog.organizations.length} organizations; at most ${MAX_TIER1_ORGANIZATIONS} are supported`,
      );
    }
  }

  verify(doc: Record<string, unknown>): Tier1AlignmentReport {
    return this.evaluate(parseQuorumConfig(doc));
  }

  evaluate(config: ParsedQuorumConfig): Tier1AlignmentReport {
    const diagnostics: Diagnostic[] = [];
    const emit = (
      rule: string,
      fallback: Severity,
      message: string,
      path?: string,
      suggestion?: string,
    ) => {
      const severity = severityFor(rule, fallback, this.rules);
      if (severity === undefined) return;
      diagnostics.push({
        rule,
        severity,
        category: 'network',
        message,
        ...(path === undefined ? {} : { path }),
        ...(suggestion === undefined ? {} : { suggestion }),
      });
    };

    const organizations = this.catalog.organizations;
    const orgCount = organizations.length;
    const coreQuorumOrganizations = Math.ceil((orgCount * 2) / 3);
    const orgOfKey = new Map<string, Tier1Organization>();
    for (const org of organizations) {
      for (const node of org.validators) orgOfKey.set(node.publicKey, org);
    }
    const tier1Domains = new Map(organizations.map((org) => [org.homeDomain, org]));

    const keys =
      config.root === undefined ? new Set<string>() : collectKeys(config.root, new Set());
    const coverage: Tier1OrganizationCoverage[] = organizations.map((org) => ({
      name: org.name,
      homeDomain: org.homeDomain,
      inSlice: org.validators.filter((node) => keys.has(node.publicKey)).length,
      total: org.validators.length,
    }));
    const represented = coverage.filter((org) => org.inSlice > 0);

    // A key that claims a Tier-1 home domain but is not in the catalog may be
    // a newly registered node or an impostor; it never counts as Tier-1.
    const unverified: string[] = [];
    for (const validator of config.declared) {
      if (validator.homeDomain === undefined) continue;
      const claimed = tier1Domains.get(validator.homeDomain);
      if (claimed === undefined || orgOfKey.has(validator.publicKey)) continue;
      unverified.push(validator.publicKey);
      emit(
        TIER1_UNVERIFIED_VALIDATOR,
        'warning',
        `Validator ${validator.name ?? validator.publicKey} claims Tier-1 home domain ${validator.homeDomain} but its key is not in the Tier-1 catalog`,
        'VALIDATORS',
        `Confirm the key in https://${validator.homeDomain}/.well-known/stellar.toml; if it is a newly added ${claimed.name} node, add it to the catalog with --tier1-catalog.`,
      );
    }
    const nonTier1Keys = [...keys].filter((key) => !orgOfKey.has(key));

    for (const entry of config.unresolved) {
      emit(
        TIER1_UNRESOLVED_VALIDATOR,
        'warning',
        `Quorum set entry "${entry.entry}" does not resolve to a validator public key`,
        entry.path,
        'Use a G... node id, or a $NAME that matches a [[VALIDATORS]] NAME.',
      );
    }
    for (const problem of config.invalidThresholds) {
      emit(TIER1_THRESHOLD_INVALID, 'error', problem.message, problem.path);
    }

    const quorumSets: QuorumSetCoverage[] =
      config.root === undefined
        ? []
        : collectSets(config.root, []).map((set) => {
            const tier1Validators = set.validators.filter((key) => orgOfKey.has(key)).length;
            return {
              path: set.path,
              threshold: set.threshold,
              members: set.validators.length + set.innerSets.length,
              validators: set.validators.length,
              tier1Validators,
              tier1Ratio: set.validators.length === 0 ? 0 : tier1Validators / set.validators.length,
            };
          });

    let minTier1OrganizationsToAgree: number | null = null;
    if (config.root === undefined) {
      emit(
        TIER1_QUORUM_UNDECLARED,
        'info',
        'No quorum set was found, so Tier-1 alignment cannot be evaluated',
        undefined,
        'Add an explicit [QUORUM_SET] or QUALITY-rated [[VALIDATORS]] entries for the nodes you trust.',
      );
    } else {
      const root = config.root;
      const keysOf = (orgs: Tier1Organization[]) =>
        orgs.flatMap((org) => org.validators.map((node) => node.publicKey));
      const representedOrgs = organizations.filter((org) =>
        org.validators.some((node) => keys.has(node.publicKey)),
      );
      for (let size = 0; size <= representedOrgs.length; size++) {
        const found = someSubset(representedOrgs, size, (subset) =>
          isSatisfied(root, new Set([...nonTier1Keys, ...keysOf(subset)])),
        );
        if (found) {
          minTier1OrganizationsToAgree = size;
          break;
        }
      }

      if (minTier1OrganizationsToAgree === null) {
        emit(
          TIER1_THRESHOLD_INVALID,
          'error',
          'The quorum set can never be satisfied, even if every listed validator agrees',
          root.path,
          'Lower THRESHOLD_PERCENT or add the validators the threshold expects.',
        );
      } else if (minTier1OrganizationsToAgree === 0) {
        emit(
          TIER1_INDEPENDENT_QUORUM,
          'error',
          'The quorum slice can agree without any Tier-1 organization, so it can split from global consensus',
          root.path,
          'Require agreement from Tier-1 organizations, for example an inner set per organization with a 67% top-level threshold.',
        );
      } else if (minTier1OrganizationsToAgree <= orgCount - coreQuorumOrganizations) {
        emit(
          TIER1_SPLIT_QUORUM,
          'error',
          `The quorum slice can agree with only ${minTier1OrganizationsToAgree} of ${orgCount} Tier-1 organizations, which need not overlap a Tier-1 core quorum of ${coreQuorumOrganizations}`,
          root.path,
          `Raise the threshold so more than ${orgCount - coreQuorumOrganizations} Tier-1 organizations must agree.`,
        );
      } else if (minTier1OrganizationsToAgree < Math.floor(orgCount / 2) + 1) {
        emit(
          TIER1_NARROW_AGREEMENT,
          'warning',
          `The quorum slice is satisfied by ${minTier1OrganizationsToAgree} of ${orgCount} Tier-1 organizations, a minority of the consensus core`,
          root.path,
          'Require a majority of Tier-1 organizations to agree.',
        );
      }

      if (represented.length < coreQuorumOrganizations) {
        emit(
          TIER1_LOW_REPRESENTATION,
          'warning',
          `Only ${represented.length} of ${orgCount} Tier-1 organizations appear in the quorum slice`,
          root.path,
          `Include validators from at least ${coreQuorumOrganizations} Tier-1 organizations.`,
        );
      }
      for (const org of coverage) {
        if (org.inSlice > 0 && org.inSlice < Math.floor(org.total / 2) + 1) {
          emit(
            TIER1_PARTIAL_ORGANIZATION,
            'info',
            `${org.name} is represented by ${org.inSlice} of its ${org.total} validators, so one node outage removes it from the slice`,
            root.path,
            `List a majority of ${org.name}'s validators in one inner set.`,
          );
        }
      }
    }

    return {
      ok: !diagnostics.some((d) => d.severity === 'error'),
      source: config.source,
      catalog: {
        updated: this.catalog.updated,
        organizations: orgCount,
        ...(this.catalog.source === undefined ? {} : { source: this.catalog.source }),
      },
      organizations: coverage,
      representedOrganizations: represented.length,
      representationRatio: orgCount === 0 ? 0 : represented.length / orgCount,
      quorumSets,
      minTier1OrganizationsToAgree,
      coreQuorumOrganizations,
      unverifiedValidators: unverified,
      nonTier1Validators: nonTier1Keys.length,
      diagnostics,
    };
  }
}

function bar(filled: number, total: number): string {
  const width = Math.max(total, 1);
  return '█'.repeat(filled) + '░'.repeat(Math.max(width - filled, 0));
}

/** Human-readable report with per-organization representation bars. */
export function renderTier1AlignmentReport(report: Tier1AlignmentReport): string {
  const sourceLabel =
    report.source === 'explicit'
      ? 'explicit [QUORUM_SET]'
      : report.source === 'automatic'
        ? 'automatic quorum from QUALITY-rated [[VALIDATORS]]'
        : 'none';
  const nameWidth = Math.max(...report.organizations.map((org) => org.name.length), 12);
  const lines = [
    `Tier-1 quorum alignment (catalog ${report.catalog.updated}, ${report.catalog.organizations} organizations)`,
    `  quorum source: ${sourceLabel}`,
  ];
  for (const org of report.organizations) {
    const mark = org.inSlice === 0 ? '✘' : org.inSlice * 2 > org.total ? '✔' : '⚠';
    lines.push(
      `  ${mark} ${org.name.padEnd(nameWidth)} ${bar(org.inSlice, org.total)} ${org.inSlice}/${org.total}`,
    );
  }
  lines.push(
    `  representation: ${report.representedOrganizations}/${report.catalog.organizations} organizations (${Math.round(report.representationRatio * 100)}%)`,
  );
  for (const set of report.quorumSets) {
    if (set.validators === 0) continue;
    lines.push(
      `  ${set.path}: ${set.tier1Validators}/${set.validators} validators are Tier-1 (${Math.round(set.tier1Ratio * 100)}%), threshold ${set.threshold}/${set.members}`,
    );
  }
  if (report.source !== 'none') {
    lines.push(
      report.minTier1OrganizationsToAgree === null
        ? '  agreement: the quorum set can never be satisfied'
        : `  agreement: needs ${report.minTier1OrganizationsToAgree} Tier-1 organization(s) to agree (core quorum: ${report.coreQuorumOrganizations})`,
    );
  }
  if (report.nonTier1Validators > 0) {
    lines.push(`  non-Tier-1 validators in slice: ${report.nonTier1Validators}`);
  }
  if (report.unverifiedValidators.length > 0) {
    lines.push(`  unverified Tier-1 claims: ${report.unverifiedValidators.join(', ')}`);
  }
  lines.push(`  verdict: ${report.ok ? 'ALIGNED' : 'MISALIGNED'}`);
  return `${lines.join('\n')}\n`;
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const tier1AlignmentRules: Rule[] = [
  {
    id: TIER1_INDEPENDENT_QUORUM,
    category: 'network',
    severity: 'error',
    description: 'A quorum slice must not be satisfiable without Tier-1 organizations',
    run() {},
  },
  {
    id: TIER1_SPLIT_QUORUM,
    category: 'network',
    severity: 'error',
    description: 'A quorum slice must require enough Tier-1 organizations to overlap the core',
    run() {},
  },
  {
    id: TIER1_NARROW_AGREEMENT,
    category: 'network',
    severity: 'warning',
    description: 'A quorum slice should require a majority of Tier-1 organizations to agree',
    run() {},
  },
  {
    id: TIER1_LOW_REPRESENTATION,
    category: 'network',
    severity: 'warning',
    description: 'A quorum slice should include at least two thirds of Tier-1 organizations',
    run() {},
  },
  {
    id: TIER1_PARTIAL_ORGANIZATION,
    category: 'network',
    severity: 'info',
    description: 'A Tier-1 organization should be represented by a majority of its validators',
    run() {},
  },
  {
    id: TIER1_UNVERIFIED_VALIDATOR,
    category: 'network',
    severity: 'warning',
    description: 'Validators claiming a Tier-1 home domain must be listed in the Tier-1 catalog',
    run() {},
  },
  {
    id: TIER1_UNRESOLVED_VALIDATOR,
    category: 'network',
    severity: 'warning',
    description: 'Quorum set entries must resolve to validator public keys',
    run() {},
  },
  {
    id: TIER1_THRESHOLD_INVALID,
    category: 'network',
    severity: 'error',
    description: 'Quorum set thresholds must be in range and satisfiable',
    run() {},
  },
  {
    id: TIER1_QUORUM_UNDECLARED,
    category: 'network',
    severity: 'info',
    description: 'Tier-1 alignment needs a quorum set to evaluate',
    run() {},
  },
];

export const tier1AlignmentRuleIds: readonly string[] = tier1AlignmentRules.map((rule) => rule.id);
