import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { specUrl } from '../spec.js';

/**
 * SCP quorum slice intersection solver (issue #85).
 *
 * Federated Byzantine Agreement keeps the network from forking only while
 * every pair of quorums intersects: two disjoint quorums can each close
 * consensus on conflicting ledgers. This solver reads the quorum sets that
 * validators declare — either inline as a `QUORUM_SET` table under
 * `[[VALIDATORS]]`, or in a linked `stellar-core.cfg` named by `CONFIG_URL` —
 * enumerates their minimal quorums and blocking sets, and reports whether
 * quorum intersection can fail.
 *
 * Analysis is exhaustive but capped (see MAX_* constants); a network large
 * enough to hit a cap is reported as "could not be fully analysed" and left
 * alone — a solver that guesses must not produce false errors.
 */

export const QUORUM_INTERSECTION_FAILURE_RULE = 'validators/quorum-intersection-failure';
export const FRAGILE_QUORUM_THRESHOLD_RULE = 'validators/fragile-quorum-threshold';

/** Two quorums this size would already be exponential; refuse to enumerate. */
const MAX_INNER_SETS = 24;
/** Upper bound on enumerated minimal quorums per validator. */
const MAX_MINIMAL_QUORUMS = 5_000;
/** Upper bound on minimal blocking sets per validator. */
const MAX_BLOCKING_SETS = 5_000;

/** A normalised quorum set: `threshold` of the `inner` members must agree. */
export interface QuorumSet {
  threshold: number;
  inner: Array<string | QuorumSet>;
}

/** Raw TOML / stellar-core.cfg shape, tolerant of field-naming variants. */
export interface RawQuorumSet {
  threshold_percent?: number;
  thresholdPercentage?: number;
  THRESHOLD_PERCENT?: number;
  validators?: unknown[];
  inner?: unknown[];
  inner_sets?: unknown[];
  quorum_sets?: unknown[];
}

export interface QuorumSolverOptions {
  rules?: RuleOverrides;
  /** Quorum sets keyed by validator public key, overriding the document. */
  quorumSets?: Record<string, RawQuorumSet>;
}

/** Whether analysis of one validator's set completed exhaustively. */
interface Analysis {
  publicKey: string;
  path: string;
  set: QuorumSet;
  percent: number;
  minimalQuorums: string[][];
  blockingSets: string[][];
  complete: boolean;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function pickNumber(...candidates: unknown[]): number | undefined {
  for (const candidate of candidates) {
    if (typeof candidate === 'number' && Number.isFinite(candidate)) return candidate;
    if (typeof candidate === 'string' && /^\d+(\.\d+)?$/.test(candidate.trim())) {
      return Number(candidate.trim());
    }
  }
  return undefined;
}

function pickArray(...candidates: unknown[]): unknown[] {
  for (const candidate of candidates) {
    if (Array.isArray(candidate)) return candidate;
    if (typeof candidate === 'string' && candidate.trim() !== '') return [candidate];
  }
  return [];
}

/**
 * Normalises a declared quorum set into the absolute-threshold form.
 *
 * `validators` entries become leaf identities, nested tables become child
 * sets, and `threshold_percent` (defaulting to stellar-core's 67) is rounded
 * up onto the child count, mirroring how stellar-core itself decides.
 * Returns `undefined` when the shape is not analysable.
 */
export function normalizeQuorumSet(raw: unknown): QuorumSet | undefined {
  if (!isRecord(raw)) return undefined;
  const direct = normalizeInner(raw);
  if (direct === undefined) return undefined;
  return direct;
}

function normalizeInner(raw: Record<string, unknown>): QuorumSet | undefined {
  const members = pickArray(raw.validators, raw.VALIDATORS, raw.node_ids);
  const nested = pickArray(
    raw.inner,
    raw.inner_sets,
    raw.quorum_sets,
    raw.QUORUM_SETS,
    raw.innerSets,
  );
  const inner: Array<string | QuorumSet> = [];
  for (const member of members) {
    if (typeof member === 'string' && member.trim() !== '') inner.push(member.trim());
  }
  for (const child of nested) {
    if (typeof child === 'string' && child.trim() !== '') {
      inner.push(child.trim());
      continue;
    }
    const childSet = isRecord(child) ? normalizeInner(child) : undefined;
    if (childSet === undefined) return undefined;
    inner.push(childSet);
  }
  if (inner.length === 0) return undefined;

  const percent =
    pickNumber(raw.threshold_percent, raw.thresholdPercentage, raw.THRESHOLD_PERCENT) ?? 67;
  if (percent <= 0 || percent > 100) return undefined;
  const threshold = Math.max(1, Math.ceil((percent / 100) * inner.length));
  return { threshold, inner };
}

/** The universe of public keys a set (and its children) can ever agree on. */
function collectMembers(set: QuorumSet): Set<string> {
  const found = new Set<string>();
  const visit = (candidate: QuorumSet): void => {
    for (const child of candidate.inner) {
      if (typeof child === 'string') found.add(child);
      else visit(child);
    }
  };
  visit(set);
  return found;
}

/**
 * Enumerates the minimal satisfying member sets of a quorum set.
 *
 * A quorum needs exactly `threshold` children (more is never minimal); the
 * chosen children contribute their own minimal quorums, and unions are then
 * minimised. `complete=false` signals a cap was hit and results are partial.
 */
export function minimalQuorums(set: QuorumSet): { quorums: string[][]; complete: boolean } {
  let complete = true;

  const solve = (candidate: QuorumSet): string[][] => {
    const children: string[][][] = [];
    for (const child of candidate.inner) {
      if (typeof child === 'string') {
        children.push([[child]]);
        continue;
      }
      const childQuorums = solve(child);
      if (childQuorums.length === 0) {
        complete = false;
        return [];
      }
      children.push(childQuorums);
    }
    if (children.length > MAX_INNER_SETS) {
      complete = false;
      return [];
    }

    const results: string[][] = [];
    const seen = new Set<string>();
    const combine = (index: number, chosen: number[], acc: string[]): void => {
      const need = candidate.threshold - chosen.length;
      const remaining = children.length - index;
      if (need <= 0) {
        const minimal = minimiseUnion(acc);
        const key = minimal.join(',');
        if (!seen.has(key)) {
          seen.add(key);
          results.push(minimal);
        }
        if (results.length > MAX_MINIMAL_QUORUMS) complete = false;
        return;
      }
      if (remaining < need) return;
      for (let i = index; i <= children.length - need; i++) {
        if (results.length > MAX_MINIMAL_QUORUMS) {
          complete = false;
          return;
        }
        for (const option of children[i] ?? []) {
          chosen.push(i);
          combine(i + 1, chosen, [...acc, ...option]);
          chosen.pop();
        }
      }
    };
    combine(0, [], []);
    return results;
  };

  const quorums = solve(set);
  const unique = new Map<string, string[]>();
  for (const quorum of quorums) {
    const sorted = [...new Set(quorum)].sort();
    unique.set(sorted.join(','), sorted);
  }
  // A union across chosen slices can swallow another candidate; only the
  // minimal sets matter for disjointness, so trim the rest away.
  return { quorums: keepMinimalSets([...unique.values()]), complete };
}

function minimiseUnion(members: string[]): string[] {
  return [...new Set(members)].sort();
}

/** True when no member set of `candidate` is a superset of another. */
function keepMinimalSets(sets: string[][]): string[][] {
  const sorted = [...sets].sort((a, b) => a.length - b.length);
  const kept: string[][] = [];
  for (const candidate of sorted) {
    const covered = kept.some((smaller) => smaller.every((member) => candidate.includes(member)));
    if (!covered) kept.push(candidate);
  }
  return kept;
}

/**
 * Minimal blocking sets of one validator's quorum set: the smallest groups of
 * members whose failure leaves that validator unable to reach any quorum —
 * i.e. the minimal hitting sets over its minimal quorums.
 *
 * Enumeration runs by increasing subset size and stops at the first size that
 * blocks: every blocker found there is automatically minimal (nothing smaller
 * hits all quorums) and sufficient for the resilience figure. The search is
 * capped at BLOCKING_SET_MAX_SIZE; networks needing more coordinated failures
 * than that report `complete=false` rather than a number.
 */
const BLOCKING_SET_MAX_SIZE = 6;

export function minimalBlockingSets(
  set: QuorumSet,
  quorums: string[][],
): { blockingSets: string[][]; complete: boolean } {
  if (quorums.length === 0) return { blockingSets: [], complete: false };
  const universe = [...collectMembers(set)].sort();
  let candidateCount = 0;

  for (let size = 1; size <= Math.min(universe.length, BLOCKING_SET_MAX_SIZE); size++) {
    const hits: string[][] = [];
    const choose = (start: number, picked: string[]): void => {
      if (candidateCount++ > MAX_BLOCKING_SETS) return;
      if (picked.length === size) {
        const blocks = quorums.every((quorum) => quorum.some((member) => picked.includes(member)));
        if (blocks) hits.push([...picked]);
        return;
      }
      for (let i = start; i < universe.length; i++) {
        picked.push(universe[i] as string);
        choose(i + 1, picked);
        picked.pop();
      }
    };
    choose(0, []);
    if (hits.length > 0) return { blockingSets: hits, complete: true };
  }
  // Nothing blocked within the cap: either the whole (small) universe was
  // exhausted — impossible, it always hits — or the answer is beyond it.
  return { blockingSets: [], complete: universe.length <= BLOCKING_SET_MAX_SIZE };
}

/**
 * How many crashes the validator tolerates before it can no longer close
 * ledgers. `undefined` when the blocking-set analysis was capped.
 */
export function failureResilience(blockingSets: string[][], complete: boolean): number | undefined {
  if (!complete) return undefined;
  if (blockingSets.length === 0) return Number.POSITIVE_INFINITY;
  const smallest = Math.min(...blockingSets.map((block) => block.length));
  return smallest - 1;
}

/** The first disjoint quorum pair across two validators, if one exists. */
export function findDisjointQuorumPair(
  left: { publicKey: string; quorums: string[][] },
  right: { publicKey: string; quorums: string[][] },
): [string[], string[]] | undefined {
  for (const a of left.quorums) {
    for (const b of right.quorums) {
      if (a.every((member) => !b.includes(member))) return [a, b];
    }
  }
  return undefined;
}

/**
 * Parses the `[QUORUM_SET]` stanza family of a stellar-core.cfg.
 *
 * Handles `THRESHOLD_PERCENT`, `VALIDATORS` (inline arrays or one-per-line
 * string lists), nested `[QUORUM_SET.<name>]` sections, and `$alias` child
 * references resolved against names or public keys elsewhere in the stanza
 * tree. Returns `undefined` for configs it cannot fully interpret.
 */
export function parseCoreCfgQuorumSet(text: string): QuorumSet | undefined {
  type Pending = {
    name: string;
    percent?: number;
    validators: string[];
    children: Map<string, Pending>;
  };

  const root: Pending = { name: '', validators: [], children: new Map() };
  let current: Pending = root;
  let inQuorumTree = false;
  const lines = text.split(/\r?\n/);

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (line === '' || line.startsWith('#') || line.startsWith('//')) continue;

    const section = /^\[([A-Za-z0-9_.-]+)\]$/.exec(line);
    if (section?.[1] !== undefined) {
      const name = section[1];
      inQuorumTree = name === 'QUORUM_SET' || name.startsWith('QUORUM_SET.');
      if (!inQuorumTree) {
        current = root;
        continue;
      }
      if (name === 'QUORUM_SET') {
        current = root;
      } else {
        const childName = name.slice('QUORUM_SET.'.length);
        let child = root.children.get(childName);
        if (child === undefined) {
          child = { name: childName, validators: [], children: new Map() };
          root.children.set(childName, child);
        }
        current = child;
      }
      continue;
    }
    if (!inQuorumTree) continue;

    const threshold = /^THRESHOLD_PERCENT\s*=\s*(\d+)/i.exec(line);
    if (threshold?.[1] !== undefined) {
      current.percent = Number(threshold[1]);
      continue;
    }
    const validatorsMatch = /^VALIDATORS\s*=\s*(.+)/i.exec(line);
    if (validatorsMatch?.[1] !== undefined) {
      const value = validatorsMatch[1].trim();
      const items = value.startsWith('[')
        ? [...value.matchAll(/"([^"]+)"|'([^']+)'|([^,[\]\s]+)/g)]
            .map((m) => (m[1] ?? m[2] ?? m[3] ?? '').trim())
            .filter((item) => item !== '')
        : [value.replace(/^"|"$/g, '').trim()].filter((item) => item !== '');
      current.validators.push(...items);
    }
  }

  // `$full1` means "the quorum set defined by [QUORUM_SET.full1]" — the same
  // validator, at its own threshold. Stanzas no reference points at are part
  // of no slice and stay out of the tree.
  const build = (pending: Pending, path: Set<string>): QuorumSet | undefined => {
    if (path.has(pending.name)) return undefined; // cycle
    path.add(pending.name);
    const inner: Array<string | QuorumSet> = [];
    for (const entry of pending.validators) {
      if (!entry.startsWith('$')) {
        inner.push(entry);
        continue;
      }
      const reference = entry.slice(1);
      const child = root.children.get(reference);
      if (child !== undefined) {
        const childSet = build(child, new Set(path));
        if (childSet === undefined) return undefined;
        inner.push(childSet);
        continue;
      }
      // `$GABC...` may also reference a public key listed elsewhere in the
      // tree — that validator's agreement, not a nested slice.
      const allEntries = [root, ...root.children.values()].flatMap((node) => node.validators);
      if (allEntries.includes(reference)) {
        inner.push(reference);
        continue;
      }
      return undefined;
    }
    if (inner.length === 0) return undefined;
    const percent = pending.percent ?? 67;
    const threshold = Math.max(1, Math.ceil((percent / 100) * inner.length));
    return { threshold, inner };
  };

  const resolved = build(root, new Set());
  return resolved === undefined || resolved.inner.length === 0 ? undefined : resolved;
}

function validatorEntries(doc: Record<string, unknown>): Array<Record<string, unknown>> {
  const list = Array.isArray(doc.VALIDATORS) ? doc.VALIDATORS : [];
  return list.filter((entry): entry is Record<string, unknown> => isRecord(entry));
}

async function fetchCoreCfg(url: string, fetchImpl: typeof fetch): Promise<QuorumSet | undefined> {
  try {
    const response = await fetchImpl(url);
    if (!response.ok) return undefined;
    const text = await response.text();
    return parseCoreCfgQuorumSet(text);
  } catch {
    return undefined;
  }
}

/**
 * Audits declared quorum configuration for split-brain risk.
 *
 * Emits `validators/quorum-intersection-failure` (error) when two validators
 * can form disjoint quorums, and `validators/fragile-quorum-threshold`
 * (warning) for a quorum set below the two-thirds safety margin or one that a
 * single member failure can block. Validators with no declared quorum set,
 * unreachable configs, and capped analyses degrade to silence — the check
 * only ever reports what it proved.
 */
export async function checkQuorumIntersection(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: QuorumSolverOptions = {},
): Promise<Diagnostic[]> {
  const validators = validatorEntries(doc);
  if (validators.length < 2) return [];

  const analyses: Analysis[] = [];
  for (let index = 0; index < validators.length; index++) {
    const entry = validators[index];
    if (entry === undefined) continue;
    const publicKey = typeof entry.PUBLIC_KEY === 'string' ? entry.PUBLIC_KEY : undefined;
    if (publicKey === undefined) continue;
    const path = `VALIDATORS[${index}].QUORUM_SET`;

    let set: QuorumSet | undefined;
    const override = options.quorumSets?.[publicKey];
    if (override !== undefined) {
      set = normalizeQuorumSet(override);
    } else if (entry.QUORUM_SET !== undefined) {
      set = normalizeQuorumSet(entry.QUORUM_SET);
    } else if (typeof entry.CONFIG_URL === 'string') {
      set = await fetchCoreCfg(entry.CONFIG_URL, fetchImpl);
    }
    if (set === undefined) continue;

    const { quorums, complete } = minimalQuorums(set);
    const blocking = minimalBlockingSets(set, quorums);
    analyses.push({
      publicKey,
      path,
      set,
      percent: approximatePercent(set),
      minimalQuorums: quorums,
      blockingSets: blocking.blockingSets,
      complete: complete && blocking.complete && quorums.length > 0,
    });
  }

  if (analyses.length < 2) return [];

  const diagnostics: Diagnostic[] = [];
  const report = (
    rule: string,
    fallback: 'error' | 'warning',
    finding: Omit<Diagnostic, 'rule' | 'severity' | 'category'>,
  ): void => {
    const override = options.rules?.[rule];
    if (override === 'off') return;
    diagnostics.push({
      ...finding,
      rule,
      category: 'validators',
      severity: override === 'error' || override === 'warning' ? override : fallback,
    });
  };

  outer: for (let i = 0; i < analyses.length; i++) {
    for (let j = i + 1; j < analyses.length; j++) {
      const left = analyses[i];
      const right = analyses[j];
      if (left === undefined || right === undefined) continue;
      if (!left.complete || !right.complete) continue;
      const pair = findDisjointQuorumPair(
        { publicKey: left.publicKey, quorums: left.minimalQuorums },
        { publicKey: right.publicKey, quorums: right.minimalQuorums },
      );
      if (pair !== undefined) {
        report(QUORUM_INTERSECTION_FAILURE_RULE, 'error', {
          message:
            `Quorum intersection can fail: ${left.publicKey} and ${right.publicKey} can form ` +
            `disjoint quorums (${pair[0].join(', ')} vs ${pair[1].join(', ')}), so the network ` +
            'can split-brain and close conflicting ledgers on each side',
          path: left.path,
          helpUri: specUrl('validator-information'),
          suggestion:
            'Redefine the quorum sets so every pair of quorums shares a validator, or add an ' +
            'overlapping high-threshold slice both sides must agree with.',
        });
        break outer;
      }
    }
  }

  for (const analysis of analyses) {
    const reasons: string[] = [];
    if (analysis.percent < 67) {
      reasons.push(
        `threshold is ${analysis.percent}% of ${analysis.set.inner.length} slices, below the 67% two-thirds safety margin`,
      );
    }
    const resilience = failureResilience(analysis.blockingSets, analysis.complete);
    if (resilience === 0) {
      const blocker = analysis.blockingSets
        .filter((block) => block.length === 1)
        .map((block) => block[0])
        .join(', ');
      reasons.push(`a single member failure (${blocker}) halts this validator`);
    }
    if (reasons.length > 0) {
      report(FRAGILE_QUORUM_THRESHOLD_RULE, 'warning', {
        message: `Validator ${analysis.publicKey} has a fragile quorum configuration: ${reasons.join('; ')}`,
        path: analysis.path,
        helpUri: specUrl('validator-information'),
        suggestion:
          'Raise the threshold toward 2/3 of well-distributed slices so no small coalition can steer or halt consensus.',
      });
    }
  }

  return diagnostics;
}

function approximatePercent(set: QuorumSet): number {
  return Math.round((set.threshold / set.inner.length) * 100);
}

/** Rules registered so `--list-rules`, `--off`, and SARIF know the ids. */
export const quorumSolverRules: Rule[] = [
  {
    id: QUORUM_INTERSECTION_FAILURE_RULE,
    category: 'validators',
    severity: 'error',
    description: 'Declared quorum sets must guarantee intersection — no disjoint quorums',
    run() {},
  },
  {
    id: FRAGILE_QUORUM_THRESHOLD_RULE,
    category: 'validators',
    severity: 'warning',
    description: 'Quorum thresholds should sit at or above the two-thirds safety margin',
    run() {},
  },
];

export const quorumSolverRuleIds: readonly string[] = quorumSolverRules.map((rule) => rule.id);
