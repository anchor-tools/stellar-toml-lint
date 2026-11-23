/**
 * Bridge validator quorum and staking auditor.
 *
 * Runs under opt-in `--audit-bridge-quorum` or
 * `audit-bridge-quorum --domain <domain>`; staking evidence is only fetched
 * with `--check-network`.
 *
 * Each `[[BRIDGES]]` table may declare:
 *
 *   RELAYER_KEYS            Stellar keys of the active relayer set (n)
 *   THRESHOLD               signatures needed to authorise a mint or burn (m)
 *   PREVIOUS_RELAYER_KEYS   the set before a rotation
 *   STAKING_CONTRACT, MIN_STAKE, STAKING_EVIDENCE_URL
 *
 * Byzantine fault tolerance needs m >= 2n/3, checked with integers
 * (`3m >= 2n`). A threshold at or below half lets a bare majority collude.
 * Evidence is JSON: `{ "bonds": { "<key>": "<amount>" }, "slashing": [...] }`.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isAccountId, isHttpsUrl } from '../predicates.js';
import {
  createReporter,
  errorMessage,
  fetchWithTimeout,
  isRecord,
  toScaled,
} from '../protocols/verifierSupport.js';
import { bridgesOf } from './bridgeSupport.js';

const KEY_RULE = 'bridgequorum/invalid-relayer-key';
const DUP_RULE = 'bridgequorum/duplicate-relayer';
const THRESHOLD_RULE = 'bridgequorum/invalid-threshold';
const SUPERMAJORITY_RULE = 'bridgequorum/below-supermajority';
const MINORITY_RULE = 'bridgequorum/minority-threshold';
const SMALL_SET_RULE = 'bridgequorum/small-validator-set';
const ROTATION_RULE = 'bridgequorum/abrupt-rotation';
const STAKING_RULE = 'bridgequorum/missing-staking';
const STAKE_RULE = 'bridgequorum/insufficient-stake';
const SLASHING_RULE = 'bridgequorum/missing-slashing';
const EVIDENCE_RULE = 'bridgequorum/evidence-unavailable';

const SPEC = 'https://pmg.csail.mit.edu/papers/osdi99.pdf';

export interface StakingEvidence {
  bonds?: Record<string, string>;
  slashing?: unknown[];
}

export interface BridgeQuorumOptions {
  rules?: RuleOverrides;
  /** Fetch `STAKING_EVIDENCE_URL` documents. */
  probe?: boolean;
  /** Evidence supplied directly, keyed by bridge NAME. Takes precedence over fetching. */
  evidence?: Record<string, StakingEvidence>;
  timeoutMs?: number;
}

export interface BridgeQuorumSummary {
  relayers: number;
  threshold: number | undefined;
  /** Smallest compliant threshold, `ceil(2n/3)`. */
  required: number;
  /** Faults tolerated: `floor((n - 1) / 3)`. */
  faultTolerance: number;
}

export interface BridgeQuorumResult {
  diagnostics: Diagnostic[];
  bridges: Record<string, BridgeQuorumSummary>;
}

/** Smallest m with 3m >= 2n. */
export const requiredThreshold = (n: number): number => Math.ceil((2 * n) / 3);

/** Relayers dropped or added by a rotation, and whether enough of the old set carries over. */
export function rotationContinuity(
  previous: string[],
  next: string[],
): { retained: number; continuous: boolean } {
  const prev = new Set(previous);
  const retained = new Set(next.filter((k) => prev.has(k))).size;
  // The old quorum must still be able to vouch for the new set: at least 2/3 stays.
  return { retained, continuous: retained * 3 >= prev.size * 2 };
}

const keysOf = (value: unknown): unknown[] | undefined =>
  Array.isArray(value) ? value : undefined;

export class BridgeQuorumAuditor {
  constructor(
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly options: BridgeQuorumOptions = {},
  ) {}

  async audit(doc: Record<string, unknown>): Promise<BridgeQuorumResult> {
    const diagnostics: Diagnostic[] = [];
    const bridges: Record<string, BridgeQuorumSummary> = {};
    const push = createReporter(diagnostics, this.options.rules, SPEC, 'policy');

    for (const bridge of bridgesOf(doc)) {
      const at = `BRIDGES[${bridge.index}]`;
      const name = bridge.name;
      const raw = keysOf(bridge.raw.RELAYER_KEYS);
      if (raw === undefined) {
        push(
          KEY_RULE,
          'error',
          `${name}: RELAYER_KEYS must be an array of Stellar public keys`,
          `${at}.RELAYER_KEYS`,
          'Declare every active relayer key.',
        );
        continue;
      }
      const valid: string[] = [];
      raw.forEach((key, i) => {
        if (!isAccountId(key)) {
          push(
            KEY_RULE,
            'error',
            `${name}: RELAYER_KEYS[${i}] is not a valid Stellar public key`,
            `${at}.RELAYER_KEYS[${i}]`,
            'Use the G... key each relayer signs with.',
          );
        } else if (valid.includes(key as string)) {
          push(
            DUP_RULE,
            'error',
            `${name}: RELAYER_KEYS[${i}] repeats an earlier key, so it adds no independent signer`,
            `${at}.RELAYER_KEYS[${i}]`,
            'List each relayer once; a duplicate inflates the apparent set size.',
          );
        } else valid.push(key as string);
      });
      const n = valid.length;
      const required = requiredThreshold(n);
      const m = bridge.raw.THRESHOLD;
      const threshold = Number.isInteger(m) ? (m as number) : undefined;
      bridges[name] = {
        relayers: n,
        threshold,
        required,
        faultTolerance: Math.floor((n - 1) / 3),
      };

      if (threshold === undefined || threshold < 1 || threshold > n) {
        push(
          THRESHOLD_RULE,
          'error',
          `${name}: THRESHOLD must be an integer between 1 and the ${n} distinct relayers`,
          `${at}.THRESHOLD`,
          'Set THRESHOLD to the number of signatures required (m of n).',
        );
      } else if (threshold * 2 <= n) {
        push(
          MINORITY_RULE,
          'error',
          `${name}: ${threshold}-of-${n} is not even a majority; a minority can authorise mints`,
          `${at}.THRESHOLD`,
          `Raise THRESHOLD to at least ${required}.`,
        );
      } else if (threshold * 3 < n * 2) {
        push(
          SUPERMAJORITY_RULE,
          'warning',
          `${name}: ${threshold}-of-${n} is below the 2/3 BFT supermajority (${required} needed)`,
          `${at}.THRESHOLD`,
          `Raise THRESHOLD to at least ${required}.`,
        );
      }
      if (n > 0 && n < 4) {
        push(
          SMALL_SET_RULE,
          'warning',
          `${name}: ${n} relayer${n === 1 ? '' : 's'} cannot tolerate any Byzantine fault (n >= 3f + 1)`,
          `${at}.RELAYER_KEYS`,
          'Run at least four independent relayers to tolerate one faulty or colluding member.',
        );
      }

      const previous = keysOf(bridge.raw.PREVIOUS_RELAYER_KEYS)?.filter((k): k is string =>
        isAccountId(k),
      );
      if (previous && previous.length > 0) {
        const { retained, continuous } = rotationContinuity(previous, valid);
        if (!continuous) {
          push(
            ROTATION_RULE,
            'warning',
            `${name}: rotation keeps only ${retained} of ${previous.length} previous relayers; the old quorum cannot vouch for the new set`,
            `${at}.PREVIOUS_RELAYER_KEYS`,
            'Rotate in stages so at least two thirds of the set carries over each time.',
          );
        }
      }
      await this.checkStaking(bridge.raw, name, at, valid, push);
    }
    return { diagnostics, bridges };
  }

  private async checkStaking(
    raw: Record<string, unknown>,
    name: string,
    at: string,
    relayers: string[],
    push: ReturnType<typeof createReporter>,
  ): Promise<void> {
    if (typeof raw.STAKING_CONTRACT !== 'string' || raw.STAKING_CONTRACT === '') {
      push(
        STAKING_RULE,
        'warning',
        `${name}: no STAKING_CONTRACT, so relayer misbehaviour has no economic penalty`,
        `${at}.STAKING_CONTRACT`,
        'Bond relayer stake in an on-chain contract with slashing conditions.',
      );
      return;
    }
    let evidence = this.options.evidence?.[name];
    const url = raw.STAKING_EVIDENCE_URL;
    if (evidence === undefined && this.options.probe && typeof url === 'string') {
      if (!isHttpsUrl(url)) {
        push(
          EVIDENCE_RULE,
          'warning',
          `${name}: STAKING_EVIDENCE_URL must be https`,
          `${at}.STAKING_EVIDENCE_URL`,
          'Publish evidence over https.',
        );
        return;
      }
      try {
        const res = await fetchWithTimeout(this.fetchImpl, url, {}, this.options.timeoutMs);
        const body: unknown = await res.json();
        if (!res.ok || !isRecord(body)) throw new Error(`HTTP ${res.status}`);
        evidence = body as StakingEvidence;
      } catch (error) {
        push(
          EVIDENCE_RULE,
          'warning',
          `${name}: staking evidence could not be read (${errorMessage(error)})`,
          `${at}.STAKING_EVIDENCE_URL`,
          'Serve a JSON document with bonds and slashing conditions.',
        );
        return;
      }
    }
    if (evidence === undefined) return;

    const conditions = Array.isArray(evidence.slashing) ? evidence.slashing : [];
    if (conditions.length === 0) {
      push(
        SLASHING_RULE,
        'error',
        `${name}: the staking contract defines no slashing conditions`,
        `${at}.STAKING_CONTRACT`,
        'Define slashing for double signing and for signing invalid transfers.',
      );
    }
    const min = typeof raw.MIN_STAKE === 'string' ? toScaled(raw.MIN_STAKE) : undefined;
    const bonds = isRecord(evidence.bonds) ? evidence.bonds : {};
    for (const key of relayers) {
      const bonded = typeof bonds[key] === 'string' ? toScaled(bonds[key] as string) : undefined;
      if (bonded === undefined || bonded === 0n || (min !== undefined && bonded < min)) {
        push(
          STAKE_RULE,
          'error',
          `${name}: relayer ${key.slice(0, 8)}… has ${bonded === undefined || bonded === 0n ? 'no' : 'too little'} bonded stake`,
          `${at}.STAKING_CONTRACT`,
          min === undefined
            ? 'Require a bond from every relayer.'
            : `Bond at least ${String(raw.MIN_STAKE)} per relayer.`,
        );
      }
    }
  }
}

export async function auditBridgeQuorum(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: BridgeQuorumOptions = {},
): Promise<BridgeQuorumResult> {
  return new BridgeQuorumAuditor(fetchImpl, options).audit(doc);
}

const def = (id: string, description: string): Rule => ({
  id,
  category: 'policy',
  severity: 'warning',
  description,
  run() {},
});

export const bridgeQuorumRules: Rule[] = [
  def(KEY_RULE, 'Bridge relayer keys must be valid Stellar public keys'),
  def(DUP_RULE, 'Bridge relayer keys must be distinct'),
  def(THRESHOLD_RULE, 'Bridge THRESHOLD must be between 1 and the relayer count'),
  def(SUPERMAJORITY_RULE, 'Bridge threshold should be at least a 2/3 supermajority'),
  def(MINORITY_RULE, 'Bridge threshold must be more than half the relayers'),
  def(SMALL_SET_RULE, 'Bridge relayer sets should tolerate at least one Byzantine fault'),
  def(ROTATION_RULE, 'Relayer set rotations should retain two thirds of the previous set'),
  def(STAKING_RULE, 'Bridge relayers should be bonded in a staking contract'),
  def(STAKE_RULE, 'Every relayer must have sufficient bonded stake'),
  def(SLASHING_RULE, 'The staking contract must define slashing conditions'),
  def(EVIDENCE_RULE, 'Staking evidence must be readable'),
];

export const bridgeQuorumRuleIds: readonly string[] = bridgeQuorumRules.map((r) => r.id);
