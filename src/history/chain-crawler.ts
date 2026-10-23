/**
 * History Archive atomic-checkpoint consistency and HAS chain crawler
 * (issue #312).
 *
 * Stellar archives publish one History Archive State (HAS) per 64-ledger
 * checkpoint. A root HAS describes the newest checkpoint, and every older
 * checkpoint is addressable at the content-derived `history/xx/yy/zz/` path.
 * A catchup walks that chain backwards: if one checkpoint is missing, or if a
 * checkpoint's parent hash does not match the ledger hash of the checkpoint
 * before it, a joining validator silently diverges or aborts halfway through
 * replay.
 *
 * Under opt-in `--check-network --crawl-history` this module reads each
 * `[[VALIDATORS]].HISTORY` root state, crawls back through the previous ten
 * checkpoints, and checks two invariants:
 *
 *   1. the `currentLedger` of each checkpoint is exactly 64 less than the one
 *      after it (the first may be at the newest published boundary);
 *   2. a newer checkpoint's `previousLedgerHash` matches the older checkpoint's
 *      ledger hash.
 *
 * Findings:
 *   - `history/broken-checkpoint-sequence` (error) for a missing, malformed, or
 *     non-consecutive checkpoint;
 *   - `history/checkpoint-ledger-hash-mismatch` (error) when adjacent
 *     checkpoints disagree about their shared ledger hash.
 *
 * An unreadable root HAS degrades to silence; the crawler only reports links it
 * actually followed.
 */

import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';
import { specUrl } from '../spec.js';
import { archiveBase, readJson } from './publish-validator.js';
import {
  CHECKPOINT_FREQUENCY,
  checkpointContaining,
  checkpointFilePath,
  isCheckpointLedger,
  latestArchivedLedger,
} from './gap-auditor.js';

export const BROKEN_CHECKPOINT_SEQUENCE_RULE = 'history/broken-checkpoint-sequence';
export const CHECKPOINT_LEDGER_HASH_MISMATCH_RULE = 'history/checkpoint-ledger-hash-mismatch';

export const HISTORY_BROKEN_CHECKPOINT_SEQUENCE = BROKEN_CHECKPOINT_SEQUENCE_RULE;
export const HISTORY_CHECKPOINT_LEDGER_HASH_MISMATCH = CHECKPOINT_LEDGER_HASH_MISMATCH_RULE;
export const CHECKPOINT_CHAIN_HASH_MISMATCH_RULE = CHECKPOINT_LEDGER_HASH_MISMATCH_RULE;

/** How many previous checkpoints the crawler follows by default. */
export const DEFAULT_CRAWLED_CHECKPOINTS = 10;

export interface ChainCrawlerOptions {
  rules?: RuleOverrides;
  /** Number of older checkpoints to fetch. Defaults to 10. */
  maxCheckpoints?: number;
  /** Alias for `maxCheckpoints`. */
  checkpointCount?: number;
}

/** One parsed root or checkpoint HAS. */
export interface HistoryCheckpointRecord {
  /** The checkpoint's `currentLedger`. */
  ledger: number;
  /** The ledger/root hash this HAS declares for that checkpoint. */
  hash?: string;
  /** The hash the newer checkpoint says its parent had. */
  previousHash?: string;
  /** Explicit numeric parent ledger, when the HAS declares one. */
  previousLedger?: number;
  /** Explicit URL of the previous HAS, when the HAS declares one. */
  parentUrl?: string;
  /** URL this record was read from. */
  url: string;
  source: 'root' | 'checkpoint';
}

export type HistoryChainIssue =
  | {
      kind: 'broken-sequence';
      reason: 'missing' | 'malformed' | 'interval' | 'not-decreasing';
      expected: number;
      actual?: number;
      newer?: number;
      url: string;
    }
  | {
      kind: 'hash-mismatch';
      newer: number;
      older: number;
      expected: string;
      actual: string;
      url: string;
    };

export interface HistoryChainAudit {
  /** The root HAS's `currentLedger`, or `undefined` when it could not be read. */
  rootLedger?: number;
  /** The root first, then each older checkpoint in crawl order. */
  checkpoints: HistoryCheckpointRecord[];
  issues: HistoryChainIssue[];
  /** True when the requested number of checkpoints was reached without a gap. */
  complete: boolean;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : undefined;
}

function numberValue(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isInteger(value) && value >= 0) return value;
  if (typeof value === 'string' && /^\d+$/.test(value.trim())) return Number(value.trim());
  return undefined;
}

export type ParsedHistoryCheckpoint = Omit<HistoryCheckpointRecord, 'ledger' | 'url' | 'source'> & {
  ledger?: number;
};

function severityFor(
  rule: string,
  fallback: Severity,
  rules: RuleOverrides | undefined,
): Severity | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' || override === 'info'
    ? override
    : fallback;
}

/**
 * Parses the ledger, ledger hash, parent hash, and optional parent link out of
 * a HAS. Field names from both stellar-core HAS versions and looser mirrors are
 * accepted; a HAS that declares no ledger still parses (the caller reports the
 * missing sequence).
 */
export function parseHistoryCheckpoint(body: unknown): ParsedHistoryCheckpoint {
  if (!isRecord(body)) return {};
  const nestedLedger = isRecord(body.ledger) ? body.ledger : undefined;
  const ledger =
    latestArchivedLedger(body) ??
    numberValue(body.current_ledger) ??
    numberValue(body.latestLedger) ??
    numberValue(nestedLedger?.sequence) ??
    numberValue(nestedLedger?.currentLedger);

  const hash =
    stringValue(body.ledgerHash) ??
    stringValue(body.ledger_hash) ??
    stringValue(body.currentLedgerHash) ??
    stringValue(body.current_ledger_hash) ??
    stringValue(body.rootHash) ??
    stringValue(body.root_hash) ??
    stringValue(body.latest_ledger_hash) ??
    stringValue(body.latestLedgerHash) ??
    stringValue(body.hash) ??
    stringValue(nestedLedger?.hash);

  const previousHash =
    stringValue(body.previousLedgerHash) ??
    stringValue(body.previous_ledger_hash) ??
    stringValue(body.prevLedgerHash) ??
    stringValue(body.prev_ledger_hash) ??
    stringValue(body.parentLedgerHash) ??
    stringValue(body.parent_ledger_hash) ??
    stringValue(body.previousHash) ??
    stringValue(body.previous_hash) ??
    stringValue(body.parentHash) ??
    stringValue(body.parent_hash) ??
    stringValue(nestedLedger?.previousHash);

  const previousLedger =
    numberValue(body.previousLedger) ??
    numberValue(body.previous_ledger) ??
    numberValue(body.previousLedgerSequence) ??
    numberValue(body.previous_ledger_sequence) ??
    numberValue(body.parentLedger) ??
    numberValue(body.parent_ledger) ??
    numberValue(body.parentSequence);

  const parentUrl =
    stringValue(body.previousHistory) ??
    stringValue(body.previousHAS) ??
    stringValue(body.previousHistoryState) ??
    stringValue(body.parentUrl) ??
    stringValue(body.parent_url) ??
    stringValue(body.previousUrl) ??
    stringValue(body.previous) ??
    stringValue(body.parent);

  return {
    ...(ledger === undefined ? {} : { ledger }),
    ...(hash === undefined ? {} : { hash }),
    ...(previousHash === undefined ? {} : { previousHash }),
    ...(previousLedger === undefined ? {} : { previousLedger }),
    ...(parentUrl === undefined ? {} : { parentUrl }),
  };
}

function record(
  parsed: ParsedHistoryCheckpoint,
  url: string,
  source: HistoryCheckpointRecord['source'],
): HistoryCheckpointRecord | undefined {
  if (parsed.ledger === undefined || !Number.isInteger(parsed.ledger) || parsed.ledger < 0) {
    return undefined;
  }
  return { ...parsed, ledger: parsed.ledger, url, source };
}

/**
 * Crawls one archive's HAS chain. The root state is always read first; then the
 * newest published checkpoint and the nine before it are fetched (ten total).
 *
 * A root whose `currentLedger` is not itself a checkpoint boundary has not been
 * published as a checkpoint yet, so the crawl starts from the newest boundary
 * before it, exactly as a catchup would.
 */
export async function crawlHistoryChain(
  baseUrl: string,
  fetchImpl: typeof fetch = fetch,
  options: ChainCrawlerOptions = {},
): Promise<HistoryChainAudit> {
  const requested = Math.max(
    0,
    Math.trunc(options.maxCheckpoints ?? options.checkpointCount ?? DEFAULT_CRAWLED_CHECKPOINTS),
  );
  const rootUrl = new URL('.well-known/stellar-history.json', baseUrl).toString();
  const rootBody = await readJson(rootUrl, fetchImpl);
  if (rootBody === undefined) {
    return { checkpoints: [], issues: [], complete: false };
  }

  const rootParsed = parseHistoryCheckpoint(rootBody);
  const root = record(rootParsed, rootUrl, 'root');
  if (root === undefined) {
    return { checkpoints: [], issues: [], complete: false };
  }

  const issues: HistoryChainIssue[] = [];
  const checkpoints: HistoryCheckpointRecord[] = [root];
  const rootIsBoundary = isCheckpointLedger(root.ledger);
  let current = root;
  let currentIsBoundary = rootIsBoundary;
  let expected = rootIsBoundary
    ? root.ledger - CHECKPOINT_FREQUENCY
    : checkpointContaining(root.ledger) - CHECKPOINT_FREQUENCY;
  let followed = 0;
  let complete = requested === 0;

  while (followed < requested && expected >= CHECKPOINT_FREQUENCY - 1) {
    const explicitParent = currentIsBoundary ? current.parentUrl : undefined;
    const url =
      explicitParent === undefined
        ? new URL(checkpointFilePath('history', expected), baseUrl).toString()
        : new URL(explicitParent, current.url).toString();

    const body = await readJson(url, fetchImpl);
    if (body === undefined) {
      issues.push({
        kind: 'broken-sequence',
        reason: 'missing',
        expected,
        newer: current.ledger,
        url,
      });
      break;
    }

    const parsed = parseHistoryCheckpoint(body);
    const next = record(parsed, url, 'checkpoint');
    if (next === undefined) {
      issues.push({
        kind: 'broken-sequence',
        reason: 'malformed',
        expected,
        newer: current.ledger,
        url,
      });
      break;
    }

    const requireInterval = currentIsBoundary;
    if (next.ledger >= current.ledger) {
      issues.push({
        kind: 'broken-sequence',
        reason: 'not-decreasing',
        expected,
        actual: next.ledger,
        newer: current.ledger,
        url,
      });
      checkpoints.push(next);
      break;
    }

    if (requireInterval && current.ledger - next.ledger !== CHECKPOINT_FREQUENCY) {
      issues.push({
        kind: 'broken-sequence',
        reason: 'interval',
        expected,
        actual: next.ledger,
        newer: current.ledger,
        url,
      });
    }

    // The newer HAS names its parent ledger; that link must point at the
    // checkpoint we just walked back to. The older checkpoint's own
    // `previousLedger` refers to the link after this one.
    if (
      currentIsBoundary &&
      current.previousLedger !== undefined &&
      current.previousLedger !== next.ledger
    ) {
      issues.push({
        kind: 'broken-sequence',
        reason: 'interval',
        expected: next.ledger,
        actual: current.previousLedger,
        newer: current.ledger,
        url,
      });
    }

    // A non-boundary root describes a ledger newer than the newest published
    // checkpoint, so its "previous" hash refers to a different ledger and must
    // not be compared with the checkpoint we walked back to.
    if (
      (currentIsBoundary || current.source === 'checkpoint') &&
      current.previousHash !== undefined
    ) {
      if (next.hash !== undefined && current.previousHash !== next.hash) {
        issues.push({
          kind: 'hash-mismatch',
          newer: current.ledger,
          older: next.ledger,
          expected: current.previousHash,
          actual: next.hash,
          url,
        });
      }
    }

    checkpoints.push(next);
    current = next;
    currentIsBoundary = true;
    expected = next.ledger - CHECKPOINT_FREQUENCY;
    followed++;
    complete = followed >= requested;
  }

  return {
    rootLedger: root.ledger,
    checkpoints,
    issues,
    complete: complete || expected < CHECKPOINT_FREQUENCY - 1,
  };
}

export const crawlCheckpointChain = crawlHistoryChain;

function issueMessage(path: string, issue: HistoryChainIssue): string {
  if (issue.kind === 'hash-mismatch') {
    return (
      `${path} checkpoint ${issue.newer} says its parent ledger hash is ${issue.expected}, ` +
      `but checkpoint ${issue.older} publishes ${issue.actual}; the HAS chain is broken ` +
      'between those checkpoints'
    );
  }
  switch (issue.reason) {
    case 'missing':
      return (
        `${path} is missing the checkpoint HAS for ledger ${issue.expected} ` +
        `(needed after checkpoint ${issue.newer ?? 'unknown'}); a catchup cannot walk past the gap`
      );
    case 'malformed':
      return (
        `${path} checkpoint at ${issue.url} declares no readable currentLedger; ` +
        `expected ledger ${issue.expected}`
      );
    case 'not-decreasing':
      return (
        `${path} checkpoint ${issue.actual ?? '?'} does not precede checkpoint ` +
        `${issue.newer ?? '?'}; the archive chain is not strictly descending`
      );
    case 'interval':
      return (
        `${path} checkpoint ${issue.actual ?? '?'} is not exactly ` +
        `${CHECKPOINT_FREQUENCY} ledgers before checkpoint ${issue.newer ?? '?'}; ` +
        `expected ${issue.expected}`
      );
  }
}

/**
 * The `--check-network --crawl-history` entry point: crawl every declared
 * `[[VALIDATORS]].HISTORY` archive and report broken links in its checkpoint
 * chain.
 */
export async function checkHistoryChain(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: ChainCrawlerOptions = {},
): Promise<Diagnostic[]> {
  const brokenSeverity = severityFor(BROKEN_CHECKPOINT_SEQUENCE_RULE, 'error', options.rules);
  const mismatchSeverity = severityFor(
    CHECKPOINT_LEDGER_HASH_MISMATCH_RULE,
    'error',
    options.rules,
  );
  if (brokenSeverity === undefined && mismatchSeverity === undefined) return [];

  const list = Array.isArray(doc.VALIDATORS) ? doc.VALIDATORS : [];
  const diagnostics: Diagnostic[] = [];

  for (let index = 0; index < list.length; index++) {
    const entry = list[index];
    if (!isRecord(entry)) continue;
    const history = stringValue(entry.HISTORY);
    if (history === undefined) continue;
    const baseUrl = archiveBase(history);
    if (baseUrl === undefined) continue;
    const path = `VALIDATORS[${index}].HISTORY`;

    const audit = await crawlHistoryChain(baseUrl, fetchImpl, options);
    for (const issue of audit.issues) {
      if (issue.kind === 'hash-mismatch') {
        if (mismatchSeverity === undefined) continue;
        diagnostics.push({
          rule: CHECKPOINT_LEDGER_HASH_MISMATCH_RULE,
          severity: mismatchSeverity,
          category: 'validators',
          message: issueMessage(path, issue),
          path,
          helpUri: specUrl('validator-information'),
          suggestion:
            'Re-publish the affected checkpoints from a single synced stellar-core instance; a ' +
            'rebuilt or partially restored archive can keep valid sequences but break the hash chain.',
        });
        continue;
      }
      if (brokenSeverity === undefined) continue;
      diagnostics.push({
        rule: BROKEN_CHECKPOINT_SEQUENCE_RULE,
        severity: brokenSeverity,
        category: 'validators',
        message: issueMessage(path, issue),
        path,
        helpUri: specUrl('validator-information'),
        suggestion:
          'Re-publish every missing checkpoint in the 64-ledger sequence from a full-history node ' +
          '(`stellar-core publish` after `catchup`), or point HISTORY at an archive that has them.',
      });
    }
  }

  return diagnostics;
}

export const checkHistoryArchiveChain = checkHistoryChain;
export const auditHistoryChain = checkHistoryChain;
export const crawlHistoryCheckpoints = checkHistoryChain;

/** Rules registered so `--list-rules`, `--off`, and SARIF know the ids. */
export const chainCrawlerRules: Rule[] = [
  {
    id: BROKEN_CHECKPOINT_SEQUENCE_RULE,
    category: 'validators',
    severity: 'error',
    description:
      'Every HAS checkpoint in a history archive must be present and exactly 64 ledgers before the next',
    run() {},
  },
  {
    id: CHECKPOINT_LEDGER_HASH_MISMATCH_RULE,
    category: 'validators',
    severity: 'error',
    description:
      'Adjacent HAS checkpoints must agree on the ledger hash shared by their parent/child link',
    run() {},
  },
];

export const chainCrawlerRuleIds: readonly string[] = chainCrawlerRules.map((rule) => rule.id);
