import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';
import { specUrl } from '../spec.js';
import { archiveState } from './archive-diff.js';
import { archiveBase, readJson } from './publish-validator.js';

/**
 * Ledger sequence gap and catchup recovery auditor (issue #319).
 *
 * A validator that falls out of sync recovers by catching up from a history
 * archive: it downloads every checkpoint between its last closed ledger and
 * the network's, and replays them in order. stellar-core publishes one
 * checkpoint every 64 ledgers — at ledgers 63, 127, 191, … — so an archive
 * that skipped a single publish leaves a hole a catchup cannot step over, and
 * the node aborts the moment it reaches it.
 *
 * `history/archive-lagging` and the publish validator look at the archive's
 * head; neither walks back through it. Under opt-in
 * `--check-network --verify-history-gaps` this module reads the root History
 * Archive State to find the latest checkpoint, then asks the archive for the
 * checkpoint file of every 64-ledger boundary across the most recent
 * `ledgerRange` ledgers (10,000 by default, about 157 checkpoints). Consecutive
 * missing checkpoints are folded into one `history/ledger-sequence-gap-detected`
 * error naming the ledger range a catchup would fail on.
 *
 * Like its siblings it reports only what it observed: an archive whose root
 * state cannot be read stays silent rather than flagging every checkpoint.
 */

export const LEDGER_SEQUENCE_GAP_RULE = 'history/ledger-sequence-gap-detected';
export const HISTORY_LEDGER_SEQUENCE_GAP_DETECTED = LEDGER_SEQUENCE_GAP_RULE;

/** stellar-core publishes a checkpoint once every this many ledgers. */
export const CHECKPOINT_FREQUENCY = 64;

/** How far back from the archive head the audit walks, in ledgers. */
export const DEFAULT_GAP_AUDIT_LEDGERS = 10_000;

/** How many checkpoint probes may be in flight against one archive at once. */
export const DEFAULT_GAP_AUDIT_CONCURRENCY = 8;

/** The per-checkpoint files an archive publishes. */
export type CheckpointCategory = 'history' | 'ledger' | 'transactions' | 'results' | 'scp';

export interface GapAuditorOptions {
  rules?: RuleOverrides;
  /** Number of ledgers, counted back from the archive head, to audit. */
  ledgerRange?: number;
  /**
   * The checkpoint files that must exist at every boundary. Defaults to the
   * `ledger` headers, which a catchup replays first and cannot do without.
   */
  categories?: readonly CheckpointCategory[];
  /** Concurrent probes per archive. */
  concurrency?: number;
}

/** A run of consecutive checkpoints that are missing from one archive. */
export interface LedgerGap {
  /** The first ledger the gap covers (the ledger after the last good checkpoint). */
  firstLedger: number;
  /** The last ledger the gap covers (the last missing checkpoint). */
  lastLedger: number;
  /** Every missing checkpoint ledger in the run, ascending. */
  checkpoints: number[];
  /** The archive-relative path of the first file that could not be fetched. */
  firstMissingFile: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : undefined;
}

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

/** True when `ledger` is a checkpoint boundary (63, 127, 191, …). */
export function isCheckpointLedger(ledger: number): boolean {
  return Number.isInteger(ledger) && ledger > 0 && (ledger + 1) % CHECKPOINT_FREQUENCY === 0;
}

/** The checkpoint ledger whose files contain `ledger`. */
export function checkpointContaining(ledger: number): number {
  return (
    Math.floor(Math.max(0, ledger) / CHECKPOINT_FREQUENCY) * CHECKPOINT_FREQUENCY +
    CHECKPOINT_FREQUENCY -
    1
  );
}

/** A checkpoint ledger as the 8-digit lower-case hex stellar-core names files with. */
export function checkpointHex(checkpoint: number): string {
  return checkpoint.toString(16).padStart(8, '0');
}

/**
 * The archive-relative path of one checkpoint file, e.g.
 * `ledger/00/00/04/ledger-0000043f.xdr.gz` or
 * `history/00/00/04/history-0000043f.json`.
 */
export function checkpointFilePath(category: CheckpointCategory, checkpoint: number): string {
  const hex = checkpointHex(checkpoint);
  const directory = `${category}/${hex.slice(0, 2)}/${hex.slice(2, 4)}/${hex.slice(4, 6)}`;
  const extension = category === 'history' ? 'json' : 'xdr.gz';
  return `${directory}/${category}-${hex}.${extension}`;
}

/**
 * Every checkpoint boundary across the `ledgerRange` ledgers ending at
 * `latestLedger`, ascending. A head that is not itself a boundary has not been
 * published as a checkpoint yet, so the walk starts from the one before it.
 */
export function checkpointsInRange(latestLedger: number, ledgerRange: number): number[] {
  if (!Number.isFinite(latestLedger) || latestLedger < CHECKPOINT_FREQUENCY - 1) return [];
  const last = isCheckpointLedger(latestLedger)
    ? latestLedger
    : checkpointContaining(latestLedger) - CHECKPOINT_FREQUENCY;
  if (last < CHECKPOINT_FREQUENCY - 1) return [];
  const span = Math.max(1, Math.trunc(ledgerRange));
  const first = checkpointContaining(Math.max(0, last - span + 1));
  const checkpoints: number[] = [];
  for (let ledger = first; ledger <= last; ledger += CHECKPOINT_FREQUENCY) {
    checkpoints.push(ledger);
  }
  return checkpoints;
}

/**
 * The latest ledger a root HAS declares. stellar-core writes `currentLedger`;
 * the looser spellings `archiveState` already understands are accepted too.
 */
export function latestArchivedLedger(has: unknown): number | undefined {
  if (isRecord(has)) {
    const current = has.currentLedger;
    if (typeof current === 'number' && Number.isInteger(current) && current >= 0) return current;
    if (typeof current === 'string' && /^\d+$/.test(current.trim())) return Number(current);
  }
  return archiveState(has)?.sequence;
}

/**
 * Whether a file can be downloaded. A `HEAD` is tried first; archives on
 * object stores that refuse it get a one-byte ranged `GET` instead, so the
 * probe never transfers a whole checkpoint.
 */
export async function isDownloadable(url: string, fetchImpl: typeof fetch): Promise<boolean> {
  try {
    const head = await fetchImpl(url, { method: 'HEAD' });
    if (head.ok) return true;
    if (head.status !== 403 && head.status !== 405 && head.status !== 501) return false;
  } catch {
    // Some transports reject HEAD outright; fall through to a ranged GET.
  }
  try {
    const response = await fetchImpl(url, { headers: { Range: 'bytes=0-0' } });
    await response.body?.cancel().catch(() => undefined);
    return response.ok;
  } catch {
    return false;
  }
}

/** Runs `task` over `items` with at most `limit` in flight, preserving order. */
async function mapConcurrent<T, R>(
  items: readonly T[],
  limit: number,
  task: (item: T) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
    while (next < items.length) {
      const index = next++;
      results[index] = await task(items[index] as T);
    }
  });
  await Promise.all(workers);
  return results;
}

/** Folds missing checkpoints into runs of consecutive boundaries. */
export function groupGaps(missing: readonly { checkpoint: number; file: string }[]): LedgerGap[] {
  const sorted = [...missing].sort((a, b) => a.checkpoint - b.checkpoint);
  const gaps: LedgerGap[] = [];
  for (const entry of sorted) {
    const current = gaps[gaps.length - 1];
    if (current !== undefined && entry.checkpoint === current.lastLedger + CHECKPOINT_FREQUENCY) {
      current.lastLedger = entry.checkpoint;
      current.checkpoints.push(entry.checkpoint);
      continue;
    }
    gaps.push({
      firstLedger: entry.checkpoint - CHECKPOINT_FREQUENCY + 1,
      lastLedger: entry.checkpoint,
      checkpoints: [entry.checkpoint],
      firstMissingFile: entry.file,
    });
  }
  return gaps;
}

/**
 * Probes every checkpoint across the audited range of one archive and returns
 * the gaps, or `undefined` when the archive's root state could not be read.
 */
export async function findLedgerGaps(
  baseUrl: string,
  fetchImpl: typeof fetch,
  options: GapAuditorOptions = {},
): Promise<{ latestLedger: number; checked: number; gaps: LedgerGap[] } | undefined> {
  const has = await readJson(
    new URL('.well-known/stellar-history.json', baseUrl).toString(),
    fetchImpl,
  );
  const latestLedger = latestArchivedLedger(has);
  if (latestLedger === undefined) return undefined;

  const categories =
    options.categories !== undefined && options.categories.length > 0
      ? options.categories
      : (['ledger'] as const);
  const checkpoints = checkpointsInRange(
    latestLedger,
    options.ledgerRange ?? DEFAULT_GAP_AUDIT_LEDGERS,
  );
  const probes = checkpoints.flatMap((checkpoint) =>
    categories.map((category) => ({ checkpoint, file: checkpointFilePath(category, checkpoint) })),
  );

  const results = await mapConcurrent(
    probes,
    options.concurrency ?? DEFAULT_GAP_AUDIT_CONCURRENCY,
    async (probe) => ({
      ...probe,
      ok: await isDownloadable(new URL(probe.file, baseUrl).toString(), fetchImpl),
    }),
  );

  // A checkpoint counts once, however many of its files are missing.
  const missing = new Map<number, string>();
  for (const result of results) {
    if (!result.ok && !missing.has(result.checkpoint)) {
      missing.set(result.checkpoint, result.file);
    }
  }
  const gaps = groupGaps([...missing].map(([checkpoint, file]) => ({ checkpoint, file })));
  return { latestLedger, checked: checkpoints.length, gaps };
}

function gapMessage(path: string, gap: LedgerGap, latestLedger: number): string {
  const count = gap.checkpoints.length;
  const checkpoints = count === 1 ? 'checkpoint' : `${count} consecutive checkpoints`;
  return `${path} is missing ${checkpoints} for ledgers ${gap.firstLedger}–${gap.lastLedger} (first missing file: ${gap.firstMissingFile}); a catchup to ledger ${latestLedger} cannot replay past ledger ${gap.firstLedger - 1}`;
}

function validatorHistories(doc: Record<string, unknown>): { index: number; history: string }[] {
  const list = Array.isArray(doc.VALIDATORS) ? doc.VALIDATORS : [];
  const histories: { index: number; history: string }[] = [];
  list.forEach((entry, index) => {
    if (!isRecord(entry)) return;
    const history = stringValue(entry.HISTORY);
    if (history !== undefined) histories.push({ index, history });
  });
  return histories;
}

/**
 * The `--check-network --verify-history-gaps` entry point: walk the recent
 * checkpoints of every `[[VALIDATORS]].HISTORY` archive and report each run of
 * missing ones as `history/ledger-sequence-gap-detected`.
 */
export async function checkHistoryGaps(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: GapAuditorOptions = {},
): Promise<Diagnostic[]> {
  const severity = severityFor(LEDGER_SEQUENCE_GAP_RULE, 'error', options.rules);
  if (severity === undefined) return [];

  const diagnostics: Diagnostic[] = [];
  for (const { index, history } of validatorHistories(doc)) {
    const baseUrl = archiveBase(history);
    if (baseUrl === undefined) continue;
    const path = `VALIDATORS[${index}].HISTORY`;

    const audit = await findLedgerGaps(baseUrl, fetchImpl, options);
    if (audit === undefined) continue; // root state unreadable; stay silent

    for (const gap of audit.gaps) {
      diagnostics.push({
        rule: LEDGER_SEQUENCE_GAP_RULE,
        severity,
        category: 'validators',
        message: gapMessage(path, gap, audit.latestLedger),
        path,
        helpUri: specUrl('validator-information'),
        suggestion:
          'Re-publish the missing checkpoints from a full-history node (`stellar-core publish` after a `catchup` over the range), or point HISTORY at an archive that has them.',
      });
    }
  }
  return diagnostics;
}

export const auditHistoryGaps = checkHistoryGaps;
export const verifyHistoryGaps = checkHistoryGaps;

/** Rules registered so `--list-rules`, `--off`, and SARIF know the ids. */
export const gapAuditorRules: Rule[] = [
  {
    id: LEDGER_SEQUENCE_GAP_RULE,
    category: 'validators',
    severity: 'error',
    description:
      'Every 64-ledger checkpoint in a validator history archive must be published and downloadable',
    run() {},
  },
];

export const gapAuditorRuleIds: readonly string[] = gapAuditorRules.map((rule) => rule.id);
