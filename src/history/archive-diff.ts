import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { specUrl } from '../spec.js';
import { horizonUrlFor } from '../network-checks.js';
import { archiveBase, readJson } from './publish-validator.js';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * History archive ledger-delta auditor (issue #86).
 *
 * Validators publish history archive states (HAS) and checkpoint files every
 * 64 ledgers. An archive that drifts behind the live chain — delayed uploads,
 * a stalled captor, silent corruption — makes every consumer that catches up
 * from it (Horizon nodes, new validators) lag or diverge. This check compares
 * each declared `[[VALIDATORS]].HISTORY` archive's root HAS against the live
 * Horizon ledger sequence and the close hash Horizon records.
 *
 * Like its siblings under `--check-network`, it degrades to silence when a
 * surface is unreachable: the audit only reports what it actually observed.
 */

export const ARCHIVE_LAGGING_RULE = 'history/archive-lagging';
export const ARCHIVE_HASH_MISMATCH_RULE = 'history/archive-hash-mismatch';

/** Warning past one checkpoint window missed, error past eight. */
export const ARCHIVE_LAG_WARNING_LEDGERS = 128;
export const ARCHIVE_LAG_ERROR_LEDGERS = 512;

export interface ArchiveDiffOptions {
  rules?: RuleOverrides;
  /** Override the Horizon endpoint (defaults from NETWORK_PASSPHRASE). */
  horizonUrl?: string;
  /** Ledger lag at or below which only warnings (never errors) are raised. */
  warningLag?: number;
  errorLag?: number;
}

function numberValue(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value) && value >= 0) return Math.trunc(value);
  if (typeof value === 'string' && /^\d+$/.test(value.trim())) return Number(value.trim());
  return undefined;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : undefined;
}

/** The ledger sequence + hash a root HAS file (`stellar-history.json`) claims. */
export function archiveState(body: unknown): { sequence: number; hash?: string } | undefined {
  if (!isRecord(body)) return undefined;
  const sequence =
    numberValue(body.latest_ledger) ??
    numberValue(body.ledger_sequence) ??
    numberValue(body.latest_sequence) ??
    numberValue(body.ledger);
  if (sequence === undefined) return undefined;
  const hash =
    stringValue(body.latest_ledger_hash) ?? stringValue(body.ledger_hash) ?? stringValue(body.hash);
  return { sequence, ...(hash === undefined ? {} : { hash }) };
}

/** Horizon's live ledger sequence. */
export async function fetchHorizonSequence(
  horizonUrl: string,
  fetchImpl: typeof fetch,
): Promise<number | undefined> {
  const root = await readJson(`${horizonUrl.replace(/\/+$/, '')}/`, fetchImpl);
  if (!isRecord(root)) return undefined;
  return numberValue(root.core_latest_ledger) ?? numberValue(root.history_latest_ledger);
}

/** The hash Horizon recorded for one closed ledger. */
export async function fetchHorizonLedgerHash(
  horizonUrl: string,
  ledgerSequence: number,
  fetchImpl: typeof fetch,
): Promise<string | undefined> {
  const ledger = await readJson(
    `${horizonUrl.replace(/\/+$/, '')}/ledgers/${ledgerSequence}`,
    fetchImpl,
  );
  if (!isRecord(ledger)) return undefined;
  return stringValue(ledger.hash) ?? stringValue(ledger.close_time_hash);
}

function validatorHistories(doc: Record<string, unknown>): Array<Record<string, unknown>> {
  const list = Array.isArray(doc.VALIDATORS) ? doc.VALIDATORS : [];
  return list.filter((entry): entry is Record<string, unknown> => isRecord(entry));
}

/**
 * Audits every `[[VALIDATORS]].HISTORY` archive against live Horizon.
 *
 * `history/archive-lagging` warns once the archive falls more than 128
 * ledgers behind (two checkpoint windows) and errors past 512;
 * `history/archive-hash-mismatch` errors when the archive's ledger hash
 * disagrees with the hash Horizon recorded for the same ledger.
 */
export async function checkArchiveDiff(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: ArchiveDiffOptions = {},
): Promise<Diagnostic[]> {
  const validators = validatorHistories(doc);
  if (validators.length === 0) return [];

  const warningLag = options.warningLag ?? ARCHIVE_LAG_WARNING_LEDGERS;
  const errorLag = options.errorLag ?? ARCHIVE_LAG_ERROR_LEDGERS;

  const diagnostics: Diagnostic[] = [];
  const report = (
    rule: string,
    fallback: Diagnostic['severity'],
    finding: Omit<Diagnostic, 'rule' | 'severity' | 'category'>,
  ): void => {
    const override = options.rules?.[rule];
    if (override === 'off') return;
    diagnostics.push({
      ...finding,
      rule,
      category: 'validators',
      severity:
        override === 'error' || override === 'warning' || override === 'info' ? override : fallback,
    });
  };

  const passphrase = stringValue(doc.NETWORK_PASSPHRASE);
  const horizonUrl = options.horizonUrl ?? horizonUrlFor(passphrase);

  // One Horizon root query per run; the per-ledger hash is cached by
  // sequence because validators can sit on different checkpoints.
  let networkSequence: number | undefined;
  let horizonQueried = false;
  const hashBySequence = new Map<number, string | undefined>();

  for (let index = 0; index < validators.length; index++) {
    const entry = validators[index];
    if (entry === undefined) continue;
    const history = stringValue(entry.HISTORY);
    if (history === undefined) continue;
    const baseUrl = archiveBase(history);
    if (baseUrl === undefined) continue;
    const path = `VALIDATORS[${index}].HISTORY`;

    const hasBody = await readJson(
      new URL('.well-known/stellar-history.json', baseUrl).toString(),
      fetchImpl,
    );
    const archive = archiveState(hasBody);
    if (archive === undefined) continue; // not analysable; stay silent

    if (!horizonQueried) {
      horizonQueried = true;
      networkSequence = await fetchHorizonSequence(horizonUrl, fetchImpl);
    }
    if (networkSequence === undefined) continue; // Horizon unreachable; degrade

    const lag = networkSequence - archive.sequence;
    if (lag > warningLag) {
      const severity: Diagnostic['severity'] = lag > errorLag ? 'error' : 'warning';
      report(ARCHIVE_LAGGING_RULE, severity, {
        message:
          `History archive is ${lag} ledgers behind the network (archive at ${archive.sequence}, ` +
          `Horizon at ${networkSequence})`,
        path,
        helpUri: specUrl('validator-information'),
        suggestion:
          'Check the archive publisher (captain/carchiver) for stalled or failing uploads; ' +
          'checkpoints are expected every 64 ledgers.',
      });
    }

    if (archive.hash !== undefined) {
      if (!hashBySequence.has(archive.sequence)) {
        hashBySequence.set(
          archive.sequence,
          await fetchHorizonLedgerHash(horizonUrl, archive.sequence, fetchImpl),
        );
      }
      const horizonHash = hashBySequence.get(archive.sequence);
      if (horizonHash !== undefined && horizonHash !== archive.hash) {
        report(ARCHIVE_HASH_MISMATCH_RULE, 'error', {
          message:
            `Ledger ${archive.sequence} hash ${archive.hash} published by the archive does not ` +
            `match the ${horizonHash} Horizon closed it as`,
          path,
          helpUri: specUrl('validator-information'),
          suggestion:
            'The archive is serving a ledger the network does not recognise; re-publish the ' +
            'affected checkpoints from a node synced to the canonical chain.',
        });
      }
    }
  }

  return diagnostics;
}

/** Rules registered so `--list-rules`, `--off`, and SARIF know the ids. */
export const archiveDiffRules: Rule[] = [
  {
    id: ARCHIVE_LAGGING_RULE,
    category: 'validators',
    severity: 'warning',
    description: 'History archives must track the live ledger within two checkpoint windows',
    run() {},
  },
  {
    id: ARCHIVE_HASH_MISMATCH_RULE,
    category: 'validators',
    severity: 'error',
    description: 'Archive checkpoint hashes must match the hashes Horizon closed with',
    run() {},
  },
];

export const archiveDiffRuleIds: readonly string[] = archiveDiffRules.map((rule) => rule.id);
