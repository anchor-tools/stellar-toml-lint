/**
 * EVM-to-Stellar bridge lockbox event log replay detector.
 *
 * Runs under opt-in `--audit-bridge-replays <evidence.json>`.
 *
 * An EVM custody contract emits `Locked(address indexed sender, bytes32
 * indexed stellarRecipient, uint256 amount)` and a relayer mints the wrapped
 * asset on Stellar. If the mint does not record the originating
 * `(txHash, logIndex)` pair, the same lock can be replayed into a second mint.
 * This module takes the recorded EVM logs (decoded, or raw `eth_getLogs`
 * entries) and the recorded Stellar mint operations, and checks that every
 * finalised lock maps to exactly one mint with the same amount and recipient.
 *
 * Reorgs: a log with `removed: true` was dropped by a chain reorganisation,
 * and a log less than `confirmations` blocks deep can still be. Minting
 * against either is flagged; an unminted lock is only reported once final.
 *
 * Hashes and recipients are compared as strict 32-byte values: exactly 64
 * hex digits, zero-padded, never shorter values padded on the fly.
 */

import { StrKey } from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isString } from '../predicates.js';
import { isRecord, severityFor, toScaled } from '../protocols/verifierSupport.js';

const INVALID_EVENT_RULE = 'bridgereplay/invalid-event';
const INVALID_MINT_RULE = 'bridgereplay/invalid-mint';
const MISSING_ID_RULE = 'bridgereplay/missing-replay-id';
const DUPLICATE_RULE = 'bridgereplay/duplicate-mint';
const UNRECORDED_RULE = 'bridgereplay/unrecorded-lock';
const ORPHAN_RULE = 'bridgereplay/orphan-mint';
const REORGED_RULE = 'bridgereplay/reorged-event-minted';
const PREMATURE_RULE = 'bridgereplay/premature-mint';
const AMOUNT_RULE = 'bridgereplay/amount-mismatch';
const RECIPIENT_RULE = 'bridgereplay/recipient-mismatch';

const SPEC = 'https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_getlogs';

export interface LockEvent {
  /** `<txHash>:<logIndex>`, the replay-protection key. */
  id: string;
  txHash: string;
  logIndex: number;
  blockNumber?: number;
  /** Token base units. */
  amount: bigint;
  /** 32-byte hex recipient (raw ed25519 key). */
  recipient: string;
  removed: boolean;
}

export interface ReplayOptions {
  rules?: RuleOverrides;
  /** Latest EVM block seen; enables the finality check. */
  headBlock?: number;
  /** Blocks a lock must be buried under before it counts as final. Default 12. */
  confirmations?: number;
  /** Decimals of the EVM token. Stellar amounts have 7. Default 18. */
  tokenDecimals?: number;
}

export interface ReplayResult {
  diagnostics: Diagnostic[];
  events: number;
  mints: number;
  /** Lock ids that map to exactly one valid mint. */
  matched: string[];
}

/** Strict 32-byte hex: `0x` plus exactly 64 hex digits, lower-cased. */
export function normalizeBytes32(value: unknown): string | undefined {
  if (!isString(value) || !/^0x[0-9a-fA-F]{64}$/.test(value)) return undefined;
  return value.toLowerCase();
}

function toIndex(value: unknown): number | undefined {
  if (Number.isSafeInteger(value) && (value as number) >= 0) return value as number;
  if (isString(value) && /^0x[0-9a-fA-F]+$/.test(value)) return Number.parseInt(value, 16);
  if (isString(value) && /^\d+$/.test(value)) return Number(value);
  return undefined;
}

function toAmount(value: unknown): bigint | undefined {
  if (isString(value) && /^(0x[0-9a-fA-F]+|\d+)$/.test(value)) return BigInt(value);
  if (Number.isSafeInteger(value) && (value as number) >= 0) return BigInt(value as number);
  return undefined;
}

/** The 32-byte hex form of a Stellar `G...` account, for comparison with `bytes32`. */
export function accountToBytes32(account: string): string | undefined {
  if (!StrKey.isValidEd25519PublicKey(account)) return undefined;
  return `0x${Buffer.from(StrKey.decodeEd25519PublicKey(account)).toString('hex')}`;
}

/**
 * Parses a decoded log (`txHash`, `logIndex`, `amount`, `recipient`) or a raw
 * `eth_getLogs` entry (`transactionHash`, `topics[2]` recipient, `data` amount).
 */
export function parseLockEvent(raw: unknown): LockEvent | string {
  if (!isRecord(raw)) return 'not an object';
  const rawLog = Array.isArray(raw.topics);
  const txHash = normalizeBytes32(rawLog ? raw.transactionHash : raw.txHash);
  if (txHash === undefined) return 'transaction hash is not a 32-byte hex value';
  const logIndex = toIndex(raw.logIndex);
  if (logIndex === undefined) return 'logIndex is not a non-negative integer';
  const recipient = normalizeBytes32(rawLog ? (raw.topics as unknown[])[2] : raw.recipient);
  if (recipient === undefined) return 'recipient is not a 32-byte hex value';
  const amountSource = rawLog ? normalizeBytes32(raw.data) : raw.amount;
  const amount = toAmount(amountSource);
  if (amount === undefined) return 'amount is not an unsigned integer';
  const blockNumber = raw.blockNumber === undefined ? undefined : toIndex(raw.blockNumber);
  if (raw.blockNumber !== undefined && blockNumber === undefined) return 'blockNumber is invalid';
  return {
    id: `${txHash}:${logIndex}`,
    txHash,
    logIndex,
    blockNumber,
    amount,
    recipient,
    removed: raw.removed === true,
  };
}

export class BridgeEventReplayDetector {
  constructor(private readonly options: ReplayOptions = {}) {}

  detect(evidence: unknown): ReplayResult {
    const diagnostics: Diagnostic[] = [];
    const push = (rule: string, fallback: 'error' | 'warning', message: string, path: string) => {
      const severity = severityFor(rule, fallback, this.options.rules);
      if (severity !== undefined) {
        diagnostics.push({ rule, severity, category: 'currencies', message, path, helpUri: SPEC });
      }
    };
    const result: ReplayResult = { diagnostics, events: 0, mints: 0, matched: [] };
    if (!isRecord(evidence) || !Array.isArray(evidence.lockEvents)) {
      push(INVALID_EVENT_RULE, 'error', 'Evidence must contain a "lockEvents" array', 'lockEvents');
      return result;
    }
    const mints = Array.isArray(evidence.stellarMints) ? evidence.stellarMints : [];
    const head = this.options.headBlock ?? toIndex(evidence.headBlock);
    const depth = this.options.confirmations ?? toIndex(evidence.confirmations) ?? 12;
    const decimals = this.options.tokenDecimals ?? toIndex(evidence.tokenDecimals) ?? 18;

    // The same log can be reported again after a reorg; any live copy wins.
    const events = new Map<string, LockEvent>();
    evidence.lockEvents.forEach((raw, i) => {
      const parsed = parseLockEvent(raw);
      if (isString(parsed)) {
        push(INVALID_EVENT_RULE, 'error', `lockEvents[${i}]: ${parsed}`, `lockEvents[${i}]`);
        return;
      }
      const seen = events.get(parsed.id);
      if (!seen || (seen.removed && !parsed.removed)) events.set(parsed.id, parsed);
    });
    result.events = events.size;
    const isFinal = (e: LockEvent): boolean =>
      !e.removed &&
      (head === undefined || (e.blockNumber !== undefined && head - e.blockNumber + 1 >= depth));

    const minted = new Map<string, number>();
    mints.forEach((mint, i) => {
      const path = `stellarMints[${i}]`;
      if (
        !isRecord(mint) ||
        !isString(mint.stellarTxHash) ||
        !/^[0-9a-f]{64}$/i.test(mint.stellarTxHash)
      ) {
        push(INVALID_MINT_RULE, 'error', `${path} has no 64-hex stellarTxHash`, path);
        return;
      }
      result.mints++;
      const where = `Stellar tx ${mint.stellarTxHash.toLowerCase()}`;
      const source = normalizeBytes32(mint.sourceTxHash);
      const logIndex = toIndex(mint.sourceLogIndex);
      if (source === undefined || logIndex === undefined) {
        push(
          MISSING_ID_RULE,
          'error',
          `${where} records no 32-byte source txHash and logIndex, so the lock it pays out can be replayed`,
          path,
        );
        return;
      }
      const id = `${source}:${logIndex}`;
      const count = (minted.get(id) ?? 0) + 1;
      minted.set(id, count);
      if (count === 2)
        push(
          DUPLICATE_RULE,
          'error',
          `Lock ${id} was minted more than once (again in ${where})`,
          path,
        );
      const event = events.get(id);
      if (!event) {
        push(ORPHAN_RULE, 'error', `${where} mints against unknown lock ${id}`, path);
        return;
      }
      if (event.removed) {
        push(
          REORGED_RULE,
          'error',
          `${where} mints against lock ${id}, which a reorg removed`,
          path,
        );
      } else if (!isFinal(event)) {
        push(
          PREMATURE_RULE,
          'warning',
          `${where} minted lock ${id} before ${depth} confirmations`,
          path,
        );
      }
      const scaled = isString(mint.amount) ? toScaled(mint.amount) : undefined;
      const expected =
        decimals >= 7
          ? event.amount / 10n ** BigInt(decimals - 7)
          : event.amount * 10n ** BigInt(7 - decimals);
      if (scaled === undefined || scaled !== expected) {
        push(AMOUNT_RULE, 'error', `${where} minted ${String(mint.amount)} for lock ${id}`, path);
      }
      const recipient = isString(mint.recipient) ? accountToBytes32(mint.recipient) : undefined;
      if (recipient !== event.recipient) {
        push(
          RECIPIENT_RULE,
          'error',
          `${where} pays ${String(mint.recipient)}, not the locked recipient`,
          path,
        );
      }
    });

    for (const event of events.values()) {
      const count = minted.get(event.id) ?? 0;
      if (count === 0 && isFinal(event)) {
        push(
          UNRECORDED_RULE,
          'warning',
          `Final lock ${event.id} has no Stellar mint`,
          'lockEvents',
        );
      }
      if (count === 1 && isFinal(event)) result.matched.push(event.id);
    }
    return result;
  }
}

export function auditBridgeReplays(evidence: unknown, options: ReplayOptions = {}): ReplayResult {
  return new BridgeEventReplayDetector(options).detect(evidence);
}

const def = (id: string, description: string): Rule => ({
  id,
  category: 'currencies',
  severity: 'error',
  description,
  run() {},
});

export const bridgeReplayRules: Rule[] = [
  def(
    INVALID_EVENT_RULE,
    'EVM lock logs must carry 32-byte hashes, a log index, recipient and amount',
  ),
  def(INVALID_MINT_RULE, 'Stellar mint records must carry a transaction hash'),
  def(MISSING_ID_RULE, 'Every mint must record the source txHash and logIndex it pays out'),
  def(DUPLICATE_RULE, 'Each lock event may be minted on Stellar only once'),
  def(UNRECORDED_RULE, 'Every final lock event should have a Stellar mint'),
  def(ORPHAN_RULE, 'Mints must reference a known lock event'),
  def(REORGED_RULE, 'Mints must not pay out lock events removed by a reorg'),
  def(PREMATURE_RULE, 'Mints should wait for the configured confirmation depth'),
  def(AMOUNT_RULE, 'Minted amounts must equal the locked amount'),
  def(RECIPIENT_RULE, 'Mints must pay the recipient named in the lock event'),
];

export const bridgeReplayRuleIds: readonly string[] = bridgeReplayRules.map((r) => r.id);
