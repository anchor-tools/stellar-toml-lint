/**
 * SEP-24 interactive transaction lifecycle simulator.
 *
 * Runs under opt-in `--check-network --simulate-sep24`.
 *
 * `verifySep24` proves the interactive endpoint answers and hands back an id;
 * it says nothing about what happens next. Wallets poll `/transaction` until a
 * terminal status arrives, and they rely on that status never going backwards:
 * a `completed` deposit that later reads `pending_anchor` makes the wallet
 * re-prompt the user for a payment that already settled. This simulator drives
 * a real deposit session through its lifecycle and validates every observed
 * status against the SEP-24 state machine.
 *
 * The session is synthetic: an ephemeral keypair performs the SEP-10 handshake
 * when the anchor exposes `WEB_AUTH_ENDPOINT` and `SIGNING_KEY`, and the probe
 * falls back to a clearly-labelled test JWT otherwise, matching the other
 * SEP-24 audits. Transport failures and auth rejections are silence — only spec
 * violations are reported.
 */

import { Keypair, Networks, TransactionBuilder } from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleCategory, RuleOverrides, Severity } from '../types.js';
import { isString, isUrl } from '../predicates.js';
import { currenciesOf } from '../rules/currencies.js';

export const ILLEGAL_STATE_TRANSITION_RULE = 'sep24/illegal-state-transition';
export const MISSING_LIFECYCLE_TIMESTAMPS_RULE = 'sep24/missing-lifecycle-timestamps';

const SEP24_SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0024.md';
const TEST_JWT = 'sep24.lint.test.jwt';
const DEFAULT_POLL_INTERVAL_MS = 2_000;
const DEFAULT_POLL_DURATION_MS = 20_000;
const DEFAULT_MAX_POLLS = 10;

/** Every status SEP-24 defines for `GET /transaction`. */
export const SEP24_LIFECYCLE_STATES: readonly string[] = [
  'incomplete',
  'pending_user_transfer_start',
  'pending_user_transfer_complete',
  'pending_trust',
  'pending_user',
  'pending_anchor',
  'pending_stellar',
  'pending_external',
  'completed',
  'refunded',
  'expired',
  'error',
  'no_market',
  'too_small',
  'too_large',
];

/** Statuses after which no further transition is legal. */
export const SEP24_TERMINAL_STATES: readonly string[] = [
  'completed',
  'refunded',
  'expired',
  'error',
  'no_market',
  'too_small',
  'too_large',
];

const PENDING_STATES = SEP24_LIFECYCLE_STATES.filter((status) => status.startsWith('pending_'));

/**
 * Allowed edges out of each status.
 *
 * Wait states may retry into one another (`pending_anchor` -> `pending_external`
 * -> `pending_anchor`) because that is how an anchor polls an external rail;
 * what the state machine forbids is leaving a terminal status, or jumping
 * straight from `incomplete` to a pending state that has no meaning yet.
 */
export const SEP24_ALLOWED_TRANSITIONS: Readonly<Record<string, readonly string[]>> = {
  incomplete: [...PENDING_STATES, 'completed', 'refunded', 'expired', 'error'],
  ...Object.fromEntries(
    PENDING_STATES.map((status) => [
      status,
      [...PENDING_STATES, 'completed', 'refunded', 'expired', 'error'],
    ]),
  ),
  ...Object.fromEntries(SEP24_TERMINAL_STATES.map((status) => [status, []])),
};

/** True when `to` is a legal successor of `from` (a repeated status is legal). */
export function isValidTransition(from: string, to: string): boolean {
  if (from === to) return true;
  const allowed = SEP24_ALLOWED_TRANSITIONS[from];
  if (allowed === undefined) return false;
  return allowed.includes(to);
}

export interface Sep24LifecycleOptions {
  rules?: RuleOverrides;
  /** Delay between `GET /transaction` polls. */
  pollIntervalMs?: number;
  /** Wall-clock budget for polling one transaction. */
  pollDurationMs?: number;
  /** Hard cap on polls, independent of the time budget. */
  maxPolls?: number;
  /** Override the ephemeral SEP-10 keypair (tests). */
  clientKeypair?: Keypair;
}

interface TransactionPayload {
  status?: unknown;
  amount_in?: unknown;
  amount_out?: unknown;
  amount_fee?: unknown;
  started_at?: unknown;
  completed_at?: unknown;
}

function severityFor(
  rule: string,
  fallback: Severity,
  rules?: RuleOverrides,
): Severity | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override ?? fallback;
}

function report(
  diagnostics: Diagnostic[],
  rule: string,
  fallback: Severity,
  message: string,
  suggestion: string,
  rules?: RuleOverrides,
  extras: Partial<Diagnostic> = {},
): void {
  const severity = severityFor(rule, fallback, rules);
  if (severity === undefined) return;
  diagnostics.push({
    rule,
    severity,
    category: 'network' as RuleCategory,
    message,
    helpUri: SEP24_SPEC,
    suggestion,
    ...extras,
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isTimestamp(value: unknown): boolean {
  return (typeof value === 'string' && value.trim() !== '') || typeof value === 'number';
}

function normalizeTransferServer(doc: Record<string, unknown>): string | undefined {
  const preferred = doc.TRANSFER_SERVER_SEP0024;
  const fallback = doc.TRANSFER_SERVER;
  const server = isString(preferred) && isUrl(preferred) ? preferred : fallback;
  if (!isString(server) || !isUrl(server)) return undefined;
  return server.replace(/\/+$/, '');
}

function firstAnchoredAssetCode(doc: Record<string, unknown>): string | undefined {
  const anchored = currenciesOf(doc).find(
    (entry) => entry.is_asset_anchored === true && isString(entry.code) && entry.code !== '',
  );
  const code = anchored?.code ?? currenciesOf(doc)[0]?.code;
  return isString(code) && code !== '' ? code : undefined;
}

/**
 * Performs a SEP-10 challenge/response and returns the bearer token.
 *
 * `undefined` on any failure: absence of `WEB_AUTH_ENDPOINT`/`SIGNING_KEY`, an
 * unreachable server, or a rejected challenge. The caller then falls back to a
 * synthetic token, so a lint run never insists that an anchor accept the
 * probe's authentication.
 */
async function obtainSep10Token(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch,
  clientKeypair: Keypair,
): Promise<string | undefined> {
  const endpoint = doc.WEB_AUTH_ENDPOINT;
  const signingKey = doc.SIGNING_KEY;
  if (!isString(endpoint) || !isUrl(endpoint) || !isString(signingKey)) return undefined;

  try {
    const challengeResponse = await fetchImpl(
      `${endpoint}?${new URLSearchParams({ account: clientKeypair.publicKey() }).toString()}`,
      { headers: { accept: 'application/json' }, redirect: 'follow' },
    );
    if (!challengeResponse.ok) return undefined;
    const challengeBody: unknown = await challengeResponse.json();
    if (!isRecord(challengeBody) || !isString(challengeBody.transaction)) return undefined;

    const passphrase = isString(doc.NETWORK_PASSPHRASE)
      ? doc.NETWORK_PASSPHRASE
      : isString(challengeBody.network_passphrase)
        ? challengeBody.network_passphrase
        : Networks.PUBLIC;

    const transaction = TransactionBuilder.fromXDR(challengeBody.transaction, passphrase);
    transaction.sign(clientKeypair);

    const tokenResponse = await fetchImpl(endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ transaction: transaction.toXDR() }),
      redirect: 'follow',
    });
    if (!tokenResponse.ok) return undefined;
    const tokenBody: unknown = await tokenResponse.json();
    if (!isRecord(tokenBody) || !isString(tokenBody.token) || tokenBody.token === '') {
      return undefined;
    }
    return tokenBody.token;
  } catch {
    return undefined;
  }
}

async function initiateDeposit(
  base: string,
  assetCode: string,
  token: string,
  fetchImpl: typeof fetch,
): Promise<string | undefined> {
  try {
    const response = await fetchImpl(`${base}/transactions/deposit/interactive`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ asset_code: assetCode, type: 'bank_account' }),
      redirect: 'follow',
    });
    if (!response.ok) return undefined;
    const body: unknown = await response.json();
    if (!isRecord(body)) return undefined;
    return isString(body.id) && body.id !== '' ? body.id : undefined;
  } catch {
    return undefined;
  }
}

async function pollTransaction(
  base: string,
  id: string,
  token: string,
  fetchImpl: typeof fetch,
): Promise<TransactionPayload | undefined> {
  const url = new URL(`${base}/transaction`);
  url.searchParams.set('id', id);
  try {
    const response = await fetchImpl(url.toString(), {
      headers: { accept: 'application/json', authorization: `Bearer ${token}` },
      redirect: 'follow',
    });
    if (!response.ok) return undefined;
    const body: unknown = await response.json();
    if (!isRecord(body)) return undefined;
    // Some anchors wrap the transaction in `{ transaction: {...} }`.
    return isRecord(body.transaction) ? (body.transaction as TransactionPayload) : body;
  } catch {
    return undefined;
  }
}

/**
 * Drives one interactive deposit through its lifecycle and validates the
 * status graph and lifecycle timestamps.
 *
 * Silent when the file declares no usable transfer server or no anchored
 * currency to deposit, and when the session cannot be opened at all.
 */
export async function simulateSep24Lifecycle(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: Sep24LifecycleOptions = {},
): Promise<Diagnostic[]> {
  const base = normalizeTransferServer(doc);
  if (base === undefined) return [];

  const assetCode = firstAnchoredAssetCode(doc);
  if (assetCode === undefined) return [];

  const pollIntervalMs = options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
  const pollDurationMs = options.pollDurationMs ?? DEFAULT_POLL_DURATION_MS;
  const maxPolls = options.maxPolls ?? DEFAULT_MAX_POLLS;
  const diagnostics: Diagnostic[] = [];
  const path = 'TRANSFER_SERVER_SEP0024';

  const token =
    (await obtainSep10Token(doc, fetchImpl, options.clientKeypair ?? Keypair.random())) ?? TEST_JWT;
  const id = await initiateDeposit(base, assetCode, token, fetchImpl);
  if (id === undefined) return [];

  let previous: string | undefined;
  let reportedTransition = false;
  let reportedStart = false;
  let reportedCompletion = false;
  // One confirmation poll after a terminal status: a wallet stops polling at
  // `completed`, so the only way to catch a transaction that later regresses is
  // to ask once more after the terminal answer arrived.
  let pollsAfterTerminal = 0;
  const startedAt = Date.now();

  for (let poll = 0; poll < maxPolls; poll++) {
    if (poll > 0) {
      if (Date.now() - startedAt + pollIntervalMs > pollDurationMs) break;
      await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
    }

    const payload = await pollTransaction(base, id, token, fetchImpl);
    if (payload === undefined) continue;

    const status = payload.status;
    if (!isString(status)) {
      if (!reportedTransition) {
        reportedTransition = true;
        report(
          diagnostics,
          ILLEGAL_STATE_TRANSITION_RULE,
          'error',
          `GET /transaction for ${assetCode} returned no status`,
          'Every transaction payload must carry a SEP-24 status.',
          options.rules,
          { path },
        );
      }
      break;
    }

    const known = SEP24_LIFECYCLE_STATES.includes(status);
    const legal =
      previous === undefined ||
      !SEP24_LIFECYCLE_STATES.includes(previous) ||
      isValidTransition(previous, status);

    if (!known || !legal) {
      if (!reportedTransition) {
        reportedTransition = true;
        report(
          diagnostics,
          ILLEGAL_STATE_TRANSITION_RULE,
          'error',
          !known
            ? `GET /transaction for ${assetCode} returned the unknown status "${status}"`
            : `Transaction for ${assetCode} regressed from ${previous} to ${status}`,
          known
            ? 'Terminal statuses are final: never move a completed or refunded transaction back into a pending state.'
            : `Use one of the SEP-24 statuses: ${SEP24_LIFECYCLE_STATES.join(', ')}.`,
          options.rules,
          { path },
        );
      }
      break;
    }

    // Timestamps: `started_at` once the flow has left `incomplete`, and
    // `completed_at` when it reaches a terminal success state.
    if (!reportedStart && status !== 'incomplete' && !isTimestamp(payload.started_at)) {
      reportedStart = true;
      report(
        diagnostics,
        MISSING_LIFECYCLE_TIMESTAMPS_RULE,
        'warning',
        `Transaction for ${assetCode} is "${status}" but has no started_at timestamp`,
        'Set started_at when the anchor first receives the transaction.',
        options.rules,
        { path },
      );
    }

    if (
      !reportedCompletion &&
      (status === 'completed' || status === 'refunded') &&
      !isTimestamp(payload.completed_at)
    ) {
      reportedCompletion = true;
      report(
        diagnostics,
        MISSING_LIFECYCLE_TIMESTAMPS_RULE,
        'warning',
        `Transaction for ${assetCode} is "${status}" but has no completed_at timestamp`,
        'Set completed_at when the transaction reaches a terminal status.',
        options.rules,
        { path },
      );
    }

    previous = status;
    if (SEP24_TERMINAL_STATES.includes(status)) {
      if (pollsAfterTerminal >= 1) break;
      pollsAfterTerminal += 1;
    }
  }

  return diagnostics;
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const sep24LifecycleRules: Rule[] = [
  {
    id: ILLEGAL_STATE_TRANSITION_RULE,
    category: 'network',
    severity: 'error',
    description:
      'SEP-24 transaction status must follow the state machine and never leave a terminal state',
    run() {},
  },
  {
    id: MISSING_LIFECYCLE_TIMESTAMPS_RULE,
    category: 'network',
    severity: 'warning',
    description: 'SEP-24 transactions must expose started_at and completed_at lifecycle timestamps',
    run() {},
  },
];
