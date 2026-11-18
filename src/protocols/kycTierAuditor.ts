/**
 * KYC tier mapping and SEP-12 customer status state machine auditor.
 *
 * Runs under opt-in `--audit-kyc-fsm --domain <domain>`.
 *
 * SEP-12 defines four customer statuses: NEEDS_INFO, PENDING, ACCEPTED and
 * REJECTED. A customer who lands in a state with no way forward (no fields to
 * submit, no URL to follow) or who can only loop between states is stuck in
 * limbo. This auditor builds the finite state machine an anchor exposes and
 * reports the states that trap customers.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isHttpsUrl, isString } from '../predicates.js';

const UNKNOWN_STATUS_RULE = 'sep12/unknown-customer-status';
const NO_NEXT_ACTION_RULE = 'sep12/status-missing-next-action';
const CIRCULAR_RULE = 'sep12/circular-status-transition';
const NONDETERMINISTIC_RULE = 'sep12/nondeterministic-status-transition';
const UNREACHABLE_RULE = 'sep12/unreachable-status';

const SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0012.md';

/** The only statuses SEP-12 defines. */
export const SEP12_STATUSES = ['NEEDS_INFO', 'PENDING', 'ACCEPTED', 'REJECTED'] as const;
const TERMINAL = new Set(['ACCEPTED', 'REJECTED']);

/** Transitions SEP-12 permits; the default when an anchor declares none. */
const SPEC_TRANSITIONS: Transition[] = [
  { from: 'NEEDS_INFO', on: 'submit_fields', to: 'PENDING' },
  { from: 'PENDING', on: 'approve', to: 'ACCEPTED' },
  { from: 'PENDING', on: 'reject', to: 'REJECTED' },
  { from: 'PENDING', on: 'request_info', to: 'NEEDS_INFO' },
];

export interface Transition {
  from: string;
  /** Event that triggers the transition; the same (from, on) must map to one `to`. */
  on: string;
  to: string;
}

export interface StatusObservation {
  /** Fields the customer is asked for (NEEDS_INFO). */
  fields?: string[];
  more_info_url?: string;
  message?: string;
}

export interface KycModel {
  /** Customer type / tier, e.g. `sep31-sender`. */
  type: string;
  initial?: string;
  states: Record<string, StatusObservation>;
  transitions?: Transition[];
}

export interface KycAuditOptions {
  rules?: RuleOverrides;
}

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules?: RuleOverrides,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Validates one customer type's FSM. */
export class KycTierStateMachineAuditor {
  constructor(private readonly options: KycAuditOptions = {}) {}

  audit(model: KycModel): Diagnostic[] {
    const out: Diagnostic[] = [];
    const path = `KYC[${model.type}]`;
    const emit = (
      rule: string,
      fallback: 'error' | 'warning',
      message: string,
      suggestion: string,
    ): void => {
      const severity = severityFor(rule, fallback, this.options.rules);
      if (severity === undefined) return;
      out.push({
        rule,
        severity,
        category: 'sep12',
        message,
        path,
        helpUri: SPEC,
        suggestion,
      });
    };

    const known = new Set<string>(SEP12_STATUSES);
    for (const state of Object.keys(model.states)) {
      if (!known.has(state)) {
        emit(
          UNKNOWN_STATUS_RULE,
          'error',
          `Customer type "${model.type}" returns status "${state}", which SEP-12 does not define`,
          `Use one of ${SEP12_STATUSES.join(', ')}.`,
        );
      }
    }

    // Next-action requirements per SEP-12: NEEDS_INFO lists fields; PENDING and
    // REJECTED should say where to follow up.
    for (const [state, obs] of Object.entries(model.states)) {
      if (state === 'NEEDS_INFO' && !(obs.fields && obs.fields.length > 0)) {
        emit(
          NO_NEXT_ACTION_RULE,
          'error',
          `Status NEEDS_INFO for "${model.type}" lists no required fields`,
          'Return a fields object describing what the customer must provide.',
        );
      }
      if (
        (state === 'PENDING' || state === 'REJECTED') &&
        !(isString(obs.more_info_url) && isHttpsUrl(obs.more_info_url)) &&
        !(isString(obs.message) && obs.message !== '')
      ) {
        emit(
          NO_NEXT_ACTION_RULE,
          'warning',
          `Status ${state} for "${model.type}" gives no more_info_url or message`,
          'Return a more_info_url or message so the customer knows what happens next.',
        );
      }
    }

    // Reachability analysis needs a declared machine: a single observed response
    // says nothing about where a customer can go next.
    if (model.transitions === undefined) return out;
    const transitions = model.transitions;

    // Determinism: one event from one state must have exactly one outcome.
    const seen = new Map<string, string>();
    for (const t of transitions) {
      const key = `${t.from}\u0000${t.on}`;
      const prior = seen.get(key);
      if (prior !== undefined && prior !== t.to) {
        emit(
          NONDETERMINISTIC_RULE,
          'error',
          `Event "${t.on}" in ${t.from} leads to both ${prior} and ${t.to} for "${model.type}"`,
          'Make each status transition deterministic.',
        );
      }
      seen.set(key, t.to);
    }

    const initial = model.initial ?? (model.states.NEEDS_INFO ? 'NEEDS_INFO' : 'PENDING');
    const reachable = reach(initial, transitions);
    for (const state of Object.keys(model.states)) {
      if (!reachable.has(state)) {
        emit(
          UNREACHABLE_RULE,
          'warning',
          `Status ${state} for "${model.type}" is unreachable from ${initial}`,
          'Remove the orphaned status or add a transition into it.',
        );
      }
    }

    // A non-terminal state from which no terminal state can be reached traps
    // the customer in a loop.
    for (const state of reachable) {
      if (TERMINAL.has(state)) continue;
      const forward = reach(state, transitions);
      if (![...forward].some((s) => TERMINAL.has(s))) {
        emit(
          CIRCULAR_RULE,
          'error',
          `Customer in ${state} for "${model.type}" can never reach ACCEPTED or REJECTED`,
          'Add a transition out of the cycle so onboarding can complete.',
        );
      }
    }
    return out;
  }
}

function defaultTransitions(model: KycModel): Transition[] {
  return SPEC_TRANSITIONS.filter((t) => t.from in model.states && t.to in model.states);
}

function reach(start: string, transitions: Transition[]): Set<string> {
  const visited = new Set<string>([start]);
  const queue = [start];
  while (queue.length > 0) {
    const current = queue.shift() as string;
    for (const t of transitions) {
      if (t.from === current && !visited.has(t.to)) {
        visited.add(t.to);
        queue.push(t.to);
      }
    }
  }
  return visited;
}

/** Terminal-friendly state transition diagram. */
export function renderKycDiagram(model: KycModel): string {
  const transitions = model.transitions ?? defaultTransitions(model);
  const lines = transitions.map((t) => `  [${t.from}] --${t.on}--> [${t.to}]`);
  const states = Object.keys(model.states).join(', ');
  return `KYC state machine for "${model.type}" (states: ${states || 'none'})\n${lines.join('\n')}\n`;
}

/** Customer types advertised in SEP-31 `/info` (`receive.<asset>.sep12.sender.types`). */
export function extractCustomerTypes(info: unknown): string[] {
  const types = new Set<string>();
  const receive = isRecord(info) ? info.receive : undefined;
  if (!isRecord(receive)) return [];
  for (const asset of Object.values(receive)) {
    const sep12 = isRecord(asset) ? asset.sep12 : undefined;
    if (!isRecord(sep12)) continue;
    for (const side of ['sender', 'receiver']) {
      const entry = sep12[side];
      const t = isRecord(entry) ? entry.types : undefined;
      if (isRecord(t)) Object.keys(t).forEach((k) => types.add(k));
    }
  }
  return [...types].sort();
}

async function getJson(url: string, fetchImpl: typeof fetch): Promise<unknown> {
  try {
    const response = await fetchImpl(url);
    if (!response.ok) return undefined;
    return (await response.json()) as unknown;
  } catch {
    return undefined;
  }
}

/** Builds a model from one SEP-12 `GET /customer` response body. */
export function observationFromCustomer(body: unknown): [string, StatusObservation] | undefined {
  if (!isRecord(body) || !isString(body.status)) return undefined;
  const obs: StatusObservation = {};
  if (isRecord(body.fields)) obs.fields = Object.keys(body.fields);
  if (isString(body.more_info_url)) obs.more_info_url = body.more_info_url;
  if (isString(body.message)) obs.message = body.message;
  return [body.status, obs];
}

/**
 * Fetches SEP-31 `/info` and SEP-12 `/customer` per advertised type and audits
 * the resulting state machines. Silent when either server is missing or the
 * anchor requires authentication to see any customer status.
 */
export async function auditKycStateMachines(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: KycAuditOptions = {},
): Promise<{ diagnostics: Diagnostic[]; models: KycModel[] }> {
  const kyc = doc.KYC_SERVER;
  const direct = doc.DIRECT_PAYMENT_SERVER;
  if (!isString(kyc) || !isString(direct)) return { diagnostics: [], models: [] };

  const info = await getJson(`${direct.replace(/\/+$/, '')}/info`, fetchImpl);
  const auditor = new KycTierStateMachineAuditor(options);
  const diagnostics: Diagnostic[] = [];
  const models: KycModel[] = [];
  for (const type of extractCustomerTypes(info)) {
    const body = await getJson(
      `${kyc.replace(/\/+$/, '')}/customer?type=${encodeURIComponent(type)}`,
      fetchImpl,
    );
    const observed = observationFromCustomer(body);
    if (observed === undefined) continue;
    const model: KycModel = { type, states: { [observed[0]]: observed[1] } };
    models.push(model);
    diagnostics.push(...auditor.audit(model));
  }
  return { diagnostics, models };
}

export const kycTierRules: Rule[] = [
  {
    id: UNKNOWN_STATUS_RULE,
    category: 'sep12',
    severity: 'error',
    description: 'SEP-12 customer status must be NEEDS_INFO, PENDING, ACCEPTED or REJECTED',
    run() {},
  },
  {
    id: NO_NEXT_ACTION_RULE,
    category: 'sep12',
    severity: 'error',
    description: 'Each SEP-12 status must give required fields or a next-action URL',
    run() {},
  },
  {
    id: CIRCULAR_RULE,
    category: 'sep12',
    severity: 'error',
    description: 'KYC status transitions must be able to reach ACCEPTED or REJECTED',
    run() {},
  },
  {
    id: NONDETERMINISTIC_RULE,
    category: 'sep12',
    severity: 'error',
    description: 'KYC status transitions must be deterministic',
    run() {},
  },
  {
    id: UNREACHABLE_RULE,
    category: 'sep12',
    severity: 'warning',
    description: 'Every advertised KYC status must be reachable',
    run() {},
  },
];

export const kycTierRuleIds: readonly string[] = kycTierRules.map((rule) => rule.id);
