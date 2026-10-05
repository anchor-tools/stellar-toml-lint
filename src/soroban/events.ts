/**
 * Soroban contract event schema extractor and SEP-41 synchronizer.
 *
 * Wallets and indexers react to Soroban events by topic, not by reading the
 * contract source. If a token contract emits non-standard topics — a renamed or
 * reordered `transfer`, or a `burn` whose amount arrives as a string — balance
 * changes silently fail to show up off-chain even though the contract itself
 * works. This audit reads the event definitions out of the contract's
 * `contractspecv0` custom section, checks them against the SEP-41 event
 * conventions, and (when the RPC is reachable) verifies the events the contract
 * actually emits with a `getEvents` call.
 *
 * Runs under the opt-in `--check-network` flag like the other on-chain audits,
 * never throws on an RPC outage, and registers rule objects so `--list-rules`
 * and `--off`/`--warn`/`--error` know its ids.
 *
 * Diagnostics:
 * - `soroban/event-topic-mismatch` (warning)
 * - `soroban/event-data-type-invalid` (error)
 */
import { cereal, xdr } from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isString } from '../predicates.js';
import { rpcUrlFor } from '../rules/display-decimals-audit.js';
import { contractCurrenciesOf } from '../rules/currencies.js';
import { getWasmCustomSection } from './wasm-auditor.js';
import { fetchContractWasm, RPC_TIMEOUT_MS, severityFor } from './rpc.js';

export const EVENT_TOPIC_MISMATCH_RULE = 'soroban/event-topic-mismatch';
export const EVENT_DATA_TYPE_INVALID_RULE = 'soroban/event-data-type-invalid';

/** How many recent contract events to validate per contract. */
const EVENT_LOOKBACK_LIMIT = 25;

/** The standard SEP-41 events and the topic/type conventions they must keep. */
export const SEP41_EVENT_SCHEMA: Record<string, { topics: string[]; dataType: 'scSpecTypeI128' }> =
  {
    transfer: { topics: ['transfer', 'from', 'to'], dataType: 'scSpecTypeI128' },
    mint: { topics: ['mint', 'admin', 'to'], dataType: 'scSpecTypeI128' },
    burn: { topics: ['burn', 'from'], dataType: 'scSpecTypeI128' },
  };

export interface EventsOptions {
  rules?: RuleOverrides;
  /** The file path that named the contract, attached to every diagnostic. */
  path?: string;
  /** Soroban RPC endpoint, overriding the one derived from the passphrase. */
  rpcUrl?: string;
  /** Skip the live `getEvents` query, checking only the declared schema. */
  skipLiveEvents?: boolean;
}

/** One event as the contract's spec declares it. */
export interface SpecEvent {
  name: string;
  prefixTopics: string[];
  topics: string[];
  dataTypes: string[];
}

/** Reads the `eventV0` entries out of a contract's spec section. */
export function extractSpecEvents(wasm: Buffer): SpecEvent[] | undefined {
  const section = getWasmCustomSection(wasm, 'contractspecv0');
  if (section === undefined) return undefined;

  try {
    // `xdr.ScSpecEntry.read` accepts the cereal reader directly even though its
    // published type says Buffer; keep the cast in one place.
    const reader = new cereal.XdrReader(section);
    const events: SpecEvent[] = [];
    while (!reader.eof) {
      const entry = xdr.ScSpecEntry.read(reader as unknown as Buffer);
      if (entry.switch().name !== 'scSpecEntryEventV0') continue;
      events.push(specEventOf(entry.eventV0()));
    }
    return events;
  } catch {
    return undefined;
  }
}

function specEventOf(event: xdr.ScSpecEventV0): SpecEvent {
  const params = event.params();
  const topics = params
    .filter((p) => p.location().name === 'scSpecEventParamLocationTopicList')
    .map((p) => p.name().toString());
  const dataTypes = params
    .filter((p) => p.location().name === 'scSpecEventParamLocationData')
    .map((p) => p.type().switch().name);
  return {
    name: event.name().toString(),
    prefixTopics: event.prefixTopics().map((t) => t.toString()),
    topics,
    dataTypes,
  };
}

function eventFinding(
  contractId: string,
  options: EventsOptions,
): (
  rule: string,
  fallback: 'error' | 'warning',
  detail: string,
  suggestion?: string,
) => Diagnostic[] {
  return (rule, fallback, detail, suggestion) => {
    const severity = severityFor(rule, fallback, options.rules);
    if (severity === undefined) return [];
    return [
      {
        rule,
        severity,
        category: 'network',
        message: `Contract ${contractId} ${detail}`,
        ...(options.path !== undefined ? { path: options.path } : {}),
        ...(suggestion !== undefined ? { suggestion } : {}),
      },
    ];
  };
}

/**
 * Checks a contract's declared event definitions against the SEP-41
 * conventions. Only events the spec actually declares are checked, so a
 * contract that emits a subset is not punished for the ones it omits.
 */
export function verifySep41EventSpecs(
  wasm: Buffer,
  contractId: string,
  options: EventsOptions = {},
): Diagnostic[] {
  const events = extractSpecEvents(wasm);
  if (events === undefined) return [];

  const finding = eventFinding(contractId, options);
  const diagnostics: Diagnostic[] = [];
  const byName = new Map(events.map((event) => [event.name, event]));

  for (const [name, expected] of Object.entries(SEP41_EVENT_SCHEMA)) {
    const event = byName.get(name);
    if (event === undefined) continue;

    const expectedTopics = expected.topics;
    const expectedTopicParams = expectedTopics.slice(1);
    const prefixOk = event.prefixTopics.length === 1 && event.prefixTopics[0] === name;
    const topicsOk =
      prefixOk &&
      event.topics.length === expectedTopicParams.length &&
      event.topics.every((topic, index) => topic === expectedTopicParams[index]);

    if (!topicsOk) {
      diagnostics.push(
        ...finding(
          EVENT_TOPIC_MISMATCH_RULE,
          'warning',
          `declares "${name}" with topics [${[...event.prefixTopics, ...event.topics].join(', ')}], expected [${expectedTopics.join(', ')}]`,
          `Emit "${name}" with the SEP-41 topic list [${expectedTopics.join(', ')}].`,
        ),
      );
    }

    if (!event.dataTypes.includes(expected.dataType)) {
      diagnostics.push(
        ...finding(
          EVENT_DATA_TYPE_INVALID_RULE,
          'error',
          `declares "${name}" with a non-${expected.dataType} data payload`,
          `Emit the "${name}" amount as an i128 value.`,
        ),
      );
    }
  }

  return diagnostics;
}

/** One event as the RPC returned it, with base64 XDR topics and value. */
export interface RawEvent {
  topics?: unknown;
  value?: unknown;
}

/** Maps a spec type name (`scSpecTypeI128`) to its runtime name (`scvI128`). */
function liveScValType(specType: string): string {
  return specType.replace('scSpecType', 'scv');
}

function decodeScVal(xdrString: unknown): xdr.ScVal | undefined {
  if (!isString(xdrString)) return undefined;
  try {
    return xdr.ScVal.fromXDR(xdrString, 'base64');
  } catch {
    return undefined;
  }
}

/**
 * Validates the live events a contract emitted against the SEP-41 shape:
 * `transfer` with topics `[transfer, from, to]`, `mint` with
 * `[mint, admin, to]`, `burn` with `[burn, from]`, each carrying an i128 data
 * payload. Events whose name is not one of the three are ignored.
 */
export function verifyLiveEvents(
  events: RawEvent[],
  contractId: string,
  options: EventsOptions = {},
): Diagnostic[] {
  const finding = eventFinding(contractId, options);
  const diagnostics: Diagnostic[] = [];

  for (const event of events) {
    const topicVals = Array.isArray(event.topics) ? event.topics : [];
    const nameVal = decodeScVal(topicVals[0]);
    if (nameVal === undefined) continue;
    const name =
      nameVal.switch().name === 'scvSymbol' || nameVal.switch().name === 'scvString'
        ? nameVal.value()!.toString()
        : undefined;
    if (name === undefined) continue;

    const expected = SEP41_EVENT_SCHEMA[name];
    if (expected === undefined) continue;

    const topicsMatch =
      topicVals.length === expected.topics.length &&
      topicVals.slice(1).every((topic) => {
        const val = decodeScVal(topic);
        return val !== undefined && val.switch().name === 'scvAddress';
      });

    if (!topicsMatch) {
      diagnostics.push(
        ...finding(
          EVENT_TOPIC_MISMATCH_RULE,
          'warning',
          `emitted "${name}" with ${topicVals.length - 1} topic value(s), expected ${expected.topics.length - 1}`,
          `Emit "${name}" with the SEP-41 topic list [${expected.topics.join(', ')}].`,
        ),
      );
    }

    const dataVal = decodeScVal(event.value);
    if (dataVal === undefined || dataVal.switch().name !== liveScValType(expected.dataType)) {
      diagnostics.push(
        ...finding(
          EVENT_DATA_TYPE_INVALID_RULE,
          'error',
          `emitted "${name}" with a non-i128 data payload`,
          `Emit the "${name}" amount as an i128 value.`,
        ),
      );
    }
  }

  return diagnostics;
}

interface RpcResult {
  result?: Record<string, unknown>;
}

async function rpcCall(
  rpcUrl: string,
  method: string,
  params: Record<string, unknown>,
  fetchImpl: typeof fetch,
): Promise<RpcResult | undefined> {
  try {
    const response = await fetchImpl(rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
      signal: AbortSignal.timeout(RPC_TIMEOUT_MS),
    });
    if (!response.ok) return undefined;
    const body = (await response.json()) as RpcResult;
    return typeof body.result === 'object' && body.result !== null ? body : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Queries the most recent events the contract emitted. `undefined` means the
 * RPC could not answer; an empty array is a valid "no recent events" answer.
 */
export async function fetchRecentEvents(
  contractId: string,
  rpcUrl: string,
  fetchImpl: typeof fetch = fetch,
): Promise<RawEvent[] | undefined> {
  const body = await rpcCall(
    rpcUrl,
    'getEvents',
    {
      filters: [{ type: 'contract', contractIds: [contractId] }],
      pagination: { limit: EVENT_LOOKBACK_LIMIT },
    },
    fetchImpl,
  );
  if (body === undefined) return undefined;
  const events = body.result?.events;
  return Array.isArray(events) ? (events as RawEvent[]) : [];
}

/**
 * Audits one contract: its declared event schema, then the events it actually
 * emitted. Stays silent when the WASM cannot be fetched, and skips live event
 * validation entirely when the RPC does not answer.
 */
export async function auditContractEvents(
  contractId: string,
  rpcUrl: string,
  fetchImpl: typeof fetch = fetch,
  options: EventsOptions = {},
): Promise<Diagnostic[]> {
  const wasm = await fetchContractWasm(contractId, rpcUrl, fetchImpl);
  const diagnostics = wasm === undefined ? [] : verifySep41EventSpecs(wasm, contractId, options);
  if (options.skipLiveEvents) return diagnostics;

  const events = await fetchRecentEvents(contractId, rpcUrl, fetchImpl);
  if (events !== undefined) {
    diagnostics.push(...verifyLiveEvents(events, contractId, options));
  }
  return diagnostics;
}

/**
 * Audits the event schema of every contract the file declares under
 * `[[CURRENCIES]]`. Silent when no RPC URL can be derived.
 */
export async function auditTomlContractEvents(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: EventsOptions = {},
): Promise<Diagnostic[]> {
  const rpcUrl =
    options.rpcUrl ??
    rpcUrlFor(typeof doc.NETWORK_PASSPHRASE === 'string' ? doc.NETWORK_PASSPHRASE : undefined);
  if (!rpcUrl) return [];

  const diagnostics: Diagnostic[] = [];
  for (const currency of contractCurrenciesOf(doc)) {
    diagnostics.push(
      ...(await auditContractEvents(currency.id, rpcUrl, fetchImpl, {
        ...options,
        path: currency.path,
      })),
    );
  }
  return diagnostics;
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const eventRules: Rule[] = [
  {
    id: EVENT_TOPIC_MISMATCH_RULE,
    category: 'network',
    severity: 'warning',
    description: 'A Soroban contract event does not use the standard SEP-41 topics',
    run() {},
  },
  {
    id: EVENT_DATA_TYPE_INVALID_RULE,
    category: 'network',
    severity: 'error',
    description: 'A Soroban contract event carries an amount that is not an i128',
    run() {},
  },
];

/** Rule ids emitted by {@link auditTomlContractEvents}. */
export const eventRuleIds: readonly string[] = eventRules.map((rule) => rule.id);
