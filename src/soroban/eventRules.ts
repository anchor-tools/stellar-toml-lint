/**
 * Soroban contract event conventions and validation rules.
 *
 * An off-chain indexer only sees what a contract chose to put in the event's
 * topics and data, and it can only filter on topics — the host indexes them,
 * data it does not. Ecosystem tooling therefore relies on a stable layout:
 * topic 0 names the action, the addresses that identify the participants come
 * next, and the data payload stays a flat `SCVal`.
 *
 * Two conventions are in use and both are supported here:
 *
 * - **Core** — the Stellar Asset Contract's own events (`transfer`, `mint`,
 *   `burn`, `clawback`, `approve`, `set_admin`, ...), where topic 0 is a
 *   `Symbol` and topics 1 and 2 are the participating `Address`es.
 * - **Community** — contract-defined events that follow the same shape
 *   (action, address, optional secondary identifier) without being one of the
 *   Core actions. A name the Core table does not know is judged by the general
 *   layout instead of being rejected.
 *
 * The rules here are pure: they take an already-decoded event (or a spec
 * definition) and return findings. `eventVerifier.ts` decodes the WASM spec and
 * the simulated `ContractEvent` XDR, then turns these findings into
 * diagnostics.
 */
import { Address } from '@stellar/stellar-base';
import type { xdr } from '@stellar/stellar-base';
import type { Rule } from '../types.js';

export const EVENT_MISSING_TOPICS_RULE = 'soroban/event-missing-topics';
export const EVENT_TOPIC_NOT_SYMBOL_RULE = 'soroban/event-topic-not-symbol';
export const EVENT_UNINDEXED_ADDRESS_RULE = 'soroban/event-unindexed-address';
export const EVENT_SECONDARY_TOPIC_RULE = 'soroban/event-secondary-topic-invalid';
export const EVENT_NESTED_DATA_RULE = 'soroban/event-unexpected-nested-data';
export const EVENT_SPEC_MISSING_NAME_RULE = 'soroban/event-spec-missing-name-topic';
export const EVENT_SPEC_UNINDEXED_ADDRESS_RULE = 'soroban/event-spec-unindexed-address';
export const EVENT_UNDECLARED_RULE = 'soroban/event-undeclared';

/** Stellar's reference documentation for contract events. */
export const SOROBAN_EVENTS_SPEC_URL =
  'https://developers.stellar.org/docs/learn/encyclopedia/contract-development/events';

/** The role a decoded topic value plays in the indexing schema. */
export type TopicRole = 'symbol' | 'string' | 'address' | 'integer' | 'bytes' | 'other';

/** One topic, classified for validation. */
export interface TopicInfo {
  /** Position in the topics array. */
  index: number;
  role: TopicRole;
  /** The symbol or string value, when the topic carries text. */
  text?: string;
  /** The canonical `C...`/`G...` address, when the topic carries one. */
  address?: string;
}

/** The shape of an event's data payload. */
export type DataShape = 'void' | 'scalar' | 'vec' | 'map' | 'other';

/** One decoded contract event, ready to validate. */
export interface EventRecord {
  /** The contract that emitted it, when the XDR names one. */
  contractId?: string;
  /** `contract`, `system`, `diagnostic`, or `unknown`. */
  type: string;
  /** Raw topics, in order. */
  topics: xdr.ScVal[];
  /** Raw data payload. */
  data: xdr.ScVal;
}

/** One event's spec declaration, as shipped in `contractspecv0`. */
export interface EventSpecDefinition {
  name: string;
  /** Constant topics prefixed to every emission of this event. */
  prefixTopics: string[];
  params: EventSpecParam[];
  dataFormat: 'single' | 'vec' | 'map' | 'unknown';
}

/** One declared event parameter and where the contract puts it. */
export interface EventSpecParam {
  name: string;
  /** `topic` when indexed, `data` when only carried in the payload. */
  location: 'topic' | 'data';
  /** The declared type's XDR switch name, e.g. `scSpecTypeAddress`. */
  type: string;
  /** True for `Address` and `MuxedAddress`. */
  address: boolean;
}

/** A problem found in an event's indexing schema. */
export interface EventFinding {
  rule: string;
  severity: 'error' | 'warning';
  message: string;
  suggestion?: string;
}

/** A convention's expected layout for one action. */
export interface EventActionLayout {
  /** Topic positions that must carry an address. */
  addressTopics: readonly number[];
  /** Data shapes the convention accepts. */
  dataShapes: readonly DataShape[];
}

/** One supported event convention. */
export interface EventConvention {
  id: 'core' | 'community';
  description: string;
  /** Known actions, keyed by lowercased topic-0 name. */
  actions: Readonly<Record<string, EventActionLayout>>;
  /** True when an action absent from {@link actions} still follows the layout. */
  allowsUnknownActions: boolean;
}

/**
 * Stellar Asset Contract (Core) events.
 *
 * `transfer` names both endpoints; `mint`/`burn`/`clawback` name the account
 * whose balance moves. `approve` names owner and spender. The data payload is
 * the amount, except for `approve`, which carries `(amount, expiration)`.
 */
export const CORE_EVENT_CONVENTIONS: EventConvention = {
  id: 'core',
  description: 'Stellar Asset Contract event layout',
  actions: {
    transfer: { addressTopics: [1, 2], dataShapes: ['scalar', 'vec'] },
    mint: { addressTopics: [1], dataShapes: ['scalar'] },
    burn: { addressTopics: [1], dataShapes: ['scalar'] },
    burn_from: { addressTopics: [1], dataShapes: ['scalar'] },
    clawback: { addressTopics: [1], dataShapes: ['scalar'] },
    approve: { addressTopics: [1, 2], dataShapes: ['scalar', 'vec', 'map'] },
    set_admin: { addressTopics: [1], dataShapes: ['scalar', 'void'] },
    set_authorized: { addressTopics: [1], dataShapes: ['scalar'] },
    freeze: { addressTopics: [1], dataShapes: ['scalar', 'void'] },
    unfreeze: { addressTopics: [1], dataShapes: ['scalar', 'void'] },
  },
  allowsUnknownActions: false,
};

/**
 * Community events: any action name is allowed, but the general layout still
 * has to hold — topic 1 is the participating address, topic 2 is an optional
 * secondary identifier, and the data payload stays flat.
 */
export const COMMUNITY_EVENT_CONVENTIONS: EventConvention = {
  id: 'community',
  description: 'Community contract event layout',
  actions: {},
  allowsUnknownActions: true,
};

/** Both conventions, Core first so a known Core action is judged by it. */
export const EVENT_CONVENTIONS: readonly EventConvention[] = [
  CORE_EVENT_CONVENTIONS,
  COMMUNITY_EVENT_CONVENTIONS,
];

/** The lowercased action name a topic 0 carries, when it carries text. */
export function eventActionName(topics: readonly xdr.ScVal[]): string | undefined {
  const first = topics[0];
  if (first === undefined) return undefined;
  const role = topicInfo(first, 0).role;
  if (role !== 'symbol' && role !== 'string') return undefined;
  return topicInfo(first, 0).text?.toLowerCase();
}

/** Classifies one topic. */
export function topicInfo(scVal: xdr.ScVal, index: number): TopicInfo {
  const switchName = scVal.switch().name;
  switch (switchName) {
    case 'scvSymbol':
      return { index, role: 'symbol', text: scVal.sym().toString() };
    case 'scvString':
      return { index, role: 'string', text: scVal.str().toString() };
    case 'scvAddress':
      return { index, role: 'address', ...addressOf(scVal) };
    case 'scvI32':
    case 'scvU32':
    case 'scvI64':
    case 'scvU64':
    case 'scvI128':
    case 'scvU128':
    case 'scvI256':
    case 'scvU256':
    case 'scvTimepoint':
    case 'scvDuration':
      return { index, role: 'integer' };
    case 'scvBytes':
      return { index, role: 'bytes' };
    default:
      return { index, role: 'other' };
  }
}

/** The canonical address a topic carries, when it is one. */
function addressOf(scVal: xdr.ScVal): { address?: string } {
  try {
    return { address: Address.fromScAddress(scVal.address()).toString() };
  } catch {
    return {};
  }
}

/** The shape of a data payload. */
export function dataShapeOf(scVal: xdr.ScVal): DataShape {
  switch (scVal.switch().name) {
    case 'scvVoid':
      return 'void';
    case 'scvVec':
      return 'vec';
    case 'scvMap':
      return 'map';
    default:
      return scVal.switch().name.startsWith('scv') ? 'scalar' : 'other';
  }
}

/**
 * The deepest container nesting in `scVal`: 0 for a scalar, 1 for a vector or
 * map of scalars, 2 when a vector or map holds another one, and so on.
 */
export function containerDepth(scVal: xdr.ScVal): number {
  switch (scVal.switch().name) {
    case 'scvVec': {
      const values = scVal.vec() ?? [];
      return 1 + Math.max(0, ...values.map((value) => containerDepth(value)));
    }
    case 'scvMap': {
      const entries = scVal.map() ?? [];
      const depths = entries.flatMap((entry) => [
        containerDepth(entry.key()),
        containerDepth(entry.val()),
      ]);
      return 1 + Math.max(0, ...depths);
    }
    default:
      return 0;
  }
}

/** True when an address value appears anywhere inside `scVal`. */
export function containsAddress(scVal: xdr.ScVal): boolean {
  switch (scVal.switch().name) {
    case 'scvAddress':
      return true;
    case 'scvVec':
      return (scVal.vec() ?? []).some((value) => containsAddress(value));
    case 'scvMap':
      return (scVal.map() ?? []).some(
        (entry) => containsAddress(entry.key()) || containsAddress(entry.val()),
      );
    default:
      return false;
  }
}

/**
 * The convention that governs an event: Core when the action is one of the
 * SAC's own, Community for anything else.
 */
export function conventionFor(action: string | undefined): EventConvention {
  if (action !== undefined && CORE_EVENT_CONVENTIONS.actions[action] !== undefined) {
    return CORE_EVENT_CONVENTIONS;
  }
  return COMMUNITY_EVENT_CONVENTIONS;
}

/**
 * Validates one decoded event against the Core and Community conventions.
 *
 * An event passes when it satisfies either convention. A Core action is judged
 * by the Core layout, because a `transfer` with the recipient in the data
 * payload is not indexable even though the general Community layout would only
 * complain about the missing address topic.
 */
export function validateEvent(record: EventRecord): EventFinding[] {
  const findings: EventFinding[] = [];
  const { topics } = record;

  if (topics.length === 0) {
    findings.push({
      rule: EVENT_MISSING_TOPICS_RULE,
      severity: 'error',
      message: 'event has no topics, so an indexer cannot subscribe to or filter it',
      suggestion:
        'Index the action name as topic 0 and the participating addresses as topics 1 and 2.',
    });
    return findings;
  }

  const first = topicInfo(topics[0] as xdr.ScVal, 0);
  if (first.role !== 'symbol' && first.role !== 'string') {
    findings.push({
      rule: EVENT_TOPIC_NOT_SYMBOL_RULE,
      severity: 'error',
      message: `event topic 0 is a ${first.role} value, not a symbol naming the action`,
      suggestion: 'Encode the action name, e.g. "transfer", as a Symbol in topic 0.',
    });
  }

  const action = first.text?.toLowerCase();
  const convention = conventionFor(action);
  const layout = action === undefined ? undefined : convention.actions[action];

  if (layout !== undefined) {
    for (const slot of layout.addressTopics) {
      const raw = topics[slot];
      const topic = raw === undefined ? undefined : topicInfo(raw, slot);
      if (topic === undefined) {
        findings.push({
          rule: EVENT_UNINDEXED_ADDRESS_RULE,
          severity: 'error',
          message: `\`${action}\` event is missing the address topic at position ${slot}`,
          suggestion: `Index the participating address as topic ${slot} so indexers can filter by account.`,
        });
        continue;
      }
      if (topic.role !== 'address') {
        findings.push({
          rule: EVENT_UNINDEXED_ADDRESS_RULE,
          severity: 'error',
          message: `\`${action}\` event topic ${slot} is a ${topic.role} value, not the participating address`,
          suggestion: `Index the participating address as topic ${slot} so indexers can filter by account.`,
        });
      }
    }

    if (
      containsAddress(record.data) &&
      !topics.some((topic) => topicInfo(topic, 0).role === 'address')
    ) {
      findings.push({
        rule: EVENT_UNINDEXED_ADDRESS_RULE,
        severity: 'error',
        message: `\`${action}\` event carries an address only in its data payload, where indexers cannot filter on it`,
        suggestion: 'Move the participating address into topic 1 (or 2).',
      });
    }

    const shape = dataShapeOf(record.data);
    if (!layout.dataShapes.includes(shape)) {
      findings.push({
        rule: EVENT_NESTED_DATA_RULE,
        severity: 'warning',
        message: `\`${action}\` event data is a ${shape} payload; the Core convention expects ${layout.dataShapes.join(
          ' or ',
        )}`,
        suggestion:
          'Emit the amount as a single SCVal so reconcilers can decode it without guessing.',
      });
    }
  } else {
    // Community layout: topic 0 action, topic 1 address, topic 2 secondary id.
    if (topics.length < 2 || topicInfo(topics[1] as xdr.ScVal, 1).role !== 'address') {
      findings.push({
        rule: EVENT_UNINDEXED_ADDRESS_RULE,
        severity: 'error',
        message: `${
          action === undefined ? 'event' : `\`${action}\` event`
        } does not index a participating address in topic 1`,
        suggestion: 'Index the account the event is about as topic 1.',
      });
    }
  }

  const second = topics[2];
  // A Core layout may put a second participant in topic 2; only a slot the
  // layout does not claim is used for a secondary identifier.
  if (second !== undefined && layout?.addressTopics.includes(2) !== true) {
    const role = topicInfo(second, 2).role;
    if (role !== 'symbol' && role !== 'string' && role !== 'integer' && role !== 'bytes') {
      findings.push({
        rule: EVENT_SECONDARY_TOPIC_RULE,
        severity: 'warning',
        message: `event topic 2 is a ${role} value, not a secondary identifier (symbol, string, integer, or bytes)`,
        suggestion:
          'Index a stable secondary identifier (asset code, pool key, or sequence) as topic 2, or omit it.',
      });
    }
  }

  const depth = containerDepth(record.data);
  if (depth > 1) {
    findings.push({
      rule: EVENT_NESTED_DATA_RULE,
      severity: 'warning',
      message: `event data nests containers ${depth} levels deep, which the standard indexing schema does not expect`,
      suggestion: 'Flatten the payload into a single value, a flat vector, or a map of scalars.',
    });
  }

  return findings;
}

/** Validates one event's spec declaration. */
export function validateEventSpec(spec: EventSpecDefinition): EventFinding[] {
  const findings: EventFinding[] = [];

  const prefix = spec.prefixTopics[0];
  if (prefix === undefined || prefix.toLowerCase() !== spec.name.toLowerCase()) {
    findings.push({
      rule: EVENT_SPEC_MISSING_NAME_RULE,
      severity: 'warning',
      message: `event spec \`${spec.name}\` does not declare its name as the first prefix topic`,
      suggestion: `Declare \`${spec.name}\` as the first symbol topic so emissions are self-describing.`,
    });
  }

  const indexedAddress = spec.params.some((param) => param.location === 'topic' && param.address);
  if (!indexedAddress) {
    findings.push({
      rule: EVENT_SPEC_UNINDEXED_ADDRESS_RULE,
      severity: 'warning',
      message: `event spec \`${spec.name}\` declares no address parameter in its topic list`,
      suggestion:
        'Mark the participating address parameter as a topic (for example `#[topic] from: Address`).',
    });
  }

  return findings;
}

/** Finds a declared event by its lowercased name. */
export function declaredEvent(
  specs: readonly EventSpecDefinition[],
  action: string | undefined,
): EventSpecDefinition | undefined {
  if (action === undefined) return undefined;
  return specs.find((spec) => spec.name.toLowerCase() === action);
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const eventRules: Rule[] = [
  {
    id: EVENT_MISSING_TOPICS_RULE,
    category: 'network',
    severity: 'error',
    description: 'A Soroban contract event has no topics and cannot be indexed',
    run() {},
  },
  {
    id: EVENT_TOPIC_NOT_SYMBOL_RULE,
    category: 'network',
    severity: 'error',
    description: 'A Soroban contract event does not name its action as a symbol in topic 0',
    run() {},
  },
  {
    id: EVENT_UNINDEXED_ADDRESS_RULE,
    category: 'network',
    severity: 'error',
    description: 'A Soroban contract event does not index the participating address in a topic',
    run() {},
  },
  {
    id: EVENT_SECONDARY_TOPIC_RULE,
    category: 'network',
    severity: 'warning',
    description: 'A Soroban contract event topic 2 is not a usable secondary identifier',
    run() {},
  },
  {
    id: EVENT_NESTED_DATA_RULE,
    category: 'network',
    severity: 'warning',
    description: 'A Soroban contract event payload nests containers beyond the schema',
    run() {},
  },
  {
    id: EVENT_SPEC_MISSING_NAME_RULE,
    category: 'network',
    severity: 'warning',
    description: 'A Soroban event spec does not declare its name as the first prefix topic',
    run() {},
  },
  {
    id: EVENT_SPEC_UNINDEXED_ADDRESS_RULE,
    category: 'network',
    severity: 'warning',
    description: 'A Soroban event spec declares no indexed address parameter',
    run() {},
  },
  {
    id: EVENT_UNDECLARED_RULE,
    category: 'network',
    severity: 'warning',
    description: 'A Soroban contract emits an event its spec does not declare',
    run() {},
  },
];
