/**
 * Soroban contract event schema and indexing verifier.
 *
 * Off-chain indexers, custody services, and payment reconcilers subscribe to a
 * contract's events by topic. That only works when the contract emits a stable
 * schema: topic 0 names the action, topic 1 carries the participating address,
 * and the data payload is a flat `SCVal`. A contract that puts the recipient in
 * its data payload is invisible to a subscription that filters on the recipient
 * topic, and a deposit confirmation is silently lost.
 *
 * This module audits both halves of the contract:
 *
 * - **Static** — the `contractspecv0` custom section of the deployed WASM
 *   declares every `#[contractevent]`, its prefix topics, and which parameters
 *   are indexed (`ScSpecEventParamLocationV0`).
 * - **Dynamic** — token operations (`mint`, `transfer`, `approve`, admin
 *   changes) are dry-run through `simulateTransaction` in recording auth mode,
 *   and the returned `ContractEvent` XDR is decoded and validated against the
 *   Core (SAC) and Community layouts in `eventRules.ts`.
 *
 * Nothing is signed or submitted. The verifier degrades silently when the RPC
 * cannot answer or the WASM cannot be parsed: an outage is not a finding.
 */
import {
  Account,
  Address,
  Operation,
  StrKey,
  TransactionBuilder,
  nativeToScVal,
  xdr,
  cereal,
} from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides, Severity } from '../types.js';
import { isString } from '../predicates.js';
import { rpcUrlFor } from '../rules/display-decimals-audit.js';
import { contractCurrenciesOf } from '../rules/currencies.js';
import {
  CORE_EVENT_CONVENTIONS,
  EVENT_UNDECLARED_RULE,
  SOROBAN_EVENTS_SPEC_URL,
  declaredEvent,
  eventActionName,
  eventRules,
  topicInfo,
  validateEvent,
  validateEventSpec,
  type EventFinding,
  type EventRecord,
  type EventSpecDefinition,
} from './eventRules.js';

export const DEFAULT_SOURCE_ACCOUNT = 'GDVEU3DD4KOFECV66VIHWEZOYX4ZKR3WV27L464SIIPOU2IUI3JCZA57';
const NETWORK_PASSPHRASE = 'Test SDF Network ; September 2015';
export const RPC_TIMEOUT_MS = 10_000;

/** The recording auth mode lets `require_auth` contracts simulate without signatures. */
export const RECORDING_AUTH_MODE = 'record';

/** How many entry points are dry-run per contract. */
export const DEFAULT_MAX_SIMULATED_FUNCTIONS = 6;

/** The WASM custom section Soroban stores a contract's spec entries in. */
const CONTRACT_SPEC_SECTION = 'contractspecv0';

/**
 * Entry points a token contract emits events from. Simulated first so the
 * verifier spends its RPC budget on the operations that matter.
 */
export const EVENT_EMITTING_FUNCTIONS: ReadonlySet<string> = new Set([
  'mint',
  'transfer',
  'transfer_from',
  'clawback',
  'burn',
  'burn_from',
  'approve',
  'increase_allowance',
  'decrease_allowance',
  'set_admin',
  'set_owner',
  'set_authorized',
  'freeze',
  'unfreeze',
  'initialize',
  'init',
]);

/** Read-only entry points that do not emit value events. */
const READ_ONLY_FUNCTIONS: ReadonlySet<string> = new Set([
  'balance',
  'allowance',
  'decimals',
  'name',
  'symbol',
  'owner',
  'admin',
  'get_admin',
  'total_supply',
  'get_config',
]);

/** Entry points that change the contract's code and are not simulated. */
const SKIPPED_FUNCTIONS: ReadonlySet<string> = new Set([
  'upgrade',
  'set_wasm',
  'update_wasm',
  'extend_ttl',
]);

/** One exported contract function, as declared by the spec. */
export interface ContractFunctionSpec {
  name: string;
  /** Declared input types, in order, for building simulation arguments. */
  inputs: xdr.ScSpecTypeDef[];
}

/** Everything the verifier reads out of a contract's spec section. */
export interface ContractSpecAudit {
  events: EventSpecDefinition[];
  functions: ContractFunctionSpec[];
}

export interface EventVerifierOptions {
  /** Severity overrides, keyed by rule id. */
  rules?: RuleOverrides;
  /** The file path that named the contract, attached to every diagnostic. */
  path?: string;
  /** Soroban RPC endpoint, overriding the one derived from the passphrase. */
  rpcUrl?: string;
  /** Network passphrase used to build the simulated envelope. */
  networkPassphrase?: string;
  /** Source account for the simulated envelope. */
  sourceAccount?: string;
  /** Maximum entry points dry-run per contract. */
  maxSimulatedFunctions?: number;
  /** Skip the simulated half and only inspect the WASM spec. */
  specOnly?: boolean;
}

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules?: RuleOverrides,
): Severity | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' || override === 'info'
    ? override
    : fallback;
}

// ---------------------------------------------------------------------------
// WASM custom section reading
// ---------------------------------------------------------------------------

function readLeb128(wasm: Buffer, offset: number): { value: number; next: number } | undefined {
  let value = 0;
  let shift = 0;
  let pos = offset;
  while (pos < wasm.length) {
    const byte = wasm[pos] as number;
    value |= (byte & 0x7f) << shift;
    pos++;
    if ((byte & 0x80) === 0) return { value: value >>> 0, next: pos };
    shift += 7;
    if (shift > 28) return undefined;
  }
  return undefined;
}

/** The payload of the named WASM custom section, or `undefined`. */
function wasmCustomSection(wasm: Buffer, name: string): Buffer | undefined {
  if (wasm.length < 8 || wasm.readUInt32BE(0) !== 0x0061736d) return undefined;

  let pos = 8;
  while (pos < wasm.length) {
    const id = wasm[pos] as number;
    const size = readLeb128(wasm, pos + 1);
    if (size === undefined) return undefined;

    const start = size.next;
    const end = start + size.value;
    if (end > wasm.length) return undefined;

    if (id === 0) {
      const nameLength = readLeb128(wasm, start);
      if (nameLength !== undefined) {
        const nameStart = nameLength.next;
        const nameEnd = nameStart + nameLength.value;
        if (nameEnd <= end && wasm.toString('utf8', nameStart, nameEnd) === name) {
          return wasm.subarray(nameEnd, end);
        }
      }
    }

    pos = end;
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Spec parsing
// ---------------------------------------------------------------------------

function dataFormatOf(format: xdr.ScSpecEventDataFormat): EventSpecDefinition['dataFormat'] {
  switch (format.name) {
    case 'scSpecEventDataFormatSingleValue':
      return 'single';
    case 'scSpecEventDataFormatVec':
      return 'vec';
    case 'scSpecEventDataFormatMap':
      return 'map';
    default:
      return 'unknown';
  }
}

/** True when a declared type is an address (account or muxed account). */
export function isAddressType(type: xdr.ScSpecTypeDef): boolean {
  const name = type.switch().name;
  return name === 'scSpecTypeAddress' || name === 'scSpecTypeMuxedAddress';
}

/**
 * Reads the event and function declarations out of a contract's
 * `contractspecv0` section.
 *
 * `undefined` means the module is not WASM, has no spec section, or the section
 * cannot be decoded — all of which are reasons not to judge the contract.
 */
export function parseContractSpec(wasm: Buffer): ContractSpecAudit | undefined {
  const section = wasmCustomSection(wasm, CONTRACT_SPEC_SECTION);
  if (section === undefined) return undefined;

  const events: EventSpecDefinition[] = [];
  const functions: ContractFunctionSpec[] = [];

  try {
    const reader = new cereal.XdrReader(section);
    while (!reader.eof) {
      const entry = xdr.ScSpecEntry.read(reader as unknown as Buffer);
      switch (entry.switch().name) {
        case 'scSpecEntryEventV0': {
          const event = entry.eventV0();
          events.push({
            name: event.name().toString(),
            prefixTopics: event.prefixTopics().map((topic) => topic.toString()),
            params: event.params().map((param) => {
              const type = param.type();
              return {
                name: param.name().toString(),
                location:
                  param.location().name === 'scSpecEventParamLocationTopicList'
                    ? ('topic' as const)
                    : ('data' as const),
                type: type.switch().name,
                address: isAddressType(type),
              };
            }),
            dataFormat: dataFormatOf(event.dataFormat()),
          });
          break;
        }
        case 'scSpecEntryFunctionV0': {
          const fn = entry.functionV0();
          functions.push({
            name: fn.name().toString(),
            inputs: fn.inputs().map((input) => input.type()),
          });
          break;
        }
        default:
          break;
      }
    }
  } catch {
    return undefined;
  }

  return { events, functions };
}

/** The event declarations alone, or `undefined` when the spec cannot be read. */
export function parseEventSpecs(wasm: Buffer): EventSpecDefinition[] | undefined {
  return parseContractSpec(wasm)?.events;
}

// ---------------------------------------------------------------------------
// ContractEvent decoding
// ---------------------------------------------------------------------------

/** Reads one `ContractEvent` XDR into a validation record. */
export function parseContractEvent(raw: unknown): EventRecord | undefined {
  if (!isString(raw)) return undefined;
  try {
    const event = xdr.ContractEvent.fromXDR(raw, 'base64');
    const contractId = event.contractId();
    let id: string | undefined;
    if (contractId !== null) {
      try {
        id = StrKey.encodeContract(Buffer.from(contractId as unknown as Buffer));
      } catch {
        id = undefined;
      }
    }
    const body = event.body().v0();
    return {
      ...(id !== undefined ? { contractId: id } : {}),
      type: event.type().name,
      topics: body.topics(),
      data: body.data(),
    };
  } catch {
    return undefined;
  }
}

/**
 * Reads the events array of a `simulateTransaction` response.
 *
 * Newer RPCs return them at the top level of the result; some put them on each
 * `results[]` item. Both shapes are accepted, and an entry that cannot be
 * decoded is skipped rather than guessed at.
 */
export function parseSimulatedEvents(raw: unknown): EventRecord[] {
  if (!Array.isArray(raw)) return [];
  const events: EventRecord[] = [];
  for (const item of raw) {
    const event = parseContractEvent(
      isString(item)
        ? item
        : typeof item === 'object' && item !== null && isString((item as { xdr?: unknown }).xdr)
          ? (item as { xdr: string }).xdr
          : undefined,
    );
    if (event !== undefined) events.push(event);
  }
  return events;
}

/** Where an RPC result keeps the simulated contract events. */
export function simulatedEventsOf(result: Record<string, unknown>): unknown[] {
  const found: unknown[] = [];
  const push = (value: unknown): void => {
    if (Array.isArray(value)) found.push(...value);
  };

  push(result.events);
  push(result.diagnosticEvents);

  if (Array.isArray(result.results)) {
    for (const item of result.results) {
      if (typeof item !== 'object' || item === null) continue;
      push((item as Record<string, unknown>).events);
      push((item as Record<string, unknown>).diagnosticEvents);
    }
  }
  return found;
}

// ---------------------------------------------------------------------------
// Simulation
// ---------------------------------------------------------------------------

/** A placeholder argument for a declared input type. */
function defaultValue(type: xdr.ScSpecTypeDef, source: string): xdr.ScVal {
  switch (type.switch().name) {
    case 'scSpecTypeAddress':
    case 'scSpecTypeMuxedAddress':
      return new Address(source).toScVal();
    case 'scSpecTypeBool':
      return nativeToScVal(false, { type: 'bool' });
    case 'scSpecTypeU32':
      return nativeToScVal(0, { type: 'u32' });
    case 'scSpecTypeI32':
      return nativeToScVal(0, { type: 'i32' });
    case 'scSpecTypeU64':
      return nativeToScVal(0n, { type: 'u64' });
    case 'scSpecTypeI64':
      return nativeToScVal(0n, { type: 'i64' });
    case 'scSpecTypeU128':
      return nativeToScVal(0n, { type: 'u128' });
    case 'scSpecTypeI128':
      return nativeToScVal(0n, { type: 'i128' });
    case 'scSpecTypeSymbol':
      return nativeToScVal('event', { type: 'symbol' });
    case 'scSpecTypeString':
      return nativeToScVal('', { type: 'string' });
    case 'scSpecTypeBytes':
      return nativeToScVal(Buffer.alloc(0), { type: 'bytes' });
    default:
      return xdr.ScVal.scvVoid();
  }
}

/**
 * Builds the base64 `TransactionEnvelope` that dry-runs `fn` on `contractId`.
 * The transaction is never signed or submitted.
 */
export function buildEventSimulationTransaction(
  contractId: string,
  fn: ContractFunctionSpec,
  options: EventVerifierOptions = {},
): string {
  const source = options.sourceAccount ?? DEFAULT_SOURCE_ACCOUNT;
  try {
    const contract = new Address(contractId).toScAddress();
    const args = fn.inputs.map((type) => defaultValue(type, source));
    const hostFunction = xdr.HostFunction.hostFunctionTypeInvokeContract(
      new xdr.InvokeContractArgs({
        contractAddress: contract,
        functionName: fn.name,
        args,
      }),
    );

    const transaction = new TransactionBuilder(new Account(source, '0'), {
      fee: '100',
      networkPassphrase: options.networkPassphrase ?? NETWORK_PASSPHRASE,
    })
      .addOperation(Operation.invokeHostFunction({ func: hostFunction, auth: [] }))
      .setTimeout(30)
      .build();

    return transaction.toEnvelope().toXDR('base64');
  } catch {
    return '';
  }
}

/** The entry points worth simulating, in priority order. */
export function simulationTargets(
  functions: readonly ContractFunctionSpec[],
  limit = DEFAULT_MAX_SIMULATED_FUNCTIONS,
): ContractFunctionSpec[] {
  const candidates = functions.filter((fn) => {
    const name = fn.name.toLowerCase();
    return !READ_ONLY_FUNCTIONS.has(name) && !SKIPPED_FUNCTIONS.has(name);
  });
  const preferred = candidates.filter((fn) => EVENT_EMITTING_FUNCTIONS.has(fn.name.toLowerCase()));
  const rest = candidates.filter((fn) => !EVENT_EMITTING_FUNCTIONS.has(fn.name.toLowerCase()));
  return [...preferred, ...rest].slice(0, Math.max(0, limit));
}

/** POSTs one `simulateTransaction`; `undefined` when the RPC cannot answer. */
async function simulateResult(
  rpcUrl: string,
  envelope: string,
  fetchImpl: typeof fetch,
): Promise<Record<string, unknown> | undefined> {
  try {
    const response = await fetchImpl(rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'simulateTransaction',
        params: { transaction: envelope, authMode: RECORDING_AUTH_MODE },
      }),
      signal: AbortSignal.timeout(RPC_TIMEOUT_MS),
    });
    if (!response.ok) return undefined;

    const body = (await response.json()) as { result?: Record<string, unknown> };
    const result = body.result;
    return typeof result === 'object' && result !== null ? result : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Dry-runs the contract's event-emitting entry points and returns every
 * decoded event, de-duplicated by XDR.
 */
export async function simulateContractEvents(
  contractId: string,
  functions: readonly ContractFunctionSpec[],
  rpcUrl: string,
  fetchImpl: typeof fetch = fetch,
  options: EventVerifierOptions = {},
): Promise<EventRecord[]> {
  const events: EventRecord[] = [];
  const seen = new Set<string>();

  for (const fn of simulationTargets(functions, options.maxSimulatedFunctions)) {
    const envelope = buildEventSimulationTransaction(contractId, fn, options);
    if (envelope === '') continue;
    const result = await simulateResult(rpcUrl, envelope, fetchImpl);
    if (result === undefined) continue;

    for (const item of simulatedEventsOf(result)) {
      if (!isString(item)) continue;
      if (seen.has(item)) continue;
      seen.add(item);
      const event = parseContractEvent(item);
      if (event !== undefined) events.push(event);
    }
  }
  return events;
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/** Turns an event finding into a diagnostic, honouring severity overrides. */
function eventDiagnostic(
  finding: EventFinding,
  options: EventVerifierOptions,
): Diagnostic | undefined {
  const severity = severityFor(finding.rule, finding.severity, options.rules);
  if (severity === undefined) return undefined;
  return {
    rule: finding.rule,
    severity,
    category: 'network',
    message: finding.message,
    ...(options.path !== undefined ? { path: options.path } : {}),
    helpUri: SOROBAN_EVENTS_SPEC_URL,
    ...(finding.suggestion !== undefined ? { suggestion: finding.suggestion } : {}),
  };
}

/**
 * Validates decoded events.
 *
 * Events emitted by another contract (a nested token call) are not this
 * contract's schema and are skipped when the event names a different contract.
 * A declared spec is also checked for emissions it does not declare.
 */
export function validateContractEvents(
  contractId: string,
  events: readonly EventRecord[],
  specs: readonly EventSpecDefinition[] = [],
  options: EventVerifierOptions = {},
): Diagnostic[] {
  const diagnostics: Diagnostic[] = [];

  for (const event of events) {
    if (event.type !== 'contract') continue;
    if (event.contractId !== undefined && event.contractId !== contractId) continue;

    for (const finding of validateEvent(event)) {
      const diagnostic = eventDiagnostic(
        {
          ...finding,
          message: `Contract ${contractId} ${finding.message}`,
        },
        options,
      );
      if (diagnostic !== undefined) diagnostics.push(diagnostic);
    }

    const action = eventActionName(event.topics);
    if (specs.length > 0 && action !== undefined && declaredEvent(specs, action) === undefined) {
      const diagnostic = eventDiagnostic(
        {
          rule: EVENT_UNDECLARED_RULE,
          severity: 'warning',
          message: `Contract ${contractId} emits \`${action}\` but its spec declares ${specs
            .map((spec) => `\`${spec.name}\``)
            .join(', ')}`,
          suggestion:
            'Declare the event in the contract with #[contractevent] so indexers can generate a typed subscription.',
        },
        options,
      );
      if (diagnostic !== undefined) diagnostics.push(diagnostic);
    }
  }

  return diagnostics;
}

/** Validates the event declarations of a contract's WASM spec. */
export function validateEventSpecs(
  contractId: string,
  specs: readonly EventSpecDefinition[],
  options: EventVerifierOptions = {},
): Diagnostic[] {
  const diagnostics: Diagnostic[] = [];
  for (const spec of specs) {
    for (const finding of validateEventSpec(spec)) {
      const diagnostic = eventDiagnostic(
        {
          ...finding,
          message: `Contract ${contractId} ${finding.message}`,
        },
        options,
      );
      if (diagnostic !== undefined) diagnostics.push(diagnostic);
    }
  }
  return diagnostics;
}

// ---------------------------------------------------------------------------
// RPC ledger access
// ---------------------------------------------------------------------------

async function ledgerEntryXdr(
  rpcUrl: string,
  key: string,
  fetchImpl: typeof fetch,
): Promise<unknown> {
  try {
    const response = await fetchImpl(rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'getLedgerEntries',
        params: { keys: [key] },
      }),
    });
    if (!response.ok) return undefined;
    const body = (await response.json()) as { result?: { entries?: unknown } };
    const entries = body.result?.entries;
    if (!Array.isArray(entries)) return undefined;
    const entry = entries.find(
      (item): item is Record<string, unknown> => typeof item === 'object' && item !== null,
    );
    return entry?.xdr;
  } catch {
    return undefined;
  }
}

function contractInstanceKey(contractId: string): string {
  return xdr.LedgerKey.contractData(
    new xdr.LedgerKeyContractData({
      contract: new Address(contractId).toScAddress(),
      key: xdr.ScVal.scvLedgerKeyContractInstance(),
      durability: xdr.ContractDataDurability.persistent(),
    }),
  ).toXDR('base64');
}

function wasmHashOfEntry(entryXdr: unknown): Buffer | undefined {
  if (!isString(entryXdr)) return undefined;
  try {
    const data = xdr.LedgerEntryData.fromXDR(entryXdr, 'base64');
    const val = data.contractData().val();
    if (val.switch().name !== 'scvContractInstance') return undefined;
    const executable = val.instance().executable();
    if (executable.switch().name !== 'contractExecutableWasm') return undefined;
    return Buffer.from(executable.wasmHash());
  } catch {
    return undefined;
  }
}

function wasmBytesOfEntry(entryXdr: unknown): Buffer | undefined {
  if (!isString(entryXdr)) return undefined;
  try {
    const data = xdr.LedgerEntryData.fromXDR(entryXdr, 'base64');
    if (data.switch().name !== 'contractCode') return undefined;
    return Buffer.from(data.contractCode().code());
  } catch {
    return undefined;
  }
}

/** The WASM behind `contractId`, or `undefined` when it cannot be read. */
export async function fetchEventContractWasm(
  contractId: string,
  rpcUrl: string,
  fetchImpl: typeof fetch = fetch,
): Promise<Buffer | undefined> {
  const instance = await ledgerEntryXdr(rpcUrl, contractInstanceKey(contractId), fetchImpl);
  const hash = wasmHashOfEntry(instance);
  if (hash === undefined) return undefined;

  const key = xdr.LedgerKey.contractCode(new xdr.LedgerKeyContractCode({ hash })).toXDR('base64');
  return wasmBytesOfEntry(await ledgerEntryXdr(rpcUrl, key, fetchImpl));
}

// ---------------------------------------------------------------------------
// The verifier
// ---------------------------------------------------------------------------

/**
 * Audits a contract's event schema, both statically (WASM spec) and dynamically
 * (simulated emissions).
 *
 * ```ts
 * const verifier = new EventSchemaVerifier({ rpcUrl });
 * const diagnostics = await verifier.verifyContract(contractId);
 * ```
 */
export class EventSchemaVerifier {
  private readonly options: EventVerifierOptions;

  constructor(options: EventVerifierOptions = {}) {
    this.options = options;
  }

  /** Reads the event and function declarations from a WASM module. */
  specOf(wasm: Buffer): ContractSpecAudit | undefined {
    return parseContractSpec(wasm);
  }

  /** Decodes the events array of a simulated transaction result. */
  parseEvents(raw: unknown): EventRecord[] {
    return parseSimulatedEvents(raw);
  }

  /** Diagnoses the event declarations of a WASM module. */
  verifySpec(contractId: string, wasm: Buffer): Diagnostic[] {
    const spec = this.specOf(wasm);
    if (spec === undefined) return [];
    return validateEventSpecs(contractId, spec.events, this.options);
  }

  /** Diagnoses already-decoded events. */
  verifyEvents(
    contractId: string,
    events: readonly EventRecord[],
    specs: readonly EventSpecDefinition[] = [],
  ): Diagnostic[] {
    return validateContractEvents(contractId, events, specs, this.options);
  }

  /** Dry-runs the contract's event-emitting entry points. */
  async simulate(
    contractId: string,
    wasm: Buffer,
    rpcUrl: string,
    fetchImpl: typeof fetch = fetch,
  ): Promise<EventRecord[]> {
    const spec = this.specOf(wasm);
    if (spec === undefined) return [];
    return simulateContractEvents(contractId, spec.functions, rpcUrl, fetchImpl, this.options);
  }

  /**
   * Audits the WASM the verifier was handed: spec declarations first, then the
   * emissions of the simulated entry points when a transport is available.
   */
  async verifyWasm(
    contractId: string,
    wasm: Buffer,
    fetchImpl: typeof fetch = fetch,
  ): Promise<Diagnostic[]> {
    const spec = this.specOf(wasm);
    if (spec === undefined) return [];

    const diagnostics = validateEventSpecs(contractId, spec.events, this.options);
    if (this.options.specOnly === true) return diagnostics;

    const rpcUrl = this.options.rpcUrl ?? rpcUrlFor(this.options.networkPassphrase);
    if (rpcUrl === undefined) return diagnostics;

    const events = await simulateContractEvents(
      contractId,
      spec.functions,
      rpcUrl,
      fetchImpl,
      this.options,
    );
    diagnostics.push(...validateContractEvents(contractId, events, spec.events, this.options));
    return diagnostics;
  }

  /**
   * Fetches the deployed WASM behind `contractId` and audits it. Silent when
   * the contract cannot be read (RPC outage, missing entry, or a Stellar Asset
   * Contract, which has no WASM).
   */
  async verifyContract(contractId: string, fetchImpl: typeof fetch = fetch): Promise<Diagnostic[]> {
    const rpcUrl = this.options.rpcUrl ?? rpcUrlFor(this.options.networkPassphrase);
    if (rpcUrl === undefined) return [];

    const wasm = await fetchEventContractWasm(contractId, rpcUrl, fetchImpl);
    if (wasm === undefined) return [];

    return this.verifyWasm(contractId, wasm, fetchImpl);
  }
}

// ---------------------------------------------------------------------------
// Stellar.toml integration
// ---------------------------------------------------------------------------

export interface TomlEventAuditOptions extends EventVerifierOptions {
  /** Soroban RPC endpoint, overriding the one derived from the passphrase. */
  rpcUrl?: string;
}

/**
 * Audits every contract the file declares under `[[CURRENCIES]].contract` as
 * well as `WEB_AUTH_CONTRACT_ID`, and returns the schema findings.
 */
export async function auditTomlEvents(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: TomlEventAuditOptions = {},
): Promise<Diagnostic[]> {
  const passphrase =
    typeof doc.NETWORK_PASSPHRASE === 'string' ? doc.NETWORK_PASSPHRASE : undefined;
  const rpcUrl = options.rpcUrl ?? rpcUrlFor(passphrase);
  if (rpcUrl === undefined) return [];

  const targets = contractCurrenciesOf(doc);
  const webAuth = doc.WEB_AUTH_CONTRACT_ID;
  if (isString(webAuth) && webAuth.trim() !== '') {
    targets.push({
      entry: doc,
      index: 0,
      id: webAuth.trim(),
      path: 'WEB_AUTH_CONTRACT_ID',
    });
  }
  if (targets.length === 0) return [];

  const diagnostics: Diagnostic[] = [];
  for (const target of targets) {
    const verifier = new EventSchemaVerifier({
      ...options,
      rpcUrl,
      path: options.path ?? target.path,
    });
    diagnostics.push(...(await verifier.verifyContract(target.id, fetchImpl)));
  }
  return diagnostics;
}

/** Every rule id emitted by this module, for `--list-rules` consumers. */
export const eventVerifierRuleIds: readonly string[] = eventRules.map((rule) => rule.id);

/** Registered like the other network checks. */
export const eventVerifierRules: Rule[] = eventRules;

export { CORE_EVENT_CONVENTIONS, eventRules, topicInfo };
