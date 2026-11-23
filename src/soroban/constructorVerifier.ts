/**
 * Protocol 23 constructor and initialization invariant verifier.
 *
 * Deploying a Soroban contract is two separate steps unless the contract ships
 * a constructor: the WASM is uploaded and instantiated, then someone invokes an
 * initializer to set the admin, decimals, or governance state. Between those
 * steps the contract exists on the ledger with no owner, so anyone watching the
 * network can call `initialize` first and claim it. Protocol 23 removes that
 * window: a `__constructor` runs atomically inside the deployment operation, so
 * a contract that exports one can never be observed uninitialized.
 *
 * This verifier reads the deployed WASM's `contractspecv0` section without
 * executing it, learns whether the contract is constructor-protected or relies
 * on a custom initializer (`initialize`/`init`), and — for the latter — reads
 * the contract's instance storage and the persistent initialization-marker keys
 * over Soroban RPC. No initialization state means an uninitialized contract, and
 * state that is not guarded by a single-use boolean flag means a re-invocation
 * can overwrite whatever the first caller stored.
 *
 * What cannot be verified: a constructor's arguments are runtime values that are
 * not retained on the ledger, so the audit compares the declared *signature*
 * against expectations derived from `stellar.toml` (for example
 * `CURRENCIES[].display_decimals`) and any expectations the caller supplies for
 * metadata SEP-1 has no field for, such as an admin address or governance
 * quorum. A mismatch is a deploy-time mistake the file can expose; it is never
 * a guess about values.
 *
 * Like the other network-bound checks this audit never fails the run on an RPC
 * outage: an unreachable endpoint, an archived entry, a Stellar Asset Contract,
 * or a module without a readable spec stays silent. Only a spec that parses and
 * declares an initialization entry point can produce a finding.
 */
import { cereal, xdr } from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { specUrl } from '../spec.js';
import { isString } from '../predicates.js';
import { rpcUrlFor } from '../rules/display-decimals-audit.js';
import { contractCodeKey, contractDataInstanceKey, wasmHashOf } from './ledgerKeys.js';
import { contractTargetsOf, persistentStorageKey, queryLedgerEntries } from './ttlAuditor.js';

export const CONSTRUCTOR_UNINITIALIZED_RULE = 'soroban/constructor-uninitialized';
export const CONSTRUCTOR_NO_REPLAY_PROTECTION_RULE = 'soroban/constructor-no-replay-protection';
export const CONSTRUCTOR_ARGUMENT_MISMATCH_RULE = 'soroban/constructor-argument-mismatch';

/** The Protocol 23 constructor entry point. */
export const CONSTRUCTOR_FUNCTION = '__constructor';

/** Custom initializers an anchor typically invokes after deployment. */
export const INITIALIZER_FUNCTIONS = ['initialize', 'init'] as const;

/**
 * Instance or persistent storage keys that contracts use to record that
 * initialization has already happened. Matched case-insensitively.
 */
export const INITIALIZATION_MARKER_NAMES = [
  'initialized',
  'is_initialized',
  'initialised',
  'is_initialised',
  'init',
] as const;

/** The WASM custom section Soroban stores a contract's spec entries in. */
const CONTRACT_SPEC_SECTION = 'contractspecv0';

/** Coarse parameter type used to compare a signature with TOML metadata. */
export type ConstructorArgumentType =
  'integer' | 'address' | 'boolean' | 'string' | 'symbol' | 'bytes' | 'any';

/** One declared function parameter, read from the `contractspecv0` section. */
export interface ContractFunctionParameter {
  name: string;
  type: ConstructorArgumentType;
  /** The raw `ScSpecTypeDef` variant, e.g. `scSpecTypeU32`. */
  specType: string;
}

/** One declared contract function, read from the `contractspecv0` section. */
export interface ContractFunctionSignature {
  name: string;
  inputs: ContractFunctionParameter[];
  /** Raw `ScSpecTypeDef` variants of the declared outputs. */
  outputs: string[];
}

/** How a contract protects its post-deployment initialization. */
export type InitializationStrategy = 'constructor' | 'initializer';

/** The initialization entry point a contract exports. */
export interface InitializationSignature {
  strategy: InitializationStrategy;
  functionName: string;
  signature: ContractFunctionSignature;
}

/** Initialization state found in contract storage. */
export interface InitializationMarker {
  name: string;
  source: 'instance' | 'persistent';
  /** Raw `ScVal` variant of the stored value, e.g. `scvBool`. */
  valueType: string;
  /** Set when the stored value is a boolean initialization flag. */
  booleanValue?: boolean;
}

/** The initialization-related state carried by a contract instance entry. */
export interface InitializationState {
  /** Number of keys in the instance storage map. */
  storageEntries: number;
  /** Names of instance storage keys that are symbols or strings. */
  storageKeys: string[];
  /** Initialization-named keys among the instance storage keys. */
  markers: InitializationMarker[];
}

/**
 * A constructor or initializer argument the file's metadata requires.
 *
 * SEP-1 declares no admin or governance-quorum field, so expectations for
 * those are supplied by the caller through {@link ConstructorVerifierOptions};
 * decimal configuration is derived from `CURRENCIES[].display_decimals`.
 */
export interface ConstructorArgumentExpectation {
  /** Accepted parameter names, compared case-insensitively. */
  names: readonly string[];
  /** Required parameter type. Omit to accept any type. */
  type?: ConstructorArgumentType;
  /** Dotted path in `stellar.toml` that declared the expectation. */
  path?: string;
}

export interface ConstructorVerifierOptions {
  rules?: RuleOverrides;
  rpcUrl?: string;
  /** Extra argument expectations beyond the ones derived from the document. */
  constructorArgs?: readonly ConstructorArgumentExpectation[];
  /** Dotted `stellar.toml` path of the audited contract. */
  path?: string;
}

// ---------------------------------------------------------------------------
// WASM spec parsing
// ---------------------------------------------------------------------------

/**
 * Reads an unsigned LEB128 integer, the encoding WASM uses for section ids,
 * sizes, and name lengths.
 */
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

/**
 * The payload of the named WASM custom section, or `undefined` when the module
 * is malformed or the section is absent.
 *
 * Kept local rather than imported from the aggregate `soroban.ts` registry so
 * this validator can be loaded without pulling the registry (and its other
 * validators) in first.
 */
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

/** Groups a spec type into the coarse category metadata can be compared with. */
export function constructorArgumentTypeOf(typeDef: xdr.ScSpecTypeDef): ConstructorArgumentType {
  switch (typeDef.switch().name) {
    case 'scSpecTypeU32':
    case 'scSpecTypeI32':
    case 'scSpecTypeU64':
    case 'scSpecTypeI64':
    case 'scSpecTypeU128':
    case 'scSpecTypeI128':
    case 'scSpecTypeU256':
    case 'scSpecTypeI256':
    case 'scSpecTypeTimepoint':
    case 'scSpecTypeDuration':
      return 'integer';
    case 'scSpecTypeAddress':
    case 'scSpecTypeMuxedAddress':
      return 'address';
    case 'scSpecTypeBool':
      return 'boolean';
    case 'scSpecTypeString':
      return 'string';
    case 'scSpecTypeSymbol':
      return 'symbol';
    case 'scSpecTypeBytes':
    case 'scSpecTypeBytesN':
      return 'bytes';
    default:
      return 'any';
  }
}

/**
 * The function signatures a contract's spec declares, or `undefined` when the
 * module has no readable spec section.
 *
 * This is the export-table view of the contract: it reads the same
 * `contractspecv0` custom section the Soroban host uses to expose functions,
 * including each parameter's name and type. Nothing is executed.
 */
export function parseContractSpecFunctions(wasm: Buffer): ContractFunctionSignature[] | undefined {
  const section = wasmCustomSection(wasm, CONTRACT_SPEC_SECTION);
  if (section === undefined) return undefined;

  try {
    const reader = new cereal.XdrReader(section);
    const functions: ContractFunctionSignature[] = [];
    while (!reader.eof) {
      const entry = xdr.ScSpecEntry.read(reader as unknown as Buffer);
      if (entry.switch().name !== 'scSpecEntryFunctionV0') continue;
      const fn = entry.functionV0();
      functions.push({
        name: fn.name().toString(),
        inputs: fn.inputs().map((input) => ({
          name: input.name().toString(),
          type: constructorArgumentTypeOf(input.type()),
          specType: input.type().switch().name,
        })),
        outputs: fn.outputs().map((output) => output.switch().name),
      });
    }
    return functions;
  } catch {
    return undefined;
  }
}

/**
 * Picks the entry point that initializes the contract: a Protocol 23
 * `__constructor` when present, otherwise the first exported custom
 * initializer. `undefined` when the contract exports neither, in which case
 * there is no initialization window to verify.
 */
export function findInitializationSignature(
  functions: readonly ContractFunctionSignature[],
): InitializationSignature | undefined {
  const constructor = functions.find((fn) => fn.name === CONSTRUCTOR_FUNCTION);
  if (constructor !== undefined) {
    return {
      strategy: 'constructor',
      functionName: constructor.name,
      signature: constructor,
    };
  }

  const initializer = functions.find((fn) =>
    (INITIALIZER_FUNCTIONS as readonly string[]).includes(fn.name),
  );
  if (initializer !== undefined) {
    return {
      strategy: 'initializer',
      functionName: initializer.name,
      signature: initializer,
    };
  }

  return undefined;
}

// ---------------------------------------------------------------------------
// Contract storage inspection
// ---------------------------------------------------------------------------

/** The name of a storage key when it is a symbol or string. */
function storageKeyName(key: xdr.ScVal): string | undefined {
  switch (key.switch().name) {
    case 'scvSymbol':
      return key.sym().toString();
    case 'scvString':
      return key.str().toString();
    default:
      return undefined;
  }
}

function isInitializationMarkerName(name: string): boolean {
  return (INITIALIZATION_MARKER_NAMES as readonly string[]).includes(name.toLowerCase());
}

/**
 * Reads the initialization-related state of a contract instance entry: how
 * many instance storage keys exist and which of them are initialization
 * markers. Instance storage is embedded in the instance entry itself, so this
 * parses the entry XDR rather than issuing another RPC call.
 */
export function initializationStateOf(entryXdr: unknown): InitializationState {
  const empty: InitializationState = { storageEntries: 0, storageKeys: [], markers: [] };
  if (!isString(entryXdr)) return empty;

  try {
    const data = xdr.LedgerEntryData.fromXDR(entryXdr, 'base64');
    const val = data.contractData().val();
    if (val.switch().name !== 'scvContractInstance') return empty;

    const instance = val.instance();
    if (instance === null) return empty;

    const storage = instance.storage() ?? [];
    const storageKeys: string[] = [];
    const markers: InitializationMarker[] = [];

    for (const item of storage) {
      const name = storageKeyName(item.key());
      if (name === undefined) continue;
      storageKeys.push(name);

      if (!isInitializationMarkerName(name)) continue;
      const valueType = item.val().switch().name;
      const booleanValue = valueType === 'scvBool' ? item.val().b() : undefined;
      markers.push({
        name,
        source: 'instance',
        valueType,
        ...(booleanValue !== undefined ? { booleanValue } : {}),
      });
    }

    return { storageEntries: storage.length, storageKeys, markers };
  } catch {
    return empty;
  }
}

/**
 * The persistent ledger keys where a contract may keep an initialization
 * marker. Both symbol and string encodings are produced because contracts key
 * their storage either way and the RPC matches keys byte-for-byte.
 */
export function initializationMarkerKeys(contractId: string): { key: string; name: string }[] {
  const keys: { key: string; name: string }[] = [];
  for (const name of INITIALIZATION_MARKER_NAMES) {
    keys.push({
      key: persistentStorageKey(contractId, xdr.ScVal.scvSymbol(name)),
      name,
    });
    keys.push({
      key: persistentStorageKey(contractId, xdr.ScVal.scvString(name)),
      name,
    });
  }
  return keys;
}

/** Reads an initialization marker out of a persistent contract-data entry. */
export function persistentInitializationMarker(
  name: string,
  entryXdr: unknown,
): InitializationMarker | undefined {
  if (!isString(entryXdr)) return undefined;
  try {
    const data = xdr.LedgerEntryData.fromXDR(entryXdr, 'base64');
    if (data.switch().name !== 'contractData') return undefined;
    const val = data.contractData().val();
    const valueType = val.switch().name;
    const booleanValue = valueType === 'scvBool' ? val.b() : undefined;
    return {
      name,
      source: 'persistent',
      valueType,
      ...(booleanValue !== undefined ? { booleanValue } : {}),
    };
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// TOML metadata
// ---------------------------------------------------------------------------

function currenciesOf(doc: Record<string, unknown>): Record<string, unknown>[] {
  const currencies = doc.CURRENCIES;
  if (!Array.isArray(currencies)) return [];
  return currencies.filter(
    (entry): entry is Record<string, unknown> =>
      typeof entry === 'object' && entry !== null && !Array.isArray(entry),
  );
}

/**
 * The constructor/initializer arguments `stellar.toml` metadata implies.
 *
 * A `[[CURRENCIES]]` entry that declares `display_decimals` describes a decimal
 * configuration the contract's initializer must accept, so a matching integer
 * parameter is expected. When `contractId` is given only the entries naming
 * that contract contribute. Admin and governance-quorum expectations have no
 * SEP-1 field and are supplied through {@link ConstructorVerifierOptions}.
 */
export function expectedConstructorArgs(
  doc: Record<string, unknown>,
  contractId?: string,
): ConstructorArgumentExpectation[] {
  const expectations: ConstructorArgumentExpectation[] = [];
  const seen = new Set<string>();

  currenciesOf(doc).forEach((currency, index) => {
    if (contractId !== undefined && currency.contract !== contractId) return;
    if (typeof currency.display_decimals !== 'number') return;
    if (!Number.isInteger(currency.display_decimals)) return;

    const key = 'decimals:integer';
    if (seen.has(key)) return;
    seen.add(key);
    expectations.push({
      names: ['decimals', 'display_decimals', 'decimal_places'],
      type: 'integer',
      path: `CURRENCIES[${index}].display_decimals`,
    });
  });

  return expectations;
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules?: RuleOverrides,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

function argumentMismatchDiagnostics(
  contractId: string,
  signature: ContractFunctionSignature,
  expectations: readonly ConstructorArgumentExpectation[],
  options: ConstructorVerifierOptions,
): Diagnostic[] {
  const severity = severityFor(CONSTRUCTOR_ARGUMENT_MISMATCH_RULE, 'error', options.rules);
  if (severity === undefined) return [];

  const diagnostics: Diagnostic[] = [];
  for (const expectation of expectations) {
    const parameter = signature.inputs.find((input) =>
      expectation.names.some((name) => name.toLowerCase() === input.name.toLowerCase()),
    );

    if (parameter === undefined) {
      diagnostics.push({
        rule: CONSTRUCTOR_ARGUMENT_MISMATCH_RULE,
        severity,
        category: 'network',
        message: `Contract ${contractId} ${signature.name} is missing the "${expectation.names[0]}" parameter required by the metadata${expectation.path === undefined ? '' : ` at ${expectation.path}`}`,
        path: expectation.path ?? options.path ?? 'CURRENCIES.contract',
        helpUri: specUrl('general-information'),
        suggestion: `Add the ${expectation.type ?? 'declared'} parameter to ${signature.name} or remove the metadata that requires it.`,
      });
      continue;
    }

    if (
      expectation.type !== undefined &&
      expectation.type !== 'any' &&
      parameter.type !== expectation.type
    ) {
      diagnostics.push({
        rule: CONSTRUCTOR_ARGUMENT_MISMATCH_RULE,
        severity,
        category: 'network',
        message: `Contract ${contractId} ${signature.name} parameter "${parameter.name}" is ${parameter.specType} (${parameter.type}) but the metadata requires a ${expectation.type}${expectation.path === undefined ? '' : ` at ${expectation.path}`}`,
        path: expectation.path ?? options.path ?? 'CURRENCIES.contract',
        helpUri: specUrl('general-information'),
        suggestion: `Change "${parameter.name}" to a ${expectation.type} parameter, or update the metadata that declares its type.`,
      });
    }
  }
  return diagnostics;
}

function uninitializedDiagnostic(
  contractId: string,
  init: InitializationSignature,
  options: ConstructorVerifierOptions,
): Diagnostic[] {
  const severity = severityFor(CONSTRUCTOR_UNINITIALIZED_RULE, 'error', options.rules);
  if (severity === undefined) return [];

  return [
    {
      rule: CONSTRUCTOR_UNINITIALIZED_RULE,
      severity,
      category: 'network',
      message: `Contract ${contractId} exports ${init.functionName} but holds no initialization state, so it can be front-run and claimed by the first caller`,
      path: options.path ?? 'CURRENCIES.contract',
      helpUri: specUrl('general-information'),
      suggestion: `Deploy with a Protocol 23 ${CONSTRUCTOR_FUNCTION} so initialization runs atomically, or invoke ${init.functionName} in the same transaction as deployment and gate it on a single-use initialized flag.`,
    },
  ];
}

function missingReplayProtectionDiagnostic(
  contractId: string,
  init: InitializationSignature,
  storageKeys: readonly string[],
  options: ConstructorVerifierOptions,
): Diagnostic[] {
  const severity = severityFor(CONSTRUCTOR_NO_REPLAY_PROTECTION_RULE, 'warning', options.rules);
  if (severity === undefined) return [];

  const keys = storageKeys.join(', ');
  return [
    {
      rule: CONSTRUCTOR_NO_REPLAY_PROTECTION_RULE,
      severity,
      category: 'network',
      message: `Contract ${contractId} has initialization state (${keys}) but no boolean initialization flag, so ${init.functionName} can be invoked again and overwrite it`,
      path: options.path ?? 'CURRENCIES.contract',
      helpUri: specUrl('general-information'),
      suggestion: `Store an initialized: bool in instance storage and reject ${init.functionName} when it is already true, before accepting the initialization arguments.`,
    },
  ];
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

/** The WASM bytes a contract-code entry carries, or `undefined` otherwise. */
function wasmBytesOf(entryXdr: unknown): Buffer | undefined {
  if (!isString(entryXdr)) return undefined;
  try {
    const data = xdr.LedgerEntryData.fromXDR(entryXdr, 'base64');
    if (data.switch().name !== 'contractCode') return undefined;
    return Buffer.from(data.contractCode().code());
  } catch {
    return undefined;
  }
}

function dedupeExpectations(
  expectations: readonly ConstructorArgumentExpectation[],
): ConstructorArgumentExpectation[] {
  const seen = new Set<string>();
  const unique: ConstructorArgumentExpectation[] = [];
  for (const expectation of expectations) {
    const key = `${expectation.names.join('|')}:${expectation.type ?? 'any'}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(expectation);
  }
  return unique;
}

/**
 * Verifies one contract's initialization invariants against the deployed WASM
 * and its on-chain storage.
 *
 * The instance entry is read first; it yields both the WASM hash and the
 * instance storage map. The code entry then yields the spec section, which
 * decides whether the contract is constructor-protected (atomic, nothing left
 * to verify) or relies on a custom initializer. Only in the second case are the
 * persistent marker keys queried and the initialization state classified.
 */
export async function auditConstructorInvariants(
  contractId: string,
  doc: Record<string, unknown>,
  rpcUrl: string,
  fetchImpl: typeof fetch = fetch,
  options: ConstructorVerifierOptions = {},
): Promise<Diagnostic[]> {
  const diagnostics: Diagnostic[] = [];

  const instanceKey = contractDataInstanceKey(contractId);
  const instance = await queryLedgerEntries(rpcUrl, [instanceKey], fetchImpl);
  const instanceEntry = instance?.entries.get(instanceKey);
  if (instanceEntry?.xdr === undefined) return diagnostics;

  const wasmHash = wasmHashOf(instanceEntry.xdr);
  if (wasmHash === undefined) return diagnostics;

  const codeKey = contractCodeKey(wasmHash);
  const code = await queryLedgerEntries(rpcUrl, [codeKey], fetchImpl);
  const codeEntry = code?.entries.get(codeKey);
  const wasm = codeEntry?.xdr === undefined ? undefined : wasmBytesOf(codeEntry.xdr);
  if (wasm === undefined) return diagnostics;

  const functions = parseContractSpecFunctions(wasm);
  if (functions === undefined || functions.length === 0) return diagnostics;

  const init = findInitializationSignature(functions);
  if (init === undefined) return diagnostics;

  const expectations = dedupeExpectations([
    ...expectedConstructorArgs(doc, contractId),
    ...(options.constructorArgs ?? []),
  ]);
  diagnostics.push(
    ...argumentMismatchDiagnostics(contractId, init.signature, expectations, options),
  );

  // A Protocol 23 constructor runs inside the deployment operation, so there is
  // no window in which the contract is live but uninitialized.
  if (init.strategy === 'constructor') return diagnostics;

  const state = initializationStateOf(instanceEntry.xdr);
  const markerKeys = initializationMarkerKeys(contractId);
  const markerResponse = await queryLedgerEntries(
    rpcUrl,
    markerKeys.map((candidate) => candidate.key),
    fetchImpl,
  );

  const persistentMarkers: InitializationMarker[] = [];
  if (markerResponse !== undefined) {
    for (const candidate of markerKeys) {
      const raw = markerResponse.entries.get(candidate.key);
      if (raw === undefined) continue;
      const marker = persistentInitializationMarker(candidate.name, raw.xdr);
      if (marker !== undefined) persistentMarkers.push(marker);
    }
  }

  const markers = [...state.markers, ...persistentMarkers];
  const replayFlag = markers.find((marker) => marker.booleanValue !== undefined);
  const hasState = state.storageEntries > 0 || persistentMarkers.length > 0;

  if (replayFlag !== undefined) {
    if (replayFlag.booleanValue === false) {
      diagnostics.push(...uninitializedDiagnostic(contractId, init, options));
    }
    return diagnostics;
  }

  if (!hasState) {
    diagnostics.push(...uninitializedDiagnostic(contractId, init, options));
    return diagnostics;
  }

  const stateKeys = [...new Set([...state.storageKeys, ...markers.map((marker) => marker.name)])];
  diagnostics.push(...missingReplayProtectionDiagnostic(contractId, init, stateKeys, options));
  return diagnostics;
}

/**
 * Audits every contract a document declares, deriving the RPC endpoint from
 * `NETWORK_PASSPHRASE` unless one is supplied. Silent when no network can be
 * derived or the document names no contract.
 */
export async function auditTomlConstructorInvariants(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: ConstructorVerifierOptions = {},
): Promise<Diagnostic[]> {
  const rpcUrl =
    options.rpcUrl ??
    rpcUrlFor(typeof doc.NETWORK_PASSPHRASE === 'string' ? doc.NETWORK_PASSPHRASE : undefined);
  if (rpcUrl === undefined) return [];

  const targets = contractTargetsOf(doc);
  if (targets.length === 0) return [];

  const diagnostics: Diagnostic[] = [];
  for (const target of targets) {
    diagnostics.push(
      ...(await auditConstructorInvariants(target.id, doc, rpcUrl, fetchImpl, {
        ...options,
        path: target.path,
      })),
    );
  }
  return diagnostics;
}

/**
 * The verifier as an injectable object, mirroring `SorobanTtlAuditor`, so a
 * monitor or CI job can hold one configuration and audit many documents.
 */
export class ConstructorInvariantVerifier {
  private readonly options: ConstructorVerifierOptions;

  constructor(options: ConstructorVerifierOptions = {}) {
    this.options = options;
  }

  /** Verifies one contract. */
  async verify(
    contractId: string,
    doc: Record<string, unknown>,
    rpcUrl: string,
    fetchImpl: typeof fetch = fetch,
  ): Promise<Diagnostic[]> {
    return auditConstructorInvariants(contractId, doc, rpcUrl, fetchImpl, this.options);
  }

  /** Verifies every contract a document declares. */
  async verifyDocument(
    doc: Record<string, unknown>,
    fetchImpl: typeof fetch = fetch,
  ): Promise<Diagnostic[]> {
    return auditTomlConstructorInvariants(doc, fetchImpl, this.options);
  }
}

export const constructorVerifierRules: Rule[] = [
  {
    id: CONSTRUCTOR_UNINITIALIZED_RULE,
    category: 'network',
    severity: 'error',
    description:
      'A Soroban contract with a custom initializer has no on-chain initialization state and can be front-run',
    run() {},
  },
  {
    id: CONSTRUCTOR_NO_REPLAY_PROTECTION_RULE,
    category: 'network',
    severity: 'warning',
    description:
      'A Soroban initializer lacks a single-use boolean flag, so it can be invoked again after initialization',
    run() {},
  },
  {
    id: CONSTRUCTOR_ARGUMENT_MISMATCH_RULE,
    category: 'network',
    severity: 'error',
    description:
      'A Soroban constructor or initializer signature does not match the metadata declared in stellar.toml',
    run() {},
  },
];
