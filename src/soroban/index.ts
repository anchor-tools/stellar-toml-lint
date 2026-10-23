/**
 * The Soroban contract audits, gathered in one place.
 *
 * Every module here is opt-in and network-bound: it reaches a Soroban RPC
 * endpoint to inspect a contract the file declares under `[[CURRENCIES]]`.
 * Each exports an async runner plus the `Rule` objects that make its ids
 * addressable through `--off`/`--warn`/`--error` and `--list-rules`.
 *
 * The modules themselves stay independent of each other — this barrel only
 * re-exports them, so a caller can reach the whole family from one path.
 */
export * from './admin-auditor.js';
export * from './auth-auditor.js';
export * from './auth-tree-simulator.js';
export * from './cbor.js';
export * from './dependency-graph.js';
export * from './errors.js';
export * from './instance-storage-auditor.js';
export * from './multi-network.js';
export * from './rpc.js';
export * from './sep45.js';
export * from './simulation.js';
export * from './storage-footprint.js';
export * from './wasm-auditor.js';
export * from './wasm.js';

/*
 * Four modules export a name another one also exports: `ENV_META_SECTION` and
 * `ContractEnvMeta` from `contractMetadata.ts` and `env-meta.ts`, `SpecEvent`
 * from `contractMetadata.ts` and `events.ts`, and `fetchContractWasm` from
 * `contractMetadata.ts` and `rpc.ts`. Those four are re-exported by name here
 * so the ambiguity stays visible instead of silently dropping a name.
 */
export {
  SPEC_SECTION,
  METADATA_UNDECODABLE_RULE,
  FUNCTION_UNDECLARED_RULE,
  FUNCTION_UNDOCUMENTED_RULE,
  EVENT_UNDECLARED_RULE,
  INTERFACE_VERSION_DRIFT_RULE,
  renderSpecType,
  decodeSpecEntries,
  decodeEnvMetaEntry,
  parseContractMetadata,
  declaredContractsOf,
  checkContractMetadata,
  contractMetadataRules,
} from './contractMetadata.js';
export type {
  SpecParameter,
  SpecFunction,
  SpecErrorCase,
  SpecErrorEnum,
  SpecStruct,
  SpecUnionCase,
  SpecUnion,
  SpecEnumCase,
  SpecEnum,
  ContractSpec,
  SpecDecodeError,
  ContractFetchError,
  ContractMetadataParser,
  DeclaredContract,
  ContractMetadataCheckOptions,
} from './contractMetadata.js';

export {
  ENV_META_SECTION,
  MISSING_ENV_META_RULE,
  DEPRECATED_PROTOCOL_RULE,
  DEFAULT_PROTOCOL_VERSION,
  extractEnvMeta,
  verifyEnvMeta,
  auditContractEnvMeta,
  auditTomlContractEnvMeta,
  envMetaRules,
  envMetaRuleIds,
} from './env-meta.js';
export type { EnvMetaOptions } from './env-meta.js';

export {
  EVENT_TOPIC_MISMATCH_RULE,
  EVENT_DATA_TYPE_INVALID_RULE,
  SEP41_EVENT_SCHEMA,
  extractSpecEvents,
  verifySep41EventSpecs,
  verifyLiveEvents,
  fetchRecentEvents,
  auditContractEvents,
  auditTomlContractEvents,
  eventRules,
  eventRuleIds,
} from './events.js';
export type { EventsOptions, SpecEvent, RawEvent } from './events.js';
