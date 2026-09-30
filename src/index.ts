/**
 * Public API for stellar-toml-lint.
 *
 * @example
 * ```ts
 * import { lint, formatText } from 'stellar-toml-lint';
 *
 * const result = lint(await readFile('stellar.toml', 'utf8'));
 * if (!result.ok) console.error(formatText(result));
 * ```
 */
export { lint, lintDomain } from './lint.js';
export { formatToml } from './format-file.js';
export type { FormatResult } from './format-file.js';
export { lspMain } from './lsp.js';
export {
  parseCst,
  parseOrThrow,
  printCst,
  serialize,
  firstError,
  CstParseError,
} from './cst/parser.js';
export type {
  CstArrayValue,
  CstBooleanValue,
  CstComment,
  CstDateTimeValue,
  CstDocument,
  CstEntry,
  CstError,
  CstInlineTableValue,
  CstKey,
  CstKeySegment,
  CstKeyValueEntry,
  CstNumberValue,
  CstStringValue,
  CstTableEntry,
  CstTokenSpan,
  CstTrivia,
  CstValue,
} from './cst/parser.js';
export {
  evaluateDocument,
  toValue,
  walk,
  collectComments,
  keyValueEntries,
  tableEntries,
  nodeAtOffset,
} from './cst/visitor.js';
export type { CstNode, CstVisitor, EvaluationResult } from './cst/visitor.js';
export { Lexer, tokenize, SourcePositions, isTrivia } from './cst/lexer.js';
export type {
  LexContext,
  SourcePosition,
  StringStyle,
  Token,
  TokenKind,
  TriviaKind,
} from './cst/lexer.js';
export { allRules, ruleIds } from './rules/index.js';
export { PRESETS, PRESET_NAMES, resolvePreset } from './presets.js';
export type { Preset, PresetName } from './presets.js';
export {
  formatText,
  formatCount,
  formatJson,
  formatSarif,
  formatGithub,
  formatJunit,
  formatHtml,
  formatCheckstyle,
  formatMarkdown,
  formatPrComment,
} from './reporters.js';
export type { TextReporterOptions } from './reporters.js';
export { probeTls } from './tls.js';
export type { TlsProbe } from './tls.js';
export {
  checkPeerPortReachability,
  probeTcpPort,
  validatorHostsOf,
  peerPortRule,
  PEER_PORT_UNREACHABLE_RULE,
  DEFAULT_PROBE_TIMEOUT_MS,
} from './validators/net-probe.js';
export type { TcpPortProbe } from './validators/net-probe.js';
export { createFixtureFetch, fixtureCandidates, MissingFixtureError } from './mock-fixtures.js';
export type { FixtureFile } from './mock-fixtures.js';
export {
  auditCryptoFraming,
  auditCryptoSession,
  auditOverlayCrypto,
  auditOverlayCryptoSession,
  computeOverlayMac,
  CryptoAuditor,
  deriveHkdf,
  deriveHkdfKey,
  cryptoAuditorRules,
  cryptoRuleIds,
  overlayCryptoRuleIds,
  INVALID_CRYPTO_FRAMING_RULE,
  MAC_AUTHENTICATION_FAILURE_RULE,
  OVERLAY_INVALID_CRYPTO_FRAMING,
  OVERLAY_MAC_AUTHENTICATION_FAILURE,
} from './overlay/crypto-auditor.js';
export type {
  BinaryValue,
  CryptoAuditOptions,
  CryptoSessionInput,
  OverlayFrame,
} from './overlay/crypto-auditor.js';
export {
  checkOverlayCrawler,
  checkOverlayPeerDiscovery,
  checkOverlayPeers,
  checkPeerDiscovery,
  crawlOverlayPeers,
  crawlPeers,
  crawlValidatorPeers,
  decodePeersMessage,
  encodeGetPeersFrame,
  encodeGetPeersMessage,
  encodeGetPeersXdr,
  encodePeersMessage,
  frameOverlayMessage,
  parsePeersResponse,
  OVERLAY_DEFAULT_PORT,
  OVERLAY_MAX_FRAME_BYTES,
  OVERLAY_MAX_PEERS,
  OVERLAY_MESSAGE_GET_PEERS,
  OVERLAY_MESSAGE_PEERS,
  overlayCrawlerRules,
  overlayCrawlerRuleIds,
  crawlerRules,
  ISOLATED_NODE_ZERO_PEERS_RULE,
  LOW_PEER_COUNT_RULE,
} from './overlay/crawler.js';
export type {
  CrawlOptions,
  OverlayConnector,
  OverlayConnectorOptions,
  PeerAddress,
  PeerCrawlCheckOptions,
  PeerCrawlResult,
} from './overlay/crawler.js';
export {
  checkOverlayHandshake,
  decodeStellarMessage,
  decodeAuthenticatedMessage,
  encodeAuth,
  encodeAuthCert,
  encodeAuthenticatedMessage,
  encodeOverlayFrame,
  overlayFrameLength,
  overlayMac,
  verifyOverlayMac,
  deriveSharedMacKey,
  deriveMacKeys,
  macSigningInput,
  encodeHello,
  failureFindings,
  generateEphemeralIdentity,
  helloFindings,
  authCert,
  authCertDigest,
  authCertPreimage,
  signedAuthCert,
  verifyAuthCert,
  networkIdForPassphrase,
  sharedSecret,
  validatorEndpoints,
  overlayHandshakeRules,
  overlayHandshakeRuleIds,
  OVERLAY_HANDSHAKE_TIMEOUT_RULE,
  OVERLAY_NETWORK_MISMATCH_RULE,
  OVERLAY_PUBLIC_KEY_MISMATCH_RULE,
  OVERLAY_PROTOCOL_VERSION_OUTDATED_RULE,
  OVERLAY_MESSAGE_AUTH,
  OVERLAY_MESSAGE_ERROR,
  OVERLAY_MESSAGE_HELLO,
  OVERLAY_PROTOCOL_VERSION,
  OVERLAY_HANDSHAKE_TIMEOUT_MS,
  OVERLAY_AUTH_FLOW_CONTROL_FLAGS,
  OVERLAY_FRAME_CONTINUATION_BIT,
  OVERLAY_MAC_BYTES,
  ENVELOPE_TYPE_AUTH,
} from './overlay/handshake.js';
export type {
  AnnouncedHello,
  EphemeralIdentity,
  HandshakeFailure,
  HandshakeOptions,
  HandshakeOutcome,
  OverlayEnvelope,
  OverlayPeerRole,
  OverlayTransport,
  PeerHello,
  ValidatorEndpoint,
} from './overlay/handshake.js';
export {
  checkHistoryPublish,
  checkHistoryPublishState,
  checkHistoryPublishValidator,
  validateHistoryArchive,
  historyPublishRules,
  historyPublishRuleIds,
  validateHistoryPublish,
  HISTORY_BROKEN_CHECKPOINT_CHAIN,
  HISTORY_MISSING_CATEGORY_ARCHIVE,
  BROKEN_CHECKPOINT_CHAIN_RULE,
  MISSING_CATEGORY_ARCHIVE_RULE,
} from './history/publish-validator.js';
export type {
  HistoryArchiveCategory,
  HistoryCheckpoint,
  HistoryPublishOptions,
} from './history/publish-validator.js';
export {
  checkArchiveDiff,
  archiveDiffRules,
  archiveDiffRuleIds,
  ARCHIVE_LAGGING_RULE,
  ARCHIVE_HASH_MISMATCH_RULE,
  ARCHIVE_LAG_WARNING_LEDGERS,
  ARCHIVE_LAG_ERROR_LEDGERS,
} from './history/archive-diff.js';
export type { ArchiveDiffOptions } from './history/archive-diff.js';
export {
  checkBucketIntegrity,
  checkBucketAudit,
  checkBucketHashes,
  verifyBuckets,
  bucketReferences,
  bucketHashFromName,
  bucketPathFor,
  isBucketEntryStream,
  sampleBuckets,
  auditBucketFile,
  bucketAuditorRules,
  bucketAuditorRuleIds,
  BUCKET_DOWNLOAD_FAILED_RULE,
  BUCKET_HASH_MISMATCH_RULE,
  BUCKET_XDR_CORRUPTED_RULE,
  DEFAULT_BUCKET_SAMPLE_COUNT,
  DEFAULT_MAX_BUCKET_BYTES,
} from './history/bucket-auditor.js';
export type { BucketAuditorOptions, BucketReference } from './history/bucket-auditor.js';
export {
  checkQuorumIntersection,
  quorumSolverRules,
  quorumSolverRuleIds,
  QUORUM_INTERSECTION_FAILURE_RULE,
  FRAGILE_QUORUM_THRESHOLD_RULE,
  minimalQuorums,
  minimalBlockingSets,
  normalizeQuorumSet,
  parseCoreCfgQuorumSet,
} from './validators/quorum-solver.js';
export type { QuorumSet, QuorumSolverOptions, RawQuorumSet } from './validators/quorum-solver.js';
export {
  checkDnsIntegrity,
  checkDnsIntegrityForDomain,
  checkDnssecIntegrity,
  DEFAULT_DNS_RESOLVERS,
  dnsIntegrityRules,
  dnsIntegrityRuleIds,
  dnsRuleIds,
  resolveDnsIntegrity,
  SECURITY_DNS_RESOLVER_DIVERGENCE,
  SECURITY_DNSSEC_NOT_ENABLED,
  DNS_RESOLVER_DIVERGENCE_RULE,
  DNSSEC_NOT_ENABLED_RULE,
} from './security/dns-integrity.js';
export type {
  DnsIntegrityOptions,
  DnsResolver,
  DnsResolverResult,
} from './security/dns-integrity.js';
export {
  parseSep7Uri,
  validateSep7Uri,
  verifySep7Signature,
  signSep7Uri,
  checkSep7Uris,
  sep7Rules,
  sep7RuleIds,
  INVALID_URI_SCHEME_RULE,
  INVALID_SIGNATURE_RULE,
  UNSUPPORTED_REPLACEMENT_FIELD_RULE,
} from './protocols/sep7.js';
export type { ParsedSep7Uri, Sep7Options } from './protocols/sep7.js';

export {
  checkTokenBinding,
  acquireSep10Token,
  parseJwtPayload,
  JWT_REJECTED_RULE,
  JWT_DOMAIN_MISMATCH_RULE,
} from './security/token-binding.js';
export type { TokenBindingOptions } from './security/token-binding.js';

export {
  verifySep6Integration,
  sep6IntegrationRules,
  sep6IntegrationRuleIds,
  DEPOSIT_PARAMETER_MISMATCH_RULE,
  FEE_CALCULATION_MISMATCH_RULE,
  INVALID_TRANSACTION_STATUS_RULE,
} from './protocols/sep6.js';
export type { Sep6IntegrationOptions } from './protocols/sep6.js';

export {
  verifySep31,
  sep31Rules,
  sep31RuleIds,
  INFO_SCHEMA_INVALID_RULE,
  ASSET_UNSUPPORTED_RULE,
  MISSING_KYC_REQUIREMENTS_RULE,
} from './protocols/sep31.js';
export type { Sep31Options } from './protocols/sep31.js';

export {
  verifySep8,
  buildSyntheticSep8Transaction,
  isValidTransactionXdr,
  sep8Rules,
  sep8RuleIds,
  APPROVAL_SERVER_UNRESPONSIVE_RULE,
  INVALID_RESPONSE_STATUS_RULE,
  INVALID_REVISED_TX_XDR_RULE,
} from './protocols/sep8.js';
export type { Sep8Options } from './protocols/sep8.js';

export {
  verifySep38,
  sep38QuoteRules,
  sep38QuoteRuleIds,
  INFO_SCHEMA_INVALID_RULE as SEP38_INFO_SCHEMA_INVALID_RULE,
  PRICES_MISSING_DECLARED_ASSET_RULE,
  ABNORMAL_EXCHANGE_RATE_SPREAD_RULE,
  INVALID_QUOTE_EXPIRATION_RULE,
  MAX_QUOTE_SPREAD_PERCENT,
} from './protocols/sep38.js';
export type { Sep38QuoteOptions } from './protocols/sep38.js';

export {
  auditContractWasm,
  auditTomlContractWasm,
  verifySep41Wasm,
  decompressWasm,
  extractContractSpecEntries,
  getWasmCustomSection,
  wasmAuditorRules,
  wasmAuditorRuleIds,
  WASM_NOT_FOUND_RULE,
  MISSING_CONTRACT_SPEC_RULE,
  MISSING_SEP41_FUNCTION_RULE,
  INVALID_SEP41_SIGNATURE_RULE,
  SEP41_MANDATORY_FUNCTIONS,
} from './soroban/wasm-auditor.js';
export type { WasmAuditorOptions } from './soroban/wasm-auditor.js';

export {
  auditContractStorageFootprint,
  auditTomlStorageFootprint,
  getContractStorageFootprint,
  calculateStorageFootprint,
  calculateProjectedRent,
  estimateTtlExpiration,
  storageFootprintRules,
  storageFootprintRuleIds,
  TTL_EXPIRING_SOON_RULE,
  HIGH_STORAGE_FOOTPRINT_RULE,
  DEFAULT_MAX_STORAGE_BYTES,
  DEFAULT_RENT_FEE_PER_BYTE_PER_100K,
  TTL_EXPIRING_THRESHOLD_LEDGERS,
} from './soroban/storage-footprint.js';
export type {
  ContractStorageFootprint,
  StorageFootprintOptions,
} from './soroban/storage-footprint.js';

export {
  auditContractAuth,
  auditTomlContractAuth,
  verifyContractAuth,
  extractFunctionSpecs,
  authAuditorRules,
  authAuditorRuleIds,
  MISSING_AUTH_PARAMETER_RULE,
  UNSAFE_UNAUTHORIZED_MINT_RULE,
  STATE_MUTATING_AUTH_FUNCTIONS,
  SEP42_SPEC_URL,
} from './soroban/auth-auditor.js';
export type { AuthAuditorOptions, ContractFunctionSpec } from './soroban/auth-auditor.js';

export type {
  Diagnostic,
  Fix,
  LintOptions,
  LintResult,
  Position,
  Rule,
  RuleCategory,
  RuleContext,
  RuleOverrides,
  Severity,
  TlsSession,
} from './types.js';
export { SPEC_URL } from './spec.js';
export { applyFixes, computeFixEdits } from './fix.js';
export type { OffsetTextEdit } from './fix.js';
export { codeActionsFor } from './lsp/code-actions.js';
export type { LspCodeAction, LspRange, LspTextEdit, LspWorkspaceEdit } from './lsp/code-actions.js';

export {
  checkSignatureStateMachine,
  checkSignatureStateMachineFromDocument,
  signatureSchemeFromDocument,
  analyzeSignatureCombinations,
  signerCombinations,
  singleSignerThresholdBreakers,
  signatureStateMachineRules,
  signatureStateMachineRuleIds,
  SECURITY_INSUFFICIENT_THRESHOLD_PROTECTION,
  SECURITY_UNBALANCED_SIGNER_WEIGHTS,
} from './security/signature-state-machine.js';
export type {
  Signer,
  SignerThresholds,
  SignatureCombination,
  SignatureScheme,
  SignatureStateMachineOptions,
} from './security/signature-state-machine.js';

export {
  checkRateLimitResilience,
  probeHorizonRateLimit,
  computeBackoffDelayMs,
  rateLimitTesterRules,
  rateLimitTesterRuleIds,
  RATE_LIMIT_HEADERS,
  NETWORK_MISSING_RATE_LIMIT_HEADERS,
  NETWORK_UNSTANDARDIZED_RATE_LIMIT_RESPONSE,
} from './network/rate-limit-tester.js';
export type { RateLimitProbe, RateLimitTesterOptions } from './network/rate-limit-tester.js';

export {
  analyzeValidatorGeoDiversity,
  checkGeoDiversity,
  computeDistribution,
  loadGeoLookupFromEnv,
  validatorHostsFromDocument,
  geoDiversityRules,
  geoDiversityRuleIds,
  VALIDATORS_HIGH_ASN_CONCENTRATION,
  VALIDATORS_HIGH_GEOGRAPHIC_CONCENTRATION,
  DEFAULT_CONCENTRATION_THRESHOLD_PERCENT,
} from './validators/geo-diversity.js';
export type {
  GeoDiversityEntry,
  GeoDiversityOptions,
  GeoRecord,
  GeoLookup,
  GeoDistributionBucket,
} from './validators/geo-diversity.js';

export {
  analyzeSigningKeyRevocation,
  checkSigningKeyRevocation,
  keyRevocationRules,
  keyRevocationRuleIds,
  SECURITY_REVOKED_SIGNING_KEY,
  SECURITY_UNRECORDED_KEY_ROTATION,
} from './security/key-revocation.js';
export type {
  HorizonSigner,
  KeyRevocationAnalysisInput,
  KeyRevocationOptions,
} from './security/key-revocation.js';

export {
  analyzeAccountThresholds,
  auditAccountThresholds,
  checkSigningKeyMultisig,
  multisigRules,
  multisigRuleIds,
  SECURITY_SIGNING_KEY_INSUFFICIENT_WEIGHT,
  SECURITY_SIGNING_KEY_SINGLE_SIGNATURE,
  SECURITY_SIGNING_KEY_UNUSABLE,
  SECURITY_SINGLE_SIGNER_HIGH_THRESHOLD,
  SECURITY_UNREACHABLE_THRESHOLD,
} from './security/multisig.js';
export type {
  HorizonSigner as MultisigHorizonSigner,
  MultisigAnalysisInput,
  MultisigAuditOptions,
} from './security/multisig.js';

export {
  analyzeCtCertificates,
  checkCertificateTransparency,
  checkCertificateTransparencyFromDocument,
  ctAuditorRules,
  ctAuditorRuleIds,
  SECURITY_MISSING_SCT_TIMESTAMPS,
  SECURITY_UNRECOGNIZED_CA_IN_CT_LOGS,
} from './security/ct-auditor.js';
export type { CtCertificate, CtAuditOptions } from './security/ct-auditor.js';
