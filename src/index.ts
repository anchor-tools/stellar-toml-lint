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
export {
  auditIndentation,
  detectIndentation,
  INDENT_STYLES,
  indentUnit,
  isIndentStyle,
  normalizeIndentation,
} from './cst/indentation.js';
export type { IndentStyle, IndentationFinding, IndentationReport } from './cst/indentation.js';
export {
  semanticHash,
  semanticallyEqual,
  canonicalize,
  hashCanonical,
} from './cst/semantic-hash.js';
export type { SemanticHashResult } from './cst/semantic-hash.js';
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
export {
  LosslessRewriter,
  rewrite,
  countComments,
  detectCommentLoss,
  evaluateRewritten,
  COMMENT_LOSS_RULE,
} from './cst/lossless-rewrite.js';
export type { RewriteEdit, RewriteResult } from './cst/lossless-rewrite.js';
export { IncrementalParser, computeLineDelta } from './cst/incremental-parser.js';
export type {
  IncrementalParserOptions,
  LineDelta,
  ReparseResult,
} from './cst/incremental-parser.js';
export { renderSplitDiff, detectTerminalWidth } from './reporters/split-diff.js';
export type { Segment, SplitDiffOptions } from './reporters/split-diff.js';
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
  formatReadiness,
  formatReadinessJson,
  formatHtml,
  formatCheckstyle,
  formatMarkdown,
  formatPrComment,
  formatSonar,
} from './reporters.js';
export type { TextReporterOptions, ReadinessReporterOptions } from './reporters.js';
export { calculateReadiness, gradeFor } from './readiness.js';
export type {
  ReadinessCheck,
  ReadinessGrade,
  ReadinessPillar,
  ReadinessPillarId,
  ReadinessReport,
} from './readiness.js';
export { fix, type TextEdit, type FixResult } from './fix.js';
export { probeTls } from './tls.js';
export type { TlsProbe } from './tls.js';
export {
  checkSniFallback,
  sniHandshakeProbe,
  sniAuditorRules,
  SECURITY_SNI_FALLBACK_INFORMATION_LEAK,
} from './security/sni-auditor.js';
export type { SniCertificateInfo, SniProbe } from './security/sni-auditor.js';
export {
  checkSubdomainTakeover,
  subdomainTakeoverRules,
  DEFAULT_TAKEOVER_PATTERNS,
  SECURITY_DANGLING_CNAME_TAKEOVER_RISK,
} from './security/subdomain-takeover.js';
export type {
  CnameTargetPattern,
  SubdomainTakeoverOptions,
} from './security/subdomain-takeover.js';
export {
  checkPeerPortReachability,
  probeTcpPort,
  validatorHostsOf,
  peerPortRule,
  PEER_PORT_UNREACHABLE_RULE,
  DEFAULT_PROBE_TIMEOUT_MS,
} from './validators/net-probe.js';
export type { TcpPortProbe } from './validators/net-probe.js';

export {
  validateCid,
  validateIpfsMetadata,
  parseCid,
  extractCids,
  fetchCidFromGateways,
  verifyCidHash,
  ipfsMetadataRules,
  ipfsMetadataRuleIds,
  DEFAULT_IPFS_GATEWAYS,
} from './validators/ipfsMetadata.js';
export type {
  IpfsMetadataValidatorOptions,
  ParsedCid,
  CidVerificationResult,
  GatewayResult,
} from './validators/ipfsMetadata.js';
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
export {
  checkOverlayCipher,
  verifyOverlayCipher,
  verifyCipherSession,
  cipherFindings,
  deriveCipherKeys,
  cipherNonce,
  sealFrame,
  openFrame,
  encodePeerAddressRequest,
  openSocketChannel,
  overlayCipherRules,
  overlayCipherRuleIds,
  OVERLAY_CIPHER_NEGOTIATION_FAILED_RULE,
  OVERLAY_MAC_TAG_MISMATCH_RULE,
  CIPHER_NEGOTIATION_FAILED_RULE,
  MAC_TAG_MISMATCH_RULE,
  CHACHA20_POLY1305_KEY_BYTES,
  CHACHA20_POLY1305_NONCE_BYTES,
  POLY1305_TAG_BYTES,
  SEALED_FRAME_HEADER_BYTES,
} from './overlay/cipher-verifier.js';
export type {
  CipherChannel,
  CipherChannelFactory,
  CipherKeys,
  CipherOutcome,
  CipherVerifierOptions,
  OpenedFrame,
} from './overlay/cipher-verifier.js';
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
  checkOverlayDos,
  auditOverlayDos,
  testOverlayDos,
  runOverlayDosTest,
  overlayDosRules,
  overlayDosRuleIds,
  OVERLAY_UNPROTECTED_CONNECTION_CHURN,
  OVERLAY_PEER_SOCKET_EXHAUSTION,
  UNPROTECTED_CONNECTION_CHURN_RULE,
  PEER_SOCKET_EXHAUSTION_RULE,
  DEFAULT_DOS_ATTEMPTS,
  DEFAULT_DOS_TIMEOUT_MS,
} from './overlay/dos-tester.js';
export type {
  DosAttempt,
  DosAttemptStatus,
  DosProbe,
  DosProbeResult,
  OverlayDosOptions,
  OverlayDosResult,
} from './overlay/dos-tester.js';
export {
  analyzeOverlayTopology,
  analyzePeerTopology,
  checkOverlayTopology,
  auditOverlayTopology,
  topologyAnalyzerRules,
  topologyAnalyzerRuleIds,
  OVERLAY_HIGH_TOPOLOGICAL_DISTANCE,
  OVERLAY_DISCONNECTED_PEER_COMPONENT,
  HIGH_TOPOLOGICAL_DISTANCE_RULE,
  DISCONNECTED_PEER_COMPONENT_RULE,
  DEFAULT_MAX_TOPOLOGICAL_HOPS,
} from './overlay/topology-analyzer.js';
export type { TopologyAnalysis, TopologyOptions } from './overlay/topology-analyzer.js';
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
  checkBucketStreams,
  verifyBucketStreams,
  auditBucketStreams,
  validateBucketStream,
  parseGzipHeader,
  verifyGzipMember,
  inflatePrefix,
  decodeLeadingBucketEntries,
  normalizeBucketReference,
  sampleRandomBuckets,
  crc32,
  bucketStreamRules,
  bucketStreamRuleIds,
  CORRUPTED_BUCKET_GZIP_STREAM_RULE,
  TRUNCATED_BUCKET_XDR_RULE,
  HISTORY_CORRUPTED_BUCKET_GZIP_STREAM,
  HISTORY_TRUNCATED_BUCKET_XDR,
  DEFAULT_BUCKET_STREAM_SAMPLE_COUNT,
  DEFAULT_BUCKET_RANGE_BYTES,
  DEFAULT_FULL_VERIFY_MAX_BYTES,
  DEFAULT_LEADING_ENTRIES,
} from './history/bucket-stream-validator.js';
export type {
  BucketStreamOptions,
  BucketStreamVerdict,
  GzipHeaderResult,
} from './history/bucket-stream-validator.js';
export {
  checkHistoryGaps,
  auditHistoryGaps,
  verifyHistoryGaps,
  findLedgerGaps,
  groupGaps,
  checkpointsInRange,
  checkpointContaining,
  checkpointFilePath,
  checkpointHex,
  isCheckpointLedger,
  latestArchivedLedger,
  gapAuditorRules,
  gapAuditorRuleIds,
  LEDGER_SEQUENCE_GAP_RULE,
  HISTORY_LEDGER_SEQUENCE_GAP_DETECTED,
  CHECKPOINT_FREQUENCY,
  DEFAULT_GAP_AUDIT_LEDGERS,
  DEFAULT_GAP_AUDIT_CONCURRENCY,
} from './history/gap-auditor.js';
export type { CheckpointCategory, GapAuditorOptions, LedgerGap } from './history/gap-auditor.js';
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
  checkSplitBrain,
  buildTrustGraph,
  findBridgeNodes,
  findOrganizationChokePoints,
  flattenMembers,
  minimumNodeCut,
  analyzeQuorumSets,
  splitBrainRules,
  splitBrainRuleIds,
  PARTITION_VULNERABILITY_RULE,
  CRITICAL_BRIDGE_NODE_RULE,
} from './validators/split-brain-solver.js';
export type {
  SplitBrainOptions,
  QuorumAnalysis,
  TrustGraph,
  BridgeNode,
  ChokePoint,
} from './validators/split-brain-solver.js';
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
  checkValidatorDnsDiscovery,
  checkDnsDiscovery,
  auditValidatorDnsDiscovery,
  resolveValidatorDnsDiscovery,
  dnsDiscoveryRules,
  dnsDiscoveryRuleIds,
  VALIDATORS_DNS_SRV_RECORD_MISSING,
  VALIDATORS_DNS_SRV_TARGET_UNREACHABLE,
  DNS_SRV_RECORD_MISSING_RULE,
  DNS_SRV_TARGET_UNREACHABLE_RULE,
} from './validators/dns-discovery.js';
export type {
  DnsDiscoveryOptions,
  DnsDiscoveryResolver,
  DnsDiscoveryResult,
  DnsTargetProbe,
  SrvRecord,
} from './validators/dns-discovery.js';
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
  auditEmailDns,
  DEFAULT_EMAIL_DNS_DOMAIN_SOURCE,
  dmarcAuditorRules,
  SECURITY_MISSING_DMARC_RULE,
  SECURITY_WEAK_SPF_RULE,
} from './security/dmarc-auditor.js';
export type { DmarcAuditorOptions, TxtResolver } from './security/dmarc-auditor.js';

export {
  auditCaa,
  isCaaIssuerAuthorized,
  caaAuditorRules,
  SECURITY_MISSING_CAA_RULE,
  SECURITY_UNAUTHORIZED_CA_RULE,
} from './security/caa-auditor.js';
export type {
  CaaAuditorOptions,
  CaaRecord,
  CaaResolver,
  CertificateIssuerProbe,
} from './security/caa-auditor.js';

export {
  auditTlsForwardSecrecy,
  tlsPfsAuditorRules,
  DEFAULT_TLS_SESSION_OBSERVATION_WINDOW_MS,
  SECURITY_LACKS_FORWARD_SECRECY_RULE,
  SECURITY_SESSION_RESUMPTION_RULE,
} from './security/tls-pfs-auditor.js';
export type {
  TlsHandshakeObservation,
  TlsPfsAuditorOptions,
  TlsProbe as TlsPfsProbe,
} from './security/tls-pfs-auditor.js';

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
  verifySep8Webhook,
  buildSyntheticSep8Transaction as buildSyntheticSep8WebhookTransaction,
  isValidTransactionXdr as isValidSep8WebhookTransactionXdr,
  verifyCoSignedTransaction,
  sep8WebhookRules,
  sep8WebhookRuleIds,
  WEBHOOK_UNRESPONSIVE_RULE,
  INVALID_WEBHOOK_RESPONSE_RULE,
  INVALID_CO_SIGNED_TX_RULE,
  IDEMPOTENCY_VIOLATION_RULE,
  WEBHOOK_LATENCY_RULE,
} from './sep8/webhookCoordinator.js';
export type { Sep8WebhookOptions } from './sep8/webhookCoordinator.js';

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
  verifySep12Deletion,
  DELETE_CUSTOMER_UNSUPPORTED_RULE,
  CUSTOMER_RECORD_RETENTION_FAILURE_RULE,
  sep12DeletionRules,
} from './protocols/sep12-deletion.js';
export type { Sep12DeletionOptions } from './protocols/sep12-deletion.js';

export {
  simulateClawback,
  CLAWBACK_PERMISSION_MISMATCH_RULE,
  clawbackSimulatorRules,
} from './security/clawback-simulator.js';
export type { ClawbackSimulatorOptions } from './security/clawback-simulator.js';

export {
  verifySep24QuoteLock,
  QUOTE_FEE_INSTABILITY_RULE,
  sep24QuoteLockRules,
} from './protocols/sep24-quote-lock.js';
export type { Sep24QuoteLockOptions } from './protocols/sep24-quote-lock.js';

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
  auditContractInstanceStorage,
  auditTomlInstanceStorage,
  instanceStorageAuditorRules,
  instanceStorageAuditorRuleIds,
  CORRUPTED_ENTRY_RULE,
  DATA_MISMATCH_RULE,
} from './soroban/instance-storage-auditor.js';
export type { InstanceStorageAuditorOptions } from './soroban/instance-storage-auditor.js';

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

export {
  auditJwtCrypto,
  verifyJwtCrypto,
  checkJwtCrypto,
  parseJwt,
  decodeBase64Url,
  jwtCryptoAuditorRules,
  jwtCryptoRuleIds,
  INSECURE_JWT_ALGORITHM_RULE,
  JWT_SIGNATURE_VERIFICATION_FAILED_RULE,
} from './security/jwt-crypto-auditor.js';
export type {
  JwtCryptoAuditorOptions,
  JwtHeader,
  JwtJwk,
  JwtPayload,
  ParsedJwt,
} from './security/jwt-crypto-auditor.js';

export {
  auditZkpAttestations,
  validateZkpAttestations,
  checkZkpAttestations,
  zkpAttestationRules,
  zkpAttestationRuleIds,
  MALFORMED_ZKP_PROOF_RULE,
  MALFORMED_ZKP_PROOF_DATA_RULE,
  ZKP_SUPPLY_COMMITMENT_MISMATCH_RULE,
} from './crypto/zkp-attestation.js';
export type { ZkpAttestationOptions } from './crypto/zkp-attestation.js';

export {
  simulateTrustlineFreezing,
  simulateTrustLineFreeze,
  simulateTrustlineRevocation,
  simulateTrustlineAuthorization,
  auditTrustlineSimulator,
  checkTrustlineSimulator,
  checkTrustlineFreezing,
  auditTrustlineFreezing,
  auditTrustlineAuthorization,
  fetchIssuerAuthorization,
  buildTrustLineFreezeTransaction,
  hasFreezeDisclosure,
  trustlineSimulatorRules,
  trustlineSimulatorRuleIds,
  UNDISCLOSED_FREEZING_RULE,
  UNDISCLOSED_ASSET_FREEZING_RULE,
} from './security/trustline-simulator.js';
export type {
  HorizonIssuerAuthorization,
  TrustlineSimulatorOptions,
} from './security/trustline-simulator.js';

export {
  auditVanityAddresses,
  auditVanityAddress,
  checkVanityAddresses,
  analyzeVanityAddress,
  vanityAuditorRules,
  vanityAuditorRuleIds,
  SUSPICIOUS_VANITY_ADDRESS_RULE,
  VANITY_SECURITY_ADVISORY_URL,
} from './crypto/vanity-auditor.js';
export type { VanityAnalysis } from './crypto/vanity-auditor.js';

export {
  verifySep10,
  sep10Rules,
  sep10RuleIds,
  INVALID_SOURCE_RULE,
  INVALID_SEQUENCE_RULE,
  EXPIRED_TIMEBOUNDS_RULE,
  INVALID_SERVER_SIGNATURE_RULE,
  MISSING_CLIENT_DOMAIN_RULE,
  CHALLENGE_SUBMISSION_FAILED_RULE,
} from './protocols/sep10.js';
export type { Sep10Options } from './protocols/sep10.js';

export type {
  Diagnostic,
  Fix,
  LintOptions,
  LintResult,
  Position,
  Rule,
  RuleCategory,
  RuleContext,
  RuleInstrumenter,
  RuleOutcome,
  RuleOverrides,
  Severity,
  TlsSession,
} from './types.js';
export { SPEC_URL } from './spec.js';
export { applyFixes, computeFixEdits } from './fix.js';
export type { OffsetTextEdit } from './fix.js';
export { codeActionsFor } from './lsp/code-actions-provider.js';
export type {
  LspCodeAction,
  LspCodeActionKind,
  LspRange,
  LspTextEdit,
  LspWorkspaceEdit,
} from './lsp/code-actions-provider.js';

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
  analyzeKeyRotations,
  analyzeRotationTimeline,
  checkKeyRotation,
  checkKeyRotationSynchronization,
  checkSigningKeyRotation,
  detectKeyRotationHistory,
  checkRotation,
  rotationDetector,
  checkRotationDetector,
  checkRotationSynchronization,
  detectKeyRotation,
  rotationEventsFromOperations,
  rotationDetectorRules,
  keyRotationRules,
  rotationRules,
  keyRotationDetectorRules,
  rotationDetectorRuleIds,
  STALE_SIGNING_KEY_POST_ROTATION_RULE,
  UNRECORDED_SIGNER_ADDITION_RULE,
  SECURITY_STALE_SIGNING_KEY_POST_ROTATION,
  SECURITY_UNRECORDED_SIGNER_ADDITION,
  STALE_SIGNING_KEY_RULE,
  ROTATION_WINDOW_DAYS,
  ROTATION_SYNC_GRACE_MS,
} from './security/rotation-detector.js';
export type {
  HorizonOperation as RotationHorizonOperation,
  KeyRotationEvent,
  AccountOperations,
  RotationAnalysisInput,
  RotationDetectorOptions,
} from './security/rotation-detector.js';

export {
  checkProofOfReserve,
  checkCollateralReserves,
  auditProofOfReserve,
  auditCollateralReserves,
  auditReserves,
  checkReserves,
  auditReserveBalances,
  proofOfReserveAuditor,
  collateralAccountsOf,
  collateralReserveAccountsOf,
  fetchCollateralBalance,
  fetchEthereumBalance,
  fetchEvmBalance,
  fetchBitcoinBalance,
  fetchSolanaBalance,
  fetchStellarBalance,
  compareCollateralReserve,
  collateralReserveDeficitDiagnostics,
  compareReserveToSupply,
  proofOfReserveRules,
  collateralReserveRules,
  reserveAuditorRules,
  proofOfReserveAuditorRules,
  proofOfReserveRuleIds,
  COLLATERAL_RESERVE_DEFICIT_RULE,
  UNSUPPORTED_COLLATERAL_CHAIN_RULE,
  SECURITY_COLLATERAL_RESERVE_DEFICIT,
  SECURITY_UNSUPPORTED_COLLATERAL_CHAIN,
  RESERVE_DEFICIT_RULE,
  DEFAULT_ETHEREUM_RPC_URL,
  DEFAULT_BITCOIN_API_URL,
  DEFAULT_SOLANA_RPC_URL,
} from './security/proof-of-reserve.js';
export type {
  CollateralAccount,
  CollateralChain,
  ProofOfReserveOptions,
  ReserveSnapshot,
  ReserveComparisonInput,
} from './security/proof-of-reserve.js';

export {
  parsePkcs11Uri,
  parsePkcs11,
  validatePkcs11Uri,
  validatePkcs11,
  auditPkcs11Uri,
  checkPkcs11Uri,
  pkcs11Diagnostics,
  auditPkcs11,
  checkPkcs11Pointers,
  checkPkcs11Uris,
  auditPkcs11Pointers,
  isPkcs11Uri,
  isValidPkcs11Uri,
  pkcs11ValidatorRules,
  pkcs11Rules,
  pkcs11ValidatorRuleIds,
  MALFORMED_PKCS11_URI_RULE,
  INSECURE_EMBEDDED_PKCS11_PIN_RULE,
  CRYPTO_MALFORMED_PKCS11_URI,
  CRYPTO_INSECURE_EMBEDDED_PKCS11_PIN,
} from './crypto/pkcs11-validator.js';
export type {
  ParsedPkcs11Uri,
  Pkcs11Attribute,
  Pkcs11ParseResult,
  Pkcs11ValidatorOptions,
} from './crypto/pkcs11-validator.js';

export {
  checkSignatureMalleability,
  checkMalleability,
  auditMalleability,
  auditSignatureMalleability,
  auditCollateralSignatureMalleability,
  auditSep10ChallengeSignatures,
  auditEd25519Signature,
  parseEd25519Signature,
  parseSignature,
  decodeEd25519Signature,
  bytesToBigIntLE,
  isCanonicalEd25519Signature,
  isCanonicalSignature,
  isMalleableEd25519Signature,
  isSignatureMalleable,
  isEd25519SignatureMalleable,
  malleabilityAuditorRules,
  malleabilityRules,
  signatureMalleabilityRules,
  malleabilityAuditorRuleIds,
  MALLEABLE_SIGNATURE_RULE,
  CRYPTO_MALLEABLE_SIGNATURE,
  MALLEABLE_SIGNATURE_DETECTED_RULE,
  MALLEABILITY_RULE,
  ED25519_GROUP_ORDER,
  ED25519_L,
  ED25519_SIGNATURE_BYTES,
} from './crypto/malleability-auditor.js';
export type {
  ParsedEd25519Signature,
  SignatureMalleabilityResult,
  MalleabilityAuditOptions,
} from './crypto/malleability-auditor.js';

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
  optimizeThresholds,
  analyzeThresholds,
  optimizeSignerWeights,
  solveMinimalWinningCoalitions,
  minimalWinningCoalitions,
  findMinimalWinningCoalitions,
  checkThresholdOptimizer,
  auditThresholds,
  checkMultisigThresholds,
  thresholdOptimizerRules,
  thresholdOptimizerRuleIds,
  SECURITY_USELESS_SIGNER_DETECTED,
  SECURITY_UNINTENDED_VETO_KEY,
  USELESS_SIGNER_DETECTED_RULE,
  UNINTENDED_VETO_KEY_RULE,
} from './security/threshold-optimizer.js';
export type {
  ThresholdName,
  ThresholdSigner,
  Thresholds,
  ThresholdAccount,
  SignerCoalition,
  ThresholdOptimization,
  ThresholdOptimizerOptions,
} from './security/threshold-optimizer.js';

export {
  auditCorpHeaders,
  corpHeaderRules,
  SECURITY_MISSING_CORP_HEADER,
  SECURITY_MISSING_NOSNIFF_HEADER,
  SECURITY_MISSING_OPENER_POLICY,
} from './security/corp-auditor.js';
export {
  checkMpcGovernance,
  mpcGovernanceRules,
  SECURITY_INSUFFICIENT_MPC_THRESHOLD,
} from './security/mpc-governance.js';

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

export {
  auditAccountData,
  auditTomlAccountData,
  accountDataAuditorRules,
  accountDataAuditorRuleIds,
  HASH_MISMATCH_RULE,
  MISSING_PROOF_RULE,
} from './security/account-data-auditor.js';

export {
  auditIpv6Reachability,
  ipv6TargetsOf,
  ipv6AuditorRules,
  ipv6AuditorRuleIds,
  MISSING_IPV6_AAAA_RULE,
  IPV6_CONNECTION_TIMEOUT_RULE,
  IPV6_CONNECTION_FAILED_RULE,
} from './network/ipv6-auditor.js';
export type {
  Ipv6AuditorOptions,
  Ipv6ConnectionResult,
  Ipv6Connector,
  Ipv6LookupResult,
  Ipv6Resolver,
} from './network/ipv6-auditor.js';

export {
  analyzeImmutability,
  checkImmutabilityClaims,
  fetchImmutabilityRecord,
  immutabilityClaimsOf,
  immutabilityAuditorRules,
  immutabilityAuditorRuleIds,
  FALSE_IMMUTABILITY_CLAIM_RULE,
  IMMUTABILITY_UNVERIFIABLE_RULE,
} from './security/immutability-auditor.js';
export type {
  HorizonAccountSigner,
  ImmutabilityAccountRecord,
  ImmutabilityAuditorOptions,
  ImmutabilityClaim,
  ImmutabilityVerdict,
} from './security/immutability-auditor.js';

export {
  verifySep31Webhooks,
  verifyWebhookSignature,
  webhookPayloadProblem,
  sep31WebhookRules,
  sep31WebhookRuleIds,
  SEP31_WEBHOOK_EVENT_TYPES,
  DEFAULT_WEBHOOK_TIMEOUT_MS,
  MISSING_WEBHOOK_SIGNATURE_RULE,
  WEBHOOK_DELIVERY_TIMEOUT_RULE,
  INVALID_WEBHOOK_PAYLOAD_RULE,
} from './protocols/sep31-webhook-verifier.js';
export type {
  Sep31WebhookDelivery,
  Sep31WebhookListener,
  Sep31WebhookListenerFactory,
  Sep31WebhookOptions,
  SignatureValidation,
} from './protocols/sep31-webhook-verifier.js';

export {
  AnchorDiscoveryValidator,
  validateAnchorDiscovery,
  parseDirectoryRecords,
  declaredSepsOf,
  advertisedSepsOf,
  anchorDomainOf,
  anchorDiscoveryRules,
  anchorDiscoveryRuleIds,
  DEFAULT_DIRECTORY_REGISTRIES,
  TOML_SEP_ENDPOINTS,
  REGISTRY_UNREACHABLE_RULE,
  SCHEMA_INVALID_RULE,
  PROFILE_OUT_OF_SYNC_RULE,
  CAPABILITY_MISMATCH_RULE,
} from './validators/anchorDiscovery.js';
export type {
  AnchorDiscoveryOptions,
  DirectoryEntry,
  DirectoryRegistry,
} from './validators/anchorDiscovery.js';
export type { AccountDataAuditorOptions } from './security/account-data-auditor.js';

export {
  PrometheusMetricsServer,
  renderPrometheusText,
  metricsFromLintResult,
  collectMetrics,
  collectTlsCertExpiries,
  collectValidatorStatuses,
  escapeLabelValue,
  PROMETHEUS_CONTENT_TYPE,
  DEFAULT_METRICS_PORT,
  DEFAULT_METRICS_PROBE_TIMEOUT_MS,
} from './telemetry/prometheus-server.js';
export type {
  MetricsSnapshot,
  PrometheusMetricsServerOptions,
  RuleViolationMetric,
  TlsCertificateMetric,
  ValidatorStatusMetric,
} from './telemetry/prometheus-server.js';

export {
  DEFAULT_OTEL_SERVICE_NAME,
  DEFAULT_OTEL_TIMEOUT_MS,
  DURATION_BUCKETS_SECONDS,
  instrumentedFetch,
  metricsFromRun,
  durationMetric,
  otlpEndpointFor,
  OTelSpanKind,
  OTelStatusCode,
  OTLP_JSON_CONTENT_TYPE,
  OTLP_METRICS_PATH,
  OTLP_TRACES_PATH,
  OtelExporter,
  OtelTracer,
  renderOtlpMetrics,
  renderOtlpTraces,
  ruleSpanRecorder,
  severityMetrics,
} from './telemetry/otel-exporter.js';
export type {
  OtelActiveSpan,
  OtelAttributes,
  OtelAttributeValue,
  OtelExportResult,
  OtelExporterOptions,
  OtelMetric,
  OtelSpanOptions,
  OtelSpanRecord,
  OtelTracerOptions,
} from './telemetry/otel-exporter.js';

export {
  auditHttpVersions,
  httpVersionTargetsOf,
  httpVersionAuditorRules,
  httpVersionAuditorRuleIds,
  defaultAlpnProbe,
  defaultMultiplexProbe,
  LEGACY_HTTP1_ONLY_RULE,
  ALPN_NEGOTIATION_FAILED_RULE,
  TCP_ALPN_PROTOCOLS,
  HTTP3_ALPN_PROTOCOL,
} from './network/http-version-auditor.js';
export type {
  AlpnProbe,
  AlpnProbeResult,
  HttpVersionAuditOptions,
  HttpVersionObservation,
  HttpVersionTarget,
  MultiplexingMeasurement,
  MultiplexingProbe,
} from './network/http-version-auditor.js';

export {
  auditBgpRoutes,
  bgpRouteDetectorRules,
  DEFAULT_RIPESTAT_URL,
  NETWORK_RPKI_INVALID_ROUTE_RULE,
  NETWORK_UNVERIFIED_BGP_RULE,
} from './network/bgp-route-detector.js';
export type {
  AddressResolver,
  BgpRoute,
  BgpRouteAuditorOptions,
} from './network/bgp-route-detector.js';

export {
  SlaCalculator,
  defaultIsSuccess,
  slaCalculatorRules,
  slaCalculatorRuleIds,
  SLA_BELOW_THRESHOLD_RULE,
  DEFAULT_SLA_THRESHOLD_PERCENT,
  SLA_WINDOWS_DAYS,
  SLA_THRESHOLD_WINDOW_DAYS,
  DEFAULT_MAX_RECORDS,
} from './monitor/sla-calculator.js';
export type {
  ProbeInput,
  ProbeRecord,
  SlaCalculatorOptions,
  SlaSummary,
} from './monitor/sla-calculator.js';

export {
  generateJsonLd,
  organizationNodeOf,
  financialProductNodeOf,
  formatJsonLd,
  formatJsonLdScript,
  validateJsonLd,
  SCHEMA_ORG_CONTEXT,
  ORGANIZATION_NODE_ID,
  KNOWN_SCHEMA_TYPES,
} from './generators/jsonld.js';
export type { JsonLdNode, JsonLdValidation } from './generators/jsonld.js';

export { MonitorDaemon } from './monitor/daemon.js';
export type { DiffResult, MonitorDaemonOptions, PollSample } from './monitor/daemon.js';

export {
  coordinateSep30Recovery,
  extractRecoveryServers,
  sep30CoordinatorRules,
  sep30CoordinatorRuleIds,
  INSUFFICIENT_RECOVERY_SIGNATURES_RULE,
  SIGNATURE_COORDINATION_TIMEOUT_RULE,
} from './protocols/sep30-coordinator.js';
export type { Sep30CoordinatorOptions } from './protocols/sep30-coordinator.js';

export {
  validateSep31KycMatrix,
  generateSep31PaymentJsonSchema,
  generateSep31ClientSchemas,
  sep31KycRules,
  sep31KycRuleIds,
  INVALID_KYC_FIELD_DEFINITION_RULE,
  MISSING_SENDER_KYC_DECLARATION_RULE,
} from './protocols/sep31-kyc-matrix.js';
export type {
  Sep31FieldDefinition,
  Sep31AssetFields,
  Sep31AssetInfo,
  Sep31KycMatrixOptions,
} from './protocols/sep31-kyc-matrix.js';

export {
  upgradeFederationDeclaration,
  canonicalFederationServer,
  legacyLookupFlags,
  federationUpgradeRules,
  FEDERATION_UPGRADE_APPLIED_RULE,
  FEDERATION_UPGRADE_SKIPPED_RULE,
  FEDERATION_SERVER_INVALID_RULE,
  FEDERATION_SERVER_UNREACHABLE_RULE,
} from './codemod/index.js';
export type {
  FederationLookupFlags,
  FederationUpgradeOptions,
  FederationUpgradeResult,
} from './codemod/index.js';

export {
  auditMultiTenantRouting,
  multiTenantRules,
  TENANT_CROSS_CONTAMINATION_RULE,
  INVALID_HOST_ROUTING_RULE,
} from './network/multi-tenant.js';
export type { MultiTenantOptions } from './network/multi-tenant.js';

export {
  verifySep6FeeCurve,
  sep6FeeVerifierRules,
  DEFAULT_FEE_SAMPLE_AMOUNTS,
  NON_MONOTONIC_FEE_CURVE_RULE,
  FEE_EXCEEDS_DECLARED_BOUNDS_RULE,
} from './protocols/sep6-fee-verifier.js';
export type { Sep6FeeVerifierOptions } from './protocols/sep6-fee-verifier.js';

export {
  simulateSep24Lifecycle,
  sep24LifecycleRules,
  isValidTransition,
  SEP24_LIFECYCLE_STATES,
  SEP24_TERMINAL_STATES,
  SEP24_ALLOWED_TRANSITIONS,
  ILLEGAL_STATE_TRANSITION_RULE,
  MISSING_LIFECYCLE_TIMESTAMPS_RULE,
} from './protocols/sep24-lifecycle.js';
export type { Sep24LifecycleOptions } from './protocols/sep24-lifecycle.js';
