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
export { lspMain } from './lsp.js';
export { allRules, ruleIds } from './rules/index.js';
export { PRESETS, PRESET_NAMES, resolvePreset } from './presets.js';
export type { Preset, PresetName } from './presets.js';
export {
  formatText,
  formatJson,
  formatSarif,
  formatGithub,
  formatJunit,
  formatHtml,
  formatCheckstyle,
  formatMarkdown,
} from './reporters.js';
export type { TextReporterOptions } from './reporters.js';
export { probeTls } from './tls.js';
export type { TlsProbe } from './tls.js';
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
  checkSubdomainTakeover,
  renderTakeoverReport,
  scanSubdomainTakeover,
  subdomainTakeoverRuleIds,
  subdomainTakeoverRules,
  takeoverDiagnostics,
  TAKEOVER_SIGNATURES,
  SECURITY_DNS_TAKEOVER_CNAME,
  SECURITY_DNS_TAKEOVER_NS,
  SECURITY_DNS_TAKEOVER_TIMEOUT,
} from './security/subdomainScanner.js';
export type {
  SubdomainTakeoverOptions,
  SubdomainTakeoverReport,
  TakeoverDnsRecord,
  TakeoverDnsResolver,
  TakeoverDnsResponse,
  TakeoverFinding,
  TakeoverRisk,
  TakeoverSignature,
} from './security/subdomainScanner.js';
export {
  checkSecrets,
  maskSecret,
  renderSecretReport,
  scanSecrets,
  secretDetectorRuleIds,
  secretDetectorRules,
  SECURITY_SECRET_AWS_ACCESS_KEY,
  SECURITY_SECRET_AWS_SECRET_KEY,
  SECURITY_SECRET_BEARER_TOKEN,
  SECURITY_SECRET_GITHUB_TOKEN,
  SECURITY_SECRET_HIGH_ENTROPY,
  SECURITY_SECRET_PRIVATE_KEY,
  SECURITY_SECRET_STELLAR_SEED,
  shannonEntropy,
} from './security/secretDetector.js';
export type {
  SecretDetectorOptions,
  SecretFinding,
  SecretKind,
  SecretScanResult,
} from './security/secretDetector.js';
export {
  checkSsrf,
  isBlockedIp,
  normalizeIp,
  renderSsrfReport,
  scanSsrf,
  ssrfDiagnostics,
  ssrfRuleIds,
  ssrfRules,
  BLOCKED_CIDRS,
  SECURITY_SSRF_DNS_REBINDING,
  SECURITY_SSRF_PRIVATE_IP,
  SECURITY_SSRF_TIMEOUT,
} from './security/ssrfScanner.js';
export type {
  SsrfDnsResolver,
  SsrfFinding,
  SsrfOptions,
  SsrfReport,
} from './security/ssrfScanner.js';
export {
  deduplicateAssets,
  diffText,
  renderRefactorSummary,
  splitLargeFile,
  StructuralRefactoringEngine,
} from './cst/structuralRefactoring.js';
export type {
  AssetDuplicateGroup,
  FieldConflict,
  PartialFile,
  RefactorResult,
  RefactorValidation,
  SplitOptions,
  SplitResult,
} from './cst/structuralRefactoring.js';
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
export {
  ServiceWorkerOfflineValidator,
  validateOfflinePwa,
  simulateOfflineLint,
  parseServiceWorker,
  parseManifest,
  parseCacheNames,
  isVersionedCacheName,
  renderOfflineReport,
  swOfflineRuleIds,
} from './wasm/swValidator.js';
export type {
  ManifestAnalysis,
  OfflineFinding,
  OfflineFindingCode,
  OfflineValidationOptions,
  OfflineValidationResult,
  PwaIcon,
  ServiceWorkerAnalysis,
} from './wasm/swValidator.js';
export {
  WebWorkerLinterEngine,
  createLinterEngine,
  registerWorkerFactory,
  encodeLintSource,
  decodeLintSource,
  encodeLintResponse,
  decodeLintResponse,
  defaultPoolSize,
  workersAvailable,
} from './wasm/workerEngine.js';
export type {
  LintJob,
  LintJobOutcome,
  LintWorkerMessage,
  LintWorkerResponse,
  WorkerEngineOptions,
  WorkerEngineStats,
  WorkerFactory,
  WorkerPort,
} from './wasm/workerEngine.js';
export {
  EdgeRuntimeVerifier,
  verifyEdgeCompatibility,
  createEdgeIsolateScope,
  checkEdgeWebApis,
  readEdgeStream,
  renderEdgeReport,
  DEFAULT_EDGE_THRESHOLDS,
  EDGE_WEB_APIS,
} from './wasm/edgeRuntimeVerifier.js';
export type {
  EdgeBenchmark,
  EdgeFinding,
  EdgeThresholds,
  EdgeVerificationOptions,
  EdgeVerificationResult,
} from './wasm/edgeRuntimeVerifier.js';
export {
  IncidentWebhookDispatcher,
  formatSlackIncident,
  formatDiscordIncident,
  formatPagerDutyIncident,
  formatIncident,
  dedupKeyFor,
  routesFor,
  isSupportedIncidentUrl,
  renderIncidentReport,
  SEVERITY_ROUTES,
} from './gitops/incidentDispatcher.js';
export type {
  Incident,
  IncidentChannel,
  IncidentDelivery,
  IncidentSeverity,
  IncidentTargets,
  DispatcherOptions,
  SlackIncidentPayload,
  DiscordIncidentPayload,
  PagerDutyIncidentPayload,
} from './gitops/incidentDispatcher.js';
export { SPEC_URL } from './spec.js';
export { applyFixes, computeFixEdits } from './fix.js';
export type { OffsetTextEdit } from './fix.js';
export { codeActionsFor } from './lsp/code-actions.js';
export type { LspCodeAction, LspRange, LspTextEdit, LspWorkspaceEdit } from './lsp/code-actions.js';
export {
  auditTomlAuthTree,
  simulateAuthTree,
  analyzeAuthTree,
  buildAuthTreeTransaction,
  parseAuthEntry,
  parseAuthEntries,
  authorizedIdentitiesOf,
  allowedContractsOf,
  canonicalIdentity,
  authTreeSimulatorRules,
  authTreeSimulatorRuleIds,
  AUTH_TREE_OPERATIONS,
  AUTH_MARKER_FUNCTIONS,
  VALUE_MOVING_FUNCTIONS,
  RECORDING_AUTH_MODE,
  UNAUTHORIZED_CROSS_CONTRACT_RULE,
  UNBOUNDED_AUTH_GRANT_RULE,
} from './soroban/auth-tree-simulator.js';
export { WasiSandboxRunner, SANDBOX_SYSCALLS, WASI_ERRNO } from './wasm/wasiRunner.js';
export type {
  SandboxFileSnapshot,
  SandboxViolation,
  VirtualFileInput,
  WasiSandboxOptions,
  WasiSandboxResult,
} from './wasm/wasiRunner.js';
export { FuelMeterError, WasiSandboxError } from './wasm/errors.js';
export type { SandboxErrorCode } from './wasm/errors.js';
export { DEFAULT_FUEL, FUEL_EXPORT_NAME, injectFuelMeter } from './wasm/fuelMeter.js';
export type { InstrumentedModule } from './wasm/fuelMeter.js';
export {
  DEFAULT_LEAK_THRESHOLD_BYTES,
  DEFAULT_STABLE_WINDOW,
  WASM_PAGE_BYTES,
  WasmHeapProfiler,
} from './wasm/heapProfiler.js';
export type { HeapProfile, HeapProfilerOptions, HeapSample } from './wasm/heapProfiler.js';
export { PointerLedger } from './wasm/pointerLedger.js';
export type { DanglingPointer } from './wasm/pointerLedger.js';
export {
  CACHE_DB_VERSION,
  CACHE_STORES,
  DEFAULT_CACHE_TTL_MS,
  DEFAULT_MAX_ENTRIES,
  IndexedDbSchemaCache,
} from './wasm/indexedDbCache.js';
export type {
  CacheBackend,
  CacheRecord,
  CacheSetOptions,
  CacheStats,
  CacheStore,
  IdbFactoryLike,
  IndexedDbCacheOptions,
} from './wasm/indexedDbCache.js';
export {
  buildDenoManifest,
  DenoCompatibilityVerifier,
  extractSpecifiers,
  permissionFlags,
} from './wasm/denoVerifier.js';
export type {
  DenoCompatibilityFinding,
  DenoCompatibilityReport,
  DenoEntryPointReport,
  DenoFindingKind,
  DenoVerifierOptions,
  ImportedSpecifier,
  PermissionRequest,
  PermissionUsage,
} from './wasm/denoVerifier.js';
export {
  CrossOriginIsolationAuditor,
  normalizeHeaders,
  renderDeploymentGuide,
  renderIsolationReport,
} from './wasm/isolationAuditor.js';
export type {
  IsolationAuditorOptions,
  IsolationFinding,
  IsolationFindingCode,
  IsolationReport,
  ResourceCheck,
} from './wasm/isolationAuditor.js';
export {
  BrowserBoundaryVerifier,
  NODE_BUILTINS,
  extractBundleSpecifiers,
  isNodeBuiltin,
  renderBrowserBoundaryReport,
} from './wasm/browserBoundaryVerifier.js';
export type {
  BrowserBoundaryCode,
  BrowserBoundaryFinding,
  BrowserBoundaryOptions,
  BrowserBoundaryReport,
  BundleArtifact,
} from './wasm/browserBoundaryVerifier.js';
export {
  ERROR_LEAK_PATTERNS,
  FederationSecurityTester,
  INJECTION_PROBES,
  auditFederationSecurity,
  federationSecurityRuleIds,
  federationSecurityRules,
  findLeakedDetail,
  renderFederationSecurityReport,
} from './protocols/federationSecurityTester.js';
export type {
  FederationProbe,
  FederationQueryType,
  FederationSecurityFinding,
  FederationSecurityOptions,
  FederationSecurityReport,
} from './protocols/federationSecurityTester.js';
export {
  ReverseFederationVerifier,
  collectAnchorAccounts,
  renderReverseFederationReport,
  reverseFederationRuleIds,
  reverseFederationRules,
  validateFederationRecord,
  validateMemo,
  verifyFederationSync,
} from './protocols/reverseFederationVerifier.js';
export type {
  FederationRecord,
  MemoProblem,
  MemoType,
  ReverseCheck,
  ReverseFederationOptions,
  ReverseFederationReport,
} from './protocols/reverseFederationVerifier.js';
export type {
  AuthTreeOptions,
  AuthTreeOperation,
  AuthTreeNode,
  AuthTreeEntry,
  AuthTreeFinding,
  AuthTreeContext,
} from './soroban/auth-tree-simulator.js';
export {
  MAX_WASM_MEMORY_BYTES,
  MAX_WASM_PAGES,
  WASM_PAGE_SIZE,
  WasmPointerError,
  WasmPointerProtector,
} from './wasm/pointerProtector.js';
export type {
  GrowthResult,
  PointerProtectorOptions,
  PointerWindow,
  WasmMemoryHandle,
  WasmPointerCode,
  WasmPointerDetails,
} from './wasm/pointerProtector.js';
export {
  SIMD_PROBE_MODULE,
  WasmScanError,
  auditWasmBinary,
  detectSimdSupport,
  renderSimdFallback,
  renderSimdReport,
  scanWasmBinary,
} from './wasm/simdAuditor.js';
export type {
  MemoryGrowthAudit,
  SimdAuditOptions,
  SimdAuditReport,
  SimdFinding,
  SimdFindingCode,
  SimdInstruction,
  SimdRuntimeLike,
  WasmScanResult,
} from './wasm/simdAuditor.js';
export {
  WasmStreamingVerifier,
  renderStreamingFixes,
  renderStreamingReport,
  supportsStreamingCompilation,
} from './wasm/streamingVerifier.js';
export type {
  StreamingBenchmark,
  StreamingFinding,
  StreamingFindingCode,
  StreamingRuntimeLike,
  StreamingVerificationResult,
  StreamingVerifierOptions,
} from './wasm/streamingVerifier.js';
export {
  DirectorySyncVerifier,
  SERVICE_KEYS,
  diffAnchor,
  extractPublishedAnchor,
  mapPool,
  normalizeAsset,
  normalizeDomain,
  normalizeServiceKey,
  normalizeUrl,
  parseDirectoryFeed,
  renderDirectorySyncReport,
} from './protocols/directorySyncVerifier.js';
export type {
  AnchorSyncResult,
  DirectoryAnchorRecord,
  DirectoryFeedParseResult,
  DirectorySyncFinding,
  DirectorySyncFindingCode,
  DirectorySyncOptions,
  DirectorySyncReport,
  DirectorySyncStatus,
  DriftField,
  PublishedAnchor,
} from './protocols/directorySyncVerifier.js';
export {
  PROBE_ADDRESS,
  SEP30_AUTH_METHODS,
  Sep30RecoveryVerifier,
  auditSep30Recovery,
  findUnsupportedAuthMethods,
  sep30RuleIds,
  sep30Rules,
} from './protocols/sep30Verifier.js';
export type { Sep30Options, Sep30Result } from './protocols/sep30Verifier.js';
export {
  PromotionalPricingVerifier,
  collectPromoClaims,
  formatPercent,
  parsePromoClaim,
  promotionalPricingRuleIds,
  promotionalPricingRules,
  verifyPromotions,
} from './protocols/promotionalPricingVerifier.js';
export type {
  PromoClaim,
  PromotionalPricingOptions,
  PromotionalPricingResult,
} from './protocols/promotionalPricingVerifier.js';
export {
  FederationSrvRecordVerifier,
  federationSrvRuleIds,
  federationSrvRules,
  isValidSrvTarget,
  verifyFederationSrv,
} from './protocols/federationSrvVerifier.js';
export type {
  FederationSrvOptions,
  FederationSrvResult,
  SrvRecord,
  SrvResolver,
} from './protocols/federationSrvVerifier.js';
export {
  EsgComplianceVerifier,
  auditEsgDisclosures,
  esgRuleIds,
  esgRules,
  rate as rateEsgScore,
  renderEsgReport,
  verifyAttestationSignature,
} from './protocols/esgComplianceVerifier.js';
export type {
  EsgCriterion,
  EsgOptions,
  EsgRating,
  EsgReport,
  EsgResult,
} from './protocols/esgComplianceVerifier.js';
