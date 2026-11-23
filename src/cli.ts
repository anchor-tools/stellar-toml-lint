#!/usr/bin/env node
/**
 * Command line entry point.
 *
 * Argument parsing is hand-rolled rather than pulled from a library: the flag
 * set is small and stable, and a linter that anchors run in CI benefits from a
 * dependency tree small enough to audit by eye.
 */
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { parse as parseToml } from 'smol-toml';
import { createReadStream, watch } from 'node:fs';
import { basename, dirname, resolve } from 'node:path';
import process from 'node:process';
import { assertKnownRule, loadConfig } from './config.js';
import { loadPluginRules } from './engine/ruleLoader.js';
import { lint, lintDomain, finalize, followTomlPointers } from './lint.js';
import { checkNetworkAccounts } from './network-checks.js';
import { ASSET_CACHE_ENV, createAssetCacheFetch } from './gitops/ciAssetCache.js';
import {
  CiMatrixWorkflowGenerator,
  type CiMatrixWorkflowOptions,
} from './gitops/ciWorkflowGenerator.js';
import {
  checkNetworkIsolation,
  parseCiMatrix,
  resolveCiEnvironment,
} from './gitops/ciEnvironments.js';
import {
  buildCiReport,
  formatCiSarif,
  isCiEnvironmentReport,
  type CiEnvironmentReport,
} from './gitops/ciSarif.js';
import { formatCiScorecard, formatEnvironmentScorecard } from './gitops/ciScorecard.js';
import { VaultSecretEngineVerifier } from './gitops/vaultVerifier.js';
import { checkCorsPreflight } from './network/cors-preflight.js';
import {
  formatCheckstyle,
  formatGithub,
  formatHtml,
  formatJson,
  formatJunit,
  formatMarkdown,
  formatNdjson,
  formatSarif,
  formatSummary,
  formatText,
} from './reporters.js';
import { expandGlob, hasMagic } from './glob.js';
import { checkDisplayDecimals, rpcUrlFor } from './rules/display-decimals-audit.js';
import { checkHorizon } from './rules/horizon-check.js';
import { checkSep38 } from './rules/sep38-endpoints.js';
import { checkRegulatedIssuerFlags } from './rules/currencies.js';
import { checkContracts } from './rules/soroban.js';
import { auditTomlAuthTree } from './soroban/auth-tree-simulator.js';
import { auditTomlEvents } from './soroban/eventVerifier.js';
import { AuthTreeSimulator, renderAuthTreeReport } from './soroban/authTreeSimulator.js';
import { analyzeWasmMemory, renderMemoryHazardReport } from './soroban/wasmMemoryAnalyzer.js';
import {
  auditSignatureReplay,
  renderSignatureReplayReport,
} from './soroban/signatureReplayAuditor.js';
import {
  contractTargetsOf,
  ledgersToDays,
  SorobanTtlAuditor,
  ttlThresholdsOf,
} from './soroban/ttlAuditor.js';
import { checkSep6 } from './cross-sep/sep6.js';
import { checkSep10Replay } from './protocols/sep10-replay.js';
import { checkSep10ClientDomain } from './protocols/sep10-client-domain.js';
import { auditQuoteBinding } from './protocols/quote-binding-auditor.js';
import { auditKycStateMachines, renderKycDiagram } from './protocols/kycTierAuditor.js';
import {
  ClawbackAuditTrailGenerator,
  DEFAULT_HORIZON,
  parseAsset,
  renderClawbackJson,
  renderClawbackMarkdown,
} from './protocols/clawbackAuditGenerator.js';
import { validateUnicode } from './cst/unicodeValidator.js';
import { sortCanonical } from './cst/canonicalSortCodemod.js';
import {
  renderSemanticDiff,
  renderSemanticDiffJson,
  SemanticTomlDiffer,
} from './cst/semanticDiffer.js';
import { SchemaMigrationCodemod } from './cst/migrationCodemod.js';
import type { MigrationOptions } from './cst/migrationCodemod.js';
import { MIGRATION_RULES } from './cst/codemodRules/index.js';
import { OrphanedKeyScanner, pruneOrphans } from './cst/orphanedKeyScanner.js';
import type { OrphanFinding, OrphanScanOptions, PruneAction } from './cst/orphanedKeyScanner.js';
import { formatUnifiedDiff } from './line-diff.js';
import {
  auditConsumerProtection,
  renderScorecard,
} from './protocols/consumerProtectionVerifier.js';
import { auditSep30Recovery } from './protocols/sep30Verifier.js';
import { verifyPromotions } from './protocols/promotionalPricingVerifier.js';
import { verifySep38Volatility } from './protocols/sep38CircuitBreaker.js';
import { auditSep38QuoteDiscrepancies } from './protocols/sep38Discrepancy.js';
import { auditSep6Polling } from './protocols/sep6Polling.js';
import { auditSep10Jwt } from './protocols/sep10JwtAuditor.js';
import { testSep12FileUploads } from './protocols/sep12FileUpload.js';
import { verifyFederationSrv } from './protocols/federationSrvVerifier.js';
import {
  renderSep31Sep12Report,
  Sep31Sep12ConsistencyEngine,
} from './protocols/sep31Sep12Consistency.js';
import { auditEsgDisclosures, renderEsgReport } from './protocols/esgComplianceVerifier.js';
import { verifyPorFeeds } from './bridges/chainlinkPorVerifier.js';
import { verifySolanaBridges } from './bridges/solanaEscrowVerifier.js';
import { auditErc4626Vaults } from './bridges/erc4626VaultAuditor.js';
import {
  WormholeVaaAuditor,
  parseGuardianSet,
  renderVaaReport,
} from './bridges/wormholeVaaAuditor.js';
import { benchmarkBridgeLatency, renderLatencyReport } from './bridges/latencyBenchmark.js';
import { auditBridgeReplays } from './bridges/eventReplayDetector.js';
import { verifyBankAttestations } from './bridges/bankAttestationVerifier.js';
import { auditBurnRedemptions, renderBurnReport } from './bridges/proofOfBurnValidator.js';
import { auditTlsCiphers, renderCipherReport } from './security/tlsCipherAuditor.js';
import { auditHsts, renderHstsBadges } from './security/hstsVerifier.js';
import { auditEmergencyPause } from './bridges/emergencyPauseValidator.js';
import { auditBridgeQuorum } from './bridges/bridgeQuorumAuditor.js';
import { checkCollateralGovernance } from './security/collateral-governance.js';
import { auditCors, renderCorsReport } from './security/corsAuditor.js';
import { auditAssetSecurity, renderMimeReport } from './security/mimeScanner.js';
import { auditClickjacking, renderClickjackingReport } from './security/clickjackingAuditor.js';
import { auditKeySeparation, renderKeySeparationReport } from './security/keySeparationAuditor.js';
import { checkHistoryPublish } from './history/publish-validator.js';
import { checkDnsIntegrity } from './security/dns-integrity.js';
import {
  scanSubdomainTakeover,
  renderTakeoverReport,
  takeoverDiagnostics,
} from './security/subdomainScanner.js';
import { scanSecrets, renderSecretReport } from './security/secretDetector.js';
import { scanSsrf, renderSsrfReport, ssrfDiagnostics } from './security/ssrfScanner.js';
import { StructuralRefactoringEngine, renderRefactorSummary } from './cst/structuralRefactoring.js';
import { checkOverlayPeers } from './overlay/crawler.js';
import { ArchiveGpgVerifier } from './overlay/archiveGpgVerifier.js';
import { QuorumSetIntersectionAuditor } from './overlay/quorumIntersectionAuditor.js';
import { ScpBallotTracer } from './overlay/scpBallotTracer.js';
import { ArchiveProgressionVerifier } from './overlay/archiveProgressionVerifier.js';
import { GeographicDiversityScorer } from './overlay/diversityScorer.js';
import { parseValidatorEndpoints } from './overlay/handshakeTester.js';
import {
  FloodPropagationVerifier,
  parseBurstProfile,
  renderFloodPolicyReport,
  type OverlayExchange,
  type SubmissionEvent,
} from './overlay/floodVerifier.js';
import {
  ValidatorKeyRotationVerifier,
  renderKeyRotationReport,
  type KeyRotationAttestation,
  type QuorumPeerConfig,
} from './overlay/keyRotationVerifier.js';
import {
  HEARTBEAT_ERRATIC,
  HEARTBEAT_SUDDEN_CLOSURE,
  HEARTBEAT_UNRESPONSIVE,
  OverlayHeartbeatWatchdog,
  renderHeartbeatReport,
} from './overlay/heartbeatWatchdog.js';
import {
  Tier1QuorumAlignmentVerifier,
  renderTier1AlignmentReport,
} from './overlay/tier1AlignmentVerifier.js';
import { DEFAULT_TIER1_CATALOG, parseTier1Catalog } from './overlay/tier1Catalog.js';
import { OpenTelemetryTraceValidator, renderTraceAuditReport } from './telemetry/traceValidator.js';
import { validateOfflinePwa, renderOfflineReport } from './wasm/swValidator.js';
import { verifyEdgeCompatibility, renderEdgeReport } from './wasm/edgeRuntimeVerifier.js';
import { CrossOriginIsolationAuditor, renderIsolationReport } from './wasm/isolationAuditor.js';
import {
  auditErrorTaxonomyCommand,
  auditTlsCommand,
  calculateUptimeCommand,
  probeSlaCommand,
  verifyMetricsCommand,
  verifyRateHeadersCommand,
} from './telemetry/commands.js';
import { LosslessCstFormatter } from './cst/cstFormatter.js';
import {
  BrowserBoundaryVerifier,
  renderBrowserBoundaryReport,
} from './wasm/browserBoundaryVerifier.js';
import {
  auditFederationSecurity,
  renderFederationSecurityReport,
} from './protocols/federationSecurityTester.js';
import {
  renderReverseFederationReport,
  verifyFederationSync,
} from './protocols/reverseFederationVerifier.js';
import {
  IncidentWebhookDispatcher,
  renderIncidentReport,
  type IncidentChannel,
  type IncidentSeverity,
} from './gitops/incidentDispatcher.js';
import { auditDockerfile, renderContainerReport } from './gitops/containerAuditor.js';
import {
  renderProvenanceReport,
  verifySlsaProvenance,
  type SlsaLevel,
} from './gitops/slsaVerifier.js';
import { allRules } from './rules/index.js';
import { PRESETS, resolvePreset, type PresetName } from './presets.js';
import { generateBadgeSvg, generateShieldsEndpoint } from './generators/badge.js';
import {
  generateAnchorPlatformConfig,
  formatAnchorPlatformYaml,
} from './generators/anchor-platform.js';
import { generateOpenApiSpec } from './generators/openapi.js';
import { generateDiagram, type GraphFormat } from './generators/diagram.js';
import { deliverWebhooks, isSupportedWebhookUrl } from './reporters/webhook.js';
import { runHealthCheck, formatHealthCheckTable } from './health-check.js';
import { runDashboard, supportsDashboard } from './ui/dashboard.js';
import { loadPolicy, validatePolicy, evaluatePolicy } from './policy/engine.js';
import { createFixtureFetch } from './mock-fixtures.js';
import { runLspServer } from './lsp/server.js';
import { getTomlJsonSchema } from './schema.js';
import { runCloudKmsSignerCheck, type KmsThresholdLevel } from './gitops/kmsSignerCoordinator.js';
import { formatKmsSignerReport } from './gitops/kmsReport.js';
import { KmsError } from './gitops/kmsTypes.js';
import {
  DriftDetectionError,
  GitOpsDriftDetector,
  liveUrlForDomain,
  renderDriftErrorJson,
  renderDriftJson,
  renderDriftLineDiff,
  renderDriftText,
} from './gitops/driftDetector.js';
import { generateCompletion, isCompletionShell } from './completion.js';
import { WasiSandboxRunner } from './wasm/wasiRunner.js';
import { WasiSandboxError } from './wasm/errors.js';
import { WasmHeapProfiler } from './wasm/heapProfiler.js';
import { auditWasmBinary, renderSimdReport } from './wasm/simdAuditor.js';
import { renderStreamingReport, WasmStreamingVerifier } from './wasm/streamingVerifier.js';
import {
  DirectorySyncVerifier,
  parseDirectoryFeed,
  renderDirectorySyncReport,
} from './protocols/directorySyncVerifier.js';
import { isWasmMemory, wasmRuntime } from './wasm/wasmApi.js';
import type { Diagnostic, LintOptions, LintResult, RuleOverrides } from './types.js';
import type { SemanticRule } from './engine/semanticRuleEngine.js';

const VERSION = '0.1.0';
const DEFAULT_PATH = 'stellar.toml';

type Format =
  'text' | 'json' | 'ndjson' | 'sarif' | 'github' | 'junit' | 'html' | 'checkstyle' | 'markdown';

interface Cli {
  noSuggestions?: boolean;
  paths: string[];
  domain?: string;
  format: Format;
  healthCheck?: boolean;
  strict: boolean;
  watch?: boolean;
  color?: boolean;
  quiet: boolean;
  showHelp: boolean;
  rules: RuleOverrides;
  rulesDir: string[];
  plugins: string[];
  preset?: PresetName;
  maxWarnings?: number;
  checkNetwork: boolean;
  followLinks: boolean;
  verifySep10: boolean;
  auditQuotes: boolean;
  auditUnicodeSecurity: boolean;
  auditConsumerProtection: boolean;
  auditKycFsm: boolean;
  auditFederationSecurity: boolean;
  auditSep30Recovery: boolean;
  auditCors: boolean;
  auditAssetSecurity: boolean;
  auditClickjacking: boolean;
  verifyPromotions: boolean;
  auditSep38Volatility: boolean;
  auditSep38Spreads: boolean;
  auditSep6Polling: boolean;
  auditSep10Jwt: boolean;
  testSep12Upload: boolean;
  sep10Tokens: string[];
  transactionId?: string;
  verifyFederationSrv: boolean;
  auditEsgDisclosures: boolean;
  verifyPorFeed: boolean;
  verifySolanaBridge: boolean;
  auditErc4626Vaults: boolean;
  auditBridgeReplays?: string;
  verifyAttestations: boolean;
  auditBurnRedemptions?: string;
  auditHsts: boolean;
  auditEmergencyPause: boolean;
  auditBridgeQuorum: boolean;
  auditOpenTelemetry: boolean;
  auditOfflinePwa?: string;
  auditEdgeCompatibility?: string;
  crawlPeers: boolean;
  monitorHeartbeat: boolean;
  heartbeatTimeoutSeconds?: number;
  verifyTier1Alignment: boolean;
  tier1Catalog?: string;
  verifyDnssec: boolean;
  auditDnsTakeover: boolean;
  auditSecrets: boolean;
  auditSsrf: boolean;
  auditVaultSecrets: boolean;
  badgeSvg?: string;
  badgeJson?: string;
  exportApConfig?: boolean;
  generateOpenapi?: string;
  webhookSlack?: string;
  webhookDiscord?: string;
  interactive?: boolean;
  checkContracts: boolean;
  auditEvents: boolean;
  auditReentrancy: boolean;
  sorobanRpc?: string;
  graph?: GraphFormat;
  graphIncludeContracts?: boolean;
  graphIncludeValidators?: boolean;
  graphColorByProtocol?: boolean;
  policy?: string;
  mockFixtures?: string;
  lsp?: boolean;
  sortKeys?: boolean;
  dryRun?: boolean;
  detectOrphans?: boolean;
  pruneOrphaned?: boolean;
  allowKeys?: string[];
  runSandboxedPlugin?: string;
  sandboxFuel?: number;
  verifyWasmStreaming?: string;
}

const USAGE = `stellar-toml-lint ${VERSION}

Validate a Stellar Info File (stellar.toml) against SEP-1 — offline.

USAGE
  stellar-toml-lint [file...]            Lint local files (default: ./stellar.toml)
  stellar-toml-lint audit-ciphers --domain <domain> [--port <n>]
  stellar-toml-lint test-kms-signer --key-id <arn> --envelope <xdr>
                                         Sign a transaction envelope with a cloud
                                         KMS key and verify the signature and
                                         Horizon signer weight threshold
  stellar-toml-lint audit-clawbacks --asset <code:issuer> [--horizon <url>] [--format json|markdown]
                                         Generate a clawback audit trail from Horizon
  stellar-toml-lint dispatch-alert --webhook <url> --type slack|discord|pagerduty
                                   [--severity critical|error|warning|info] [--title <text>]
                                   Dispatch an incident, or --resolve to close it
  stellar-toml-lint "configs/**/*.toml"  Lint a glob — quote it so the shell
                                         passes the pattern through instead of
                                         expanding it (or failing to)
  stellar-toml-lint --domain <domain>    Fetch and lint https://<domain>/.well-known/stellar.toml
  cat stellar.toml | stellar-toml-lint - Lint stdin
  stellar-toml-lint --sort-keys [file...]
                                         Reorder table keys into canonical order
                                         in place; --dry-run prints the diff
                                         instead of writing
  stellar-toml-lint migrate [file...]    Rewrite deprecated SEP-1 fields into
                                         their current form in place; --dry-run
                                         prints the diff instead of writing, and
                                         exits 1 when a file still needs work
  stellar-toml-lint --detect-orphans [file...]
                                         Report keys and table headers that
                                         configure nothing, and exit 1 if any
  stellar-toml-lint profile-wasm-heap --wasm <plugin.wasm> --iterations <n>
                                         Run a plugin repeatedly and report heap growth
  stellar-toml-lint sync-directory --feed <url|file> [--format text|json]
                                         Diff a multi-tenant anchor directory feed
                                         against each anchor's live stellar.toml
  stellar-toml-lint benchmark-bridge-latency --receipts <file.json> [--corridor <source-dest>]
                                         Benchmark cross-chain bridge settlement latency (p99 SLA)
  stellar-toml-lint verify-attestations --domain <domain>
                                         Verify reserve attestation PDFs, checksums and freshness
  stellar-toml-lint verify-archive-gpg --url <archive-url> --pubkey <key-file>
                                         Verify the latest ledger checkpoint's detached GPG signature
  stellar-toml-lint refactor <file> [--deduplicate-assets] [--split]
                                    [--max-bytes <n>] [--out-dir <dir>] [--write]
                                          Deduplicate assets / split a large stellar.toml
                                          and print a diff for review
  stellar-toml-lint audit-wasm-simd --file <path.wasm> [--json]
                                         Audit a WASM binary for SIMD opcodes and
                                         unbounded memory growth
  stellar-toml-lint verify-por-feed --domain <domain>
                                         Check Chainlink Proof of Reserve feeds
  stellar-toml-lint verify-solana-bridge --domain <domain>
                                         Check Solana escrow covers Stellar supply
  stellar-toml-lint audit-wormhole-vaa --vaa <hex|base64> [--guardian-set <file.json>]
                                         [--format text|json]
                                         Verify a Wormhole VAA's guardian quorum
  stellar-toml-lint audit-wasm-memory --file <path.wasm> [--format text|json]
                                         Audit a Soroban contract WASM for memory
                                         growth, recursion, unbounded loops and
                                         large stack frames
  stellar-toml-lint auth-tree --xdr <txEnvelopeXdr> [--network <passphrase>]
                              [--rpc-url <url>] [--format text|json]
                                         Parse a Soroban transaction envelope and
                                         render its authorization call tree
  stellar-toml-lint audit-signature-replay --file <path.wasm> [--format text|json]
                                         Detect signature verification that lacks
                                         nonce, domain separation or expiration
  stellar-toml-lint verify-metrics --url <metrics_url> [--format text|json]
                                         Scrape a Prometheus/OpenMetrics endpoint and
                                         validate names, TYPE/HELP and anchor gauges
                                         (--domain discovers it from stellar.toml)
  stellar-toml-lint probe-sla --domain <domain> [--samples <n>] [--threshold-ms <ms>]
                                         Probe SEP /info endpoints read-only and report
                                         p50/p95/p99 TTFB against the SLA (500 ms)
  stellar-toml-lint --audit-error-taxonomy --domain <domain>
                                         Send invalid read-only requests to SEP
                                         endpoints; check RFC 7807 / SEP error JSON
                                         and flag leaked stack traces or secrets
  stellar-toml-lint calculate-uptime --log-file <path> [--format text|markdown|json]
                                         Availability over 24h/7d/30d, incidents and
                                         downtime streaks from JSON/CSV health logs
  stellar-toml-lint format --file <file> [--write]
                                         Format stellar.toml losslessly preserving comments
  stellar-toml-lint verify-rate-headers --url <url> [--burst <n>] [--format text|json]
                                         Verify API rate-limit headers (RFC 6585)
  stellar-toml-lint detect-drift --domain <domain> [--git-path <path>] [--ref <ref>]
                                         [--format text|json|diff] [--timeout <ms>]
                                         [--url <live-url>] [--max-history <n>]
                                         Compare the stellar.toml in Git with the live
                                         one; report unreleased commits and out-of-band
                                         production edits (exit 0 in sync, 1 drift,
                                         2 on fetch/git errors)
  stellar-toml-lint soroban-ttl --domain <domain> [--min-buffer-ledgers <n>]
                                         Audit the remaining TTL of every storage
                                         entry behind the contracts in the file;
                                         exit 1 when any entry is expiring,
                                         critical, or archived
  stellar-toml-lint audit-tls --domain <domain> [--format text|json]
  stellar-toml-lint audit-flood-policy --host <host> [--admin-port <port>] [--format text|json]
                                         Audit SSL/TLS renewal and OCSP stapling health
  stellar-toml-lint audit-key-separation --domain <domain> [--horizon <url>]
                                         [--format text|json]
                                         Map every public key in the file to its roles
                                         and report reused signing, issuer, account and
                                         validator keys
  stellar-toml-lint audit-validator-rotation --domain <domain>
                                         [--previous-signature <sig>]
                                         [--replacement-signature <sig>]
                                         [--peers <quorum.json>] [--format text|json]
                                         Verify a coordinated validator key rotation:
                                         markers, cross-signatures and peer quorum adoption
  stellar-toml-lint diff <a> <b> [--json]
                                         Compare two stellar.toml files, URLs or
                                         - (stdin) by value rather than by line;
                                         exit 1 on a breaking change

OPTIONS
  -d, --domain <domain>   Domain serving the file. Enables CORS, content-type and
                          ORG_URL same-domain checks. Fetches unless files are given.
  -f, --format <fmt>      text (default), json, ndjson, sarif, github, junit, html,
                          checkstyle, or markdown (for GitHub step summaries)
      --strict            Treat warnings as errors
      --max-warnings <n>  Fail if warnings exceed n
      --off <rule>        Disable a rule (repeatable)
      --error <rule>      Raise a rule to error (repeatable)
      --warn <rule>       Lower a rule to warning (repeatable)
      --preset <name>     Start from a role's rule bundle: validator, anchor-sep24,
                          or issuer (see PRESETS)
      --rules-dir <dir>   Load rule plugins from a directory of .js/.mjs/.cjs
                          modules (repeatable). Each module exports one rule as
                          its default export, or a list of rules as "rules".
      --plugin <spec>     Load a rule plugin from a module specifier — a path or
                          an installed package name (repeatable)
  -i, --interactive       Full-screen dashboard to walk the findings. Needs a TTY;
                          without one the text reporter is used instead
      --lsp               Run as a Language Server on stdio (diagnostics,
                          quick-fix code actions, and SEP-1 hover docs)
      --sort-keys         Rewrite files into canonical key order: SEP-1 fields in
                          spec order inside each table, [[CURRENCIES]] sorted by
                          code, [[VALIDATORS]] by public_key, and keys this tool
                          does not know pushed to the end of their table. Leading
                          comments travel with the key they describe.
      --dry-run           With --sort-keys, --prune-orphaned, or the migrate
                          subcommand, print a unified diff and change nothing.
                          Exits 1 when a file is not already in the shape asked
                          for, so CI can check ordering, orphaned keys, and
                          deprecated fields without writing to the tree.
      --detect-orphans    Report every key and table header that matches no
                          field any SEP defines, with a "did you mean" spelling
                          when the name is a near-miss. Exits 1 when a file has
                          any. A near-miss in the wrong table is reported as a
                          move for migrate, not a deletion.
      --prune-orphaned    Apply those findings: rename the near-miss spellings,
                          delete what nothing defines (with the comments
                          attached to it), and leave anything that needs a
                          schema move in place with a warning.
      --allow-key <name>  Accept a name as intentional (repeatable): a bare key
                          (X_ACME_ID), a dotted path (DOCUMENTATION.ORG_NAME),
                          a table name, or a PREFIX_* glob that blesses a whole
                          vendor section. Also read from "knownKeys" in
                          .stellartomlrc.json.
  -q, --quiet             Report errors only
      --show-help-urls    Print the spec link for each finding
      --no-suggestions    Hide diagnostic suggestions in the output
      --health-check      Ping declared endpoint URLs to ensure they are live
      --check-network     Verify SIGNING_KEY, ACCOUNTS, HORIZON_URL, SEP-8
                          regulated issuer flags, and ANCHOR_QUOTE_SERVER
                          against the network
      --verify-sep10      Verify SEP-10 nonce uniqueness and replay resistance
      --audit-quotes      Book an ANCHOR_QUOTE_SERVER SEP-38 quote and execute it on
                          TRANSFER_SERVER to verify atomic price and fee execution
      --audit-unicode-security
                          Detect bidi overrides, invisible characters, homoglyph
                          spoofing, and malformed language tags in string values
      --audit-consumer-protection
                          Verify complaints, dispute, jurisdiction and license
                          disclosures and print a scorecard (add --check-network
                          to probe the dispute URL)
      --audit-sep30-recovery
                          Verify RECOVERY_SERVER and recovery signing keys, and
                          (with --check-network) probe /accounts/{address} for
                          unauthenticated recovery
      --verify-promotions Compare promotional fee claims against SEP-38 quote
                          fees (with --check-network); also available as
                          'verify-promotions --domain <domain>'
  stellar-toml-lint verify-sep31-sep12 --domain <domain> [--format text|json]
                                         Cross-check the fields advertised by SEP-31
                                         /info against the SEP-12 customer schemas
      --audit-sep38-volatility
                          Sample GET /prices and POST /quote through simulated
                          SDEX shocks; flag quote windows over the 60s volatility
                          buffer, stale rates and missing circuit breakers; also
                          available as 'sep38-volatility --domain <domain>'
      --audit-sep38-spreads
                          Price small, medium and large trades through both
                          GET /prices and POST /quote, flag firm spreads beyond
                          the configured tolerance or disclosed fees, and verify
                          expired quotes are refused; also available as
                          'sep38-spreads --domain <domain>'
      --audit-sep6-polling
                          Repeat GET /transaction at 2s/5s/10s cadences to check
                          idempotency, cache headers and rate-limit signals (use
                          with --transaction-id and --sep10-token)
      --audit-sep10-jwt   Decode --sep10-token JWTs and verify claims, lifetime,
                          signature algorithm and client_domain binding
      --test-sep12-upload Send executable, oversized and MIME-spoofed documents
                          to PUT /customer/verification and check rejection (use
                          with --sep10-token)
      --sep10-token <jwt> SEP-10 token for the SEP-6, SEP-10 and SEP-12 audits
                          (repeatable)
      --transaction-id <id>
                          Existing SEP-6 transfer to poll with --audit-sep6-polling
      --verify-federation-srv
                          Check _stellar-federation._tcp.<domain> SRV records
                          against FEDERATION_SERVER (use with --domain)
      --audit-bridge-replays <evidence.json>
                          Match EVM lock event logs to Stellar mints and flag
                          duplicate, unrecorded or replayable events
      --verify-attestations
                          Verify DOCUMENTATION.ATTESTATIONS checksums and age
                          (downloads PDFs with --check-network)
      --audit-burn-redemptions <evidence.json>
                          Verify wrapped-asset redemptions burn supply
      --audit-esg-disclosures
                          Verify DOCUMENTATION.ORG_ESG disclosures, check the
                          attestation signature with --check-network, and print
                          a sustainability rating
      --verify-por-feed   Check Chainlink Proof of Reserve feeds declared in
                          DOCUMENTATION.PROOF_OF_RESERVES for freshness and
                          collateralization (queries with --check-network)
      --verify-solana-bridge
                          Check that Solana escrow balances cover the Stellar
                          supply of CURRENCIES[].solana_bridge assets
      --audit-erc4626-vaults
                          Audit CURRENCIES[].collateral_vaults ERC-4626 share
                          prices and NAV backing (queries with --check-network)
      --audit-hsts        Check Strict-Transport-Security on the domain and every
                          host stellar.toml declares, against the Chromium
                          preload criteria (use with --domain)
      --audit-emergency-pause
                          Check [[BRIDGES]] export pause methods, restrict pause
                          authority and publish a 24/7 security contact
      --audit-bridge-quorum
                          Check [[BRIDGES]] relayer thresholds against the 2/3 BFT
                          supermajority and staking evidence; also available as
                          'audit-bridge-quorum --domain <domain>'
      --audit-opentelemetry
                          Probe declared SEP-6, SEP-24, SEP-31 and SEP-38 /info
                          endpoints with W3C trace context and inspect response evidence
      --audit-offline-pwa <path>
                          Audit a Service Worker script (or manifest.json) for offline
                          precaching, cache versioning, and PWA manifest requirements
      --audit-edge-compatibility <path>
                          Check a bundle for Node-only APIs and measure its cold start
                          and heap against Cloudflare Workers limits
      --audit-kyc-fsm     Audit SEP-12 customer status state machines advertised by
                          KYC_SERVER and DIRECT_PAYMENT_SERVER (use with --domain)
      --audit-federation-security
                          Probe FEDERATION_SERVER with non-destructive injection
                          payloads and check for leaked internals (use with --domain)
      --audit-cors        Send browser-shaped pre-flight and actual requests to every
                          declared endpoint and report wildcard-with-credentials CORS
                          policies and unvalidated Origin echoing
      --audit-asset-security
                          Check the Content-Type and X-Content-Type-Options of every
                          linked logo, image and document, and scan SVG payloads for
                          scripts and entity declarations
      --audit-clickjacking
                          Probe interactive endpoints for Content-Security-Policy
                          frame-ancestors and X-Frame-Options framing defenses
      --crawl-peers       Discover overlay peers with GET_PEERS and check connectivity
      --monitor-heartbeat  Establish an overlay session with every advertised validator
                          and report ping/pong latency, jitter and keepalive state
      --timeout <seconds> Monitoring window for --monitor-heartbeat (default: 10)
      --verify-tier1-alignment
                          Cross-reference the [QUORUM_SET] (or QUALITY-rated
                          [[VALIDATORS]]) against the Tier-1 validator catalog and
                          flag slices that can agree without the consensus core
      --tier1-catalog <file.json>
                          Tier-1 catalog for --verify-tier1-alignment (default:
                          bundled snapshot; see docs/schemas/tier1-catalog.schema.json)
      --verify-dnssec     Compare A/AAAA answers across DNSSEC-validating DoH resolvers
       --audit-dns-takeover
                           Query CNAME/NS records for every referenced domain and
                           flag dangling pointers to claimable cloud resources
       --audit-secrets     Halt with exit 1 on leaked Stellar seeds, cloud keys,
                           bearer tokens or PEM blocks; output is always redacted
       --audit-vault-secrets
                           Halt with exit 1 on misconfigured Vault secret engine
                           paths, exposed tokens, and TTL misconfigurations
       --audit-ssrf        Flag advertised URLs resolving to private, loopback,
                           link-local or multicast IPs, including DNS rebinding
      --follow-links      Fetch and lint the toml pointers in CURRENCIES
                          (implied by --domain)
      --check-contracts   Verify Soroban contract and WASM TTL liveliness
      --audit-reentrancy  Statically audit each contract's WASM for missing
                          reentrancy guards, non-atomic cross-contract writes,
                          and recursive call graphs
      --audit-events      Verify the event schema and indexing topics of every
                          contract the file advertises, via its WASM spec and
                          simulated emissions
      --soroban-rpc <url> Soroban RPC endpoint to use with --check-contracts
                          and --audit-events
      --mock-fixtures <dir>
                          Serve network checks from recorded JSON responses under
                          <dir> instead of the network. A URL with no fixture
                          fails instead of making a request (hermetic CI)
      --webhook-slack <url>
                          POST a Slack Block Kit card with the run summary
      --webhook-discord <url>
                          POST a Discord embed with the run summary
      --badge-svg <file>  Generate an SVG compliance badge
      --badge-json <file> Generate a Shields.io JSON endpoint
      --export-ap-config  Export Anchor Platform YAML config to stdout
      --generate-openapi <file>
                          Generate an OpenAPI 3.1 spec (json or yaml extension)
      --graph <fmt>       Generate architecture diagram: mermaid or dot
      --graph-contracts   Include Soroban contracts in diagram
      --graph-validators  Include validators in diagram
      --graph-color       Color nodes by protocol type
      --policy <file>     Evaluate enterprise policy file (JSON or YAML)
      --verify-wasm-streaming <url>
                          Check that a .wasm URL is served as application/wasm and
                          benchmark instantiateStreaming against buffered compile
      verify-archive-gpg --url <archive-url> --pubkey <key-file>
                          [--signature-url <url>] [--trusted-fingerprint <hex>]
                          [--format text|json] [--timeout <ms>]
                          Checks the latest ledger checkpoint's optional .sig sidecar
      --run-sandboxed-plugin <file.wasm>
                          Run a third-party validator plugin inside the WASI
                          preview 1 capability sandbox: in-memory files only,
                          no host filesystem, fuel-metered execution
      --sandbox-fuel <n>  Instruction budget for --run-sandboxed-plugin
                          (default 5000000)
      --json-schema       Print a JSON Schema (Draft 2020-12) for stellar.toml
                          to stdout, for editor autocompletion via schema
                          associations
      --color / --no-color
      --list-rules        Print every rule and exit

test-kms-signer OPTIONS
  --key-id <id>       AWS KMS ARN, GCP Cloud KMS resource name, or Azure Key
                      Vault key URL. Credentials come from the provider's
                      standard environment variables only
  --envelope <xdr>    Base64 transaction envelope to sign
  --network <name>    Network passphrase (default: Stellar public network)
  --horizon <url>     Horizon base URL for the signer weight audit
  --account <G...>    Account to audit (default: the envelope source)
  --signer-key <G...> Override the Stellar signer matched to the KMS key
  --threshold <level> low, medium (default), or high
  --no-quorum         Skip the Horizon signer weight audit
  --no-verify         Skip local signature verification
  --mock-fixtures <dir>
                      Serve the Horizon audit from recorded JSON fixtures
  --json              Emit the report as JSON

      --completion <sh>   Print a shell completion script for bash, zsh, or fish
                          (e.g. eval "$(stellar-toml-lint --completion zsh)")
  -v, --version
  -h, --help

init-ci OPTIONS
  --matrix <envs>     Comma-separated environments: development, staging,
                      testnet, public (aliases: dev, stage, prod, mainnet).
                      Default: testnet,public
  --node <versions>   Comma-separated Node.js versions; the first is primary
                      and uploads SARIF and the scorecard. Default: 20,22
  --file-pattern <p>  Tenant file path; {environment} is substituted.
                      Default: environments/{environment}/stellar.toml
  --file <env>=<path> Override one environment's path (repeatable)
  --output <path>     Default: .github/workflows/stellar-toml-lint-matrix.yml
  --check-network / --no-check-network
                      Force live link, TLS and Horizon checks on or off for
                      every environment (default: on for testnet and public)
  --strict            Treat warnings as failures
  --no-sarif          Skip code scanning upload
  --no-pr-comment     Skip the pull request scorecard bot
  --no-cache          Skip tool and remote asset caching
  --stdout            Print the workflow instead of writing it
  --force             Overwrite an existing workflow file

ENVIRONMENT
  STELLAR_TOML_LINT_ASSET_CACHE=<dir>
                      Cache fetched logos, JSON schemas and IPFS content under
                      <dir> for 24 hours (set automatically by init-ci workflows)

CONFIG
  .stellartomlrc.json    Project defaults, discovered upward from the linted
                         file's directory (from the current directory for stdin
                         and --domain), stopping at the filesystem root.
                         Recognises "rules", "strict", "maxWarnings", and
                         "knownKeys" (the same names as --allow-key).
                         CLI flags always override the file; a malformed config
                         or an unknown rule id exits with code 2.

PRESETS
  --preset <name>        Apply a role's rule bundle before anything else, so a
                         team that is only half an ecosystem does not have to
                         copy a long --off chain into every workflow:

    validator            [[VALIDATORS]] and general file checks stay on; the
                         currency issuance and anchor service rules are off.
                         Duplicate validator hosts and aliases fail the build.
    anchor-sep24         SEP-24, SEP-10, and currency requirements at error
                         (a transfer server with no [[CURRENCIES]], an
                         incomplete SEP-45 pair, an undescribed anchored
                         asset). Validator rules are off — an anchor runs no
                         validator nodes.
    issuer               Currency, collateral, and documentation completeness
                         at error. Anchor service rules are off — a standalone
                         issuer runs no servers.

                         A preset is a baseline, not a policy: an explicit
                         --off, --warn, or --error on the same command line
                         still wins, whatever order the flags appear in. For the
                         same reason a preset overrides .stellartomlrc.json.
                         An unknown name lists the available presets and exits
                         with code 2.

EXIT CODES
  0  no errors     1  errors found     2  bad usage, unmatched glob, or I/O failure

EXAMPLES
  stellar-toml-lint public/.well-known/stellar.toml
  stellar-toml-lint "accounts/*/stellar.toml"
  stellar-toml-lint --domain example.com --strict
  stellar-toml-lint --preset validator public/.well-known/stellar.toml
  stellar-toml-lint -f sarif > results.sarif
  stellar-toml-lint --graph mermaid > diagram.mmd
  stellar-toml-lint --graph dot --graph-contracts > diagram.dot
  stellar-toml-lint --policy policy.yaml public/.well-known/stellar.toml
  stellar-toml-lint --sort-keys --dry-run          # show the reorder, change nothing
  stellar-toml-lint --sort-keys                    # apply it
  stellar-toml-lint public/.well-known/stellar.toml --check-network \\\\
    --mock-fixtures ./test/fixtures/network
`;

/** Opt-in audits that run on the parsed document, on top of the standard rules. */
async function runExtraAudits(
  cli: Cli,
  parsed: Record<string, unknown>,
  fetchImpl: typeof fetch,
  rules: RuleOverrides,
  domain?: string,
): Promise<Diagnostic[]> {
  const out: Diagnostic[] = [];
  if (cli.auditUnicodeSecurity) out.push(...validateUnicode(parsed, { rules }));
  if (cli.auditConsumerProtection) {
    const result = await auditConsumerProtection(parsed, fetchImpl, {
      rules,
      checkReachability: cli.checkNetwork,
    });
    out.push(...result.diagnostics);
    // stderr keeps machine-readable stdout formats parseable.
    process.stderr.write(renderScorecard(result.scorecard));
  }
  if (cli.auditKycFsm) {
    const result = await auditKycStateMachines(parsed, fetchImpl, { rules });
    out.push(...result.diagnostics);
    for (const model of result.models) process.stderr.write(renderKycDiagram(model));
  }
  if (cli.auditFederationSecurity) {
    const result = await auditFederationSecurity(parsed, fetchImpl, { rules });
    out.push(...result.diagnostics);
    process.stderr.write(renderFederationSecurityReport(result.report));
  }
  if (cli.auditSep30Recovery) {
    const result = await auditSep30Recovery(parsed, fetchImpl, { rules, probe: cli.checkNetwork });
    out.push(...result.diagnostics);
  }
  if (cli.auditCors) {
    const result = await auditCors(parsed, fetchImpl, {
      rules,
      ...(domain === undefined ? {} : { domain }),
    });
    out.push(...result.diagnostics);
    process.stderr.write(renderCorsReport(result.report));
  }
  if (cli.auditAssetSecurity) {
    const result = await auditAssetSecurity(parsed, fetchImpl, { rules });
    out.push(...result.diagnostics);
    process.stderr.write(renderMimeReport(result.report));
  }
  if (cli.auditClickjacking) {
    const result = await auditClickjacking(parsed, fetchImpl, { rules });
    out.push(...result.diagnostics);
    process.stderr.write(renderClickjackingReport(result.report));
  }
  if (cli.verifyPromotions) {
    const result = await verifyPromotions(parsed, fetchImpl, {
      rules,
      checkQuotes: cli.checkNetwork,
    });
    out.push(...result.diagnostics);
  }
  if (cli.auditSep38Volatility) {
    const result = await verifySep38Volatility(parsed, fetchImpl, { rules });
    out.push(...result.diagnostics);
  }
  if (cli.auditSep38Spreads && (cli.checkNetwork || domain !== undefined)) {
    const result = await auditSep38QuoteDiscrepancies(parsed, fetchImpl, { rules });
    out.push(...result.diagnostics);
  }
  if (cli.auditSep6Polling) {
    const result = await auditSep6Polling(parsed, fetchImpl, {
      rules,
      ...(cli.transactionId === undefined ? {} : { transactionId: cli.transactionId }),
      ...(cli.sep10Tokens[0] === undefined ? {} : { token: cli.sep10Tokens[0] }),
    });
    out.push(...result.diagnostics);
  }
  if (cli.auditSep10Jwt) {
    const result = await auditSep10Jwt(parsed, fetchImpl, {
      rules,
      tokens: cli.sep10Tokens,
      ...(domain === undefined ? {} : { expectedDomain: domain }),
    });
    out.push(...result.diagnostics);
  }
  if (cli.testSep12Upload) {
    const result = await testSep12FileUploads(parsed, fetchImpl, {
      rules,
      ...(cli.sep10Tokens[0] === undefined ? {} : { token: cli.sep10Tokens[0] }),
    });
    out.push(...result.diagnostics);
  }
  if (cli.verifyFederationSrv && domain !== undefined) {
    const result = await verifyFederationSrv(parsed, fetchImpl, {
      rules,
      domain,
      probe: cli.checkNetwork,
    });
    out.push(...result.diagnostics);
  }
  if (cli.auditEsgDisclosures) {
    const result = await auditEsgDisclosures(parsed, fetchImpl, {
      rules,
      checkAttestation: cli.checkNetwork,
    });
    out.push(...result.diagnostics);
    process.stderr.write(renderEsgReport(result.report));
  }
  if (cli.verifyPorFeed) {
    const result = await verifyPorFeeds(parsed, fetchImpl, { rules, probe: cli.checkNetwork });
    out.push(...result.diagnostics);
  }
  if (cli.verifySolanaBridge) {
    const result = await verifySolanaBridges(parsed, fetchImpl, {
      rules,
      probe: cli.checkNetwork,
    });
    out.push(...result.diagnostics);
  }
  if (cli.auditErc4626Vaults) {
    const result = await auditErc4626Vaults(parsed, fetchImpl, {
      rules,
      probe: cli.checkNetwork,
    });
    out.push(...result.diagnostics);
  }
  if (cli.auditBridgeReplays !== undefined) {
    out.push(
      ...auditBridgeReplays(await readEvidence(cli.auditBridgeReplays), { rules }).diagnostics,
    );
  }
  if (cli.verifyAttestations) {
    const result = await verifyBankAttestations(parsed, fetchImpl, {
      rules,
      download: cli.checkNetwork,
    });
    out.push(...result.diagnostics);
  }
  if (cli.auditBurnRedemptions !== undefined) {
    const result = auditBurnRedemptions(parsed, await readEvidence(cli.auditBurnRedemptions), {
      rules,
    });
    out.push(...result.diagnostics);
    process.stderr.write(renderBurnReport(result));
  }
  if (cli.auditHsts) {
    const result = await auditHsts(parsed, fetchImpl, { rules, ...(domain ? { domain } : {}) });
    out.push(...result.diagnostics);
    process.stderr.write(renderHstsBadges(result));
  }
  if (cli.auditEmergencyPause) out.push(...auditEmergencyPause(parsed, { rules }).diagnostics);
  if (cli.auditBridgeQuorum) {
    const result = await auditBridgeQuorum(parsed, fetchImpl, { rules, probe: cli.checkNetwork });
    out.push(...result.diagnostics);
  }
  if (cli.auditDnsTakeover) {
    const report = await scanSubdomainTakeover(parsed, { rules, fetchImpl, domain });
    out.push(...takeoverDiagnostics(report, rules));
    process.stderr.write(renderTakeoverReport(report));
  }
  if (cli.auditSsrf) {
    const report = await scanSsrf(parsed, { rules, fetchImpl, domain });
    out.push(...ssrfDiagnostics(report, rules));
    process.stderr.write(renderSsrfReport(report));
  }
  if (cli.auditOpenTelemetry) {
    const verifier = new OpenTelemetryTraceValidator(
      // Recorded fixture transport is explicitly requested; ordinary network
      // probes use the verifier's DNS-pinned HTTPS transport.
      cli.mockFixtures === undefined ? {} : { fetchImpl },
    );
    const result = await verifier.verify(parsed, rules);
    out.push(...result.diagnostics);
    process.stderr.write(renderTraceAuditReport(result));
  }
  if (cli.verifyTier1Alignment) {
    const catalog =
      cli.tier1Catalog === undefined
        ? DEFAULT_TIER1_CATALOG
        : parseTier1Catalog(JSON.parse(await readFile(cli.tier1Catalog, 'utf8')) as unknown);
    const report = new Tier1QuorumAlignmentVerifier({ rules, catalog }).verify(parsed);
    out.push(...report.diagnostics);
    process.stderr.write(renderTier1AlignmentReport(report));
  }
  if (cli.monitorHeartbeat) {
    const endpoints = parseValidatorEndpoints(parsed);
    const timeoutMs = (cli.heartbeatTimeoutSeconds ?? 10) * 1000;
    if (endpoints.length === 0) {
      process.stderr.write(
        '--monitor-heartbeat: no [[VALIDATORS]] endpoints with HOST/PORT were advertised.\n',
      );
    }
    for (const endpoint of endpoints) {
      const report = await new OverlayHeartbeatWatchdog({ timeoutMs }).watch({
        host: endpoint.host,
        port: endpoint.port,
        ...(endpoint.publicKey === '' ? {} : { publicKey: endpoint.publicKey }),
      });
      // Monitoring output goes to stderr so --format json stays parseable.
      process.stderr.write(renderHeartbeatReport(report));
      if (report.ok) continue;

      const where = endpoint.path === undefined ? 'VALIDATORS' : `${endpoint.path}.HOST`;
      if (report.suddenClosure !== undefined) {
        out.push({
          rule: HEARTBEAT_SUDDEN_CLOSURE,
          severity: 'error',
          category: 'network',
          message: `Overlay session with ${endpoint.rawEndpoint} closed before a heartbeat was acknowledged: ${report.suddenClosure}`,
          path: where,
          suggestion:
            'Check middlebox idle timeouts and the peer logs, then reconnect and verify the peer is still in the validator set before routing consensus traffic through it.',
        });
      } else if (report.metrics.probesAcknowledged === 0) {
        out.push({
          rule: HEARTBEAT_UNRESPONSIVE,
          severity: 'error',
          category: 'network',
          message: `Advertised validator ${endpoint.rawEndpoint} did not acknowledge a single heartbeat within ${timeoutMs}ms`,
          path: where,
          suggestion:
            'Confirm the overlay port is reachable from your network and that the peer accepts heartbeat probes; remove it from rotation until it answers.',
        });
      } else if (report.metrics.erratic) {
        out.push({
          rule: HEARTBEAT_ERRATIC,
          severity: 'warning',
          category: 'network',
          message: `Validator ${endpoint.rawEndpoint} returned erratic heartbeat responses (${report.metrics.probesMissed} missed, jitter ${report.metrics.jitterMs?.toFixed(1) ?? 'n/a'}ms)`,
          path: where,
          suggestion:
            'Check the network path for packet loss before relying on this peer for quorum; stable latency matters more than the absolute value.',
        });
      }
    }
  }
  return out;
}

/** Recorded evidence files are JSON; an unreadable one is reported by the audit as invalid. */
async function readEvidence(path: string): Promise<unknown> {
  try {
    return JSON.parse(await readFile(resolve(path), 'utf8'));
  } catch {
    return undefined;
  }
}

/** `stellar-toml-lint benchmark-bridge-latency --receipts <file> [--corridor <s-d>]` */
async function benchmarkBridgeLatencyCommand(args: string[]): Promise<number> {
  let receipts: string | undefined;
  let corridor: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    if (arg === '--receipts') receipts = requireValue(args, ++i, arg);
    else if (arg === '--corridor') corridor = requireValue(args, ++i, arg);
    else {
      process.stderr.write(`Unknown option ${arg} for benchmark-bridge-latency\n`);
      return 2;
    }
  }
  if (receipts === undefined) {
    process.stderr.write(
      'Usage: stellar-toml-lint benchmark-bridge-latency --receipts <file.json> [--corridor <source-dest>]\n',
    );
    return 2;
  }
  const result = benchmarkBridgeLatency(await readEvidence(receipts), { corridor });
  process.stdout.write(renderLatencyReport(result.corridors));
  for (const d of result.diagnostics)
    process.stderr.write(`${d.severity}: ${d.message} [${d.rule}]\n`);
  return result.diagnostics.some((d) => d.severity === 'error') ? 1 : 0;
}

/** `stellar-toml-lint audit-ciphers --domain <domain> [--port <n>]` */
async function auditCiphersCommand(args: string[]): Promise<number> {
  let domain: string | undefined;
  let port: number | undefined;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    if (arg === '--domain') domain = requireValue(args, ++i, arg);
    else if (arg === '--port') port = Number(requireValue(args, ++i, arg));
    else {
      process.stderr.write(`Unknown option ${arg} for audit-ciphers\n`);
      return 2;
    }
  }
  if (domain === undefined || (port !== undefined && !Number.isInteger(port))) {
    process.stderr.write('Usage: stellar-toml-lint audit-ciphers --domain <domain> [--port <n>]\n');
    return 2;
  }
  const host = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  const result = await auditTlsCiphers(host, port === undefined ? {} : { port });
  process.stdout.write(renderCipherReport(result.report));
  for (const d of result.diagnostics) {
    process.stdout.write(`${d.severity}: ${d.message} [${d.rule}]\n`);
  }
  return result.report.grade === 'F' || result.report.grade === null ? 1 : 0;
}

/**
 * Secrets are the one audit that halts the whole run: a leaked credential must
 * never reach a reporter (SARIF embeds source snippets) and no further network
 * work should happen with a compromised key in hand. All output is masked.
 */
async function auditSecretsOrHalt(
  parsed: Record<string, unknown> | undefined,
  source: string | undefined,
  rules: RuleOverrides,
): Promise<number | undefined> {
  const result = scanSecrets(source ?? '', parsed, { rules });
  if (!result.halt) return undefined;
  process.stderr.write(renderSecretReport(result));
  return 1;
}

/** `stellar-toml-lint audit-clawbacks --asset CODE:ISSUER [--horizon <url>] [--format json|markdown]` */
async function auditClawbacks(args: string[]): Promise<number> {
  let asset: string | undefined;
  let horizon = DEFAULT_HORIZON;
  let format = 'markdown';
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    if (arg === '--asset') asset = requireValue(args, ++i, arg);
    else if (arg === '--horizon') horizon = requireValue(args, ++i, arg);
    else if (arg === '--format') format = requireValue(args, ++i, arg);
    else {
      process.stderr.write(`Unknown option ${arg} for audit-clawbacks\n`);
      return 2;
    }
  }
  if (asset === undefined || (format !== 'json' && format !== 'markdown')) {
    process.stderr.write(
      'Usage: stellar-toml-lint audit-clawbacks --asset <code:issuer> [--horizon <url>] [--format json|markdown]\n',
    );
    return 2;
  }
  try {
    const report = await new ClawbackAuditTrailGenerator(fetch, horizon).generate(
      parseAsset(asset),
    );
    process.stdout.write(
      format === 'json' ? renderClawbackJson(report) : renderClawbackMarkdown(report),
    );
    return report.unreferenced > 0 ? 1 : 0;
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }
}

/** `stellar-toml-lint dispatch-alert --webhook <url> --type slack|discord|pagerduty ...` */
async function dispatchAlert(args: string[]): Promise<number> {
  let webhook: string | undefined;
  let type: IncidentChannel | undefined;
  let severity: IncidentSeverity = 'warning';
  let title = 'stellar-toml-lint alert';
  let summary: string | undefined;
  let source: string | undefined;
  let rule: string | undefined;
  let dedupKey: string | undefined;
  let routingKey: string | undefined;
  let throttleMs: number | undefined;
  let resolved = false;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    if (arg === '--webhook') webhook = requireValue(args, ++i, arg);
    else if (arg === '--type') type = requireValue(args, ++i, arg) as IncidentChannel;
    else if (arg === '--severity') severity = requireValue(args, ++i, arg) as IncidentSeverity;
    else if (arg === '--title') title = requireValue(args, ++i, arg);
    else if (arg === '--summary') summary = requireValue(args, ++i, arg);
    else if (arg === '--source') source = requireValue(args, ++i, arg);
    else if (arg === '--rule') rule = requireValue(args, ++i, arg);
    else if (arg === '--dedup-key') dedupKey = requireValue(args, ++i, arg);
    else if (arg === '--routing-key') routingKey = requireValue(args, ++i, arg);
    else if (arg === '--throttle-ms') throttleMs = Number(requireValue(args, ++i, arg));
    else if (arg === '--resolve') resolved = true;
    else {
      process.stderr.write(`Unknown option ${arg} for dispatch-alert\n`);
      return 2;
    }
  }

  if (webhook === undefined || type === undefined) {
    process.stderr.write(
      'Usage: stellar-toml-lint dispatch-alert --webhook <url> --type slack|discord|pagerduty ' +
        '[--severity critical|error|warning|info] [--title <text>] [--resolve]\n',
    );
    return 2;
  }
  if (type !== 'slack' && type !== 'discord' && type !== 'pagerduty') {
    process.stderr.write(`Unknown alert type "${type}". Expected slack, discord, or pagerduty.\n`);
    return 2;
  }

  const dispatcher = new IncidentWebhookDispatcher({
    ...(throttleMs !== undefined ? { throttleMs } : {}),
  });
  const targets = {
    ...(type === 'slack'
      ? { slack: webhook }
      : type === 'discord'
        ? { discord: webhook }
        : { pagerduty: webhook }),
    ...(routingKey !== undefined ? { pagerdutyRoutingKey: routingKey } : {}),
  };
  const incident = {
    title,
    severity,
    ...(summary !== undefined ? { summary } : {}),
    ...(source !== undefined ? { source } : {}),
    ...(rule !== undefined ? { rule } : {}),
    ...(dedupKey !== undefined ? { dedupKey } : {}),
  };

  const deliveries = resolved
    ? await dispatcher.resolve(incident, targets)
    : await dispatcher.dispatch(incident, targets, { force: true });
  process.stdout.write(renderIncidentReport(deliveries));
  return deliveries.every((delivery) => delivery.ok) ? 0 : 1;
}

/** `stellar-toml-lint --audit-offline-pwa <sw.js|manifest.json>` */
async function auditOfflinePwa(input: string): Promise<number> {
  const path = resolve(input);
  const readOptional = async (candidate: string): Promise<string | undefined> => {
    try {
      return await readFile(candidate, 'utf8');
    } catch {
      return undefined;
    }
  };

  try {
    const source = await readFile(path, 'utf8');
    const isManifest = path.toLowerCase().endsWith('.json');
    const serviceWorkerSource = isManifest
      ? ((await readOptional(resolve(dirname(path), 'sw.js'))) ??
        (await readOptional(resolve(dirname(path), 'service-worker.js'))) ??
        '')
      : source;
    const manifestSource = isManifest
      ? source
      : ((await readOptional(resolve(dirname(path), 'manifest.json'))) ?? '{}');

    const result = validateOfflinePwa(serviceWorkerSource, manifestSource);
    process.stdout.write(renderOfflineReport(result));
    return result.ok ? 0 : 1;
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }
}

/** `stellar-toml-lint --audit-edge-compatibility <bundle.js>` */
async function auditEdgeCompatibility(input: string): Promise<number> {
  try {
    const source = await readFile(resolve(input), 'utf8');
    const result = verifyEdgeCompatibility(source);
    process.stdout.write(renderEdgeReport(result));
    return result.compatible ? 0 : 1;
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }
}

/** `stellar-toml-lint sync-directory --feed <url|file> [--format text|json]` */
async function syncDirectory(args: string[]): Promise<number> {
  let feed: string | undefined;
  let format: 'text' | 'json' = 'text';
  let concurrency = 8;
  let timeoutMs = 10_000;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    if (arg === '--feed') feed = requireValue(args, ++i, arg);
    else if (arg === '--format') {
      const value = requireValue(args, ++i, arg);
      if (value !== 'text' && value !== 'json') {
        process.stderr.write(`Unknown format "${value}". Expected text or json.\n`);
        return 2;
      }
      format = value;
    } else if (arg === '--concurrency') {
      const value = Number(requireValue(args, ++i, arg));
      if (!Number.isInteger(value) || value < 1) {
        process.stderr.write('--concurrency expects a positive integer.\n');
        return 2;
      }
      concurrency = value;
    } else if (arg === '--timeout') {
      const value = Number(requireValue(args, ++i, arg));
      if (!Number.isFinite(value) || value <= 0) {
        process.stderr.write('--timeout expects a positive number of milliseconds.\n');
        return 2;
      }
      timeoutMs = value;
    } else {
      process.stderr.write(`Unknown option ${arg} for sync-directory\n`);
      return 2;
    }
  }

  if (feed === undefined) {
    process.stderr.write(
      'Usage: stellar-toml-lint sync-directory --feed <url|file> [--format text|json] ' +
        '[--concurrency <n>] [--timeout <ms>]\n',
    );
    return 2;
  }

  try {
    let payload: unknown;
    if (/^https?:\/\//i.test(feed)) {
      const response = await fetch(feed);
      if (!response.ok) throw new Error(`Could not fetch ${feed}: HTTP ${response.status}`);
      payload = await response.json();
    } else {
      payload = JSON.parse(await readFile(resolve(feed), 'utf8'));
    }

    const parsedFeed = parseDirectoryFeed(payload);
    const report = await new DirectorySyncVerifier({ concurrency, timeoutMs }).verify(
      parsedFeed.anchors,
      feed,
    );
    process.stdout.write(
      format === 'json'
        ? `${JSON.stringify(report, null, 2)}\n`
        : renderDirectorySyncReport(report),
    );
    for (const problem of parsedFeed.problems) process.stderr.write(`feed: ${problem}\n`);
    return report.ok ? 0 : 1;
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }
}

async function readArchivePublicKey(input: string): Promise<string> {
  const maxBytes = 1024 * 1024;
  if (input.includes('-----BEGIN PGP PUBLIC KEY BLOCK-----')) {
    if (Buffer.byteLength(input, 'utf8') > maxBytes) {
      throw new Error('The supplied public key exceeds the 1 MiB size limit');
    }
    return input;
  }

  const stream = createReadStream(resolve(input));
  const chunks: Buffer[] = [];
  let size = 0;
  try {
    for await (const chunk of stream) {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      size += bytes.length;
      if (size > maxBytes) {
        throw new Error('The public key file exceeds the 1 MiB size limit');
      }
      chunks.push(bytes);
    }
  } finally {
    stream.destroy();
  }
  return Buffer.concat(chunks, size).toString('utf8');
}

/** `stellar-toml-lint verify-archive-gpg --url <archive-url> --pubkey <key-file>` */
async function verifyArchiveGpgCommand(args: string[]): Promise<number> {
  let archiveUrl: string | undefined;
  let publicKeyInput: string | undefined;
  let signatureUrl: string | undefined;
  let trustedFingerprint: string | undefined;
  let format: 'text' | 'json' = 'text';
  let timeoutMs = 10_000;

  try {
    for (let index = 0; index < args.length; index++) {
      const arg = args[index] as string;
      if (arg === '--url') archiveUrl = requireValue(args, ++index, arg);
      else if (arg === '--pubkey') publicKeyInput = requireValue(args, ++index, arg);
      else if (arg === '--signature-url') signatureUrl = requireValue(args, ++index, arg);
      else if (arg === '--trusted-fingerprint') {
        trustedFingerprint = requireValue(args, ++index, arg);
      } else if (arg === '--format') {
        const value = requireValue(args, ++index, arg);
        if (value !== 'text' && value !== 'json') {
          process.stderr.write(`Unknown format "${value}". Expected text or json.\n`);
          return 2;
        }
        format = value;
      } else if (arg === '--timeout') {
        timeoutMs = Number(requireValue(args, ++index, arg));
        if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) {
          process.stderr.write('--timeout expects an integer from 1 to 120000 milliseconds.\n');
          return 2;
        }
      } else {
        process.stderr.write(`Unknown option ${arg} for verify-archive-gpg\n`);
        return 2;
      }
    }
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }

  if (archiveUrl === undefined || publicKeyInput === undefined) {
    process.stderr.write(
      'Usage: stellar-toml-lint verify-archive-gpg --url <archive-url> --pubkey <key-file> ' +
        '[--signature-url <url>] [--trusted-fingerprint <hex>] [--format text|json]\n',
    );
    return 2;
  }

  try {
    const publicKey = await readArchivePublicKey(publicKeyInput);
    const verifier = new ArchiveGpgVerifier({ timeoutMs });
    const result = await verifier.verifyArchive({
      archiveUrl,
      publicKey,
      ...(signatureUrl === undefined ? {} : { signatureUrl }),
      ...(trustedFingerprint === undefined ? {} : { trustedFingerprint }),
    });
    if (format === 'json') {
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    } else {
      process.stdout.write(`Archive GPG verification: ${result.status.toUpperCase()}\n`);
      if (result.checkpointSequence !== undefined) {
        process.stdout.write(`Checkpoint ledger: ${result.checkpointSequence}\n`);
      }
      if (result.payloadUrl !== undefined) process.stdout.write(`Payload: ${result.payloadUrl}\n`);
      if (result.signatureUrl !== undefined) {
        process.stdout.write(`Signature: ${result.signatureUrl}\n`);
      }
      for (const signer of result.signers) {
        process.stdout.write(
          `Signing key: ${signer.fingerprint} (${signer.algorithm}${signer.keyBits === undefined ? '' : `, ${signer.keyBits} bits`})\n`,
        );
        process.stdout.write(`Primary key: ${signer.primaryFingerprint}\n`);
      }
      process.stdout.write(
        `Cryptographic verification: ${result.cryptographicallyValid ? 'VALID' : 'FAILED'}\n`,
      );
      process.stdout.write(`Operator identity trust: ${result.identityTrust.toUpperCase()}\n`);
      if (result.error !== undefined) process.stdout.write(`Result: ${result.error}\n`);
    }
    return result.ok ? 0 : 1;
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }
}

/** `stellar-toml-lint audit-wasm-simd --file <path.wasm> [--json]` */
async function auditWasmSimd(args: string[]): Promise<number> {
  let file: string | undefined;
  let json = false;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    if (arg === '--file') file = requireValue(args, ++i, arg);
    else if (arg === '--json') json = true;
    else {
      process.stderr.write(`Unknown option ${arg} for audit-wasm-simd\n`);
      return 2;
    }
  }

  if (file === undefined) {
    process.stderr.write('Usage: stellar-toml-lint audit-wasm-simd --file <path.wasm> [--json]\n');
    return 2;
  }

  try {
    const bytes = new Uint8Array(await readFile(resolve(file)));
    const report = auditWasmBinary(bytes, { file });
    process.stdout.write(json ? `${JSON.stringify(report, null, 2)}\n` : renderSimdReport(report));
    return report.findings.some((finding) => finding.severity === 'error') ? 1 : 0;
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }
}

/** `stellar-toml-lint audit-wasm-memory --file <path.wasm> [--json]` */
async function auditWasmMemory(args: string[]): Promise<number> {
  let file: string | undefined;
  let json = false;
  let maxInitialPages: number | undefined;
  let maxStackSlots: number | undefined;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    if (arg === '--file') file = requireValue(args, ++i, arg);
    else if (arg === '--json' || arg === '--format') {
      if (arg === '--json') json = true;
      else {
        const format = requireValue(args, ++i, arg);
        if (format !== 'text' && format !== 'json') {
          process.stderr.write(`Unknown format ${format} for audit-wasm-memory\n`);
          return 2;
        }
        json = format === 'json';
      }
    } else if (arg === '--max-initial-pages') {
      maxInitialPages = Number(requireValue(args, ++i, arg));
    } else if (arg === '--max-stack-slots') {
      maxStackSlots = Number(requireValue(args, ++i, arg));
    } else {
      process.stderr.write(`Unknown option ${arg} for audit-wasm-memory\n`);
      return 2;
    }
  }

  if (file === undefined) {
    process.stderr.write(
      'Usage: stellar-toml-lint audit-wasm-memory --file <path.wasm> [--format text|json]\n',
    );
    return 2;
  }

  try {
    const bytes = new Uint8Array(await readFile(resolve(file)));
    const report = analyzeWasmMemory(bytes, {
      file,
      ...(maxInitialPages !== undefined ? { maxInitialPages } : {}),
      ...(maxStackSlots !== undefined ? { maxStackSlots } : {}),
    });
    process.stdout.write(
      json ? `${JSON.stringify(report, null, 2)}\n` : renderMemoryHazardReport(report),
    );
    return report.findings.some((finding) => finding.severity === 'error') ? 1 : 0;
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }
}

/** `stellar-toml-lint auth-tree --xdr <txEnvelopeXdr> [--format text|json]` */
async function authTreeCommand(args: string[]): Promise<number> {
  let envelope: string | undefined;
  let file: string | undefined;
  let networkPassphrase: string | undefined;
  let rpcUrl: string | undefined;
  let latestLedger: number | undefined;
  let json = false;
  const authorizedIdentities: string[] = [];
  const allowedContracts: string[] = [];

  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    if (arg === '--xdr') envelope = requireValue(args, ++i, arg);
    else if (arg === '--file') file = requireValue(args, ++i, arg);
    else if (arg === '--network') networkPassphrase = requireValue(args, ++i, arg);
    else if (arg === '--rpc-url') rpcUrl = requireValue(args, ++i, arg);
    else if (arg === '--latest-ledger') latestLedger = Number(requireValue(args, ++i, arg));
    else if (arg === '--signing-key' || arg === '--authorized-identity') {
      authorizedIdentities.push(requireValue(args, ++i, arg));
    } else if (arg === '--allow-contract') allowedContracts.push(requireValue(args, ++i, arg));
    else if (arg === '--json' || arg === '--format') {
      if (arg === '--json') json = true;
      else {
        const format = requireValue(args, ++i, arg);
        if (format !== 'text' && format !== 'json') {
          process.stderr.write(`Unknown format ${format} for auth-tree\n`);
          return 2;
        }
        json = format === 'json';
      }
    } else {
      process.stderr.write(`Unknown option ${arg} for auth-tree\n`);
      return 2;
    }
  }

  if (envelope === undefined && file === undefined) {
    process.stderr.write(
      'Usage: stellar-toml-lint auth-tree --xdr <txEnvelopeXdr> [--network <passphrase>] [--rpc-url <url>] [--format text|json]\n',
    );
    return 2;
  }

  try {
    const source = envelope ?? (await readFile(resolve(file as string), 'utf8')).trim();
    const simulator = new AuthTreeSimulator({
      ...(networkPassphrase !== undefined ? { networkPassphrase } : {}),
      ...(rpcUrl !== undefined ? { rpcUrl } : {}),
      ...(latestLedger !== undefined ? { latestLedger } : {}),
      authorizedIdentities,
      allowedContracts,
    });
    const report = await simulator.simulate(source);
    process.stdout.write(
      json ? `${JSON.stringify(report, null, 2)}\n` : renderAuthTreeReport(report),
    );
    return report.ok ? 0 : 1;
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }
}

/** `stellar-toml-lint audit-signature-replay --file <path.wasm> [--json]` */
async function auditSignatureReplayCommand(args: string[]): Promise<number> {
  let file: string | undefined;
  let json = false;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    if (arg === '--file') file = requireValue(args, ++i, arg);
    else if (arg === '--json' || arg === '--format') {
      if (arg === '--json') json = true;
      else {
        const format = requireValue(args, ++i, arg);
        if (format !== 'text' && format !== 'json') {
          process.stderr.write(`Unknown format ${format} for audit-signature-replay\n`);
          return 2;
        }
        json = format === 'json';
      }
    } else {
      process.stderr.write(`Unknown option ${arg} for audit-signature-replay\n`);
      return 2;
    }
  }

  if (file === undefined) {
    process.stderr.write(
      'Usage: stellar-toml-lint audit-signature-replay --file <path.wasm> [--format text|json]\n',
    );
    return 2;
  }

  try {
    const bytes = new Uint8Array(await readFile(resolve(file)));
    const report = auditSignatureReplay(bytes, { file });
    process.stdout.write(
      json ? `${JSON.stringify(report, null, 2)}\n` : renderSignatureReplayReport(report),
    );
    return report.findings.some((finding) => finding.severity === 'error') ? 1 : 0;
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }
}

const VERIFY_PROVENANCE_USAGE = `stellar-toml-lint verify-provenance --artifact <file> --provenance <file> [options]

Verify an in-toto / Sigstore provenance document against an artifact and grade
its SLSA build level.

OPTIONS
      --artifact <file>              Artifact the attestation describes (required)
      --provenance <file>            DSSE envelope, Sigstore bundle, or *.intoto.jsonl (required)
      --expected-builder <id>        Require this builder identity
      --expected-repository <repo>   Require this source repository
      --expected-commit <sha>        Require this source commit
      --expected-trigger <event>     Require this workflow trigger (push, release, …)
      --trusted-key <pem|file>       Public key allowed to sign provenance (repeatable)
      --trusted-certificate <sha256> Allowed signing certificate fingerprint (repeatable)
      --trusted-root <pem|file>      Root CA the bundle chain must terminate in (repeatable)
      --require-level <0|1|2|3>      Minimum SLSA level (default 1)
      --json                         Print the structured report as JSON
`;

/** `stellar-toml-lint verify-provenance --artifact <file> --provenance <file>` */
async function verifyProvenance(args: string[]): Promise<number> {
  let artifactPath: string | undefined;
  let provenancePath: string | undefined;
  let json = false;
  let requiredLevel: SlsaLevel | undefined;
  let expectedBuilderId: string | undefined;
  let expectedSourceRepository: string | undefined;
  let expectedCommitSha: string | undefined;
  let expectedWorkflowTrigger: string | undefined;
  const trustedPublicKeys: string[] = [];
  const trustedCertificateSha256: string[] = [];
  const trustedRootCertificates: string[] = [];

  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    if (arg === '-h' || arg === '--help') {
      process.stdout.write(VERIFY_PROVENANCE_USAGE);
      return 0;
    } else if (arg === '--artifact') artifactPath = requireValue(args, ++i, arg);
    else if (arg === '--provenance') provenancePath = requireValue(args, ++i, arg);
    else if (arg === '--json') json = true;
    else if (arg === '--expected-builder') expectedBuilderId = requireValue(args, ++i, arg);
    else if (arg === '--expected-repository') {
      expectedSourceRepository = requireValue(args, ++i, arg);
    } else if (arg === '--expected-commit') expectedCommitSha = requireValue(args, ++i, arg);
    else if (arg === '--expected-trigger') {
      expectedWorkflowTrigger = requireValue(args, ++i, arg);
    } else if (arg === '--trusted-key') {
      const value = requireValue(args, ++i, arg);
      trustedPublicKeys.push(
        value.includes('BEGIN PUBLIC KEY') ? value : await readFile(resolve(value), 'utf8'),
      );
    } else if (arg === '--trusted-certificate') {
      trustedCertificateSha256.push(requireValue(args, ++i, arg));
    } else if (arg === '--trusted-root') {
      const value = requireValue(args, ++i, arg);
      trustedRootCertificates.push(
        value.includes('BEGIN CERTIFICATE') ? value : await readFile(resolve(value), 'utf8'),
      );
    } else if (arg === '--require-level') {
      const value = Number(requireValue(args, ++i, arg));
      if (value !== 0 && value !== 1 && value !== 2 && value !== 3) {
        process.stderr.write('--require-level expects 0, 1, 2, or 3.\n');
        return 2;
      }
      requiredLevel = value;
    } else {
      process.stderr.write(`Unknown option ${arg} for verify-provenance\n`);
      return 2;
    }
  }

  if (artifactPath === undefined || provenancePath === undefined) {
    process.stderr.write(VERIFY_PROVENANCE_USAGE);
    return 2;
  }

  try {
    const artifact = new Uint8Array(await readFile(resolve(artifactPath)));
    const provenance = await readFile(resolve(provenancePath), 'utf8');
    const report = verifySlsaProvenance(artifact, provenance, {
      artifactName: basename(artifactPath),
      ...(requiredLevel !== undefined ? { requiredLevel } : {}),
      ...(expectedBuilderId !== undefined ? { expectedBuilderId } : {}),
      ...(expectedSourceRepository !== undefined ? { expectedSourceRepository } : {}),
      ...(expectedCommitSha !== undefined ? { expectedCommitSha } : {}),
      ...(expectedWorkflowTrigger !== undefined ? { expectedWorkflowTrigger } : {}),
      ...(trustedPublicKeys.length > 0 ? { trustedPublicKeys } : {}),
      ...(trustedCertificateSha256.length > 0 ? { trustedCertificateSha256 } : {}),
      ...(trustedRootCertificates.length > 0 ? { trustedRootCertificates } : {}),
    });
    process.stdout.write(
      json ? `${JSON.stringify(report, null, 2)}\n` : renderProvenanceReport(report),
    );
    return report.ok ? 0 : 1;
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }
}

const AUDIT_DOCKERFILE_USAGE = `stellar-toml-lint audit-dockerfile [options]

Audit the runtime stage of a Dockerfile and its .dockerignore against CKV/CIS
Docker Benchmark hardening rules.

OPTIONS
      --dockerfile <path>      Dockerfile to audit (default: ./Dockerfile)
      --dockerignore <path>    .dockerignore to use (default: next to the Dockerfile)
      --image-size <megabytes> Measured image size, checked against the 100 MB budget
      --json                   Print the report as JSON
`;

/** `stellar-toml-lint audit-dockerfile [--dockerfile <path>]` */
async function auditContainer(args: string[]): Promise<number> {
  let dockerfilePath = 'Dockerfile';
  let dockerignorePath: string | undefined;
  let imageSizeBytes: number | undefined;
  let json = false;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    if (arg === '-h' || arg === '--help') {
      process.stdout.write(AUDIT_DOCKERFILE_USAGE);
      return 0;
    } else if (arg === '--dockerfile') dockerfilePath = requireValue(args, ++i, arg);
    else if (arg === '--dockerignore') dockerignorePath = requireValue(args, ++i, arg);
    else if (arg === '--image-size') {
      const megabytes = Number(requireValue(args, ++i, arg));
      if (!Number.isFinite(megabytes) || megabytes <= 0) {
        process.stderr.write('--image-size expects a positive number of megabytes.\n');
        return 2;
      }
      imageSizeBytes = Math.round(megabytes * 1024 * 1024);
    } else if (arg === '--json') json = true;
    else {
      process.stderr.write(`Unknown option ${arg} for audit-dockerfile\n`);
      return 2;
    }
  }

  const resolvedDockerfile = resolve(dockerfilePath);
  const readOptional = async (candidate: string): Promise<string | undefined> => {
    try {
      return await readFile(candidate, 'utf8');
    } catch {
      return undefined;
    }
  };

  try {
    const source = await readFile(resolvedDockerfile, 'utf8');
    const dockerignore =
      dockerignorePath !== undefined
        ? await readFile(resolve(dockerignorePath), 'utf8')
        : await readOptional(resolve(dirname(resolvedDockerfile), '.dockerignore'));
    const report = auditDockerfile(source, {
      dockerfilePath,
      ...(dockerignore !== undefined ? { dockerignore } : {}),
      ...(imageSizeBytes !== undefined ? { imageSizeBytes } : {}),
    });
    process.stdout.write(
      json ? `${JSON.stringify(report, null, 2)}\n` : renderContainerReport(report),
    );
    return report.ok ? 0 : 1;
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }
}

/** `stellar-toml-lint --verify-wasm-streaming <url>` */
async function verifyWasmStreaming(url: string): Promise<number> {
  try {
    const result = await new WasmStreamingVerifier().verify(url);
    process.stdout.write(renderStreamingReport(result));
    return result.ok ? 0 : 1;
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }
}

/** `stellar-toml-lint audit-coop-coep --url <web_app_url>` */
async function auditCoopCoep(args: string[]): Promise<number> {
  let url: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    if (arg === '--url') url = requireValue(args, ++i, arg);
    else {
      process.stderr.write(`Unknown option ${arg} for audit-coop-coep\n`);
      return 2;
    }
  }
  if (url === undefined) {
    process.stderr.write('Usage: stellar-toml-lint audit-coop-coep --url <web_app_url>\n');
    return 2;
  }

  try {
    const report = await new CrossOriginIsolationAuditor().audit(url);
    process.stdout.write(renderIsolationReport(report));
    return report.ok ? 0 : 1;
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }
}

/** `stellar-toml-lint audit-quorum [--file <path>] [--format text|json]` */
async function auditQuorumCommand(args: string[]): Promise<number> {
  let file = 'stellar.toml';
  let format: 'text' | 'json' = 'text';

  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    if (arg === '--file') file = requireValue(args, ++i, arg);
    else if (arg === '--format') {
      const val = requireValue(args, ++i, arg);
      if (val === 'text' || val === 'json') format = val;
      else {
        process.stderr.write('--format expects text or json\n');
        return 2;
      }
    } else if (arg === '--json') format = 'json';
    else {
      process.stderr.write(`Unknown option ${arg} for audit-quorum\n`);
      return 2;
    }
  }

  try {
    const content = await readFile(resolve(file), 'utf8');
    const auditor = new QuorumSetIntersectionAuditor();
    const result = auditor.audit(content);
    if (format === 'json') {
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    } else {
      process.stdout.write(
        `Quorum Intersection: ${result.hasQuorumIntersection ? 'PASS' : 'FAIL'}\n`,
      );
      process.stdout.write(`Minimal Quorums: ${result.minimalQuorums.length}\n`);
      process.stdout.write(`Split-Brain Risk: ${result.hasSplitBrainRisk ? 'DETECTED' : 'NONE'}\n`);
      process.stdout.write(`Fragmentation: ${result.isFragmented ? 'FRAGMENTED' : 'HEALTHY'}\n`);
      if (result.intersectionNodes.length > 0) {
        process.stdout.write(`Common Intersection Nodes: ${result.intersectionNodes.join(', ')}\n`);
      }
      for (const w of result.warnings) {
        process.stdout.write(`Warning: ${w}\n`);
      }
    }
    return result.hasQuorumIntersection && !result.hasSplitBrainRisk ? 0 : 1;
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }
}

/** `stellar-toml-lint verify-archive-lag [--file <path>] [--horizon <url>] [--live-ledger <num>] [--format text|json]` */
async function verifyArchiveLagCommand(args: string[]): Promise<number> {
  let file = 'stellar.toml';
  let horizonUrl: string | undefined;
  let liveLedger: number | undefined;
  let format: 'text' | 'json' = 'text';

  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    if (arg === '--file') file = requireValue(args, ++i, arg);
    else if (arg === '--horizon') horizonUrl = requireValue(args, ++i, arg);
    else if (arg === '--live-ledger') liveLedger = Number(requireValue(args, ++i, arg));
    else if (arg === '--format') {
      const val = requireValue(args, ++i, arg);
      if (val === 'text' || val === 'json') format = val;
      else {
        process.stderr.write('--format expects text or json\n');
        return 2;
      }
    } else if (arg === '--json') format = 'json';
    else {
      process.stderr.write(`Unknown option ${arg} for verify-archive-lag\n`);
      return 2;
    }
  }

  try {
    const content = await readFile(resolve(file), 'utf8');
    const verifier = new ArchiveProgressionVerifier({
      horizonUrl,
      liveLedger,
    });
    const report = await verifier.verify(content);
    if (format === 'json') {
      process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    } else {
      process.stdout.write(`Archive Progression: ${report.ok ? 'HEALTHY' : 'LAGGING'}\n`);
      if (report.liveLedger !== undefined) {
        process.stdout.write(`Live Ledger: ${report.liveLedger}\n`);
      }
      for (const a of report.archives) {
        process.stdout.write(
          `Archive: ${a.archiveUrl} (current: ${a.currentLedger ?? 'unknown'}, checkpoint: ${a.checkpointHeight ?? 'unknown'}, lag: ${a.checkpointLag ?? 0} cp)\n`,
        );
      }
      for (const err of report.errors) {
        process.stdout.write(`Error: ${err}\n`);
      }
    }
    return report.ok ? 0 : 1;
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }
}

/** `stellar-toml-lint score-diversity [--file <path>] [--format text|json]` */
async function scoreDiversityCommand(args: string[]): Promise<number> {
  let file = 'stellar.toml';
  let format: 'text' | 'json' = 'text';

  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    if (arg === '--file') file = requireValue(args, ++i, arg);
    else if (arg === '--format') {
      const val = requireValue(args, ++i, arg);
      if (val === 'text' || val === 'json') format = val;
      else {
        process.stderr.write('--format expects text or json\n');
        return 2;
      }
    } else if (arg === '--json') format = 'json';
    else {
      process.stderr.write(`Unknown option ${arg} for score-diversity\n`);
      return 2;
    }
  }

  try {
    const content = await readFile(resolve(file), 'utf8');
    const scorer = new GeographicDiversityScorer();
    const report = await scorer.score(content);
    if (format === 'json') {
      process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    } else {
      process.stdout.write(
        `Validators Resolved: ${report.resolvedValidators}/${report.totalValidators}\n`,
      );
      process.stdout.write(
        `ASN Diversity: Simpson=${report.asnDiversity.simpsonIndex}, Shannon=${report.asnDiversity.shannonEntropy}\n`,
      );
      process.stdout.write(
        `Datacenter Diversity: Simpson=${report.datacenterDiversity.simpsonIndex}, Shannon=${report.datacenterDiversity.shannonEntropy}\n`,
      );
      process.stdout.write(
        `Concentration Risk: ASN=${report.hasAsnConcentrationRisk ? 'HIGH' : 'LOW'}, Datacenter=${report.hasDatacenterConcentrationRisk ? 'HIGH' : 'LOW'}\n`,
      );
      for (const w of report.warnings) {
        process.stdout.write(`Warning: ${w}\n`);
      }
    }
    return !report.hasAsnConcentrationRisk && !report.hasDatacenterConcentrationRisk ? 0 : 1;
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }
}

/** `stellar-toml-lint trace-scp --file <xdr-file> [--timeout <ms>] [--format text|json]` */
async function traceScpCommand(args: string[]): Promise<number> {
  let file: string | undefined;
  let timeoutMs: number | undefined;
  let format: 'text' | 'json' = 'text';

  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    if (arg === '--file') file = requireValue(args, ++i, arg);
    else if (arg === '--timeout') timeoutMs = Number(requireValue(args, ++i, arg));
    else if (arg === '--format') {
      const val = requireValue(args, ++i, arg);
      if (val === 'text' || val === 'json') format = val;
      else {
        process.stderr.write('--format expects text or json\n');
        return 2;
      }
    } else if (arg === '--json') format = 'json';
    else {
      process.stderr.write(`Unknown option ${arg} for trace-scp\n`);
      return 2;
    }
  }

  if (file === undefined) {
    process.stderr.write(
      'Usage: stellar-toml-lint trace-scp --file <xdr-file> [--timeout <ms>] [--format text|json]\n',
    );
    return 2;
  }

  try {
    const raw = await readFile(resolve(file));
    const tracer = new ScpBallotTracer({ stallTimeoutMs: timeoutMs });
    tracer.record(raw);
    const traces = tracer.getAllTraces();
    const stalls = tracer.detectStalls();

    if (format === 'json') {
      process.stdout.write(`${JSON.stringify({ traces, stalls }, null, 2)}\n`);
    } else {
      process.stdout.write(`Slots Traced: ${traces.length}\n`);
      process.stdout.write(`Consensus Stalls: ${stalls.length}\n`);
      for (const stall of stalls) {
        process.stdout.write(`Stall at Slot ${stall.slotIndex}: ${stall.reason}\n`);
      }
    }
    return stalls.length === 0 ? 0 : 1;
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }
}

/** `stellar-toml-lint verify-federation-sync --domain <domain>` */
async function verifyFederationSyncCommand(args: string[]): Promise<number> {
  let domain: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    if (arg === '--domain') domain = requireValue(args, ++i, arg);
    else {
      process.stderr.write(`Unknown option ${arg} for verify-federation-sync\n`);
      return 2;
    }
  }
  if (domain === undefined) {
    process.stderr.write('Usage: stellar-toml-lint verify-federation-sync --domain <domain>\n');
    return 2;
  }

  try {
    const url = `https://${domain.replace(/^https?:\/\//, '').replace(/\/+$/, '')}/.well-known/stellar.toml`;
    const response = await fetch(url);
    if (!response.ok) {
      process.stderr.write(`Could not fetch ${url}: HTTP ${response.status}\n`);
      return 2;
    }
    const doc = parseToml(await response.text()) as Record<string, unknown>;
    const result = await verifyFederationSync(doc);
    process.stdout.write(renderReverseFederationReport(result.report));
    return result.report.ok ? 0 : 1;
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }
}

/** `stellar-toml-lint verify-sep31-sep12 --domain <domain> [--format text|json] [--timeout <ms>]` */
async function verifySep31Sep12Command(args: string[]): Promise<number> {
  let domain: string | undefined;
  let format: 'text' | 'json' = 'text';
  let timeoutMs: number | undefined;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    if (arg === '--domain') domain = requireValue(args, ++i, arg);
    else if (arg === '--format') {
      const value = requireValue(args, ++i, arg);
      if (value !== 'text' && value !== 'json') {
        process.stderr.write(`Unknown format "${value}". Expected text or json.\n`);
        return 2;
      }
      format = value;
    } else if (arg === '--timeout') {
      const value = Number(requireValue(args, ++i, arg));
      if (!Number.isInteger(value) || value < 1 || value > 120_000) {
        process.stderr.write('--timeout expects an integer from 1 to 120000 milliseconds.\n');
        return 2;
      }
      timeoutMs = value;
    } else {
      process.stderr.write(`Unknown option ${arg} for verify-sep31-sep12\n`);
      return 2;
    }
  }

  if (domain === undefined) {
    process.stderr.write(
      'Usage: stellar-toml-lint verify-sep31-sep12 --domain <domain> [--format text|json] ' +
        '[--timeout <ms>]\n',
    );
    return 2;
  }

  try {
    const host = domain.replace(/^https?:\/\//, '').replace(/\/+$/, '');
    const url = `https://${host}/.well-known/stellar.toml`;
    const response = await fetch(url);
    if (!response.ok) {
      process.stderr.write(`Could not fetch ${url}: HTTP ${response.status}\n`);
      return 2;
    }
    const doc = parseToml(await response.text()) as Record<string, unknown>;
    const direct = doc.DIRECT_PAYMENT_SERVER;
    const kyc = doc.KYC_SERVER;
    if (typeof direct !== 'string' || typeof kyc !== 'string') {
      process.stderr.write(
        'stellar.toml must declare both DIRECT_PAYMENT_SERVER (SEP-31) and KYC_SERVER (SEP-12)\n',
      );
      return 1;
    }

    const report = await new Sep31Sep12ConsistencyEngine({
      ...(timeoutMs === undefined ? {} : { timeoutMs }),
    }).verify({ directPaymentServer: direct, kycServer: kyc });
    process.stdout.write(
      format === 'json' ? `${JSON.stringify(report, null, 2)}\n` : renderSep31Sep12Report(report),
    );
    return report.ok ? 0 : 1;
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }
}

/** `stellar-toml-lint audit-key-separation --domain <domain> [--horizon <url>] [--format text|json]` */
async function auditKeySeparationCommand(args: string[]): Promise<number> {
  let domain: string | undefined;
  let horizon: string | undefined;
  let format = 'text';
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    if (arg === '--domain') domain = requireValue(args, ++i, arg);
    else if (arg === '--horizon') horizon = requireValue(args, ++i, arg);
    else if (arg === '--format') format = requireValue(args, ++i, arg);
    else {
      process.stderr.write(`Unknown option ${arg} for audit-key-separation\n`);
      return 2;
    }
  }
  if (domain === undefined || (format !== 'text' && format !== 'json')) {
    process.stderr.write(
      'Usage: stellar-toml-lint audit-key-separation --domain <domain> [--horizon <url>] [--format text|json]\n',
    );
    return 2;
  }

  try {
    const host = domain.replace(/^https?:\/\//, '').replace(/\/+$/, '');
    const url = `https://${host}/.well-known/stellar.toml`;
    const response = await fetch(url);
    if (!response.ok) {
      process.stderr.write(`Could not fetch ${url}: HTTP ${response.status}\n`);
      return 2;
    }
    const doc = parseToml(await response.text()) as Record<string, unknown>;
    const result = await auditKeySeparation(doc, fetch, {
      ...(horizon === undefined ? {} : { horizonUrl: horizon }),
    });
    process.stdout.write(
      format === 'json'
        ? `${JSON.stringify({ ...result.report, diagnostics: result.diagnostics }, null, 2)}\n`
        : renderKeySeparationReport(result.report),
    );
    return result.report.ok ? 0 : 1;
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }
}

function parseQuorumPeers(value: unknown): QuorumPeerConfig[] {
  const raw = Array.isArray(value)
    ? value
    : typeof value === 'object' &&
        value !== null &&
        Array.isArray((value as { peers?: unknown }).peers)
      ? (value as { peers: unknown[] }).peers
      : undefined;
  if (raw === undefined) {
    throw new Error('Quorum file must be a JSON array or an object with a "peers" array');
  }

  return raw.map((entry, index) => {
    if (typeof entry !== 'object' || entry === null) {
      throw new Error(`Quorum entry ${index} must be an object with name and validatorKeys`);
    }
    const peer = entry as Record<string, unknown>;
    const name = typeof peer.name === 'string' ? peer.name : undefined;
    const keys = Array.isArray(peer.validatorKeys)
      ? peer.validatorKeys.filter((key): key is string => typeof key === 'string')
      : undefined;
    if (name === undefined || keys === undefined) {
      throw new Error(`Quorum entry ${index} must have a string name and a validatorKeys array`);
    }
    const kind = peer.kind === 'anchor' ? 'anchor' : 'peer';
    return { name, validatorKeys: keys, kind };
  });
}

const AUDIT_FLOOD_POLICY_USAGE = `Usage: stellar-toml-lint audit-flood-policy [--host <host>] [options]

Checks transaction flood propagation and mempool eviction policy. Metrics come
from a stellar-core admin endpoint (--host) or saved files; transaction bursts
are simulated locally against the node's configured queue, never submitted.

Options:
  --host <host>             stellar-core admin host; reads /info and /metrics over HTTP
  --admin-port <port>       Admin HTTP port (default: 11626)
  --metrics-file <file>     Saved stellar-core /metrics JSON (instead of --host)
  --info-file <file>        Saved stellar-core /info JSON (instead of --host)
  --exchanges-file <file>   JSON array of {request, response} base64 StellarMessage XDR
                            (GET_TX_SET / TX_SET / DONT_HAVE / TRANSACTION frames)
  --submissions-file <file> Observed submission log to check for fair queueing
  --profile <spec>          Burst per fee tier, e.g. low=300,medium=150,high=60,priority=15
                            (default: 150% of queue capacity)
  --capacity <ops>          Queue capacity in operations (default: maxTxSetSize x 2)
  --seed <n>                Burst shuffle seed (default: 1)
  --format text|json        Output format (default: text)
`;

function parseSubmissionLog(input: unknown): SubmissionEvent[] {
  if (!Array.isArray(input)) throw new Error('submissions file must be a JSON array');
  return input.map((raw: unknown, index) => {
    const entry = raw as Record<string, unknown>;
    const tx = (entry?.tx ?? {}) as Record<string, unknown>;
    if (
      typeof tx.id !== 'string' ||
      typeof tx.account !== 'string' ||
      typeof tx.operations !== 'number' ||
      (typeof tx.fee !== 'string' && typeof tx.fee !== 'number') ||
      (entry.status !== 'accepted' && entry.status !== 'rejected') ||
      typeof entry.occupancyOps !== 'number'
    ) {
      throw new Error(`submissions[${index}] is not a valid submission event`);
    }
    return {
      tx: {
        id: tx.id,
        account: tx.account,
        operations: tx.operations,
        fee: BigInt(tx.fee),
        ...(typeof tx.tier === 'string' ? { tier: tx.tier as 'low' } : {}),
      },
      status: entry.status,
      ...(typeof entry.reason === 'string' ? { reason: entry.reason as 'insufficient-fee' } : {}),
      evicted: Array.isArray(entry.evicted) ? entry.evicted.map(String) : [],
      ...(typeof entry.replaced === 'string' ? { replaced: entry.replaced } : {}),
      ...(Array.isArray(entry.removed) ? { removed: entry.removed.map(String) } : {}),
      occupancyOps: entry.occupancyOps,
    };
  });
}

async function fetchJson(url: string): Promise<unknown> {
  const response = await fetch(url, { signal: AbortSignal.timeout(5000) });
  if (!response.ok) throw new Error(`HTTP ${response.status} from ${url}`);
  return (await response.json()) as unknown;
}

/** `stellar-toml-lint audit-flood-policy --host <host>` */
async function auditFloodPolicyCommand(args: string[]): Promise<number> {
  let host: string | undefined;
  let adminPort = 11626;
  let format = 'text';
  const files: Record<string, string> = {};
  const options: {
    capacityOps?: number;
    seed?: number;
    profile?: ReturnType<typeof parseBurstProfile>;
  } = {};
  try {
    for (let i = 0; i < args.length; i++) {
      const arg = args[i] as string;
      if (arg === '--host') host = requireValue(args, ++i, arg);
      else if (arg === '--admin-port') adminPort = Number(requireValue(args, ++i, arg));
      else if (arg === '--format') format = requireValue(args, ++i, arg);
      else if (
        arg === '--metrics-file' ||
        arg === '--info-file' ||
        arg === '--exchanges-file' ||
        arg === '--submissions-file'
      ) {
        files[arg] = requireValue(args, ++i, arg);
      } else if (arg === '--profile')
        options.profile = parseBurstProfile(requireValue(args, ++i, arg));
      else if (arg === '--capacity') options.capacityOps = Number(requireValue(args, ++i, arg));
      else if (arg === '--seed') options.seed = Number(requireValue(args, ++i, arg));
      else if (arg === '--help' || arg === '-h') {
        process.stdout.write(AUDIT_FLOOD_POLICY_USAGE);
        return 0;
      } else {
        process.stderr.write(`Unknown option ${arg} for audit-flood-policy\n`);
        return 2;
      }
    }
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }
  if (
    (format !== 'text' && format !== 'json') ||
    !Number.isInteger(adminPort) ||
    adminPort < 1 ||
    adminPort > 65535
  ) {
    process.stderr.write(AUDIT_FLOOD_POLICY_USAGE);
    return 2;
  }

  try {
    const readJson = async (flag: string) =>
      files[flag] === undefined
        ? undefined
        : (JSON.parse(await readFile(resolve(files[flag] as string), 'utf8')) as unknown);
    let metrics = await readJson('--metrics-file');
    let info = await readJson('--info-file');
    if (host !== undefined) {
      const base = `http://${host}:${adminPort}`;
      for (const [name, assign] of [
        ['metrics', (value: unknown) => (metrics ??= value)],
        ['info', (value: unknown) => (info ??= value)],
      ] as const) {
        try {
          assign(await fetchJson(`${base}/${name}`));
        } catch (error) {
          process.stderr.write(`Could not read ${base}/${name}: ${message(error)}\n`);
        }
      }
    }
    const exchanges = (await readJson('--exchanges-file')) as OverlayExchange[] | undefined;
    if (exchanges !== undefined && !Array.isArray(exchanges)) {
      throw new Error('exchanges file must be a JSON array of {request, response}');
    }
    const submissions = await readJson('--submissions-file');
    const report = new FloodPropagationVerifier(options).verify({
      ...(metrics === undefined ? {} : { metrics }),
      ...(info === undefined ? {} : { info }),
      ...(exchanges === undefined ? {} : { exchanges }),
      ...(submissions === undefined ? {} : { observed: parseSubmissionLog(submissions) }),
    });
    process.stdout.write(
      format === 'json'
        ? `${JSON.stringify(report, (_key, value: unknown) => (typeof value === 'bigint' ? value.toString() : value), 2)}\n`
        : renderFloodPolicyReport(report),
    );
    return report.ok ? 0 : 1;
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }
}

/** `stellar-toml-lint audit-validator-rotation --domain <domain> [--format text|json]` */
async function auditValidatorRotationCommand(args: string[]): Promise<number> {
  let domain: string | undefined;
  let format = 'text';
  let peersPath: string | undefined;
  let previousSignature: string | undefined;
  let replacementSignature: string | undefined;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    if (arg === '--domain') domain = requireValue(args, ++i, arg);
    else if (arg === '--format') format = requireValue(args, ++i, arg);
    else if (arg === '--peers') peersPath = requireValue(args, ++i, arg);
    else if (arg === '--previous-signature') previousSignature = requireValue(args, ++i, arg);
    else if (arg === '--replacement-signature') replacementSignature = requireValue(args, ++i, arg);
    else {
      process.stderr.write(`Unknown option ${arg} for audit-validator-rotation\n`);
      return 2;
    }
  }
  if (domain === undefined || (format !== 'text' && format !== 'json')) {
    process.stderr.write(
      'Usage: stellar-toml-lint audit-validator-rotation --domain <domain> ' +
        '[--previous-signature <sig>] [--replacement-signature <sig>] ' +
        '[--peers <quorum.json>] [--format text|json]\n',
    );
    return 2;
  }

  try {
    const host = domain.replace(/^https?:\/\//, '').replace(/\/+$/, '');
    const url = `https://${host}/.well-known/stellar.toml`;
    const response = await fetch(url);
    if (!response.ok) {
      process.stderr.write(`Could not fetch ${url}: HTTP ${response.status}\n`);
      return 2;
    }
    const doc = parseToml(await response.text()) as Record<string, unknown>;

    const peers =
      peersPath === undefined
        ? []
        : parseQuorumPeers(JSON.parse(await readFile(resolve(peersPath), 'utf8')) as unknown);
    const attestation: KeyRotationAttestation = {};
    if (previousSignature !== undefined) attestation.previousKeySignature = previousSignature;
    if (replacementSignature !== undefined) {
      attestation.replacementKeySignature = replacementSignature;
    }
    const declaredValidatorKeys = Array.isArray(doc.VALIDATORS)
      ? doc.VALIDATORS.flatMap((entry) => {
          if (typeof entry !== 'object' || entry === null) return [];
          const key = (entry as Record<string, unknown>).PUBLIC_KEY;
          return typeof key === 'string' ? [key] : [];
        })
      : [];

    const verifier = new ValidatorKeyRotationVerifier({
      domain: host,
      attestation,
      peers,
      declaredValidatorKeys,
    });
    const report = verifier.audit(doc);
    process.stdout.write(
      format === 'json' ? `${JSON.stringify(report, null, 2)}\n` : renderKeyRotationReport(report),
    );
    return report.ok ? 0 : 1;
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }
}

/** `stellar-toml-lint verify-browser-bundle [--dir dist/browser]` */
async function verifyBrowserBundleCommand(args: string[]): Promise<number> {
  let dir = 'dist/browser';
  let maxBytes: number | undefined;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    if (arg === '--dir') dir = requireValue(args, ++i, arg);
    else if (arg === '--max-bytes') maxBytes = Number(requireValue(args, ++i, arg));
    else {
      process.stderr.write(`Unknown option ${arg} for verify-browser-bundle\n`);
      return 2;
    }
  }

  try {
    const entries = await readdir(resolve(dir), { withFileTypes: true });
    const files = entries.filter((entry) => entry.isFile() && entry.name.endsWith('.js'));
    const artifacts = await Promise.all(
      files.map(async (entry) => ({
        path: `${dir}/${entry.name}`,
        source: await readFile(resolve(dir, entry.name), 'utf8'),
      })),
    );
    const verifier = new BrowserBoundaryVerifier({
      ...(maxBytes !== undefined && Number.isFinite(maxBytes) ? { maxBundleBytes: maxBytes } : {}),
      requiredFiles: ['index.js'],
    });
    const report = verifier.verify(artifacts);
    process.stdout.write(renderBrowserBoundaryReport(report));
    return report.ok ? 0 : 1;
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }
}

/** `stellar-toml-lint audit-wormhole-vaa --vaa <hex|base64> [--guardian-set <file>] [--format text|json]` */
async function auditWormholeVaaCommand(args: string[]): Promise<number> {
  let vaa: string | undefined;
  let setFile: string | undefined;
  let format = 'text';
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    if (arg === '--vaa') vaa = requireValue(args, ++i, arg);
    else if (arg === '--guardian-set') setFile = requireValue(args, ++i, arg);
    else if (arg === '--format') format = requireValue(args, ++i, arg);
    else {
      process.stderr.write(`Unknown option ${arg} for audit-wormhole-vaa\n`);
      return 2;
    }
  }
  if (vaa === undefined || (format !== 'text' && format !== 'json')) {
    process.stderr.write(
      'Usage: stellar-toml-lint audit-wormhole-vaa --vaa <hex|base64> ' +
        '[--guardian-set <file.json>] [--format text|json]\n',
    );
    return 2;
  }
  let guardianSet;
  if (setFile !== undefined) {
    try {
      guardianSet = parseGuardianSet(JSON.parse(await readFile(resolve(setFile), 'utf8')));
    } catch (error) {
      process.stderr.write(`${message(error)}\n`);
      return 2;
    }
    if (guardianSet === undefined) {
      process.stderr.write('Guardian set must be { "index": n, "keys": ["0x..."] }\n');
      return 2;
    }
  }
  const result = new WormholeVaaAuditor(guardianSet ? { guardianSet } : {}).audit(vaa);
  if (format === 'json') {
    const replacer = (_key: string, value: unknown): unknown =>
      typeof value === 'bigint'
        ? value.toString()
        : value instanceof Uint8Array
          ? `0x${Buffer.from(value).toString('hex')}`
          : value;
    process.stdout.write(`${JSON.stringify(result, replacer, 2)}\n`);
  } else {
    process.stdout.write(renderVaaReport(result));
    for (const d of result.diagnostics) {
      process.stdout.write(`${d.severity}: ${d.message} [${d.rule}]\n`);
    }
  }
  return result.diagnostics.some((d) => d.severity === 'error') ? 1 : 0;
}

/**
 * `--sort-keys` rewrites files into canonical key order; `--dry-run` prints the
 * diff and leaves the tree alone. Both go through this one pass so a preview can
 * never disagree with what the write would have done.
 */
async function sortKeysCommand(cli: Cli, color: boolean): Promise<number> {
  if (cli.domain !== undefined) {
    process.stderr.write(
      '--sort-keys rewrites files on disk, so it cannot be combined with --domain.\n\nRun with --help for usage.\n',
    );
    return 2;
  }

  let wouldChange = 0;
  let unparseable = 0;

  try {
    const paths = await expandInputs(cli.paths.length > 0 ? cli.paths : [DEFAULT_PATH]);
    for (const path of paths) {
      const name = path === '-' ? 'stdin' : path;
      const source = path === '-' ? await readStdin() : await readFile(resolve(path), 'utf8');
      const sorted = sortCanonical(source);
      for (const warning of sorted.warnings) process.stderr.write(`${name}: ${warning}\n`);
      if (!sorted.parsed) unparseable++;
      if (!sorted.changed) continue;

      wouldChange++;
      // A dry run only ever shows the diff; stdin has no file to write back to,
      // so there the sorted text is the output.
      if (cli.dryRun) {
        process.stdout.write(formatUnifiedDiff(name, source, sorted.output, { color }));
      } else if (path === '-') {
        process.stdout.write(sorted.output);
      } else {
        await writeFile(resolve(path), sorted.output);
        process.stdout.write(`${name}: sorted\n`);
      }
    }
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }

  // Only a dry run fails on a change — that is what makes it usable as a CI
  // ordering gate. In apply mode the sort *is* the success, so a file that
  // could not be parsed is the only non-zero exit.
  if (cli.dryRun) {
    if (wouldChange === 0 && unparseable === 0 && !cli.quiet) {
      process.stdout.write('All files are in canonical key order.\n');
    }
    return wouldChange > 0 || unparseable > 0 ? 1 : 0;
  }
  return unparseable > 0 ? 1 : 0;
}

/** `stellar-toml-lint refactor <file> [options]` */
async function refactorCommand(args: string[]): Promise<number> {
  let file: string | undefined;
  let split = false;
  let write = false;
  let json = false;
  let maxBytes: number | undefined;
  let outDir: string | undefined;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    if (arg === '--deduplicate-assets') continue;
    else if (arg === '--split') split = true;
    else if (arg === '--write') write = true;
    else if (arg === '--json') json = true;
    else if (arg === '--max-bytes') {
      const value = Number(requireValue(args, ++i, arg));
      if (!Number.isInteger(value) || value <= 0) {
        process.stderr.write('--max-bytes expects a positive integer.\n');
        return 2;
      }
      maxBytes = value;
    } else if (arg === '--out-dir') outDir = requireValue(args, ++i, arg);
    else if (!arg.startsWith('-')) file = arg;
    else {
      process.stderr.write(`Unknown option ${arg} for refactor\n`);
      return 2;
    }
  }

  if (file === undefined) {
    process.stderr.write(
      'Usage: stellar-toml-lint refactor <file> [--deduplicate-assets] [--split] ' +
        '[--max-bytes <n>] [--out-dir <dir>] [--write] [--json]\n',
    );
    return 2;
  }

  try {
    const source = await readFile(resolve(file), 'utf8');
    const engine = new StructuralRefactoringEngine(source);

    if (split) {
      const result = engine.split({
        ...(maxBytes === undefined ? {} : { maxBytes }),
        ...(outDir === undefined ? {} : { baseName: basename(file, '.toml') }),
      });
      if (outDir !== undefined) {
        await mkdir(resolve(outDir), { recursive: true });
        for (const partial of result.files) {
          await writeFile(resolve(outDir, partial.name), partial.source, 'utf8');
        }
      }
      process.stdout.write(
        json
          ? `${JSON.stringify(result, null, 2)}\n`
          : `${result.files.map((partial) => partial.name).join('\n')}\n` +
              `Validation: ${result.validation.ok ? 'passed' : `FAILED: ${result.validation.errors.join('; ')}`}\n`,
      );
      return result.validation.ok ? 0 : 1;
    }

    const result = engine.deduplicateAssets();
    process.stderr.write(renderRefactorSummary(result));
    process.stdout.write(json ? `${JSON.stringify(result, null, 2)}\n` : result.diff);
    if (write && result.validation.ok) await writeFile(resolve(file), result.source, 'utf8');
    return result.validation.ok ? 0 : 1;
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }
}

/**
 * `stellar-toml-lint diff <source> <target> [--json]`
 *
 * Compares two documents by value rather than by line, which is what makes it
 * usable as a deployment review gate: `git diff` of a restaged `stellar.toml` is
 * mostly the canonical sort having done its job.
 *
 * The exit code follows the severity mapping the linter already uses — findings
 * that would break a client are errors, everything else is information. So an
 * identical pair and a harmless edit both exit 0, and a run exits 1 only when
 * something a client is already relying on went away. A side that does not parse
 * exits 2, because the comparison could not be made at all.
 */
async function diffCommand(args: string[]): Promise<number> {
  const inputs: string[] = [];
  let json = false;

  for (const arg of args) {
    if (arg === '--json') json = true;
    else if (arg.startsWith('-') && arg !== '-') {
      process.stderr.write(`Unknown option ${arg} for diff\n`);
      return 2;
    } else inputs.push(arg);
  }

  const usage = 'Usage: stellar-toml-lint diff <source> <target> [--json]\n';
  if (inputs.length !== 2) {
    process.stderr.write(usage);
    return 2;
  }
  const [source = '-', target = '-'] = inputs;
  if (source === '-' && target === '-') {
    process.stderr.write('Only one side of a diff can come from stdin.\n');
    return 2;
  }

  try {
    const report = await new SemanticTomlDiffer().diffInputs(source, target);
    process.stdout.write(
      json ? renderSemanticDiffJson(report) : renderSemanticDiff(report, shouldUseColor()),
    );
    if (!report.source.parsed || !report.target.parsed) return 2;
    return report.breaking > 0 ? 1 : 0;
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }
}

async function formatCommand(argv: string[]): Promise<number> {
  let file: string | undefined;
  let write = false;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === '--file' || arg === '-f') {
      file = argv[++i];
    } else if (arg === '--write' || arg === '-w') {
      write = true;
    } else if (!arg.startsWith('-')) {
      file = arg;
    }
  }
  if (!file) {
    process.stderr.write('Usage: stellar-toml-lint format --file <stellar.toml> [--write]\n');
    return 2;
  }
  try {
    const formatter = new LosslessCstFormatter();
    const result = await formatter.formatFile(file, write);
    if (!write) {
      process.stdout.write(result.formatted);
    } else if (result.changed) {
      process.stdout.write(`Formatted ${file}\n`);
    } else {
      process.stdout.write(`${file} is already formatted\n`);
    }
    return 0;
  } catch (err) {
    process.stderr.write(`Formatting error: ${err instanceof Error ? err.message : String(err)}\n`);
    return 2;
  }
}

/**
 * `stellar-toml-lint detect-drift --domain <domain> [--git-path <path>]`
 *
 * Exit codes are the CI contract: 0 in sync, 1 drift, 2 when the check could
 * not run (timeout, HTTP error, missing file, invalid TOML, bad arguments).
 */
async function detectDriftCommand(args: string[]): Promise<number> {
  let domain: string | undefined;
  let url: string | undefined;
  let gitPath: string | undefined;
  let ref: string | undefined;
  let format = 'text';
  let timeoutMs: number | undefined;
  let maxHistory: number | undefined;
  let color: boolean | undefined;
  const usage =
    'Usage: stellar-toml-lint detect-drift --domain <domain> [--git-path <path>] [--ref <ref>] ' +
    '[--format text|json|diff] [--timeout <ms>] [--url <live-url>] [--max-history <n>]\n';
  const positive = (flag: string, raw: string): number => {
    const value = Number(raw);
    if (!Number.isInteger(value) || value <= 0)
      throw new Error(`${flag} expects a positive integer.`);
    return value;
  };

  try {
    for (let i = 0; i < args.length; i++) {
      const arg = args[i] as string;
      if (arg === '--domain') domain = requireValue(args, ++i, arg);
      else if (arg === '--url') url = requireValue(args, ++i, arg);
      else if (arg === '--git-path') gitPath = requireValue(args, ++i, arg);
      else if (arg === '--ref') ref = requireValue(args, ++i, arg);
      else if (arg === '--format') format = requireValue(args, ++i, arg);
      else if (arg === '--timeout') timeoutMs = positive(arg, requireValue(args, ++i, arg));
      else if (arg === '--max-history') maxHistory = positive(arg, requireValue(args, ++i, arg));
      else if (arg === '--color') color = true;
      else if (arg === '--no-color') color = false;
      else throw new Error(`Unknown option ${arg} for detect-drift`);
    }
    if (!['text', 'json', 'diff'].includes(format)) {
      throw new Error('--format expects text, json or diff.');
    }
  } catch (error) {
    process.stderr.write(`${message(error)}\n${usage}`);
    return 2;
  }
  if (domain === undefined && url === undefined) {
    process.stderr.write(usage);
    return 2;
  }

  const useColor = color ?? shouldUseColor();
  let liveUrl: string | undefined = url;
  try {
    liveUrl ??= liveUrlForDomain(domain!);
    const report = await new GitOpsDriftDetector({
      ...(domain !== undefined ? { domain } : {}),
      url: liveUrl,
      ...(gitPath !== undefined ? { gitPath } : {}),
      ...(ref !== undefined ? { ref } : {}),
      ...(timeoutMs !== undefined ? { timeoutMs } : {}),
      ...(maxHistory !== undefined ? { maxHistory } : {}),
    }).detect();
    if (format === 'json') process.stdout.write(renderDriftJson(report));
    else if (format === 'diff')
      process.stdout.write(renderDriftLineDiff(report, { color: useColor }));
    else process.stdout.write(renderDriftText(report, { color: useColor }));
    return report.inSync ? 0 : 1;
  } catch (error) {
    if (format === 'json') {
      process.stdout.write(
        renderDriftErrorJson(error instanceof Error ? error : new Error(String(error)), liveUrl),
      );
    }
    const prefix = error instanceof DriftDetectionError ? `${error.code}: ` : '';
    process.stderr.write(`${prefix}${message(error)}\n`);
    return 2;
  }
}

const SOROBAN_TTL_USAGE = `stellar-toml-lint soroban-ttl --domain <domain> [options]

USAGE
  stellar-toml-lint soroban-ttl --domain <domain>
  stellar-toml-lint soroban-ttl --file <stellar.toml>

OPTIONS
  -d, --domain <domain>              Fetch https://<domain>/.well-known/stellar.toml
  -f, --file <path>                  Audit a local stellar.toml instead
      --rpc-url <url>                Soroban RPC endpoint (default: from NETWORK_PASSPHRASE)
      --min-buffer-ledgers <n>       Renewal horizon (default: 518400, ~30 days)
      --critical-buffer-ledgers <n>  Critical horizon (default: 86400, ~5 days)
      --format text|json             Output format (default: text)
      --key <base64-ledger-key>      Extra persistent ledger key to inspect (repeatable)

Exits 0 when every entry is healthy, 1 when any entry is expiring, critical, or
archived, and 2 when the file, the network, or the arguments cannot be read.
`;

/**
 * `stellar-toml-lint soroban-ttl --domain <domain> [--min-buffer-ledgers <n>]`
 *
 * Reads the contracts the file declares, looks each one's storage entries up
 * through Soroban RPC, and reports how far each is from archival. The exit code
 * is the CI contract: 0 healthy, 1 findings, 2 could not run.
 */
async function sorobanTtlCommand(args: string[]): Promise<number> {
  let domain: string | undefined;
  let file: string | undefined;
  let rpcUrl: string | undefined;
  let format = 'text';
  let minBufferLedgers: number | undefined;
  let criticalBufferLedgers: number | undefined;
  const extraKeys: string[] = [];

  const positive = (flag: string, raw: string): number => {
    const value = Number(raw);
    if (!Number.isInteger(value) || value <= 0) {
      throw new Error(`${flag} expects a positive integer.`);
    }
    return value;
  };

  try {
    for (let i = 0; i < args.length; i++) {
      const arg = args[i] as string;
      if (arg === '-h' || arg === '--help') {
        process.stdout.write(SOROBAN_TTL_USAGE);
        return 0;
      } else if (arg === '-d' || arg === '--domain') domain = requireValue(args, ++i, arg);
      else if (arg === '-f' || arg === '--file') file = requireValue(args, ++i, arg);
      else if (arg === '--rpc-url') rpcUrl = requireValue(args, ++i, arg);
      else if (arg === '--format') format = requireValue(args, ++i, arg);
      else if (arg === '--min-buffer-ledgers')
        minBufferLedgers = positive(arg, requireValue(args, ++i, arg));
      else if (arg === '--critical-buffer-ledgers')
        criticalBufferLedgers = positive(arg, requireValue(args, ++i, arg));
      else if (arg === '--key') extraKeys.push(requireValue(args, ++i, arg));
      else throw new Error(`Unknown option ${arg} for soroban-ttl`);
    }
    if (format !== 'text' && format !== 'json') {
      throw new Error('--format expects text or json.');
    }
    if (domain === undefined && file === undefined) {
      throw new Error('soroban-ttl needs --domain or --file.');
    }
  } catch (error) {
    process.stderr.write(`${message(error)}\n${SOROBAN_TTL_USAGE}`);
    return 2;
  }

  try {
    const source =
      file !== undefined
        ? await readFile(file, 'utf8')
        : await (async () => {
            const host = domain!.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
            const response = await fetch(`https://${host}/.well-known/stellar.toml`);
            if (!response.ok) {
              throw new Error(
                `Could not fetch https://${host}/.well-known/stellar.toml: HTTP ${response.status}`,
              );
            }
            return response.text();
          })();

    const doc = parseToml(source) as Record<string, unknown>;
    const targets = contractTargetsOf(doc);
    if (targets.length === 0) {
      process.stdout.write('No Soroban contracts found in the file.\n');
      return 0;
    }

    const passphrase =
      typeof doc.NETWORK_PASSPHRASE === 'string' ? doc.NETWORK_PASSPHRASE : undefined;
    const endpoint = rpcUrl ?? rpcUrlFor(passphrase);
    if (endpoint === undefined) {
      throw new Error('No Soroban RPC endpoint: set NETWORK_PASSPHRASE or pass --rpc-url.');
    }

    const options = {
      ...(minBufferLedgers !== undefined ? { minBufferLedgers } : {}),
      ...(criticalBufferLedgers !== undefined ? { criticalBufferLedgers } : {}),
      ...(extraKeys.length > 0
        ? { storageKeys: extraKeys.map((key) => ({ key, required: true as const })) }
        : {}),
    };
    const reports = await new SorobanTtlAuditor(options).auditAll(
      targets.map((target) => target.id),
      endpoint,
    );
    const thresholds = ttlThresholdsOf(options);

    if (format === 'json') {
      process.stdout.write(
        `${JSON.stringify({ network: passphrase ?? null, rpcUrl: endpoint, reports }, null, 2)}\n`,
      );
    } else {
      let out = '';
      for (const report of reports) {
        out += `Contract ${report.contractId} at ledger ${report.latestLedger}\n`;
        for (const entry of report.entries) {
          const remaining =
            entry.remainingLedgers === undefined
              ? 'archived'
              : `${entry.remainingLedgers} ledgers (~${ledgersToDays(entry.remainingLedgers)} days)`;
          out += `  ${entry.kind.padEnd(10)} ${entry.health.padEnd(8)} ${remaining}\n`;
        }
        if (report.extension !== undefined) {
          out +=
            `  extend ${report.extension.entries} entries to ledger ${report.extension.extendToLedger}: ` +
            `${report.extension.cpuInstructions} CPU instructions, ` +
            `${report.extension.readBytes} read bytes, ${report.extension.writeBytes} write bytes, ` +
            `fee bid ${report.extension.feeBidStroops} stroops\n`;
        }
        out += '\n';
      }
      if (thresholds.minBufferLedgers > thresholds.criticalBufferLedgers) {
        out += `Renewal buffer ${thresholds.minBufferLedgers} ledgers, critical buffer ${thresholds.criticalBufferLedgers} ledgers\n`;
      }
      process.stdout.write(out);
    }

    return reports.some((report) => report.diagnostics.length > 0) ? 1 : 0;
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }
}

/** Run the Vault secret engine verifier; returns 1 to halt, undefined to continue. */
async function auditVaultSecretsOrHalt(path: string, source: string): Promise<number | undefined> {
  const result = await new VaultSecretEngineVerifier().verifyFile(path, source);
  if (result.passed) return undefined;
  process.stderr.write(`${result.summary}\n`);
  return 1;
}

const MIGRATE_USAGE = `stellar-toml-lint migrate [file...] [options]

Rewrite deprecated SEP-1 fields into the form the spec uses today, in place.

USAGE
  stellar-toml-lint migrate                  Migrate ./stellar.toml
  stellar-toml-lint migrate "cfg/*.toml"     Migrate a glob (quote it)
  stellar-toml-lint migrate --dry-run        Show the diff, change nothing
  cat stellar.toml | stellar-toml-lint migrate -
                                             Migrate stdin to stdout

OPTIONS
  -h, --help             Show this help
      --dry-run          Print a unified diff instead of writing, and exit 1
                         when a file still needs migrating
      --json             Report the plan as JSON
      --skip-rule <id>   Leave one migration undone (repeatable)
      --domain <domain>  Validate the result as if it were served from this
                         domain. Nothing is fetched — the files on disk are
                         what gets migrated.

MIGRATIONS
${migrationList()}
`;

/**
 * The migrations on offer, read from the registry.
 *
 * The list is generated rather than written out so `--help` cannot advertise a
 * rule that was renamed, or hide one that was added.
 */
function migrationList(): string {
  return MIGRATION_RULES.map((rule) => `  ${rule.id}\n    ${rule.reason}`).join('\n');
}

/**
 * `migrate` rewrites files through the migration codemod.
 *
 * The rewrite is refused, per file, whenever the result would be worse than the
 * input; the exit code says so instead of leaving a half-migrated tree behind a
 * green run. As with `--sort-keys`, `--dry-run` runs the identical pass so a
 * preview cannot disagree with what the write would have done.
 */
async function migrateCommand(argv: string[], color: boolean): Promise<number> {
  const paths: string[] = [];
  const skipRules: string[] = [];
  let dryRun = false;
  let json = false;
  let domain: string | undefined;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] as string;
    switch (arg) {
      case '-h':
      case '--help':
        process.stdout.write(MIGRATE_USAGE);
        return 0;
      case '--dry-run':
        dryRun = true;
        break;
      case '--json':
        json = true;
        break;
      case '--skip-rule': {
        const value = argv[++i];
        if (value === undefined) {
          process.stderr.write(`--skip-rule needs a rule id.\n\n${MIGRATE_USAGE}`);
          return 2;
        }
        skipRules.push(value);
        break;
      }
      case '--domain': {
        const value = argv[++i];
        if (value === undefined) {
          process.stderr.write(`--domain needs a value.\n\n${MIGRATE_USAGE}`);
          return 2;
        }
        domain = value;
        break;
      }
      default:
        // `-` is stdin, not an option, and the usage block promises it.
        if (arg.startsWith('--')) {
          process.stderr.write(`Unknown option "${arg}".\n\n${MIGRATE_USAGE}`);
          return 2;
        }
        paths.push(arg);
    }
  }

  const known = new Set(MIGRATION_RULES.map((rule) => rule.id));
  const unknown = skipRules.filter((id) => !known.has(id));
  if (unknown.length > 0) {
    process.stderr.write(
      `Unknown migration rule${unknown.length > 1 ? 's' : ''}: ${unknown.join(', ')}.\n\n${MIGRATE_USAGE}`,
    );
    return 2;
  }

  const codemod = new SchemaMigrationCodemod();
  const options: MigrationOptions = {
    ...(skipRules.length > 0 ? { skipRules } : {}),
    ...(domain === undefined ? {} : { domain }),
  };

  const files: {
    name: string;
    parsed: boolean;
    changed: boolean;
    steps: { rule: string; path: string; action: string; description: string }[];
    notes: string[];
    refusal?: string;
  }[] = [];
  let pending = 0;
  let refused = 0;
  let unparseable = 0;

  try {
    const inputs = await expandInputs(paths.length > 0 ? paths : [DEFAULT_PATH]);
    for (const path of inputs) {
      const name = path === '-' ? 'stdin' : path;
      const source = path === '-' ? await readStdin() : await readFile(resolve(path), 'utf8');
      const result = codemod.run(source, options);
      const report = {
        name,
        parsed: result.parsed,
        changed: result.changed,
        steps: result.steps.map((step) => ({
          rule: step.rule,
          path: step.path,
          action: step.action,
          description: step.description,
        })),
        notes: result.notes,
        ...(result.refusal === undefined ? {} : { refusal: result.refusal }),
      };
      files.push(report);

      if (!result.parsed) {
        unparseable++;
        continue;
      }
      // A plan that was thrown away is the one outcome a caller must not miss:
      // the file still holds the deprecated field.
      if (!result.validated) refused++;
      if (!result.changed) continue;
      pending++;

      if (json) continue;
      if (dryRun) {
        process.stdout.write(formatUnifiedDiff(name, source, result.output, { color }));
      } else if (path === '-') {
        process.stdout.write(result.output);
      } else {
        await writeFile(resolve(path), result.output);
      }
      for (const step of result.steps) process.stdout.write(`${name}: ${step.description}\n`);
      if (!dryRun && path !== '-') process.stdout.write(`${name}: migrated\n`);
    }
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }

  if (json) {
    process.stdout.write(`${JSON.stringify({ files, pending, refused, unparseable }, null, 2)}\n`);
  } else {
    for (const file of files) {
      for (const note of file.notes) process.stderr.write(`${file.name}: ${note}\n`);
      if (file.refusal !== undefined) process.stderr.write(`${file.name}: ${file.refusal}\n`);
    }
    if (pending === 0 && refused === 0 && unparseable === 0) {
      process.stdout.write('No deprecated fields to migrate.\n');
    }
  }

  // Only a dry run fails on work still to do — that is what makes it usable as
  // a CI gate. In apply mode the migration *is* the success; a file the codemod
  // refused to rewrite, or could not read at all, is the non-zero exit.
  if (refused > 0 || unparseable > 0) return 1;
  return dryRun && pending > 0 ? 1 : 0;
}

/**
 * `--detect-orphans` reports keys and table headers that configure nothing;
 * `--prune-orphaned` applies the findings that are safe to apply.
 *
 * Both read the same scan, so what the preview says is exactly what the rewrite
 * would do — and a finding `migrate` owns is reported as a move, never deleted.
 */
async function orphanCommand(cli: Cli, color: boolean): Promise<number> {
  if (cli.domain !== undefined) {
    process.stderr.write(
      '--detect-orphans and --prune-orphaned read files on disk, so they cannot be combined with --domain.\n\nRun with --help for usage.\n',
    );
    return 2;
  }

  const prune = cli.pruneOrphaned === true;
  let findings = 0;
  let unparseable = 0;

  try {
    const paths = await expandInputs(cli.paths.length > 0 ? cli.paths : [DEFAULT_PATH]);
    for (const path of paths) {
      const name = path === '-' ? 'stdin' : path;
      const source = path === '-' ? await readStdin() : await readFile(resolve(path), 'utf8');
      const allowKeys = await allowKeysFor(cli, path);
      const options: OrphanScanOptions = allowKeys.length > 0 ? { allowKeys } : {};
      const scan = new OrphanedKeyScanner().scan(source, options);
      findings += scan.findings.length;
      if (!scan.parsed) unparseable++;
      if (scan.allowed > 0) {
        process.stderr.write(`${name}: ${scan.allowed} key(s) matched the allow-list\n`);
      }

      if (!prune) {
        const result = finalize(
          scan.findings.map(orphanDiagnostic),
          { strict: cli.strict },
          undefined,
        );
        process.stdout.write(render(result, name, cli, color, source));
        continue;
      }

      const result = pruneOrphans(source, options);
      for (const warning of result.warnings) process.stderr.write(`${name}: ${warning}\n`);

      if (cli.dryRun) {
        process.stdout.write(formatUnifiedDiff(name, source, result.output, { color }));
      } else if (path === '-') {
        process.stdout.write(result.output);
      } else if (result.changed) {
        await writeFile(resolve(path), result.output);
      }
      for (const action of result.actions) {
        process.stdout.write(`${name}: ${describeAction(action)}\n`);
      }
    }
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }

  // No summary line of its own: the text reporter already answers "nothing
  // found", and prose appended after a machine format would break the parser
  // reading it.

  // Detecting and dry-running are gates: a finding is the failure the caller is
  // asking about. Applying is not — the file has been fixed, so only a file that
  // could not be read is a non-zero exit.
  if (cli.dryRun || !prune) return findings > 0 || unparseable > 0 ? 1 : 0;
  return unparseable > 0 ? 1 : 0;
}

/**
 * An orphan as a diagnostic, so `--detect-orphans` answers in whatever format
 * `--format` asks for instead of inventing a second report shape.
 *
 * The rule id is deliberately not in the rule registry: a key that configures
 * nothing is not a SEP-1 violation, so it is a warning and only `--strict`, or
 * the exit code above, turns it into a failure.
 */
function orphanDiagnostic(finding: OrphanFinding): Diagnostic {
  return {
    rule: `general/${finding.kind}`,
    severity: 'warning',
    category: 'general',
    message: finding.message,
    path: finding.path,
    position: { line: finding.line, column: finding.column },
  };
}

/** What a prune did, in the words a reviewer reads in `--dry-run`. */
function describeAction(action: PruneAction): string {
  const where = action.section === '' ? action.written : `${action.section}.${action.written}`;
  if (action.kind === 'removed') return `removed ${where} (no SEP defines it)`;
  return `renamed ${where} to ${action.suggestion}`;
}

/**
 * Names the orphan scan is told to accept: `--allow-key`, plus the project's
 * `knownKeys` from the config file nearest the file being scanned.
 *
 * A vendor section belongs to the team that owns the repo, so it is blessed
 * once in the config; a one-off run overrides that with flags, which join on
 * top rather than replace it.
 */
async function allowKeysFor(cli: Cli, path: string): Promise<string[]> {
  const config = await loadConfig(path === '-' ? process.cwd() : dirname(resolve(path)));
  return [...(config.knownKeys ?? []), ...(cli.allowKeys ?? [])];
}

/**
 * `init-ci`: writes a GitHub Actions workflow validating one stellar.toml per
 * environment across a Node.js matrix. Exit codes: 0 written, 1 the target
 * exists (without --force), 2 bad usage.
 */
async function initCiCommand(args: string[]): Promise<number> {
  const files: NonNullable<CiMatrixWorkflowOptions['files']> = {};
  const options: CiMatrixWorkflowOptions = { toolVersion: VERSION, files };
  let toStdout = false;
  let force = false;

  try {
    for (let i = 0; i < args.length; i++) {
      const arg = args[i] as string;
      switch (arg) {
        case '-h':
        case '--help':
          process.stdout.write(USAGE);
          return 0;
        case '--matrix':
          options.environments = parseCiMatrix(requireValue(args, ++i, arg));
          break;
        case '--node':
          options.nodeVersions = requireValue(args, ++i, arg)
            .split(',')
            .map((v) => v.trim())
            .filter((v) => v !== '');
          break;
        case '--file-pattern':
          options.filePattern = requireValue(args, ++i, arg);
          break;
        case '--file': {
          const value = requireValue(args, ++i, arg);
          const eq = value.indexOf('=');
          const env = eq > 0 ? resolveCiEnvironment(value.slice(0, eq)) : undefined;
          if (env === undefined) throw new Error('--file expects <environment>=<path>');
          files[env] = value.slice(eq + 1);
          break;
        }
        case '-o':
        case '--output':
          options.workflowPath = requireValue(args, ++i, arg);
          break;
        case '--check-network':
          options.checkNetwork = true;
          break;
        case '--no-check-network':
          options.checkNetwork = false;
          break;
        case '--strict':
          options.strict = true;
          break;
        case '--no-sarif':
          options.sarif = false;
          break;
        case '--no-pr-comment':
          options.prComment = false;
          break;
        case '--no-cache':
          options.cache = false;
          break;
        case '--stdout':
          toStdout = true;
          break;
        case '--force':
          force = true;
          break;
        default:
          throw new Error(`Unknown option "${arg}" for init-ci`);
      }
    }
    const matrix = options.environments ?? ['testnet', 'public'];
    for (const env of Object.keys(files)) {
      if (!matrix.includes(env as (typeof matrix)[number])) {
        throw new Error(`--file names "${env}", which is not in --matrix`);
      }
    }
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }

  let generator: CiMatrixWorkflowGenerator;
  try {
    generator = new CiMatrixWorkflowGenerator(options);
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }

  const yaml = generator.generate();
  if (toStdout) {
    process.stdout.write(yaml);
    return 0;
  }

  const target = resolve(generator.workflowPath);
  try {
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, yaml, { encoding: 'utf8', flag: force ? 'w' : 'wx' });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
      process.stderr.write(`${generator.workflowPath} already exists; pass --force to overwrite\n`);
      return 1;
    }
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }

  const listed = Object.entries(generator.files).map(([env, file]) => `  ${env}: ${file}`);
  process.stdout.write(
    `Wrote ${generator.workflowPath}\nValidating:\n${listed.join('\n')}\n` +
      'Commit it, then enable code scanning to see SARIF alerts in the Security tab.\n',
  );
  return 0;
}

/**
 * `ci-report`: turns one matrix cell's linter output into the environment
 * report, SARIF file and scorecard fragment. It exits 0 once inputs are valid —
 * pass/fail is published as `ok=` on $GITHUB_OUTPUT so the workflow can upload
 * results before failing the job.
 */
async function ciReportCommand(args: string[]): Promise<number> {
  let environment: string | undefined;
  let file: string | undefined;
  let lintJsonPath: string | undefined;
  let lintExitCode = 0;
  let node: string | undefined;
  let outDir = 'reports';
  let checkNetwork = false;
  let strict = false;

  try {
    for (let i = 0; i < args.length; i++) {
      const arg = args[i] as string;
      if (arg === '--environment') environment = requireValue(args, ++i, arg);
      else if (arg === '--file') file = requireValue(args, ++i, arg);
      else if (arg === '--lint-json') lintJsonPath = requireValue(args, ++i, arg);
      else if (arg === '--lint-exit-code') {
        lintExitCode = Number(requireValue(args, ++i, arg));
        if (!Number.isInteger(lintExitCode) || lintExitCode < 0) {
          throw new Error('--lint-exit-code expects a non-negative integer');
        }
      } else if (arg === '--node') node = requireValue(args, ++i, arg);
      else if (arg === '--out-dir') outDir = requireValue(args, ++i, arg);
      else if (arg === '--check-network') checkNetwork = true;
      else if (arg === '--strict') strict = true;
      else throw new Error(`Unknown option "${arg}" for ci-report`);
    }
    if (environment === undefined || file === undefined) {
      throw new Error(
        'Usage: stellar-toml-lint ci-report --environment <env> --file <path> ' +
          '[--lint-json <file>] [--lint-exit-code <n>] [--node <v>] [--out-dir <dir>]',
      );
    }
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }

  const env = resolveCiEnvironment(environment);
  if (env === undefined) {
    process.stderr.write(`Unknown environment "${environment}"\n`);
    return 2;
  }

  const source = await readFile(resolve(file), 'utf8').catch(() => undefined);
  const lintJson =
    lintJsonPath === undefined
      ? undefined
      : await readFile(resolve(lintJsonPath), 'utf8').catch(() => undefined);
  const report = buildCiReport({
    environment: env,
    file,
    ...(node === undefined ? {} : { node }),
    checkNetwork,
    strict,
    lintExitCode,
    ...(lintJson === undefined ? {} : { lintJson }),
    isolation: source === undefined ? [] : checkNetworkIsolation(source, env),
  });
  if (source === undefined && report.error === undefined) {
    report.error = `could not read ${file}`;
    report.ok = false;
  }

  const markdown = formatEnvironmentScorecard(report);
  try {
    const dir = resolve(outDir);
    await mkdir(dir, { recursive: true });
    await writeFile(resolve(dir, `${env}.json`), `${JSON.stringify(report, null, 2)}\n`, 'utf8');
    await writeFile(
      resolve(dir, `${env}.sarif`),
      formatCiSarif([report], VERSION, source === undefined ? {} : { [file]: source }),
      'utf8',
    );
    await writeFile(resolve(dir, `${env}.md`), markdown, 'utf8');
    if (process.env.GITHUB_OUTPUT) {
      await writeFile(process.env.GITHUB_OUTPUT, `ok=${report.ok}\n`, { flag: 'a' });
    }
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }

  process.stdout.write(markdown);
  return 0;
}

/** Reads every CI report under `dir`, up to two levels of artifact folders deep. */
async function readCiReports(dir: string): Promise<CiEnvironmentReport[]> {
  const reports: CiEnvironmentReport[] = [];
  const visit = async (path: string, depth: number): Promise<void> => {
    const entries = await readdir(path, { withFileTypes: true });
    for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      const full = resolve(path, entry.name);
      if (entry.isDirectory() && depth < 2) await visit(full, depth + 1);
      else if (entry.isFile() && entry.name.endsWith('.json')) {
        try {
          const parsed: unknown = JSON.parse(await readFile(full, 'utf8'));
          if (isCiEnvironmentReport(parsed)) reports.push(parsed);
        } catch {
          // Not a report; artifacts may carry other JSON.
        }
      }
    }
  };
  await visit(dir, 0);
  return reports;
}

/** `ci-scorecard`: combines the matrix's reports into the PR comment body. */
async function ciScorecardCommand(args: string[]): Promise<number> {
  let input: string | undefined;
  let output: string | undefined;
  let runUrl: string | undefined;
  let commit: string | undefined;
  try {
    for (let i = 0; i < args.length; i++) {
      const arg = args[i] as string;
      if (arg === '--input') input = requireValue(args, ++i, arg);
      else if (arg === '--output') output = requireValue(args, ++i, arg);
      else if (arg === '--run-url') runUrl = requireValue(args, ++i, arg);
      else if (arg === '--commit') commit = requireValue(args, ++i, arg);
      else throw new Error(`Unknown option "${arg}" for ci-scorecard`);
    }
    if (input === undefined) {
      throw new Error('Usage: stellar-toml-lint ci-scorecard --input <dir> [--output <file>]');
    }
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }

  let reports: CiEnvironmentReport[];
  try {
    reports = await readCiReports(resolve(input));
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }
  const markdown = formatCiScorecard(reports, {
    ...(runUrl ? { runUrl } : {}),
    ...(commit ? { commit } : {}),
  });
  if (output === undefined) process.stdout.write(markdown);
  else await writeFile(resolve(output), markdown, 'utf8');
  return 0;
}

async function main(argv: string[]): Promise<number> {
  if (argv[0] === 'test-kms-signer') {
    try {
      return await runKmsSignerCommand(argv.slice(1));
    } catch (error) {
      const text = error instanceof KmsError ? `${error.code}: ${error.message}` : message(error);
      process.stderr.write(`${text}\n`);
      return error instanceof KmsError && !isKmsUsageError(error.code) ? 1 : 2;
    }
  }

  // `verify-promotions --domain <domain>` is the flag form with quotes enabled.
  if (argv[0] === 'verify-promotions') {
    argv = ['--verify-promotions', '--check-network', ...argv.slice(1)];
  }
  // `verify-por-feed` / `verify-solana-bridge --domain <domain>` are the flag forms with RPC queries.
  if (argv[0] === 'verify-por-feed' || argv[0] === 'verify-solana-bridge') {
    const flag = argv[0] === 'verify-por-feed' ? '--verify-por-feed' : '--verify-solana-bridge';
    argv = [flag, '--check-network', ...argv.slice(1)];
  }
  if (argv[0] === 'audit-wormhole-vaa') return auditWormholeVaaCommand(argv.slice(1));
  if (argv[0] === 'verify-attestations') {
    argv = ['--verify-attestations', '--check-network', ...argv.slice(1)];
  }
  if (argv[0] === 'benchmark-bridge-latency') return benchmarkBridgeLatencyCommand(argv.slice(1));
  if (argv[0] === 'audit-bridge-quorum') {
    argv = ['--audit-bridge-quorum', '--check-network', ...argv.slice(1)];
  }
  if (argv[0] === 'audit-ciphers') return auditCiphersCommand(argv.slice(1));
  // `sep38-volatility --domain <domain>` books live quotes, so network is implied.
  if (argv[0] === 'sep38-volatility') {
    argv = ['--audit-sep38-volatility', '--check-network', ...argv.slice(1)];
  }
  // `sep38-spreads --domain <domain>` requests live indicative and firm quotes.
  if (argv[0] === 'sep38-spreads') {
    argv = ['--audit-sep38-spreads', '--check-network', ...argv.slice(1)];
  }
  if (argv[0] === 'refactor') return refactorCommand(argv.slice(1));
  if (argv[0] === 'profile-wasm-heap') return runHeapProfileCommand(argv.slice(1));
  if (argv[0] === 'audit-clawbacks') return auditClawbacks(argv.slice(1));
  if (argv[0] === 'dispatch-alert') return dispatchAlert(argv.slice(1));
  if (argv[0] === 'audit-coop-coep') return auditCoopCoep(argv.slice(1));
  if (argv[0] === 'verify-federation-sync') return verifyFederationSyncCommand(argv.slice(1));
  if (argv[0] === 'verify-sep31-sep12') return verifySep31Sep12Command(argv.slice(1));
  if (argv[0] === 'verify-browser-bundle') return verifyBrowserBundleCommand(argv.slice(1));
  if (argv[0] === 'sync-directory') return syncDirectory(argv.slice(1));
  if (argv[0] === 'verify-archive-gpg') return verifyArchiveGpgCommand(argv.slice(1));
  if (argv[0] === 'audit-quorum') return auditQuorumCommand(argv.slice(1));
  if (argv[0] === 'verify-archive-lag') return verifyArchiveLagCommand(argv.slice(1));
  if (argv[0] === 'score-diversity') return scoreDiversityCommand(argv.slice(1));
  if (argv[0] === 'trace-scp') return traceScpCommand(argv.slice(1));
  if (argv[0] === 'audit-wasm-simd') return auditWasmSimd(argv.slice(1));
  if (argv[0] === 'audit-wasm-memory') return auditWasmMemory(argv.slice(1));
  if (argv[0] === 'auth-tree') return authTreeCommand(argv.slice(1));
  if (argv[0] === 'audit-signature-replay' || argv[0] === '--audit-signature-replay') {
    return auditSignatureReplayCommand(argv.slice(1));
  }
  if (argv[0] === 'verify-provenance') return verifyProvenance(argv.slice(1));
  if (argv[0] === 'audit-dockerfile') return auditContainer(argv.slice(1));
  if (argv[0] === 'migrate') return migrateCommand(argv.slice(1), shouldUseColor());
  if (argv[0] === 'verify-metrics') return verifyMetricsCommand(argv.slice(1));
  if (argv[0] === 'probe-sla') return probeSlaCommand(argv.slice(1));
  if (argv[0] === 'calculate-uptime') return calculateUptimeCommand(argv.slice(1));
  if (argv[0] === 'audit-error-taxonomy') return auditErrorTaxonomyCommand(argv.slice(1));
  if (argv.includes('--audit-error-taxonomy')) return auditErrorTaxonomyCommand(argv);
  if (argv[0] === 'audit-key-separation') return auditKeySeparationCommand(argv.slice(1));
  if (argv[0] === 'init-ci') return initCiCommand(argv.slice(1));
  if (argv[0] === 'ci-report') return ciReportCommand(argv.slice(1));
  if (argv[0] === 'ci-scorecard') return ciScorecardCommand(argv.slice(1));
  if (argv[0] === 'audit-validator-rotation') return auditValidatorRotationCommand(argv.slice(1));
  if (argv[0] === 'verify-rate-headers') return verifyRateHeadersCommand(argv.slice(1));
  if (argv[0] === 'audit-flood-policy') return auditFloodPolicyCommand(argv.slice(1));
  if (argv[0] === 'audit-tls') return auditTlsCommand(argv.slice(1));
  if (argv[0] === 'detect-drift') return detectDriftCommand(argv.slice(1));
  if (argv[0] === 'soroban-ttl') return sorobanTtlCommand(argv.slice(1));
  if (argv[0] === 'verify-provenance') return verifyProvenance(argv.slice(1));
  if (argv[0] === 'audit-dockerfile') return auditContainer(argv.slice(1));
  if (argv[0] === 'format') return formatCommand(argv.slice(1));
  if (argv[0] === 'diff') return diffCommand(argv.slice(1));
  let cli: Cli;
  try {
    const parsed = parseArgs(argv);
    if (parsed === 'handled') return 0;
    cli = parsed;
  } catch (error) {
    process.stderr.write(`${message(error)}\n\nRun with --help for usage.\n`);
    return 2;
  }

  if (cli.runSandboxedPlugin !== undefined) {
    return runSandboxedPlugin(cli.runSandboxedPlugin, cli.sandboxFuel);
  }
  if (cli.auditOfflinePwa !== undefined) return auditOfflinePwa(cli.auditOfflinePwa);
  if (cli.auditEdgeCompatibility !== undefined) {
    return auditEdgeCompatibility(cli.auditEdgeCompatibility);
  }
  if (cli.verifyWasmStreaming !== undefined) {
    return verifyWasmStreaming(cli.verifyWasmStreaming);
  }

  if (cli.dryRun && !cli.sortKeys && !cli.pruneOrphaned) {
    process.stderr.write(
      '--dry-run has nothing to preview without --sort-keys or --prune-orphaned.\n\nRun with --help for usage.\n',
    );
    return 2;
  }

  const color = cli.color ?? shouldUseColor();

  if (cli.sortKeys) return sortKeysCommand(cli, color);
  if (cli.detectOrphans || cli.pruneOrphaned) return orphanCommand(cli, color);

  // Plugins load once, here, before the first file: `lint()` stays synchronous and
  // keeps the filesystem out of the core, and a broken plugin is a usage error
  // rather than a finding repeated against every input. `runLint` closes over
  // these, so `--watch` and `--domain` get the same rules as a plain file run.
  let pluginRules: SemanticRule[] = [];
  if (cli.rulesDir.length > 0 || cli.plugins.length > 0) {
    try {
      pluginRules = await loadPluginRules({
        dirs: cli.rulesDir,
        modules: cli.plugins,
        reservedIds: allRules.map((rule) => rule.id),
      });
    } catch (error) {
      process.stderr.write(`${message(error)}\n`);
      return 2;
    }
    // `parseArgs` could not know these ids yet; now that it does, a typo in
    // `--off/--error/--warn` fails the same way it does without plugins.
    const loadedIds = pluginRules.map((rule) => rule.id);
    for (const id of Object.keys(cli.rules)) assertKnownRule(id, undefined, loadedIds);
    if (!cli.quiet && loadedIds.length > 0) {
      process.stderr.write(`Loaded ${loadedIds.length} plugin rule(s): ${loadedIds.join(', ')}\n`);
    }
  }
  const pluginRuleIds = pluginRules.map((rule) => rule.id);
  // Absent rather than empty: an option that is not set is the same run as
  // before plugins existed, and `lint()` only ever touches the engine when it is.
  const pluginOptions: Pick<LintOptions, 'semanticRules'> =
    pluginRules.length > 0 ? { semanticRules: pluginRules } : {};

  const runLint = async (cli: Cli, color: boolean): Promise<number> => {
    if (cli.lsp) {
      // The framed stdio server: diagnostics, quick fixes, and hover. It used to
      // be `lspMain()`, which registered a stdin listener and then let `main()`
      // fall through to `process.exit` — so `--lsp` printed nothing and exited
      // before a client could send a single message.
      await runLspServer();
      return 0;
    }

    const results: { name: string; result: LintResult; source?: string }[] = [];
    // Project defaults from .stellartomlrc.json, overridden by any CLI flag.
    let strict = cli.strict;
    let maxWarnings = cli.maxWarnings;

    try {
      // Fixture mode replaces the transport for every network-bound check, so a
      // hermetic run can never reach the internet by accident.
      const assetCache = process.env[ASSET_CACHE_ENV];
      const fetchImpl =
        cli.mockFixtures !== undefined
          ? createFixtureFetch(cli.mockFixtures)
          : assetCache
            ? createAssetCacheFetch(fetch, resolve(assetCache))
            : fetch;

      if (cli.domain && cli.paths.length === 0) {
        const config = await loadConfig(process.cwd(), pluginRuleIds);
        strict = strict || config.strict;
        maxWarnings ??= config.maxWarnings;
        const rules = { ...config.rules, ...cli.rules };
        let domainResult = await lintDomain(
          cli.domain,
          {
            strict,
            rules,
            checkNetwork: cli.checkNetwork,
            followLinks: true,
            ...pluginOptions,
          },
          fetchImpl,
        );
        if (cli.auditSecrets) {
          const host = cli.domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
          let secretSource: string | undefined;
          try {
            const response = await fetchImpl(`https://${host}/.well-known/stellar.toml`, {
              redirect: 'follow',
            });
            if (response.ok) secretSource = await response.text();
          } catch {
            // The parsed document is still scanned when the refetch fails.
          }
          const halted = await auditSecretsOrHalt(domainResult.parsed, secretSource, rules);
          if (halted !== undefined) return halted;
        }
        if (cli.auditVaultSecrets) {
          const host = cli.domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
          const response = await fetchImpl(`https://${host}/.well-known/stellar.toml`, {
            redirect: 'follow',
          });
          if (!response.ok) {
            process.stderr.write(
              `Could not fetch https://${host}/.well-known/stellar.toml: HTTP ${response.status}\n`,
            );
            return 2;
          }
          const halted = await auditVaultSecretsOrHalt('stellar.toml', await response.text());
          if (halted !== undefined) return halted;
        }
        if (domainResult.parsed && cli.checkNetwork) {
          const networkDiagnostics: Diagnostic[] = [
            ...(await checkHistoryPublish(domainResult.parsed, fetchImpl, { rules })),
            ...(await auditTomlAuthTree(domainResult.parsed, fetchImpl, {
              rules,
              ...(cli.sorobanRpc !== undefined ? { rpcUrl: cli.sorobanRpc } : {}),
            })),
            ...(cli.verifyDnssec
              ? await checkDnsIntegrity(domainResult.parsed, fetchImpl, {
                  rules,
                  domain: cli.domain,
                })
              : []),
            ...(cli.crawlPeers && cli.mockFixtures === undefined
              ? await checkOverlayPeers(domainResult.parsed, { rules })
              : []),
          ];
          if (networkDiagnostics.length > 0) {
            domainResult = finalize(
              [...domainResult.diagnostics, ...networkDiagnostics],
              { strict },
              domainResult.parsed,
            );
          }
        }
        if (domainResult.parsed && cli.auditEvents) {
          const eventDiagnostics = await auditTomlEvents(domainResult.parsed, fetchImpl, {
            rules,
            ...(cli.sorobanRpc !== undefined ? { rpcUrl: cli.sorobanRpc } : {}),
          });
          if (eventDiagnostics.length > 0) {
            domainResult = finalize(
              [...domainResult.diagnostics, ...eventDiagnostics],
              { strict },
              domainResult.parsed,
            );
          }
        }
        if (domainResult.parsed) {
          const extra = await runExtraAudits(
            cli,
            domainResult.parsed,
            fetchImpl,
            rules,
            cli.domain,
          );
          if (extra.length > 0) {
            domainResult = finalize(
              [...domainResult.diagnostics, ...extra],
              { strict },
              domainResult.parsed,
            );
          }
        }
        results.push({ name: cli.domain, result: domainResult });
      } else {
        const paths = await expandInputs(cli.paths.length > 0 ? cli.paths : [DEFAULT_PATH]);
        for (const path of paths) {
          const config = await loadConfig(
            path === '-' ? process.cwd() : dirname(resolve(path)),
            pluginRuleIds,
          );
          const fileStrict = cli.strict || config.strict;
          strict = strict || config.strict;
          maxWarnings ??= config.maxWarnings;
          const rules = { ...config.rules, ...cli.rules };

          const source = path === '-' ? await readStdin() : await readFile(path, 'utf8');
          let fileResult = lint(source, {
            strict: fileStrict,
            rules,
            checkNetwork: cli.checkNetwork,
            ...(cli.domain ? { domain: cli.domain } : {}),
            ...pluginOptions,
          });

          if (cli.auditSecrets) {
            const halted = await auditSecretsOrHalt(fileResult.parsed, source, rules);
            if (halted !== undefined) return halted;
          }

          if (cli.auditVaultSecrets) {
            const halted = await auditVaultSecretsOrHalt(path === '-' ? 'stdin' : path, source);
            if (halted !== undefined) return halted;
          }

          if (fileResult.parsed) {
            const extra = await runExtraAudits(
              cli,
              fileResult.parsed,
              fetchImpl,
              rules,
              cli.domain,
            );
            if (extra.length > 0) {
              fileResult = finalize(
                [...fileResult.diagnostics, ...extra],
                { strict: fileStrict },
                fileResult.parsed,
              );
            }
          }

          if (
            fileResult.parsed &&
            (cli.checkNetwork ||
              cli.checkContracts ||
              cli.auditReentrancy ||
              cli.auditEvents ||
              cli.followLinks ||
              cli.domain !== undefined)
          ) {
            const networkDiagnostics: Diagnostic[] = [];

            // SEP-6 is reachable under either flag: `--domain` already means the
            // file was fetched from a live host, and `--check-network` is the
            // explicit opt-in for a local file.
            if (cli.checkNetwork || cli.domain !== undefined) {
              networkDiagnostics.push(
                ...(await checkSep6(fileResult.parsed, fetchImpl, { rules })),
              );
            }

            if (cli.verifySep10 && cli.checkNetwork) {
              const webAuthEndpoint = (fileResult.parsed as Record<string, unknown>)
                .WEB_AUTH_ENDPOINT;
              if (typeof webAuthEndpoint === 'string') {
                const signingKey =
                  typeof (fileResult.parsed as Record<string, unknown>).SIGNING_KEY === 'string'
                    ? ((fileResult.parsed as Record<string, unknown>).SIGNING_KEY as string)
                    : '';
                networkDiagnostics.push(
                  ...(await checkSep10Replay(signingKey, new URL(webAuthEndpoint).origin, {
                    rules,
                    fetchImpl,
                  })),
                  ...(await checkSep10ClientDomain(signingKey, webAuthEndpoint, {
                    rules,
                    fetchImpl,
                  })),
                );
              }
            }

            if (cli.auditQuotes && cli.checkNetwork) {
              networkDiagnostics.push(
                ...(await auditQuoteBinding(fileResult.parsed, fetchImpl, { rules })),
              );
            }
            if (cli.checkNetwork) {
              networkDiagnostics.push(
                ...(await checkHorizon(fileResult.parsed, fetchImpl, { rules })),
                ...(await checkNetworkAccounts(fileResult.parsed, fetchImpl)),
                ...(await checkDisplayDecimals(fileResult.parsed, fetchImpl, { rules })),
                ...(await checkSep38(fileResult.parsed, fetchImpl, { rules })),
                ...(await checkRegulatedIssuerFlags(fileResult.parsed, fetchImpl, {
                  rules,
                })),
                ...(await checkCorsPreflight(fileResult.parsed, fetchImpl, { rules })),
                ...(await checkHistoryPublish(fileResult.parsed, fetchImpl, { rules })),
                ...(cli.verifyDnssec
                  ? await checkDnsIntegrity(fileResult.parsed, fetchImpl, {
                      rules,
                      ...(cli.domain === undefined ? {} : { domain: cli.domain }),
                    })
                  : []),
                ...(cli.crawlPeers && cli.mockFixtures === undefined
                  ? await checkOverlayPeers(fileResult.parsed, { rules })
                  : []),
              );
            }

            if (cli.checkNetwork) {
              networkDiagnostics.push(
                ...(await checkCollateralGovernance(fileResult.parsed, {
                  rules,
                  fetchImpl,
                })),
                ...(await checkContracts(fileResult.parsed, fetchImpl, {
                  rules,
                  ...(cli.auditReentrancy ? { auditReentrancy: true } : {}),
                  ...(cli.sorobanRpc !== undefined ? { rpcUrl: cli.sorobanRpc } : {}),
                })),
                ...(await auditTomlAuthTree(fileResult.parsed, fetchImpl, {
                  rules,
                  ...(cli.sorobanRpc !== undefined ? { rpcUrl: cli.sorobanRpc } : {}),
                })),
              );
            }

            if (cli.followLinks) {
              networkDiagnostics.push(
                ...(await followTomlPointers(
                  fileResult.parsed,
                  { strict: fileStrict, rules, domain: cli.domain, ...pluginOptions },
                  fetchImpl,
                )),
              );
            }

            if (cli.checkContracts) {
              networkDiagnostics.push(
                ...(await checkContracts(fileResult.parsed, fetchImpl, {
                  rules,
                  ...(cli.auditReentrancy ? { auditReentrancy: true } : {}),
                  ...(cli.sorobanRpc !== undefined ? { rpcUrl: cli.sorobanRpc } : {}),
                })),
              );
            }

            if (cli.auditReentrancy && !cli.checkNetwork && !cli.checkContracts) {
              networkDiagnostics.push(
                ...(await checkContracts(fileResult.parsed, fetchImpl, {
                  rules,
                  auditReentrancy: true,
                  ...(cli.sorobanRpc !== undefined ? { rpcUrl: cli.sorobanRpc } : {}),
                })),
              );
            }

            if (cli.auditEvents) {
              networkDiagnostics.push(
                ...(await auditTomlEvents(fileResult.parsed, fetchImpl, {
                  rules,
                  ...(cli.sorobanRpc !== undefined ? { rpcUrl: cli.sorobanRpc } : {}),
                })),
              );
            }

            if (networkDiagnostics.length > 0) {
              fileResult = finalize(
                [...fileResult.diagnostics, ...networkDiagnostics],
                { strict: fileStrict },
                fileResult.parsed,
              );
            }
          }

          results.push({
            name: path === '-' ? 'stdin' : path,
            result: fileResult,
            source,
          });
        }
      }
    } catch (error) {
      process.stderr.write(`${message(error)}\n`);
      return 2;
    }

    const firstResult = results[0]?.result;

    if (cli.badgeSvg && firstResult) {
      await writeFile(cli.badgeSvg, generateBadgeSvg(firstResult));
    }
    if (cli.badgeJson && firstResult) {
      await writeFile(
        cli.badgeJson,
        JSON.stringify(generateShieldsEndpoint(firstResult), null, 2) + '\n',
      );
    }
    if (cli.exportApConfig && firstResult?.parsed) {
      const config = generateAnchorPlatformConfig(firstResult.parsed);
      process.stdout.write(formatAnchorPlatformYaml(config));
    }
    if (cli.generateOpenapi && firstResult?.parsed) {
      const spec = generateOpenApiSpec(firstResult.parsed);
      const ext =
        cli.generateOpenapi.endsWith('.yaml') || cli.generateOpenapi.endsWith('.yml')
          ? 'yaml'
          : 'json';
      if (ext === 'yaml') {
        const yamlLines: string[] = [];
        yamlLines.push(`openapi: "${spec.openapi}"`);
        yamlLines.push(`info:`);
        yamlLines.push(`  title: "${spec.info.title}"`);
        yamlLines.push(`  version: "${spec.info.version}"`);
        yamlLines.push(`  description: "${spec.info.description}"`);
        await writeFile(cli.generateOpenapi, yamlLines.join('\n') + '\n');
      } else {
        await writeFile(cli.generateOpenapi, JSON.stringify(spec, null, 2) + '\n');
      }
    }

    if (cli.graph && firstResult?.parsed) {
      const diagram = generateDiagram(firstResult.parsed, {
        format: cli.graph,
        includeContracts: cli.graphIncludeContracts,
        includeValidators: cli.graphIncludeValidators,
        colorByProtocol: cli.graphColorByProtocol,
      });
      process.stdout.write(diagram + '\n');
    }

    // Evaluate enterprise policy
    if (cli.policy && firstResult?.parsed) {
      const policy = await loadPolicy(cli.policy);
      const validation = validatePolicy(policy);
      if (!validation.valid) {
        process.stderr.write(`Policy validation failed:\n${validation.errors.join('\n')}\n`);
        return 2;
      }
      const sourcePath = cli.paths[0] ?? DEFAULT_PATH;
      const source = sourcePath === '-' ? await readStdin() : await readFile(sourcePath, 'utf8');
      const policyDiagnostics = evaluatePolicy(policy, firstResult.parsed, source);

      // Convert policy diagnostics to standard diagnostics
      const convertedDiagnostics: Diagnostic[] = policyDiagnostics.map((pd) => ({
        rule: `policy/${pd.rule}`,
        severity: pd.severity,
        category: 'policy',
        message: pd.message,
        path: pd.path,
        position: pd.position,
        suggestion: pd.suggestion,
        helpUri: undefined,
      }));

      if (convertedDiagnostics.length > 0 && results[0]) {
        const finalized = finalize(
          [...firstResult.diagnostics, ...convertedDiagnostics],
          { strict: cli.strict },
          firstResult.parsed,
        );
        results[0] = { name: results[0].name, result: finalized };
      }
    }

    if (cli.interactive && cli.format !== 'text') {
      process.stderr.write(
        `--interactive draws its own view of the findings; drop --format ${cli.format}.\n\nRun with --help for usage.\n`,
      );
      return 2;
    }

    // A dashboard written into a pipe or a file would corrupt the output it is
    // meant to replace, so anything that is not a terminal keeps the text report.
    const dashboard = cli.interactive === true && supportsDashboard(process.stdout);

    if (!cli.exportApConfig && dashboard) {
      await runDashboard(
        results,
        { stdin: process.stdin, stdout: process.stdout },
        { color, ...(cli.quiet ? { filter: 'error' as const } : {}) },
      );
    } else if (!cli.exportApConfig) {
      for (const { name, result, source } of results) {
        const filtered = cli.quiet
          ? { ...result, diagnostics: result.diagnostics.filter((d) => d.severity === 'error') }
          : result;
        process.stdout.write(render(filtered, name, cli, color, source));
      }

      // One line closing a multi-file run, so a CI log answers "did the whole
      // set pass?" without anyone counting per-file blocks. Only the text
      // reporter gets it: appending prose to JSON, SARIF, or XML would break the
      // parsers those formats exist for.
      if (results.length > 1 && cli.format === 'text') {
        process.stdout.write(formatSummary(results, { color }));
      }
    }

    if (cli.webhookSlack !== undefined || cli.webhookDiscord !== undefined) {
      const deliveries = await deliverWebhooks(results, {
        ...(cli.webhookSlack !== undefined ? { slack: cli.webhookSlack } : {}),
        ...(cli.webhookDiscord !== undefined ? { discord: cli.webhookDiscord } : {}),
      });

      for (const delivery of deliveries) {
        if (delivery.ok) continue;
        // The exit code stays tied to the diagnostics: a broken alert endpoint
        // must not turn a clean file into a failing build.
        process.stderr.write(
          `Warning: ${delivery.channel} webhook failed after ${delivery.attempts} attempt(s)${
            delivery.error === undefined ? '' : `: ${delivery.error}`
          }\n`,
        );
      }
    }

    let healthCheckFailed = false;
    if (cli.healthCheck) {
      for (const { result } of results) {
        const hcResults = await runHealthCheck(result);
        if (hcResults.length > 0) {
          process.stdout.write(formatHealthCheckTable(hcResults, color));
          if (hcResults.some((r) => r.error || (r.statusCode && r.statusCode >= 400))) {
            healthCheckFailed = true;
          }
        }
      }
    }

    const lintPassed = verdict(results, { strict, maxWarnings });
    return lintPassed && !healthCheckFailed ? 0 : 1;
  };

  const paths = cli.paths.length > 0 ? cli.paths : [DEFAULT_PATH];
  if (cli.watch) {
    return watchFiles(cli.domain ? [] : paths, cli, color, runLint);
  }
  return runLint(cli, color);
}

/**
 * Resolves the positional arguments to a concrete list of paths.
 *
 * Anything holding glob magic is expanded here rather than by the shell, so
 * the same quoted argument works under sh, PowerShell, and CMD — the first two
 * agree on nothing else about quoting. A pattern that matches nothing is a
 * usage mistake rather than a lint result, so it throws and `main` reports it
 * with the exit code 2 every other bad-usage path already uses.
 */
async function expandInputs(inputs: string[]): Promise<string[]> {
  const paths: string[] = [];

  for (const input of inputs) {
    if (input === '-' || !hasMagic(input)) {
      paths.push(input);
      continue;
    }

    const matches = await expandGlob(input);
    if (matches.length === 0) {
      throw new Error(
        `No files matched "${input}". Patterns are expanded by the linter, not the shell — check the path, and quote the pattern so it arrives intact.`,
      );
    }
    paths.push(...matches);
  }

  return [...new Set(paths)];
}

/**
 * `test-kms-signer`: signs an envelope through a cloud HSM and verifies the
 * result as a Stellar signature plus a Horizon quorum member.
 *
 * Exit codes follow the linter's convention: 0 verified, 1 a failed check or
 * KMS denial, 2 bad usage.
 */
async function runKmsSignerCommand(argv: string[]): Promise<number> {
  let keyId: string | undefined;
  let envelope: string | undefined;
  let networkPassphrase: string | undefined;
  let horizonUrl: string | undefined;
  let accountId: string | undefined;
  let signerKey: string | undefined;
  let threshold: KmsThresholdLevel | undefined;
  let skipQuorumCheck = false;
  let verifySignature = true;
  let json = false;
  let mockFixtures: string | undefined;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] as string;
    switch (arg) {
      case '-h':
      case '--help':
        process.stdout.write(USAGE);
        return 0;
      case '--key-id':
      case '--key':
        keyId = requireValue(argv, ++i, arg);
        break;
      case '--envelope':
        envelope = requireValue(argv, ++i, arg);
        break;
      case '--network':
      case '--network-passphrase':
        networkPassphrase = requireValue(argv, ++i, arg);
        break;
      case '--horizon':
        horizonUrl = requireValue(argv, ++i, arg);
        break;
      case '--account':
        accountId = requireValue(argv, ++i, arg);
        break;
      case '--signer-key':
        signerKey = requireValue(argv, ++i, arg);
        break;
      case '--threshold': {
        const value = requireValue(argv, ++i, arg);
        if (value !== 'low' && value !== 'medium' && value !== 'high') {
          throw new KmsError('invalid-arguments', '--threshold expects low, medium, or high');
        }
        threshold = value;
        break;
      }
      case '--no-quorum':
        skipQuorumCheck = true;
        break;
      case '--no-verify':
        verifySignature = false;
        break;
      case '--mock-fixtures':
        mockFixtures = requireValue(argv, ++i, arg);
        break;
      case '--json':
        json = true;
        break;
      default:
        throw new KmsError('invalid-arguments', `Unknown option "${arg}" for test-kms-signer`);
    }
  }

  if (keyId === undefined || envelope === undefined) {
    throw new KmsError(
      'invalid-arguments',
      'test-kms-signer requires --key-id <arn> and --envelope <xdr>',
    );
  }

  const fetchImpl = mockFixtures !== undefined ? createFixtureFetch(mockFixtures) : fetch;

  let report;
  try {
    report = await runCloudKmsSignerCheck({
      keyId,
      envelope,
      ...(networkPassphrase !== undefined ? { networkPassphrase } : {}),
      ...(horizonUrl !== undefined ? { horizonUrl } : {}),
      ...(accountId !== undefined ? { accountId } : {}),
      ...(signerKey !== undefined ? { signerKey } : {}),
      ...(threshold !== undefined ? { threshold } : {}),
      skipQuorumCheck,
      verifySignature,
      fetchImpl,
    });
  } catch (error) {
    if (error instanceof KmsError && isKmsUsageError(error.code)) throw error;
    const detail = error instanceof KmsError ? `${error.code}: ${error.message}` : message(error);
    process.stderr.write(`Cloud KMS signer check failed: ${detail}\n`);
    return 1;
  }

  process.stdout.write(
    json ? `${JSON.stringify(report, null, 2)}\n` : formatKmsSignerReport(report),
  );
  return report.ok ? 0 : 1;
}

/** Problems that mean the invocation was wrong, not that the key refused. */
function isKmsUsageError(code: string): boolean {
  return (
    code === 'invalid-arguments' ||
    code === 'invalid-envelope' ||
    code === 'unsupported-key-id' ||
    code === 'invalid-public-key'
  );
}

function render(
  result: LintResult,
  name: string,
  cli: Cli,
  color: boolean,
  source?: string,
): string {
  switch (cli.format) {
    case 'json':
      return formatJson(result, name);
    case 'ndjson':
      return formatNdjson(result, name);
    case 'sarif':
      return formatSarif(result, name, VERSION, source);
    case 'github':
      return formatGithub(result, name);
    case 'junit':
      return formatJunit(result, name);
    case 'html':
      return formatHtml(result, name);
    case 'checkstyle':
      return formatCheckstyle(result, name, VERSION);
    case 'markdown':
      return formatMarkdown(result, name);
    case 'text':
      return formatText(result, {
        filename: name,
        color,
        showHelp: cli.showHelp,
        showSuggestions: !cli.noSuggestions,
        errorsOnly: cli.quiet,
      });
  }
}

/** Combines per-file verdicts, including the `--max-warnings` threshold. */
function verdict(
  results: { result: LintResult }[],
  options: { strict: boolean; maxWarnings?: number },
): boolean {
  const totals = results.reduce(
    (acc, { result }) => {
      acc.error += result.counts.error;
      acc.warning += result.counts.warning;
      return acc;
    },
    { error: 0, warning: 0 },
  );

  if (totals.error > 0) return false;
  if (options.strict && totals.warning > 0) return false;
  if (options.maxWarnings !== undefined && totals.warning > options.maxWarnings) return false;
  return true;
}

/**
 * True when the command line asks for rules the built-in catalog cannot know
 * about, which is what defers the `--off/--error/--warn` id check until after
 * the plugins load.
 */
function usesPluginSources(argv: string[]): boolean {
  return argv.includes('--rules-dir') || argv.includes('--plugin');
}

function parseArgs(argv: string[]): Cli | 'handled' {
  const cli: Cli = {
    paths: [],
    format: 'text',
    strict: false,
    quiet: false,
    showHelp: false,
    rules: {},
    rulesDir: [],
    plugins: [],
    checkNetwork: false,
    followLinks: false,
    verifySep10: false,
    auditQuotes: false,
    auditUnicodeSecurity: false,
    auditConsumerProtection: false,
    auditKycFsm: false,
    auditFederationSecurity: false,
    auditSep30Recovery: false,
    auditCors: false,
    auditAssetSecurity: false,
    auditClickjacking: false,
    verifyPromotions: false,
    auditSep38Volatility: false,
    auditSep38Spreads: false,
    auditSep6Polling: false,
    auditSep10Jwt: false,
    testSep12Upload: false,
    sep10Tokens: [],
    verifyFederationSrv: false,
    auditEsgDisclosures: false,
    verifyPorFeed: false,
    verifySolanaBridge: false,
    auditErc4626Vaults: false,
    verifyAttestations: false,
    auditHsts: false,
    auditEmergencyPause: false,
    auditBridgeQuorum: false,
    auditOpenTelemetry: false,
    crawlPeers: false,
    monitorHeartbeat: false,
    verifyTier1Alignment: false,
    verifyDnssec: false,
    auditDnsTakeover: false,
    auditSecrets: false,
    auditSsrf: false,
    auditVaultSecrets: false,
    checkContracts: false,
    auditEvents: false,
    auditReentrancy: false,
    graphIncludeContracts: false,
    graphIncludeValidators: false,
    graphColorByProtocol: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] as string;

    switch (arg) {
      case '-h':
      case '--help':
        process.stdout.write(USAGE);
        return 'handled';

      case '-v':
      case '--version':
        process.stdout.write(`${VERSION}\n`);
        return 'handled';

      case '--list-rules':
        process.stdout.write(listRules());
        return 'handled';

      case '--json-schema':
        process.stdout.write(`${JSON.stringify(getTomlJsonSchema(), null, 2)}\n`);
        return 'handled';

      case '--completion': {
        const shell = requireValue(argv, i + 1, arg);
        if (!isCompletionShell(shell)) {
          throw new Error(`Unknown shell "${shell}". Expected bash, zsh, or fish.`);
        }
        process.stdout.write(generateCompletion(shell, allRules));
        return 'handled';
      }

      case '--lsp':
        cli.lsp = true;
        break;

      case '--sort-keys':
        cli.sortKeys = true;
        break;

      case '--dry-run':
        cli.dryRun = true;
        break;

      case '--detect-orphans':
        cli.detectOrphans = true;
        break;

      case '--prune-orphaned':
        cli.pruneOrphaned = true;
        break;

      case '--allow-key':
        (cli.allowKeys ??= []).push(requireValue(argv, ++i, arg));
        break;

      case '-d':
      case '--domain':
        cli.domain = requireValue(argv, ++i, arg);
        break;

      case '-f':
      case '--format': {
        const value = requireValue(argv, ++i, arg);
        if (!isFormat(value)) {
          throw new Error(
            `Unknown format "${value}". Expected text, json, ndjson, sarif, github, junit, html, checkstyle, or markdown.`,
          );
        }
        cli.format = value;
        break;
      }

      case '--strict':
        cli.strict = true;
        break;

      case '-w':
      case '--watch':
        cli.watch = true;
        break;

      case '-i':
      case '--interactive':
        cli.interactive = true;
        break;

      case '--no-suggestions':
        cli.noSuggestions = true;
        break;

      case '--health-check':
        cli.healthCheck = true;
        break;

      case '--check-network':
        cli.checkNetwork = true;
        break;

      case '--verify-sep10':
        cli.verifySep10 = true;
        break;

      case '--audit-quotes':
        cli.auditQuotes = true;
        break;

      case '--audit-unicode-security':
        cli.auditUnicodeSecurity = true;
        break;

      case '--audit-consumer-protection':
        cli.auditConsumerProtection = true;
        break;

      case '--audit-kyc-fsm':
        cli.auditKycFsm = true;
        break;

      case '--audit-federation-security':
        cli.auditFederationSecurity = true;
        break;

      case '--audit-sep30-recovery':
        cli.auditSep30Recovery = true;
        break;

      case '--audit-cors':
        cli.auditCors = true;
        break;

      case '--audit-asset-security':
        cli.auditAssetSecurity = true;
        break;

      case '--audit-clickjacking':
        cli.auditClickjacking = true;
        break;

      case '--verify-promotions':
        cli.verifyPromotions = true;
        break;

      case '--audit-sep38-volatility':
        cli.auditSep38Volatility = true;
        break;

      case '--audit-sep38-spreads':
        cli.auditSep38Spreads = true;
        break;

      case '--audit-sep6-polling':
        cli.auditSep6Polling = true;
        break;

      case '--audit-sep10-jwt':
        cli.auditSep10Jwt = true;
        break;

      case '--test-sep12-upload':
        cli.testSep12Upload = true;
        break;

      case '--sep10-token':
        cli.sep10Tokens.push(requireValue(argv, ++i, arg));
        break;

      case '--transaction-id':
        cli.transactionId = requireValue(argv, ++i, arg);
        break;

      case '--verify-federation-srv':
        cli.verifyFederationSrv = true;
        break;

      case '--audit-bridge-replays':
        cli.auditBridgeReplays = requireValue(argv, ++i, arg);
        break;

      case '--verify-attestations':
        cli.verifyAttestations = true;
        break;

      case '--audit-burn-redemptions':
        cli.auditBurnRedemptions = requireValue(argv, ++i, arg);
        break;

      case '--audit-esg-disclosures':
        cli.auditEsgDisclosures = true;
        break;

      case '--verify-por-feed':
        cli.verifyPorFeed = true;
        break;

      case '--verify-solana-bridge':
        cli.verifySolanaBridge = true;
        break;

      case '--audit-erc4626-vaults':
        cli.auditErc4626Vaults = true;
        break;

      case '--audit-hsts':
        cli.auditHsts = true;
        break;

      case '--audit-emergency-pause':
        cli.auditEmergencyPause = true;
        break;

      case '--audit-bridge-quorum':
        cli.auditBridgeQuorum = true;
        break;

      case '--audit-opentelemetry':
        cli.auditOpenTelemetry = true;
        break;

      case '--audit-offline-pwa':
        cli.auditOfflinePwa = requireValue(argv, ++i, arg);
        break;

      case '--audit-edge-compatibility':
        cli.auditEdgeCompatibility = requireValue(argv, ++i, arg);
        break;

      case '--verify-wasm-streaming':
        cli.verifyWasmStreaming = requireValue(argv, ++i, arg);
        break;

      case '--crawl-peers':
        cli.crawlPeers = true;
        break;

      case '--monitor-heartbeat':
        cli.monitorHeartbeat = true;
        break;

      case '--verify-tier1-alignment':
        cli.verifyTier1Alignment = true;
        break;

      case '--tier1-catalog':
        cli.tier1Catalog = requireValue(argv, ++i, arg);
        break;

      case '--timeout': {
        const raw = requireValue(argv, ++i, arg);
        const seconds = Number(raw);
        if (!Number.isFinite(seconds) || seconds <= 0) {
          throw new Error(`--timeout expects a positive number of seconds, got "${raw}".`);
        }
        cli.heartbeatTimeoutSeconds = seconds;
        break;
      }

      case '--verify-dnssec':
        cli.verifyDnssec = true;
        break;
      case '--audit-dns-takeover':
        cli.auditDnsTakeover = true;
        break;

      case '--audit-secrets':
        cli.auditSecrets = true;
        break;

      case '--audit-ssrf':
        cli.auditSsrf = true;
        break;

      case '--audit-vault-secrets':
        cli.auditVaultSecrets = true;
        break;

      case '--follow-links':
        cli.followLinks = true;
        break;

      case '--check-contracts':
        cli.checkContracts = true;
        break;

      case '--audit-events':
        cli.auditEvents = true;
        break;

      case '--audit-reentrancy':
        cli.auditReentrancy = true;
        break;

      case '--soroban-rpc':
        cli.sorobanRpc = requireValue(argv, ++i, arg);
        break;

      case '--mock-fixtures':
        cli.mockFixtures = requireValue(argv, ++i, arg);
        break;

      case '--run-sandboxed-plugin':
        cli.runSandboxedPlugin = requireValue(argv, ++i, arg);
        break;

      case '--sandbox-fuel': {
        const value = Number(requireValue(argv, ++i, arg));
        if (!Number.isSafeInteger(value) || value <= 0) {
          throw new Error('--sandbox-fuel expects a positive integer.');
        }
        cli.sandboxFuel = value;
        break;
      }

      case '--webhook-slack':
      case '--webhook-discord': {
        const value = requireValue(argv, ++i, arg);
        if (!isSupportedWebhookUrl(value)) {
          throw new Error(`${arg} expects an http or https URL.`);
        }
        if (arg === '--webhook-slack') cli.webhookSlack = value;
        else cli.webhookDiscord = value;
        break;
      }

      case '--badge-svg':
        cli.badgeSvg = requireValue(argv, ++i, arg);
        break;

      case '--badge-json':
        cli.badgeJson = requireValue(argv, ++i, arg);
        break;

      case '--export-ap-config':
        cli.exportApConfig = true;
        break;

      case '--generate-openapi':
        cli.generateOpenapi = requireValue(argv, ++i, arg);
        break;

      case '--graph': {
        const value = requireValue(argv, ++i, arg);
        if (value !== 'mermaid' && value !== 'dot') {
          throw new Error(`Unknown graph format "${value}". Expected mermaid or dot.`);
        }
        cli.graph = value;
        break;
      }

      case '--graph-contracts':
        cli.graphIncludeContracts = true;
        break;

      case '--graph-validators':
        cli.graphIncludeValidators = true;
        break;

      case '--graph-color':
        cli.graphColorByProtocol = true;
        break;

      case '--policy':
        cli.policy = requireValue(argv, ++i, arg);
        break;

      case '--max-warnings': {
        const value = Number(requireValue(argv, ++i, arg));
        if (!Number.isInteger(value) || value < 0) {
          throw new Error('--max-warnings expects a non-negative integer.');
        }
        cli.maxWarnings = value;
        break;
      }

      case '--off':
      case '--error':
      case '--warn': {
        const id = requireValue(argv, ++i, arg);
        // A plugin id is only known once its module is loaded, which is async and
        // happens in `main`. When plugin flags are present the check runs there
        // instead, against the built-ins *plus* the ids that actually loaded.
        if (!usesPluginSources(argv)) assertKnownRule(id);
        // The flag says `--warn`; the severity token is `warning`. Storing the
        // flag's spelling made every summary count read NaN.
        cli.rules[id] = arg === '--off' ? 'off' : arg === '--warn' ? 'warning' : 'error';
        break;
      }

      case '--rules-dir':
        cli.rulesDir.push(requireValue(argv, ++i, arg));
        break;

      case '--plugin':
        cli.plugins.push(requireValue(argv, ++i, arg));
        break;

      case '--preset': {
        const value = requireValue(argv, ++i, arg);
        // Resolved here rather than stored as a name, so an unknown preset is
        // the same exit-2 usage error an unknown rule id is.
        cli.preset = resolvePreset(value).name;
        break;
      }

      case '-q':
      case '--quiet':
        cli.quiet = true;
        break;

      case '--show-help-urls':
        cli.showHelp = true;
        break;

      case '--color':
        cli.color = true;
        break;

      case '--no-color':
        cli.color = false;
        break;

      default:
        if (arg.startsWith('--')) throw new Error(`Unknown option "${arg}".`);
        cli.paths.push(arg);
    }
  }

  if (cli.preset !== undefined) {
    // The bundle is laid down *after* the loop, so a rule flag wins whether it
    // was typed before or after `--preset`: the preset is a baseline, and the
    // command line is the intent for this run.
    cli.rules = { ...PRESETS[cli.preset].rules, ...cli.rules };
  }

  return cli;
}

function requireValue(argv: string[], index: number, flag: string): string {
  const value = argv[index];
  if (value === undefined || value.startsWith('-')) {
    throw new Error(`${flag} expects a value.`);
  }
  return value;
}

function isFormat(value: string): value is Format {
  return (
    value === 'text' ||
    value === 'json' ||
    value === 'ndjson' ||
    value === 'sarif' ||
    value === 'github' ||
    value === 'junit' ||
    value === 'html' ||
    value === 'checkstyle' ||
    value === 'markdown'
  );
}

function listRules(): string {
  const width = Math.max(...allRules.map((r) => r.id.length));
  const lines = allRules.map(
    (r) => `  ${r.id.padEnd(width)}  ${r.severity.padEnd(7)}  ${r.description}`,
  );
  return `${allRules.length} rules\n\n${lines.join('\n')}\n`;
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString('utf8');
}

/**
 * Decides whether the text reporter emits ANSI colour.
 *
 * Follows the NO_COLOR standard (https://no-color.org): any non-empty NO_COLOR
 * value disables colour, whatever it contains, and an empty value counts as
 * unset. FORCE_COLOR is honoured next, and TTY detection is the fallback.
 *
 * An explicit `--color` or `--no-color` is resolved by `main` before this is
 * consulted, so the flag always wins — that is the only thing that overrides
 * NO_COLOR.
 */
function shouldUseColor(): boolean {
  const noColor = process.env.NO_COLOR;
  if (noColor !== undefined && noColor !== '') return false;
  if (process.env.FORCE_COLOR && process.env.FORCE_COLOR !== '0') return true;
  return process.stdout.isTTY === true;
}

function message(error: unknown): string {
  if (error instanceof Error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') {
      const path = (error as NodeJS.ErrnoException).path ?? DEFAULT_PATH;
      return `Could not find ${path}. Pass a path, or use --domain to check a live site.`;
    }
    if (code === 'EISDIR') {
      const path = (error as NodeJS.ErrnoException).path ?? '';
      return `${path} is a directory. Point at the file, e.g. ${basename(path)}/stellar.toml.`;
    }
    return error.message;
  }
  return String(error);
}

/**
 * Runs a plugin inside the WASI capability sandbox.
 *
 * Anything the sandbox denies is reported even though the guest saw only an
 * errno: a probe for the host filesystem is worth failing the build over, and
 * the exit code says so (`1`) rather than hiding it in the output.
 */
async function runSandboxedPlugin(path: string, fuel: number | undefined): Promise<number> {
  const bytes = new Uint8Array(await readFile(path));
  const runner = new WasiSandboxRunner(fuel === undefined ? {} : { fuel });

  try {
    const result = await runner.run(bytes);
    process.stdout.write(result.stdout);
    process.stderr.write(result.stderr);
    for (const violation of result.violations) {
      process.stderr.write(`sandbox/violation: ${violation.syscall} — ${violation.detail}\n`);
    }
    if (result.violations.length > 0) return 1;
    return result.exitCode === 0 ? 0 : 1;
  } catch (error) {
    if (error instanceof WasiSandboxError) {
      process.stderr.write(`sandbox/${error.code}: ${error.message}\n`);
      // A sandbox rejection is a plugin failure; an unreadable or malformed
      // module is a usage error, the same code as every other bad input.
      return error.code === 'fuel' || error.code === 'trap' || error.code === 'capability' ? 1 : 2;
    }
    throw error;
  }
}

const PROFILE_USAGE = `stellar-toml-lint profile-wasm-heap --wasm <file.wasm> [options]

Run a validator plugin repeatedly and report whether its memory stabilises.

OPTIONS
      --wasm <file>        Module to profile (required)
      --iterations <n>     Invocations to sample (default 1000)
      --json               Print the profile as JSON
      --svg <file>         Write the heap growth curve as SVG
`;

async function runHeapProfileCommand(argv: string[]): Promise<number> {
  let wasmPath: string | undefined;
  let iterations = 1_000;
  let json = false;
  let svg: string | undefined;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] as string;
    switch (arg) {
      case '-h':
      case '--help':
        process.stdout.write(PROFILE_USAGE);
        return 0;
      case '--wasm':
        wasmPath = argv[++i];
        break;
      case '--iterations': {
        const value = Number(argv[++i]);
        if (!Number.isInteger(value) || value < 1) {
          process.stderr.write('--iterations expects a positive integer.\n');
          return 2;
        }
        iterations = value;
        break;
      }
      case '--json':
        json = true;
        break;
      case '--svg':
        svg = argv[++i];
        break;
      default:
        process.stderr.write(`Unknown option "${arg}".\n\n${PROFILE_USAGE}`);
        return 2;
    }
  }

  if (wasmPath === undefined) {
    process.stderr.write(`profile-wasm-heap needs --wasm <file.wasm>.\n\n${PROFILE_USAGE}`);
    return 2;
  }

  try {
    const runtime = wasmRuntime();
    const compiled = await runtime.compile(new Uint8Array(await readFile(wasmPath)));
    const pending = runtime.Module.imports(compiled);
    if (pending.length > 0) {
      throw new Error(
        `Module imports ${pending.map((entry) => `${entry.module}.${entry.name}`).join(', ')}; profile-wasm-heap runs self-contained modules only.`,
      );
    }

    const instance = await runtime.instantiate(compiled, {});
    const memory = instance.exports['memory'];
    if (!isWasmMemory(memory)) {
      throw new Error('Module exports no memory, so there is no heap to sample.');
    }

    const entry = ['run', '_start', 'main']
      .map((name) => instance.exports[name])
      .find((candidate) => typeof candidate === 'function') as (() => unknown) | undefined;
    if (entry === undefined) {
      throw new Error('Module exports no entry point. Expected run, _start, or main.');
    }

    const profiler = new WasmHeapProfiler();
    const profile = await profiler.profile(
      () => {
        entry();
      },
      () => memory.buffer.byteLength,
      iterations,
    );

    process.stdout.write(
      json ? `${JSON.stringify(profile, null, 2)}\n` : profiler.formatReport(profile),
    );
    if (svg !== undefined) await writeFile(svg, profiler.renderGrowthCurve(profile));

    return profile.leaked ? 1 : 0;
  } catch (error) {
    process.stderr.write(`${message(error)}\n`);
    return 2;
  }
}

main(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error: unknown) => {
    process.stderr.write(`Unexpected failure: ${message(error)}\n`);
    process.exitCode = 2;
  });

async function watchFiles(
  paths: string[],
  cli: Cli,
  color: boolean,
  runLint: (cli: Cli, color: boolean) => Promise<number>,
) {
  await runLint(cli, color);

  for (const path of paths) {
    if (path === '-') continue; // can't watch stdin
    let timer: NodeJS.Timeout | null = null;
    try {
      const watcher = watch(path, () => {
        if (timer) clearTimeout(timer);
        timer = setTimeout(async () => {
          timer = null;
          if (process.stdout.isTTY) process.stdout.write('\x1Bc');
          await runLint(cli, color);
        }, 100);
      });
      watcher.on('error', (error) => {
        process.stderr.write(`Warning: Watcher error on ${path}: ${error.message}\n`);
      });
    } catch (error) {
      const e = error as Error;
      process.stderr.write(`Warning: Could not watch ${path}: ${e.message}\n`);
    }
  }

  // Wait indefinitely, exit on SIGINT
  return new Promise<number>(() => {
    process.on('SIGINT', () => process.exit(0));
  });
}
