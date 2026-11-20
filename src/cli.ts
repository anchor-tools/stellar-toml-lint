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
import { lint, lintDomain, finalize, followTomlPointers } from './lint.js';
import { checkNetworkAccounts } from './network-checks.js';
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
import { checkDisplayDecimals } from './rules/display-decimals-audit.js';
import { checkHorizon } from './rules/horizon-check.js';
import { checkSep38 } from './rules/sep38-endpoints.js';
import { checkRegulatedIssuerFlags } from './rules/currencies.js';
import { checkContracts } from './rules/soroban.js';
import { auditTomlAuthTree } from './soroban/auth-tree-simulator.js';
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
import { formatUnifiedDiff } from './line-diff.js';
import {
  auditConsumerProtection,
  renderScorecard,
} from './protocols/consumerProtectionVerifier.js';
import { auditSep30Recovery } from './protocols/sep30Verifier.js';
import { verifyPromotions } from './protocols/promotionalPricingVerifier.js';
import { verifyFederationSrv } from './protocols/federationSrvVerifier.js';
import { auditEsgDisclosures, renderEsgReport } from './protocols/esgComplianceVerifier.js';
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
import type { Diagnostic, LintResult, RuleOverrides, Severity } from './types.js';

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
  verifyFederationSrv: boolean;
  auditEsgDisclosures: boolean;
  auditOpenTelemetry: boolean;
  auditOfflinePwa?: string;
  auditEdgeCompatibility?: string;
  crawlPeers: boolean;
  verifyDnssec: boolean;
  auditDnsTakeover: boolean;
  auditSecrets: boolean;
  auditSsrf: boolean;
  badgeSvg?: string;
  badgeJson?: string;
  exportApConfig?: boolean;
  generateOpenapi?: string;
  webhookSlack?: string;
  webhookDiscord?: string;
  interactive?: boolean;
  checkContracts: boolean;
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
  runSandboxedPlugin?: string;
  sandboxFuel?: number;
  verifyWasmStreaming?: string;
}

const USAGE = `stellar-toml-lint ${VERSION}

Validate a Stellar Info File (stellar.toml) against SEP-1 — offline.

USAGE
  stellar-toml-lint [file...]            Lint local files (default: ./stellar.toml)
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
  stellar-toml-lint profile-wasm-heap --wasm <plugin.wasm> --iterations <n>
                                         Run a plugin repeatedly and report heap growth
  stellar-toml-lint sync-directory --feed <url|file> [--format text|json]
                                         Diff a multi-tenant anchor directory feed
                                         against each anchor's live stellar.toml
  stellar-toml-lint verify-archive-gpg --url <archive-url> --pubkey <key-file>
                                         Verify the latest ledger checkpoint's detached GPG signature
  stellar-toml-lint refactor <file> [--deduplicate-assets] [--split]
                                    [--max-bytes <n>] [--out-dir <dir>] [--write]
                                          Deduplicate assets / split a large stellar.toml
                                          and print a diff for review
  stellar-toml-lint audit-wasm-simd --file <path.wasm> [--json]
                                         Audit a WASM binary for SIMD opcodes and
                                         unbounded memory growth
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
  stellar-toml-lint audit-tls --domain <domain> [--format text|json]
                                         Audit SSL/TLS renewal and OCSP stapling health
  stellar-toml-lint audit-key-separation --domain <domain> [--horizon <url>]
                                         [--format text|json]
                                         Map every public key in the file to its roles
                                         and report reused signing, issuer, account and
                                         validator keys

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
  -i, --interactive       Full-screen dashboard to walk the findings. Needs a TTY;
                          without one the text reporter is used instead
      --lsp               Run as a Language Server on stdio (diagnostics,
                          quick-fix code actions, and SEP-1 hover docs)
      --sort-keys         Rewrite files into canonical key order: SEP-1 fields in
                          spec order inside each table, [[CURRENCIES]] sorted by
                          code, [[VALIDATORS]] by public_key, and keys this tool
                          does not know pushed to the end of their table. Leading
                          comments travel with the key they describe.
      --dry-run           With --sort-keys, print a unified diff and change
                          nothing. Exits 1 when a file is not already canonical,
                          so CI can check ordering without writing to the tree.
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
      --verify-federation-srv
                          Check _stellar-federation._tcp.<domain> SRV records
                          against FEDERATION_SERVER (use with --domain)
      --audit-esg-disclosures
                          Verify DOCUMENTATION.ORG_ESG disclosures, check the
                          attestation signature with --check-network, and print
                          a sustainability rating
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
      --verify-dnssec     Compare A/AAAA answers across DNSSEC-validating DoH resolvers
       --audit-dns-takeover
                           Query CNAME/NS records for every referenced domain and
                           flag dangling pointers to claimable cloud resources
       --audit-secrets     Halt with exit 1 on leaked Stellar seeds, cloud keys,
                           bearer tokens or PEM blocks; output is always redacted
       --audit-ssrf        Flag advertised URLs resolving to private, loopback,
                           link-local or multicast IPs, including DNS rebinding
      --follow-links      Fetch and lint the toml pointers in CURRENCIES
                          (implied by --domain)
      --check-contracts   Verify Soroban contract and WASM TTL liveliness
      --soroban-rpc <url> Soroban RPC endpoint to use with --check-contracts
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

CONFIG
  .stellartomlrc.json    Project defaults, discovered upward from the linted
                         file's directory (from the current directory for stdin
                         and --domain), stopping at the filesystem root.
                         Recognises "rules", "strict", and "maxWarnings".
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
  return out;
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
  if (argv[0] === 'refactor') return refactorCommand(argv.slice(1));
  if (argv[0] === 'profile-wasm-heap') return runHeapProfileCommand(argv.slice(1));
  if (argv[0] === 'audit-clawbacks') return auditClawbacks(argv.slice(1));
  if (argv[0] === 'dispatch-alert') return dispatchAlert(argv.slice(1));
  if (argv[0] === 'audit-coop-coep') return auditCoopCoep(argv.slice(1));
  if (argv[0] === 'verify-federation-sync') return verifyFederationSyncCommand(argv.slice(1));
  if (argv[0] === 'verify-browser-bundle') return verifyBrowserBundleCommand(argv.slice(1));
  if (argv[0] === 'sync-directory') return syncDirectory(argv.slice(1));
  if (argv[0] === 'verify-archive-gpg') return verifyArchiveGpgCommand(argv.slice(1));
  if (argv[0] === 'audit-wasm-simd') return auditWasmSimd(argv.slice(1));
  if (argv[0] === 'profile-wasm-heap') return runHeapProfileCommand(argv.slice(1));
  if (argv[0] === 'verify-metrics') return verifyMetricsCommand(argv.slice(1));
  if (argv[0] === 'probe-sla') return probeSlaCommand(argv.slice(1));
  if (argv[0] === 'calculate-uptime') return calculateUptimeCommand(argv.slice(1));
  if (argv[0] === 'audit-error-taxonomy') return auditErrorTaxonomyCommand(argv.slice(1));
  if (argv.includes('--audit-error-taxonomy')) return auditErrorTaxonomyCommand(argv);
  if (argv[0] === 'audit-key-separation') return auditKeySeparationCommand(argv.slice(1));
  if (argv[0] === 'verify-rate-headers') return verifyRateHeadersCommand(argv.slice(1));
  if (argv[0] === 'audit-tls') return auditTlsCommand(argv.slice(1));
  if (argv[0] === 'format') return formatCommand(argv.slice(1));
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

  if (cli.dryRun && !cli.sortKeys) {
    process.stderr.write(
      '--dry-run has nothing to preview without --sort-keys.\n\nRun with --help for usage.\n',
    );
    return 2;
  }

  const color = cli.color ?? shouldUseColor();

  if (cli.sortKeys) return sortKeysCommand(cli, color);

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
      const fetchImpl =
        cli.mockFixtures !== undefined ? createFixtureFetch(cli.mockFixtures) : fetch;

      if (cli.domain && cli.paths.length === 0) {
        const config = await loadConfig(process.cwd());
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
          const config = await loadConfig(path === '-' ? process.cwd() : dirname(resolve(path)));
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
          });

          if (cli.auditSecrets) {
            const halted = await auditSecretsOrHalt(fileResult.parsed, source, rules);
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
            (cli.checkNetwork || cli.checkContracts || cli.followLinks || cli.domain !== undefined)
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
                  { strict: fileStrict, rules, domain: cli.domain },
                  fetchImpl,
                )),
              );
            }

            if (cli.checkContracts) {
              networkDiagnostics.push(
                ...(await checkContracts(fileResult.parsed, fetchImpl, {
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

function parseArgs(argv: string[]): Cli | 'handled' {
  const cli: Cli = {
    paths: [],
    format: 'text',
    strict: false,
    quiet: false,
    showHelp: false,
    rules: {},
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
    verifyFederationSrv: false,
    auditEsgDisclosures: false,
    auditOpenTelemetry: false,
    crawlPeers: false,
    verifyDnssec: false,
    auditDnsTakeover: false,
    auditSecrets: false,
    auditSsrf: false,
    checkContracts: false,
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

      case '--verify-federation-srv':
        cli.verifyFederationSrv = true;
        break;

      case '--audit-esg-disclosures':
        cli.auditEsgDisclosures = true;
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

      case '--follow-links':
        cli.followLinks = true;
        break;

      case '--check-contracts':
        cli.checkContracts = true;
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
        assertKnownRule(id);
        cli.rules[id] = arg === '--off' ? 'off' : (arg.slice(2) as Severity);
        break;
      }

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
