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
