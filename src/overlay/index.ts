/**
 * The overlay checks, gathered in one place.
 *
 * Each module keeps its own transport behind a dynamic import, so importing
 * this barrel never loads `node:net` or `node:crypto` on its own. The CLI runs
 * the entry points under their flags: `--crawl-peers`, `--crawl-topology`,
 * `--audit-dos`, and `--verify-overlay` (handshake, then cipher session).
 */
export { checkOverlayPeers } from './crawler.js';
export { overlayCrawlerRules } from './crawler-rules.js';
export { checkOverlayHandshake, overlayHandshakeRules } from './handshake.js';
export { checkOverlayDos, overlayDosRules } from './dos-tester.js';
export { checkOverlayTopology, topologyAnalyzerRules } from './topology-analyzer.js';
export { cryptoAuditorRules } from './crypto-auditor.js';
export {
  checkOverlayCipher,
  verifyOverlayCipher,
  verifyCipherSession,
  cipherFindings,
  overlayCipherRules,
  overlayCipherRuleIds,
  OVERLAY_CIPHER_NEGOTIATION_FAILED_RULE,
  OVERLAY_MAC_TAG_MISMATCH_RULE,
} from './cipher-verifier.js';
export type {
  CipherChannel,
  CipherChannelFactory,
  CipherOutcome,
  CipherVerifierOptions,
} from './cipher-verifier.js';
