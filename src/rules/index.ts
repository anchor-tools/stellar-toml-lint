import type { Rule } from '../types.js';
import { generalRules } from './general.js';
import { documentationRules } from './documentation.js';
import { principalRules } from './principals.js';
import { currencyRules, sep41MetadataRules, collateralSigFormatRules } from './currencies.js';
import { regulatedFlagRules } from './regulated-flags.js';
import { validatorRules } from './validators.js';
import { validatorDedupRules } from './validator-dedup.js';
import { securityRules } from './security.js';
import { deprecationRules } from './deprecations.js';
import { emailMxRule } from './email-mx.js';
import { maxDecimalsRules } from './max-decimals.js';
import { horizonRules } from './horizon-check.js';
import { sep3Rules } from './sep3-auth.js';
import { sep38Rules } from './sep38-endpoints.js';
import { orgUrlRules } from './org-url-check.js';
import { imageAssetRules } from './image-assets.js';
import { sorobanRules } from '../soroban.js';
import { sorobanErrorRules } from '../soroban/errors.js';
import { multiNetworkRules } from '../soroban/multi-network.js';
import { dependencyGraphRules } from '../soroban/dependency-graph.js';
import { sep12Rules } from './sep12-schema.js';
import { sep6Rules } from '../cross-sep/sep6.js';
import { corsPreflightRules } from '../network/cors-preflight.js';
import { overlayCrawlerRules } from '../overlay/crawler-rules.js';
import { overlayHandshakeRules } from '../overlay/handshake.js';
import { cryptoAuditorRules } from '../overlay/crypto-auditor.js';
import { historyPublishRules } from '../history/publish-validator.js';
import { archiveDiffRules } from '../history/archive-diff.js';
import { quorumSolverRules } from '../validators/quorum-solver.js';
import { dnsIntegrityRules } from '../security/dns-integrity.js';
import { certExpiryRules } from '../network/cert-expiry.js';
import { peerPortRule } from '../validators/net-probe.js';
import { fixedSupplyLockRules } from './fixed-supply-audit.js';
import { circularPointerRules } from './circular-pointers.js';
import { docComplianceRules } from './doc-compliance.js';
import { networkPassphraseRules } from './network-passphrase.js';
import { testnetContractRules } from './testnet-contracts.js';
import { sep7Rules } from '../protocols/sep7.js';
import { sep6IntegrationRules } from '../protocols/sep6.js';
import { sep31Rules } from '../protocols/sep31.js';
import { sep8Rules } from '../protocols/sep8.js';
import { sep38QuoteRules } from '../protocols/sep38.js';
import { wasmAuditorRules } from '../soroban/wasm-auditor.js';
import { envMetaRules } from '../soroban/env-meta.js';
import { eventRules } from '../soroban/events.js';
import { adminAuditorRules } from '../soroban/admin-auditor.js';
import { simulationRules } from '../soroban/simulation.js';
import { storageFootprintRules } from '../soroban/storage-footprint.js';
import { authAuditorRules } from '../soroban/auth-auditor.js';
import { insecureHttpRule } from './insecure-http.js';
import { multisigRules } from '../security/multisig.js';

/** Every rule, in report order. */
export const allRules: Rule[] = [
  ...generalRules,
  insecureHttpRule,
  ...deprecationRules,
  ...documentationRules,
  ...principalRules,
  ...currencyRules,
  ...fixedSupplyLockRules,
  ...regulatedFlagRules,
  ...maxDecimalsRules,
  ...validatorRules,
  ...validatorDedupRules,
  ...securityRules,
  ...multisigRules,

  emailMxRule,

  ...horizonRules,
  ...sep3Rules,
  ...sep38Rules,
  ...orgUrlRules,
  ...imageAssetRules,
  ...sorobanRules,
  ...wasmAuditorRules,
  ...envMetaRules,
  ...eventRules,
  ...adminAuditorRules,
  ...simulationRules,
  ...storageFootprintRules,
  ...authAuditorRules,
  ...sorobanErrorRules,
  ...multiNetworkRules,
  ...dependencyGraphRules,
  ...sep41MetadataRules,
  ...sep12Rules,
  ...sep6Rules,
  ...sep6IntegrationRules,
  ...sep31Rules,
  ...sep8Rules,
  ...sep38QuoteRules,
  ...sep7Rules,
  ...corsPreflightRules,
  ...overlayCrawlerRules,
  ...overlayHandshakeRules,
  ...cryptoAuditorRules,
  ...historyPublishRules,
  ...archiveDiffRules,
  ...quorumSolverRules,
  ...dnsIntegrityRules,
  ...certExpiryRules,
  peerPortRule,
  ...circularPointerRules,
  ...docComplianceRules,
  ...networkPassphraseRules,
  ...testnetContractRules,
];

/** Rule ids, sorted, for `--list-rules` and docs generation. */
export const ruleIds: string[] = allRules.map((r) => r.id).sort();

export {
  generalRules,
  deprecationRules,
  documentationRules,
  principalRules,
  currencyRules,
  collateralSigFormatRules,
  fixedSupplyLockRules,
  regulatedFlagRules,
  maxDecimalsRules,
  validatorRules,
  validatorDedupRules,
  securityRules,
  multisigRules,
  horizonRules,
  sep3Rules,
  sep38Rules,
  imageAssetRules,
  sorobanRules,
  sorobanErrorRules,
  multiNetworkRules,
  dependencyGraphRules,
  sep41MetadataRules,
  sep12Rules,
  sep6Rules,
  corsPreflightRules,
  overlayCrawlerRules,
  overlayHandshakeRules,
  cryptoAuditorRules,
  historyPublishRules,
  archiveDiffRules,
  quorumSolverRules,
  dnsIntegrityRules,
  certExpiryRules,
  peerPortRule,
  circularPointerRules,
  docComplianceRules,
  networkPassphraseRules,
  testnetContractRules,
  sep7Rules,
  sep6IntegrationRules,
  sep31Rules,
  sep8Rules,
  sep38QuoteRules,
  wasmAuditorRules,
  envMetaRules,
  eventRules,
  adminAuditorRules,
  simulationRules,
  storageFootprintRules,
  authAuditorRules,
  insecureHttpRule,
};
