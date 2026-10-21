import type { Rule } from '../types.js';
import { generalRules } from './general.js';
import { telegramHandleRules } from './telegram-handle.js';
import { documentationRules } from './documentation.js';
import { principalRules } from './principals.js';
import {
  currencyRules,
  sep41MetadataRules,
  collateralSigFormatRules,
  duplicateCurrencyRules,
} from './currencies.js';
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
import { crossSepFeeRules } from './cross-sep-fee-auditor.js';
import { orgUrlRules } from './org-url-check.js';
import { imageAssetRules } from './image-assets.js';
import { sorobanRules } from '../soroban.js';
import { sorobanErrorRules } from '../soroban/errors.js';
import { multiNetworkRules } from '../soroban/multi-network.js';
import { dependencyGraphRules } from '../soroban/dependency-graph.js';
import { sep12Rules } from './sep12-schema.js';
import { sep10Rules } from '../protocols/sep10.js';
import { sep6Rules } from '../cross-sep/sep6.js';
import { corsPreflightRules } from '../network/cors-preflight.js';
import { overlayCrawlerRules } from '../overlay/crawler-rules.js';
import { overlayHandshakeRules } from '../overlay/handshake.js';
import { overlayCipherRules } from '../overlay/cipher-verifier.js';
import { cryptoAuditorRules } from '../overlay/crypto-auditor.js';
import { historyPublishRules } from '../history/publish-validator.js';
import { archiveDiffRules } from '../history/archive-diff.js';
import { bucketAuditorRules } from '../history/bucket-auditor.js';
import { bucketStreamRules } from '../history/bucket-stream-validator.js';
import { gapAuditorRules } from '../history/gap-auditor.js';
import { quorumSolverRules } from '../validators/quorum-solver.js';
import { quorumAuditRules } from '../validators/quorum.js';
import { dnsIntegrityRules } from '../security/dns-integrity.js';
import { corpHeaderRules } from '../security/corp-auditor.js';
import { mpcGovernanceRules } from '../security/mpc-governance.js';
import { hstsAuditorRules } from '../security/hsts-auditor.js';
import {
  dmarcAuditorRules,
  caaAuditorRules,
  tlsPfsAuditorRules,
  sniAuditorRules,
  subdomainTakeoverRules,
} from '../security/index.js';
import { certExpiryRules } from '../network/cert-expiry.js';
import { bgpRouteDetectorRules } from '../network/bgp-route-detector.js';
import { ipv6AuditorRules } from '../network/ipv6-auditor.js';
import { httpVersionAuditorRules } from '../network/http-version-auditor.js';
import { slaCalculatorRules } from '../monitor/sla-calculator.js';
import { peerPortRule } from '../validators/net-probe.js';
import { anchorDiscoveryRules } from '../validators/anchorDiscovery.js';
import { fixedSupplyLockRules } from './fixed-supply-audit.js';
import { circularPointerRules } from './circular-pointers.js';
import { docComplianceRules } from './doc-compliance.js';
import { networkPassphraseRules } from './network-passphrase.js';
import { testnetContractRules } from './testnet-contracts.js';
import { sep7Rules } from '../protocols/sep7.js';
import { sep6IntegrationRules } from '../protocols/sep6.js';
import { sep31Rules } from '../protocols/sep31.js';
import { sep31WebhookRules } from '../protocols/sep31-webhook-verifier.js';
import { sep31KycRules } from '../protocols/sep31-kyc-matrix.js';
import { sep30Rules } from '../protocols/sep30.js';
import { sep30CoordinatorRules } from '../protocols/sep30-coordinator.js';
import { sep8Rules } from '../protocols/sep8.js';
import { sep38QuoteRules } from '../protocols/sep38.js';
import { sep24Rules } from '../protocols/sep24.js';
import { sep24LifecycleRules } from '../protocols/sep24-lifecycle.js';
import { multiTenantRules } from '../network/multi-tenant.js';
import { wasmAuditorRules } from '../soroban/wasm-auditor.js';
import { envMetaRules } from '../soroban/env-meta.js';
import { eventRules } from '../soroban/events.js';
import { adminAuditorRules } from '../soroban/admin-auditor.js';
import { simulationRules } from '../soroban/simulation.js';
import { storageFootprintRules } from '../soroban/storage-footprint.js';
import { authAuditorRules } from '../soroban/auth-auditor.js';
import { instanceStorageAuditorRules } from '../soroban/instance-storage-auditor.js';
import { insecureHttpRule } from './insecure-http.js';
import { deadCodeRules } from './dead-code.js';
import { multisigRules } from '../security/multisig.js';
import { ipfsMetadataRules } from '../validators/ipfsMetadata.js';
import { sep8WebhookRules } from '../sep8/webhookCoordinator.js';
import { accountDataAuditorRules } from '../security/account-data-auditor.js';
import { contractMetadataRules } from '../soroban/contractMetadata.js';
import { historyArchiveRules } from '../validators/historyArchive.js';
import { bridgeReserveRules } from '../validators/bridgeReserve.js';
import { corridorRoutingRules } from '../corridors/routingVerifier.js';
import { redosDetectorRules } from './redos-detector.js';
import { overlayDosRules } from '../overlay/dos-tester.js';
import { topologyAnalyzerRules } from '../overlay/topology-analyzer.js';

/** Every rule, in report order. */
export const allRules: Rule[] = [
  ...generalRules,
  ...deadCodeRules,
  insecureHttpRule,
  ...deprecationRules,
  ...sep10Rules,
  ...documentationRules,
  ...principalRules,
  ...currencyRules,
  ...fixedSupplyLockRules,
  ...regulatedFlagRules,
  ...maxDecimalsRules,
  ...validatorRules,
  ...validatorDedupRules,
  ...historyArchiveRules,
  ...securityRules,
  ...multisigRules,
  ...corpHeaderRules,
  ...mpcGovernanceRules,

  emailMxRule,

  ...horizonRules,
  ...sep3Rules,
  ...sep38Rules,
  ...crossSepFeeRules,
  ...corridorRoutingRules,
  ...bridgeReserveRules,
  ...orgUrlRules,
  ...imageAssetRules,
  ...sorobanRules,
  ...contractMetadataRules,
  ...wasmAuditorRules,
  ...envMetaRules,
  ...eventRules,
  ...adminAuditorRules,
  ...simulationRules,
  ...storageFootprintRules,
  ...authAuditorRules,
  ...instanceStorageAuditorRules,
  ...sorobanErrorRules,
  ...multiNetworkRules,
  ...dependencyGraphRules,
  ...sep41MetadataRules,
  ...sep12Rules,
  ...sep6Rules,
  ...sep6IntegrationRules,
  ...sep30Rules,
  ...sep30CoordinatorRules,
  ...sep31Rules,
  ...sep31WebhookRules,
  ...sep31KycRules,
  ...sep8Rules,
  ...sep8WebhookRules,
  ...sep38QuoteRules,
  ...sep24Rules,
  ...sep24LifecycleRules,
  ...sep7Rules,
  ...corsPreflightRules,
  ...overlayCrawlerRules,
  ...overlayHandshakeRules,
  ...overlayCipherRules,
  ...overlayDosRules,
  ...topologyAnalyzerRules,
  ...cryptoAuditorRules,
  ...historyPublishRules,
  ...archiveDiffRules,
  ...bucketAuditorRules,
  ...bucketStreamRules,
  ...gapAuditorRules,
  ...quorumSolverRules,
  ...quorumAuditRules,
  ...dnsIntegrityRules,
  ...dmarcAuditorRules,
  ...caaAuditorRules,
  ...tlsPfsAuditorRules,
  ...sniAuditorRules,
  ...subdomainTakeoverRules,
  ...bgpRouteDetectorRules,
  ...certExpiryRules,
  ...hstsAuditorRules,
  ...ipv6AuditorRules,
  // `httpVersionAuditorRules` is folded into `generalRules` (see
  // src/rules/general.ts, where the issue wires it), so it is exported rather
  // than spread again here.
  ...slaCalculatorRules,
  ...anchorDiscoveryRules,
  peerPortRule,
  ...circularPointerRules,
  ...docComplianceRules,
  ...networkPassphraseRules,
  ...testnetContractRules,
  ...ipfsMetadataRules,
  ...accountDataAuditorRules,
  ...redosDetectorRules,
];

/** Rule ids, sorted, for `--list-rules` and docs generation. */
export const ruleIds: string[] = allRules.map((r) => r.id).sort();

export {
  generalRules,
  telegramHandleRules,
  deprecationRules,
  documentationRules,
  principalRules,
  currencyRules,
  collateralSigFormatRules,
  duplicateCurrencyRules,
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
  crossSepFeeRules,
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
  overlayCipherRules,
  cryptoAuditorRules,
  historyPublishRules,
  archiveDiffRules,
  bucketAuditorRules,
  bucketStreamRules,
  gapAuditorRules,
  quorumSolverRules,
  quorumAuditRules,
  dnsIntegrityRules,
  certExpiryRules,
  ipv6AuditorRules,
  httpVersionAuditorRules,
  slaCalculatorRules,
  anchorDiscoveryRules,
  peerPortRule,
  circularPointerRules,
  docComplianceRules,
  networkPassphraseRules,
  testnetContractRules,
  sep7Rules,
  sep6IntegrationRules,
  sep30Rules,
  sep30CoordinatorRules,
  sep31Rules,
  sep31WebhookRules,
  sep31KycRules,
  sep8Rules,
  sep38QuoteRules,
  sep24Rules,
  sep24LifecycleRules,
  multiTenantRules,
  wasmAuditorRules,
  envMetaRules,
  eventRules,
  adminAuditorRules,
  simulationRules,
  storageFootprintRules,
  authAuditorRules,
  instanceStorageAuditorRules,
  insecureHttpRule,
  ipfsMetadataRules,
  sep8WebhookRules,
  accountDataAuditorRules,
  contractMetadataRules,
  historyArchiveRules,
  bridgeReserveRules,
  corridorRoutingRules,
  redosDetectorRules,
  corpHeaderRules,
  mpcGovernanceRules,
  hstsAuditorRules,
};
