import type { Rule } from '../types.js';
import { generalRules } from './general.js';
import { documentationRules } from './documentation.js';
import { principalRules } from './principals.js';
import { currencyRules } from './currencies.js';
import { validatorRules } from './validators.js';
import { validatorDedupRules } from './validator-dedup.js';
import { securityRules } from './security.js';
import { deprecationRules } from './deprecations.js';
import { emailMxRule } from './email-mx.js';
import { maxDecimalsRules } from './max-decimals.js';
import { horizonRules } from './horizon-check.js';
import { orgUrlRules } from './org-url-check.js';
import { sep38Rules } from './sep38-endpoints.js';
import { sorobanRules } from './soroban.js';
import { authTreeSimulatorRules } from '../soroban/auth-tree-simulator.js';
import { authTreeCredentialRules } from '../soroban/authTreeSimulator.js';
import { wasmMemoryRules } from '../soroban/wasmMemoryAnalyzer.js';
import { signatureReplayRules } from '../soroban/signatureReplayAuditor.js';
import { sep12Rules } from './sep12-schema.js';
import { sep6Rules } from '../cross-sep/sep6.js';
import { corsPreflightRules } from '../network/cors-preflight.js';
import { overlayCrawlerRules } from '../overlay/crawler-rules.js';
import { cryptoAuditorRules } from '../overlay/crypto-auditor.js';
import { historyPublishRules } from '../history/publish-validator.js';
import { dnsIntegrityRules } from '../security/dns-integrity.js';
import { sep10ClientDomainRules } from '../protocols/sep10-client-domain.js';
import { quoteBindingRules } from '../protocols/quote-binding-auditor.js';
import { consumerProtectionRules } from '../protocols/consumerProtectionVerifier.js';
import { kycTierRules } from '../protocols/kycTierAuditor.js';
import { unicodeRules } from '../cst/unicodeValidator.js';
import { federationSecurityRules } from '../protocols/federationSecurityTester.js';
import { reverseFederationRules } from '../protocols/reverseFederationVerifier.js';
import { sep30Rules } from '../protocols/sep30Verifier.js';
import { promotionalPricingRules } from '../protocols/promotionalPricingVerifier.js';
import { sep38CircuitBreakerRules } from '../protocols/sep38CircuitBreaker.js';
import { sep38DiscrepancyRules } from '../protocols/sep38Discrepancy.js';
import { sep6PollingRules } from '../protocols/sep6Polling.js';
import { sep10JwtRules } from '../protocols/sep10JwtAuditor.js';
import { sep10IsolationRules } from '../protocols/sep10Isolation.js';
import { sep24SecurityRules } from '../protocols/sep24Security.js';
import { sep24RefundRules } from '../protocols/sep24RefundAuditor.js';
import { sep38DeliveryRules } from '../protocols/sep38Delivery.js';
import { sep12FileUploadRules } from '../protocols/sep12FileUpload.js';
import { federationSrvRules } from '../protocols/federationSrvVerifier.js';
import { esgRules } from '../protocols/esgComplianceVerifier.js';
import { chainlinkPorRules } from '../bridges/chainlinkPorVerifier.js';
import { wormholeRules } from '../bridges/wormholeVaaAuditor.js';
import { solanaEscrowRules } from '../bridges/solanaEscrowVerifier.js';
import { erc4626Rules } from '../bridges/erc4626VaultAuditor.js';
import { bridgeLatencyRules } from '../bridges/latencyBenchmark.js';
import { bridgeReplayRules } from '../bridges/eventReplayDetector.js';
import { bankAttestationRules } from '../bridges/bankAttestationVerifier.js';
import { proofOfBurnRules } from '../bridges/proofOfBurnValidator.js';
import { tlsCipherRules } from '../security/tlsCipherAuditor.js';
import { hstsRules } from '../security/hstsVerifier.js';
import { emergencyPauseRules } from '../bridges/emergencyPauseValidator.js';
import { bridgeQuorumRules } from '../bridges/bridgeQuorumAuditor.js';
import { subdomainTakeoverRules } from '../security/subdomainScanner.js';
import { secretDetectorRules } from '../security/secretDetector.js';
import { ssrfRules } from '../security/ssrfScanner.js';
import { telemetryRules } from '../telemetry/rules.js';
import { corsSecurityRules } from '../security/corsAuditor.js';
import { mimeSecurityRules } from '../security/mimeScanner.js';
import { keySeparationRules } from '../security/keySeparationAuditor.js';
import { clickjackingRules } from '../security/clickjackingAuditor.js';
import { zkRules } from '../zk/rangeProofVerifier.js';
import { secp256k1BridgeRules } from '../crypto/secp256k1Verifier.js';
import { kzgRules } from '../crypto/kzgVerifier.js';
import { overlayHandshakeRules } from '../overlay/handshakeTester.js';
import { floodPropagationRules } from '../overlay/floodVerifier.js';
import { validatorKeyRotationRules } from '../overlay/keyRotationVerifier.js';
import { floodingDefenseRules } from '../overlay/floodingTester.js';
import { overlayHeartbeatRules } from '../overlay/heartbeat-rules.js';
import { tier1AlignmentRules } from '../overlay/tier1AlignmentVerifier.js';
import { sep31Sep12Rules } from '../protocols/sep31Sep12Consistency.js';
import { sep31SanctionsRules } from '../protocols/sep31Sanctions.js';
import { footprintDetectorRules } from '../soroban/footprintDetector.js';
import { gitopsRules } from '../gitops/k8sIngressAuditor.js';

export const IAC_DEPLOYMENT_RULE = 'gitops/iac-deployment';

/** Every rule, in report order. */
export const allRules: Rule[] = [
  ...generalRules,
  ...deprecationRules,
  ...documentationRules,
  ...principalRules,
  ...currencyRules,
  ...maxDecimalsRules,
  ...validatorRules,
  ...validatorDedupRules,
  ...securityRules,

  emailMxRule,

  ...horizonRules,
  ...orgUrlRules,
  ...sep38Rules,
  ...sorobanRules,
  ...authTreeSimulatorRules,
  ...authTreeCredentialRules,
  ...wasmMemoryRules,
  ...signatureReplayRules,
  ...sep12Rules,
  ...sep6Rules,
  ...corsPreflightRules,
  ...overlayCrawlerRules,
  ...cryptoAuditorRules,
  ...historyPublishRules,
  ...dnsIntegrityRules,
  ...sep10ClientDomainRules,
  ...quoteBindingRules,
  ...unicodeRules,
  ...consumerProtectionRules,
  ...kycTierRules,
  ...federationSecurityRules,
  ...reverseFederationRules,
  ...sep30Rules,
  ...promotionalPricingRules,
  ...sep38CircuitBreakerRules,
  ...sep38DiscrepancyRules,
  ...sep6PollingRules,
  ...sep10JwtRules,
  ...sep10IsolationRules,
  ...sep24SecurityRules,
  ...sep24RefundRules,
  ...sep38DeliveryRules,
  ...sep12FileUploadRules,
  ...federationSrvRules,
  ...esgRules,
  ...chainlinkPorRules,
  ...wormholeRules,
  ...solanaEscrowRules,
  ...erc4626Rules,
  ...bridgeLatencyRules,
  ...bridgeReplayRules,
  ...bankAttestationRules,
  ...proofOfBurnRules,
  ...tlsCipherRules,
  ...hstsRules,
  ...emergencyPauseRules,
  ...bridgeQuorumRules,
  ...subdomainTakeoverRules,
  ...secretDetectorRules,
  ...ssrfRules,
  ...telemetryRules,
  ...corsSecurityRules,
  ...mimeSecurityRules,
  ...keySeparationRules,
  ...clickjackingRules,
  ...zkRules,
  ...secp256k1BridgeRules,
  ...kzgRules,
  ...overlayHandshakeRules,
  ...floodPropagationRules,
  ...validatorKeyRotationRules,
  ...floodingDefenseRules,
  ...overlayHeartbeatRules,
  ...tier1AlignmentRules,
  ...sep31Sep12Rules,
  ...sep31SanctionsRules,
  ...footprintDetectorRules,
  ...gitopsRules,
  {
    id: IAC_DEPLOYMENT_RULE,
    category: 'gitops',
    severity: 'warning',
    description: 'Terraform and Ansible anchor deployment configuration',
    run() {},
  },
];

/** Rule ids, sorted, for `--list-rules` and docs generation. */
export const ruleIds: string[] = allRules.map((r) => r.id).sort();

export {
  generalRules,
  deprecationRules,
  documentationRules,
  principalRules,
  currencyRules,
  maxDecimalsRules,
  validatorRules,
  validatorDedupRules,
  securityRules,
  horizonRules,
  sep38Rules,
  sorobanRules,
  authTreeSimulatorRules,
  authTreeCredentialRules,
  wasmMemoryRules,
  signatureReplayRules,
  sep12Rules,
  sep6Rules,
  corsPreflightRules,
  overlayCrawlerRules,
  cryptoAuditorRules,
  historyPublishRules,
  dnsIntegrityRules,
  sep10ClientDomainRules,
  quoteBindingRules,
  unicodeRules,
  consumerProtectionRules,
  kycTierRules,
  federationSecurityRules,
  reverseFederationRules,
  sep30Rules,
  promotionalPricingRules,
  sep38CircuitBreakerRules,
  sep38DiscrepancyRules,
  sep6PollingRules,
  sep10JwtRules,
  sep10IsolationRules,
  sep24SecurityRules,
  sep24RefundRules,
  sep38DeliveryRules,
  sep12FileUploadRules,
  federationSrvRules,
  esgRules,
  chainlinkPorRules,
  wormholeRules,
  solanaEscrowRules,
  erc4626Rules,
  bridgeLatencyRules,
  bridgeReplayRules,
  bankAttestationRules,
  proofOfBurnRules,
  tlsCipherRules,
  hstsRules,
  emergencyPauseRules,
  bridgeQuorumRules,
  subdomainTakeoverRules,
  secretDetectorRules,
  ssrfRules,
  telemetryRules,
  corsSecurityRules,
  mimeSecurityRules,
  keySeparationRules,
  clickjackingRules,
  zkRules,
  secp256k1BridgeRules,
  kzgRules,
  overlayHandshakeRules,
  floodPropagationRules,
  validatorKeyRotationRules,
  floodingDefenseRules,
  overlayHeartbeatRules,
  tier1AlignmentRules,
  sep31Sep12Rules,
  gitopsRules,
};
