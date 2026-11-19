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
};
