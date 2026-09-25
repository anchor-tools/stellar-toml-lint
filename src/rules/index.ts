import type { Rule } from '../types.js';
import { generalRules } from './general.js';
import { documentationRules } from './documentation.js';
import { principalRules } from './principals.js';
import { currencyRules } from './currencies.js';
import { regulatedFlagRules } from './regulated-flags.js';
import { validatorRules } from './validators.js';
import { validatorDedupRules } from './validator-dedup.js';
import { securityRules } from './security.js';
import { deprecationRules } from './deprecations.js';
import { emailMxRule } from './email-mx.js';
import { maxDecimalsRules } from './max-decimals.js';
import { horizonRules } from './horizon-check.js';
import { orgUrlRules } from './org-url-check.js';
import { sep38Rules } from './sep38-endpoints.js';
import { sorobanRules } from '../soroban.js';
import { sep12Rules } from './sep12-schema.js';
import { sep6Rules } from '../cross-sep/sep6.js';
import { corsPreflightRules } from '../network/cors-preflight.js';
import { overlayCrawlerRules } from '../overlay/crawler-rules.js';
import { cryptoAuditorRules } from '../overlay/crypto-auditor.js';
import { historyPublishRules } from '../history/publish-validator.js';
import { dnsIntegrityRules } from '../security/dns-integrity.js';
import { certExpiryRules } from '../network/cert-expiry.js';

/** Every rule, in report order. */
export const allRules: Rule[] = [
  ...generalRules,
  ...deprecationRules,
  ...documentationRules,
  ...principalRules,
  ...currencyRules,
  ...regulatedFlagRules,
  ...maxDecimalsRules,
  ...validatorRules,
  ...validatorDedupRules,
  ...securityRules,

  emailMxRule,

  ...horizonRules,
  ...orgUrlRules,
  ...sep38Rules,
  ...sorobanRules,
  ...sep12Rules,
  ...sep6Rules,
  ...corsPreflightRules,
  ...overlayCrawlerRules,
  ...cryptoAuditorRules,
  ...historyPublishRules,
  ...dnsIntegrityRules,
  ...certExpiryRules,
];

/** Rule ids, sorted, for `--list-rules` and docs generation. */
export const ruleIds: string[] = allRules.map((r) => r.id).sort();

export {
  generalRules,
  deprecationRules,
  documentationRules,
  principalRules,
  currencyRules,
  regulatedFlagRules,
  maxDecimalsRules,
  validatorRules,
  validatorDedupRules,
  securityRules,
  horizonRules,
  sep38Rules,
  sorobanRules,
  sep12Rules,
  sep6Rules,
  corsPreflightRules,
  overlayCrawlerRules,
  cryptoAuditorRules,
  historyPublishRules,
  dnsIntegrityRules,
  certExpiryRules,
};
