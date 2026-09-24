import type { Rule } from '../types.js';
import { generalRules } from './general.js';
import { documentationRules } from './documentation.js';
import { principalRules } from './principals.js';
import { currencyRules } from './currencies.js';
import { validatorRules } from './validators.js';
import { validatorDedupRules } from './validator-dedup.js';
import { securityRules } from './security.js';

/** Every rule, in report order. */
export const allRules: Rule[] = [
  ...generalRules,
  ...documentationRules,
  ...principalRules,
  ...currencyRules,
  ...validatorRules,
  ...validatorDedupRules,
  ...securityRules,
];

/** Rule ids, sorted, for `--list-rules` and docs generation. */
export const ruleIds: string[] = allRules.map((r) => r.id).sort();

export {
  generalRules,
  documentationRules,
  principalRules,
  currencyRules,
  validatorRules,
  validatorDedupRules,
  securityRules,
};
