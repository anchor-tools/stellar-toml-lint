import type { Rule } from '../types.js';
import { generalRules } from './general.js';
import { documentationRules } from './documentation.js';
import { principalRules } from './principals.js';
import { currencyRules } from './currencies.js';
import { validatorRules } from './validators.js';
import { securityRules } from './security.js';
import { horizonRules } from './horizon-check.js';
import { sep38Rules } from './sep38-endpoints.js';
import { sep41Rules } from '../network-checks.js';

/** Every rule, in report order. */
export const allRules: Rule[] = [
  ...generalRules,
  ...documentationRules,
  ...principalRules,
  ...currencyRules,
  ...validatorRules,
  ...securityRules,
  ...horizonRules,
  ...sep38Rules,
  ...sep41Rules,
];

/** Rule ids, sorted, for `--list-rules` and docs generation. */
export const ruleIds: string[] = allRules.map((r) => r.id).sort();

export {
  generalRules,
  documentationRules,
  principalRules,
  currencyRules,
  validatorRules,
  securityRules,
  horizonRules,
  sep38Rules,
};
