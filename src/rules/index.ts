import type { Rule } from '../types.js';
import { generalRules } from './general.js';
import { documentationRules } from './documentation.js';
import { principalRules } from './principals.js';
import { currencyRules } from './currencies.js';
import { validatorRules } from './validators.js';
import { securityRules } from './security.js';

import { emailMxRule } from './email-mx.js';
import { maxDecimalsRules } from './max-decimals.js';

import { horizonRules } from './horizon-check.js';
import { sep38Rules } from './sep38-endpoints.js';
import { sorobanRules } from '../soroban.js';

/** Every rule, in report order. */
export const allRules: Rule[] = [
  ...generalRules,
  ...documentationRules,
  ...principalRules,
  ...currencyRules,
  ...maxDecimalsRules,
  ...validatorRules,
  ...securityRules,

  emailMxRule,

  ...horizonRules,
  ...sep38Rules,
  ...sorobanRules,
];

/** Rule ids, sorted, for `--list-rules` and docs generation. */
export const ruleIds: string[] = allRules.map((r) => r.id).sort();

export {
  generalRules,
  documentationRules,
  principalRules,
  currencyRules,
  maxDecimalsRules,
  validatorRules,
  securityRules,
  horizonRules,
  sep38Rules,
  sorobanRules,
};
