import type { Rule } from '../types.js';
import { specUrl } from '../spec.js';

function validatorsOf(doc: Record<string, unknown>): Record<string, unknown>[] {
  const list = doc.VALIDATORS;
  if (!Array.isArray(list)) return [];
  return list.filter(
    (entry): entry is Record<string, unknown> =>
      typeof entry === 'object' && entry !== null && !Array.isArray(entry),
  );
}

function duplicateRule(
  field: 'PUBLIC_KEY' | 'HOST' | 'ALIAS',
  id: string,
  severity: 'error' | 'warning',
  description: string,
  suggestion: string,
): Rule {
  return {
    id,
    category: 'validators',
    severity,
    description,
    run(ctx) {
      const seen = new Map<string, number>();

      validatorsOf(ctx.doc).forEach((entry, i) => {
        const value = entry[field];
        if (typeof value !== 'string') return;

        const first = seen.get(value);
        if (first !== undefined) {
          const path = `VALIDATORS[${i}].${field}`;
          ctx.report({
            rule: id,
            category: 'validators',
            message: `${path} "${value}" duplicates VALIDATORS[${first}]`,
            path,
            position: ctx.locate(path),
            helpUri: specUrl('validator-information'),
            suggestion,
          });
        } else {
          seen.set(value, i);
        }
      });
    },
  };
}

export const validatorDedupRules: Rule[] = [
  duplicateRule(
    'PUBLIC_KEY',
    'validators/duplicate-public-key',
    'error',
    'PUBLIC_KEY values must be unique across validators',
    'Each validator must use a unique public key.',
  ),
  duplicateRule(
    'HOST',
    'validators/duplicate-host',
    'warning',
    'HOST values should be unique across validators',
    'Each validator should use a unique host and port.',
  ),
  duplicateRule(
    'ALIAS',
    'validators/duplicate-alias',
    'warning',
    'ALIAS values should be unique across validators',
    'Each validator should use a unique alias.',
  ),
];
