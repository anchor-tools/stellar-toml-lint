import type { Rule } from '../types.js';
import { specUrl } from '../spec.js';

const DUPLICATE_CURRENCY_DECLARATION_RULE = 'currencies/duplicate-currency-declaration';

function isTomlPointer(entry: Record<string, unknown>): boolean {
  return entry.toml !== undefined;
}

export const duplicateCurrencyRules: Rule[] = [
  {
    id: DUPLICATE_CURRENCY_DECLARATION_RULE,
    category: 'currencies',
    severity: 'error',
    description:
      'Flags duplicate currency declarations sharing identical code and issuer (or both having empty issuer for native)',
    run(ctx) {
      const currencies = ctx.doc.CURRENCIES;
      if (!Array.isArray(currencies)) return;

      const seen = new Map<string, number>();

      currencies.forEach((entry, index) => {
        if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) return;
        if (isTomlPointer(entry)) return;

        const code = entry.code;
        if (typeof code !== 'string') return;

        const issuer =
          typeof entry.issuer === 'string'
            ? entry.issuer
            : typeof entry.contract === 'string'
              ? entry.contract
              : '';

        const key = `${code}:${issuer}`;
        const firstIndex = seen.get(key);

        if (firstIndex !== undefined) {
          const path = `CURRENCIES[${index}]`;
          ctx.report({
            rule: DUPLICATE_CURRENCY_DECLARATION_RULE,
            category: 'currencies',
            message: `${path} duplicates the currency declaration for "${code}" already declared at CURRENCIES[${firstIndex}]`,
            path,
            position: ctx.locate(path),
            helpUri: specUrl('currency-documentation'),
            suggestion: 'Merge duplicate currency entries or correct the asset code/issuer.',
          });
        } else {
          seen.set(key, index);
        }
      });
    },
  },
];
