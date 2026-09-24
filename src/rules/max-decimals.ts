import type { Rule, RuleContext } from '../types.js';
import { specUrl } from '../spec.js';

function eachCurrency(
  ctx: RuleContext,
  visit: (entry: Record<string, unknown>, path: string) => void,
): void {
  const currencies = ctx.doc.CURRENCIES;
  if (!Array.isArray(currencies)) return;

  currencies.forEach((entry, index) => {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) return;
    if (entry.toml !== undefined) return;
    visit(entry, `CURRENCIES[${index}]`);
  });
}

export const maxDecimalsRules: Rule[] = [
  {
    id: 'currencies/display-decimals-exceeds-max',
    category: 'currencies',
    severity: 'warning',
    description: 'Warn when display_decimals exceeds 7 for classic assets',
    run(ctx) {
      eachCurrency(ctx, (entry, path) => {
        const hasContract = entry.contract !== undefined || entry.contract_id !== undefined;
        if (hasContract) return;

        const decimals = entry.display_decimals;
        if (typeof decimals !== 'number' || decimals <= 7) return;

        ctx.report({
          rule: 'currencies/display-decimals-exceeds-max',
          category: 'currencies',
          severity: 'warning',
          message: `${path}.display_decimals exceeds 7 (Stellar network max precision)`,
          path: `${path}.display_decimals`,
          position: ctx.locate(`${path}.display_decimals`),
          helpUri: specUrl('currency-documentation'),
          suggestion: 'Set display_decimals to 7 or fewer for a classic asset.',
        });
      });
    },
  },
];
