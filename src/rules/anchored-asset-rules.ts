import type { Rule, RuleContext } from '../types.js';
import { ANCHOR_ASSET_TYPES, specUrl } from '../spec.js';

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

export const anchoredAssetRules: Rule[] = [
  {
    id: 'currencies/missing-anchor-asset-type',
    category: 'currencies',
    severity: 'error',
    description: 'An asset-anchored currency must declare a valid anchor_asset_type',
    run(ctx) {
      eachCurrency(ctx, (entry, path) => {
        if (entry.is_asset_anchored !== true) return;

        const type = entry.anchor_asset_type;
        if (type !== undefined && ANCHOR_ASSET_TYPES.includes(type as never)) return;

        ctx.report({
          rule: 'currencies/missing-anchor-asset-type',
          category: 'currencies',
          message:
            type === undefined
              ? `${path} is marked asset-anchored but has no anchor_asset_type`
              : `${path}.anchor_asset_type must be one of ${ANCHOR_ASSET_TYPES.join(', ')}`,
          path: `${path}.anchor_asset_type`,
          position: ctx.locate(`${path}.anchor_asset_type`),
          helpUri: specUrl('currency-documentation'),
          suggestion: `Use one of ${ANCHOR_ASSET_TYPES.join(', ')} for anchor_asset_type.`,
        });
      });
    },
  },
  {
    id: 'currencies/missing-anchor-asset-code',
    category: 'currencies',
    severity: 'warning',
    description: 'An asset-anchored currency should declare its anchor asset code',
    run(ctx) {
      eachCurrency(ctx, (entry, path) => {
        if (entry.is_asset_anchored !== true || entry.anchor_asset !== undefined) return;

        ctx.report({
          rule: 'currencies/missing-anchor-asset-code',
          category: 'currencies',
          message: `${path} is marked asset-anchored but has no anchor_asset`,
          path: `${path}.anchor_asset`,
          position: ctx.locate(`${path}.anchor_asset`),
          helpUri: specUrl('currency-documentation'),
          suggestion: 'Add anchor_asset with the code or identifier of the backing asset.',
        });
      });
    },
  },
];
