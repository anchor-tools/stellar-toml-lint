import type { Rule, RuleContext } from '../types.js';
import { specUrl } from '../spec.js';

/**
 * Dead configuration detector: keys whose gating condition has been switched
 * off (issue #307).
 *
 * When an anchor decommissions a service — turns off regulation, shuts down
 * the collateral arrangement — the keys that service used to read are often
 * left behind. They are not malformed, so the schema and format rules stay
 * quiet, but no client ever reads them again: the configuration is dead.
 *
 * Two dependency groups are checked, both living on `[[CURRENCIES]]` entries:
 *
 * - `approval_server` / `approval_criteria` are SEP-8 approval-service
 *   fields. SEP-8 clients only consult them for a `regulated = true` asset,
 *   so on any other asset they are unreachable.
 * - `collateral_addresses` / `collateral_address_messages` /
 *   `collateral_address_signatures` describe reserves backing an anchored
 *   asset. On an explicitly non-anchored asset (`is_asset_anchored = false`)
 *   there is nothing for them to back, so the whole reserve claim is inert.
 *
 * Both conditions follow the issue text literally: "regulated is not true"
 * includes an absent `regulated`, while the collateral group requires the
 * explicit `is_asset_anchored = false` rather than a missing key — an anchor
 * that never mentioned anchoring is flagged by other rules first, and this
 * one stays a dead-key detector rather than a completeness check.
 */
const DEAD_KEY_RULE = 'general/dead-configuration-key';

/** SEP-8 fields only read when the entry is regulated. */
const APPROVAL_FIELDS = ['approval_server', 'approval_criteria'] as const;

/** Reserve-claim fields only meaningful for an asset-anchored entry. */
const COLLATERAL_FIELDS = [
  'collateral_addresses',
  'collateral_address_messages',
  'collateral_address_signatures',
] as const;

export const deadCodeRules: Rule[] = [
  {
    id: DEAD_KEY_RULE,
    category: 'general',
    severity: 'warning',
    description: 'Flag configuration keys whose gating condition is off, so no client reads them',
    run(ctx) {
      eachCurrency(ctx, (entry, path) => {
        if (entry.regulated !== true) {
          for (const field of APPROVAL_FIELDS) {
            if (entry[field] === undefined) continue;
            ctx.report({
              rule: DEAD_KEY_RULE,
              category: 'general',
              message: `${path}.${field} is dead configuration: the entry is not regulated, so SEP-8 clients never read it`,
              path: `${path}.${field}`,
              position: ctx.locate(`${path}.${field}`),
              helpUri: specUrl('currency-documentation'),
              suggestion: `Set regulated = true on ${path} to activate ${field}, or remove ${field}.`,
            });
          }
        }

        if (entry.is_asset_anchored === false) {
          for (const field of COLLATERAL_FIELDS) {
            if (entry[field] === undefined) continue;
            ctx.report({
              rule: DEAD_KEY_RULE,
              category: 'general',
              message: `${path}.${field} is dead configuration: the entry is not asset-anchored, so the collateral claim backs nothing`,
              path: `${path}.${field}`,
              position: ctx.locate(`${path}.${field}`),
              helpUri: specUrl('currency-documentation'),
              suggestion: `Set is_asset_anchored = true on ${path} to activate ${field}, or remove ${field}.`,
            });
          }
        }
      });
    },
  },
];

/** Visits every object entry of `CURRENCIES` with its dotted path. */
function eachCurrency(
  ctx: RuleContext,
  visit: (entry: Record<string, unknown>, path: string) => void,
): void {
  const currencies = ctx.doc.CURRENCIES;
  if (!Array.isArray(currencies)) return;

  currencies.forEach((entry, index) => {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) return;
    visit(entry as Record<string, unknown>, `CURRENCIES[${index}]`);
  });
}
