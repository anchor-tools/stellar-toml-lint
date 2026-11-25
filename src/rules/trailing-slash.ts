import type { Rule } from '../types.js';
import { hasTrailingSlash, isString } from '../predicates.js';
import { specUrl } from '../spec.js';

/**
 * Endpoint URLs are bases, not pages: clients concatenate sub-routes such as
 * `/info`, `/deposit`, or `/authorize` onto them. A trailing slash turns that
 * concatenation into `//info`, which some servers reject outright and others
 * answer with a 301 that strips the `Authorization` header SEP-10 challenges
 * depend on. The fix is mechanical — drop the final slash — so the diagnostic
 * hands back the corrected URL as its suggestion.
 */

const RULE_ID = 'general/trailing-slash-in-endpoint';

/** Service endpoints clients append path sub-routes to. */
const ENDPOINT_FIELDS = [
  'WEB_AUTH_ENDPOINT',
  'TRANSFER_SERVER',
  'TRANSFER_SERVER_SEP0024',
  'KYC_SERVER',
  'ANCHOR_QUOTE_SERVER',
  'DIRECT_PAYMENT_SERVER',
] as const;

/** Warns when a service endpoint URL ends with a trailing slash. */
export const trailingSlashRule: Rule = {
  id: RULE_ID,
  category: 'general',
  severity: 'warning',
  description: 'Service endpoint URLs must not end with a trailing slash',
  run(ctx) {
    for (const field of ENDPOINT_FIELDS) {
      const value = ctx.doc[field];
      if (value === undefined || !isString(value)) continue;
      if (!hasTrailingSlash(value)) continue;

      ctx.report({
        rule: RULE_ID,
        category: 'general',
        message: `${field} has a trailing slash, which produces double-slash request paths (e.g. //info) when clients append sub-routes`,
        path: field,
        position: ctx.locate(field),
        helpUri: specUrl('general-information'),
        suggestion: `Remove the trailing slash: ${value.replace(/\/+$/, '')}`,
        fix: { value: value.replace(/\/+$/, '') },
      });
    }
  },
};
