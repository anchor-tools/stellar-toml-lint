import type { Rule, RuleContext } from '../types.js';
import { isString } from '../predicates.js';
import { specUrl } from '../spec.js';

/**
 * Canonical Stellar account IDs use uppercase base32.
 *
 * base32 is case-insensitive per RFC 4648, so a lowercase `g...` key still
 * decodes to the same 32 bytes — but wallets and exchanges compare the
 * string form when matching keys, and a case mismatch there looks like a
 * different account. The fix is mechanical (uppercase the letters), so the
 * diagnostic hands back the corrected value as its suggestion.
 */

const RULE_ID = 'general/lowercase-public-key';

/** Lowercase letters are never part of the canonical encoding. */
const HAS_LOWERCASE = /[a-z]/;

function reportLowercase(ctx: RuleContext, path: string, value: string): void {
  if (!HAS_LOWERCASE.test(value)) return;

  ctx.report({
    rule: RULE_ID,
    category: 'general',
    message: `${path} contains lowercase letters; Stellar public keys use uppercase base32`,
    path,
    position: ctx.locate(path),
    helpUri: specUrl('general-information'),
    suggestion: `Replace it with: ${value.toUpperCase()}`,
  });
}

/** Reads a list of tables (e.g. `[[CURRENCIES]]`), ignoring malformed entries. */
function entriesOf(list: unknown): Record<string, unknown>[] {
  if (!Array.isArray(list)) return [];
  return list.filter(
    (entry): entry is Record<string, unknown> =>
      typeof entry === 'object' && entry !== null && !Array.isArray(entry),
  );
}

function checkSigningKey(ctx: RuleContext): void {
  const value = ctx.doc.SIGNING_KEY;
  if (isString(value)) reportLowercase(ctx, 'SIGNING_KEY', value);
}

function checkCurrencyIssuers(ctx: RuleContext): void {
  entriesOf(ctx.doc.CURRENCIES).forEach((entry, i) => {
    const issuer = entry.issuer;
    if (isString(issuer)) reportLowercase(ctx, `CURRENCIES[${i}].issuer`, issuer);
  });
}

function checkValidatorPublicKeys(ctx: RuleContext): void {
  entriesOf(ctx.doc.VALIDATORS).forEach((entry, i) => {
    const key = entry.PUBLIC_KEY;
    if (isString(key)) reportLowercase(ctx, `VALIDATORS[${i}].PUBLIC_KEY`, key);
  });
}

/** Rules covering uppercase canonicalisation of Stellar account public keys. */
export const uppercaseKeyRules: Rule[] = [
  {
    id: RULE_ID,
    category: 'general',
    severity: 'warning',
    description: 'Stellar account public keys (SIGNING_KEY, issuer, PUBLIC_KEY) must be uppercase',
    run(ctx) {
      checkSigningKey(ctx);
      checkCurrencyIssuers(ctx);
      checkValidatorPublicKeys(ctx);
    },
  },
];
