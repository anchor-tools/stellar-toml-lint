import type { Rule } from '../types.js';
import { KNOWN_PRINCIPAL_FIELDS, specUrl } from '../spec.js';
import { isEmail, isHex, isString } from '../predicates.js';

/** Reads `[[PRINCIPALS]]` as a list of tables, ignoring malformed entries. */
function principalsOf(doc: Record<string, unknown>): Record<string, unknown>[] {
  const list = doc.PRINCIPALS;
  if (!Array.isArray(list)) return [];
  return list.filter(
    (entry): entry is Record<string, unknown> =>
      typeof entry === 'object' && entry !== null && !Array.isArray(entry),
  );
}

/** Rules covering the `[[PRINCIPALS]]` list. */
export const principalRules: Rule[] = [
  {
    id: 'principals/entries-are-tables',
    category: 'principals',
    severity: 'error',
    description: 'PRINCIPALS must be a list of tables',
    run(ctx) {
      const list = ctx.doc.PRINCIPALS;
      if (list === undefined) return;

      if (!Array.isArray(list)) {
        ctx.report({
          rule: 'principals/entries-are-tables',
          category: 'principals',
          message: 'PRINCIPALS must be a list of tables, written as [[PRINCIPALS]]',
          path: 'PRINCIPALS',
          position: ctx.locate('PRINCIPALS'),
          helpUri: specUrl('point-of-contact-documentation'),
        });
        return;
      }

      list.forEach((entry, i) => {
        if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
          ctx.report({
            rule: 'principals/entries-are-tables',
            category: 'principals',
            message: `PRINCIPALS[${i}] must be a table`,
            path: `PRINCIPALS[${i}]`,
            position: ctx.locate(`PRINCIPALS[${i}]`),
            helpUri: specUrl('point-of-contact-documentation'),
          });
        }
      });
    },
  },

  {
    id: 'principals/required-fields',
    category: 'principals',
    severity: 'warning',
    description: 'Each principal should give a name and a business email',
    run(ctx) {
      principalsOf(ctx.doc).forEach((entry, i) => {
        const path = `PRINCIPALS[${i}]`;

        for (const field of ['name', 'email'] as const) {
          if (entry[field] !== undefined) continue;
          ctx.report({
            rule: 'principals/required-fields',
            category: 'principals',
            message: `${path} is missing ${field}`,
            path: `${path}.${field}`,
            position: ctx.locate(path),
            helpUri: specUrl('point-of-contact-documentation'),
            suggestion: 'Partners use this to reach a named, accountable contact.',
          });
        }

        const email = entry.email;
        if (email !== undefined && !isEmail(email)) {
          ctx.report({
            rule: 'principals/required-fields',
            category: 'principals',
            severity: 'error',
            message: `${path}.email is not a valid email address`,
            path: `${path}.email`,
            position: ctx.locate(`${path}.email`),
            helpUri: specUrl('point-of-contact-documentation'),
          });
        }
      });
    },
  },

  {
    id: 'principals/photo-hashes',
    category: 'principals',
    severity: 'error',
    description: 'Identity photo hashes must be hex-encoded SHA-256 digests',
    run(ctx) {
      principalsOf(ctx.doc).forEach((entry, i) => {
        const path = `PRINCIPALS[${i}]`;

        for (const field of ['id_photo_hash', 'verification_photo_hash'] as const) {
          const value = entry[field];
          if (value === undefined) continue;

          if (!isHex(value)) {
            ctx.report({
              rule: 'principals/photo-hashes',
              category: 'principals',
              message: `${path}.${field} is not a hex-encoded hash`,
              path: `${path}.${field}`,
              position: ctx.locate(`${path}.${field}`),
              helpUri: specUrl('point-of-contact-documentation'),
              suggestion: 'Use the lowercase hex digest, e.g. the output of `sha256sum photo.jpg`.',
            });
            continue;
          }

          // SEP-1's prose specifies SHA-256 (64 hex chars) while its own example
          // shows 128 chars. Anything else is almost certainly a mistake, so
          // flag the length without pretending the spec is unambiguous.
          const length = String(value).length;
          if (length !== 64 && length !== 128) {
            ctx.report({
              rule: 'principals/photo-hashes',
              category: 'principals',
              severity: 'warning',
              message: `${path}.${field} is ${length} hex characters, which is not a SHA-256 digest`,
              path: `${path}.${field}`,
              position: ctx.locate(`${path}.${field}`),
              helpUri: specUrl('point-of-contact-documentation'),
              suggestion: 'A SHA-256 digest is 64 hex characters.',
            });
          }
        }
      });
    },
  },

  {
    id: 'principals/social-handles',
    category: 'principals',
    severity: 'warning',
    description: 'Principal social fields should hold bare handles, not URLs',
    run(ctx) {
      principalsOf(ctx.doc).forEach((entry, i) => {
        const path = `PRINCIPALS[${i}]`;

        for (const field of ['twitter', 'github', 'keybase', 'telegram'] as const) {
          const value = entry[field];
          if (!isString(value)) continue;
          if (!/^https?:\/\//i.test(value) && !value.includes('/') && !value.startsWith('@')) {
            continue;
          }

          const handle = value.replace(/^@/, '').replace(/\/+$/, '').split('/').pop() ?? value;
          ctx.report({
            rule: 'principals/social-handles',
            category: 'principals',
            message: `${path}.${field} should be an account name, not a URL or @handle`,
            path: `${path}.${field}`,
            position: ctx.locate(`${path}.${field}`),
            helpUri: specUrl('point-of-contact-documentation'),
            suggestion: `Use "${handle}".`,
            fix: { value: handle },
          });
        }
      });
    },
  },

  {
    id: 'principals/unknown-field',
    category: 'principals',
    severity: 'info',
    description: 'Flags principal fields SEP-1 does not define',
    run(ctx) {
      principalsOf(ctx.doc).forEach((entry, i) => {
        const path = `PRINCIPALS[${i}]`;
        for (const key of Object.keys(entry)) {
          if (KNOWN_PRINCIPAL_FIELDS.has(key)) continue;
          ctx.report({
            rule: 'principals/unknown-field',
            category: 'principals',
            message: `${path}.${key} is not a field defined by SEP-1`,
            path: `${path}.${key}`,
            position: ctx.locate(`${path}.${key}`),
            helpUri: specUrl('point-of-contact-documentation'),
          });
        }
      });
    },
  },
];
