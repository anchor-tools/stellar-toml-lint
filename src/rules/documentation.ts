import type { Rule } from '../types.js';
import { KNOWN_DOCUMENTATION_FIELDS, RECOMMENDED_DOCUMENTATION_FIELDS, specUrl } from '../spec.js';
import {
  hostOf,
  isE164,
  isEmail,
  isHttpsUrl,
  isSameOrSubdomain,
  isString,
  isUrl,
} from '../predicates.js';

/** Reads the `[DOCUMENTATION]` table, or `undefined` if absent/malformed. */
export function documentationOf(doc: Record<string, unknown>): Record<string, unknown> | undefined {
  const table = doc.DOCUMENTATION;
  if (typeof table !== 'object' || table === null || Array.isArray(table)) return undefined;
  return table as Record<string, unknown>;
}

/** Rules covering the `[DOCUMENTATION]` table. */
export const documentationRules: Rule[] = [
  {
    id: 'documentation/present',
    category: 'documentation',
    severity: 'warning',
    description: 'A [DOCUMENTATION] table should be present',
    run(ctx) {
      if (ctx.doc.DOCUMENTATION === undefined) {
        ctx.report({
          rule: 'documentation/present',
          category: 'documentation',
          message: 'No [DOCUMENTATION] table, which wallets and exchanges use to vet issuers',
          path: 'DOCUMENTATION',
          helpUri: specUrl('organization-documentation'),
          suggestion:
            'Add a [DOCUMENTATION] table with at least ORG_NAME, ORG_URL, and ORG_DESCRIPTION.',
        });
        return;
      }
      if (documentationOf(ctx.doc) === undefined) {
        ctx.report({
          rule: 'documentation/present',
          category: 'documentation',
          severity: 'error',
          message: 'DOCUMENTATION must be a table, written as [DOCUMENTATION]',
          path: 'DOCUMENTATION',
          position: ctx.locate('DOCUMENTATION'),
          helpUri: specUrl('organization-documentation'),
        });
      }
    },
  },

  {
    id: 'documentation/recommended-fields',
    category: 'documentation',
    severity: 'warning',
    description: 'Fields wallets weigh when deciding whether to list an asset',
    run(ctx) {
      const documentation = documentationOf(ctx.doc);
      if (!documentation) return;

      for (const field of RECOMMENDED_DOCUMENTATION_FIELDS) {
        if (documentation[field] !== undefined) continue;
        ctx.report({
          rule: 'documentation/recommended-fields',
          category: 'documentation',
          message: `DOCUMENTATION.${field} is missing, which weakens your listing case`,
          path: `DOCUMENTATION.${field}`,
          position: ctx.locate('DOCUMENTATION'),
          helpUri: specUrl('organization-documentation'),
          suggestion: 'Wallets and exchanges rank issuers by documentation completeness.',
        });
      }
    },
  },

  {
    id: 'documentation/urls',
    category: 'documentation',
    severity: 'error',
    description: 'ORG_URL and attestation URLs must use https://',
    run(ctx) {
      const documentation = documentationOf(ctx.doc);
      if (!documentation) return;

      const httpsFields = [
        'ORG_URL',
        'ORG_PHYSICAL_ADDRESS_ATTESTATION',
        'ORG_PHONE_NUMBER_ATTESTATION',
      ] as const;

      for (const field of httpsFields) {
        const value = documentation[field];
        if (value === undefined) continue;
        if (!isHttpsUrl(value)) {
          ctx.report({
            rule: 'documentation/urls',
            category: 'documentation',
            message: `DOCUMENTATION.${field} must be an https:// URL`,
            path: `DOCUMENTATION.${field}`,
            position: ctx.locate(`DOCUMENTATION.${field}`),
            helpUri: specUrl('organization-documentation'),
          });
        }
      }

      // ORG_LOGO is specified as a plain `url`, and must be a PNG.
      const logo = documentation.ORG_LOGO;
      if (logo !== undefined) {
        if (!isUrl(logo)) {
          ctx.report({
            rule: 'documentation/urls',
            category: 'documentation',
            message: 'DOCUMENTATION.ORG_LOGO must be a valid URL',
            path: 'DOCUMENTATION.ORG_LOGO',
            position: ctx.locate('DOCUMENTATION.ORG_LOGO'),
            helpUri: specUrl('organization-documentation'),
          });
        } else if (!/\.png(\?|#|$)/i.test(String(logo))) {
          ctx.report({
            rule: 'documentation/urls',
            category: 'documentation',
            severity: 'warning',
            message: 'DOCUMENTATION.ORG_LOGO should be a PNG on a transparent background',
            path: 'DOCUMENTATION.ORG_LOGO',
            position: ctx.locate('DOCUMENTATION.ORG_LOGO'),
            helpUri: specUrl('organization-documentation'),
          });
        }
      }
    },
  },

  {
    id: 'documentation/attestation-domain',
    category: 'documentation',
    severity: 'warning',
    description: 'Attestation URLs must be on the same domain as ORG_URL',
    run(ctx) {
      const documentation = documentationOf(ctx.doc);
      if (!documentation) return;

      const orgHost = hostOf(documentation.ORG_URL);
      if (!orgHost) return;

      for (const field of ['ORG_PHYSICAL_ADDRESS_ATTESTATION', 'ORG_PHONE_NUMBER_ATTESTATION']) {
        const value = documentation[field];
        if (value === undefined) continue;
        const host = hostOf(value);
        if (!host || isSameOrSubdomain(host, orgHost)) continue;

        ctx.report({
          rule: 'documentation/attestation-domain',
          category: 'documentation',
          message: `DOCUMENTATION.${field} is hosted on ${host}, not on the ORG_URL domain ${orgHost}`,
          path: `DOCUMENTATION.${field}`,
          position: ctx.locate(`DOCUMENTATION.${field}`),
          helpUri: specUrl('organization-documentation'),
          suggestion: 'SEP-1 requires attestation documents to live on your own domain.',
        });
      }
    },
  },

  {
    id: 'documentation/org-url-matches-domain',
    category: 'documentation',
    severity: 'error',
    description: 'ORG_URL must match the domain hosting the file (needs --domain)',
    run(ctx) {
      const documentation = documentationOf(ctx.doc);
      const domain = ctx.options.domain;
      if (!documentation || !domain) return;

      const orgHost = hostOf(documentation.ORG_URL);
      if (!orgHost) return;

      const servingHost = domain.replace(/^https?:\/\//, '').split('/')[0] ?? domain;
      if (isSameOrSubdomain(orgHost, servingHost) || isSameOrSubdomain(servingHost, orgHost)) {
        return;
      }

      ctx.report({
        rule: 'documentation/org-url-matches-domain',
        category: 'documentation',
        message: `ORG_URL points at ${orgHost} but the file is served from ${servingHost}`,
        path: 'DOCUMENTATION.ORG_URL',
        position: ctx.locate('DOCUMENTATION.ORG_URL'),
        helpUri: specUrl('organization-documentation'),
        suggestion: 'SEP-1 requires the stellar.toml to be hosted on the ORG_URL domain.',
      });
    },
  },

  {
    id: 'documentation/emails',
    category: 'documentation',
    severity: 'error',
    description: 'Organization emails must be well formed and correctly hosted',
    run(ctx) {
      const documentation = documentationOf(ctx.doc);
      if (!documentation) return;

      for (const field of ['ORG_OFFICIAL_EMAIL', 'ORG_SUPPORT_EMAIL']) {
        const value = documentation[field];
        if (value === undefined) continue;
        if (!isEmail(value)) {
          ctx.report({
            rule: 'documentation/emails',
            category: 'documentation',
            message: `DOCUMENTATION.${field} is not a valid email address`,
            path: `DOCUMENTATION.${field}`,
            position: ctx.locate(`DOCUMENTATION.${field}`),
            helpUri: specUrl('organization-documentation'),
          });
        }
      }

      // Only ORG_OFFICIAL_EMAIL carries the same-domain requirement; support
      // addresses are commonly delegated to a helpdesk provider.
      const official = documentation.ORG_OFFICIAL_EMAIL;
      const orgHost = hostOf(documentation.ORG_URL);
      if (isEmail(official) && orgHost) {
        const emailDomain = String(official).split('@')[1]?.toLowerCase();
        if (emailDomain && !isSameOrSubdomain(emailDomain, orgHost)) {
          ctx.report({
            rule: 'documentation/emails',
            category: 'documentation',
            severity: 'warning',
            message: `DOCUMENTATION.ORG_OFFICIAL_EMAIL is at ${emailDomain}, not the ORG_URL domain ${orgHost}`,
            path: 'DOCUMENTATION.ORG_OFFICIAL_EMAIL',
            position: ctx.locate('DOCUMENTATION.ORG_OFFICIAL_EMAIL'),
            helpUri: specUrl('organization-documentation'),
            suggestion: 'SEP-1 requires the official email to be hosted at your ORG_URL domain.',
          });
        }
      }
    },
  },

  {
    id: 'documentation/phone-e164',
    category: 'documentation',
    severity: 'warning',
    description: 'ORG_PHONE_NUMBER should be in E.164 format',
    run(ctx) {
      const documentation = documentationOf(ctx.doc);
      if (!documentation) return;

      const phone = documentation.ORG_PHONE_NUMBER;
      if (phone === undefined) return;
      if (isE164(phone)) return;

      const digits = isString(phone) ? phone.replace(/[^\d]/g, '') : '';
      ctx.report({
        rule: 'documentation/phone-e164',
        category: 'documentation',
        message: 'DOCUMENTATION.ORG_PHONE_NUMBER is not in E.164 format',
        path: 'DOCUMENTATION.ORG_PHONE_NUMBER',
        position: ctx.locate('DOCUMENTATION.ORG_PHONE_NUMBER'),
        helpUri: 'https://en.wikipedia.org/wiki/E.164',
        suggestion: digits
          ? `Use a leading + and digits only, e.g. "+${digits}".`
          : 'Use a leading + followed by country code and number, e.g. "+14155552671".',
        ...(isE164(`+${digits}`) ? { fix: { value: `+${digits}` } } : {}),
      });
    },
  },

  {
    id: 'documentation/social-handles',
    category: 'documentation',
    severity: 'warning',
    description: 'Social fields should hold bare handles, not URLs',
    run(ctx) {
      const documentation = documentationOf(ctx.doc);
      if (!documentation) return;

      // ORG_GITHUB is deliberately absent: a github.com profile URL is an
      // accepted form, so `general/invalid-github-handle` owns that field.
      for (const field of ['ORG_TWITTER', 'ORG_KEYBASE']) {
        const value = documentation[field];
        if (!isString(value)) continue;

        if (/^https?:\/\//i.test(value) || value.includes('/')) {
          const handle = value.replace(/\/+$/, '').split('/').pop() ?? value;
          ctx.report({
            rule: 'documentation/social-handles',
            category: 'documentation',
            message: `DOCUMENTATION.${field} should be an account name, not a URL`,
            path: `DOCUMENTATION.${field}`,
            position: ctx.locate(`DOCUMENTATION.${field}`),
            helpUri: specUrl('organization-documentation'),
            suggestion: `Use the bare handle, e.g. "${handle}".`,
            fix: { value: handle },
          });
        } else if (value.startsWith('@')) {
          ctx.report({
            rule: 'documentation/social-handles',
            category: 'documentation',
            message: `DOCUMENTATION.${field} should not include a leading @`,
            path: `DOCUMENTATION.${field}`,
            position: ctx.locate(`DOCUMENTATION.${field}`),
            helpUri: specUrl('organization-documentation'),
            suggestion: `Use "${value.slice(1)}".`,
            fix: { value: value.slice(1) },
          });
        }
      }
    },
  },

  {
    id: 'documentation/license-number-without-authority',
    category: 'documentation',
    severity: 'warning',
    description: 'ORG_LICENSE_NUMBER requires ORG_LICENSING_AUTHORITY',
    run(ctx) {
      const documentation = documentationOf(ctx.doc);
      if (!documentation) return;

      const licenseNumber = documentation.ORG_LICENSE_NUMBER;
      const licensingAuthority = documentation.ORG_LICENSING_AUTHORITY;

      if (licenseNumber !== undefined && licensingAuthority === undefined) {
        ctx.report({
          rule: 'documentation/license-number-without-authority',
          category: 'documentation',
          message:
            'ORG_LICENSE_NUMBER is set without ORG_LICENSING_AUTHORITY, making the license unverifiable',
          path: 'ORG_LICENSE_NUMBER',
          position: ctx.locate('ORG_LICENSE_NUMBER'),
          helpUri: specUrl('organization-documentation'),
          suggestion:
            'Add ORG_LICENSING_AUTHORITY to specify the licensing authority, or remove ORG_LICENSE_NUMBER.',
        });
      }
    },
  },
  {
    id: 'documentation/unknown-field',
    category: 'documentation',
    severity: 'info',
    description: 'Flags [DOCUMENTATION] fields SEP-1 does not define',
    run(ctx) {
      const documentation = documentationOf(ctx.doc);
      if (!documentation) return;

      for (const key of Object.keys(documentation)) {
        if (KNOWN_DOCUMENTATION_FIELDS.has(key)) continue;
        ctx.report({
          rule: 'documentation/unknown-field',
          category: 'documentation',
          message: `DOCUMENTATION.${key} is not a field defined by SEP-1`,
          path: `DOCUMENTATION.${key}`,
          position: ctx.locate(`DOCUMENTATION.${key}`),
          helpUri: specUrl('organization-documentation'),
        });
      }
    },
  },
];
