import { DEPRECATED_FIELDS, KNOWN_DOCUMENTATION_FIELDS, specUrl } from '../spec.js';
import type { Rule } from '../types.js';

export const deprecationRules: Rule[] = [
  {
    id: 'general/deprecated-field',
    category: 'general',
    severity: 'warning',
    description: 'Flags deprecated SEP-1 fields and legacy configuration forms',
    run(ctx) {
      for (const [field, deprecation] of Object.entries(DEPRECATED_FIELDS)) {
        if (ctx.doc[field] === undefined) continue;
        ctx.report({
          rule: 'general/deprecated-field',
          category: 'general',
          message: `${field} is deprecated because ${deprecation.message}`,
          path: field,
          position: ctx.locate(field),
          helpUri: specUrl('general-information'),
          suggestion: deprecation.suggestion,
        });
      }

      const federationServer = ctx.doc.FEDERATION_SERVER;
      if (typeof federationServer === 'string' && /^http:\/\//i.test(federationServer)) {
        ctx.report({
          rule: 'general/deprecated-field',
          category: 'general',
          message: 'FEDERATION_SERVER uses the deprecated unencrypted form',
          path: 'FEDERATION_SERVER',
          position: ctx.locate('FEDERATION_SERVER'),
          helpUri: specUrl('general-information'),
          suggestion: 'Replace it with FEDERATION_SERVER = "https://api.example.com/federation".',
        });
      }

      for (const field of KNOWN_DOCUMENTATION_FIELDS) {
        if (ctx.doc[field] === undefined) continue;
        ctx.report({
          rule: 'general/deprecated-field',
          category: 'general',
          message: `${field} is deprecated at the top level`,
          path: field,
          position: ctx.locate(field),
          helpUri: specUrl('organization-documentation'),
          suggestion: `Move it under [DOCUMENTATION], for example: [DOCUMENTATION]\n${field} = "...".`,
        });
      }
    },
  },
];
