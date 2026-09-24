import type { Rule } from '../types.js';

export const emailMxRule: Rule = {
  id: 'general/email-domain-no-mx',
  category: 'general',
  severity: 'warning',
  description: 'ORG_OFFICIAL_EMAIL domain must have MX records for email deliverability',
  run: async (ctx) => {
    // Guard: only run under --check-network
    if (!ctx.options.checkNetwork) return;

    const documentation = ctx.doc.DOCUMENTATION;
    if (!documentation) return;

    const officialEmail = (documentation as Record<string, unknown>).ORG_OFFICIAL_EMAIL;
    if (typeof officialEmail !== 'string') return;

    const domain = officialEmail.split('@')[1];
    if (!domain) return;

    // DNS is a Node built-in, but this rule lives in the shared registry the
    // browser build walks. Load it lazily and stay silent where it cannot
    // exist — reported as not observed rather than guessed at, the same
    // bargain `tls.ts` makes for its socket. Typed structurally so the module
    // is only named in the `import()` call, never in a static import.
    let resolveMx: (hostname: string) => Promise<{ exchange: string; priority: number }[]>;
    try {
      ({ resolveMx } = await import('node:dns/promises'));
    } catch {
      return;
    }

    try {
      const mxRecords = await resolveMx(domain);
      if (mxRecords.length === 0) {
        ctx.report({
          rule: 'general/email-domain-no-mx',
          severity: 'warning',
          category: 'general',
          message: `Domain ${domain} has no MX records; email sent to ORG_OFFICIAL_EMAIL may bounce`,
          path: 'DOCUMENTATION.ORG_OFFICIAL_EMAIL',
          position: ctx.locate('DOCUMENTATION.ORG_OFFICIAL_EMAIL'),
          helpUri: 'https://developers.stellar.org/docs/sep-0001/#org-official-email',
          suggestion: 'Add MX records for your domain to ensure email deliverability.',
        });
      }
      // If mxRecords.length > 0, pass silently — no warning needed
    } catch {
      ctx.report({
        rule: 'general/email-domain-no-mx',
        severity: 'warning',
        category: 'general',
        message: `Could not resolve MX records for domain ${domain}`,
        path: 'DOCUMENTATION.ORG_OFFICIAL_EMAIL',
        position: ctx.locate('DOCUMENTATION.ORG_OFFICIAL_EMAIL'),
        helpUri: 'https://developers.stellar.org/docs/sep-0001/#org-official-email',
        suggestion: 'Verify that your domain has valid MX records configured.',
      });
    }
  },
};
