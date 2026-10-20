import type { Diagnostic, Rule, RuleOverrides } from '../types.js';

export const SECURITY_MISSING_DMARC_RULE = 'security/missing-dmarc-record';
export const SECURITY_WEAK_SPF_RULE = 'security/weak-spf-policy';

export type TxtResolver = (hostname: string) => Promise<string[][] | undefined>;

export interface DmarcAuditorOptions {
  rules?: RuleOverrides;
  resolveTxt?: TxtResolver;
}

export const DEFAULT_EMAIL_DNS_DOMAIN_SOURCE = 'DOCUMENTATION.ORG_OFFICIAL_EMAIL';

export const dmarcAuditorRules: Rule[] = [
  {
    id: SECURITY_MISSING_DMARC_RULE,
    category: 'network',
    severity: 'warning',
    description: 'Anchor email domains should enforce a DMARC policy',
    run() {},
  },
  {
    id: SECURITY_WEAK_SPF_RULE,
    category: 'network',
    severity: 'warning',
    description: 'Anchor email domains should publish a strict SPF policy',
    run() {},
  },
];

const systemTxtResolver: TxtResolver = async (hostname) => {
  const dns = await import('node:dns/promises').catch(() => null);
  if (dns === null) return undefined;
  try {
    return await dns.resolveTxt(hostname);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    return code === 'ENODATA' || code === 'ENOTFOUND' ? [] : undefined;
  }
};

function normalizedDomain(value: unknown): string | undefined {
  if (typeof value !== 'string' || value.trim() === '') return undefined;
  try {
    const raw = value.trim();
    const url = new URL(raw.includes('://') ? raw : `https://${raw}`);
    return url.hostname.toLowerCase().replace(/\.$/, '');
  } catch {
    return undefined;
  }
}

function severityFor(rule: string, rules: RuleOverrides | undefined): 'warning' | undefined {
  return rules?.[rule] === 'off' ? undefined : 'warning';
}

export async function auditEmailDns(
  doc: Record<string, unknown>,
  options: DmarcAuditorOptions = {},
): Promise<Diagnostic[]> {
  const documentation = doc.DOCUMENTATION;
  const documentationRecord =
    typeof documentation === 'object' && documentation !== null && !Array.isArray(documentation)
      ? (documentation as Record<string, unknown>)
      : undefined;
  const officialEmail = documentationRecord?.ORG_OFFICIAL_EMAIL;
  const emailAddress = typeof officialEmail === 'string' ? officialEmail.trim() : '';
  const emailDomain = /^.+@([^@\s]+)$/.exec(emailAddress)?.[1];
  const domain =
    normalizedDomain(emailDomain) ??
    normalizedDomain(doc.DOMAIN) ??
    normalizedDomain(documentationRecord?.ORG_URL);
  if (domain === undefined) return [];

  const resolver = options.resolveTxt ?? systemTxtResolver;
  const [rootRecords, dmarcRecords] = await Promise.all([
    resolver(domain),
    resolver(`_dmarc.${domain}`),
  ]);
  const diagnostics: Diagnostic[] = [];

  if (rootRecords !== undefined) {
    const spf = rootRecords
      .map((record) => record.join(''))
      .filter((record) => /^v=spf1(?:\s|$)/i.test(record));
    const policy = spf.length === 1 ? spf[0] : undefined;
    if (
      policy === undefined ||
      !/(?:^|\s)-all\s*$/i.test(policy) ||
      /(?:^|\s)[+~]all\s*$/i.test(policy)
    ) {
      const severity = severityFor(SECURITY_WEAK_SPF_RULE, options.rules);
      if (severity !== undefined) {
        diagnostics.push({
          rule: SECURITY_WEAK_SPF_RULE,
          severity,
          category: 'network',
          message: `The SPF policy for ${domain} is missing, ambiguous, or does not end with -all`,
          suggestion:
            'Publish one valid SPF record and end it with -all to reject unauthorized senders.',
        });
      }
    }
  }

  if (dmarcRecords !== undefined) {
    const dmarc = dmarcRecords
      .map((record) => record.join(''))
      .filter((record) => /^v=DMARC1(?:\s*;|$)/i.test(record));
    const policy = dmarc.length === 1 ? dmarc[0] : undefined;
    const enforced =
      policy !== undefined && /(?:^|;)\s*p\s*=\s*(?:reject|quarantine)\s*(?:;|$)/i.test(policy);
    if (!enforced) {
      const severity = severityFor(SECURITY_MISSING_DMARC_RULE, options.rules);
      if (severity !== undefined) {
        diagnostics.push({
          rule: SECURITY_MISSING_DMARC_RULE,
          severity,
          category: 'network',
          message: `No enforcing DMARC record was found for ${domain}`,
          suggestion: 'Publish a DMARC record with p=reject or p=quarantine.',
        });
      }
    }
  }

  return diagnostics;
}
