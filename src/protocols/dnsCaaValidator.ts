/**
 * DNS CAA (Certification Authority Authorization) validator (RFC 8659).
 *
 * Runs under opt-in `--audit-caa` together with `--domain`.
 *
 * Without CAA records any public CA may issue a certificate for the anchor's
 * domain, so a single mis-issuing CA is enough for a man-in-the-middle on the
 * SEP-10/SEP-24 endpoints. RFC 8659 §3 finds the relevant record set by
 * climbing from the domain towards the TLD and stopping at the first name that
 * has CAA records; this validator does the same and judges that set.
 *
 * The CAA lookup is injected so tests (and `--mock-fixtures` runs) never touch
 * real DNS. The default resolver is Node's `resolveCaa`, which follows CNAME
 * chains, so an aliased name is judged by the records at the alias target.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { errorMessage, severityFor } from './verifierSupport.js';

const MISSING_RULE = 'caa/missing-records';
const ISSUE_RULE = 'caa/missing-issue';
const ISSUEWILD_RULE = 'caa/missing-issuewild';
const UNRECOGNIZED_RULE = 'caa/unrecognized-ca';
const IODEF_RULE = 'caa/missing-iodef';
const INVALID_IODEF_RULE = 'caa/invalid-iodef';
const CRITICAL_RULE = 'caa/unknown-critical-tag';
const LOOKUP_RULE = 'caa/lookup-failed';

const SPEC = 'https://www.rfc-editor.org/rfc/rfc8659';

/** Issuer domain names of widely used public CAs. */
export const RECOGNIZED_CAS: readonly string[] = [
  'letsencrypt.org',
  'digicert.com',
  'sectigo.com',
  'comodoca.com',
  'globalsign.com',
  'pki.goog',
  'amazon.com',
  'amazontrust.com',
  'awstrust.com',
  'amazonaws.com',
  'godaddy.com',
  'starfieldtech.com',
  'entrust.net',
  'buypass.com',
  'zerossl.com',
  'ssl.com',
  'identrust.com',
  'certum.pl',
  'harica.gr',
  'microsoft.com',
];

/** Tags this validator understands; RFC 8659 §4.2 plus `contactemail`/`contactphone`. */
const KNOWN_TAGS = ['issue', 'issuewild', 'iodef', 'issuemail', 'contactemail', 'contactphone'];

/** Shape of Node's `dns.promises.resolveCaa` records. */
export interface CaaRecord {
  critical: number;
  issue?: string;
  issuewild?: string;
  iodef?: string;
  [tag: string]: string | number | undefined;
}

export type CaaResolver = (name: string) => Promise<CaaRecord[]>;

export interface DnsCaaOptions {
  rules?: RuleOverrides;
  domain: string;
  /** Defaults to `node:dns/promises` `resolveCaa`. */
  resolver?: CaaResolver;
  /** Issuer domains accepted without a warning. Defaults to {@link RECOGNIZED_CAS}. */
  recognizedCas?: readonly string[];
}

export interface DnsCaaResult {
  diagnostics: Diagnostic[];
  /** The name whose records are relevant, or `undefined` when none was found. */
  relevantName?: string;
  records: CaaRecord[];
  /** Every name that was queried, from the domain up to the registrable zone. */
  queried: string[];
}

/** Error codes that mean "this name has no CAA records", not "the lookup failed". */
const NO_DATA = new Set(['ENODATA', 'ENOTFOUND', 'NOTFOUND', 'NODATA']);

/** `a.b.example.com` -> `a.b.example.com`, `b.example.com`, `example.com` (never the TLD). */
export function caaLookupChain(domain: string): string[] {
  const labels = domain.toLowerCase().replace(/\.$/, '').split('.').filter(Boolean);
  const chain: string[] = [];
  for (let i = 0; i < labels.length - 1; i++) chain.push(labels.slice(i).join('.'));
  return chain;
}

/** The issuer domain of an `issue`/`issuewild` value, `''` for "no CA may issue". */
export function issuerOf(value: string): string {
  return (value.split(';')[0] ?? '').trim().toLowerCase();
}

/** RFC 8659 §4.4: `iodef` is a `mailto:` or `https:`/`http:` URL. */
export function isValidIodef(value: string): boolean {
  try {
    const u = new URL(value.trim());
    if (u.protocol === 'mailto:') return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(u.pathname);
    return u.protocol === 'https:' || u.protocol === 'http:';
  } catch {
    return false;
  }
}

const defaultResolver: CaaResolver = async (name) => {
  // Non-literal specifier keeps the browser bundle from trying to resolve a Node builtin.
  const specifier = 'node:dns/promises';
  const dns = (await import(specifier)) as { resolveCaa: CaaResolver };
  return dns.resolveCaa(name);
};

export class DnsCaaRecordValidator {
  constructor(private readonly options: DnsCaaOptions) {}

  async validate(): Promise<DnsCaaResult> {
    const diagnostics: Diagnostic[] = [];
    const { domain, rules } = this.options;
    const recognized = this.options.recognizedCas ?? RECOGNIZED_CAS;
    const resolver = this.options.resolver ?? defaultResolver;
    const push = (
      rule: string,
      fallback: 'error' | 'warning' | 'info',
      message: string,
      path: string,
      suggestion: string,
    ): void => {
      const severity = severityFor(rule, fallback, rules);
      if (severity === undefined) return;
      diagnostics.push({
        rule,
        severity,
        category: 'network',
        message,
        path,
        helpUri: SPEC,
        suggestion,
      });
    };

    const queried: string[] = [];
    for (const name of caaLookupChain(domain)) {
      queried.push(name);
      let records: CaaRecord[];
      try {
        records = await resolver(name);
      } catch (error) {
        const code = (error as { code?: unknown }).code;
        if (typeof code === 'string' && NO_DATA.has(code)) continue;
        // A timeout or SERVFAIL: a CA must refuse to issue, but we cannot judge the policy.
        push(
          LOOKUP_RULE,
          'warning',
          `CAA lookup for ${name} failed (${errorMessage(error)})`,
          name,
          'Make sure every authoritative name server answers CAA queries; CAs refuse to issue on SERVFAIL.',
        );
        return { diagnostics, records: [], queried };
      }
      if (records.length > 0) {
        this.judge(name, records, recognized, push);
        return { diagnostics, relevantName: name, records, queried };
      }
    }

    push(
      MISSING_RULE,
      'warning',
      `No CAA records on ${domain} or any parent zone; any public CA may issue certificates for it`,
      domain,
      `Publish e.g. ${domain} CAA 0 issue "letsencrypt.org" and ${domain} CAA 0 iodef "mailto:security@${domain}".`,
    );
    return { diagnostics, records: [], queried };
  }

  private judge(
    name: string,
    records: CaaRecord[],
    recognized: readonly string[],
    push: (
      rule: string,
      fallback: 'error' | 'warning' | 'info',
      message: string,
      path: string,
      suggestion: string,
    ) => void,
  ): void {
    const issue: string[] = [];
    const issuewild: string[] = [];
    const iodef: string[] = [];
    for (const record of records) {
      for (const [tag, value] of Object.entries(record)) {
        if (tag === 'critical' || typeof value !== 'string') continue;
        if (tag === 'issue') issue.push(value);
        else if (tag === 'issuewild') issuewild.push(value);
        else if (tag === 'iodef') iodef.push(value);
        else if (!KNOWN_TAGS.includes(tag) && (record.critical & 128) !== 0) {
          push(
            CRITICAL_RULE,
            'error',
            `CAA record on ${name} marks unknown tag "${tag}" critical; compliant CAs will refuse to issue`,
            name,
            'Clear the critical flag (use 0) or remove the record.',
          );
        }
      }
    }

    if (issue.length === 0) {
      push(
        ISSUE_RULE,
        'warning',
        `CAA records on ${name} have no "issue" property, so they do not restrict which CA may issue`,
        name,
        `Add ${name} CAA 0 issue "<your CA>" naming only the CAs you use.`,
      );
    }
    if (issuewild.length === 0) {
      push(
        ISSUEWILD_RULE,
        'info',
        `CAA records on ${name} have no "issuewild" property; wildcard issuance falls back to "issue"`,
        name,
        `Add ${name} CAA 0 issuewild ";" if you never need wildcard certificates.`,
      );
    }
    for (const [tag, values] of [
      ['issue', issue],
      ['issuewild', issuewild],
    ] as const) {
      for (const value of values) {
        const issuer = issuerOf(value);
        if (issuer !== '' && !recognized.includes(issuer)) {
          push(
            UNRECOGNIZED_RULE,
            'warning',
            `CAA ${tag} on ${name} names unrecognized CA "${issuer}"`,
            name,
            `Check the issuer domain against your CA's documentation (known: ${recognized.slice(0, 4).join(', ')}, ...).`,
          );
        }
      }
    }
    if (iodef.length === 0) {
      push(
        IODEF_RULE,
        'warning',
        `CAA records on ${name} have no "iodef" property; CAs cannot report refused requests`,
        name,
        `Add ${name} CAA 0 iodef "mailto:security@${name}".`,
      );
    }
    for (const value of iodef) {
      if (!isValidIodef(value)) {
        push(
          INVALID_IODEF_RULE,
          'error',
          `CAA iodef "${value}" on ${name} is not a mailto: or http(s) URL`,
          name,
          'Use mailto:security@<domain> or an https:// incident reporting endpoint.',
        );
      }
    }
  }
}

export async function auditDnsCaa(options: DnsCaaOptions): Promise<DnsCaaResult> {
  return new DnsCaaRecordValidator(options).validate();
}

const def = (id: string, severity: 'error' | 'warning' | 'info', description: string): Rule => ({
  id,
  category: 'network',
  severity,
  description,
  run() {},
});

export const dnsCaaRules: Rule[] = [
  def(MISSING_RULE, 'warning', 'The anchor domain should publish CAA records (RFC 8659)'),
  def(ISSUE_RULE, 'warning', 'CAA records should name the permitted CAs with "issue"'),
  def(ISSUEWILD_RULE, 'info', 'CAA records should set "issuewild" explicitly'),
  def(UNRECOGNIZED_RULE, 'warning', 'CAA issue/issuewild should name a recognized CA'),
  def(IODEF_RULE, 'warning', 'CAA records should configure an "iodef" reporting endpoint'),
  def(INVALID_IODEF_RULE, 'error', 'CAA iodef must be a mailto: or http(s) URL'),
  def(CRITICAL_RULE, 'error', 'CAA records must not mark unknown tags critical'),
  def(LOOKUP_RULE, 'warning', 'CAA lookups must succeed on every authoritative server'),
];

export const dnsCaaRuleIds: readonly string[] = dnsCaaRules.map((r) => r.id);
