/**
 * RFC 9116 `security.txt` validator.
 *
 * Runs under opt-in `--verify-security-txt` (or `stellar-toml-lint
 * verify-security-txt --domain <domain>`).
 *
 * Anchors hold customer funds, so researchers need a working, current way to
 * report a vulnerability. This fetches `https://<domain>/.well-known/security.txt`,
 * checks the required `Contact` and `Expires` fields, the optional URI fields,
 * and the shape of an OpenPGP cleartext signature when one is present.
 *
 * Cryptographic signature checking needs the signer's key and an OpenPGP
 * implementation, neither of which this dependency-free linter ships, so it is
 * an injected `verifySignature` hook. Without it the armor and its CRC-24
 * checksum are still verified.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { errorMessage, fetchWithTimeout, severityFor } from './verifierSupport.js';

const UNREACHABLE_RULE = 'securitytxt/unreachable';
const CONTACT_RULE = 'securitytxt/missing-contact';
const INVALID_CONTACT_RULE = 'securitytxt/invalid-contact';
const EXPIRES_RULE = 'securitytxt/missing-expires';
const EXPIRED_RULE = 'securitytxt/expired';
const FAR_EXPIRY_RULE = 'securitytxt/expires-too-far';
const FIELD_RULE = 'securitytxt/invalid-field';
const POLICY_RULE = 'securitytxt/missing-policy';
const SIGNATURE_RULE = 'securitytxt/invalid-signature';

const SPEC = 'https://www.rfc-editor.org/rfc/rfc9116';

const URI_FIELDS = ['encryption', 'acknowledgments', 'policy', 'hiring', 'canonical', 'csaf'];
const SINGLE_FIELDS = ['expires', 'preferred-languages'];
const YEAR_MS = 366 * 24 * 60 * 60 * 1000;

export interface SecurityTxtField {
  name: string;
  value: string;
  line: number;
}

export interface ParsedSecurityTxt {
  fields: SecurityTxtField[];
  /** Present when the file is an OpenPGP cleartext signed message. */
  signature?: { signedText: string; armor: string; hash?: string };
  /** Lines that are neither comments, blank, nor `Name: value`. */
  malformedLines: number[];
}

export type SignatureVerifier = (signedText: string, armoredSignature: string) => Promise<boolean>;

export interface SecurityTxtOptions {
  rules?: RuleOverrides;
  domain: string;
  /** Use this text instead of fetching it (tests, recorded fixtures). */
  text?: string;
  /** Reference time for `Expires`; defaults to now. */
  now?: Date;
  timeoutMs?: number;
  verifySignature?: SignatureVerifier;
}

export interface SecurityTxtResult {
  diagnostics: Diagnostic[];
  url: string;
  parsed?: ParsedSecurityTxt;
  expires?: Date;
}

/**
 * Parses an RFC 9116 `Expires` value: an RFC 3339 date-time with seconds and
 * an explicit offset (`Z` or `+hh:mm`). Returns `undefined` for anything else,
 * including impossible calendar dates.
 */
export function parseExpires(value: string): Date | undefined {
  const m =
    /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/.exec(
      value.trim(),
    );
  if (!m) return undefined;
  const [year, month, day, hour, minute, second] = m.slice(1, 7).map(Number) as number[];
  const date = new Date(Date.UTC(year!, month! - 1, day!, hour!, minute!, second!));
  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month! - 1 ||
    date.getUTCDate() !== day ||
    hour! > 23 ||
    minute! > 59 ||
    second! > 59
  ) {
    return undefined;
  }
  const parsed = new Date(value.trim());
  return Number.isNaN(parsed.getTime()) ? undefined : parsed;
}

/** CRC-24 as used by OpenPGP ASCII armor (RFC 4880 §6.1). */
export function crc24(bytes: Uint8Array): number {
  let crc = 0xb704ce;
  for (const byte of bytes) {
    crc ^= byte << 16;
    for (let i = 0; i < 8; i++) {
      crc <<= 1;
      if (crc & 0x1000000) crc ^= 0x1864cfb;
    }
  }
  return crc & 0xffffff;
}

/** Checks armor framing, base64 body and the `=XXXX` CRC-24 line. */
export function isWellFormedArmor(armor: string): boolean {
  const lines = armor.split(/\r?\n/).map((l) => l.trim());
  const begin = lines.indexOf('-----BEGIN PGP SIGNATURE-----');
  const end = lines.indexOf('-----END PGP SIGNATURE-----');
  if (begin < 0 || end < begin) return false;
  let i = begin + 1;
  while (i < end && lines[i] !== '') i++; // armor headers
  const body = lines.slice(i + 1, end).filter((l) => l !== '');
  const checksum = body.at(-1);
  if (!checksum?.startsWith('=')) return false;
  const data = body.slice(0, -1).join('');
  if (data === '' || data.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(data)) return false;
  if (!/^=[A-Za-z0-9+/]{4}$/.test(checksum)) return false;
  const crc = base64Bytes(checksum.slice(1));
  return crc24(base64Bytes(data)) === (crc[0]! << 16) + (crc[1]! << 8) + crc[2]!;
}

function base64Bytes(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

export function parseSecurityTxt(text: string): ParsedSecurityTxt {
  let body = text.replace(/^\uFEFF/, '');
  let signature: ParsedSecurityTxt['signature'];
  const lines = body.split(/\r?\n/);
  if (lines[0]?.trim() === '-----BEGIN PGP SIGNED MESSAGE-----') {
    const sigStart = lines.findIndex((l) => l.trim() === '-----BEGIN PGP SIGNATURE-----');
    let i = 1;
    let hash: string | undefined;
    while (i < lines.length && lines[i]!.trim() !== '') {
      const h = /^Hash:\s*(.+)$/.exec(lines[i]!.trim());
      if (h) hash = h[1];
      i++;
    }
    const signedLines = lines.slice(i + 1, sigStart < 0 ? lines.length : sigStart);
    // Dash-escaped lines ("- -----") are unescaped before parsing (RFC 4880 §7.1).
    const signedText = signedLines.map((l) => l.replace(/^- /, '')).join('\n');
    signature = {
      signedText,
      armor: sigStart < 0 ? '' : lines.slice(sigStart).join('\n'),
      ...(hash !== undefined ? { hash } : {}),
    };
    body = signedText;
  }

  const fields: SecurityTxtField[] = [];
  const malformedLines: number[] = [];
  body.split(/\r?\n/).forEach((raw, idx) => {
    const line = raw.trim();
    if (line === '' || line.startsWith('#')) return;
    const m = /^([A-Za-z0-9-]+):\s*(.*)$/.exec(line);
    if (!m || m[2] === '') malformedLines.push(idx + 1);
    else fields.push({ name: m[1]!.toLowerCase(), value: m[2]!, line: idx + 1 });
  });
  return { fields, malformedLines, ...(signature ? { signature } : {}) };
}

function isContactUri(value: string): boolean {
  try {
    const u = new URL(value);
    if (u.protocol === 'mailto:') return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(u.pathname);
    if (u.protocol === 'tel:') return /^\+?[0-9-. ()]{4,}$/.test(decodeURIComponent(u.pathname));
    return u.protocol === 'https:';
  } catch {
    return false;
  }
}

function isHttpsUri(value: string): boolean {
  try {
    const u = new URL(value);
    // `Encryption` may also be an `openpgp4fpr:` or `dns:` URI (RFC 9116 §2.5.4).
    return u.protocol === 'https:' || u.protocol === 'openpgp4fpr:' || u.protocol === 'dns:';
  } catch {
    return false;
  }
}

export class SecurityTxtValidator {
  constructor(
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly options: SecurityTxtOptions,
  ) {}

  async validate(): Promise<SecurityTxtResult> {
    const diagnostics: Diagnostic[] = [];
    const { domain, rules } = this.options;
    const url = `https://${domain}/.well-known/security.txt`;
    const push = (
      rule: string,
      fallback: 'error' | 'warning' | 'info',
      message: string,
      suggestion: string,
    ): void => {
      const severity = severityFor(rule, fallback, rules);
      if (severity === undefined) return;
      diagnostics.push({
        rule,
        severity,
        category: 'network',
        message,
        path: url,
        helpUri: SPEC,
        suggestion,
      });
    };

    let text = this.options.text;
    if (text === undefined) {
      try {
        const res = await fetchWithTimeout(this.fetchImpl, url, {}, this.options.timeoutMs);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        text = await res.text();
      } catch (error) {
        push(
          UNREACHABLE_RULE,
          'error',
          `${url} could not be fetched (${errorMessage(error)})`,
          'Serve an RFC 9116 security.txt at /.well-known/security.txt over HTTPS as text/plain.',
        );
        return { diagnostics, url };
      }
    }

    const parsed = parseSecurityTxt(text);
    const byName = (name: string): SecurityTxtField[] =>
      parsed.fields.filter((f) => f.name === name);

    const contacts = byName('contact');
    if (contacts.length === 0) {
      push(
        CONTACT_RULE,
        'error',
        'security.txt has no Contact field',
        `Add "Contact: mailto:security@${domain}".`,
      );
    }
    for (const c of contacts) {
      if (!isContactUri(c.value)) {
        push(
          INVALID_CONTACT_RULE,
          'error',
          `Contact "${c.value}" (line ${c.line}) is not a mailto:, tel: or https: URI`,
          'Write e-mail contacts as mailto: URIs and web forms as https:// URLs.',
        );
      }
    }

    const expiresFields = byName('expires');
    let expires: Date | undefined;
    if (expiresFields.length === 0) {
      push(
        EXPIRES_RULE,
        'error',
        'security.txt has no Expires field',
        'Add "Expires: <RFC 3339 date-time>" less than a year in the future.',
      );
    } else {
      expires = parseExpires(expiresFields[0]!.value);
      const now = this.options.now ?? new Date();
      if (expires === undefined) {
        push(
          FIELD_RULE,
          'error',
          `Expires "${expiresFields[0]!.value}" is not an RFC 3339 date-time`,
          'Use the form 2027-01-31T23:59:59Z.',
        );
      } else if (expires.getTime() <= now.getTime()) {
        push(
          EXPIRED_RULE,
          'error',
          `security.txt expired on ${expires.toISOString()}`,
          'Review the file and move Expires forward; researchers must treat it as stale.',
        );
      } else if (expires.getTime() - now.getTime() > YEAR_MS) {
        push(
          FAR_EXPIRY_RULE,
          'info',
          `Expires ${expires.toISOString()} is more than a year away`,
          'RFC 9116 recommends an Expires value less than a year in the future.',
        );
      }
    }

    for (const name of SINGLE_FIELDS) {
      if (byName(name).length > 1) {
        push(
          FIELD_RULE,
          'error',
          `security.txt has more than one ${name} field`,
          `Keep a single ${name} line.`,
        );
      }
    }
    for (const f of parsed.fields) {
      if (URI_FIELDS.includes(f.name) && !isHttpsUri(f.value)) {
        push(
          FIELD_RULE,
          'error',
          `${f.name} "${f.value}" (line ${f.line}) must be an https:// URI`,
          'RFC 9116 requires web URIs in security.txt to use https.',
        );
      }
    }
    for (const lang of byName('preferred-languages')) {
      const tags = lang.value.split(',').map((t) => t.trim());
      if (tags.some((t) => !/^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*$/.test(t))) {
        push(
          FIELD_RULE,
          'error',
          `Preferred-Languages "${lang.value}" is not a comma-separated list of language tags`,
          'Use RFC 5646 tags such as "en, fr".',
        );
      }
    }
    for (const line of parsed.malformedLines) {
      push(
        FIELD_RULE,
        'error',
        `Line ${line} is not a "Field: value" line or a comment`,
        'Prefix free text with "#".',
      );
    }
    if (byName('policy').length === 0) {
      push(
        POLICY_RULE,
        'info',
        'security.txt has no Policy field linking a vulnerability disclosure policy',
        'Add "Policy: https://<domain>/security-policy" describing scope and safe harbour.',
      );
    }

    if (parsed.signature) await this.checkSignature(parsed.signature, push);
    return { diagnostics, url, parsed, ...(expires ? { expires } : {}) };
  }

  private async checkSignature(
    sig: NonNullable<ParsedSecurityTxt['signature']>,
    push: (rule: string, fallback: 'error', message: string, suggestion: string) => void,
  ): Promise<void> {
    if (!isWellFormedArmor(sig.armor)) {
      push(
        SIGNATURE_RULE,
        'error',
        'security.txt has a cleartext signature header but no valid PGP SIGNATURE block (bad armor or CRC-24)',
        'Re-sign with "gpg --clearsign security.txt" and publish the output unchanged.',
      );
      return;
    }
    if (!this.options.verifySignature) return;
    let ok: boolean;
    try {
      ok = await this.options.verifySignature(sig.signedText, sig.armor);
    } catch {
      ok = false;
    }
    if (!ok) {
      push(
        SIGNATURE_RULE,
        'error',
        'The OpenPGP signature over security.txt does not verify',
        'Re-sign the current file with the key published under Encryption.',
      );
    }
  }
}

export async function verifySecurityTxt(
  fetchImpl: typeof fetch,
  options: SecurityTxtOptions,
): Promise<SecurityTxtResult> {
  return new SecurityTxtValidator(fetchImpl, options).validate();
}

const def = (id: string, severity: 'error' | 'warning' | 'info', description: string): Rule => ({
  id,
  category: 'network',
  severity,
  description,
  run() {},
});

export const securityTxtRules: Rule[] = [
  def(UNREACHABLE_RULE, 'error', 'The anchor domain must serve /.well-known/security.txt'),
  def(CONTACT_RULE, 'error', 'security.txt must have a Contact field'),
  def(INVALID_CONTACT_RULE, 'error', 'security.txt Contact must be a mailto:, tel: or https: URI'),
  def(EXPIRES_RULE, 'error', 'security.txt must have an Expires field'),
  def(EXPIRED_RULE, 'error', 'security.txt Expires must be in the future'),
  def(FAR_EXPIRY_RULE, 'info', 'security.txt Expires should be less than a year away'),
  def(FIELD_RULE, 'error', 'security.txt fields must follow RFC 9116 syntax'),
  def(POLICY_RULE, 'info', 'security.txt should link a disclosure Policy'),
  def(SIGNATURE_RULE, 'error', 'A signed security.txt must carry a valid OpenPGP signature'),
];

export const securityTxtRuleIds: readonly string[] = securityTxtRules.map((r) => r.id);
