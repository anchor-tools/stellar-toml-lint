/**
 * Small, dependency-light predicates shared by the rules.
 *
 * Stellar key validation delegates to `@stellar/stellar-base`, which verifies
 * the base32 encoding *and* the CRC16 checksum. That matters: a typo'd account
 * ID is the single most common `stellar.toml` defect, and a regex like
 * `/^G[A-Z2-7]{55}$/` happily accepts it.
 */
import { StrKey, Networks } from '@stellar/stellar-base';

/** Maximum file size SEP-1 permits. */
export const MAX_FILE_BYTES = 100 * 1024;

/** Network passphrases SEP-1 documents. Anything else is suspicious. */
export const KNOWN_PASSPHRASES: Record<string, string> = {
  [Networks.PUBLIC]: 'Public',
  [Networks.TESTNET]: 'Testnet',
  [Networks.FUTURENET]: 'Futurenet',
};

/**
 * `value` with the whitespace around its first `;` collapsed to exactly ` ; `.
 *
 * Every network passphrase has the shape `<name> ; <month> <year>`, and
 * whitespace typed around that separator is the classic hand-edited mistake —
 * it breaks signature verification while looking identical in an editor. So
 * three rules normalise the separator before deciding whether a passphrase is
 * a known one spelled badly or an unknown one spelled fine.
 *
 * Written with `indexOf` rather than the obvious replace against a
 * whitespace-semicolon-whitespace pattern, because that pattern is quadratic:
 * with no `;` in the value, `String.replace`
 * retries the unanchored match at every offset and each attempt rescans the
 * whitespace run. `NETWORK_PASSPHRASE` is a document value, so its length is
 * the file author's choice — 20,000 spaces cost 200ms per rule, measured.
 * `benchmarks/regression-harness.ts` is what caught it and what keeps it from
 * coming back.
 */
export function normalizePassphraseSeparator(value: string): string {
  const semicolon = value.indexOf(';');
  if (semicolon === -1) return value;
  return `${value.slice(0, semicolon).trimEnd()} ; ${value.slice(semicolon + 1).trimStart()}`;
}

export function isString(v: unknown): v is string {
  return typeof v === 'string';
}

export function isBoolean(v: unknown): v is boolean {
  return typeof v === 'boolean';
}

export function isInteger(v: unknown): v is number {
  return typeof v === 'number' && Number.isInteger(v);
}

export function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every(isString);
}

/** A `G...` account ID, checksum included. */
export function isAccountId(v: unknown): boolean {
  return isString(v) && StrKey.isValidEd25519PublicKey(v);
}

/** A `M...` muxed account ID. */
export function isMuxedAccountId(v: unknown): boolean {
  return isString(v) && StrKey.isValidMed25519PublicKey(v);
}

/** A `C...` contract ID, checksum included. */
export function isContractId(v: unknown): boolean {
  return isString(v) && StrKey.isValidContract(v);
}

/** Any absolute http(s) URL. */
export function isUrl(v: unknown): boolean {
  if (!isString(v)) return false;
  try {
    const u = new URL(v);
    return u.protocol === 'https:' || u.protocol === 'http:';
  } catch {
    return false;
  }
}

/** SEP-1 requires `https://` for every endpoint field. */
export function isHttpsUrl(v: unknown): boolean {
  if (!isString(v)) return false;
  try {
    return new URL(v).protocol === 'https:';
  } catch {
    return false;
  }
}

/**
 * Deliberately permissive: enough to catch `user@` or `not-an-email`, without
 * pretending to implement RFC 5322. Rejecting a valid exotic address would be
 * worse than missing an invalid one.
 */
export function isEmail(v: unknown): boolean {
  return isString(v) && /^[^\s@]+@[^\s@.]+(\.[^\s@.]+)+$/.test(v);
}

/**
 * Curated denylist of disposable / throwaway email providers.
 *
 * A ten-minute inbox is a strong signal of a low-quality or fraudulent issuer:
 * wallets, exchanges, and directory maintainers reach out to the contacts in
 * `[DOCUMENTATION]` and `[[PRINCIPALS]]` to verify an anchor, and an address
 * that expires before the reply arrives makes that impossible — listing
 * applications get rejected for it. Deliberately a small static set: the
 * linter runs offline, so no runtime package or network lookup may back it.
 */
export const DISPOSABLE_EMAIL_DOMAINS: ReadonlySet<string> = new Set([
  '10minutemail.com',
  '10minutemail.net',
  'dispostable.com',
  'fakeinbox.com',
  'getnada.com',
  'guerrillamail.com',
  'guerrillamailblock.com',
  'guerrillamail.info',
  'mailcatch.com',
  'maildrop.cc',
  'mailinator.com',
  'mailinator.org',
  'mailnesia.com',
  'minuteinbox.com',
  'mytemp.email',
  'sharklasers.com',
  'temp-mail.org',
  'tempmail.com',
  'tempmail.plus',
  'throwawayemail.com',
  'throwawaymail.com',
  'trash-mail.com',
  'trashmail.com',
  'yopmail.com',
  'yopmail.fr',
]);

/**
 * True when `email` is hosted at a known disposable provider.
 *
 * Subdomains count, because providers hand out `user@random.mailinator.com`
 * style aliases, and the comparison is case-insensitive so
 * `user@MAILINATOR.COM` is caught too. Syntax is not this predicate's job —
 * callers guard with {@link isEmail} so a malformed address is reported once,
 * by the rule that owns validity.
 */
export function isDisposableEmail(email: string): boolean {
  const at = email.lastIndexOf('@');
  if (at < 0) return false;
  const host = email
    .slice(at + 1)
    .toLowerCase()
    .replace(/\.$/, '');
  for (const domain of DISPOSABLE_EMAIL_DOMAINS) {
    if (host === domain || host.endsWith(`.${domain}`)) return true;
  }
  return false;
}

/** E.164: a leading `+`, then 2–15 digits, no separators. */
export function isE164(v: unknown): boolean {
  return isString(v) && /^\+[1-9]\d{1,14}$/.test(v);
}

export function isHex(v: unknown, length?: number): boolean {
  if (!isString(v) || !/^[0-9a-fA-F]+$/.test(v)) return false;
  return length === undefined || v.length === length;
}

/** Extracts a lowercase hostname from a URL, or `undefined` if unparseable. */
export function hostOf(url: unknown): string | undefined {
  if (!isString(url)) return undefined;
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return undefined;
  }
}

/**
 * True when `host` is `base` or a subdomain of it.
 *
 * SEP-1's "same domain" language is about organisational control, so
 * `www.example.com` satisfies a requirement anchored at `example.com`.
 */
export function isSameOrSubdomain(host: string, base: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, '');
  const b = base
    .toLowerCase()
    .replace(/^www\./, '')
    .replace(/\.$/, '');
  return h === b || h.endsWith(`.${b}`);
}

/** `host:port` or `domain:port`, as used by `[[VALIDATORS]].HOST`. */
export function isHostPort(v: unknown): boolean {
  if (!isString(v)) return false;
  const at = v.lastIndexOf(':');
  if (at <= 0 || at === v.length - 1) return false;
  const port = Number(v.slice(at + 1));
  if (!Number.isInteger(port) || port < 1 || port > 65535) return false;
  const host = v.slice(0, at);
  return host.length > 0 && !/\s/.test(host);
}

/** Endpoint fields must not carry a trailing slash; clients concatenate paths. */
export function hasTrailingSlash(v: unknown): boolean {
  if (!isString(v)) return false;
  try {
    const u = new URL(v);
    return u.pathname.endsWith('/') && u.pathname !== '/';
  } catch {
    return v.endsWith('/');
  }
}
