/**
 * RFC 7512 PKCS#11 key URI syntax and attribute validator.
 *
 * Enterprise anchors often keep `SIGNING_KEY` and issuer keys in an HSM and
 * refer to them with a PKCS#11 URI such as
 * `pkcs11:token=stellar;object=signing-key`. Those pointers are deployment
 * configuration, but a malformed URI or an embedded plaintext PIN is a real
 * security problem, so this module validates the URI before a file is
 * published.
 *
 * The parser implements the URI shape from RFC 7512: a `pkcs11:` scheme, an
 * optional semicolon-separated path, and an optional `?` query whose names and
 * values are separated by `&` and `=`. Percent escapes are decoded strictly.
 */
import type { Diagnostic, Rule, RuleContext, RuleOverrides } from '../types.js';
import { isString } from '../predicates.js';

export const MALFORMED_PKCS11_URI_RULE = 'crypto/malformed-pkcs11-uri';
export const INSECURE_EMBEDDED_PKCS11_PIN_RULE = 'crypto/insecure-embedded-pkcs11-pin';
export const CRYPTO_MALFORMED_PKCS11_URI = MALFORMED_PKCS11_URI_RULE;
export const CRYPTO_INSECURE_EMBEDDED_PKCS11_PIN = INSECURE_EMBEDDED_PKCS11_PIN_RULE;

/** Path attributes RFC 7512 defines, plus the query-only attributes. */
const PATH_ATTRIBUTES = new Set([
  'token',
  'manufacturer',
  'serial',
  'model',
  'library-manufacturer',
  'library-description',
  'library-version',
  'object',
  'type',
  'id',
  'slot-description',
  'slot-manufacturer',
  'slot-id',
  // Not strictly path attributes in RFC 7512, but accepted here so an
  // author who puts a PIN on the path still gets the security finding rather
  // than a less helpful syntax finding.
  'pin-source',
  'pin-value',
]);

const QUERY_ATTRIBUTES = new Set(['pin-source', 'pin-value', 'module-name', 'module-path']);

export interface Pkcs11Attribute {
  /** Lower-cased attribute name. */
  name: string;
  /** Percent-decoded value. */
  value: string;
  /** Raw text after `=`, before percent-decoding. */
  rawValue: string;
}

export interface ParsedPkcs11Uri {
  raw: string;
  path: Pkcs11Attribute[];
  query: Pkcs11Attribute[];
  /** Convenience lookup across both components; later duplicates are ignored. */
  attributes: Record<string, string>;
  /** True when a `pin-value` attribute is present (in either component). */
  embeddedPin: boolean;
  pinValue?: string;
  pinSource?: string;
}

export type Pkcs11ParseResult = { ok: true; uri: ParsedPkcs11Uri } | { ok: false; reason: string };

/** True for anything whose scheme is `pkcs11:` (case-insensitive). */
export function isPkcs11Uri(value: unknown): value is string {
  return typeof value === 'string' && /^pkcs11:/i.test(value.trim());
}

/** A URI is usable as a key pointer when it parses without a syntax problem. */
export function isValidPkcs11Uri(value: unknown): boolean {
  const result = parsePkcs11Uri(value);
  return result.ok;
}

function decodeComponent(value: string): string | undefined {
  try {
    // `decodeURIComponent` rejects truncated or non-hex escapes, which is the
    // strictness RFC 7512 requires.
    return decodeURIComponent(value);
  } catch {
    return undefined;
  }
}

function parseAttributes(
  source: string,
  separator: string,
  allowed: Set<string>,
): { attributes: Pkcs11Attribute[]; problem?: string } {
  const attributes: Pkcs11Attribute[] = [];
  if (source === '') return { attributes };

  const seen = new Set<string>();
  for (const part of source.split(separator)) {
    if (part === '') return { attributes, problem: 'contains an empty attribute segment' };
    const equals = part.indexOf('=');
    if (equals <= 0) {
      return { attributes, problem: `attribute segment "${part}" has no name or value` };
    }
    const rawName = part.slice(0, equals);
    const rawValue = part.slice(equals + 1);
    const name = rawName.toLowerCase();
    if (!/^[a-z][a-z0-9-]*$/.test(name)) {
      return { attributes, problem: `attribute name "${rawName}" is not a valid token` };
    }
    if (!allowed.has(name)) {
      return { attributes, problem: `unknown PKCS#11 attribute "${rawName}"` };
    }
    if (seen.has(name)) {
      return { attributes, problem: `duplicate PKCS#11 attribute "${rawName}"` };
    }
    seen.add(name);

    const value = decodeComponent(rawValue);
    if (value === undefined) {
      return { attributes, problem: `attribute "${rawName}" has malformed percent-encoding` };
    }
    attributes.push({ name, value, rawValue });
  }
  return { attributes };
}

/** Parses a PKCS#11 URI, returning a reason on malformed input. */
export function parsePkcs11Uri(value: unknown): Pkcs11ParseResult {
  if (typeof value !== 'string') {
    return { ok: false, reason: 'PKCS#11 URI must be a string' };
  }
  const raw = value.trim();
  const prefix = /^pkcs11:/i.exec(raw);
  if (prefix === null || prefix[0] === undefined) {
    return { ok: false, reason: 'URI must start with pkcs11:' };
  }

  const body = raw.slice(prefix[0].length);
  const question = body.indexOf('?');
  const pathSource = question === -1 ? body : body.slice(0, question);
  const querySource = question === -1 ? '' : body.slice(question + 1);

  const path = parseAttributes(pathSource, ';', PATH_ATTRIBUTES);
  if (path.problem !== undefined) return { ok: false, reason: path.problem };
  const query = parseAttributes(querySource, '&', QUERY_ATTRIBUTES);
  if (query.problem !== undefined) return { ok: false, reason: query.problem };

  const attributes: Record<string, string> = {};
  for (const attribute of [...path.attributes, ...query.attributes]) {
    if (attributes[attribute.name] === undefined) attributes[attribute.name] = attribute.value;
  }

  const pin = [...path.attributes, ...query.attributes].find(
    (attribute) => attribute.name === 'pin-value',
  );
  const pinSource = attributes['pin-source'];

  // A key URI with no identifying attribute is syntactically valid but names
  // no particular key; treat it as malformed configuration.
  const identifiers = ['token', 'object', 'id', 'slot-id', 'serial', 'model'];
  if (!identifiers.some((name) => attributes[name] !== undefined && attributes[name] !== '')) {
    return {
      ok: false,
      reason: 'URI must name a key or token using token, object, id, slot-id, serial, or model',
    };
  }

  return {
    ok: true,
    uri: {
      raw,
      path: path.attributes,
      query: query.attributes,
      attributes,
      embeddedPin: pin !== undefined,
      ...(pin === undefined ? {} : { pinValue: pin.value }),
      ...(pinSource === undefined ? {} : { pinSource }),
    },
  };
}

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules: RuleOverrides | undefined,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

export interface Pkcs11ValidatorOptions {
  rules?: RuleOverrides;
  /** Dotted path reported on the diagnostic. */
  path?: string;
}

/**
 * Validates one URI and returns its findings.
 *
 * A compliant URI produces `[]`. A malformed URI emits
 * `crypto/malformed-pkcs11-uri`; any URI carrying `pin-value` emits
 * `crypto/insecure-embedded-pkcs11-pin`, including one that is otherwise
 * syntactically valid.
 */
export function validatePkcs11Uri(
  value: unknown,
  options: Pkcs11ValidatorOptions = {},
): Diagnostic[] {
  const diagnostics: Diagnostic[] = [];
  const path = options.path;
  const parsed = parsePkcs11Uri(value);

  if (!parsed.ok) {
    const severity = severityFor(MALFORMED_PKCS11_URI_RULE, 'error', options.rules);
    if (severity !== undefined) {
      diagnostics.push({
        rule: MALFORMED_PKCS11_URI_RULE,
        severity,
        category: 'general',
        message: `${path === undefined ? 'PKCS#11 URI' : path} is malformed: ${parsed.reason}`,
        ...(path === undefined ? {} : { path }),
        suggestion:
          'Use an RFC 7512 URI such as pkcs11:token=stellar;object=signing-key (percent-encode special characters).',
      });
    }
  }

  // Even a malformed URI can leak a PIN, so inspect the raw text too.
  if (isPkcs11Uri(value) && hasEmbeddedPinValue(value as string)) {
    const severity = severityFor(INSECURE_EMBEDDED_PKCS11_PIN_RULE, 'error', options.rules);
    if (severity !== undefined) {
      diagnostics.push({
        rule: INSECURE_EMBEDDED_PKCS11_PIN_RULE,
        severity,
        category: 'general',
        message: `${path === undefined ? 'PKCS#11 URI' : path} embeds a plaintext PIN in pin-value, exposing the HSM credential in stellar.toml, shell history, and logs`,
        ...(path === undefined ? {} : { path }),
        suggestion:
          'Remove pin-value and use pin-source=file:/run/secrets/hsm-pin or supply the PIN through the HSM client environment.',
      });
    }
  }

  return diagnostics;
}

function hasEmbeddedPinValue(value: string): boolean {
  const body = value.replace(/^pkcs11:/i, '');
  return /(?:^|[;&?])pin-value=[^;&]*/i.test(body);
}

export const auditPkcs11Uri = validatePkcs11Uri;
export const checkPkcs11Uri = validatePkcs11Uri;
export const pkcs11Diagnostics = validatePkcs11Uri;
export const validatePkcs11 = validatePkcs11Uri;
export const parsePkcs11 = parsePkcs11Uri;
export const auditPkcs11 = validatePkcs11Uri;

function walkStrings(
  value: unknown,
  path: string,
  visit: (value: string, path: string) => void,
): void {
  if (typeof value === 'string') {
    visit(value, path);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((entry, index) => walkStrings(entry, `${path}[${index}]`, visit));
    return;
  }
  if (typeof value !== 'object' || value === null) return;
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    walkStrings(entry, path === '' ? key : `${path}.${key}`, visit);
  }
}

/**
 * Finds every PKCS#11 URI anywhere in a document and validates it.
 *
 * The recursive walk catches `SIGNING_KEY`, `URI_REQUEST_SIGNING_KEY`,
 * currency issuer fields, and vendor extensions without hard-coding a list of
 * places an enterprise might store a vault pointer.
 */
export function checkPkcs11Pointers(
  doc: Record<string, unknown>,
  options: Pkcs11ValidatorOptions = {},
): Diagnostic[] {
  const diagnostics: Diagnostic[] = [];
  walkStrings(doc, '', (value, path) => {
    if (!isPkcs11Uri(value)) return;
    diagnostics.push(...validatePkcs11Uri(value, { ...options, path }));
  });
  return diagnostics;
}

export const checkPkcs11Uris = checkPkcs11Pointers;
export const auditPkcs11Pointers = checkPkcs11Pointers;

interface Pkcs11Pointer {
  value: string;
  path: string;
}

/**
 * The fields that may legitimately carry a vault pointer. Scanning only these
 * keeps both rules under the per-rule latency budget on large documents; the
 * public {@link checkPkcs11Pointers} still offers a full recursive scan.
 */
const TOP_LEVEL_POINTER_FIELDS = ['SIGNING_KEY', 'URI_REQUEST_SIGNING_KEY'] as const;
const CURRENCY_POINTER_FIELDS = ['issuer', 'signing_key', 'key'] as const;

const pointerCache = new WeakMap<object, Pkcs11Pointer[]>();

function pointersOf(doc: Record<string, unknown>): Pkcs11Pointer[] {
  const cached = pointerCache.get(doc);
  if (cached !== undefined) return cached;

  const pointers: Pkcs11Pointer[] = [];
  for (const field of TOP_LEVEL_POINTER_FIELDS) {
    const value = doc[field];
    if (isString(value) && isPkcs11Uri(value)) pointers.push({ value, path: field });
  }

  const accounts = doc.ACCOUNTS;
  if (Array.isArray(accounts)) {
    accounts.forEach((account, index) => {
      if (isString(account) && isPkcs11Uri(account)) {
        pointers.push({ value: account, path: `ACCOUNTS[${index}]` });
      }
    });
  }

  const currencies = doc.CURRENCIES;
  if (Array.isArray(currencies)) {
    currencies.forEach((raw, index) => {
      if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return;
      const entry = raw as Record<string, unknown>;
      for (const field of CURRENCY_POINTER_FIELDS) {
        const value = entry[field];
        if (isString(value) && isPkcs11Uri(value)) {
          pointers.push({ value, path: `CURRENCIES[${index}].${field}` });
        }
      }
    });
  }

  pointerCache.set(doc, pointers);
  return pointers;
}

function checkRulePointers(
  doc: Record<string, unknown>,
  options: Pkcs11ValidatorOptions,
): Diagnostic[] {
  const diagnostics: Diagnostic[] = [];
  for (const pointer of pointersOf(doc)) {
    diagnostics.push(...validatePkcs11Uri(pointer.value, { ...options, path: pointer.path }));
  }
  return diagnostics;
}

/** Rule objects registered for `--list-rules` and severity overrides. */
export const pkcs11ValidatorRules: Rule[] = [
  {
    id: MALFORMED_PKCS11_URI_RULE,
    category: 'general',
    severity: 'error',
    description: 'PKCS#11 key URIs must follow RFC 7512 syntax and name a key or token',
    run(ctx: RuleContext) {
      for (const diagnostic of checkRulePointers(ctx.doc, { rules: ctx.options.rules })) {
        if (diagnostic.rule === MALFORMED_PKCS11_URI_RULE) ctx.report(diagnostic);
      }
    },
  },
  {
    id: INSECURE_EMBEDDED_PKCS11_PIN_RULE,
    category: 'general',
    severity: 'error',
    description: 'PKCS#11 URIs must not embed a plaintext PIN in pin-value',
    run(ctx: RuleContext) {
      for (const diagnostic of checkRulePointers(ctx.doc, { rules: ctx.options.rules })) {
        if (diagnostic.rule === INSECURE_EMBEDDED_PKCS11_PIN_RULE) ctx.report(diagnostic);
      }
    },
  },
];

export const pkcs11Rules = pkcs11ValidatorRules;
export const pkcs11ValidatorRuleIds: readonly string[] = pkcs11ValidatorRules.map(
  (rule) => rule.id,
);
