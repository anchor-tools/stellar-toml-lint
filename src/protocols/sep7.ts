/**
 * SEP-7 URI Scheme Parser and Cryptographic Signature Verifier.
 *
 * SEP-7 defines URI schemes (web+stellar:pay, web+stellar:tx) for payment
 * requests and transaction signing across Stellar wallets. Anchors publish
 * SEP-7 URIs in documentation and currency descriptions.
 *
 * This module parses web+stellar: URIs, validates operation parameters,
 * decodes replacement variables, and cryptographically verifies URI signatures
 * against the anchor's SIGNING_KEY.
 */

import { StrKey, Keypair } from '@stellar/stellar-base';
import { ed25519 } from '@noble/curves/ed25519';
import type { Diagnostic, Rule, RuleOverrides, RuleContext } from '../types.js';
import { isString } from '../predicates.js';

export const INVALID_URI_SCHEME_RULE = 'sep7/invalid-uri-scheme';
export const INVALID_SIGNATURE_RULE = 'sep7/invalid-signature';
export const UNSUPPORTED_REPLACEMENT_FIELD_RULE = 'sep7/unsupported-replacement-field';

const SEP7_SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0007.md';

const PAY_REPLACEMENT_FIELDS = new Set([
  'destination',
  'amount',
  'asset_code',
  'asset_issuer',
  'memo',
  'memo_type',
  'callback',
  'msg',
  'network_passphrase',
  'origin_domain',
]);

const TX_REPLACEMENT_FIELDS = new Set([
  'xdr',
  'callback',
  'pubkey',
  'msg',
  'network_passphrase',
  'origin_domain',
]);

const VALID_MEMO_TYPES = new Set(['MEMO_TEXT', 'MEMO_ID', 'MEMO_HASH', 'MEMO_RETURN']);

export interface Sep7Options {
  rules?: RuleOverrides;
  signingKey?: string;
  path?: string;
}

export interface ParsedSep7Uri {
  scheme: string;
  operation: 'pay' | 'tx' | string;
  params: Record<string, string>;
  signature?: string;
  uriWithoutSignature: string;
  raw: string;
}

function severityFor(
  rule: string,
  fallback: 'error' | 'warning',
  rules?: RuleOverrides,
): 'error' | 'warning' | undefined {
  const override = rules?.[rule];
  if (override === 'off') return undefined;
  return override === 'error' || override === 'warning' ? override : fallback;
}

function decodeBase64(value: string): Uint8Array | undefined {
  const trimmed = value.trim();
  if (trimmed.length === 0) return undefined;
  try {
    const binary = atob(trimmed);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch {
    return undefined;
  }
}

/**
 * Strips the signature parameter from the URI for verification.
 */
export function removeSignatureFromUri(uri: string): { uriWithoutSig: string; signature?: string } {
  const sigMatch = /(?:([?&])signature=([^&]*))/.exec(uri);
  if (!sigMatch) {
    return { uriWithoutSig: uri, signature: undefined };
  }

  const signature = decodeURIComponent(sigMatch[2] ?? '');
  let uriWithoutSig = uri.replace(/(?:[?&])signature=[^&]*/, '');
  if (uriWithoutSig.includes('?') === false && uriWithoutSig.includes('&')) {
    uriWithoutSig = uriWithoutSig.replace('&', '?');
  }
  return { uriWithoutSig, signature };
}

/**
 * Parses a SEP-7 URI string.
 */
export function parseSep7Uri(uri: string): ParsedSep7Uri | null {
  const match = /^web\+stellar:(?:\/\/)?([a-z0-9_-]+)(?:\?(.*))?$/i.exec(uri.trim());
  if (!match) return null;

  const operation = match[1]!.toLowerCase();
  const queryString = match[2] ?? '';
  const params: Record<string, string> = {};

  if (queryString) {
    const pairs = queryString.split('&');
    for (const pair of pairs) {
      if (!pair) continue;
      const [key, ...rest] = pair.split('=');
      if (key) {
        params[decodeURIComponent(key)] = decodeURIComponent(rest.join('='));
      }
    }
  }

  const { uriWithoutSig, signature } = removeSignatureFromUri(uri);

  return {
    scheme: 'web+stellar',
    operation,
    params,
    signature: signature ?? params.signature,
    uriWithoutSignature: uriWithoutSig,
    raw: uri,
  };
}

/**
 * Builds SEP-7 signature payload variants.
 */
function buildPayloads(uriWithoutSig: string): Uint8Array[] {
  const enc = new TextEncoder();
  const uriBytes = enc.encode(uriWithoutSig);
  const sep7PrefixWithNull = enc.encode('stellar.sep.7 - URI Scheme\0');
  const sep7Prefix = enc.encode('stellar.sep.7 - URI Scheme');

  const p1 = new Uint8Array(36 + sep7PrefixWithNull.length + uriBytes.length);
  p1.fill(0, 0, 35);
  p1[35] = 4;
  p1.set(sep7PrefixWithNull, 36);
  p1.set(uriBytes, 36 + sep7PrefixWithNull.length);

  const p2 = new Uint8Array(36 + sep7PrefixWithNull.length + uriBytes.length);
  p2.fill(0, 0, 36);
  p2.set(sep7PrefixWithNull, 36);
  p2.set(uriBytes, 36 + sep7PrefixWithNull.length);

  const p3 = new Uint8Array(sep7PrefixWithNull.length + uriBytes.length);
  p3.set(sep7PrefixWithNull, 0);
  p3.set(uriBytes, sep7PrefixWithNull.length);

  const p4 = new Uint8Array(sep7Prefix.length + uriBytes.length);
  p4.set(sep7Prefix, 0);
  p4.set(uriBytes, sep7Prefix.length);

  return [p1, p2, p3, p4, uriBytes];
}

/**
 * Cryptographically verifies an Ed25519 signature on a SEP-7 URI against a public key.
 */
export function verifySep7Signature(uri: string, signingKey: string): boolean {
  if (!StrKey.isValidEd25519PublicKey(signingKey)) return false;

  const { uriWithoutSig, signature } = removeSignatureFromUri(uri);
  if (!signature) return false;

  const sigBytes = decodeBase64(signature);
  if (!sigBytes || sigBytes.length !== 64) return false;

  let publicKeyBytes: Uint8Array;
  try {
    publicKeyBytes = new Uint8Array(StrKey.decodeEd25519PublicKey(signingKey));
  } catch {
    return false;
  }

  const payloads = buildPayloads(uriWithoutSig);
  for (const payload of payloads) {
    try {
      if (ed25519.verify(sigBytes, payload, publicKeyBytes)) {
        return true;
      }
    } catch {
      // Continue trying payload variants
    }
  }

  return false;
}

/**
 * Cryptographically signs a SEP-7 URI with an anchor's secret key.
 */
export function signSep7Uri(uri: string, secretKey: string): string {
  const keypair = Keypair.fromSecret(secretKey);
  const { uriWithoutSig } = removeSignatureFromUri(uri);

  const enc = new TextEncoder();
  const uriBytes = enc.encode(uriWithoutSig);
  const sep7PrefixWithNull = enc.encode('stellar.sep.7 - URI Scheme\0');

  const payload = new Uint8Array(36 + sep7PrefixWithNull.length + uriBytes.length);
  payload.fill(0, 0, 35);
  payload[35] = 4;
  payload.set(sep7PrefixWithNull, 36);
  payload.set(uriBytes, 36 + sep7PrefixWithNull.length);

  const sigBytes = ed25519.sign(payload, keypair.rawSecretKey());
  const b64Sig = btoa(String.fromCharCode(...sigBytes));

  const separator = uriWithoutSig.includes('?') ? '&' : '?';
  return `${uriWithoutSig}${separator}signature=${encodeURIComponent(b64Sig)}`;
}

/**
 * Validates a SEP-7 URI string and returns diagnostics.
 */
export function validateSep7Uri(uri: string, options: Sep7Options = {}): Diagnostic[] {
  const diagnostics: Diagnostic[] = [];
  const path = options.path ?? 'URI';

  if (!uri.startsWith('web+stellar:')) {
    const sev = severityFor(INVALID_URI_SCHEME_RULE, 'error', options.rules);
    if (sev) {
      diagnostics.push({
        rule: INVALID_URI_SCHEME_RULE,
        severity: sev,
        category: 'general',
        message: `URI "${uri}" is not a valid SEP-7 web+stellar: link`,
        path,
        helpUri: SEP7_SPEC,
        suggestion: 'SEP-7 URIs must begin with "web+stellar:".',
      });
    }
    return diagnostics;
  }

  const parsed = parseSep7Uri(uri);
  if (!parsed) {
    const sev = severityFor(INVALID_URI_SCHEME_RULE, 'error', options.rules);
    if (sev) {
      diagnostics.push({
        rule: INVALID_URI_SCHEME_RULE,
        severity: sev,
        category: 'general',
        message: `Could not parse SEP-7 URI: ${uri}`,
        path,
        helpUri: SEP7_SPEC,
        suggestion: 'Format the URI as web+stellar:<operation>?<parameters>.',
      });
    }
    return diagnostics;
  }

  const { operation, params, signature } = parsed;

  if (operation !== 'pay' && operation !== 'tx') {
    const sev = severityFor(INVALID_URI_SCHEME_RULE, 'error', options.rules);
    if (sev) {
      diagnostics.push({
        rule: INVALID_URI_SCHEME_RULE,
        severity: sev,
        category: 'general',
        message: `Unsupported SEP-7 operation "${operation}". Expected "pay" or "tx".`,
        path,
        helpUri: SEP7_SPEC,
        suggestion: 'Use either web+stellar:pay or web+stellar:tx.',
      });
    }
    return diagnostics;
  }

  if (operation === 'pay') {
    if (params.destination) {
      const dest = params.destination;
      const isG = StrKey.isValidEd25519PublicKey(dest);
      const isM = StrKey.isValidMed25519PublicKey(dest);
      const isFed = /^[a-zA-Z0-9._+-]+[*][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(dest);
      if (!isG && !isM && !isFed) {
        const sev = severityFor(INVALID_URI_SCHEME_RULE, 'error', options.rules);
        if (sev) {
          diagnostics.push({
            rule: INVALID_URI_SCHEME_RULE,
            severity: sev,
            category: 'general',
            message: `Invalid recipient account in destination parameter: "${dest}"`,
            path,
            helpUri: SEP7_SPEC,
            suggestion:
              'Use a valid Stellar G... public key, M... muxed account, or federated address.',
          });
        }
      }
    }

    if (params.asset_code) {
      const code = params.asset_code;
      if (code !== 'native' && !/^[a-zA-Z0-9]{1,12}$/.test(code)) {
        const sev = severityFor(INVALID_URI_SCHEME_RULE, 'error', options.rules);
        if (sev) {
          diagnostics.push({
            rule: INVALID_URI_SCHEME_RULE,
            severity: sev,
            category: 'general',
            message: `Invalid asset_code in SEP-7 pay URI: "${code}"`,
            path,
            helpUri: SEP7_SPEC,
            suggestion: 'Asset codes must be 1-12 alphanumeric characters or "native".',
          });
        }
      }
    }

    if (params.asset_issuer) {
      if (!StrKey.isValidEd25519PublicKey(params.asset_issuer)) {
        const sev = severityFor(INVALID_URI_SCHEME_RULE, 'error', options.rules);
        if (sev) {
          diagnostics.push({
            rule: INVALID_URI_SCHEME_RULE,
            severity: sev,
            category: 'general',
            message: `Invalid asset_issuer in SEP-7 pay URI: "${params.asset_issuer}"`,
            path,
            helpUri: SEP7_SPEC,
            suggestion: 'asset_issuer must be a valid Stellar public key.',
          });
        }
      }
    }

    if (params.memo_type) {
      if (!VALID_MEMO_TYPES.has(params.memo_type)) {
        const sev = severityFor(INVALID_URI_SCHEME_RULE, 'error', options.rules);
        if (sev) {
          diagnostics.push({
            rule: INVALID_URI_SCHEME_RULE,
            severity: sev,
            category: 'general',
            message: `Invalid memo_type in SEP-7 pay URI: "${params.memo_type}"`,
            path,
            helpUri: SEP7_SPEC,
            suggestion: 'memo_type must be MEMO_TEXT, MEMO_ID, MEMO_HASH, or MEMO_RETURN.',
          });
        }
      }
    }

    if (params.replace) {
      const entries = params.replace.split(/[;,]/);
      for (const entry of entries) {
        if (!entry.trim()) continue;
        const [field] = entry.split(':');
        const cleanField = field?.trim();
        if (cleanField && !PAY_REPLACEMENT_FIELDS.has(cleanField)) {
          const sev = severityFor(UNSUPPORTED_REPLACEMENT_FIELD_RULE, 'warning', options.rules);
          if (sev) {
            diagnostics.push({
              rule: UNSUPPORTED_REPLACEMENT_FIELD_RULE,
              severity: sev,
              category: 'general',
              message: `Unsupported replacement field "${cleanField}" in SEP-7 pay URI`,
              path,
              helpUri: SEP7_SPEC,
              suggestion: `Supported pay replacement fields: ${Array.from(PAY_REPLACEMENT_FIELDS).join(', ')}.`,
            });
          }
        }
      }
    }
  }

  if (operation === 'tx') {
    if (!params.xdr) {
      const sev = severityFor(INVALID_URI_SCHEME_RULE, 'error', options.rules);
      if (sev) {
        diagnostics.push({
          rule: INVALID_URI_SCHEME_RULE,
          severity: sev,
          category: 'general',
          message: 'Missing required xdr parameter in SEP-7 tx URI',
          path,
          helpUri: SEP7_SPEC,
          suggestion: 'Include a base64-encoded transaction envelope XDR in the xdr parameter.',
        });
      }
    }

    if (params.replace) {
      const entries = params.replace.split(/[;,]/);
      for (const entry of entries) {
        if (!entry.trim()) continue;
        const [field] = entry.split(':');
        const cleanField = field?.trim();
        if (cleanField && !TX_REPLACEMENT_FIELDS.has(cleanField)) {
          const sev = severityFor(UNSUPPORTED_REPLACEMENT_FIELD_RULE, 'warning', options.rules);
          if (sev) {
            diagnostics.push({
              rule: UNSUPPORTED_REPLACEMENT_FIELD_RULE,
              severity: sev,
              category: 'general',
              message: `Unsupported replacement field "${cleanField}" in SEP-7 tx URI`,
              path,
              helpUri: SEP7_SPEC,
              suggestion: `Supported tx replacement fields: ${Array.from(TX_REPLACEMENT_FIELDS).join(', ')}.`,
            });
          }
        }
      }
    }
  }

  // Cryptographic signature verification
  if (signature) {
    const signingKey = options.signingKey;
    if (signingKey) {
      const valid = verifySep7Signature(uri, signingKey);
      if (!valid) {
        const sev = severityFor(INVALID_SIGNATURE_RULE, 'error', options.rules);
        if (sev) {
          diagnostics.push({
            rule: INVALID_SIGNATURE_RULE,
            severity: sev,
            category: 'general',
            message: `SEP-7 URI signature verification failed against SIGNING_KEY (${signingKey})`,
            path,
            helpUri: SEP7_SPEC,
            suggestion: 'Sign the SEP-7 URI using the secret key corresponding to SIGNING_KEY.',
          });
        }
      }
    }
  }

  return diagnostics;
}

/**
 * Extracts and checks SEP-7 URIs published in stellar.toml documentation and currency entries.
 */
export function checkSep7Uris(
  doc: Record<string, unknown>,
  options: Sep7Options = {},
): Diagnostic[] {
  const diagnostics: Diagnostic[] = [];
  const signingKey = isString(doc.SIGNING_KEY) ? doc.SIGNING_KEY : options.signingKey;

  function findUris(value: unknown, path: string) {
    if (isString(value)) {
      const matches = value.match(/web\+stellar:[^\s"'<>)]+/g);
      if (matches) {
        for (const uri of matches) {
          diagnostics.push(...validateSep7Uri(uri, { ...options, signingKey, path }));
        }
      }
    } else if (Array.isArray(value)) {
      value.forEach((item, i) => findUris(item, `${path}[${i}]`));
    } else if (typeof value === 'object' && value !== null) {
      for (const [k, v] of Object.entries(value)) {
        findUris(v, path ? `${path}.${k}` : k);
      }
    }
  }

  findUris(doc, '');
  return diagnostics;
}

/** Registered rules for SEP-7 */
export const sep7Rules: Rule[] = [
  {
    id: INVALID_URI_SCHEME_RULE,
    category: 'general',
    severity: 'error',
    description: 'SEP-7 URI scheme, operation, and parameters must be valid',
    run(ctx: RuleContext) {
      const diags = checkSep7Uris(ctx.doc, { rules: ctx.options.rules });
      for (const d of diags) {
        if (d.rule === INVALID_URI_SCHEME_RULE) {
          ctx.report(d);
        }
      }
    },
  },
  {
    id: INVALID_SIGNATURE_RULE,
    category: 'general',
    severity: 'error',
    description: 'SEP-7 URI cryptographic signature must verify against SIGNING_KEY',
    run(ctx: RuleContext) {
      const diags = checkSep7Uris(ctx.doc, { rules: ctx.options.rules });
      for (const d of diags) {
        if (d.rule === INVALID_SIGNATURE_RULE) {
          ctx.report(d);
        }
      }
    },
  },
  {
    id: UNSUPPORTED_REPLACEMENT_FIELD_RULE,
    category: 'general',
    severity: 'warning',
    description: 'SEP-7 replace parameter should only reference supported fields',
    run(ctx: RuleContext) {
      const diags = checkSep7Uris(ctx.doc, { rules: ctx.options.rules });
      for (const d of diags) {
        if (d.rule === UNSUPPORTED_REPLACEMENT_FIELD_RULE) {
          ctx.report(d);
        }
      }
    },
  },
];

export const sep7RuleIds: readonly string[] = sep7Rules.map((rule) => rule.id);
