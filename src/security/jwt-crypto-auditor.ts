import type { JsonWebKey } from 'node:crypto';
import { StrKey } from '@stellar/stellar-base';
import { ed25519 } from '@noble/curves/ed25519';
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';

export const INSECURE_JWT_ALGORITHM_RULE = 'security/insecure-jwt-algorithm';
export const JWT_SIGNATURE_VERIFICATION_FAILED_RULE = 'security/jwt-signature-verification-failed';

const JWT_SPEC_URL =
  'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0010.md';

const SAFE_ALGORITHMS = new Set(['ed25519', 'EdDSA', 'RS256']);
const SYMMETRIC_ALGORITHMS = new Set(['HS256', 'HS384', 'HS512']);
const INSECURE_ALGORITHMS = new Set(['none', 'None', 'NONE']);

export interface JwtHeader {
  alg?: unknown;
  typ?: unknown;
  kid?: unknown;
  [key: string]: unknown;
}

export interface JwtPayload {
  iss?: unknown;
  sub?: unknown;
  iat?: unknown;
  exp?: unknown;
  [key: string]: unknown;
}

export interface ParsedJwt {
  header: JwtHeader;
  payload: JwtPayload;
  signature: Uint8Array;
  signingInput: string;
}

export interface JwtJwk extends Record<string, unknown> {
  kty?: string;
  kid?: string;
  alg?: string;
  crv?: string;
  x?: string;
  n?: string;
  e?: string;
}

export interface JwtCryptoAuditorOptions {
  rules?: RuleOverrides;
  signingKey?: string;
  jwks?: readonly JwtJwk[];
  jwksUri?: string;
  fetchImpl?: typeof fetch;
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

function push(
  diagnostics: Diagnostic[],
  rule: string,
  severity: 'error' | 'warning',
  message: string,
  suggestion: string,
  rules?: RuleOverrides,
  path?: string,
): void {
  const effective = severityFor(rule, severity, rules);
  if (effective === undefined) return;
  diagnostics.push({
    rule,
    severity: effective,
    category: 'network',
    message,
    ...(path === undefined ? {} : { path }),
    helpUri: JWT_SPEC_URL,
    suggestion,
  });
}

export function decodeBase64Url(value: string): Uint8Array | undefined {
  if (value.length === 0) return undefined;
  if (!/^[A-Za-z0-9_-]+={0,2}$/.test(value)) return undefined;
  try {
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
    return Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
  } catch {
    return undefined;
  }
}

function decodeJson<T>(bytes: Uint8Array): T | undefined {
  try {
    const parsed: unknown = JSON.parse(new TextDecoder().decode(bytes));
    return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
      ? (parsed as T)
      : undefined;
  } catch {
    return undefined;
  }
}

/** Parses the three JWT segments without trusting or verifying any of them. */
export function parseJwt(token: string): ParsedJwt | undefined {
  const parts = token.split('.');
  if (parts.length !== 3) return undefined;
  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  if (!encodedHeader || !encodedPayload || encodedSignature === undefined) return undefined;

  const headerBytes = decodeBase64Url(encodedHeader);
  const payloadBytes = decodeBase64Url(encodedPayload);
  const signature = encodedSignature === '' ? new Uint8Array() : decodeBase64Url(encodedSignature);
  if (headerBytes === undefined || payloadBytes === undefined || signature === undefined) {
    return undefined;
  }

  const header = decodeJson<JwtHeader>(headerBytes);
  const payload = decodeJson<JwtPayload>(payloadBytes);
  if (header === undefined || payload === undefined) return undefined;

  return {
    header,
    payload,
    signature,
    signingInput: `${encodedHeader}.${encodedPayload}`,
  };
}

function algorithmHeaderProblem(header: JwtHeader): string | undefined {
  if (typeof header.alg !== 'string' || header.alg.length === 0) {
    return 'the JWT header has no algorithm (alg)';
  }
  if (INSECURE_ALGORITHMS.has(header.alg) || header.alg.toLowerCase() === 'none') {
    return `the JWT uses the insecure "none" algorithm`;
  }
  if (SYMMETRIC_ALGORITHMS.has(header.alg)) {
    return `the JWT uses the symmetric ${header.alg} algorithm, which can be forged if the shared secret leaks`;
  }
  if (!SAFE_ALGORITHMS.has(header.alg)) {
    return `the JWT uses unsupported algorithm "${header.alg}"`;
  }
  return undefined;
}

function verifyEdDsaWithSigningKey(
  parsed: ParsedJwt,
  signingKey: string | undefined,
): boolean | undefined {
  if (signingKey === undefined || signingKey.length === 0) return undefined;
  if (!StrKey.isValidEd25519PublicKey(signingKey)) return undefined;
  if (parsed.signature.length !== 64) return false;
  try {
    return ed25519.verify(
      parsed.signature,
      new TextEncoder().encode(parsed.signingInput),
      StrKey.decodeEd25519PublicKey(signingKey),
    );
  } catch {
    return false;
  }
}

function verifyEdDsaWithJwks(parsed: ParsedJwt, jwks: readonly JwtJwk[]): boolean | undefined {
  const candidates = jwks.filter((jwk) => {
    if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') return false;
    if (typeof parsed.header.kid === 'string' && typeof jwk.kid === 'string') {
      return jwk.kid === parsed.header.kid;
    }
    return true;
  });
  if (candidates.length === 0) return undefined;
  if (parsed.signature.length !== 64) return false;

  for (const jwk of candidates) {
    const publicKey = decodeBase64Url(jwk.x as string);
    if (publicKey === undefined || publicKey.length !== 32) continue;
    try {
      if (
        ed25519.verify(parsed.signature, new TextEncoder().encode(parsed.signingInput), publicKey)
      ) {
        return true;
      }
    } catch {
      continue;
    }
  }
  return false;
}

async function verifyRs256(
  parsed: ParsedJwt,
  jwks: readonly JwtJwk[],
): Promise<boolean | undefined> {
  const candidates = jwks.filter((jwk) => {
    if (jwk.kty !== 'RSA' || typeof jwk.n !== 'string' || typeof jwk.e !== 'string') return false;
    if (typeof parsed.header.kid === 'string' && typeof jwk.kid === 'string') {
      return jwk.kid === parsed.header.kid;
    }
    return true;
  });
  if (candidates.length === 0) return undefined;

  const { createPublicKey, verify } = await import('node:crypto');
  const message = Buffer.from(parsed.signingInput);
  for (const jwk of candidates) {
    try {
      const key = createPublicKey({
        key: jwk as JsonWebKey,
        format: 'jwk',
      });
      if (verify('RSA-SHA256', message, key, parsed.signature)) return true;
    } catch {
      continue;
    }
  }
  return false;
}

async function fetchJwks(uri: string, fetchImpl: typeof fetch): Promise<JwtJwk[]> {
  try {
    const response = await fetchImpl(uri, { headers: { accept: 'application/json' } });
    if (!response.ok) return [];
    const body = (await response.json()) as unknown;
    const keys =
      typeof body === 'object' && body !== null && !Array.isArray(body)
        ? (body as { keys?: unknown }).keys
        : body;
    if (!Array.isArray(keys)) return [];
    return keys.filter(
      (key): key is JwtJwk => typeof key === 'object' && key !== null && !Array.isArray(key),
    );
  } catch {
    return [];
  }
}

/**
 * Audits the header algorithm and signature of a SEP-10 JWT.
 *
 * Verification uses the declared Stellar `SIGNING_KEY` for EdDSA tokens, and
 * either the supplied JWKS or `jwksUri` for RS256 tokens. Tokens with a
 * disallowed algorithm are reported without attempting a signature check,
 * because there is no safe way to verify them.
 */
export async function auditJwtCrypto(
  token: string,
  optionsOrSigningKey: JwtCryptoAuditorOptions | string = {},
  extraOptions: JwtCryptoAuditorOptions = {},
): Promise<Diagnostic[]> {
  const options =
    typeof optionsOrSigningKey === 'string'
      ? { ...extraOptions, signingKey: optionsOrSigningKey }
      : optionsOrSigningKey;
  const diagnostics: Diagnostic[] = [];

  const parsed = parseJwt(token);
  if (parsed === undefined) {
    push(
      diagnostics,
      JWT_SIGNATURE_VERIFICATION_FAILED_RULE,
      'error',
      'SEP-10 token is not a well-formed three-segment JWT',
      'Return a JWT with base64url-encoded header, payload, and signature segments.',
      options.rules,
    );
    return diagnostics;
  }

  const headerProblem = algorithmHeaderProblem(parsed.header);
  if (headerProblem !== undefined) {
    push(
      diagnostics,
      INSECURE_JWT_ALGORITHM_RULE,
      'error',
      `SEP-10 JWT algorithm is insecure: ${headerProblem}`,
      'Sign SEP-10 tokens with EdDSA (Ed25519) or RS256; never accept "none" or HMAC algorithms with a shared secret.',
      options.rules,
    );
    return diagnostics;
  }

  const alg = parsed.header.alg as string;
  let jwks = options.jwks;
  if (jwks === undefined && options.jwksUri !== undefined) {
    jwks = await fetchJwks(options.jwksUri, options.fetchImpl ?? fetch);
  }

  let verified: boolean | undefined;
  if (alg === 'ed25519' || alg === 'EdDSA') {
    verified = verifyEdDsaWithSigningKey(parsed, options.signingKey);
    if (verified === undefined && jwks !== undefined) {
      verified = verifyEdDsaWithJwks(parsed, jwks);
    }
  } else {
    verified = jwks === undefined ? undefined : await verifyRs256(parsed, jwks);
  }

  if (verified === false) {
    push(
      diagnostics,
      JWT_SIGNATURE_VERIFICATION_FAILED_RULE,
      'error',
      `SEP-10 JWT signature does not verify with the declared ${alg} key`,
      alg === 'RS256'
        ? 'Publish the signing key in the JWKS referenced by the auth server and reissue the token with the matching private key.'
        : 'Sign the SEP-10 token with the private key for SIGNING_KEY, and ensure the token header and payload are not modified in transit.',
      options.rules,
    );
  }

  return diagnostics;
}

export const verifyJwtCrypto = auditJwtCrypto;
export const checkJwtCrypto = auditJwtCrypto;

/** Rule objects for `--list-rules` and severity overrides. */
export const jwtCryptoAuditorRules: Rule[] = [
  {
    id: INSECURE_JWT_ALGORITHM_RULE,
    category: 'network',
    severity: 'error',
    description: 'SEP-10 JWTs must use EdDSA or RS256, never none or HMAC algorithms',
    run() {},
  },
  {
    id: JWT_SIGNATURE_VERIFICATION_FAILED_RULE,
    category: 'network',
    severity: 'error',
    description: 'SEP-10 JWT signatures must verify against SIGNING_KEY or published JWKS',
    run() {},
  },
];

export const jwtCryptoRuleIds: readonly string[] = jwtCryptoAuditorRules.map((rule) => rule.id);
