/**
 * SEP-10 JWT claim and client-domain binding auditor.
 *
 * Runs under opt-in `--audit-sep10-jwt` with tokens supplied by the caller.
 *
 * A SEP-10 JWT is the session credential wallets hand to SEP-6, SEP-24, SEP-31
 * and SEP-38 services. The anchor that issued it must bind it to its own
 * domain (`iss`), the authenticated account (`sub`), a bounded lifetime
 * (`iat`/`exp`), and — when client-domain authentication was used — the domain
 * whose signing key authorised the challenge (`client_domain`). A token with
 * `alg: none`, a missing expiry, a foreign issuer, or an unverifiable client
 * domain is a replay or impersonation risk, not a formatting nit.
 *
 * Decoding is pure TypeScript with no JWT dependency. Signature *algorithms*
 * are enforced; the signature itself is not re-verified here because the
 * anchor's signing key is not part of `stellar.toml`.
 */

import { StrKey } from '@stellar/stellar-base';
import { parse as parseToml } from 'smol-toml';
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isString } from '../predicates.js';
import { fetchWithTimeout, isRecord, severityFor } from './verifierSupport.js';

const MALFORMED_RULE = 'sep10/malformed-jwt';
const ALGORITHM_RULE = 'sep10/unsafe-jwt-algorithm';
const MISSING_CLAIM_RULE = 'sep10/missing-jwt-claim';
const ISSUER_RULE = 'sep10/jwt-issuer-mismatch';
const EXPIRED_RULE = 'sep10/expired-jwt';
const SUBJECT_RULE = 'sep10/invalid-jwt-subject';
const LIFETIME_RULE = 'sep10/excessive-jwt-lifetime';
const CLIENT_DOMAIN_RULE = 'sep10/unbound-client-domain';
const UNVERIFIABLE_RULE = 'sep10/jwt-unverifiable';

const SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0010.md';

/** Signature algorithms SEP-10 services are expected to accept. */
export const SEP10_ALLOWED_ALGORITHMS = ['EdDSA', 'Ed25519', 'ES256', 'RS256'] as const;

/** Default maximum token lifetime: 24 hours. */
export const DEFAULT_MAX_JWT_LIFETIME_SECONDS = 24 * 60 * 60;

/** The client-domain claim is a bare DNS name. */
const DOMAIN_PATTERN = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$/i;

export interface Sep10JwtOptions {
  rules?: RuleOverrides;
  /** Tokens to inspect. The CLI feeds these from `--sep10-token`. */
  tokens?: readonly string[];
  /** Anchor domain the tokens must be issued for (`iss`). */
  expectedDomain?: string;
  /** Account that signed the client-domain challenge, for TXT/toml binding. */
  clientSigner?: string;
  /** Fetch the client domain's stellar.toml to bind the signer. Defaults to true. */
  checkClientDomain?: boolean;
  /** Longest acceptable `exp - iat`. Defaults to 24h. */
  maxLifetimeSeconds?: number;
  /** Injectable clock for tests. */
  now?: Date;
  timeoutMs?: number;
}

export interface DecodedJwt {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: string;
}

export interface Sep10JwtAuditResult {
  diagnostics: Diagnostic[];
  tokens: DecodedJwt[];
  summary: string;
}

/** Decodes a compact JWS without verifying it. `undefined` when malformed. */
export function decodeJwt(token: string): DecodedJwt | undefined {
  const parts = token.split('.');
  if (parts.length !== 3) return undefined;
  const [encodedHeader, encodedPayload, signature] = parts as [string, string, string];
  try {
    const header: unknown = JSON.parse(Buffer.from(encodedHeader, 'base64url').toString('utf8'));
    const payload: unknown = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
    if (!isRecord(header) || !isRecord(payload)) return undefined;
    return { header, payload, signature };
  } catch {
    return undefined;
  }
}

function normalizeDomain(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/:\d+$/, '');
}

/** True for a classic `G...` account or a muxed `M...` account. */
export function isValidSep10Subject(subject: string): boolean {
  return StrKey.isValidEd25519PublicKey(subject) || StrKey.isValidMed25519PublicKey(subject);
}

export class Sep10JwtAuditor {
  constructor(
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly options: Sep10JwtOptions = {},
  ) {}

  async verify(doc: Record<string, unknown>): Promise<Sep10JwtAuditResult> {
    const tokens = this.options.tokens ?? [];
    if (tokens.length === 0) {
      return {
        diagnostics: this.finding(
          UNVERIFIABLE_RULE,
          'info',
          'No SEP-10 JWT supplied, so claim, expiry and client-domain bindings cannot be audited',
          'WEB_AUTH_ENDPOINT',
          'Obtain a token from POST /auth and pass it with --sep10-token <jwt>.',
        ),
        tokens: [],
        summary: 'No tokens supplied.',
      };
    }

    const expectedDomain =
      this.options.expectedDomain ??
      (isString(doc.WEB_AUTH_ENDPOINT) ? new URL(doc.WEB_AUTH_ENDPOINT).hostname : undefined);
    const now = this.options.now ?? new Date();
    const maxLifetime = this.options.maxLifetimeSeconds ?? DEFAULT_MAX_JWT_LIFETIME_SECONDS;
    const diagnostics: Diagnostic[] = [];
    const decoded: DecodedJwt[] = [];

    for (const token of tokens) {
      const jwt = decodeJwt(token);
      if (jwt === undefined) {
        diagnostics.push(
          ...this.finding(
            MALFORMED_RULE,
            'error',
            'Token is not a compact three-part JWT with decodable header and payload',
            'WEB_AUTH_ENDPOINT',
            'Issue a standard JWS from POST /auth; a wallet cannot read claims from a malformed token.',
          ),
        );
        continue;
      }
      decoded.push(jwt);
      diagnostics.push(...this.assessClaims(jwt, expectedDomain, now, maxLifetime));
      diagnostics.push(...(await this.assessClientDomain(jwt)));
    }

    return {
      diagnostics,
      tokens: decoded,
      summary: `${decoded.length} of ${tokens.length} SEP-10 tokens decoded and audited.`,
    };
  }

  private assessClaims(
    jwt: DecodedJwt,
    expectedDomain: string | undefined,
    now: Date,
    maxLifetime: number,
  ): Diagnostic[] {
    const diagnostics: Diagnostic[] = [];
    const { header, payload } = jwt;

    const alg = header.alg;
    if (!isString(alg) || !(SEP10_ALLOWED_ALGORITHMS as readonly string[]).includes(alg)) {
      diagnostics.push(
        ...this.finding(
          ALGORITHM_RULE,
          'error',
          `JWT uses the disallowed signature algorithm "${String(alg)}"`,
          'WEB_AUTH_ENDPOINT',
          'Sign SEP-10 tokens with EdDSA (Ed25519), ES256 or RS256; never accept "none" or shared-secret algorithms.',
        ),
      );
    }

    for (const claim of ['iss', 'sub', 'iat', 'exp']) {
      if (payload[claim] === undefined) {
        diagnostics.push(
          ...this.finding(
            MISSING_CLAIM_RULE,
            'error',
            `JWT is missing the required "${claim}" claim`,
            'WEB_AUTH_ENDPOINT',
            'Include iss, sub, iat and exp so wallets can scope, attribute and expire the session.',
          ),
        );
      }
    }

    if (isString(payload.iss) && expectedDomain !== undefined) {
      if (normalizeDomain(payload.iss) !== normalizeDomain(expectedDomain)) {
        diagnostics.push(
          ...this.finding(
            ISSUER_RULE,
            'error',
            `JWT iss "${payload.iss}" does not match the anchor domain "${normalizeDomain(expectedDomain)}"`,
            'WEB_AUTH_ENDPOINT',
            'Issue tokens with iss set to the anchor domain that served POST /auth.',
          ),
        );
      }
    }

    if (isString(payload.sub) && !isValidSep10Subject(payload.sub)) {
      diagnostics.push(
        ...this.finding(
          SUBJECT_RULE,
          'error',
          `JWT sub "${payload.sub}" is not a valid Stellar account or muxed account`,
          'WEB_AUTH_ENDPOINT',
          'Bind the token to the authenticated G... or M... account in sub.',
        ),
      );
    }

    const iat = typeof payload.iat === 'number' ? payload.iat : undefined;
    const exp = typeof payload.exp === 'number' ? payload.exp : undefined;
    const nowSeconds = Math.floor(now.getTime() / 1000);
    if (exp !== undefined && exp <= nowSeconds) {
      diagnostics.push(
        ...this.finding(
          EXPIRED_RULE,
          'error',
          `JWT expired at ${new Date(exp * 1000).toISOString()}`,
          'WEB_AUTH_ENDPOINT',
          'Reject expired tokens; do not extend exp to keep a session alive.',
        ),
      );
    }
    if (iat !== undefined && exp !== undefined) {
      if (exp - iat > maxLifetime) {
        diagnostics.push(
          ...this.finding(
            LIFETIME_RULE,
            'warning',
            `JWT lifetime is ${Math.round((exp - iat) / 3600)}h, beyond the ${Math.round(maxLifetime / 3600)}h limit`,
            'WEB_AUTH_ENDPOINT',
            'Shorten exp; long-lived bearer tokens widen the replay window if one leaks.',
          ),
        );
      }
      if (exp < iat) {
        diagnostics.push(
          ...this.finding(
            MALFORMED_RULE,
            'error',
            'JWT exp is earlier than iat',
            'WEB_AUTH_ENDPOINT',
            'Issue a token whose expiry follows its issue time.',
          ),
        );
      }
    }
    if (iat !== undefined && iat > nowSeconds + 300) {
      diagnostics.push(
        ...this.finding(
          MALFORMED_RULE,
          'warning',
          `JWT iat is ${iat - nowSeconds}s in the future`,
          'WEB_AUTH_ENDPOINT',
          'Stamp tokens with the current time so a clock-skewing client cannot extend the session.',
        ),
      );
    }
    return diagnostics;
  }

  private async assessClientDomain(jwt: DecodedJwt): Promise<Diagnostic[]> {
    const payload = jwt.payload;
    const domain = payload.client_domain;
    if (domain === undefined) return [];

    if (!isString(domain) || !DOMAIN_PATTERN.test(domain) || domain.includes('/')) {
      return this.finding(
        CLIENT_DOMAIN_RULE,
        'error',
        `JWT client_domain "${String(domain)}" is not a bare DNS name`,
        'WEB_AUTH_ENDPOINT',
        'Set client_domain to the client’s hostname without a scheme, path or port.',
      );
    }

    if (this.options.checkClientDomain === false || this.options.clientSigner === undefined) {
      return [];
    }

    const url = `https://${domain}/.well-known/stellar.toml`;
    try {
      const response = await fetchWithTimeout(this.fetchImpl, url, {}, this.options.timeoutMs);
      if (!response.ok) {
        return this.finding(
          UNVERIFIABLE_RULE,
          'info',
          `client_domain ${domain} stellar.toml returned HTTP ${response.status}`,
          'WEB_AUTH_ENDPOINT',
          'Publish stellar.toml for the client domain so its signing key can be bound to the token.',
        );
      }
      const toml = parseToml(await response.text()) as Record<string, unknown>;
      const signers = [
        ...(isString(toml.SIGNING_KEY) ? [toml.SIGNING_KEY] : []),
        ...(Array.isArray(toml.ACCOUNTS)
          ? toml.ACCOUNTS.filter((account): account is string => isString(account))
          : []),
      ];
      if (!signers.includes(this.options.clientSigner)) {
        return this.finding(
          CLIENT_DOMAIN_RULE,
          'error',
          `client_domain ${domain} does not declare the client signer ${this.options.clientSigner} in SIGNING_KEY or ACCOUNTS`,
          'WEB_AUTH_ENDPOINT',
          'Publish the signing account in the client domain’s stellar.toml and verify it before trusting the client_domain claim.',
        );
      }
    } catch {
      return this.finding(
        UNVERIFIABLE_RULE,
        'info',
        `client_domain ${domain} could not be fetched to bind the client signer`,
        'WEB_AUTH_ENDPOINT',
        'Make the client domain’s stellar.toml reachable over HTTPS.',
      );
    }
    return [];
  }

  private finding(
    rule: string,
    fallback: 'error' | 'warning' | 'info',
    message: string,
    path: string,
    suggestion: string,
  ): Diagnostic[] {
    const severity = severityFor(rule, fallback, this.options.rules);
    if (severity === undefined) return [];
    return [{ rule, severity, category: 'network', message, path, helpUri: SPEC, suggestion }];
  }
}

export async function auditSep10Jwt(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: Sep10JwtOptions = {},
): Promise<Sep10JwtAuditResult> {
  return new Sep10JwtAuditor(fetchImpl, options).verify(doc);
}

const def = (id: string, severity: 'error' | 'warning' | 'info', description: string): Rule => ({
  id,
  category: 'network',
  severity,
  description,
  run() {},
});

export const sep10JwtRules: Rule[] = [
  def(MALFORMED_RULE, 'error', 'SEP-10 tokens must be well-formed with coherent claims'),
  def(ALGORITHM_RULE, 'error', 'SEP-10 tokens must use an approved signature algorithm'),
  def(MISSING_CLAIM_RULE, 'error', 'SEP-10 tokens must include iss, sub, iat and exp'),
  def(ISSUER_RULE, 'error', 'SEP-10 iss must match the anchor domain'),
  def(EXPIRED_RULE, 'error', 'SEP-10 tokens must not be expired'),
  def(SUBJECT_RULE, 'error', 'SEP-10 sub must be a Stellar account'),
  def(LIFETIME_RULE, 'warning', 'SEP-10 tokens should have a bounded lifetime'),
  def(CLIENT_DOMAIN_RULE, 'error', 'SEP-10 client_domain must resolve to the client signer'),
  def(UNVERIFIABLE_RULE, 'info', 'SEP-10 token bindings should be verifiable'),
];

export const sep10JwtRuleIds: readonly string[] = sep10JwtRules.map((rule) => rule.id);
