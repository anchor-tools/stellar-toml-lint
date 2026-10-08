/**
 * Cross-Server Security Token Binding Auditor.
 *
 * Runs under opt-in --check-network --audit-security.
 *
 * Production anchors run distributed microservices for authentication (SEP-10),
 * deposit/withdrawal (SEP-24), quotes (SEP-38), and direct payments (SEP-31).
 * This auditor acquires a valid SEP-10 JWT from WEB_AUTH_ENDPOINT and verifies
 * that downstream service endpoints (TRANSFER_SERVER_SEP0024, KYC_SERVER,
 * DIRECT_PAYMENT_SERVER) accept the token and that domain binding (iss claim) matches.
 */

import { Keypair, Networks, TransactionBuilder } from '@stellar/stellar-base';
import type { Diagnostic, RuleOverrides } from '../types.js';
import { hostOf, isString, isUrl } from '../predicates.js';

export const JWT_REJECTED_RULE = 'security/jwt-rejected-by-transfer-server';
export const JWT_DOMAIN_MISMATCH_RULE = 'security/jwt-domain-mismatch';

const SEP10_SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0010.md';

export interface TokenBindingOptions {
  rules?: RuleOverrides;
  domain?: string;
  clientKeypair?: Keypair;
  networkPassphrase?: string;
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

function decodeBase64Url(str: string): string {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  try {
    return atob(base64);
  } catch {
    return '';
  }
}

interface JwtPayload {
  iss?: string;
  sub?: string;
  exp?: number;
  iat?: number;
  [key: string]: unknown;
}

export function parseJwtPayload(token: string): JwtPayload | null {
  const parts = token.split('.');
  if (parts.length < 2 || !parts[1]) return null;
  try {
    const jsonStr = decodeBase64Url(parts[1]);
    return JSON.parse(jsonStr) as JwtPayload;
  } catch {
    return null;
  }
}

/**
 * Executes the SEP-10 challenge flow to acquire a JWT token.
 */
export async function acquireSep10Token(
  webAuthEndpoint: string,
  fetchImpl: typeof fetch,
  options: TokenBindingOptions = {},
): Promise<string | null> {
  const clientKeypair = options.clientKeypair ?? Keypair.random();
  const publicKey = clientKeypair.publicKey();
  const base = webAuthEndpoint.replace(/\/+$/, '');
  const url = new URL(base.startsWith('http') ? base : `https://${base}`);
  url.searchParams.set('account', publicKey);
  if (options.domain) {
    url.searchParams.set('home_domain', options.domain);
  }

  let challengeRes: Response;
  try {
    challengeRes = await fetchImpl(url.toString(), { redirect: 'follow' });
  } catch {
    return null;
  }

  if (!challengeRes.ok) return null;

  let challengeData: Record<string, unknown>;
  try {
    challengeData = (await challengeRes.json()) as Record<string, unknown>;
  } catch {
    return null;
  }

  // If endpoint directly returns a token
  if (isString(challengeData.token)) return challengeData.token;
  if (isString(challengeData.jwt)) return challengeData.jwt;

  // Handle challenge transaction signing
  const txXdr = challengeData.transaction ?? challengeData.tx;
  if (isString(txXdr)) {
    try {
      const passphrase = options.networkPassphrase ?? Networks.PUBLIC;
      const tx = TransactionBuilder.fromXDR(txXdr, passphrase);
      tx.sign(clientKeypair);
      const signedXdr = tx.toXDR();

      const postRes = await fetchImpl(base, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ transaction: signedXdr }),
      });

      if (!postRes.ok) return null;
      const postData = (await postRes.json()) as Record<string, unknown>;
      if (isString(postData.token)) return postData.token;
      if (isString(postData.jwt)) return postData.jwt;
    } catch {
      return null;
    }
  }

  return null;
}

/**
 * Audits cross-server security token binding between WEB_AUTH_ENDPOINT and downstream services.
 */
export async function checkTokenBinding(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: TokenBindingOptions = {},
): Promise<Diagnostic[]> {
  const webAuth = doc.WEB_AUTH_ENDPOINT;
  if (!isString(webAuth) || !isUrl(webAuth)) return [];

  const diagnostics: Diagnostic[] = [];

  const token = await acquireSep10Token(webAuth, fetchImpl, options);
  if (!token) return [];

  // 1. Validate domain binding between JWT iss and stellar.toml host
  const payload = parseJwtPayload(token);
  if (payload?.iss) {
    const expectedDomain =
      options.domain ??
      (doc.DOCUMENTATION && typeof doc.DOCUMENTATION === 'object'
        ? hostOf((doc.DOCUMENTATION as Record<string, unknown>).ORG_URL)
        : undefined) ??
      hostOf(webAuth);

    const issHost = hostOf(payload.iss) ?? payload.iss.replace(/^https?:\/\//, '').split('/')[0];

    if (
      expectedDomain &&
      issHost &&
      !issHost.endsWith(expectedDomain) &&
      !expectedDomain.endsWith(issHost)
    ) {
      const sev = severityFor(JWT_DOMAIN_MISMATCH_RULE, 'error', options.rules);
      if (sev) {
        diagnostics.push({
          rule: JWT_DOMAIN_MISMATCH_RULE,
          severity: sev,
          category: 'network',
          message: `JWT issuer (iss: "${payload.iss}") does not match expected host domain "${expectedDomain}"`,
          path: 'WEB_AUTH_ENDPOINT',
          helpUri: SEP10_SPEC,
          suggestion:
            'Ensure WEB_AUTH_ENDPOINT issues JWTs with an iss claim matching the anchor home domain.',
        });
      }
    }
  }

  // 2. Test downstream endpoints with the acquired JWT
  const downstreamEndpoints: { name: string; path: string; url: string; testPath: string }[] = [];

  if (isString(doc.TRANSFER_SERVER_SEP0024) && isUrl(doc.TRANSFER_SERVER_SEP0024)) {
    downstreamEndpoints.push({
      name: 'TRANSFER_SERVER_SEP0024',
      path: 'TRANSFER_SERVER_SEP0024',
      url: doc.TRANSFER_SERVER_SEP0024,
      testPath: '/info',
    });
  }

  if (isString(doc.KYC_SERVER) && isUrl(doc.KYC_SERVER)) {
    downstreamEndpoints.push({
      name: 'KYC_SERVER',
      path: 'KYC_SERVER',
      url: doc.KYC_SERVER,
      testPath: '/customer',
    });
  }

  if (isString(doc.DIRECT_PAYMENT_SERVER) && isUrl(doc.DIRECT_PAYMENT_SERVER)) {
    downstreamEndpoints.push({
      name: 'DIRECT_PAYMENT_SERVER',
      path: 'DIRECT_PAYMENT_SERVER',
      url: doc.DIRECT_PAYMENT_SERVER,
      testPath: '/info',
    });
  }

  for (const endpoint of downstreamEndpoints) {
    const base = endpoint.url.replace(/\/+$/, '');
    const targetUrl = `${base}${endpoint.testPath}`;

    try {
      const res = await fetchImpl(targetUrl, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (res.status === 401 || res.status === 403) {
        const sev = severityFor(JWT_REJECTED_RULE, 'error', options.rules);
        if (sev) {
          diagnostics.push({
            rule: JWT_REJECTED_RULE,
            severity: sev,
            category: 'network',
            message: `Downstream service ${endpoint.name} (${targetUrl}) rejected auth token with HTTP ${res.status}`,
            path: endpoint.path,
            helpUri: SEP10_SPEC,
            suggestion: `Ensure ${endpoint.name} shares signing secrets/keys with WEB_AUTH_ENDPOINT and accepts issued tokens.`,
          });
        }
      }
    } catch {
      // Network transport errors are ignored by token binding audit
    }
  }

  return diagnostics;
}
