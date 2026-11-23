/**
 * SEP-30 recovery server verifier.
 *
 * Runs under opt-in `--audit-sep30-recovery`; the endpoint probes only run
 * with `--check-network`.
 *
 * SEP-30 users split custody across recovery providers. If `stellar.toml`
 * advertises a `RECOVERY_SERVER`, a wallet will register accounts there, so a
 * server that answers account queries without authentication, or a signer set
 * a single provider controls, lets one party recover (take) an account
 * without the user's consent.
 *
 * Probes send no credentials and no body, against a throwaway address, so they
 * can never register or modify a real account.
 */

import type { Diagnostic, Rule, RuleOverrides } from '../types.js';
import { isAccountId, isHttpsUrl, isString } from '../predicates.js';
import { errorMessage, fetchWithTimeout, isRecord, severityFor } from './verifierSupport.js';

const INVALID_SERVER_RULE = 'sep30/invalid-recovery-server';
const INVALID_KEY_RULE = 'sep30/invalid-signing-key';
const QUORUM_RULE = 'sep30/insufficient-recovery-quorum';
const ENDPOINT_RULE = 'sep30/endpoint-unavailable';
const UNAUTH_RULE = 'sep30/unauthenticated-recovery';
const AUTH_METHOD_RULE = 'sep30/unsupported-auth-method';

const SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0030.md';

/** SEP-30 identity auth method types, plus WebAuthn passkeys as used by wallets. */
export const SEP30_AUTH_METHODS: readonly string[] = [
  'stellar_address',
  'phone_number',
  'email',
  'webauthn',
];

/** A valid, never-funded address used so probes cannot touch a real account. */
export const PROBE_ADDRESS = 'GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7';

const METHODS = ['POST', 'GET', 'PUT'] as const;

export interface Sep30Options {
  rules?: RuleOverrides;
  /** Probe the recovery server over HTTP. */
  probe?: boolean;
  timeoutMs?: number;
}

export interface Sep30Result {
  diagnostics: Diagnostic[];
  /** Probed method -> HTTP status (`0` when the request failed). */
  endpoints: Record<string, number>;
  signingKeys: string[];
}

/** Validates the `identities[].auth_methods[].type` values of a SEP-30 account body. */
export function findUnsupportedAuthMethods(body: unknown): string[] {
  if (!isRecord(body) || !Array.isArray(body.identities)) return [];
  const bad: string[] = [];
  for (const identity of body.identities) {
    if (!isRecord(identity) || !Array.isArray(identity.auth_methods)) continue;
    for (const method of identity.auth_methods) {
      const type = isRecord(method) ? method.type : undefined;
      if (!isString(type) || !SEP30_AUTH_METHODS.includes(type)) bad.push(String(type));
    }
  }
  return bad;
}

function signingKeysOf(doc: Record<string, unknown>): { keys: unknown[]; path: string } {
  const plural = doc.RECOVERY_SIGNING_KEYS;
  if (Array.isArray(plural)) return { keys: plural, path: 'RECOVERY_SIGNING_KEYS' };
  const single = doc.RECOVERY_SIGNING_KEY;
  if (single !== undefined) return { keys: [single], path: 'RECOVERY_SIGNING_KEY' };
  return { keys: [], path: 'RECOVERY_SIGNING_KEYS' };
}

export class Sep30RecoveryVerifier {
  constructor(
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly options: Sep30Options = {},
  ) {}

  async verify(doc: Record<string, unknown>): Promise<Sep30Result> {
    const diagnostics: Diagnostic[] = [];
    const endpoints: Record<string, number> = {};
    const push = (
      rule: string,
      fallback: 'error' | 'warning',
      message: string,
      path: string,
      suggestion: string,
    ): void => {
      const severity = severityFor(rule, fallback, this.options.rules);
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

    const server = doc.RECOVERY_SERVER;
    if (server === undefined) return { diagnostics, endpoints, signingKeys: [] };

    const serverOk = isString(server) && isHttpsUrl(server);
    if (!serverOk) {
      push(
        INVALID_SERVER_RULE,
        'error',
        'RECOVERY_SERVER must be an https URL',
        'RECOVERY_SERVER',
        'Publish the SEP-30 recovery server as an https:// URL without a trailing slash.',
      );
    }

    const { keys, path } = signingKeysOf(doc);
    const valid: string[] = [];
    keys.forEach((key, i) => {
      if (!isAccountId(key)) {
        push(
          INVALID_KEY_RULE,
          'error',
          `${path}[${i}] is not a valid Stellar public key`,
          `${path}[${i}]`,
          'Use the G... account each recovery provider signs with.',
        );
      } else valid.push(key as string);
    });
    const distinct = new Set(valid);
    // One distinct signer means one provider can authorise recovery alone,
    // which defeats the point of splitting custody.
    if (distinct.size < 2) {
      push(
        QUORUM_RULE,
        'warning',
        `Recovery uses ${distinct.size} distinct signing key${distinct.size === 1 ? '' : 's'}; a single provider could recover accounts without the user`,
        path,
        'Declare at least two independent recovery signing keys so no single provider can act alone.',
      );
    }

    if (this.options.probe && serverOk) {
      await this.probe((server as string).replace(/\/+$/, ''), push, endpoints);
    }
    return { diagnostics, endpoints, signingKeys: [...distinct] };
  }

  private async probe(
    base: string,
    push: (
      rule: string,
      fallback: 'error' | 'warning',
      message: string,
      path: string,
      suggestion: string,
    ) => void,
    endpoints: Record<string, number>,
  ): Promise<void> {
    const url = `${base}/accounts/${PROBE_ADDRESS}`;
    for (const method of METHODS) {
      let status: number;
      let body: unknown;
      try {
        const res = await fetchWithTimeout(this.fetchImpl, url, { method }, this.options.timeoutMs);
        status = res.status;
        body = await res.json().catch(() => undefined);
      } catch (error) {
        push(
          ENDPOINT_RULE,
          'warning',
          `${method} /accounts/{address} could not be reached (${errorMessage(error)})`,
          'RECOVERY_SERVER',
          'Make sure the recovery server is up and answers within a few seconds.',
        );
        endpoints[method] = 0;
        continue;
      }
      endpoints[method] = status;
      if (status === 404 || status === 405 || status >= 500) {
        // 404 on GET is legitimate for an unregistered address; on POST/PUT it
        // means the route does not exist.
        if (method !== 'GET' || status !== 404) {
          push(
            ENDPOINT_RULE,
            'warning',
            `${method} /accounts/{address} returned HTTP ${status}`,
            'RECOVERY_SERVER',
            'SEP-30 requires POST, GET and PUT on /accounts/{address}.',
          );
        }
      } else if (status >= 200 && status < 300) {
        push(
          UNAUTH_RULE,
          'error',
          `${method} /accounts/{address} succeeded without authentication (HTTP ${status})`,
          'RECOVERY_SERVER',
          'Require a SEP-10 JWT on every /accounts request so recovery needs the user’s consent.',
        );
      }
      for (const type of findUnsupportedAuthMethods(body)) {
        push(
          AUTH_METHOD_RULE,
          'warning',
          `Recovery server reports unsupported auth method "${type}"`,
          'RECOVERY_SERVER',
          `Use only ${SEP30_AUTH_METHODS.join(', ')}.`,
        );
      }
    }
  }
}

export async function auditSep30Recovery(
  doc: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
  options: Sep30Options = {},
): Promise<Sep30Result> {
  return new Sep30RecoveryVerifier(fetchImpl, options).verify(doc);
}

const def = (id: string, description: string): Rule => ({
  id,
  category: 'network',
  severity: 'warning',
  description,
  run() {},
});

export const sep30Rules: Rule[] = [
  def(INVALID_SERVER_RULE, 'RECOVERY_SERVER must be an https URL'),
  def(INVALID_KEY_RULE, 'Recovery signing keys must be valid Stellar public keys'),
  def(QUORUM_RULE, 'Recovery should be split across at least two distinct signing keys'),
  def(ENDPOINT_RULE, 'The recovery server must implement POST, GET and PUT /accounts/{address}'),
  def(UNAUTH_RULE, 'Recovery endpoints must reject unauthenticated requests'),
  def(AUTH_METHOD_RULE, 'Recovery identities may only use SEP-30 auth methods'),
];

export const sep30RuleIds: readonly string[] = sep30Rules.map((r) => r.id);
