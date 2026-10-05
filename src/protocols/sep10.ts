/**
 * Interactive SEP-10 Stellar Web Authentication challenge verification engine.
 *
 * Runs under opt-in `--check-network --verify-sep10`.
 *
 * SEP-1 anchors declare `WEB_AUTH_ENDPOINT`. Static rules can only check the
 * URL shape; this engine performs the real challenge-response handshake:
 *
 *   1. GET `<endpoint>?account=<client_pub>&home_domain=<domain>&client_domain=<domain>`
 *   2. Parse the returned challenge transaction XDR.
 *   3. Verify the challenge structure and the server's signature.
 *   4. Sign the challenge with an ephemeral client keypair and POST it back.
 *   5. Validate the returned JWT payload claims.
 *
 * Every failure is reported as a targeted {@link Diagnostic}. Network errors
 * are not findings - only spec violations are.
 */

import { Keypair, StrKey, TransactionBuilder } from '@stellar/stellar-base';
import type { Transaction } from '@stellar/stellar-base';
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';

export const INVALID_SOURCE_RULE = 'sep10/invalid-source-account';
export const INVALID_SEQUENCE_RULE = 'sep10/invalid-sequence-number';
export const EXPIRED_TIMEBOUNDS_RULE = 'sep10/expired-or-missing-timebounds';
export const INVALID_SERVER_SIGNATURE_RULE = 'sep10/invalid-server-signature';
export const MISSING_CLIENT_DOMAIN_RULE = 'sep10/missing-client-domain-operation';
export const CHALLENGE_SUBMISSION_FAILED_RULE = 'sep10/challenge-submission-failed';

/** Maximum accepted challenge lifetime, in seconds (SEP-10 recommends short windows). */
const MAX_CHALLENGE_WINDOW_SECONDS = 60 * 60;
/** A JWT must not already be expired when returned. */
const JWT_FUTURE_SKEW_SECONDS = 60;

export interface Sep10Options {
  rules?: RuleOverrides;
  fetchImpl?: typeof fetch;
  networkPassphrase?: string;
  /** Value of the `home_domain` query parameter (usually the anchor domain). */
  homeDomain?: string;
  /** SEP-10 v3 client domain, when the caller wants client attribution. */
  clientDomain?: string;
  /** Override the ephemeral client keypair (tests). */
  clientKeypair?: Keypair;
  /** Override "now" (seconds) for deterministic time checks (tests). */
  nowSeconds?: number;
}

function severityForRule(
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
): void {
  const effective = severityForRule(rule, severity, rules);
  if (effective === undefined) return;
  diagnostics.push({ rule, severity: effective, category: 'network', message, suggestion });
}

function nowSeconds(options: Sep10Options): number {
  return options.nowSeconds ?? Math.floor(Date.now() / 1000);
}

/** Verify the server signed `tx` with the key identified by `serverSigningKey`. */
function hasValidServerSignature(tx: Transaction, serverSigningKey: string): boolean {
  let hint: Buffer;
  let serverKeypair: Keypair;
  try {
    hint = StrKey.decodeEd25519PublicKey(serverSigningKey).slice(-4);
    serverKeypair = Keypair.fromPublicKey(serverSigningKey);
  } catch {
    return false;
  }
  const hash = tx.hash();
  for (const signature of tx.signatures) {
    if (signature.hint().equals(hint) && serverKeypair.verify(hash, signature.signature())) {
      return true;
    }
  }
  return false;
}

/** Decode a JWT payload (base64url middle segment) without verifying its signature. */
function decodeJwtPayload(token: string): Record<string, unknown> | undefined {
  const parts = token.split('.');
  if (parts.length !== 3 || !parts[1]) return undefined;
  try {
    const json = Buffer.from(parts[1], 'base64url').toString('utf8');
    const parsed = JSON.parse(json);
    return typeof parsed === 'object' && parsed !== null
      ? (parsed as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Execute a full SEP-10 handshake against `webAuthEndpoint` and return any
 * spec violations. A conformant server yields an empty array.
 */
export async function verifySep10(
  webAuthEndpoint: string,
  serverSigningKey: string,
  options: Sep10Options = {},
): Promise<Diagnostic[]> {
  const diagnostics: Diagnostic[] = [];
  const fetchImpl = options.fetchImpl ?? fetch;
  const passphrase = options.networkPassphrase ?? 'Public Global Stellar Network ; September 2015';
  const clientKeypair = options.clientKeypair ?? Keypair.random();
  const homeDomain = options.homeDomain ?? '';

  // 1. Request the challenge transaction.
  const params = new URLSearchParams({ account: clientKeypair.publicKey() });
  if (homeDomain) params.set('home_domain', homeDomain);
  if (options.clientDomain) params.set('client_domain', options.clientDomain);

  let challengeXdr: string;
  let challengePassphrase: string;
  try {
    const response = await fetchImpl(`${webAuthEndpoint}?${params.toString()}`, {
      headers: { accept: 'application/json' },
    });
    if (!response.ok) return diagnostics;
    const body = (await response.json()) as {
      transaction?: string;
      network_passphrase?: string;
    };
    if (!body.transaction) return diagnostics;
    challengeXdr = body.transaction;
    challengePassphrase = body.network_passphrase ?? passphrase;
  } catch {
    // A network error is not a SEP-10 violation.
    return diagnostics;
  }

  // 2. Parse the challenge.
  let tx: Transaction;
  try {
    tx = TransactionBuilder.fromXDR(challengeXdr, challengePassphrase) as Transaction;
  } catch {
    push(
      diagnostics,
      CHALLENGE_SUBMISSION_FAILED_RULE,
      'error',
      'SEP-10 challenge transaction could not be parsed as XDR',
      'Ensure WEB_AUTH_ENDPOINT returns a valid base64 transaction envelope.',
      options.rules,
    );
    return diagnostics;
  }

  const now = nowSeconds(options);

  // 3a. Source account must be the declared server signing key.
  if (tx.source !== serverSigningKey) {
    push(
      diagnostics,
      INVALID_SOURCE_RULE,
      'error',
      'SEP-10 challenge source account does not match the declared SIGNING_KEY',
      'The challenge transaction must be sourced from the account in stellar.toml SIGNING_KEY.',
      options.rules,
    );
  }

  // 3b. Sequence number must be the literal string "0".
  if (tx.sequence !== '0') {
    push(
      diagnostics,
      INVALID_SEQUENCE_RULE,
      'error',
      'SEP-10 challenge sequence number must be "0"',
      'Build the challenge from an account with sequence "0" so it can never be submitted.',
      options.rules,
    );
  }

  // 3c. Timebounds must be present and enclose "now".
  const bounds = tx.timeBounds;
  const minTime = bounds ? Number(bounds.minTime) : NaN;
  const maxTime = bounds ? Number(bounds.maxTime) : NaN;
  const missing = !bounds || Number.isNaN(minTime) || Number.isNaN(maxTime);
  const notYetValid = !missing && now < minTime;
  const expired = !missing && now > maxTime;
  const tooLong = !missing && maxTime - minTime > MAX_CHALLENGE_WINDOW_SECONDS;
  if (missing || notYetValid || expired || tooLong) {
    push(
      diagnostics,
      EXPIRED_TIMEBOUNDS_RULE,
      'error',
      'SEP-10 challenge timebounds are missing, expired, not yet valid, or too long',
      'Set finite timebounds (min_time <= now <= max_time) with a short validity window.',
      options.rules,
    );
  }

  // 3d. The server must have signed the challenge.
  if (!hasValidServerSignature(tx, serverSigningKey)) {
    push(
      diagnostics,
      INVALID_SERVER_SIGNATURE_RULE,
      'error',
      'SEP-10 challenge is not signed by the declared SIGNING_KEY',
      'Sign the challenge transaction with the account in stellar.toml SIGNING_KEY.',
      options.rules,
    );
  }

  // 3e. First operation must be `<home_domain> auth` manageData.
  const firstOp = tx.operations[0];
  const expectedName = homeDomain ? `${homeDomain} auth` : undefined;
  const expectedNameLength = expectedName ? Buffer.byteLength(expectedName, 'utf8') : undefined;
  const isManageData =
    firstOp !== undefined && (firstOp as { type?: string }).type === 'manageData';
  const opName = isManageData ? (firstOp as { name?: string }).name : undefined;
  const nameMatches =
    expectedName !== undefined
      ? opName === expectedName
      : opName !== undefined && opName.endsWith(' auth');
  // `TransactionBuilder` truncates long operation names to <= 64 bytes; a
  // longer `home_domain` cannot round-trip and is itself a spec problem.
  const nameOverlong = expectedNameLength !== undefined && expectedNameLength > 64;
  if (!isManageData || !nameMatches || nameOverlong) {
    push(
      diagnostics,
      MISSING_CLIENT_DOMAIN_RULE,
      'warning',
      'SEP-10 challenge is missing the expected `<home_domain> auth` manageData operation',
      'The first operation must be a manageData with name "<home_domain> auth".',
      options.rules,
    );
  }

  // 3f. SEP-10 v3 client domain attribution.
  if (options.clientDomain) {
    const hasClientDomain = tx.operations.some(
      (op) =>
        (op as { type?: string }).type === 'manageData' &&
        (op as { name?: string }).name === 'client_domain',
    );
    if (!hasClientDomain) {
      push(
        diagnostics,
        MISSING_CLIENT_DOMAIN_RULE,
        'warning',
        'SEP-10 v3 challenge is missing the `client_domain` manageData operation',
        'When client_domain is sent, the challenge must include a client_domain manageData entry.',
        options.rules,
      );
    }
  }

  // 4. Sign and submit the challenge.
  const signed = TransactionBuilder.fromXDR(challengeXdr, challengePassphrase) as Transaction;
  signed.sign(clientKeypair);

  let token: string | undefined;
  try {
    const response = await fetchImpl(webAuthEndpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ transaction: signed.toXDR() }),
    });
    if (!response.ok) {
      push(
        diagnostics,
        CHALLENGE_SUBMISSION_FAILED_RULE,
        'error',
        `SEP-10 challenge submission failed with HTTP ${response.status}`,
        'A signed challenge must be accepted with HTTP 200 and a token.',
        options.rules,
      );
      return diagnostics;
    }
    const body = (await response.json()) as { token?: string };
    token = body.token;
  } catch {
    return diagnostics;
  }

  if (!token) {
    push(
      diagnostics,
      CHALLENGE_SUBMISSION_FAILED_RULE,
      'error',
      'SEP-10 response did not include a token',
      'On success, POST must return HTTP 200 with `{ "token": "<jwt>" }`.',
      options.rules,
    );
    return diagnostics;
  }

  // 5. Validate JWT payload claims.
  const payload = decodeJwtPayload(token);
  const claimsOk =
    payload !== undefined &&
    typeof payload.iss === 'string' &&
    typeof payload.sub === 'string' &&
    typeof payload.iat === 'number' &&
    typeof payload.exp === 'number' &&
    payload.exp > now - JWT_FUTURE_SKEW_SECONDS;
  if (!claimsOk) {
    push(
      diagnostics,
      CHALLENGE_SUBMISSION_FAILED_RULE,
      'error',
      'SEP-10 token is not a JWT with valid iss/sub/iat/exp claims',
      'Return a JWT whose payload includes iss, sub, iat, and a future exp.',
      options.rules,
    );
  }

  return diagnostics;
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const sep10Rules: Rule[] = [
  {
    id: INVALID_SOURCE_RULE,
    category: 'network',
    severity: 'error',
    description: 'SEP-10 challenge source account must match SIGNING_KEY',
    run() {},
  },
  {
    id: INVALID_SEQUENCE_RULE,
    category: 'network',
    severity: 'error',
    description: 'SEP-10 challenge sequence number must be "0"',
    run() {},
  },
  {
    id: EXPIRED_TIMEBOUNDS_RULE,
    category: 'network',
    severity: 'error',
    description: 'SEP-10 challenge timebounds must be present and valid',
    run() {},
  },
  {
    id: INVALID_SERVER_SIGNATURE_RULE,
    category: 'network',
    severity: 'error',
    description: 'SEP-10 challenge must be signed by SIGNING_KEY',
    run() {},
  },
  {
    id: MISSING_CLIENT_DOMAIN_RULE,
    category: 'network',
    severity: 'warning',
    description: 'SEP-10 challenge must include the home_domain auth / client_domain operations',
    run() {},
  },
  {
    id: CHALLENGE_SUBMISSION_FAILED_RULE,
    category: 'network',
    severity: 'error',
    description: 'SEP-10 challenge submission must return a valid JWT',
    run() {},
  },
];

/** Rule ids emitted by {@link verifySep10}. */
export const sep10RuleIds: readonly string[] = sep10Rules.map((rule) => rule.id);
