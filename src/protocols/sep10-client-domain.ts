/**
 * SEP-10 v3 client domain attribution auditor.
 *
 * Runs under opt-in --check-network --verify-sep10.
 *
 * SEP-10 v3 lets a wallet prove its home domain: the client asks
 * `WEB_AUTH_ENDPOINT` for a challenge with a `client_domain` parameter, the
 * anchor resolves `https://<client_domain>/.well-known/stellar.toml`, and the
 * challenge must carry a `manageData` operation named `client_domain` sourced
 * by the signing key that document publishes. The wallet co-signs with the
 * client domain keypair and the anchor records the attribution in the JWT.
 *
 * An anchor that silently drops the parameter authenticates the account but
 * loses the domain binding SEP-11 relies on, so this auditor walks the whole
 * attributed handshake against the live endpoint and reports the two failures
 * that matter: a malformed `client_domain` operation in the envelope, and a
 * token that omits the claim.
 */

import { Keypair, Networks, TransactionBuilder } from '@stellar/stellar-base';
import type { TransactionI } from '@stellar/stellar-base';
import { parse as parseToml } from 'smol-toml';
import type { Diagnostic, Rule, RuleOverrides } from '../types.js';

const MISSING_CLAIM_RULE = 'sep10/missing-client-domain-claim';
const INVALID_OPERATION_RULE = 'sep10/invalid-client-domain-operation';

const SEP10_SPEC = 'https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0010.md';
const CLIENT_DOMAIN_DATA_NAME = 'client_domain';
const CLIENT_DOMAIN_DATA_VALUE = 'auth';
const WELL_KNOWN_TOML_PATH = '/.well-known/stellar.toml';

/** Stand-in home domain for the mock wallet this audit authenticates. */
export const MOCK_CLIENT_DOMAIN = 'client-domain.test';

interface Sep10ClientDomainOptions {
  rules?: RuleOverrides;
  fetchImpl?: typeof fetch;
  networkPassphrase?: string;
  /** Home domain to attribute; defaults to {@link MOCK_CLIENT_DOMAIN}. */
  clientDomain?: string;
  /** Keypair whose public key is hosted at {@link Sep10ClientDomainOptions.clientDomain}. */
  clientDomainKeypair?: Keypair;
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

function finding(
  rule: string,
  fallback: 'error' | 'warning',
  message: string,
  suggestion: string,
  rules: RuleOverrides | undefined,
): Diagnostic[] {
  const severity = severityForRule(rule, fallback, rules);
  if (severity === undefined) return [];
  return [
    {
      rule,
      severity,
      category: 'network',
      message,
      path: 'WEB_AUTH_ENDPOINT',
      helpUri: SEP10_SPEC,
      suggestion,
    },
  ];
}

/**
 * The `stellar.toml` a mock client domain hosts. SEP-10 requires this document
 * to publish the signing key the anchor uses to verify attribution, so callers
 * that stand up a mock domain serve it at the well-known path.
 */
export function buildClientDomainToml(signingKey: string, domain: string): string {
  return [`SIGNING_KEY="${signingKey}"`, `# ${domain}`].join('\n');
}

/** A `manageData` operation read back out of a challenge envelope. */
function manageDataOperations(tx: unknown): { source?: string; name: string; value?: Buffer }[] {
  const operations = (tx as { operations?: unknown[] }).operations ?? [];
  const parsed: { source?: string; name: string; value?: Buffer }[] = [];
  for (const operation of operations) {
    if (typeof operation !== 'object' || operation === null) continue;
    const op = operation as Record<string, unknown>;
    if (op.type !== 'manageData') continue;
    if (typeof op.name !== 'string') continue;
    const raw = op.value;
    parsed.push({
      ...(typeof op.source === 'string' ? { source: op.source } : {}),
      name: op.name,
      ...(raw === undefined ? {} : { value: Buffer.from(raw as Buffer) }),
    });
  }
  return parsed;
}

/**
 * Reads the `client_domain` claim out of the JWT the anchor returns.
 *
 * Only the payload is decoded: this audit proves attribution was recorded, not
 * that the token is cryptographically valid, and the anchor's own signing key
 * is not always derivable from the response.
 */
export function decodeClientDomainClaim(token: string): string | undefined {
  const payload = token.split('.')[1];
  if (!payload) return undefined;
  let body: unknown;
  try {
    body = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  } catch {
    return undefined;
  }
  if (typeof body !== 'object' || body === null || Array.isArray(body)) return undefined;
  const claim = (body as Record<string, unknown>).client_domain;
  return typeof claim === 'string' ? claim : undefined;
}

/**
 * Resolves the signing key the anchor reads at the client domain's well-known
 * path, so the challenge can be checked against the same key the anchor trusts.
 *
 * Falls back to the locally hosted key when the domain publishes nothing — a
 * synthetic wallet domain has no DNS record to resolve in CI.
 */
async function publishedSigningKey(
  domain: string,
  fallback: string,
  fetchImpl: typeof fetch,
): Promise<string> {
  try {
    const response = await fetchImpl(`https://${domain}${WELL_KNOWN_TOML_PATH}`);
    if (!response.ok) return fallback;
    const doc = parseToml(await response.text()) as Record<string, unknown>;
    return typeof doc.SIGNING_KEY === 'string' ? doc.SIGNING_KEY : fallback;
  } catch {
    return fallback;
  }
}

/**
 * Reads a string field out of a JSON response, yielding `''` when the body is
 * not JSON, not an object, or carries the field as some other type — every
 * malformed-envelope case the audit reports the same way.
 */
async function readStringField(response: Response, field: string): Promise<string> {
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    return '';
  }
  if (typeof body !== 'object' || body === null || Array.isArray(body)) return '';
  const value = (body as Record<string, unknown>)[field];
  return typeof value === 'string' ? value : '';
}

/**
 * Walks a SEP-10 v3 attributed authentication against a live anchor and checks
 * that the client domain survives the handshake.
 *
 * A mock wallet account and client domain keypair stand in for the wallet, and
 * {@link buildClientDomainToml} is the document their domain hosts. The audit
 * is silent when the file declares no usable endpoint or signing key, and when
 * the endpoint cannot be reached — a connection failure proves nothing about
 * attribution, and reachability is already reported by the other network rules.
 */
export async function checkSep10ClientDomain(
  signingKey: string,
  webAuthEndpoint: string,
  options: Sep10ClientDomainOptions = {},
): Promise<Diagnostic[]> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const passphrase = options.networkPassphrase ?? Networks.PUBLIC;

  const base = webAuthEndpoint.replace(/\/+$/, '');
  if (base.length === 0 || signingKey.length === 0) return [];

  const clientDomain = options.clientDomain ?? MOCK_CLIENT_DOMAIN;
  const clientDomainKeypair = options.clientDomainKeypair ?? Keypair.random();
  const walletKeypair = Keypair.random();

  const expectedKey = await publishedSigningKey(
    clientDomain,
    clientDomainKeypair.publicKey(),
    fetchImpl,
  );

  let challengeResponse: Response | undefined;
  try {
    const params = new URLSearchParams({
      account: walletKeypair.publicKey(),
      client_domain: clientDomain,
      home_domain: new URL(base).host,
    });
    challengeResponse = await fetchImpl(`${base}?${params.toString()}`);
  } catch {
    challengeResponse = undefined;
  }
  if (challengeResponse === undefined) return [];
  if (!challengeResponse.ok) {
    return finding(
      MISSING_CLAIM_RULE,
      'error',
      `SEP-10 challenge request with client_domain=${clientDomain} was refused with HTTP ${challengeResponse.status}`,
      'Accept the client_domain parameter and build the attributed challenge SEP-10 v3 describes',
      options.rules,
    );
  }
  const challengeXdr = await readStringField(challengeResponse, 'transaction');

  if (challengeXdr.length === 0) {
    return finding(
      INVALID_OPERATION_RULE,
      'error',
      `SEP-10 challenge response from ${base} carries no transaction envelope`,
      'Return the unsigned challenge in the `transaction` field so wallets can sign it',
      options.rules,
    );
  }

  let challenge: TransactionI;
  try {
    challenge = TransactionBuilder.fromXDR(challengeXdr, passphrase);
  } catch {
    return finding(
      INVALID_OPERATION_RULE,
      'error',
      `SEP-10 challenge from ${base} is not a valid transaction envelope for its network passphrase`,
      'Build the challenge with @stellar/stellar-base so the envelope decodes under the advertised network passphrase',
      options.rules,
    );
  }

  const operation = manageDataOperations(challenge).find(
    (op) => op.name === CLIENT_DOMAIN_DATA_NAME,
  );
  if (operation === undefined) {
    return finding(
      MISSING_CLAIM_RULE,
      'error',
      `SEP-10 challenge from ${base} omits the client_domain manageData operation for ${clientDomain}`,
      'Add a manageData operation named `client_domain`, sourced by the key published at the client domain, to the challenge',
      options.rules,
    );
  }
  if (operation.value?.toString('utf8') !== CLIENT_DOMAIN_DATA_VALUE) {
    return finding(
      INVALID_OPERATION_RULE,
      'error',
      `SEP-10 client_domain operation carries "${operation.value?.toString('utf8') ?? ''}" instead of "${CLIENT_DOMAIN_DATA_VALUE}"`,
      'SEP-10 fixes the client_domain manageData value to the string "auth"',
      options.rules,
    );
  }
  if (operation.source !== undefined && operation.source !== expectedKey) {
    return finding(
      INVALID_OPERATION_RULE,
      'error',
      `SEP-10 client_domain operation is sourced by ${operation.source} rather than the ${clientDomain} signing key ${expectedKey}`,
      'Source the client_domain operation with the SIGNING_KEY published at the client domain stellar.toml',
      options.rules,
    );
  }

  // SEP-10 requires both the wallet account and the client domain key to sign
  // an attributed challenge before it can be authenticated.
  challenge.sign(walletKeypair, clientDomainKeypair);
  const signed = challenge.toXDR();

  let authResponse: Response | undefined;
  try {
    authResponse = await fetchImpl(`${base}?${new URLSearchParams({ transaction: signed })}`);
  } catch {
    authResponse = undefined;
  }
  if (authResponse === undefined) return [];
  if (!authResponse.ok) {
    return finding(
      MISSING_CLAIM_RULE,
      'error',
      `Anchor rejected the client-domain-signed challenge at ${base} with HTTP ${authResponse.status}`,
      'Verify the client_domain signature against the key published at the client domain instead of rejecting the challenge',
      options.rules,
    );
  }
  const token = await readStringField(authResponse, 'token');

  if (token.length === 0) {
    return finding(
      MISSING_CLAIM_RULE,
      'error',
      `SEP-10 authenticated challenge for client_domain=${clientDomain} returned no token`,
      'Issue the JWT in the `token` field once the attributed challenge validates',
      options.rules,
    );
  }

  const claim = decodeClientDomainClaim(token);
  if (claim === undefined) {
    return finding(
      MISSING_CLAIM_RULE,
      'error',
      `SEP-10 JWT omits the client_domain claim although the challenge was attributed to ${clientDomain}`,
      'Copy the verified client domain into the `client_domain` claim so downstream SEP-11 checks can attribute the wallet',
      options.rules,
    );
  }
  if (claim !== clientDomain) {
    return finding(
      MISSING_CLAIM_RULE,
      'error',
      `SEP-10 JWT records client_domain="${claim}" instead of the requested "${clientDomain}"`,
      'Embed the client domain the wallet authenticated with, not a cached or defaulted value',
      options.rules,
    );
  }

  return [];
}

/** Registered so `--list-rules` and `--off`/`--warn`/`--error` know these ids. */
export const sep10ClientDomainRules: Rule[] = [
  {
    id: MISSING_CLAIM_RULE,
    category: 'network',
    severity: 'error',
    description: 'SEP-10 v3 anchors must attribute the client domain in the issued JWT',
    run() {},
  },
  {
    id: INVALID_OPERATION_RULE,
    category: 'network',
    severity: 'error',
    description: 'The client_domain manageData operation must be a well-formed SEP-10 envelope',
    run() {},
  },
];

/** Rule ids emitted by {@link checkSep10ClientDomain}. */
export const sep10ClientDomainRuleIds: readonly string[] = sep10ClientDomainRules.map(
  (rule) => rule.id,
);
