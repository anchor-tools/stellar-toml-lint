import { describe, expect, it } from 'vitest';
import { Account, Keypair, Networks, Operation, TransactionBuilder } from '@stellar/stellar-base';
import {
  buildClientDomainToml,
  checkSep10ClientDomain,
  decodeClientDomainClaim,
  sep10ClientDomainRuleIds,
  sep10ClientDomainRules,
} from '../../src/protocols/sep10-client-domain.js';

const WEB_AUTH_ENDPOINT = 'https://api.example.com/auth';
const CLIENT_DOMAIN = 'wallet.example.com';

/** The key the mock client domain publishes at its well-known path. */
const CLIENT_KEYS = Keypair.random();
const SIGNING_KEY = Keypair.random().publicKey();

/** The wallet account the audit authenticates. */
const WALLET = Keypair.random();

interface ChallengeShape {
  /** Omit the client_domain operation entirely. */
  omitOperation?: boolean;
  value?: string;
  source?: string;
}

/** Builds the unsigned challenge envelope a SEP-10 anchor would return. */
function challengeXdr(shape: ChallengeShape = {}): string {
  const builder = new TransactionBuilder(new Account(SIGNING_KEY, '0'), {
    fee: '100',
    networkPassphrase: Networks.PUBLIC,
  }).addOperation(
    Operation.manageData({
      name: 'auth',
      value: Buffer.from('nonce-value'),
      source: SIGNING_KEY,
    }),
  );

  if (shape.omitOperation !== true) {
    builder.addOperation(
      Operation.manageData({
        name: 'client_domain',
        value: Buffer.from(shape.value ?? 'auth'),
        source: shape.source ?? CLIENT_KEYS.publicKey(),
      }),
    );
  }

  return builder.setTimeout(300).build().toXDR();
}

/** A JWT-shaped token whose payload carries whatever the anchor recorded. */
function token(payload: Record<string, unknown>): string {
  const encode = (value: unknown): string =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'HS256', typ: 'JWT' })}.${encode(payload)}.signature`;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

/**
 * Routes the three requests one attributed handshake makes — the client domain
 * document, the challenge, and the authenticated challenge — so a mock anchor
 * can answer each step differently, the way the SEP-38 audits do.
 */
function anchorServer(
  routes: {
    toml?: () => Response;
    challenge?: () => Response;
    authenticate?: () => Response;
  } = {},
): typeof fetch {
  return (async (input: string | URL | Request) => {
    const url = String(input);
    if (url.includes('/.well-known/stellar.toml')) {
      if (routes.toml) return routes.toml();
      return new Response('not found', { status: 404 });
    }
    if (url.includes('transaction=')) {
      if (routes.authenticate) return routes.authenticate();
      return jsonResponse({
        token: token({ client_domain: CLIENT_DOMAIN, sub: WALLET.publicKey() }),
      });
    }
    if (routes.challenge) return routes.challenge();
    return jsonResponse({ transaction: challengeXdr(), network_passphrase: Networks.PUBLIC });
  }) as unknown as typeof fetch;
}

/** Runs the audit against a mock anchor with the shared client domain keypair. */
function audit(fetchImpl: typeof fetch, rules?: Record<string, 'off' | 'error' | 'warning'>) {
  return checkSep10ClientDomain(SIGNING_KEY, WEB_AUTH_ENDPOINT, {
    fetchImpl,
    clientDomain: CLIENT_DOMAIN,
    clientDomainKeypair: CLIENT_KEYS,
    ...(rules === undefined ? {} : { rules }),
  });
}

describe('checkSep10ClientDomain', () => {
  it('registers both required rule ids', () => {
    expect(sep10ClientDomainRuleIds).toEqual([
      'sep10/missing-client-domain-claim',
      'sep10/invalid-client-domain-operation',
    ]);
  });

  it('registers both rules as errors', () => {
    expect(sep10ClientDomainRules.map((rule) => rule.severity)).toEqual(['error', 'error']);
  });

  it('passes when the anchor embeds the client domain in the JWT', async () => {
    expect(await audit(anchorServer())).toEqual([]);
  });

  it('requests the challenge with the client_domain parameter', async () => {
    const requested: string[] = [];
    const fetchImpl = (async (input: string | URL | Request) => {
      const url = String(input);
      requested.push(url);
      return anchorServer()(input);
    }) as unknown as typeof fetch;

    await checkSep10ClientDomain(SIGNING_KEY, WEB_AUTH_ENDPOINT, {
      fetchImpl,
      clientDomain: CLIENT_DOMAIN,
      clientDomainKeypair: CLIENT_KEYS,
    });

    const challengeRequest = requested.find((url) => url.includes('account='));
    expect(challengeRequest).toBeDefined();
    expect(decodeURIComponent(challengeRequest ?? '')).toContain(`client_domain=${CLIENT_DOMAIN}`);
  });

  it('reports sep10/missing-client-domain-claim when the JWT omits the claim', async () => {
    const diagnostics = await audit(
      anchorServer({ authenticate: () => jsonResponse({ token: token({ sub: 'G_WALLET' }) }) }),
    );

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.rule).toBe('sep10/missing-client-domain-claim');
    expect(diagnostics[0]?.severity).toBe('error');
  });

  it('reports sep10/missing-client-domain-claim when the claim names another domain', async () => {
    const diagnostics = await audit(
      anchorServer({
        authenticate: () => jsonResponse({ token: token({ client_domain: 'other.example.com' }) }),
      }),
    );

    expect(diagnostics[0]?.rule).toBe('sep10/missing-client-domain-claim');
    expect(diagnostics[0]?.message).toContain('other.example.com');
  });

  it('reports sep10/missing-client-domain-claim when the challenge has no client_domain operation', async () => {
    const diagnostics = await audit(
      anchorServer({
        challenge: () => jsonResponse({ transaction: challengeXdr({ omitOperation: true }) }),
      }),
    );

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.rule).toBe('sep10/missing-client-domain-claim');
  });

  it('reports sep10/invalid-client-domain-operation for an unparseable envelope', async () => {
    const diagnostics = await audit(
      anchorServer({ challenge: () => jsonResponse({ transaction: 'not-a-transaction' }) }),
    );

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.rule).toBe('sep10/invalid-client-domain-operation');
  });

  it('reports sep10/invalid-client-domain-operation when no transaction is returned', async () => {
    const diagnostics = await audit(anchorServer({ challenge: () => jsonResponse({}) }));

    expect(diagnostics[0]?.rule).toBe('sep10/invalid-client-domain-operation');
  });

  it('reports sep10/invalid-client-domain-operation for a client_domain value that is not auth', async () => {
    const diagnostics = await audit(
      anchorServer({
        challenge: () => jsonResponse({ transaction: challengeXdr({ value: 'maybe' }) }),
      }),
    );

    expect(diagnostics[0]?.rule).toBe('sep10/invalid-client-domain-operation');
    expect(diagnostics[0]?.message).toContain('maybe');
  });

  it('checks the operation against the key published at the client domain', async () => {
    const otherKey = Keypair.random().publicKey();
    const diagnostics = await audit(
      anchorServer({
        toml: () => new Response(buildClientDomainToml(otherKey, CLIENT_DOMAIN), { status: 200 }),
      }),
    );

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.rule).toBe('sep10/invalid-client-domain-operation');
    expect(diagnostics[0]?.message).toContain(otherKey);
  });

  it('reports sep10/missing-client-domain-claim when the anchor refuses the attributed challenge', async () => {
    const diagnostics = await audit(
      anchorServer({ authenticate: () => jsonResponse({ error: 'signature missing' }, 403) }),
    );

    expect(diagnostics[0]?.rule).toBe('sep10/missing-client-domain-claim');
    expect(diagnostics[0]?.message).toContain('403');
  });

  it('stays silent when the endpoint cannot be reached', async () => {
    const unreachable = (async () => {
      throw new Error('ENOTFOUND');
    }) as unknown as typeof fetch;

    expect(await audit(unreachable)).toEqual([]);
  });

  it('stays silent for a file with no signing key or no web auth endpoint', async () => {
    expect(await checkSep10ClientDomain('', WEB_AUTH_ENDPOINT)).toEqual([]);
    expect(await checkSep10ClientDomain(SIGNING_KEY, '')).toEqual([]);
  });

  it('honours rule overrides', async () => {
    const diagnostics = await audit(
      anchorServer({ authenticate: () => jsonResponse({ token: token({}) }) }),
      { 'sep10/missing-client-domain-claim': 'off' },
    );

    expect(diagnostics).toEqual([]);
  });
});

describe('buildClientDomainToml', () => {
  it('publishes the attribution signing key the anchor resolves', () => {
    expect(buildClientDomainToml(CLIENT_KEYS.publicKey(), CLIENT_DOMAIN)).toContain(
      `SIGNING_KEY="${CLIENT_KEYS.publicKey()}"`,
    );
  });
});

describe('decodeClientDomainClaim', () => {
  it('reads the client_domain claim from a JWT payload', () => {
    expect(decodeClientDomainClaim(token({ client_domain: CLIENT_DOMAIN }))).toBe(CLIENT_DOMAIN);
  });

  it('returns undefined for a token without a payload or with a broken one', () => {
    expect(decodeClientDomainClaim('only-one-part')).toBeUndefined();
    expect(decodeClientDomainClaim(`${'header'}.${'bm90IGpzb24'}.sig`)).toBeUndefined();
    expect(decodeClientDomainClaim(token({ sub: 'G_WALLET' }))).toBeUndefined();
  });
});
