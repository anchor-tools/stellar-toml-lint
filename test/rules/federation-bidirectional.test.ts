import { describe, expect, it } from 'vitest';
import { Keypair } from '@stellar/stellar-base';
import {
  FEDERATION_FORWARD_RESOLUTION_FAILED,
  FEDERATION_REVERSE_LOOKUP_MISMATCH,
  addressDomain,
  checkFederationBidirectional,
  federationBidirectionalRules,
  federationLookupUrl,
} from '../../src/rules/federation-bidirectional.js';

// Real, checksum-valid account IDs: the auditor refuses to cross-check a key
// it cannot validate, so a fixture-shaped string would make every case pass.
const SIGNING_KEY = Keypair.random().publicKey();
const OTHER_KEY = Keypair.random().publicKey();
const SERVER = 'https://fed.example.com';
const DOMAIN = 'anchor.example.com';

/** A file with a federation server, a signing key, and a domain to probe. */
function doc(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    FEDERATION_SERVER: SERVER,
    SIGNING_KEY,
    DOCUMENTATION: { ORG_URL: `https://${DOMAIN}` },
    ...overrides,
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

interface Answers {
  /** The forward (`type=name`) answer. */
  forward?: () => Response | Promise<Response>;
  /** The reverse (`type=id`) answer. */
  reverse?: () => Response | Promise<Response>;
}

/** A transport that answers forward and reverse lookups separately. */
function federationFetch(answers: Answers) {
  const calls: string[] = [];
  const fetchImpl = (async (input: string | URL | Request) => {
    const url = String(input);
    calls.push(url);
    const isForward = url.includes('type=name');
    const handler = isForward ? answers.forward : answers.reverse;
    if (handler === undefined) return jsonResponse({ account_id: SIGNING_KEY });
    return handler();
  }) as unknown as typeof fetch;
  return { fetchImpl, calls };
}

const CONSISTENT: Answers = {
  forward: () => jsonResponse({ stellar_address: `deposit*${DOMAIN}`, account_id: SIGNING_KEY }),
  reverse: () => jsonResponse({ stellar_address: `deposit*${DOMAIN}`, account_id: SIGNING_KEY }),
};

const rules = (diagnostics: { rule: string }[]): string[] => diagnostics.map((d) => d.rule);

describe('checkFederationBidirectional', () => {
  it('passes a consistent bidirectional federation configuration', async () => {
    const { fetchImpl, calls } = federationFetch(CONSISTENT);
    expect(await checkFederationBidirectional(doc(), fetchImpl)).toEqual([]);

    expect(calls).toEqual([
      federationLookupUrl(SERVER, 'name', `deposit*${DOMAIN}`),
      federationLookupUrl(SERVER, 'id', SIGNING_KEY),
    ]);
  });

  it('accepts an ACCOUNTS entry as the forward target', async () => {
    const { fetchImpl } = federationFetch({
      forward: () => jsonResponse({ account_id: OTHER_KEY }),
      reverse: () => jsonResponse({ account_id: OTHER_KEY }),
    });

    const parsed = doc({ ACCOUNTS: [OTHER_KEY] });
    expect(await checkFederationBidirectional(parsed, fetchImpl)).toEqual([]);
  });

  it('flags a reverse lookup that returns a foreign domain', async () => {
    const { fetchImpl } = federationFetch({
      forward: () => jsonResponse({ account_id: SIGNING_KEY }),
      reverse: () =>
        jsonResponse({ stellar_address: `deposit*evil.example`, account_id: SIGNING_KEY }),
    });

    const diagnostics = await checkFederationBidirectional(doc(), fetchImpl);
    expect(diagnostics).toEqual([
      expect.objectContaining({
        rule: FEDERATION_REVERSE_LOOKUP_MISMATCH,
        severity: 'error',
        category: 'network',
        path: 'FEDERATION_SERVER',
      }),
    ]);
    expect(diagnostics[0]?.message).toContain('foreign domain');
  });

  it('flags a reverse lookup returning an account that is not the queried key', async () => {
    const { fetchImpl } = federationFetch({
      forward: () => jsonResponse({ account_id: SIGNING_KEY }),
      reverse: () => jsonResponse({ account_id: OTHER_KEY }),
    });

    const diagnostics = await checkFederationBidirectional(doc(), fetchImpl);
    expect(rules(diagnostics)).toContain(FEDERATION_REVERSE_LOOKUP_MISMATCH);
    expect(diagnostics[0]?.message).toContain('does not match the queried key');
  });

  it('flags forward and reverse answers that disagree', async () => {
    const { fetchImpl } = federationFetch({
      forward: () => jsonResponse({ account_id: OTHER_KEY }),
      reverse: () => jsonResponse({ account_id: SIGNING_KEY }),
    });

    const diagnostics = await checkFederationBidirectional(
      doc({ ACCOUNTS: [OTHER_KEY] }),
      fetchImpl,
    );
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.rule).toBe(FEDERATION_REVERSE_LOOKUP_MISMATCH);
    expect(diagnostics[0]?.suggestion).toContain('both directions agree');
  });

  it('flags a forward lookup that fails to resolve', async () => {
    const { fetchImpl } = federationFetch({
      forward: () => jsonResponse({ error: 'not found' }, 404),
      reverse: () => jsonResponse({ account_id: SIGNING_KEY }),
    });

    const diagnostics = await checkFederationBidirectional(doc(), fetchImpl);
    expect(diagnostics).toEqual([
      expect.objectContaining({ rule: FEDERATION_FORWARD_RESOLUTION_FAILED, severity: 'error' }),
    ]);
    expect(diagnostics[0]?.message).toContain('HTTP 404');
  });

  it('flags a forward lookup resolving to an unauthorised account', async () => {
    const { fetchImpl } = federationFetch({
      forward: () => jsonResponse({ account_id: OTHER_KEY }),
      reverse: () => jsonResponse({ account_id: SIGNING_KEY }),
    });

    const diagnostics = await checkFederationBidirectional(doc(), fetchImpl);
    const forwardFinding = diagnostics.find((d) => d.rule === FEDERATION_FORWARD_RESOLUTION_FAILED);
    expect(forwardFinding?.message).toContain('neither SIGNING_KEY nor an ACCOUNTS entry');
    // The disagreement between the two directions is the reverse rule's concern.
    expect(rules(diagnostics)).toContain(FEDERATION_REVERSE_LOOKUP_MISMATCH);
  });

  it('flags a reverse lookup the server cannot answer', async () => {
    const fetchImpl = (async (input: string | URL | Request) => {
      if (String(input).includes('type=name')) {
        return jsonResponse({ account_id: SIGNING_KEY });
      }
      throw new Error('connect ECONNREFUSED');
    }) as unknown as typeof fetch;

    const diagnostics = await checkFederationBidirectional(doc(), fetchImpl);
    expect(diagnostics).toEqual([
      expect.objectContaining({ rule: FEDERATION_REVERSE_LOOKUP_MISMATCH }),
    ]);
    expect(diagnostics[0]?.message).toContain('ECONNREFUSED');
  });

  it('skips the forward lookup when no domain can be derived', async () => {
    const { fetchImpl, calls } = federationFetch(CONSISTENT);
    const parsed = { FEDERATION_SERVER: SERVER, SIGNING_KEY };

    expect(await checkFederationBidirectional(parsed, fetchImpl)).toEqual([]);
    expect(calls).toEqual([federationLookupUrl(SERVER, 'id', SIGNING_KEY)]);
  });

  it('honours an explicit domain and probe name', async () => {
    const { fetchImpl, calls } = federationFetch(CONSISTENT);
    await checkFederationBidirectional({ FEDERATION_SERVER: SERVER, SIGNING_KEY }, fetchImpl, {
      domain: 'custom.example',
      probeName: 'alice*custom.example',
    });

    expect(calls[0]).toBe(federationLookupUrl(SERVER, 'name', 'alice*custom.example'));
  });

  it('stays silent without a usable FEDERATION_SERVER or SIGNING_KEY', async () => {
    const { fetchImpl, calls } = federationFetch(CONSISTENT);

    expect(await checkFederationBidirectional({ SIGNING_KEY }, fetchImpl)).toEqual([]);
    expect(
      await checkFederationBidirectional({ FEDERATION_SERVER: 'not a url' }, fetchImpl),
    ).toEqual([]);
    expect(
      await checkFederationBidirectional(
        { FEDERATION_SERVER: 'http://fed.example.com' },
        fetchImpl,
      ),
    ).toEqual([]);
    expect(
      await checkFederationBidirectional(
        { FEDERATION_SERVER: SERVER, SIGNING_KEY: 'nope' },
        fetchImpl,
      ),
    ).toEqual([]);
    expect(calls).toHaveLength(0);
  });

  it('degrades non-JSON and non-object bodies to a finding, never a throw', async () => {
    const html = (async () =>
      new Response('<html>portal</html>', {
        status: 200,
        headers: { 'content-type': 'text/html' },
      })) as unknown as typeof fetch;
    expect(rules(await checkFederationBidirectional(doc(), html))).toContain(
      FEDERATION_FORWARD_RESOLUTION_FAILED,
    );

    const array = federationFetch({
      forward: () => jsonResponse([1, 2, 3]),
      reverse: () => jsonResponse({ account_id: SIGNING_KEY }),
    });
    expect(rules(await checkFederationBidirectional(doc(), array.fetchImpl))).toContain(
      FEDERATION_FORWARD_RESOLUTION_FAILED,
    );

    const missingAccount = federationFetch({
      forward: () => jsonResponse({ stellar_address: 'x' }),
      reverse: () => jsonResponse({ account_id: SIGNING_KEY }),
    });
    const diagnostics = await checkFederationBidirectional(doc(), missingAccount.fetchImpl);
    expect(diagnostics[0]?.message).toContain('valid account_id');
  });

  it('honours --off and --warn overrides', async () => {
    const off = federationFetch({
      forward: () => jsonResponse({}, 500),
      reverse: () => jsonResponse({}, 500),
    });
    expect(
      await checkFederationBidirectional(doc(), off.fetchImpl, {
        rules: {
          [FEDERATION_FORWARD_RESOLUTION_FAILED]: 'off',
          [FEDERATION_REVERSE_LOOKUP_MISMATCH]: 'off',
        },
      }),
    ).toEqual([]);

    const warn = federationFetch({
      forward: () => jsonResponse({}, 500),
      reverse: () => jsonResponse({ account_id: SIGNING_KEY }),
    });
    const diagnostics = await checkFederationBidirectional(doc(), warn.fetchImpl, {
      rules: { [FEDERATION_FORWARD_RESOLUTION_FAILED]: 'warning' },
    });
    expect(diagnostics[0]?.severity).toBe('warning');
  });
});

describe('federation helpers', () => {
  it('reads the domain out of a federation address', () => {
    expect(addressDomain('deposit*anchor.example.com')).toBe('anchor.example.com');
    expect(addressDomain('deposit@anchor.example.com')).toBe('anchor.example.com');
    expect(addressDomain('anchor.example.com')).toBeUndefined();
    expect(addressDomain('deposit*')).toBeUndefined();
  });

  it('registers the two rule ids with error severity', () => {
    expect(
      federationBidirectionalRules.map((rule) => ({ id: rule.id, severity: rule.severity })),
    ).toEqual([
      { id: FEDERATION_FORWARD_RESOLUTION_FAILED, severity: 'error' },
      { id: FEDERATION_REVERSE_LOOKUP_MISMATCH, severity: 'error' },
    ]);
  });
});
