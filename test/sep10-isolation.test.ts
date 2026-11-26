import { Account, Keypair, Networks, Operation, TransactionBuilder } from '@stellar/stellar-base';
import { describe, expect, it } from 'vitest';
import {
  NETWORK_PASSPHRASES,
  Sep10NetworkIsolationAuditor,
  alternatePassphraseFor,
  auditSep10NetworkIsolation,
  inspectChallenge,
  networkFromDocument,
  networkFromPassphrase,
  passphraseFor,
  renderSep10IsolationReport,
  sep10IsolationRuleIds,
  sep10IsolationRules,
} from '../src/protocols/sep10Isolation.js';

const SERVER = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 1));
const CLIENT = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 2));

/** Builds a SEP-10-shaped challenge: server source, client manageData op. */
function buildChallenge(
  passphrase: string,
  server: Keypair = SERVER,
  client: Keypair = CLIENT,
): string {
  const source = new Account(server.publicKey(), '1');
  const tx = new TransactionBuilder(source, { networkPassphrase: passphrase, fee: '100' })
    .addOperation(
      Operation.manageData({
        name: 'web_auth_domain',
        value: Buffer.from('anchor.test'),
        source: client.publicKey(),
      }),
    )
    .setTimeout(300)
    .build();
  tx.sign(server);
  return tx.toXDR();
}

function authServer(challengeFor: () => string) {
  const calls: string[] = [];
  const fetchImpl: typeof fetch = async (input, init) => {
    const url = new URL(String(input));
    calls.push(String(init?.method) + ' ' + url.pathname);
    expect(init?.method).toBe('GET');
    expect(url.searchParams.get('account')).toBe(CLIENT.publicKey());
    return Response.json({ transaction: challengeFor() });
  };
  return { fetchImpl, calls };
}

describe('passphrase helpers', () => {
  it('maps both networks and their alternates', () => {
    expect(passphraseFor('public')).toBe(Networks.PUBLIC);
    expect(passphraseFor('testnet')).toBe(Networks.TESTNET);
    expect(alternatePassphraseFor('public')).toBe(Networks.TESTNET);
    expect(alternatePassphraseFor('testnet')).toBe(Networks.PUBLIC);
    expect(NETWORK_PASSPHRASES.public).toBe(Networks.PUBLIC);
  });

  it('infers the network from a passphrase or document', () => {
    expect(networkFromPassphrase(`  ${Networks.PUBLIC}  `)).toBe('public');
    expect(networkFromPassphrase(Networks.TESTNET)).toBe('testnet');
    expect(networkFromPassphrase('Custom Network')).toBeUndefined();
    expect(networkFromDocument({ NETWORK_PASSPHRASE: Networks.TESTNET })).toBe('testnet');
    expect(networkFromDocument({})).toBeUndefined();
  });
});

describe('signing and inspection', () => {
  it('detects the passphrase the server signature commits to', () => {
    const xdr = buildChallenge(Networks.PUBLIC);
    const publicView = inspectChallenge(xdr, Networks.PUBLIC);
    const testnetView = inspectChallenge(xdr, Networks.TESTNET);
    expect(publicView?.validSignatures).toEqual([SERVER.publicKey()]);
    expect(publicView?.account).toBe(CLIENT.publicKey());
    expect(testnetView?.validSignatures).toEqual([]);
    expect(inspectChallenge('not-an-envelope', Networks.PUBLIC)).toBeUndefined();
  });

  it('registers one rule id per finding code and every runner is a no-op', () => {
    expect(new Set(sep10IsolationRuleIds).size).toBe(sep10IsolationRuleIds.length);
    expect(sep10IsolationRules.map((rule) => rule.id)).toEqual([...sep10IsolationRuleIds]);
    for (const rule of sep10IsolationRules) {
      expect(() => rule.run({} as never)).not.toThrow();
    }
  });

  it('inspects an envelope with no client manageData operation', () => {
    const source = new Account(SERVER.publicKey(), '1');
    const tx = new TransactionBuilder(source, {
      networkPassphrase: Networks.PUBLIC,
      fee: '100',
    })
      .addOperation(Operation.manageData({ name: 'web_auth_domain', value: Buffer.from('x') }))
      .setTimeout(30)
      .build();
    tx.sign(SERVER);
    const view = inspectChallenge(tx.toXDR(), Networks.PUBLIC);
    expect(view?.account).toBeUndefined();
    expect(view?.validSignatures).toEqual([SERVER.publicKey()]);
  });
});

describe('Sep10NetworkIsolationAuditor', () => {
  it('passes for a network-bound challenge with a single GET', async () => {
    const { fetchImpl, calls } = authServer(() => buildChallenge(Networks.PUBLIC));
    const result = await new Sep10NetworkIsolationAuditor(fetchImpl, {
      clientAccount: CLIENT.publicKey(),
    }).audit({ WEB_AUTH_ENDPOINT: 'https://anchor.test/auth' }, 'anchor.test');

    expect(result.diagnostics).toEqual([]);
    expect(result.report.ok).toBe(true);
    expect(result.report.network).toBe('public');
    expect(result.report.challenge?.networkBound).toBe(true);
    expect(result.report.challenge?.observedPassphrase).toBe(Networks.PUBLIC);
    expect(calls).toEqual(['GET /auth']);
    expect(renderSep10IsolationReport(result.report)).toContain('PASS');
  });

  it('flags a challenge that is signed for the alternate network', async () => {
    const { fetchImpl } = authServer(() => buildChallenge(Networks.TESTNET));
    const result = await new Sep10NetworkIsolationAuditor(fetchImpl, {
      clientAccount: CLIENT.publicKey(),
    }).audit({ WEB_AUTH_ENDPOINT: 'https://anchor.test/auth' }, 'anchor.test');

    expect(result.report.challenge?.networkBound).toBe(false);
    expect(result.report.challenge?.observedPassphrase).toBe(Networks.TESTNET);
    expect(result.diagnostics.map((d) => d.rule)).toContain(
      'sep10/isolation-challenge-network-mismatch',
    );
    expect(result.report.ok).toBe(false);
  });

  it('flags a challenge whose signature validates on neither network', async () => {
    const third = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 3));
    const source = new Account(SERVER.publicKey(), '1');
    const tx = new TransactionBuilder(source, {
      networkPassphrase: Networks.PUBLIC,
      fee: '100',
    })
      .addOperation(
        Operation.manageData({
          name: 'web_auth_domain',
          value: Buffer.from('x'),
          source: CLIENT.publicKey(),
        }),
      )
      .setTimeout(30)
      .build();
    tx.sign(third);
    const { fetchImpl } = authServer(() => tx.toXDR());
    const result = await new Sep10NetworkIsolationAuditor(fetchImpl, {
      clientAccount: CLIENT.publicKey(),
    }).audit({ WEB_AUTH_ENDPOINT: 'https://anchor.test/auth' }, 'anchor.test');

    expect(result.report.challenge?.networkBound).toBe(false);
    expect(result.report.challenge?.observedPassphrase).toBeUndefined();
    expect(result.diagnostics.map((d) => d.rule)).toContain(
      'sep10/isolation-challenge-signature-invalid',
    );
  });

  it('tests the reverse direction on testnet', async () => {
    const { fetchImpl } = authServer(() => buildChallenge(Networks.TESTNET));
    const result = await new Sep10NetworkIsolationAuditor(fetchImpl, {
      network: 'testnet',
      clientAccount: CLIENT.publicKey(),
    }).audit({ WEB_AUTH_ENDPOINT: 'https://testnet.anchor.test/auth' }, 'testnet.anchor.test');

    expect(result.report.expectedPassphrase).toBe(Networks.TESTNET);
    expect(result.report.alternatePassphrase).toBe(Networks.PUBLIC);
    expect(result.report.ok).toBe(true);
  });

  it('reports an unreachable challenge endpoint as unverifiable, not a failure', async () => {
    const fetchImpl = (async () => {
      throw new Error('ECONNREFUSED');
    }) as unknown as typeof fetch;
    const result = await new Sep10NetworkIsolationAuditor(fetchImpl, {
      clientAccount: CLIENT.publicKey(),
    }).audit({ WEB_AUTH_ENDPOINT: 'https://anchor.test/auth' }, 'anchor.test');

    expect(result.diagnostics.map((d) => d.rule)).toEqual(['sep10/isolation-probe-failed']);
    expect(result.diagnostics[0]?.severity).toBe('warning');
  });

  it('reports a non-2xx challenge response and a missing envelope', async () => {
    const down = (async () => new Response('nope', { status: 503 })) as unknown as typeof fetch;
    const first = await new Sep10NetworkIsolationAuditor(down, {
      clientAccount: CLIENT.publicKey(),
    }).audit({}, 'anchor.test');
    expect(first.diagnostics[0]?.message).toContain('HTTP 503');

    const empty = (async () => Response.json({})) as unknown as typeof fetch;
    const second = await new Sep10NetworkIsolationAuditor(empty, {
      clientAccount: CLIENT.publicKey(),
    }).audit({}, 'anchor.test');
    expect(second.diagnostics[0]?.message).toContain('no `transaction`');
  });

  it('reports an unparseable challenge envelope', async () => {
    const fetchImpl = (async () =>
      Response.json({ transaction: 'garbage' })) as unknown as typeof fetch;
    const result = await new Sep10NetworkIsolationAuditor(fetchImpl, {
      clientAccount: CLIENT.publicKey(),
    }).audit({}, 'anchor.test');
    expect(result.diagnostics.map((d) => d.rule)).toEqual(['sep10/isolation-challenge-malformed']);
  });

  it('audits through the document wrapper and renders an unprobed report', async () => {
    const fetchImpl = (async () =>
      new Response('down', { status: 500 })) as unknown as typeof fetch;
    const result = await auditSep10NetworkIsolation(
      { NETWORK_PASSPHRASE: Networks.TESTNET },
      'anchor.test',
      fetchImpl,
      { clientAccount: CLIENT.publicKey() },
    );
    expect(result.report.network).toBe('testnet');
    const rendered = renderSep10IsolationReport(result.report);
    expect(rendered).toContain('FAIL');
    expect(rendered).not.toContain('probe:');
  });

  it('honours severity overrides', async () => {
    const fetchImpl = (async () => {
      throw new Error('offline');
    }) as unknown as typeof fetch;
    const result = await new Sep10NetworkIsolationAuditor(fetchImpl, {
      clientAccount: CLIENT.publicKey(),
      rules: { 'sep10/isolation-probe-failed': 'off' },
    }).audit({}, 'anchor.test');
    expect(result.diagnostics).toEqual([]);
  });

  it('never includes secret keys in reports', async () => {
    const { fetchImpl } = authServer(() => buildChallenge(Networks.PUBLIC));
    const result = await new Sep10NetworkIsolationAuditor(fetchImpl, {
      clientAccount: CLIENT.publicKey(),
    }).audit({ WEB_AUTH_ENDPOINT: 'https://anchor.test/auth' }, 'anchor.test');
    const serialized = JSON.stringify(result);
    // Compare booleans so a failing assertion cannot echo a secret seed.
    expect(serialized.includes(CLIENT.secret())).toBe(false);
    expect(serialized.includes(SERVER.secret())).toBe(false);
    expect(serialized.includes(CLIENT.publicKey())).toBe(true);
  });
});
