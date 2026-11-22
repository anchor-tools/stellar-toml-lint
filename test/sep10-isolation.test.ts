import { Account, Keypair, Networks, Operation, TransactionBuilder } from '@stellar/stellar-base';
import { describe, expect, it } from 'vitest';
import {
  CROSS_NETWORK_REJECTION_STATUS,
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
  signUnderPassphrase,
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

/** A challenge endpoint whose POST handler decides whether to accept the reply. */
function authServer(
  challengeFor: () => string,
  accept: (xdr: string) => boolean,
  status = 400,
  error: string | null = 'invalid network passphrase',
) {
  const calls: string[] = [];
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input));
    calls.push(`${init?.method ?? 'GET'} ${url.pathname}`);
    if (init?.method === 'GET') {
      return Response.json({ transaction: challengeFor() });
    }
    const body = JSON.parse(String(init?.body)) as { transaction?: string };
    if (accept(body.transaction ?? '')) return Response.json({ token: 'jwt' });
    if (error === null) return new Response('', { status });
    return Response.json({ error }, { status });
  }) as unknown as typeof fetch;
  return { fetchImpl, calls };
}

/** True only when the client's signature validates under the given passphrase. */
function signedFor(xdr: string, passphrase: string, keypair = CLIENT): boolean {
  try {
    const tx = TransactionBuilder.fromXDR(xdr, passphrase);
    if ('innerTransaction' in tx) return false;
    const hash = tx.hash();
    return tx.signatures.some(
      (sig) => keypair.signatureHint().equals(sig.hint()) && keypair.verify(hash, sig.signature()),
    );
  } catch {
    return false;
  }
}

function passphraseValidation(server: Keypair, client: Keypair, passphrase: string): boolean {
  const xdr = signUnderPassphrase(buildChallenge(passphrase, server, client), passphrase, client);
  return signedFor(xdr, passphrase, client);
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
  it('signs the same envelope under different passphrases, producing different hashes', () => {
    const xdr = buildChallenge(Networks.PUBLIC);
    const publicSig = signUnderPassphrase(xdr, Networks.PUBLIC, CLIENT);
    const testnetSig = signUnderPassphrase(xdr, Networks.TESTNET, CLIENT);
    expect(publicSig).not.toBe(testnetSig);
    expect(signedFor(publicSig, Networks.PUBLIC)).toBe(true);
    expect(signedFor(publicSig, Networks.TESTNET)).toBe(false);
    expect(signedFor(testnetSig, Networks.TESTNET)).toBe(true);
    expect(signedFor(testnetSig, Networks.PUBLIC)).toBe(false);
  });

  it('detects the passphrase the server signature commits to', () => {
    const xdr = buildChallenge(Networks.PUBLIC);
    const publicView = inspectChallenge(xdr, Networks.PUBLIC);
    const testnetView = inspectChallenge(xdr, Networks.TESTNET);
    expect(publicView?.validSignatures).toEqual([SERVER.publicKey()]);
    expect(publicView?.account).toBe(CLIENT.publicKey());
    expect(testnetView?.validSignatures).toEqual([]);
    expect(inspectChallenge('not-an-envelope', Networks.PUBLIC)).toBeUndefined();
  });

  it('rejects malformed envelopes when signing', () => {
    expect(() => signUnderPassphrase('garbage', Networks.PUBLIC, CLIENT)).toThrow();
  });

  it('rejects fee-bump envelopes when signing', () => {
    const inner = TransactionBuilder.fromXDR(buildChallenge(Networks.PUBLIC), Networks.PUBLIC);
    if ('innerTransaction' in inner) throw new Error('expected a standard envelope');
    const feeBump = TransactionBuilder.buildFeeBumpTransaction(
      SERVER,
      '200',
      inner,
      Networks.PUBLIC,
    );
    expect(() => signUnderPassphrase(feeBump.toXDR(), Networks.PUBLIC, CLIENT)).toThrow(/fee-bump/);
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
  it('passes when the challenge is network-bound and the cross-network reply is rejected', async () => {
    const { fetchImpl, calls } = authServer(
      () => buildChallenge(Networks.PUBLIC),
      (xdr) => signedFor(xdr, Networks.PUBLIC),
    );
    const result = await new Sep10NetworkIsolationAuditor(fetchImpl, {
      clientKeypair: CLIENT,
    }).audit({ WEB_AUTH_ENDPOINT: 'https://anchor.test/auth' }, 'anchor.test');

    expect(result.diagnostics).toEqual([]);
    expect(result.report.ok).toBe(true);
    expect(result.report.network).toBe('public');
    expect(result.report.challenge?.networkBound).toBe(true);
    expect(result.report.challenge?.observedPassphrase).toBe(Networks.PUBLIC);
    expect(result.report.probe?.status).toBe(CROSS_NETWORK_REJECTION_STATUS);
    expect(result.report.probe?.rejectedStrictly).toBe(true);
    expect(calls).toEqual(['GET /auth', 'POST /auth']);
    expect(renderSep10IsolationReport(result.report)).toContain('PASS');
  });

  it('fails when the server accepts a testnet-signed response on mainnet', async () => {
    const { fetchImpl } = authServer(
      () => buildChallenge(Networks.PUBLIC),
      (xdr) => signedFor(xdr, Networks.PUBLIC) || signedFor(xdr, Networks.TESTNET),
    );
    const result = await new Sep10NetworkIsolationAuditor(fetchImpl, {
      clientKeypair: CLIENT,
    }).audit({ WEB_AUTH_ENDPOINT: 'https://anchor.test/auth' }, 'anchor.test');

    expect(result.report.probe?.accepted).toBe(true);
    expect(result.report.ok).toBe(false);
    expect(result.diagnostics.map((d) => d.rule)).toContain(
      'sep10/isolation-cross-network-accepted',
    );
  });

  it('flags a challenge that is signed for the alternate network', async () => {
    const { fetchImpl } = authServer(
      () => buildChallenge(Networks.TESTNET),
      () => false,
    );
    const result = await new Sep10NetworkIsolationAuditor(fetchImpl, {
      clientKeypair: CLIENT,
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
    const { fetchImpl } = authServer(
      () => tx.toXDR(),
      () => false,
    );
    const result = await new Sep10NetworkIsolationAuditor(fetchImpl, {
      clientKeypair: CLIENT,
    }).audit({ WEB_AUTH_ENDPOINT: 'https://anchor.test/auth' }, 'anchor.test');

    expect(result.report.challenge?.networkBound).toBe(false);
    expect(result.report.challenge?.observedPassphrase).toBeUndefined();
    expect(result.diagnostics.map((d) => d.rule)).toContain(
      'sep10/isolation-challenge-signature-invalid',
    );
  });

  it('requires a descriptive error code on rejection', async () => {
    const { fetchImpl } = authServer(
      () => buildChallenge(Networks.PUBLIC),
      () => false,
      400,
      null,
    );
    const result = await new Sep10NetworkIsolationAuditor(fetchImpl, {
      clientKeypair: CLIENT,
    }).audit({ WEB_AUTH_ENDPOINT: 'https://anchor.test/auth' }, 'anchor.test');

    expect(result.diagnostics.map((d) => d.rule)).toContain('sep10/isolation-missing-error-code');
    expect(result.report.probe?.rejectedStrictly).toBe(false);
    expect(result.report.ok).toBe(false);
  });

  it('flags the wrong rejection status even with an error body', async () => {
    const { fetchImpl } = authServer(
      () => buildChallenge(Networks.PUBLIC),
      () => false,
      401,
      'unauthorized',
    );
    const result = await new Sep10NetworkIsolationAuditor(fetchImpl, {
      clientKeypair: CLIENT,
    }).audit({ WEB_AUTH_ENDPOINT: 'https://anchor.test/auth' }, 'anchor.test');

    expect(result.diagnostics.map((d) => d.rule)).toContain(
      'sep10/isolation-cross-network-bad-status',
    );
  });

  it('tests the reverse direction on testnet', async () => {
    const { fetchImpl } = authServer(
      () => buildChallenge(Networks.TESTNET),
      (xdr) => signedFor(xdr, Networks.TESTNET),
    );
    const result = await new Sep10NetworkIsolationAuditor(fetchImpl, {
      network: 'testnet',
      clientKeypair: CLIENT,
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
      clientKeypair: CLIENT,
    }).audit({ WEB_AUTH_ENDPOINT: 'https://anchor.test/auth' }, 'anchor.test');

    expect(result.diagnostics.map((d) => d.rule)).toEqual(['sep10/isolation-probe-failed']);
    expect(result.diagnostics[0]?.severity).toBe('warning');
  });

  it('reports a non-2xx challenge response and a missing envelope', async () => {
    const down = (async () => new Response('nope', { status: 503 })) as unknown as typeof fetch;
    const first = await new Sep10NetworkIsolationAuditor(down, {
      clientKeypair: CLIENT,
    }).audit({}, 'anchor.test');
    expect(first.diagnostics[0]?.message).toContain('HTTP 503');

    const empty = (async () => Response.json({})) as unknown as typeof fetch;
    const second = await new Sep10NetworkIsolationAuditor(empty, {
      clientKeypair: CLIENT,
    }).audit({}, 'anchor.test');
    expect(second.diagnostics[0]?.message).toContain('no `transaction`');
  });

  it('reports an unparseable challenge envelope', async () => {
    const fetchImpl = (async () =>
      Response.json({ transaction: 'garbage' })) as unknown as typeof fetch;
    const result = await new Sep10NetworkIsolationAuditor(fetchImpl, {
      clientKeypair: CLIENT,
    }).audit({}, 'anchor.test');
    expect(result.diagnostics.map((d) => d.rule)).toEqual(['sep10/isolation-challenge-malformed']);
  });

  it('reports a network error during the cross-network submission', async () => {
    let call = 0;
    const fetchImpl = (async () => {
      call += 1;
      if (call === 1) return Response.json({ transaction: buildChallenge(Networks.PUBLIC) });
      throw new Error('socket hang up');
    }) as unknown as typeof fetch;
    const result = await new Sep10NetworkIsolationAuditor(fetchImpl, {
      clientKeypair: CLIENT,
    }).audit({ WEB_AUTH_ENDPOINT: 'https://anchor.test/auth' }, 'anchor.test');
    expect(result.diagnostics.map((d) => d.rule)).toContain('sep10/isolation-probe-failed');
  });

  it('accepts a plain-text error body from a rejecting server', async () => {
    let call = 0;
    const fetchImpl = (async () => {
      call += 1;
      if (call === 1) return Response.json({ transaction: buildChallenge(Networks.PUBLIC) });
      return new Response('bad network passphrase', { status: 400 });
    }) as unknown as typeof fetch;
    const result = await new Sep10NetworkIsolationAuditor(fetchImpl, {
      clientKeypair: CLIENT,
    }).audit({ WEB_AUTH_ENDPOINT: 'https://anchor.test/auth' }, 'anchor.test');
    expect(result.report.probe?.error).toBe('bad network passphrase');
    expect(result.report.probe?.rejectedStrictly).toBe(true);
    expect(result.report.ok).toBe(true);
  });

  it('treats a JSON error body without a string code as missing', async () => {
    let call = 0;
    const fetchImpl = (async () => {
      call += 1;
      if (call === 1) return Response.json({ transaction: buildChallenge(Networks.PUBLIC) });
      return Response.json({ detail: 42 }, { status: 400 });
    }) as unknown as typeof fetch;
    const result = await new Sep10NetworkIsolationAuditor(fetchImpl, {
      clientKeypair: CLIENT,
    }).audit({ WEB_AUTH_ENDPOINT: 'https://anchor.test/auth' }, 'anchor.test');
    expect(result.diagnostics.map((d) => d.rule)).toContain('sep10/isolation-missing-error-code');
  });

  it('treats an unreadable rejection body as a missing error code', async () => {
    let call = 0;
    const fetchImpl = (async () => {
      call += 1;
      if (call === 1) return Response.json({ transaction: buildChallenge(Networks.PUBLIC) });
      return {
        ok: false,
        status: 400,
        text: async () => {
          throw new Error('stream closed');
        },
      } as unknown as Response;
    }) as unknown as typeof fetch;
    const result = await new Sep10NetworkIsolationAuditor(fetchImpl, {
      clientKeypair: CLIENT,
    }).audit({ WEB_AUTH_ENDPOINT: 'https://anchor.test/auth' }, 'anchor.test');
    expect(result.report.probe?.error).toBeUndefined();
    expect(result.diagnostics.map((d) => d.rule)).toContain('sep10/isolation-missing-error-code');
  });

  it('audits through the document wrapper and renders an unprobed report', async () => {
    const fetchImpl = (async () =>
      new Response('down', { status: 500 })) as unknown as typeof fetch;
    const result = await auditSep10NetworkIsolation(
      { NETWORK_PASSPHRASE: Networks.TESTNET },
      'anchor.test',
      fetchImpl,
      { clientKeypair: CLIENT },
    );
    expect(result.report.network).toBe('testnet');
    const rendered = renderSep10IsolationReport(result.report);
    expect(rendered).toContain('FAIL');
    expect(rendered).not.toContain('probe:');
  });

  it('renders the probe error line', async () => {
    const { fetchImpl } = authServer(
      () => buildChallenge(Networks.PUBLIC),
      () => false,
      401,
      'wrong network',
    );
    const result = await new Sep10NetworkIsolationAuditor(fetchImpl, {
      clientKeypair: CLIENT,
    }).audit({ WEB_AUTH_ENDPOINT: 'https://anchor.test/auth' }, 'anchor.test');
    expect(renderSep10IsolationReport(result.report)).toContain('— wrong network');
  });

  it('honours severity overrides', async () => {
    const fetchImpl = (async () => {
      throw new Error('offline');
    }) as unknown as typeof fetch;
    const result = await new Sep10NetworkIsolationAuditor(fetchImpl, {
      clientKeypair: CLIENT,
      rules: { 'sep10/isolation-probe-failed': 'off' },
    }).audit({}, 'anchor.test');
    expect(result.diagnostics).toEqual([]);
  });

  it('never includes secret keys in reports', async () => {
    const { fetchImpl } = authServer(
      () => buildChallenge(Networks.PUBLIC),
      () => false,
    );
    const result = await new Sep10NetworkIsolationAuditor(fetchImpl, {
      clientKeypair: CLIENT,
    }).audit({ WEB_AUTH_ENDPOINT: 'https://anchor.test/auth' }, 'anchor.test');
    const serialized = JSON.stringify(result);
    // Compare booleans so a failing assertion cannot echo a secret seed.
    expect(serialized.includes(CLIENT.secret())).toBe(false);
    expect(serialized.includes(SERVER.secret())).toBe(false);
    expect(serialized.includes(CLIENT.publicKey())).toBe(true);
  });

  it('proves a challenge envelope verified under the target hash is not valid on the other network', () => {
    expect(passphraseValidation(SERVER, CLIENT, Networks.PUBLIC)).toBe(true);
    expect(passphraseValidation(SERVER, CLIENT, Networks.TESTNET)).toBe(true);
    const publicChallenge = signUnderPassphrase(
      buildChallenge(Networks.PUBLIC),
      Networks.PUBLIC,
      CLIENT,
    );
    expect(signedFor(publicChallenge, Networks.PUBLIC)).toBe(true);
    expect(signedFor(publicChallenge, Networks.TESTNET)).toBe(false);
  });
});
