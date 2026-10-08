import { describe, it, expect } from 'vitest';
import {
  Account,
  Keypair,
  Networks,
  Operation,
  TimeoutInfinite,
  TransactionBuilder,
} from '@stellar/stellar-base';
import {
  CHALLENGE_SUBMISSION_FAILED_RULE,
  EXPIRED_TIMEBOUNDS_RULE,
  INVALID_SEQUENCE_RULE,
  INVALID_SOURCE_RULE,
  verifySep10,
} from '../../src/protocols/sep10.js';

const PASSPHRASE = Networks.PUBLIC;
const HOME = 'anchor.example.com';
const ENDPOINT = 'https://anchor.example.com/auth';

interface ChallengeOptions {
  source?: string;
  sequence?: string;
  timebounds?: { minTime: number; maxTime: number };
  opName?: string;
}

/** Build and server-sign a SEP-10 challenge transaction. */
function makeChallenge(server: Keypair, options: ChallengeOptions = {}): string {
  const sequence = (BigInt(options.sequence ?? '0') - 1n).toString();
  const account = new Account(options.source ?? server.publicKey(), sequence);
  const builder = new TransactionBuilder(account, {
    networkPassphrase: PASSPHRASE,
    fee: '100',
    ...(options.timebounds ? { timebounds: options.timebounds } : {}),
  }).addOperation(
    Operation.manageData({
      name: options.opName ?? `${HOME} auth`,
      value: Buffer.from('nonce'),
    }),
  );
  if (!options.timebounds) builder.setTimeout(TimeoutInfinite);
  const tx = builder.build();
  tx.sign(server);
  return tx.toXDR();
}

function makeJwt(payload: Record<string, unknown>): string {
  const b64 = (value: object) => Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64(payload)}.signature`;
}

function mockFetch(challengeXdr: string, token: string, status = 200): typeof fetch {
  return (async (_url: unknown, init?: { method?: string }) => {
    if (init?.method === 'POST') {
      return { ok: status < 400, status, json: async () => ({ token }) } as unknown as Response;
    }
    return {
      ok: true,
      status: 200,
      json: async () => ({ transaction: challengeXdr, network_passphrase: PASSPHRASE }),
    } as unknown as Response;
  }) as typeof fetch;
}

function freshTimebounds(): { minTime: number; maxTime: number } {
  const now = Math.floor(Date.now() / 1000);
  return { minTime: now - 5, maxTime: now + 300 };
}

describe('verifySep10', () => {
  it('reports no diagnostics for a conformant server', async () => {
    const server = Keypair.random();
    const now = Math.floor(Date.now() / 1000);
    const xdr = makeChallenge(server, { timebounds: freshTimebounds() });
    const token = makeJwt({ iss: HOME, sub: 'GCLIENT', iat: now, exp: now + 3600 });

    const diagnostics = await verifySep10(ENDPOINT, server.publicKey(), {
      fetchImpl: mockFetch(xdr, token),
      homeDomain: HOME,
      networkPassphrase: PASSPHRASE,
    });

    expect(diagnostics).toEqual([]);
  });

  it('flags a challenge whose source account is not SIGNING_KEY', async () => {
    const server = Keypair.random();
    const now = Math.floor(Date.now() / 1000);
    const xdr = makeChallenge(server, {
      source: Keypair.random().publicKey(),
      timebounds: freshTimebounds(),
    });
    const token = makeJwt({ iss: HOME, sub: 'GCLIENT', iat: now, exp: now + 3600 });

    const diagnostics = await verifySep10(ENDPOINT, server.publicKey(), {
      fetchImpl: mockFetch(xdr, token),
      homeDomain: HOME,
      networkPassphrase: PASSPHRASE,
    });

    expect(diagnostics.map((d) => d.rule)).toContain(INVALID_SOURCE_RULE);
  });

  it('flags a challenge with a non-zero sequence number', async () => {
    const server = Keypair.random();
    const now = Math.floor(Date.now() / 1000);
    const xdr = makeChallenge(server, { sequence: '42', timebounds: freshTimebounds() });
    const token = makeJwt({ iss: HOME, sub: 'GCLIENT', iat: now, exp: now + 3600 });

    const diagnostics = await verifySep10(ENDPOINT, server.publicKey(), {
      fetchImpl: mockFetch(xdr, token),
      homeDomain: HOME,
      networkPassphrase: PASSPHRASE,
    });

    expect(diagnostics.map((d) => d.rule)).toContain(INVALID_SEQUENCE_RULE);
  });

  it('flags a challenge with missing timebounds', async () => {
    const server = Keypair.random();
    const now = Math.floor(Date.now() / 1000);
    const xdr = makeChallenge(server, {}); // no timebounds
    const token = makeJwt({ iss: HOME, sub: 'GCLIENT', iat: now, exp: now + 3600 });

    const diagnostics = await verifySep10(ENDPOINT, server.publicKey(), {
      fetchImpl: mockFetch(xdr, token),
      homeDomain: HOME,
      networkPassphrase: PASSPHRASE,
    });

    expect(diagnostics.map((d) => d.rule)).toContain(EXPIRED_TIMEBOUNDS_RULE);
  });

  it('flags an invalid JWT token', async () => {
    const server = Keypair.random();
    const xdr = makeChallenge(server, { timebounds: freshTimebounds() });

    const diagnostics = await verifySep10(ENDPOINT, server.publicKey(), {
      fetchImpl: mockFetch(xdr, 'not-a-jwt'),
      homeDomain: HOME,
      networkPassphrase: PASSPHRASE,
    });

    expect(diagnostics.map((d) => d.rule)).toContain(CHALLENGE_SUBMISSION_FAILED_RULE);
  });
});
