import { describe, expect, it } from 'vitest';
import { StrKey } from '@stellar/stellar-base';
import { allRules } from '../src/rules/index.js';
import type { NetworkTarget } from '../src/soroban/multi-network.js';
import {
  checkMultiNetworkDeployments,
  checkNetworkConsistency,
  horizonPassphraseMismatch,
  multiNetworkRules,
  NETWORK_TARGETS,
  networkTargetFor,
  probeContractPresence,
} from '../src/soroban/multi-network.js';

const ONLY_TESTNET = 'soroban/contract-only-on-testnet';
const MISMATCH = 'soroban/network-mismatch';

const MAINNET = 'Public Global Stellar Network ; September 2015';
const TESTNET = 'Test SDF Network ; September 2015';
const UNKNOWN_NETWORK = 'Private Anchor Net ; March 2026';

const TOKEN = StrKey.encodeContract(Buffer.alloc(32, 1));
const AUTH = StrKey.encodeContract(Buffer.alloc(32, 2));

function urlFor(name: 'mainnet' | 'testnet' | 'futurenet'): string {
  const target = NETWORK_TARGETS.find((one) => one.name === name);
  if (target === undefined) throw new Error(`no target for ${name}`);
  return target.rpcUrl;
}

function document(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    NETWORK_PASSPHRASE: MAINNET,
    CURRENCIES: [{ code: 'USD', contract: TOKEN }],
    ...overrides,
  };
}

/**
 * Soroban RPC answers keyed by network. `deployed` returns a live instance
 * entry, `absent` a valid but empty result, and `unreachable` a transport
 * failure — the three outcomes a real run can hit.
 */
function rpc(answers: Partial<Record<'mainnet' | 'testnet' | 'futurenet', string>>): {
  fetchImpl: typeof fetch;
  calls: string[];
} {
  const calls: string[] = [];
  const fetchImpl = (async (input: string | URL | Request) => {
    const url = String(input);
    calls.push(url);
    const answer = Object.entries(answers).find(([name]) => urlFor(name as 'mainnet') === url)?.[1];

    if (answer === undefined || answer === 'unreachable') {
      throw new TypeError('fetch failed');
    }
    if (answer === 'absent') {
      return new Response(JSON.stringify({ result: { latestLedger: 100, entries: [] } }), {
        status: 200,
      });
    }
    return new Response(
      JSON.stringify({
        result: { latestLedger: 100, entries: [{ liveUntilLedgerSeq: 500_000 }] },
      }),
      { status: 200 },
    );
  }) as unknown as typeof fetch;

  return { fetchImpl, calls };
}

describe('soroban multi-network deployment verifier', () => {
  it('knows the three public networks by passphrase', () => {
    expect(networkTargetFor(MAINNET)?.name).toBe('mainnet');
    expect(networkTargetFor(TESTNET)?.name).toBe('testnet');
    expect(networkTargetFor(UNKNOWN_NETWORK)).toBeUndefined();
  });

  it('distinguishes an absent contract from an RPC that did not answer', async () => {
    const mainnet: NetworkTarget = {
      name: 'mainnet',
      passphrase: MAINNET,
      rpcUrl: urlFor('mainnet'),
    };

    expect(await probeContractPresence(TOKEN, mainnet, rpc({ mainnet: 'absent' }).fetchImpl)).toBe(
      'absent',
    );
    expect(
      await probeContractPresence(TOKEN, mainnet, rpc({ mainnet: 'deployed' }).fetchImpl),
    ).toBe('deployed');
    expect(
      await probeContractPresence(TOKEN, mainnet, rpc({ mainnet: 'unreachable' }).fetchImpl),
    ).toBe('unknown');
  });

  it('passes when the declared network has the contract', async () => {
    const { fetchImpl } = rpc({ mainnet: 'deployed', testnet: 'deployed' });
    expect(await checkMultiNetworkDeployments(document(), fetchImpl)).toEqual([]);
  });

  it('flags a token that exists only on Testnet when the file is Mainnet', async () => {
    const { fetchImpl, calls } = rpc({ mainnet: 'absent', testnet: 'deployed' });
    const diagnostics = await checkMultiNetworkDeployments(document(), fetchImpl);

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      rule: ONLY_TESTNET,
      severity: 'error',
      category: 'network',
      path: 'CURRENCIES[0].contract',
    });
    expect(diagnostics[0]?.message).toContain(TOKEN);
    // The declared network is probed before the others, and the comparison stops
    // as soon as it knows.
    expect(calls[0]).toBe(urlFor('mainnet'));
  });

  it('reports a general network mismatch when the file is not Mainnet', async () => {
    const { fetchImpl } = rpc({ mainnet: 'deployed', testnet: 'absent' });
    const diagnostics = await checkMultiNetworkDeployments(
      document({ NETWORK_PASSPHRASE: TESTNET }),
      fetchImpl,
    );

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({ rule: MISMATCH, severity: 'error' });
    expect(diagnostics[0]?.message).toContain('absent from testnet');
    expect(diagnostics[0]?.message).toContain('live on mainnet');
  });

  it('says nothing when the contract is on no network at all', async () => {
    const { fetchImpl } = rpc({ mainnet: 'absent', testnet: 'absent', futurenet: 'absent' });
    expect(await checkMultiNetworkDeployments(document(), fetchImpl)).toEqual([]);
  });

  it('says nothing while the endpoints are unreachable', async () => {
    const { fetchImpl } = rpc({ mainnet: 'unreachable', testnet: 'unreachable' });
    expect(await checkMultiNetworkDeployments(document(), fetchImpl)).toEqual([]);
  });

  it('skips files whose network it does not recognise', async () => {
    const { fetchImpl, calls } = rpc({ mainnet: 'absent' });
    const diagnostics = await checkMultiNetworkDeployments(
      document({ NETWORK_PASSPHRASE: UNKNOWN_NETWORK }),
      fetchImpl,
    );

    expect(diagnostics).toEqual([]);
    expect(calls).toEqual([]);
  });

  it('checks the auth contract alongside the currency contracts', async () => {
    const { fetchImpl } = rpc({ mainnet: 'absent', testnet: 'deployed' });
    const diagnostics = await checkMultiNetworkDeployments(
      document({ WEB_AUTH_CONTRACT_ID: AUTH, CURRENCIES: [] }),
      fetchImpl,
    );

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({ path: 'WEB_AUTH_CONTRACT_ID', rule: ONLY_TESTNET });
  });

  it('honours severity overrides', async () => {
    const { fetchImpl } = rpc({ mainnet: 'absent', testnet: 'deployed' });

    expect(
      await checkMultiNetworkDeployments(document(), fetchImpl, {
        rules: { [ONLY_TESTNET]: 'off' },
      }),
    ).toEqual([]);

    const downgraded = await checkMultiNetworkDeployments(document(), fetchImpl, {
      rules: { [ONLY_TESTNET]: 'warning' },
    });
    expect(downgraded[0]).toMatchObject({ severity: 'warning' });
  });

  it('compares against a caller-supplied network set', async () => {
    const { fetchImpl, calls } = rpc({ mainnet: 'absent' });
    const onlyFuturenet = NETWORK_TARGETS.filter((one) => one.name === 'futurenet');
    const diagnostics = await checkMultiNetworkDeployments(document(), fetchImpl, {
      targets: onlyFuturenet,
    });

    expect(diagnostics).toEqual([]);
    expect(calls).toEqual([urlFor('mainnet'), urlFor('futurenet')]);
  });

  it('accepts probed deployments from a caller that already has them', async () => {
    const { fetchImpl, calls } = rpc({});
    const diagnostics = await checkMultiNetworkDeployments(document(), fetchImpl, {
      deployments: { [TOKEN]: { mainnet: 'absent', testnet: 'deployed' } },
    });

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({ rule: ONLY_TESTNET });
    expect(calls).toEqual([]);
  });

  describe('HORIZON_URL agreement', () => {
    it('flags a testnet Horizon under a mainnet passphrase', () => {
      const diagnostics = horizonPassphraseMismatch(
        document({ HORIZON_URL: 'https://horizon-testnet.stellar.org' }),
      );

      expect(diagnostics).toHaveLength(1);
      expect(diagnostics[0]).toMatchObject({ rule: MISMATCH, path: 'HORIZON_URL' });
    });

    it('passes a file that agrees with itself', () => {
      expect(
        horizonPassphraseMismatch(document({ HORIZON_URL: 'https://horizon.stellar.org' })),
      ).toEqual([]);
      expect(
        horizonPassphraseMismatch({
          NETWORK_PASSPHRASE: TESTNET,
          HORIZON_URL: 'https://horizon-testnet.stellar.org',
        }),
      ).toEqual([]);
    });

    it('leaves endpoints it cannot classify alone', () => {
      expect(
        horizonPassphraseMismatch(document({ HORIZON_URL: 'https://horizon.anchor.internal' })),
      ).toEqual([]);
      expect(horizonPassphraseMismatch(document({ HORIZON_URL: 'not a url' }))).toEqual([]);
      expect(horizonPassphraseMismatch(document())).toEqual([]);
    });
  });

  it('runs the offline check even when the RPC is down', async () => {
    const { fetchImpl } = rpc({ mainnet: 'unreachable', testnet: 'unreachable' });
    const diagnostics = await checkNetworkConsistency(
      document({ HORIZON_URL: 'https://horizon-testnet.stellar.org' }),
      fetchImpl,
    );

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({ rule: MISMATCH, path: 'HORIZON_URL' });
  });

  it('registers its rules so --list-rules and --off know their ids', () => {
    const ids = allRules.map((rule) => rule.id);
    for (const rule of multiNetworkRules) expect(ids).toContain(rule.id);
  });
});
