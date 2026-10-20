import { describe, expect, it } from 'vitest';
import {
  COLLATERAL_RESERVE_DEFICIT_RULE,
  UNSUPPORTED_COLLATERAL_CHAIN_RULE,
  checkProofOfReserve,
  collateralAccountsOf,
  compareCollateralReserve,
} from '../../src/security/proof-of-reserve.js';

const ISSUER = 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN';
const ETH_ADDRESS = '0x1111111111111111111111111111111111111111';
const EVM_RPC = 'https://rpc.example';
const HORIZON = 'https://horizon.example';

function doc(addresses: string[], extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    CURRENCIES: [
      {
        code: 'USDC',
        issuer: ISSUER,
        is_unlimited: true,
        collateral_addresses: addresses,
        ...extra,
      },
    ],
  };
}

function chain(reserveWei: bigint, supply = '100.0000000'): typeof fetch {
  return (async (input: string | URL | globalThis.Request, init?: RequestInit) => {
    const url = String(input);
    if (url.includes('/assets')) {
      return new Response(
        JSON.stringify({
          _embedded: { records: [{ amount: supply, asset_code: 'USDC', asset_issuer: ISSUER }] },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }

    const body = JSON.parse(String(init?.body ?? '{}')) as {
      method?: string;
      params?: unknown[];
    };
    if (body.method === 'eth_getBalance') {
      return new Response(
        JSON.stringify({ jsonrpc: '2.0', id: 1, result: `0x${reserveWei.toString(16)}` }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }
    if (body.method === 'eth_call') {
      return new Response(
        JSON.stringify({ jsonrpc: '2.0', id: 1, result: `0x${reserveWei.toString(16)}` }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }
    throw new Error(`unexpected RPC method ${body.method}`);
  }) as unknown as typeof fetch;
}

const OPTIONS = { evmRpcUrl: EVM_RPC, horizonUrl: HORIZON };

describe('proof-of-reserve auditor', () => {
  it('parses prefixed and inferred collateral accounts', () => {
    const accounts = collateralAccountsOf(
      doc(['ethereum:0x1111111111111111111111111111111111111111', 'bitcoin:bc1qexample']),
    );
    expect(accounts.map((account) => account.chain)).toEqual(['ethereum', 'bitcoin']);
  });

  it('passes when the reserve covers circulating supply', async () => {
    const diagnostics = await checkProofOfReserve(
      doc([ETH_ADDRESS]),
      chain(100n * 10n ** 18n),
      OPTIONS,
    );
    expect(diagnostics).toEqual([]);
  });

  it('detects a reserve deficit', async () => {
    const diagnostics = await checkProofOfReserve(
      doc([ETH_ADDRESS]),
      chain(99n * 10n ** 18n),
      OPTIONS,
    );
    const finding = diagnostics.find((d) => d.rule === COLLATERAL_RESERVE_DEFICIT_RULE);
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('error');
    expect(finding?.path).toBe('CURRENCIES[0]');
  });

  it('accepts options in the second argument', async () => {
    const diagnostics = await checkProofOfReserve(doc([ETH_ADDRESS]), {
      ...OPTIONS,
      fetchImpl: chain(100n * 10n ** 18n),
    });
    expect(diagnostics).toEqual([]);
  });

  it('detects a one-wei shortfall without floating-point drift', async () => {
    const diagnostics = await checkProofOfReserve(
      doc([ETH_ADDRESS]),
      chain(100n * 10n ** 18n - 1n),
      OPTIONS,
    );
    expect(diagnostics.map((d) => d.rule)).toContain(COLLATERAL_RESERVE_DEFICIT_RULE);
  });

  it('warns for an unsupported collateral chain', async () => {
    const diagnostics = await checkProofOfReserve(
      doc(['not-a-known-chain-address']),
      chain(0n),
      OPTIONS,
    );
    const finding = diagnostics.find((d) => d.rule === UNSUPPORTED_COLLATERAL_CHAIN_RULE);
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('warning');
  });

  it('compares reserve and supply with different decimal scales', () => {
    expect(
      compareCollateralReserve({
        reserve: 10n,
        reserveDecimals: 8,
        supply: 1n,
        supplyDecimals: 7,
      }),
    ).toEqual([]);
    expect(
      compareCollateralReserve({
        reserve: 1n,
        reserveDecimals: 9,
        supply: 1n,
        supplyDecimals: 7,
      }).map((d) => d.rule),
    ).toContain(COLLATERAL_RESERVE_DEFICIT_RULE);
  });
});
