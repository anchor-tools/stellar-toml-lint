import { nativeToScVal } from '@stellar/stellar-base';
import { describe, expect, it } from 'vitest';
import { checkSep41Contracts } from '../src/network-checks.js';

const CONTRACT = 'CACTZSQPCQSSZ5YG3PI3N7WO6JEERKEUHTPILKB4MBANF2K4D2UHKDDU';
const NETWORK = 'Test SDF Network ; September 2015';

function doc(displayDecimals: number): Record<string, unknown> {
  return {
    NETWORK_PASSPHRASE: NETWORK,
    CURRENCIES: [{ code: 'TOKEN', contract: CONTRACT, display_decimals: displayDecimals }],
  };
}

/** A successful `decimals()` simulation response carrying the given value. */
function responseReturning(decimals: number): Response {
  const retval = nativeToScVal(decimals, { type: 'u32' }).toXDR('base64');
  return new Response(JSON.stringify({ result: { retval } }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

/** An RPC that answers `decimals()` with the given value. */
function rpcReturning(decimals: number): typeof fetch {
  return (async () => responseReturning(decimals)) as unknown as typeof fetch;
}

/** An RPC whose simulation fails: no such contract, or no `decimals` entrypoint. */
const rpcNotAToken = (async () =>
  new Response(
    JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      error: { code: -32603, message: 'HostError: MissingValue' },
    }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  )) as unknown as typeof fetch;

/** An unreachable RPC. */
const rpcOffline = (async () => {
  throw new Error('Network offline');
}) as unknown as typeof fetch;

describe('SEP-41 contract checks', () => {
  it('is silent for an existing SEP-41 token with matching decimals', async () => {
    let url = '';
    const fetchImpl = (async (input: string | URL | globalThis.Request) => {
      url = input.toString();
      return responseReturning(6);
    }) as unknown as typeof fetch;

    const diagnostics = await checkSep41Contracts(doc(6), fetchImpl);
    expect(diagnostics).toEqual([]);
    expect(url).toBe('https://soroban-testnet.stellar.org');
  });

  it('warns when the contract is missing or does not implement SEP-41', async () => {
    const diagnostics = await checkSep41Contracts(doc(6), rpcNotAToken);

    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: 'currencies/sep41-token',
        severity: 'warning',
        path: 'CURRENCIES[0].contract',
      }),
    );
  });

  it('warns when display_decimals disagrees with the contract', async () => {
    const diagnostics = await checkSep41Contracts(doc(6), rpcReturning(7));

    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]).toMatchObject({
      rule: 'currencies/display-decimals-contract-mismatch',
      severity: 'warning',
      path: 'CURRENCIES[0].display_decimals',
      message: 'CURRENCIES[0].display_decimals is 6, but the contract reports 7',
    });
  });

  it('degrades to a warning when the RPC is unreachable', async () => {
    const diagnostics = await checkSep41Contracts(doc(6), rpcOffline);

    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: 'currencies/sep41-unverified',
        severity: 'warning',
        path: 'CURRENCIES[0].contract',
      }),
    );
  });

  it('never queries ids that are not checksum-valid contract ids', async () => {
    let calls = 0;
    const countingFetch = (async () => {
      calls++;
      return responseReturning(6);
    }) as unknown as typeof fetch;

    const broken = {
      NETWORK_PASSPHRASE: NETWORK,
      CURRENCIES: [{ code: 'X', contract: 'not-a-contract', display_decimals: 2 }],
    };
    expect(await checkSep41Contracts(broken, countingFetch)).toEqual([]);
    expect(calls).toBe(0);
  });

  it('honours an --off override', async () => {
    const diagnostics = await checkSep41Contracts(doc(6), rpcNotAToken, {
      rules: { 'currencies/sep41-token': 'off' },
    });

    expect(diagnostics).toEqual([]);
  });
});
