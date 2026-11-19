import { describe, expect, it } from 'vitest';
import {
  SolanaEscrowInvariantVerifier,
  base58Decode,
  isSolanaAddress,
  solanaEscrowRuleIds,
  verifySolanaBridges,
} from '../../src/bridges/solanaEscrowVerifier.js';

const ISSUER = 'GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY';
const MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
const PROGRAM = 'worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth';
const ESCROW = 'So11111111111111111111111111111111111111112';
const TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
const HORIZON = 'https://horizon.example.com';
const SOLANA = 'https://solana.example.com';

const doc = (bridge: Record<string, unknown> = {}): Record<string, unknown> => ({
  HORIZON_URL: HORIZON,
  CURRENCIES: [
    {
      code: 'USDS',
      issuer: ISSUER,
      solana_bridge: {
        spl_mint: MINT,
        escrow_program: PROGRAM,
        escrow_token_account: ESCROW,
        rpc: SOLANA,
        ...bridge,
      },
    },
  ],
});

interface Escrow {
  amount?: string;
  decimals?: number;
  mint?: string;
  owner?: string;
  missing?: boolean;
}

/** Mock Solana JSON-RPC node and Horizon `/assets`. */
function network(escrow: Escrow, supply = '1000.0000000'): typeof fetch {
  return (async (url: string, init?: RequestInit) => {
    if (url.startsWith(HORIZON)) {
      const record = {
        balances: {
          authorized: supply,
          authorized_to_maintain_liabilities: '0',
          unauthorized: '0',
        },
        claimable_balances_amount: '0.0000000',
        liquidity_pools_amount: '0.0000000',
        contracts_amount: '0.0000000',
      };
      return new Response(JSON.stringify({ _embedded: { records: [record] } }));
    }
    const { method, id } = JSON.parse(String(init?.body));
    const result =
      method === 'getAccountInfo'
        ? {
            value: escrow.missing
              ? null
              : {
                  owner: escrow.owner ?? TOKEN_PROGRAM,
                  data: { parsed: { info: { mint: escrow.mint ?? MINT } } },
                },
          }
        : { value: { amount: escrow.amount ?? '1000000000000', decimals: escrow.decimals ?? 9 } };
    return new Response(JSON.stringify({ jsonrpc: '2.0', id, result }));
  }) as unknown as typeof fetch;
}

const rules = (r: { diagnostics: { rule: string }[] }): string[] =>
  r.diagnostics.map((d) => d.rule);
const probe = { probe: true, retryDelayMs: 0 };

describe('SolanaEscrowInvariantVerifier', () => {
  it('registers rule ids', () => {
    expect(solanaEscrowRuleIds).toContain('solbridge/reserve-deficit');
  });

  it('decodes base58 and validates 32-byte addresses', () => {
    expect(base58Decode('11111111111111111111111111111111')).toEqual(new Uint8Array(32));
    expect(base58Decode('0OIl')).toBeUndefined();
    for (const a of [MINT, PROGRAM, ESCROW, TOKEN_PROGRAM]) expect(isSolanaAddress(a)).toBe(true);
    expect(isSolanaAddress('abc')).toBe(false);
    expect(isSolanaAddress(42)).toBe(false);
  });

  it('is silent without bridge declarations', async () => {
    expect((await verifySolanaBridges({ CURRENCIES: [{ code: 'X' }] })).diagnostics).toEqual([]);
  });

  it('rejects malformed configuration offline', async () => {
    const r = await verifySolanaBridges(doc({ spl_mint: '0xdeadbeef' }));
    expect(rules(r)).toEqual(['solbridge/invalid-config']);
    expect(r.diagnostics[0]?.path).toBe('CURRENCIES[0].solana_bridge');
    const r2 = await verifySolanaBridges(doc({ rpc: 'http://insecure' }));
    expect(rules(r2)).toEqual(['solbridge/invalid-config']);
    const r3 = await verifySolanaBridges({ CURRENCIES: [{ code: 'X', solana_bridge: 'nope' }] });
    expect(rules(r3)).toEqual(['solbridge/invalid-config']);
  });

  it('passes when locked SPL tokens cover the Stellar supply (9 vs 7 decimals)', async () => {
    const r = await verifySolanaBridges(doc(), network({ amount: '1000000000000' }), probe);
    expect(r.diagnostics).toEqual([]);
    expect(r.bridges[0]).toMatchObject({ locked: '1000', minted: '1000', surplus: '0' });
  });

  it('flags a deficit of a single stroop', async () => {
    // 999.9999999 locked at 9 decimals vs 1000 minted at 7 decimals.
    const r = await verifySolanaBridges(doc(), network({ amount: '999999999900' }), probe);
    expect(rules(r)).toEqual(['solbridge/reserve-deficit']);
    expect(r.diagnostics[0]?.message).toContain('deficit 0.0000001');
    expect(r.bridges[0]?.surplus).toBe('-0.0000001');
  });

  it('does not count sub-stroop SPL dust as a deficit', async () => {
    const r = await verifySolanaBridges(doc(), network({ amount: '1000000000001' }), probe);
    expect(r.diagnostics).toEqual([]);
    expect(r.bridges[0]?.surplus).toBe('0.000000001');
  });

  it('handles source tokens with fewer decimals than Stellar', async () => {
    // 6-decimal SPL token: 1000.000000 locked vs 1000.0000001 minted.
    const r = await verifySolanaBridges(
      doc(),
      network({ amount: '1000000000', decimals: 6 }, '1000.0000001'),
      probe,
    );
    expect(rules(r)).toEqual(['solbridge/reserve-deficit']);
  });

  it('flags an escrow holding the wrong mint or not owned by SPL Token', async () => {
    const wrongMint = await verifySolanaBridges(doc(), network({ mint: PROGRAM }), probe);
    expect(rules(wrongMint)).toEqual(['solbridge/escrow-mismatch']);
    const wrongOwner = await verifySolanaBridges(doc(), network({ owner: PROGRAM }), probe);
    expect(rules(wrongOwner)).toEqual(['solbridge/escrow-mismatch']);
    const missing = await verifySolanaBridges(doc(), network({ missing: true }), probe);
    expect(rules(missing)).toEqual(['solbridge/escrow-mismatch']);
  });

  it('warns on malformed balances and unreachable RPC', async () => {
    const malformed = await verifySolanaBridges(doc(), network({ amount: '-5' }), probe);
    expect(rules(malformed)).toEqual(['solbridge/rpc-unavailable']);
    const rpcError = (async () =>
      new Response(
        JSON.stringify({ jsonrpc: '2.0', id: 1, error: { code: -32005, message: 'busy' } }),
      )) as unknown as typeof fetch;
    const r = await verifySolanaBridges(doc(), rpcError, probe);
    expect(rules(r)).toEqual(['solbridge/rpc-unavailable']);
    expect(r.diagnostics[0]?.message).toContain('busy');
  });

  it('warns when Horizon is unavailable and accepts provided supplies', async () => {
    const solanaOnly = network({});
    const noHorizon = (async (url: string, init?: RequestInit) =>
      url.startsWith(HORIZON)
        ? new Response('down', { status: 503 })
        : solanaOnly(url, init)) as unknown as typeof fetch;
    const r = await verifySolanaBridges(doc(), noHorizon, probe);
    expect(rules(r)).toEqual(['solbridge/supply-unavailable']);
    const given = await new SolanaEscrowInvariantVerifier(noHorizon, {
      ...probe,
      supplies: { [`USDS:${ISSUER}`]: '1500' },
    }).verify(doc());
    expect(rules(given)).toEqual(['solbridge/reserve-deficit']);
  });

  it('does not query the network without probe', async () => {
    let calls = 0;
    const counting = (async () => {
      calls++;
      return new Response('{}');
    }) as unknown as typeof fetch;
    await verifySolanaBridges(doc(), counting);
    expect(calls).toBe(0);
  });
});
