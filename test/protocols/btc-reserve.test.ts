import { describe, expect, it } from 'vitest';
import {
  BtcReserveUtxoAuditor,
  auditBtcReserves,
  btcReserveRuleIds,
  formatBtc,
  parseBtcAddress,
  type Utxo,
  type UtxoProvider,
} from '../../src/protocols/btcReserveAuditor.js';

const ISSUER = 'GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY';
const P2PKH = '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa';
const P2SH = '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy';
const P2WPKH = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4';
const P2WSH = 'bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3';
const P2TR = 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0';
const TESTNET = 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx';

const doc = (addresses: unknown[], extra: Record<string, unknown> = {}) => ({
  NETWORK_PASSPHRASE: 'Public Global Stellar Network ; September 2015',
  CURRENCIES: [
    { code: 'USDC', issuer: ISSUER },
    {
      code: 'BTC',
      issuer: ISSUER,
      anchor_asset_type: 'crypto',
      anchor_asset: 'BTC',
      ...extra,
      collateral_addresses: addresses,
    },
  ],
});

const utxo = (value: number, confirmations: number, extra: Partial<Utxo> = {}): Utxo => ({
  txid: `${value}-${confirmations}`.padEnd(64, '0'),
  vout: 0,
  value,
  confirmations,
  ...extra,
});

const provider =
  (map: Record<string, Utxo[]>): UtxoProvider =>
  async (address) =>
    map[address] ?? [];

/** 1 BTC of supply = 10^7 stroops. */
const supply = (stroops: bigint) => async () => stroops;

const rules = (r: { diagnostics: { rule: string }[] }): string[] =>
  r.diagnostics.map((d) => d.rule).sort();

describe('parseBtcAddress', () => {
  it('accepts every standard address type with a valid checksum', async () => {
    expect(await parseBtcAddress(P2PKH)).toEqual({ type: 'p2pkh', network: 'mainnet' });
    expect(await parseBtcAddress(P2SH)).toEqual({ type: 'p2sh', network: 'mainnet' });
    expect(await parseBtcAddress(P2WPKH)).toEqual({ type: 'p2wpkh', network: 'mainnet' });
    expect(await parseBtcAddress(P2WPKH.toUpperCase())).toEqual({
      type: 'p2wpkh',
      network: 'mainnet',
    });
    expect(await parseBtcAddress(P2WSH)).toEqual({ type: 'p2wsh', network: 'mainnet' });
    expect(await parseBtcAddress(P2TR)).toEqual({ type: 'p2tr', network: 'mainnet' });
    expect(await parseBtcAddress(TESTNET)).toEqual({ type: 'p2wpkh', network: 'testnet' });
  });

  it('rejects bad checksums, mixed case, wrong encodings and junk', async () => {
    for (const bad of [
      '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb',
      'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5',
      'bc1qw508d6qejxtdg4y5r3zarvary0C5xw7kv8f3t4',
      // v1 program encoded with bech32 instead of bech32m (BIP-350 negative vector).
      'bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx',
      'ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9',
      '0OIl',
      '',
      'GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY',
    ]) {
      expect(await parseBtcAddress(bad), bad).toBeUndefined();
    }
  });
});

describe('BtcReserveUtxoAuditor', () => {
  it('registers rule ids', () => {
    expect(btcReserveRuleIds).toContain('btcreserve/reserve-deficit');
  });

  it('formats satoshis exactly', () => {
    expect(formatBtc(150000000n)).toBe('1.50000000');
    expect(formatBtc(-546n)).toBe('-0.00000546');
  });

  it('validates addresses offline without any lookups', async () => {
    let calls = 0;
    const counting: UtxoProvider = async () => {
      calls++;
      return [];
    };
    const r = await auditBtcReserves(doc([P2PKH, 'not-an-address', 7, TESTNET]), fetch, {
      utxoProvider: counting,
    });
    expect(rules(r)).toEqual([
      'btcreserve/invalid-address',
      'btcreserve/invalid-address',
      'btcreserve/network-mismatch',
    ]);
    expect(calls).toBe(0);
  });

  it('allows testnet addresses for a testnet file', async () => {
    const r = await auditBtcReserves({
      ...doc([TESTNET]),
      NETWORK_PASSPHRASE: 'Test SDF Network ; September 2015',
    });
    expect(r.diagnostics).toEqual([]);
  });

  it('warns when a BTC asset declares no collateral addresses', async () => {
    const r = await auditBtcReserves(doc([]));
    expect(rules(r)).toEqual(['btcreserve/no-reserve-addresses']);
  });

  it('passes fully confirmed reserves that cover the supply', async () => {
    const r = await auditBtcReserves(doc([P2WPKH, P2TR]), fetch, {
      probe: true,
      utxoProvider: provider({ [P2WPKH]: [utxo(60000000, 10)], [P2TR]: [utxo(40000000, 6)] }),
      supplyProvider: supply(10000000n),
    });
    expect(r.diagnostics).toEqual([]);
    expect(r.reports[0]).toMatchObject({ confirmedSats: 100000000n, deltaSats: 0n });
  });

  it('excludes unconfirmed and shallow outputs and flags the resulting deficit', async () => {
    const r = await auditBtcReserves(doc([P2WPKH]), fetch, {
      probe: true,
      utxoProvider: provider({
        [P2WPKH]: [utxo(50000000, 6), utxo(30000000, 5), utxo(20000000, 0)],
      }),
      supplyProvider: supply(10000000n),
    });
    expect(rules(r)).toEqual(['btcreserve/reserve-deficit', 'btcreserve/unconfirmed-excluded']);
    expect(r.reports[0]).toMatchObject({
      confirmedSats: 50000000n,
      unconfirmedSats: 50000000n,
      deltaSats: -50000000n,
    });
    const deficit = r.diagnostics.find((d) => d.rule === 'btcreserve/reserve-deficit');
    expect(deficit?.message).toContain('0.50000000 BTC (50000000 sats)');
  });

  it('computes exact satoshi-to-stroop deltas', async () => {
    // 1 stroop needs 10 sats: 99,999,999 sats cannot cover 10,000,000 stroops.
    const r = await auditBtcReserves(doc([P2PKH]), fetch, {
      probe: true,
      utxoProvider: provider({ [P2PKH]: [utxo(99999999, 100)] }),
      supplyProvider: supply(10000000n),
    });
    expect(r.reports[0]?.deltaSats).toBe(-1n);
    expect(rules(r)).toEqual(['btcreserve/reserve-deficit']);
  });

  it('does not count dust unless asked, and reports it', async () => {
    const opts = {
      probe: true,
      utxoProvider: provider({ [P2SH]: [utxo(10000000, 6), utxo(545, 6), utxo(300, 50)] }),
      supplyProvider: supply(1000000n),
    };
    const r = await auditBtcReserves(doc([P2SH]), fetch, opts);
    expect(rules(r)).toEqual(['btcreserve/dust-utxos']);
    expect(r.reports[0]?.confirmedSats).toBe(10000000n);
    const counted = await auditBtcReserves(doc([P2SH]), fetch, { ...opts, countDust: true });
    expect(counted.reports[0]?.confirmedSats).toBe(10000845n);
  });

  it('does not count confirmed outputs being swept by an unconfirmed high-fee spend', async () => {
    const r = await auditBtcReserves(doc([P2WSH]), fetch, {
      probe: true,
      utxoProvider: provider({ [P2WSH]: [utxo(100000000, 500, { spentInMempool: true })] }),
      supplyProvider: supply(10000000n),
    });
    expect(rules(r)).toEqual([
      'btcreserve/pending-sweep',
      'btcreserve/reserve-deficit',
      'btcreserve/unconfirmed-excluded',
    ]);
  });

  it('honours a stricter confirmation depth', async () => {
    const r = await auditBtcReserves(doc([P2WPKH]), fetch, {
      probe: true,
      minConfirmations: 100,
      utxoProvider: provider({ [P2WPKH]: [utxo(100000000, 99)] }),
      supplyProvider: supply(0n),
    });
    expect(rules(r)).toEqual(['btcreserve/unconfirmed-excluded']);
  });

  it('skips reconciliation when a lookup fails', async () => {
    const r = await new BtcReserveUtxoAuditor(fetch, {
      probe: true,
      utxoProvider: async () => {
        throw new Error('electrum timeout');
      },
      supplyProvider: supply(10000000n),
    }).audit(doc([P2WPKH]));
    expect(rules(r)).toEqual(['btcreserve/lookup-failed']);
    expect(r.reports[0]?.deltaSats).toBeUndefined();
  });

  it('reads Esplora UTXOs and the Horizon supply by default', async () => {
    const seen: string[] = [];
    const fetchImpl = (async (url: string) => {
      seen.push(url);
      if (url.endsWith('/blocks/tip/height')) return new Response('1000');
      if (url.includes('/utxo')) {
        return new Response(
          JSON.stringify([
            { txid: 'a', vout: 0, value: 70000000, status: { confirmed: true, block_height: 990 } },
            { txid: 'b', vout: 1, value: 30000000, status: { confirmed: true, block_height: 996 } },
            { txid: 'c', vout: 0, value: 5000000, status: { confirmed: false } },
          ]),
        );
      }
      return new Response(
        JSON.stringify({
          _embedded: {
            records: [
              {
                balances: {
                  authorized: '0.9000000',
                  authorized_to_maintain_liabilities: '0.0000000',
                  unauthorized: '0.0000000',
                },
                claimable_balances_amount: '0.0500000',
                liquidity_pools_amount: '0.0500000',
                contracts_amount: '0.0000000',
              },
            ],
          },
        }),
      );
    }) as unknown as typeof fetch;
    const r = await auditBtcReserves(doc([P2WPKH], {}), fetchImpl, {
      probe: true,
      esploraUrl: 'https://esplora.example/api',
    });
    expect(seen[0]).toBe('https://esplora.example/api/blocks/tip/height');
    expect(seen.at(-1)).toContain('https://horizon.stellar.org/assets?asset_code=BTC');
    // 990 -> 11 confirmations, 996 -> 5 confirmations (shallow), c is mempool.
    expect(r.reports[0]).toMatchObject({
      confirmedSats: 70000000n,
      unconfirmedSats: 35000000n,
      supplyStroops: 10000000n,
      deltaSats: -30000000n,
    });
  });

  it('honours rule overrides', async () => {
    const r = await auditBtcReserves(doc([]), fetch, {
      rules: { 'btcreserve/no-reserve-addresses': 'off' },
    });
    expect(r.diagnostics).toEqual([]);
  });
});
