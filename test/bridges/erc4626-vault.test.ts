import { describe, expect, it } from 'vitest';
import {
  Erc4626VaultAuditor,
  auditErc4626Vaults,
  erc4626RuleIds,
  erc4626Selectors,
} from '../../src/bridges/erc4626VaultAuditor.js';

const ISSUER = 'GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY';
const VAULT = '0x2222222222222222222222222222222222222222';
const ASSET = '0x3333333333333333333333333333333333333333';
const RPC = 'https://rpc.example.com';
const HORIZON = 'https://horizon.example.com';
const E18 = 10n ** 18n;

const doc = (
  vault: Record<string, unknown> = {},
  extra: unknown[] = [],
): Record<string, unknown> => ({
  HORIZON_URL: HORIZON,
  CURRENCIES: [
    {
      code: 'yUSD',
      issuer: ISSUER,
      collateral_vaults: [
        { chain: 'base', rpc: RPC, vault: VAULT, shares: '1000000', ...vault },
        ...extra,
      ],
    },
  ],
});

interface VaultState {
  /** Underlying (6 decimals) per whole share (18 decimals). */
  pricePerShare: bigint;
  totalAssets?: bigint;
  /** Overrides convertToAssets for the held shares, to simulate broken accounting. */
  heldAssets?: bigint;
}

const word = (v: bigint): string => `0x${v.toString(16).padStart(64, '0')}`;

/** Mock ERC-4626 vault (18-decimal shares over a 6-decimal asset) plus Horizon. */
function network(state: VaultState, supply = '1000000'): typeof fetch {
  return (async (url: string, init?: RequestInit) => {
    if (url.startsWith(HORIZON)) {
      return new Response(JSON.stringify({ _embedded: { records: [{ amount: supply }] } }));
    }
    const { params, id } = JSON.parse(String(init?.body));
    const { to, data } = params[0] as { to: string; data: string };
    let result: bigint;
    if (data === erc4626Selectors.decimals) result = to === VAULT ? 18n : 6n;
    else if (data === erc4626Selectors.asset) result = BigInt(ASSET);
    else if (data === erc4626Selectors.totalAssets)
      result = state.totalAssets ?? 5_000_000n * 10n ** 6n;
    else if (data.startsWith(erc4626Selectors.convertToAssets as string)) {
      const shares = BigInt(`0x${data.slice(10)}`);
      result =
        shares !== E18 && state.heldAssets !== undefined
          ? state.heldAssets
          : (shares * state.pricePerShare) / E18;
    } else {
      return new Response(
        JSON.stringify({ jsonrpc: '2.0', id, error: { code: -32000, message: 'revert' } }),
      );
    }
    return new Response(JSON.stringify({ jsonrpc: '2.0', id, result: word(result) }));
  }) as unknown as typeof fetch;
}

const rules = (r: { diagnostics: { rule: string }[] }): string[] =>
  r.diagnostics.map((d) => d.rule);
const probe = { probe: true, retryDelayMs: 0 };

describe('Erc4626VaultAuditor', () => {
  it('registers rule ids', () => {
    expect(erc4626RuleIds).toContain('erc4626/insufficient-nav');
  });

  it('is silent without collateral vaults', async () => {
    expect((await auditErc4626Vaults({ CURRENCIES: [{ code: 'X' }] })).diagnostics).toEqual([]);
  });

  it('validates declarations offline', async () => {
    const bad = await auditErc4626Vaults(doc({ vault: 'vault' }));
    expect(rules(bad)).toEqual(['erc4626/invalid-vault']);
    const shares = await auditErc4626Vaults(doc({ shares: '-1' }));
    expect(rules(shares)).toEqual(['erc4626/invalid-vault']);
    const price = await auditErc4626Vaults(doc({ share_price: 'one' }));
    expect(rules(price)).toEqual(['erc4626/invalid-vault']);
    const tolerance = await auditErc4626Vaults(doc({ tolerance_bps: -3 }));
    expect(rules(tolerance)).toEqual(['erc4626/invalid-vault']);
    const chain = await auditErc4626Vaults(doc({ chain: 'mars', rpc: undefined }));
    expect(rules(chain)).toEqual(['erc4626/invalid-vault']);
    const notArray = await auditErc4626Vaults({
      CURRENCIES: [{ code: 'X', collateral_vaults: 'v' }],
    });
    expect(rules(notArray)).toEqual(['erc4626/invalid-vault']);
  });

  it('skips vaults that declare another standard', async () => {
    const r = await auditErc4626Vaults(doc({ standard: 'erc20', vault: 'x' }));
    expect(r.diagnostics).toEqual([]);
    expect(r.vaults).toEqual([]);
  });

  it('passes a standard 1:1 vault and reports NAV coverage', async () => {
    const r = await auditErc4626Vaults(doc(), network({ pricePerShare: 1_000_000n }), probe);
    expect(r.diagnostics).toEqual([]);
    expect(r.vaults[0]).toMatchObject({
      underlying: ASSET,
      assets: '1000000',
      sharePrice: '1',
      totalAssets: '5000000',
    });
    expect(r.nav[0]).toMatchObject({ currency: 'yUSD', nav: '1000000', coverage: '100%' });
  });

  it('tracks a yielding vault and flags a stale declared share price', async () => {
    const r = await auditErc4626Vaults(
      doc({ share_price: '1.0' }),
      network({ pricePerShare: 1_042_500n }),
      probe,
    );
    expect(rules(r)).toEqual(['erc4626/share-price-drift']);
    expect(r.diagnostics[0]?.message).toContain('1.0425');
    expect(r.nav[0]?.coverage).toBe('104.25%');
  });

  it('accepts a declared share price within tolerance', async () => {
    const r = await auditErc4626Vaults(
      doc({ share_price: '1.04', tolerance_bps: 50 }),
      network({ pricePerShare: 1_042_500n }),
      probe,
    );
    expect(r.diagnostics).toEqual([]);
  });

  it('flags a depegged vault whose NAV no longer covers the supply', async () => {
    const r = await auditErc4626Vaults(doc(), network({ pricePerShare: 930_000n }), probe);
    expect(rules(r).sort()).toEqual(['erc4626/insufficient-nav', 'erc4626/share-price-below-par']);
    expect(r.diagnostics.find((d) => d.rule === 'erc4626/insufficient-nav')?.message).toContain(
      '93%',
    );
  });

  it('never rounds NAV up to cover a fractional shortfall', async () => {
    // 0.333333 assets per share: 1,000,000 shares redeem for 333,333 against 333,333.333333.
    const r = await auditErc4626Vaults(
      doc(),
      network({ pricePerShare: 333_333n }, '333333.333333'),
      probe,
    );
    expect(r.vaults[0]?.assets).toBe('333333');
    expect(rules(r)).toContain('erc4626/insufficient-nav');
  });

  it('flags held shares that redeem for more than totalAssets', async () => {
    const r = await auditErc4626Vaults(
      doc(),
      network({ pricePerShare: 1_000_000n, heldAssets: 6_000_000n * 10n ** 6n }),
      probe,
    );
    expect(rules(r)).toContain('erc4626/inconsistent-accounting');
  });

  it('sums NAV across several vaults for one currency', async () => {
    const r = await auditErc4626Vaults(
      doc({ shares: '600000' }, [{ chain: 'base', rpc: RPC, vault: VAULT, shares: '400000' }]),
      network({ pricePerShare: 1_000_000n }),
      probe,
    );
    expect(r.vaults).toHaveLength(2);
    expect(r.nav[0]?.nav).toBe('1000000');
    expect(r.diagnostics).toEqual([]);
  });

  it('warns on RPC failures and skips NAV for that currency', async () => {
    const down = (async () => new Response('', { status: 502 })) as unknown as typeof fetch;
    const r = await auditErc4626Vaults(doc(), down, probe);
    expect(rules(r)).toEqual(['erc4626/rpc-unavailable']);
    expect(r.nav).toEqual([]);
  });

  it('rejects share amounts finer than the vault decimals', async () => {
    const state = network({ pricePerShare: 1_000_000n });
    const sixDecimalVault = (async (url: string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body ?? '{}'));
      if (body.params?.[0]?.data === erc4626Selectors.decimals) {
        return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: word(6n) }));
      }
      return state(url, init);
    }) as unknown as typeof fetch;
    const r = await auditErc4626Vaults(doc({ shares: '1.1234567' }), sixDecimalVault, probe);
    expect(rules(r)).toEqual(['erc4626/invalid-vault']);
    expect(r.diagnostics[0]?.message).toContain('6 decimals');
  });

  it('warns when the supply is unavailable and honours overrides', async () => {
    const r = await new Erc4626VaultAuditor(network({ pricePerShare: 930_000n }, 'bad'), {
      ...probe,
      rules: { 'erc4626/share-price-below-par': 'off' },
    }).audit(doc());
    expect(rules(r)).toEqual(['erc4626/supply-unavailable']);
  });
});
