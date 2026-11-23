import { describe, expect, it } from 'vitest';
import {
  checkCollateralGovernance,
  collateralGovernanceRules,
  collateralGovernanceRuleIds,
} from '../src/security/collateral-governance.js';

describe('checkCollateralGovernance', () => {
  it('registers both required rule ids', () => {
    expect(collateralGovernanceRuleIds).toEqual([
      'collateral/single-key-reserve-risk',
      'collateral/custody-threshold-unmet',
    ]);
  });

  it('registers rules with warning severity', () => {
    expect(collateralGovernanceRules.map((r) => ({ id: r.id, severity: r.severity }))).toEqual([
      { id: 'collateral/single-key-reserve-risk', severity: 'warning' },
      { id: 'collateral/custody-threshold-unmet', severity: 'warning' },
    ]);
  });

  it('returns empty diagnostics for document with no collateral addresses', async () => {
    const diagnostics = await checkCollateralGovernance({ CURRENCIES: [] });
    expect(diagnostics).toEqual([]);
  });

  it('returns empty diagnostics for document without CURRENCIES', async () => {
    const diagnostics = await checkCollateralGovernance({});
    expect(diagnostics).toEqual([]);
  });

  it('multi-sig reserve account passes without collateral findings', async () => {
    const doc = {
      CURRENCIES: [
        {
          collateral_addresses: ['GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY'],
        },
      ],
    };
    const mockResponse = {
      ok: true,
      json: async () => ({
        thresholds: { master_weight: 2, low_threshold: 2, medium_threshold: 2, high_threshold: 2 },
        num_signers: 3,
      }),
    };
    const diagnostics = await checkCollateralGovernance(doc, {
      fetchImpl: async () => mockResponse as unknown as Response,
    });
    expect(diagnostics).toEqual([]);
  });

  it('single key reserve account asserts collateral/single-key-reserve-risk', async () => {
    const doc = {
      CURRENCIES: [
        {
          collateral_addresses: ['GAZ3V7WDE3TADF6UQWU3TAWQPVSW6ZV3NCCW6A7UN6HUDI5WXPMLQDFY'],
        },
      ],
    };
    const mockResponse = {
      ok: true,
      json: async () => ({
        thresholds: { master_weight: 1, low_threshold: 1, medium_threshold: 1, high_threshold: 1 },
        num_signers: 1,
      }),
    };
    const diagnostics = await checkCollateralGovernance(doc, {
      fetchImpl: async () => mockResponse as unknown as Response,
    });
    const finding = diagnostics.find((d) => d.rule === 'collateral/single-key-reserve-risk');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('warning');
  });
});
