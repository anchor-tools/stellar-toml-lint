import { describe, expect, it } from 'vitest';
import {
  optimizeThresholds,
  SECURITY_USELESS_SIGNER_DETECTED,
  checkThresholdOptimizer,
} from '../../src/security/threshold-optimizer.js';

const signers = [
  { key: 'A', weight: 1 },
  { key: 'B', weight: 2 },
  { key: 'C', weight: 2 },
  { key: 'D', weight: 3 },
  { key: 'E', weight: 5 },
  { key: 'F', weight: 0 },
];

describe('threshold optimizer', () => {
  it('finds exact minimal coalitions and flags a useless signer', () => {
    const result = optimizeThresholds({
      accountId: 'GACCOUNT',
      signers,
      thresholds: { low: 2, medium: 6, high: 10 },
    });

    expect(result.coalitions.medium).toEqual(
      expect.arrayContaining([
        { keys: ['A', 'B', 'D'], weight: 6 },
        { keys: ['A', 'C', 'D'], weight: 6 },
        { keys: ['B', 'C', 'D'], weight: 7 },
        { keys: ['A', 'E'], weight: 6 },
        { keys: ['B', 'E'], weight: 7 },
        { keys: ['C', 'E'], weight: 7 },
        { keys: ['D', 'E'], weight: 8 },
      ]),
    );
    expect(result.dummySigners).toContain('F');
  });

  it('audits the supplied account without requiring a live Horizon request', async () => {
    const diagnostics = await checkThresholdOptimizer(
      { SIGNING_KEY: 'GACCOUNT' },
      {
        accounts: [
          {
            accountId: 'GACCOUNT',
            role: 'SIGNING_KEY',
            signers,
            thresholds: { low: 2, medium: 6, high: 10 },
          },
        ],
      },
    );

    expect(diagnostics.map((diagnostic) => diagnostic.rule)).toContain(
      SECURITY_USELESS_SIGNER_DETECTED,
    );
  });
});
