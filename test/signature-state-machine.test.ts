import { describe, expect, it } from 'vitest';
import {
  analyzeSignatureCombinations,
  checkSignatureStateMachine,
  SECURITY_INSUFFICIENT_THRESHOLD_PROTECTION,
  SECURITY_UNBALANCED_SIGNER_WEIGHTS,
} from '../src/security/signature-state-machine.js';

describe('signature state machine', () => {
  it('passes a well-balanced 2-of-3 scheme', () => {
    const diagnostics = checkSignatureStateMachine({
      signers: [
        { key: 'A', weight: 1 },
        { key: 'B', weight: 1 },
        { key: 'C', weight: 1 },
      ],
      thresholds: { low: 1, medium: 2, high: 2 },
    });

    expect(diagnostics).toEqual([]);
  });

  it('flags a scheme where a single signer has 100% control', () => {
    const diagnostics = checkSignatureStateMachine({
      signers: [{ key: 'A', weight: 3 }],
      thresholds: { low: 1, medium: 3, high: 3 },
    });

    expect(diagnostics.map((d) => d.rule)).toContain(SECURITY_INSUFFICIENT_THRESHOLD_PROTECTION);
  });

  it('enumerates the power set with cumulative weights', () => {
    const combinations = analyzeSignatureCombinations({
      signers: [
        { key: 'A', weight: 1 },
        { key: 'B', weight: 2 },
        { key: 'C', weight: 3 },
      ],
      thresholds: { low: 1, medium: 3, high: 6 },
    });

    // 2^3 - 1 = 7 non-empty combinations
    expect(combinations).toHaveLength(7);
    const full = combinations.find((c) => c.signatures.join(',') === 'A,B,C');
    expect(full?.weight).toBe(6);
    expect(full?.meetsHigh).toBe(true);
  });

  it('flags an unbalanced weight distribution', () => {
    const diagnostics = checkSignatureStateMachine({
      signers: [
        { key: 'A', weight: 5 },
        { key: 'B', weight: 1 },
        { key: 'C', weight: 1 },
      ],
      thresholds: { low: 1, medium: 2, high: 3 },
    });

    expect(diagnostics.map((d) => d.rule)).toContain(SECURITY_UNBALANCED_SIGNER_WEIGHTS);
  });

  it('flags an unreachable high threshold as a deadlock', () => {
    const diagnostics = checkSignatureStateMachine({
      signers: [
        { key: 'A', weight: 1 },
        { key: 'B', weight: 1 },
      ],
      thresholds: { low: 1, medium: 2, high: 5 },
    });

    expect(diagnostics.map((d) => d.rule)).toContain(SECURITY_INSUFFICIENT_THRESHOLD_PROTECTION);
  });

  it('respects rule overrides that disable a rule', () => {
    const diagnostics = checkSignatureStateMachine(
      {
        signers: [{ key: 'A', weight: 3 }],
        thresholds: { low: 1, medium: 3, high: 3 },
      },
      { rules: { [SECURITY_INSUFFICIENT_THRESHOLD_PROTECTION]: 'off' } },
    );

    expect(diagnostics).toEqual([]);
  });
});
