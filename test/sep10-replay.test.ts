import { describe, expect, it } from 'vitest';
import {
  checkSep10Replay,
  sep10ReplayRules,
  sep10ReplayRuleIds,
  shannonEntropy,
} from '../src/protocols/sep10-replay.js';

describe('checkSep10Replay', () => {
  it('registers all three required rule ids', () => {
    expect(sep10ReplayRuleIds).toEqual([
      'sep10/reused-nonce-detected',
      'sep10/insufficient-nonce-entropy',
      'sep10/replay-attack-vulnerability',
    ]);
  });

  it('registers rules with error severity', () => {
    expect(sep10ReplayRules.map((r) => ({ id: r.id, severity: r.severity }))).toEqual([
      { id: 'sep10/reused-nonce-detected', severity: 'error' },
      { id: 'sep10/insufficient-nonce-entropy', severity: 'error' },
      { id: 'sep10/replay-attack-vulnerability', severity: 'error' },
    ]);
  });

  it('returns an array when called', async () => {
    const diagnostics = await checkSep10Replay('', '');
    expect(Array.isArray(diagnostics)).toBe(true);
  });
});

describe('shannonEntropy', () => {
  it('returns 0 for empty buffer', () => {
    expect(shannonEntropy(Buffer.alloc(0))).toBe(0);
  });

  it('returns higher entropy for more random data', () => {
    const uniform = Buffer.from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    const constant = Buffer.alloc(16, 0);
    expect(shannonEntropy(uniform)).toBeGreaterThan(shannonEntropy(constant));
  });
});
