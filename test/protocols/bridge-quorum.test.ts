import { describe, expect, it } from 'vitest';
import {
  BridgeQuorumAuditor,
  auditBridgeQuorum,
  bridgeQuorumRuleIds,
  requiredThreshold,
  rotationContinuity,
} from '../../src/bridges/bridgeQuorumAuditor.js';
import { Keypair } from '@stellar/stellar-base';

const keys = (n: number, offset = 0): string[] =>
  Array.from({ length: n }, (_, i) =>
    Keypair.fromRawEd25519Seed(Buffer.alloc(32, i + 1 + offset)).publicKey(),
  );

const bridge = (patch: Record<string, unknown>): Record<string, unknown> => ({
  BRIDGES: [{ NAME: 'main', RELAYER_KEYS: keys(6), THRESHOLD: 4, ...patch }],
});
const rules = async (doc: Record<string, unknown>): Promise<string[]> =>
  (await auditBridgeQuorum(doc)).diagnostics.map((d) => d.rule);

describe('threshold maths', () => {
  it('computes the 2/3 supermajority with integers', () => {
    expect([1, 3, 4, 6, 7, 10].map(requiredThreshold)).toEqual([1, 2, 3, 4, 5, 7]);
  });

  it('measures rotation continuity', () => {
    const a = keys(6);
    expect(rotationContinuity(a, a)).toEqual({ retained: 6, continuous: true });
    expect(rotationContinuity(a, [...a.slice(0, 4), ...keys(2, 50)]).continuous).toBe(true);
    expect(rotationContinuity(a, [...a.slice(0, 3), ...keys(3, 50)]).continuous).toBe(false);
  });
});

describe('BridgeQuorumAuditor', () => {
  it('registers rule ids', () => {
    expect(bridgeQuorumRuleIds).toContain('bridgequorum/below-supermajority');
  });

  it('accepts a compliant 4-of-6 quorum (only the staking advisory remains)', async () => {
    const r = await auditBridgeQuorum(bridge({}));
    expect(r.diagnostics.map((d) => d.rule)).toEqual(['bridgequorum/missing-staking']);
    expect(r.bridges.main).toEqual({ relayers: 6, threshold: 4, required: 4, faultTolerance: 1 });
  });

  it('warns below the supermajority and errors on a minority threshold', async () => {
    const warn = await auditBridgeQuorum(bridge({ RELAYER_KEYS: keys(7), THRESHOLD: 4 }));
    expect(
      warn.diagnostics.find((d) => d.rule === 'bridgequorum/below-supermajority')?.severity,
    ).toBe('warning');
    const bad = await auditBridgeQuorum(bridge({ RELAYER_KEYS: keys(2), THRESHOLD: 1 }));
    expect(bad.diagnostics.map((d) => d.rule)).toContain('bridgequorum/minority-threshold');
    expect(bad.diagnostics.map((d) => d.rule)).toContain('bridgequorum/small-validator-set');
  });

  it('rejects out-of-range or non-integer thresholds', async () => {
    for (const THRESHOLD of [0, 7, 2.5, '4', undefined]) {
      expect(await rules(bridge({ THRESHOLD }))).toContain('bridgequorum/invalid-threshold');
    }
  });

  it('flags invalid and duplicate relayer keys, and counts duplicates once', async () => {
    const k = keys(4);
    const r = await auditBridgeQuorum(bridge({ RELAYER_KEYS: [...k, k[0], 'nope'], THRESHOLD: 3 }));
    expect(r.diagnostics.map((d) => d.rule).sort()).toEqual([
      'bridgequorum/duplicate-relayer',
      'bridgequorum/invalid-relayer-key',
      'bridgequorum/missing-staking',
    ]);
    expect(r.bridges.main?.relayers).toBe(4);
  });

  it('errors when RELAYER_KEYS is malformed', async () => {
    expect(await rules(bridge({ RELAYER_KEYS: 'abc' }))).toEqual([
      'bridgequorum/invalid-relayer-key',
    ]);
  });

  it('warns about an abrupt relayer set rotation', async () => {
    const old = keys(6);
    const abrupt = bridge({
      RELAYER_KEYS: [...old.slice(0, 2), ...keys(4, 60)],
      PREVIOUS_RELAYER_KEYS: old,
    });
    expect(await rules(abrupt)).toContain('bridgequorum/abrupt-rotation');
    const staged = bridge({
      RELAYER_KEYS: [...old.slice(0, 5), ...keys(1, 60)],
      PREVIOUS_RELAYER_KEYS: old,
    });
    expect(await rules(staged)).not.toContain('bridgequorum/abrupt-rotation');
  });

  describe('staking evidence', () => {
    const relayers = keys(4);
    const doc = (extra: Record<string, unknown> = {}): Record<string, unknown> =>
      bridge({
        RELAYER_KEYS: relayers,
        THRESHOLD: 3,
        STAKING_CONTRACT: 'CSTAKE',
        MIN_STAKE: '1000',
        ...extra,
      });
    const bonds = (amount: string): Record<string, string> =>
      Object.fromEntries(relayers.map((k) => [k, amount]));

    it('passes with bonded stake and slashing conditions', async () => {
      const r = await auditBridgeQuorum(doc(), fetch, {
        evidence: { main: { bonds: bonds('1500.5'), slashing: [{ condition: 'double-sign' }] } },
      });
      expect(r.diagnostics).toEqual([]);
    });

    it('flags missing slashing and unbonded or under-bonded relayers', async () => {
      const partial = {
        ...bonds('1000'),
        [relayers[0] as string]: '10',
        [relayers[1] as string]: '0',
      };
      delete (partial as Record<string, string>)[relayers[2] as string];
      const r = await auditBridgeQuorum(doc(), fetch, {
        evidence: { main: { bonds: partial, slashing: [] } },
      });
      const found = r.diagnostics.map((d) => d.rule);
      expect(found).toContain('bridgequorum/missing-slashing');
      expect(found.filter((x) => x === 'bridgequorum/insufficient-stake')).toHaveLength(3);
    });

    it('fetches evidence only when probing', async () => {
      let calls = 0;
      const fetchImpl = (async () => {
        calls++;
        return new Response(JSON.stringify({ bonds: bonds('2000'), slashing: ['x'] }));
      }) as unknown as typeof fetch;
      const d = doc({ STAKING_EVIDENCE_URL: 'https://evidence.example.com/stake.json' });
      expect((await auditBridgeQuorum(d, fetchImpl)).diagnostics).toEqual([]);
      expect(calls).toBe(0);
      expect((await auditBridgeQuorum(d, fetchImpl, { probe: true })).diagnostics).toEqual([]);
      expect(calls).toBe(1);
    });

    it('reports unreadable evidence without throwing', async () => {
      const failing = (async () => {
        throw new Error('ECONNREFUSED');
      }) as unknown as typeof fetch;
      const d = doc({ STAKING_EVIDENCE_URL: 'https://evidence.example.com/stake.json' });
      const r = await new BridgeQuorumAuditor(failing, { probe: true }).audit(d);
      expect(r.diagnostics.map((x) => x.rule)).toEqual(['bridgequorum/evidence-unavailable']);
      const http = await auditBridgeQuorum(
        doc({ STAKING_EVIDENCE_URL: 'http://x.example.com' }),
        failing,
        { probe: true },
      );
      expect(http.diagnostics[0]?.rule).toBe('bridgequorum/evidence-unavailable');
      const notJson = (async () =>
        new Response('<html>', { status: 200 })) as unknown as typeof fetch;
      const r2 = await auditBridgeQuorum(d, notJson, { probe: true });
      expect(r2.diagnostics[0]?.rule).toBe('bridgequorum/evidence-unavailable');
    });

    it('honours overrides', async () => {
      const r = await auditBridgeQuorum(bridge({}), fetch, {
        rules: { 'bridgequorum/missing-staking': 'off' },
      });
      expect(r.diagnostics).toEqual([]);
    });
  });
});
