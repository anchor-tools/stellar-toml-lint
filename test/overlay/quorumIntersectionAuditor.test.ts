import { describe, expect, it } from 'vitest';
import {
  QuorumSetIntersectionAuditor,
  type QuorumSetDefinition,
  type ValidatorQuorumDefinition,
} from '../../src/overlay/quorumIntersectionAuditor.js';

describe('QuorumSetIntersectionAuditor', () => {
  const auditor = new QuorumSetIntersectionAuditor();

  describe('expandQuorumSetSlices', () => {
    it('expands a simple quorum set with threshold count', () => {
      const qSet: QuorumSetDefinition = {
        threshold: 2,
        validators: ['GA1', 'GA2', 'GA3'],
      };
      const slices = QuorumSetIntersectionAuditor.expandQuorumSetSlices(qSet);
      // combinations of 3 choose 2 = 3 slices
      expect(slices).toHaveLength(3);
      expect(slices).toContainEqual(['GA1', 'GA2']);
      expect(slices).toContainEqual(['GA1', 'GA3']);
      expect(slices).toContainEqual(['GA2', 'GA3']);
    });

    it('expands threshold percentage correctly', () => {
      const qSet: QuorumSetDefinition = {
        thresholdPercent: 67, // ceil(0.67 * 3) = 3
        validators: ['GA1', 'GA2', 'GA3'],
      };
      const slices = QuorumSetIntersectionAuditor.expandQuorumSetSlices(qSet);
      expect(slices).toHaveLength(1);
      expect(slices[0]).toEqual(['GA1', 'GA2', 'GA3']);
    });

    it('expands nested inner quorum sets', () => {
      const qSet: QuorumSetDefinition = {
        threshold: 2,
        validators: ['GA1'],
        innerQuorumSets: [
          {
            threshold: 1,
            validators: ['GB1', 'GB2'],
          },
        ],
      };
      // Total 2 elements: 'GA1' and inner. Threshold 2 means both must be satisfied.
      // Inner has threshold 1 of 2: slices are ['GB1'], ['GB2'].
      // Combined: ['GA1', 'GB1'], ['GA1', 'GB2']
      const slices = QuorumSetIntersectionAuditor.expandQuorumSetSlices(qSet);
      expect(slices).toHaveLength(2);
      expect(slices).toContainEqual(['GA1', 'GB1']);
      expect(slices).toContainEqual(['GA1', 'GB2']);
    });

    it('resolves $aliases using aliasMap', () => {
      const aliasMap = new Map([
        ['node1', 'GA_KEY_1'],
        ['node2', 'GA_KEY_2'],
      ]);
      const qSet: QuorumSetDefinition = {
        threshold: 2,
        validators: ['$node1', '$node2'],
      };
      const slices = QuorumSetIntersectionAuditor.expandQuorumSetSlices(qSet, aliasMap);
      expect(slices).toHaveLength(1);
      expect(slices[0]).toEqual(['GA_KEY_1', 'GA_KEY_2']);
    });
  });

  describe('extractQuorumSlices from stellar.toml', () => {
    it('extracts slices from [[VALIDATORS]] with explicit thresholds and validators', () => {
      const toml = `
[[VALIDATORS]]
ALIAS = "val1"
PUBLIC_KEY = "GVAL1"
THRESHOLD_PERCENT = 66
VALIDATORS = ["$val1", "$val2", "$val3"]

[[VALIDATORS]]
ALIAS = "val2"
PUBLIC_KEY = "GVAL2"
THRESHOLD_PERCENT = 66
VALIDATORS = ["$val1", "$val2", "$val3"]

[[VALIDATORS]]
ALIAS = "val3"
PUBLIC_KEY = "GVAL3"
THRESHOLD_PERCENT = 66
VALIDATORS = ["$val1", "$val2", "$val3"]
`;
      const slices = auditor.extractQuorumSlices(toml);
      expect(Object.keys(slices)).toHaveLength(3);
      expect(slices['GVAL1']).toBeDefined();
      // threshold 66% of 3 = 2 items
      // val1 includes itself plus 2 of 3
      expect(slices['GVAL1']!.length).toBeGreaterThanOrEqual(1);
      for (const slice of slices['GVAL1']!) {
        expect(slice).toContain('GVAL1');
      }
    });

    it('extracts top-level [QUORUM_SET] when validators omit custom slices', () => {
      const toml = `
[QUORUM_SET]
THRESHOLD_PERCENT = 100
VALIDATORS = ["GVAL1", "GVAL2"]

[[VALIDATORS]]
ALIAS = "val1"
PUBLIC_KEY = "GVAL1"

[[VALIDATORS]]
ALIAS = "val2"
PUBLIC_KEY = "GVAL2"
`;
      const slices = auditor.extractQuorumSlices(toml);
      expect(slices['GVAL1']).toEqual([['GVAL1', 'GVAL2']]);
      expect(slices['GVAL2']).toEqual([['GVAL1', 'GVAL2']]);
    });
  });

  describe('Minimal Quorums and Intersection Calculation', () => {
    it('detects common quorum intersection on resilient symmetric network', () => {
      // 4 nodes, threshold 3 (any 3 is a quorum slice)
      const nodes: ValidatorQuorumDefinition[] = [
        { publicKey: 'N1', threshold: 3, validators: ['N1', 'N2', 'N3', 'N4'] },
        { publicKey: 'N2', threshold: 3, validators: ['N1', 'N2', 'N3', 'N4'] },
        { publicKey: 'N3', threshold: 3, validators: ['N1', 'N2', 'N3', 'N4'] },
        { publicKey: 'N4', threshold: 3, validators: ['N1', 'N2', 'N3', 'N4'] },
      ];

      const result = auditor.audit(nodes);
      expect(result.hasQuorumIntersection).toBe(true);
      expect(result.hasSplitBrainRisk).toBe(false);
      expect(result.isFragmented).toBe(false);
      expect(result.minimalQuorums.length).toBeGreaterThan(0);
      // Every minimal quorum has size 3
      for (const q of result.minimalQuorums) {
        expect(q.length).toBe(3);
      }
      // Any two quorums of size 3 in a 4-node network must share at least 2 nodes
      for (let i = 0; i < result.minimalQuorums.length; i++) {
        for (let j = i + 1; j < result.minimalQuorums.length; j++) {
          const q1 = result.minimalQuorums[i]!;
          const q2 = result.minimalQuorums[j]!;
          const overlap = q1.filter((n) => q2.includes(n));
          expect(overlap.length).toBeGreaterThanOrEqual(2);
        }
      }
    });

    it('identifies central node in star quorum topology', () => {
      // Hub node H, spoke nodes S1, S2
      // S1 trusts {S1, H}, S2 trusts {S2, H}, H trusts {H, S1, S2} with threshold 2
      const nodes: ValidatorQuorumDefinition[] = [
        { publicKey: 'HUB', threshold: 2, validators: ['HUB', 'S1', 'S2'] },
        { publicKey: 'S1', threshold: 2, validators: ['S1', 'HUB'] },
        { publicKey: 'S2', threshold: 2, validators: ['S2', 'HUB'] },
      ];

      const result = auditor.audit(nodes);
      expect(result.hasQuorumIntersection).toBe(true);
      expect(result.allMinimalQuorumsIntersect).toBe(true);
      expect(result.intersectionNodes).toContain('HUB');
    });

    it('detects split-brain risk with two completely disjoint quorums', () => {
      // Cluster 1: A1, A2 trust only each other (threshold 2)
      // Cluster 2: B1, B2 trust only each other (threshold 2)
      const nodes: ValidatorQuorumDefinition[] = [
        { publicKey: 'A1', threshold: 2, validators: ['A1', 'A2'] },
        { publicKey: 'A2', threshold: 2, validators: ['A2', 'A1'] },
        { publicKey: 'B1', threshold: 2, validators: ['B1', 'B2'] },
        { publicKey: 'B2', threshold: 2, validators: ['B2', 'B1'] },
      ];

      const result = auditor.audit(nodes);
      expect(result.hasSplitBrainRisk).toBe(true);
      expect(result.hasQuorumIntersection).toBe(false);
      expect(result.allMinimalQuorumsIntersect).toBe(false);
      expect(result.intersectionNodes).toHaveLength(0);
      expect(result.warnings.some((w) => w.includes('Split-brain'))).toBe(true);
    });

    it('detects quorum fragmentation when nodes are isolated', () => {
      const nodes: ValidatorQuorumDefinition[] = [
        { publicKey: 'N1', threshold: 2, validators: ['N1', 'N2'] },
        { publicKey: 'N2', threshold: 2, validators: ['N2', 'N1'] },
        { publicKey: 'ISOLATED', threshold: 2, validators: ['ISOLATED', 'UNKNOWN_NODE'] },
      ];

      const result = auditor.audit(nodes);
      expect(result.isFragmented).toBe(true);
      expect(result.fragmentationDetails?.isolatedNodes).toContain('ISOLATED');
      expect(result.warnings.some((w) => w.includes('Isolated'))).toBe(true);
    });

    it('handles empty validator list gracefully', () => {
      const result = auditor.audit([]);
      expect(result.hasQuorumIntersection).toBe(false);
      expect(result.minimalQuorums).toHaveLength(0);
      expect(result.warnings).toContain('No validators declared in configuration.');
    });
  });
});
