import { describe, expect, it } from 'vitest';
import {
  analyzeOverlayTopology,
  checkOverlayTopology,
  OVERLAY_HIGH_TOPOLOGICAL_DISTANCE,
} from '../../src/overlay/topology-analyzer.js';

describe('overlay topology analyzer', () => {
  it('flags a node separated from Tier-1 by five hops', async () => {
    const chain = [
      'validator.example:11625',
      'peer-1.example:11625',
      'peer-2.example:11625',
      'peer-3.example:11625',
      'peer-4.example:11625',
      'core.example:11625',
    ];
    const adjacency: Record<string, string[]> = {};
    for (let index = 0; index < chain.length - 1; index++) {
      adjacency[chain[index] as string] = [chain[index + 1] as string];
    }
    adjacency[chain[chain.length - 1] as string] = [];

    const analysis = analyzeOverlayTopology(adjacency, ['core.example:11625']);
    expect(analysis.distances['validator.example:11625']).toBe(5);

    const diagnostics = await checkOverlayTopology(
      {
        VALIDATORS: [
          { HOST: 'validator.example:11625' },
          { HOST: 'core.example:11625', TIER_1: true },
        ],
      },
      {
        crawl: async () => ({
          seeds: ['validator.example:11625', 'core.example:11625'],
          visited: chain,
          peers: [],
          adjacency,
          bidirectionalPeers: [],
          errors: {},
        }),
      },
    );

    expect(diagnostics.map((diagnostic) => diagnostic.rule)).toContain(
      OVERLAY_HIGH_TOPOLOGICAL_DISTANCE,
    );
  });
});
