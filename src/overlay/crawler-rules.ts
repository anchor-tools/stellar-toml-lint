import type { Rule } from '../types.js';

export const OVERLAY_ISOLATED_NODE_ZERO_PEERS = 'overlay/isolated-node-zero-peers';
export const OVERLAY_LOW_PEER_COUNT = 'overlay/low-peer-count';
export const ISOLATED_NODE_ZERO_PEERS_RULE = OVERLAY_ISOLATED_NODE_ZERO_PEERS;
export const LOW_PEER_COUNT_RULE = OVERLAY_LOW_PEER_COUNT;

export const overlayCrawlerRules: Rule[] = [
  {
    id: OVERLAY_ISOLATED_NODE_ZERO_PEERS,
    category: 'network',
    severity: 'error',
    description: 'Overlay validators must report at least one reachable peer',
    run() {},
  },
  {
    id: OVERLAY_LOW_PEER_COUNT,
    category: 'network',
    severity: 'warning',
    description: 'Overlay validators should report more than five peers',
    run() {},
  },
];

export const crawlerRules = overlayCrawlerRules;
export const overlayCrawlerRuleIds: readonly string[] = overlayCrawlerRules.map((rule) => rule.id);
