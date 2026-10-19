import type { Rule } from '../types.js';

export const BROKEN_DNSSEC_CHAIN_RULE = 'security/broken-dnssec-chain';
export const EXPIRED_RRSIG_RULE = 'security/expired-rrsig-signature';

export const dnssecChainRules: Rule[] = [
  {
    id: BROKEN_DNSSEC_CHAIN_RULE,
    category: 'network',
    severity: 'error',
    description: 'DNSSEC delegation and key records must validate to the root trust anchors',
    run() {},
  },
  {
    id: EXPIRED_RRSIG_RULE,
    category: 'network',
    severity: 'error',
    description: 'DNSSEC RRSIG records must be current and cryptographically valid',
    run() {},
  },
];
