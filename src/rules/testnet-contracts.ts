import type { Rule } from '../types.js';
import { KNOWN_TESTNET_CONTRACTS, PUBLIC_NETWORK_PASSPHRASE } from '../spec.js';
import { isString } from '../predicates.js';
import { contractIdsOf } from './currencies.js';

const RULE = 'soroban/testnet-contract-on-mainnet';

/**
 * Flags known Testnet contract IDs in a document configured for the Public
 * (Mainnet) network.
 *
 * Copying a staging `stellar.toml` and updating only `NETWORK_PASSPHRASE` is a
 * common deploy mistake, and the leftover Soroban addresses are invisible until
 * a wallet looks one up and finds nothing. The check runs offline, like every
 * other static rule, and only fires when the passphrase is exactly the Public
 * one — a Testnet or custom-network file is free to name Testnet contracts.
 *
 * Both places a contract ID can appear are covered: the `WEB_AUTH_CONTRACT_ID`
 * global and every `[[CURRENCIES]].contract`.
 */
export const testnetContractRules: Rule[] = [
  {
    id: RULE,
    category: 'network',
    severity: 'error',
    description: 'A Mainnet file must not name a contract that exists only on Testnet',
    run(ctx) {
      if (ctx.doc.NETWORK_PASSPHRASE !== PUBLIC_NETWORK_PASSPHRASE) return;

      const check = (contractId: string, path: string): void => {
        const label = KNOWN_TESTNET_CONTRACTS.get(contractId);
        if (label === undefined) return;

        ctx.report({
          rule: RULE,
          category: 'network',
          message: `${path} names ${label} (${contractId}), which exists only on Stellar Testnet`,
          path,
          position: ctx.locate(path),
          helpUri: 'https://developers.stellar.org/docs/networks',
          suggestion:
            'Replace it with the Mainnet contract address, or use the Testnet passphrase if this file really targets Testnet.',
        });
      };

      const auth = ctx.doc.WEB_AUTH_CONTRACT_ID;
      if (isString(auth)) check(auth, 'WEB_AUTH_CONTRACT_ID');

      for (const { id, path } of contractIdsOf(ctx.doc)) check(id, path);
    },
  },
];
