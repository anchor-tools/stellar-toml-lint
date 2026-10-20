import { describe, expect, it } from 'vitest';
import {
  checkValidatorDnsDiscovery,
  VALIDATORS_DNS_SRV_TARGET_UNREACHABLE,
} from '../../src/validators/dns-discovery.js';

function resolver(target: string) {
  return {
    resolveSrv: async () => [{ name: target, port: 11625, priority: 10, weight: 5 }],
    resolveTxt: async () => [['stellar-core=validator.example:11625']],
  };
}

describe('validator DNS discovery', () => {
  it('accepts a valid SRV target matching a declared validator host', async () => {
    const diagnostics = await checkValidatorDnsDiscovery(
      { VALIDATORS: [{ HOST: 'validator.example:11625' }] },
      {
        resolver: resolver('validator.example.'),
        probe: async () => true,
      },
    );

    expect(diagnostics).toEqual([]);
  });

  it('reports an SRV target that cannot be reached', async () => {
    const diagnostics = await checkValidatorDnsDiscovery(
      { VALIDATORS: [{ HOST: 'dead.example:11625' }] },
      {
        resolver: resolver('dead.example.'),
        probe: async () => false,
      },
    );

    expect(diagnostics.map((diagnostic) => diagnostic.rule)).toContain(
      VALIDATORS_DNS_SRV_TARGET_UNREACHABLE,
    );
  });
});
