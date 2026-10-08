import { describe, expect, it } from 'vitest';
import { checkUpgradeSimulator } from '../src/validators/upgrade-simulator.js';

function documentedValidators(validators: unknown[] = []): Record<string, unknown> {
  return {
    HORIZON_URL: 'https://horizon.example.com',
    VALIDATORS: validators,
  };
}

function fetchResponse(horizonBody: unknown, crawlerBody: unknown): typeof fetch {
  return (async (url: string | URL | globalThis.Request) => {
    const urlString = url.toString();
    if (urlString.includes('horizon')) {
      return new Response(JSON.stringify(horizonBody), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }
    return new Response(JSON.stringify(crawlerBody), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }) as unknown as typeof fetch;
}

const VALIDATOR = {
  ALIAS: 'core-au',
  PUBLIC_KEY: 'GCM5YCQPFIW4ICBPPSKACX56ZTGG6KZ7A53JGUWWAFRZW462YFIK4BZS',
  HOST: 'core-au.anchor.example:11625',
};

describe('checkUpgradeSimulator', () => {
  it('passes successfully when node matches current & upcoming protocol', async () => {
    const doc = documentedValidators([VALIDATOR]);
    const horizon = {
      current_protocol_version: 20,
      core_supported_protocol_version: 21,
    };
    const telemetry = {
      nodes: [
        {
          id: VALIDATOR.PUBLIC_KEY,
          active: true,
          versionStr: 'stellar-core 21.0.0 (4eb83337380a29ad0907f4e32196ce97b8dc7649)',
          upgradeSchedule: '2024-01-30T15:00:00Z',
        },
      ],
    };

    const diagnostics = await checkUpgradeSimulator(doc, fetchResponse(horizon, telemetry));
    expect(diagnostics).toEqual([]);
  });

  it('asserts diagnostic validators/binary-outdated-for-upgrade when node is lagging protocol version', async () => {
    const doc = documentedValidators([VALIDATOR]);
    const horizon = {
      current_protocol_version: 20,
      core_supported_protocol_version: 21,
    };
    const telemetry = {
      nodes: [
        {
          id: VALIDATOR.PUBLIC_KEY,
          active: true,
          versionStr: 'stellar-core 20.1.0 (4eb83337380a29ad0907f4e32196ce97b8dc7649)',
        },
      ],
    };

    const diagnostics = await checkUpgradeSimulator(doc, fetchResponse(horizon, telemetry));
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.rule).toBe('validators/binary-outdated-for-upgrade');
    expect(diagnostics[0]?.severity).toBe('error');
    expect(diagnostics[0]?.path).toBe('VALIDATORS[0].PUBLIC_KEY');
    expect(diagnostics[0]?.message).toContain('does not support upcoming protocol 21');
  });

  it('asserts diagnostic validators/missing-upgrade-vote-schedule when missing schedule', async () => {
    const doc = documentedValidators([VALIDATOR]);
    const horizon = {
      current_protocol_version: 20,
      core_supported_protocol_version: 21,
    };
    const telemetry = {
      nodes: [
        {
          id: VALIDATOR.PUBLIC_KEY,
          active: true,
          versionStr: 'stellar-core 21.0.0 (4eb83337380a29ad0907f4e32196ce97b8dc7649)',
          // Missing upgradeSchedule
        },
      ],
    };

    const diagnostics = await checkUpgradeSimulator(doc, fetchResponse(horizon, telemetry));
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.rule).toBe('validators/missing-upgrade-vote-schedule');
    expect(diagnostics[0]?.severity).toBe('warning');
    expect(diagnostics[0]?.path).toBe('VALIDATORS[0].PUBLIC_KEY');
    expect(diagnostics[0]?.message).toContain('has not scheduled a vote');
  });

  it('returns no diagnostics if there is no upcoming upgrade', async () => {
    const doc = documentedValidators([VALIDATOR]);
    const horizon = {
      current_protocol_version: 21,
      core_supported_protocol_version: 21,
    };
    const telemetry = {
      nodes: [
        {
          id: VALIDATOR.PUBLIC_KEY,
          active: true,
          versionStr: 'stellar-core 20.1.0 (4eb83337380a29ad0907f4e32196ce97b8dc7649)',
        },
      ],
    };

    const diagnostics = await checkUpgradeSimulator(doc, fetchResponse(horizon, telemetry));
    expect(diagnostics).toEqual([]);
  });
});
