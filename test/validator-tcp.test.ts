import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createServer, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';

import {
  checkPeerPortReachability,
  DEFAULT_PROBE_TIMEOUT_MS,
  PEER_PORT_UNREACHABLE_RULE,
  probeTcpPort,
  validatorHostsOf,
} from '../src/validators/net-probe.js';
import type { RuleOverrides } from '../src/types.js';

/** A real TCP listener on an ephemeral loopback port, so probes dial real sockets. */
async function listenTcp(): Promise<{ host: string; port: number; close: () => Promise<void> }> {
  const server: Server = createServer((_req, res: ServerResponse) => {
    res.destroy(); // The probe only completes a TCP handshake, then hangs up.
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { address, port } = server.address() as AddressInfo;
  return {
    host: address,
    port,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

/** The smallest doc shape the check reads. */
function docWithHost(host: string): Record<string, unknown> {
  return { VALIDATORS: [{ ALIAS: 'au', HOST: host }] };
}

let live: { host: string; port: number; close: () => Promise<void> };

beforeAll(async () => {
  live = await listenTcp();
});

afterAll(async () => {
  await live.close();
});

describe('probeTcpPort', () => {
  it('returns true for a local TCP test server on a random port', async () => {
    await expect(probeTcpPort(live.host, live.port, 2_000)).resolves.toBe(true);
  }, 10_000);

  it('returns false — never rejects — for a closed port', async () => {
    // Port 1 on loopback is not listening in any sane environment.
    await expect(probeTcpPort('127.0.0.1', 1, 1_000)).resolves.toBe(false);
  }, 10_000);

  it('times out against a non-routable address instead of hanging', async () => {
    const started = Date.now();
    await expect(probeTcpPort('10.255.255.1', 1, 250)).resolves.toBe(false);
    expect(Date.now() - started).toBeLessThan(5_000);
  }, 10_000);
});

describe('validatorHostsOf', () => {
  it('extracts host and port from well-formed HOST entries', () => {
    const hosts = validatorHostsOf({
      VALIDATORS: [{ HOST: 'core.example.com:11625' }, { HOST: 'core-au.example.com:11625' }],
    });
    expect(hosts).toEqual([
      { host: 'core.example.com', port: 11_625, path: 'VALIDATORS[0].HOST' },
      { host: 'core-au.example.com', port: 11_625, path: 'VALIDATORS[1].HOST' },
    ]);
  });

  it('skips malformed entries, which the offline validators/host rule reports', () => {
    expect(
      validatorHostsOf({ VALIDATORS: [{ HOST: 'no-port-here' }, { HOST: 42 }, 'junk'] }),
    ).toEqual([]);
    expect(validatorHostsOf({})).toEqual([]);
  });

  it('deduplicates addresses shared by several validators', () => {
    const hosts = validatorHostsOf({
      VALIDATORS: [{ HOST: 'core.example.com:11625' }, { HOST: 'core.example.com:11625' }],
    });
    expect(hosts).toHaveLength(1);
  });
});

describe('checkPeerPortReachability', () => {
  it('reports nothing when every declared port accepts a connection', async () => {
    const doc = docWithHost(`${live.host}:${live.port}`);
    await expect(
      checkPeerPortReachability(doc, { probe: probeTcpPort, timeoutMs: 2_000 }),
    ).resolves.toEqual([]);
  }, 10_000);

  it('emits validators/peer-port-unreachable (warning) for a refused connection', async () => {
    const doc = docWithHost('127.0.0.1:1');
    const diagnostics = await checkPeerPortReachability(doc, {
      probe: probeTcpPort,
      timeoutMs: 1_000,
    });

    expect(diagnostics).toHaveLength(1);
    const finding = diagnostics[0];
    expect(finding?.rule).toBe(PEER_PORT_UNREACHABLE_RULE);
    expect(finding?.severity).toBe('warning');
    expect(finding?.category).toBe('validators');
    expect(finding?.path).toBe('VALIDATORS[0].HOST');
    expect(finding?.message).toContain('127.0.0.1:1');
    expect(finding?.suggestion).toContain('firewall');
  }, 10_000);

  it('never terminates the lint run: probe errors degrade to findings, not throws', async () => {
    const explodingProbe = async (): Promise<boolean> => {
      throw new Error('socket imploded');
    };
    const diagnostics = await checkPeerPortReachability(docWithHost('127.0.0.1:1'), {
      probe: explodingProbe,
    });
    expect(diagnostics).toHaveLength(1);
    expect(diagnostics[0]?.rule).toBe(PEER_PORT_UNREACHABLE_RULE);
  });

  it('is silent for a file without [[VALIDATORS]]', async () => {
    await expect(checkPeerPortReachability({ VERSION: '2.0.0' })).resolves.toEqual([]);
  });

  it('honours --off on the rule id, without opening a single socket', async () => {
    const rules: RuleOverrides = { [PEER_PORT_UNREACHABLE_RULE]: 'off' };
    let probed = 0;
    const countingProbe = async (): Promise<boolean> => {
      probed += 1;
      return false;
    };
    await expect(
      checkPeerPortReachability(docWithHost('127.0.0.1:1'), { rules, probe: countingProbe }),
    ).resolves.toEqual([]);
    expect(probed).toBe(0);
  });

  it('honours --error and --warn severity overrides', async () => {
    const raise: RuleOverrides = { [PEER_PORT_UNREACHABLE_RULE]: 'error' };
    const [raised] = await checkPeerPortReachability(docWithHost('127.0.0.1:1'), {
      rules: raise,
      probe: async () => false,
    });
    expect(raised?.severity).toBe('error');

    const lower: RuleOverrides = { [PEER_PORT_UNREACHABLE_RULE]: 'info' };
    const [lowered] = await checkPeerPortReachability(docWithHost('127.0.0.1:1'), {
      rules: lower,
      probe: async () => false,
    });
    expect(lowered?.severity).toBe('info');
  });

  it('probes each distinct address once and reports one finding per unreachable host', async () => {
    const doc = {
      VALIDATORS: [
        { HOST: '127.0.0.1:1' },
        { HOST: '127.0.0.1:2' },
        { HOST: '127.0.0.1:1' }, // duplicate address: probed once
      ],
    };
    const probed: string[] = [];
    const countingProbe = async (host: string, port: number): Promise<boolean> => {
      probed.push(`${host}:${port}`);
      return false;
    };
    const diagnostics = await checkPeerPortReachability(doc, { probe: countingProbe });
    expect(probed).toEqual(['127.0.0.1:1', '127.0.0.1:2']);
    expect(diagnostics.map((d) => d.path)).toEqual(['VALIDATORS[0].HOST', 'VALIDATORS[1].HOST']);
  });

  it('uses a 5-second default timeout', () => {
    expect(DEFAULT_PROBE_TIMEOUT_MS).toBe(5_000);
  });
});

describe('rule registration', () => {
  it('is discoverable by --list-rules and the severity overrides', async () => {
    const { allRules } = await import('../src/rules/index.js');
    const rule = allRules.find((r) => r.id === PEER_PORT_UNREACHABLE_RULE);
    expect(rule).toBeDefined();
    expect(rule?.severity).toBe('warning');
    expect(rule?.category).toBe('validators');
  });
});
