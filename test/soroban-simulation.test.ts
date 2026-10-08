import { describe, expect, it } from 'vitest';
import { xdr } from '@stellar/stellar-base';
import {
  EXCESSIVE_RESOURCE_RULE,
  SIMULATION_FAILED_RULE,
  buildInvokeTransaction,
  simulationRules,
  simulateContract,
} from '../src/soroban/simulation.js';

const CONTRACT = 'CACTZSQPCQSSZ5YG3PI3N7WO6JEERKEUHTPILKB4MBANF2K4D2UHKDDU';
const RPC = 'https://rpc.test';

/** An RPC stub that answers every `simulateTransaction` with `response`. */
function simulationFetch(response: Record<string, unknown>, fail?: boolean): typeof fetch {
  return (async (_url: string | URL | Request, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)) as {
      method: string;
      params: { transaction: string };
    };
    expect(body.method).toBe('simulateTransaction');
    expect(typeof body.params.transaction).toBe('string');
    return new Response(
      JSON.stringify(
        fail ? { jsonrpc: '2.0', id: 1, ...response } : { jsonrpc: '2.0', id: 1, result: response },
      ),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );
  }) as unknown as typeof fetch;
}

describe('soroban simulation sandbox (#79)', () => {
  it('builds an InvokeHostFunction transaction envelope', () => {
    const envelope = buildInvokeTransaction(CONTRACT, 'decimals', CONTRACT);
    const parsed = xdr.TransactionEnvelope.fromXDR(envelope, 'base64');
    const op = parsed.v1().tx().operations()[0]!;
    expect(op.body().switch().name).toBe('invokeHostFunction');
  });

  it('passes when every simulated call succeeds', async () => {
    const diagnostics = await simulateContract(
      CONTRACT,
      RPC,
      simulationFetch({ latestLedger: 1000, results: [], minResourceFee: '1' }),
    );
    expect(diagnostics).toEqual([]);
  });

  it('asserts soroban/simulation-failed when the host reverts the call', async () => {
    const diagnostics = await simulateContract(
      CONTRACT,
      RPC,
      simulationFetch(
        { error: { code: -32000, message: 'HostError: contract is not initialized' } },
        true,
      ),
    );
    expect(diagnostics).toContainEqual(
      expect.objectContaining({
        rule: SIMULATION_FAILED_RULE,
        severity: 'error',
        message: expect.stringContaining('HostError'),
      }),
    );
  });

  it('asserts soroban/excessive-resource-consumption on a heavy call', async () => {
    const diagnostics = await simulateContract(
      CONTRACT,
      RPC,
      simulationFetch({
        latestLedger: 1000,
        results: [],
        cost: { cpuInsns: '200000000', memBytes: '1' },
      }),
    );
    expect(diagnostics).toContainEqual(
      expect.objectContaining({ rule: EXCESSIVE_RESOURCE_RULE, severity: 'warning' }),
    );
  });

  it('honours a raised resource ceiling', async () => {
    const diagnostics = await simulateContract(
      CONTRACT,
      RPC,
      simulationFetch({
        latestLedger: 1000,
        results: [],
        cost: { cpuInsns: '200000000', memBytes: '1' },
      }),
      { maxInstructions: 500_000_000 },
    );
    expect(diagnostics).toEqual([]);
  });

  it('registers both rule definitions', () => {
    expect(simulationRules.map((r) => ({ id: r.id, severity: r.severity }))).toEqual([
      { id: SIMULATION_FAILED_RULE, severity: 'error' },
      { id: EXCESSIVE_RESOURCE_RULE, severity: 'warning' },
    ]);
  });
});
