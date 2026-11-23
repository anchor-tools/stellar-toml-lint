import { describe, expect, it } from 'vitest';
import { Keypair, Networks, StrKey, TransactionBuilder, xdr } from '@stellar/stellar-base';
import {
  MAX_ACCOUNT_SIGNERS,
  SignerRotationStateMachine,
  buildRotationEnvelope,
  formatRotationPreview,
  parseDesiredSignerState,
  parseHorizonSignerState,
  parseSignerStateFile,
  planSignerRotation,
  simulateRotationPlan,
  type AccountSignerState,
  type DesiredSignerState,
  type SignerDefinition,
} from '../../src/gitops/signerRotationStateMachine.js';

const keys = Array.from({ length: 25 }, () => Keypair.random().publicKey());
const key = (index: number): string => keys[index] ?? '';

function signer(index: number, weight = 1): SignerDefinition {
  return { key: key(index), weight, type: 'ed25519_public_key' };
}

function currentState(overrides: Partial<AccountSignerState> = {}): AccountSignerState {
  return {
    accountId: key(0),
    thresholds: { low: 1, medium: 2, high: 2, masterWeight: 1 },
    signers: [signer(1), signer(2)],
    ...overrides,
  };
}

function desiredState(overrides: Partial<DesiredSignerState> = {}): DesiredSignerState {
  return {
    thresholds: { low: 1, medium: 3, high: 3, masterWeight: 1 },
    signers: [signer(1), signer(2), signer(3), signer(4)],
    ...overrides,
  };
}

function horizonAccount(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: key(0),
    account_id: key(0),
    sequence: '123456789',
    thresholds: { low_threshold: 1, med_threshold: 2, high_threshold: 2 },
    signers: [
      { key: key(0), weight: 1, type: 'ed25519_public_key' },
      { key: key(1), weight: 1, type: 'ed25519_public_key' },
      { key: key(2), weight: 1, type: 'ed25519_public_key' },
    ],
    ...overrides,
  };
}

describe('parseHorizonSignerState', () => {
  it('reads thresholds and separates the master key from additional signers', () => {
    const state = parseHorizonSignerState(horizonAccount());
    expect(state.accountId).toBe(key(0));
    expect(state.thresholds).toEqual({ low: 1, medium: 2, high: 2, masterWeight: 1 });
    expect(state.signers.map((entry) => entry.key)).toEqual([key(1), key(2)]);
  });

  it('infers master weight when the master signer is absent', () => {
    const state = parseHorizonSignerState(
      horizonAccount({
        signers: [{ key: key(1), weight: 1, type: 'ed25519_public_key' }],
      }),
    );
    expect(state.thresholds.masterWeight).toBe(0);
  });

  it('rejects malformed account payloads', () => {
    expect(() => parseHorizonSignerState(null)).toThrow('not a JSON object');
    expect(() => parseHorizonSignerState({ thresholds: {} })).toThrow('account id');
  });
});

describe('parseDesiredSignerState / parseSignerStateFile', () => {
  it('normalizes a JSON desired state', () => {
    const desired = parseDesiredSignerState({
      account: key(0),
      thresholds: { low: 1, med: 2, high: 3, master_weight: 0 },
      signers: [{ public_key: key(1), weight: 2 }],
    });
    expect(desired.accountId).toBe(key(0));
    expect(desired.thresholds).toEqual({ low: 1, medium: 2, high: 3, masterWeight: 0 });
    expect(desired.signers).toEqual([{ key: key(1), weight: 2, type: 'ed25519_public_key' }]);
  });

  it('extracts the master key when the desired signer list includes it', () => {
    const desired = parseDesiredSignerState({
      account: key(0),
      thresholds: { low: 1, med: 2, high: 2 },
      signers: [key(0), key(1)],
    });
    expect(desired.thresholds.masterWeight).toBe(1);
    expect(desired.signers.map((entry) => entry.key)).toEqual([key(1)]);
  });

  it('parses JSON and TOML files', () => {
    const json = parseSignerStateFile(
      JSON.stringify({ signers: [key(1)], thresholds: { high: 1 } }),
      'signers.json',
    );
    expect(json.signers).toHaveLength(1);

    const toml = parseSignerStateFile(
      `[[signers]]\nkey = "${key(2)}"\nweight = 1\n[thresholds]\nlow = 1\nmed = 1\nhigh = 1\n`,
      'signers.toml',
    );
    expect(toml.signers[0]?.key).toBe(key(2));
    expect(toml.thresholds.high).toBe(1);
  });

  it('reports unreadable files clearly', () => {
    expect(() => parseSignerStateFile('')).toThrow('empty');
    expect(() => parseSignerStateFile('{ bad json', 'x.json')).toThrow('Invalid JSON');
    expect(() => parseSignerStateFile('not = [valid', 'x.toml')).toThrow(
      'Invalid signer rotation file',
    );
    expect(() => parseDesiredSignerState({ signers: [{ weight: 1 }] })).toThrow(
      'missing a signer key',
    );
  });
});

describe('planSignerRotation', () => {
  it('rotates 2-of-3 to 3-of-5 by adding signers before raising thresholds', () => {
    const plan = planSignerRotation(currentState(), desiredState());

    expect(plan.valid).toBe(true);
    expect(plan.errors).toEqual([]);
    expect(plan.operations.map((operation) => operation.signer?.key ?? 'thresholds')).toEqual([
      key(3),
      key(4),
      'thresholds',
    ]);
    expect(plan.operations[2]).toMatchObject({ medThreshold: 3, highThreshold: 3 });
    expect(plan.intermediateStates).toHaveLength(plan.operations.length);
    expect(plan.intermediateStates.every((state) => state.totalWeight >= 3)).toBe(true);
  });

  it('lowers thresholds before removing signers', () => {
    const current = currentState({
      thresholds: { low: 1, medium: 3, high: 3, masterWeight: 1 },
      signers: [signer(1), signer(2), signer(3), signer(4)],
    });
    const desired = desiredState({
      thresholds: { low: 1, medium: 2, high: 2, masterWeight: 1 },
      signers: [signer(1), signer(2)],
    });

    const plan = planSignerRotation(current, desired);
    expect(plan.valid).toBe(true);
    expect(plan.operations[0]).toMatchObject({ medThreshold: 2, highThreshold: 2 });
    expect(plan.operations.at(-1)?.signer?.weight).toBe(0);
  });

  it('disables the master key only after new signers can carry the quorum', () => {
    const desired = desiredState({
      thresholds: { low: 1, medium: 3, high: 3, masterWeight: 0 },
      signers: [signer(1), signer(2), signer(3)],
    });
    const plan = planSignerRotation(
      currentState({ thresholds: { low: 1, medium: 2, high: 2, masterWeight: 1 } }),
      desired,
    );

    expect(plan.valid).toBe(true);
    expect(plan.operations.at(-1)).toEqual({ type: 'setOptions', masterWeight: 0 });
    expect(plan.warnings.join('\n')).toContain('master key will be disabled');
  });

  it('rejects a master lockout when remaining signers cannot meet the high threshold', () => {
    const desired = desiredState({
      thresholds: { low: 1, medium: 4, high: 4, masterWeight: 0 },
      signers: [signer(1), signer(2), signer(3)],
    });
    const plan = planSignerRotation(currentState(), desired);

    expect(plan.valid).toBe(false);
    expect(plan.errors.join('\n')).toContain('master key');
    expect(plan.errors.join('\n')).toContain('lock the account');
  });

  it('handles the 20-signer limit by removing an obsolete signer before adding a replacement', () => {
    const signers = Array.from({ length: MAX_ACCOUNT_SIGNERS - 1 }, (_, index) =>
      signer(index + 1),
    );
    const current = currentState({
      thresholds: { low: 1, medium: 10, high: 10, masterWeight: 1 },
      signers,
    });
    const desired = desiredState({
      thresholds: { low: 1, medium: 10, high: 10, masterWeight: 1 },
      signers: [...signers.slice(1), signer(24)],
    });

    const plan = planSignerRotation(current, desired);
    expect(plan.valid).toBe(true);
    expect(plan.operations[0]?.signer).toMatchObject({ key: key(1), weight: 0 });
    expect(plan.operations.at(-1)?.signer).toMatchObject({ key: key(24), weight: 1 });
    expect(plan.intermediateStates.at(-1)?.signerCount).toBe(MAX_ACCOUNT_SIGNERS);
  });

  it('rejects desired states above the 20-signer maximum', () => {
    const signers = Array.from({ length: MAX_ACCOUNT_SIGNERS }, (_, index) => signer(index + 1));
    const plan = planSignerRotation(
      currentState(),
      desiredState({
        thresholds: { low: 1, medium: 1, high: 1, masterWeight: 0 },
        signers,
      }),
    );
    expect(plan.valid).toBe(false);
    expect(plan.errors.join('\n')).toContain('above the Stellar maximum');
  });

  it('supports emergency recovery signers using pre-auth and hash keys', () => {
    const preAuthKey = StrKey.encodePreAuthTx(Buffer.alloc(32, 7));
    const hashKey = StrKey.encodeSha256Hash(Buffer.alloc(32, 9));
    const desired = desiredState({
      thresholds: { low: 1, medium: 2, high: 2, masterWeight: 0 },
      signers: [
        signer(1),
        { key: preAuthKey, weight: 1, type: 'pre_auth_tx' },
        { key: hashKey, weight: 1, type: 'sha256_hash' },
      ],
    });
    const plan = planSignerRotation(currentState(), desired);
    expect(plan.valid).toBe(true);
    expect(plan.operations.some((operation) => operation.signer?.type === 'pre_auth_tx')).toBe(
      true,
    );
    expect(plan.operations.some((operation) => operation.signer?.type === 'sha256_hash')).toBe(
      true,
    );
  });

  it('warns but produces no operations when nothing changes', () => {
    const current = currentState();
    const plan = planSignerRotation(current, {
      thresholds: {
        low: current.thresholds.low,
        medium: current.thresholds.medium,
        high: current.thresholds.high,
        masterWeight: current.thresholds.masterWeight,
      },
      signers: current.signers,
    });
    expect(plan.valid).toBe(true);
    expect(plan.operations).toEqual([]);
    expect(plan.warnings.join('\n')).toContain('already matches');
  });

  it('rejects non-monotonic thresholds', () => {
    const plan = planSignerRotation(
      currentState(),
      desiredState({ thresholds: { low: 5, medium: 2, high: 1, masterWeight: 1 } }),
    );
    expect(plan.valid).toBe(false);
    expect(plan.errors.join('\n')).toContain('low <= medium <= high');
  });

  it('rejects duplicate desired signers', () => {
    const plan = planSignerRotation(
      currentState(),
      desiredState({ signers: [signer(1), signer(1)] }),
    );
    expect(plan.valid).toBe(false);
    expect(plan.errors.join('\n')).toContain('more than once');
  });

  it('raises the master weight before lowering it in a later rotation', () => {
    const current = currentState({
      thresholds: { low: 1, medium: 2, high: 2, masterWeight: 0 },
      signers: [signer(1), signer(2), signer(3)],
    });
    const desired = desiredState({
      thresholds: { low: 1, medium: 2, high: 2, masterWeight: 2 },
      signers: [signer(1), signer(2), signer(3)],
    });
    const plan = planSignerRotation(current, desired);
    expect(plan.valid).toBe(true);
    expect(plan.operations).toEqual([{ type: 'setOptions', masterWeight: 2 }]);
  });
});

describe('rotation envelope and simulation', () => {
  const account = key(0);
  const sequence = '123456789';

  it('builds a valid base64 transaction envelope', () => {
    const plan = planSignerRotation(currentState(), desiredState());
    const envelope = buildRotationEnvelope(plan, {
      sourceAccount: account,
      sequence,
      networkPassphrase: Networks.TESTNET,
    });

    const parsed = TransactionBuilder.fromXDR(envelope, Networks.TESTNET);
    expect(parsed.operations).toHaveLength(plan.operations.length);
    expect(() => xdr.TransactionEnvelope.fromXDR(envelope, 'base64')).not.toThrow();
  });

  it('refuses to build an unsafe plan', () => {
    const plan = planSignerRotation(
      currentState(),
      desiredState({ thresholds: { low: 9, medium: 9, high: 9, masterWeight: 0 } }),
    );
    expect(() => buildRotationEnvelope(plan)).toThrow('unsafe rotation');
  });

  it('simulates successfully without a remote endpoint', async () => {
    const plan = planSignerRotation(currentState(), desiredState());
    const result = await simulateRotationPlan(plan, { sourceAccount: account, sequence });
    expect(result.success).toBe(true);
    expect(result.envelopeXdr).toBeTypeOf('string');
  });

  it('returns no envelope for a no-op plan', async () => {
    const current = currentState();
    const plan = planSignerRotation(current, {
      thresholds: {
        low: 1,
        medium: 2,
        high: 2,
        masterWeight: 1,
      },
      signers: current.signers,
    });
    const result = await simulateRotationPlan(plan);
    expect(result).toEqual({ success: true });
  });

  it('reports unsafe plans without contacting a simulator', async () => {
    const plan = planSignerRotation(
      currentState(),
      desiredState({ thresholds: { low: 9, medium: 9, high: 9, masterWeight: 0 } }),
    );
    const result = await simulateRotationPlan(plan);
    expect(result.success).toBe(false);
    expect(result.error).toContain('unsafe');
  });

  it('uses an injected simulator and surfaces its failure', async () => {
    const plan = planSignerRotation(currentState(), desiredState());
    const ok = await simulateRotationPlan(plan, {
      sourceAccount: account,
      sequence,
      simulate: async () => ({ success: true }),
    });
    expect(ok.success).toBe(true);

    const failed = await simulateRotationPlan(plan, {
      sourceAccount: account,
      sequence,
      simulate: async () => ({ success: false, error: 'insufficient signatures' }),
    });
    expect(failed.success).toBe(false);
    expect(failed.error).toContain('insufficient signatures');

    const thrown = await simulateRotationPlan(plan, {
      sourceAccount: account,
      sequence,
      simulate: async () => {
        throw new Error('RPC down');
      },
    });
    expect(thrown).toMatchObject({ success: false, error: 'RPC down' });
  });

  it('calls Soroban RPC when a URL is configured', async () => {
    const plan = planSignerRotation(currentState(), desiredState());
    const bodies: unknown[] = [];
    const fetchImpl = (async (_input: string | URL | globalThis.Request, init?: RequestInit) => {
      bodies.push(JSON.parse(String(init?.body)));
      return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { ok: true } }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as unknown as typeof fetch;

    const result = await simulateRotationPlan(plan, {
      sourceAccount: account,
      sequence,
      sorobanRpcUrl: 'https://soroban.example',
      fetchImpl,
    });
    expect(result.success).toBe(true);
    expect(bodies[0]).toMatchObject({ method: 'simulateTransaction' });
  });

  it('surfaces Soroban RPC HTTP, JSON-RPC, and simulation errors', async () => {
    const plan = planSignerRotation(currentState(), desiredState());

    const http = await simulateRotationPlan(plan, {
      sourceAccount: account,
      sequence,
      sorobanRpcUrl: 'https://soroban.example',
      fetchImpl: (async () => new Response('nope', { status: 503 })) as unknown as typeof fetch,
    });
    expect(http.error).toContain('HTTP 503');

    const rpc = await simulateRotationPlan(plan, {
      sourceAccount: account,
      sequence,
      sorobanRpcUrl: 'https://soroban.example',
      fetchImpl: (async () =>
        new Response(JSON.stringify({ error: { message: 'bad request' } }), {
          status: 200,
        })) as unknown as typeof fetch,
    });
    expect(rpc.error).toBe('bad request');

    const simulated = await simulateRotationPlan(plan, {
      sourceAccount: account,
      sequence,
      sorobanRpcUrl: 'https://soroban.example',
      fetchImpl: (async () =>
        new Response(JSON.stringify({ result: { error: 'would fail' } }), {
          status: 200,
        })) as unknown as typeof fetch,
    });
    expect(simulated.error).toBe('would fail');

    const thrown = await simulateRotationPlan(plan, {
      sourceAccount: account,
      sequence,
      sorobanRpcUrl: 'https://soroban.example',
      fetchImpl: (async () => {
        throw new Error('network down');
      }) as unknown as typeof fetch,
    });
    expect(thrown.error).toBe('network down');
  });

  it('reports envelope construction failures', async () => {
    const plan = planSignerRotation(currentState(), desiredState());
    const result = await simulateRotationPlan(plan, {
      sourceAccount: 'not-an-account',
      sequence,
    });
    expect(result.success).toBe(false);
    expect(result.error).toBeTypeOf('string');
  });
});

describe('formatRotationPreview', () => {
  it('renders operations, safety warnings, and the simulation reminder', () => {
    const plan = planSignerRotation(currentState(), desiredState());
    const preview = formatRotationPreview(plan);
    expect(preview).toContain('Signer rotation preview');
    expect(preview).toContain('Operations (3)');
    expect(preview).toContain('Simulate before signing');
    expect(preview).not.toContain('UNSAFE');
  });

  it('renders errors prominently for unsafe plans', () => {
    const plan = planSignerRotation(
      currentState(),
      desiredState({ thresholds: { low: 9, medium: 9, high: 9, masterWeight: 0 } }),
    );
    const preview = formatRotationPreview(plan);
    expect(preview).toContain('UNSAFE');
    expect(preview).toContain('ERROR');
  });

  it('renders an empty operation list', () => {
    const current = currentState();
    const plan = planSignerRotation(current, {
      thresholds: { low: 1, medium: 2, high: 2, masterWeight: 1 },
      signers: current.signers,
    });
    expect(formatRotationPreview(plan)).toContain('(none)');
  });
});

describe('SignerRotationStateMachine facade', () => {
  it('wires ingestion, parsing, planning, simulation, and preview together', async () => {
    const machine = new SignerRotationStateMachine();
    const current = machine.ingestHorizonAccount(horizonAccount(), key(0));
    const desired = machine.parseDesiredState({
      thresholds: { low: 1, medium: 3, high: 3, masterWeight: 1 },
      signers: [key(1), key(2), key(3), key(4)],
    });
    const plan = machine.plan(current, desired);
    expect(plan.valid).toBe(true);
    expect(machine.preview(plan)).toContain('Operations');
    const simulation = await machine.simulate(plan, {
      sourceAccount: key(0),
      sequence: '1',
    });
    expect(simulation.success).toBe(true);
    expect(machine.buildEnvelope(plan, { sourceAccount: key(0), sequence: '1' })).toBeTypeOf(
      'string',
    );
  });

  it('honours a custom signer cap', () => {
    const machine = new SignerRotationStateMachine({ maxSigners: 3 });
    const plan = machine.plan(currentState(), desiredState());
    expect(plan.valid).toBe(false);
    expect(plan.errors.join('\n')).toContain('maximum of 3');
  });
});
