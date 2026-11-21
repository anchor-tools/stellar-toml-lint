import { describe, expect, it } from 'vitest';
import { Keypair, xdr } from '@stellar/stellar-base';
import {
  ScpBallotTracer,
  DEFAULT_STALL_TIMEOUT_MS,
} from '../../src/overlay/scpBallotTracer.js';

describe('ScpBallotTracer', () => {
  const kp1 = Keypair.random();
  const kp2 = Keypair.random();

  function makeNominateEnvelope(
    keypair: Keypair,
    slotIndex: string,
    votes: string[] = ['v1'],
    accepted: string[] = [],
  ): xdr.ScpEnvelope {
    const nom = new xdr.ScpNomination({
      quorumSetHash: Buffer.alloc(32),
      votes: votes.map((v) => Buffer.from(v)),
      accepted: accepted.map((a) => Buffer.from(a)),
    });
    const stmt = new xdr.ScpStatement({
      nodeId: keypair.xdrPublicKey(),
      slotIndex: xdr.Uint64.fromString(slotIndex),
      pledges: xdr.ScpStatementPledges.scpStNominate(nom),
    });
    return new xdr.ScpEnvelope({
      statement: stmt,
      signature: Buffer.alloc(64),
    });
  }

  function makePrepareEnvelope(
    keypair: Keypair,
    slotIndex: string,
    counter: number = 1,
    value: string = 'txset-hash-1',
  ): xdr.ScpEnvelope {
    const ballot = new xdr.ScpBallot({
      counter,
      value: Buffer.from(value),
    });
    const prep = new xdr.ScpStatementPrepare({
      quorumSetHash: Buffer.alloc(32),
      ballot,
      prepared: null,
      preparedPrime: null,
      nC: 0,
      nH: 0,
    });
    const stmt = new xdr.ScpStatement({
      nodeId: keypair.xdrPublicKey(),
      slotIndex: xdr.Uint64.fromString(slotIndex),
      pledges: xdr.ScpStatementPledges.scpStPrepare(prep),
    });
    return new xdr.ScpEnvelope({
      statement: stmt,
      signature: Buffer.alloc(64),
    });
  }

  function makeConfirmEnvelope(
    keypair: Keypair,
    slotIndex: string,
    counter: number = 1,
    value: string = 'txset-hash-1',
  ): xdr.ScpEnvelope {
    const ballot = new xdr.ScpBallot({
      counter,
      value: Buffer.from(value),
    });
    const conf = new xdr.ScpStatementConfirm({
      ballot,
      nPrepared: counter,
      nCommit: counter,
      nH: counter,
      quorumSetHash: Buffer.alloc(32),
    });
    const stmt = new xdr.ScpStatement({
      nodeId: keypair.xdrPublicKey(),
      slotIndex: xdr.Uint64.fromString(slotIndex),
      pledges: xdr.ScpStatementPledges.scpStConfirm(conf),
    });
    return new xdr.ScpEnvelope({
      statement: stmt,
      signature: Buffer.alloc(64),
    });
  }

  it('parses ScpEnvelope XDR payloads accurately', () => {
    const tracer = new ScpBallotTracer();
    const env = makePrepareEnvelope(kp1, '100', 1, 'candidate-1');
    const b64 = env.toXDR('base64');

    const event = tracer.recordEnvelope(b64, 1000);
    expect(event.slotIndex).toBe(100n);
    expect(event.nodeId).toBe(kp1.publicKey());
    expect(event.phase).toBe('prepare');
    expect(event.statement.statementType).toBe('SCP_ST_PREPARE');
    expect(event.statement.ballot?.counter).toBe(1);
    expect(event.statement.ballot?.value).toBe(Buffer.from('candidate-1').toString('hex'));
  });

  it('traces a full consensus lifecycle: nomination -> prepare -> commit', () => {
    const tracer = new ScpBallotTracer();

    // 1. Nomination at t=0
    const nom = makeNominateEnvelope(kp1, '200', ['propA', 'propB']);
    tracer.recordEnvelope(nom, 1000);

    // 2. Prepare at t=1000ms
    const prep = makePrepareEnvelope(kp1, '200', 1, 'propA');
    tracer.recordEnvelope(prep, 2000);

    // 3. Confirm (commit phase) at t=2500ms
    const conf = makeConfirmEnvelope(kp1, '200', 1, 'propA');
    tracer.recordEnvelope(conf, 3500);

    const trace = tracer.traceSlot('200');
    expect(trace).toBeDefined();
    expect(trace!.slotIndex).toBe(200n);
    expect(trace!.durationMs).toBe(2500);
    expect(trace!.phasesObserved).toEqual(['nomination', 'prepare', 'commit']);
    expect(trace!.nominationRounds).toBe(1);
    expect(trace!.isConfirmed).toBe(true);
    expect(trace!.isStalled).toBe(false);
    expect(trace!.nodesParticipating).toEqual([kp1.publicKey()]);
  });

  it('detects consensus stall when slot fails to confirm within ledger time limit', () => {
    const tracer = new ScpBallotTracer({ stallTimeoutMs: 5000 });

    // Node 1 proposes at t=0
    tracer.recordEnvelope(makePrepareEnvelope(kp1, '300', 1), 10_000);
    // Node 2 votes at t=2000
    tracer.recordEnvelope(makePrepareEnvelope(kp2, '300', 1), 12_000);

    // Evaluated at t=16_000 (6000ms elapsed since first event > 5000ms limit)
    const trace = tracer.traceSlot('300', 16_000);
    expect(trace).toBeDefined();
    expect(trace!.durationMs).toBe(6000);
    expect(trace!.isConfirmed).toBe(false);
    expect(trace!.isStalled).toBe(true);
    expect(trace!.stallReason).toContain('failed to reach consensus commit');

    const stalls = tracer.detectStalls(DEFAULT_STALL_TIMEOUT_MS, 16_000);
    expect(stalls).toHaveLength(1);
    expect(stalls[0]!.slotIndex).toBe(300n);
    expect(stalls[0]!.durationMs).toBe(6000);
    expect(stalls[0]!.lastPhase).toBe('prepare');
    expect(stalls[0]!.participatingNodes).toEqual([kp1.publicKey(), kp2.publicKey()].sort());
  });

  it('does not flag stalls if consensus confirmed before timeout', () => {
    const tracer = new ScpBallotTracer({ stallTimeoutMs: 5000 });

    tracer.recordEnvelope(makePrepareEnvelope(kp1, '400', 1), 1000);
    tracer.recordEnvelope(makeConfirmEnvelope(kp1, '400', 1), 3000);

    // Even if checked much later, confirmed slot is never stalled
    const trace = tracer.traceSlot('400', 20_000);
    expect(trace!.isConfirmed).toBe(true);
    expect(trace!.isStalled).toBe(false);

    const stalls = tracer.detectStalls(5000, 20_000);
    expect(stalls).toHaveLength(0);
  });

  it('supports raw statements and mock object payloads', () => {
    const tracer = new ScpBallotTracer();
    const event = tracer.record({
      nodeId: 'GTEST_NODE',
      slotIndex: 500,
      phase: 'prepare',
      statementType: 'SCP_ST_PREPARE',
      ballot: { counter: 2, value: '0xabc' },
    });

    expect(event.slotIndex).toBe(500n);
    expect(event.statement.ballot?.counter).toBe(2);
    expect(tracer.traceSlot(500)?.nodesParticipating).toContain('GTEST_NODE');
  });
});
