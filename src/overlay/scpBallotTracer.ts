import { StrKey, xdr } from '@stellar/stellar-base';

export type ScpPhase = 'nomination' | 'prepare' | 'commit' | 'externalize';

export interface ScpBallotInfo {
  counter: number;
  value: string;
}

export interface ScpStatementData {
  nodeId: string;
  slotIndex: bigint;
  phase: ScpPhase;
  statementType: string;
  ballot?: ScpBallotInfo;
  prepared?: ScpBallotInfo | null;
  preparedPrime?: ScpBallotInfo | null;
  nC?: number;
  nH?: number;
  nCommit?: number;
  votes?: string[];
  accepted?: string[];
  quorumSetHash?: string;
  raw?: xdr.ScpStatement;
}

export interface ScpTraceEvent {
  slotIndex: bigint;
  nodeId: string;
  phase: ScpPhase;
  timestampMs: number;
  statement: ScpStatementData;
}

export interface SlotConsensusTrace {
  slotIndex: bigint;
  startTimeMs: number;
  latestTimeMs: number;
  durationMs: number;
  phasesObserved: ScpPhase[];
  isConfirmed: boolean;
  isStalled: boolean;
  stallReason?: string;
  nodesParticipating: string[];
  nominationRounds: number;
  preparedBallots: ScpBallotInfo[];
  committedBallots: ScpBallotInfo[];
  events: ScpTraceEvent[];
}

export interface ConsensusStall {
  slotIndex: bigint;
  durationMs: number;
  lastPhase: ScpPhase;
  participatingNodes: string[];
  reason: string;
}

export interface ScpBallotTracerOptions {
  stallTimeoutMs?: number;
}

export const DEFAULT_STALL_TIMEOUT_MS = 5000; // ~5s normal Stellar ledger limit

function bufferToHex(buf: Buffer | Uint8Array): string {
  return Buffer.from(buf).toString('hex');
}

function parseNodeId(nodeId: xdr.NodeId | unknown): string {
  if (typeof nodeId === 'string') return nodeId;
  if (!nodeId) return 'UNKNOWN_NODE';
  try {
    const raw = nodeId as xdr.NodeId;
    if (typeof raw.ed25519 === 'function') {
      return StrKey.encodeEd25519PublicKey(raw.ed25519());
    }
  } catch {
    // fallback
  }
  return String(nodeId);
}

function parseBallot(ballot: xdr.ScpBallot | unknown): ScpBallotInfo | undefined {
  if (!ballot) return undefined;
  if (typeof ballot === 'object' && 'counter' in ballot && 'value' in ballot) {
    const b = ballot as { counter: number | (() => number); value: unknown };
    const counter = typeof b.counter === 'function' ? b.counter() : Number(b.counter);
    let value = '';
    if (typeof b.value === 'function') {
      const v = (b.value as () => Buffer | Uint8Array | string)();
      value = typeof v === 'string' ? v : bufferToHex(v);
    } else if (typeof b.value === 'string') {
      value = b.value;
    } else if (Buffer.isBuffer(b.value) || b.value instanceof Uint8Array) {
      value = bufferToHex(b.value);
    }
    return { counter, value };
  }
  return undefined;
}

export class ScpBallotTracer {
  private readonly stallTimeoutMs: number;
  private readonly events: ScpTraceEvent[] = [];
  private readonly slots = new Map<string, ScpTraceEvent[]>();

  constructor(options: ScpBallotTracerOptions = {}) {
    this.stallTimeoutMs = options.stallTimeoutMs ?? DEFAULT_STALL_TIMEOUT_MS;
  }

  /**
   * Parses an SCPEnvelope or SCPStatement from various payload formats:
   * raw xdr object, Buffer, Uint8Array, base64 or hex string, or structured object.
   */
  public parseStatement(
    payload:
      xdr.ScpEnvelope | xdr.ScpStatement | Uint8Array | Buffer | string | Record<string, unknown>,
  ): ScpStatementData {
    let stmt: xdr.ScpStatement | undefined;

    if (typeof payload === 'string') {
      const trimmed = payload.trim();
      const isHex = /^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0;
      const encoding: 'hex' | 'base64' = isHex ? 'hex' : 'base64';
      try {
        const env = xdr.ScpEnvelope.fromXDR(trimmed, encoding);
        stmt = env.statement();
      } catch {
        try {
          stmt = xdr.ScpStatement.fromXDR(trimmed, encoding);
        } catch {
          // If neither decodes via XDR, try JSON parse if structured
          try {
            const parsedJson = JSON.parse(trimmed) as Record<string, unknown>;
            return this.parseStatementObject(parsedJson);
          } catch {
            throw new Error(`Failed to decode SCP XDR payload as hex or base64.`);
          }
        }
      }
    } else if (Buffer.isBuffer(payload) || payload instanceof Uint8Array) {
      const buf = Buffer.from(payload);
      try {
        const env = xdr.ScpEnvelope.fromXDR(buf);
        stmt = env.statement();
      } catch {
        try {
          stmt = xdr.ScpStatement.fromXDR(buf);
        } catch (err) {
          throw new Error(
            `Failed to decode binary SCP XDR payload: ${err instanceof Error ? err.message : String(err)}`,
            { cause: err },
          );
        }
      }
    } else if (payload instanceof xdr.ScpEnvelope) {
      stmt = payload.statement();
    } else if (payload instanceof xdr.ScpStatement) {
      stmt = payload;
    } else if (typeof payload === 'object' && payload !== null) {
      return this.parseStatementObject(payload as Record<string, unknown>);
    }

    if (!stmt) {
      throw new Error('Unsupported SCP payload format');
    }

    const nodeId = parseNodeId(stmt.nodeId());
    const slotIndex = BigInt(stmt.slotIndex().toString());
    const pledges = stmt.pledges();
    const switchName = pledges.switch().name;

    switch (switchName) {
      case 'scpStNominate': {
        const nom = pledges.nominate();
        const votes = nom.votes().map((v) => bufferToHex(v));
        const accepted = nom.accepted().map((v) => bufferToHex(v));
        const quorumSetHash = bufferToHex(nom.quorumSetHash());
        return {
          nodeId,
          slotIndex,
          phase: 'nomination',
          statementType: 'SCP_ST_NOMINATE',
          votes,
          accepted,
          quorumSetHash,
          raw: stmt,
        };
      }
      case 'scpStPrepare': {
        const prep = pledges.prepare();
        const ballot = parseBallot(prep.ballot());
        const prepared = parseBallot(prep.prepared());
        const preparedPrime = parseBallot(prep.preparedPrime());
        const nC = prep.nC();
        const nH = prep.nH();
        const quorumSetHash = bufferToHex(prep.quorumSetHash());
        return {
          nodeId,
          slotIndex,
          phase: 'prepare',
          statementType: 'SCP_ST_PREPARE',
          ballot,
          prepared,
          preparedPrime,
          nC,
          nH,
          quorumSetHash,
          raw: stmt,
        };
      }
      case 'scpStConfirm': {
        const conf = pledges.confirm();
        const ballot = parseBallot(conf.ballot());
        const nCommit = conf.nCommit();
        const nH = conf.nH();
        const quorumSetHash = bufferToHex(conf.quorumSetHash());
        return {
          nodeId,
          slotIndex,
          phase: 'commit',
          statementType: 'SCP_ST_COMMIT',
          ballot,
          nCommit,
          nH,
          quorumSetHash,
          raw: stmt,
        };
      }
      case 'scpStExternalize': {
        const ext = pledges.externalize();
        const ballot = parseBallot(ext.commit());
        const nH = ext.nH();
        const quorumSetHash = bufferToHex(ext.commitQuorumSetHash());
        return {
          nodeId,
          slotIndex,
          phase: 'commit',
          statementType: 'SCP_ST_COMMIT',
          ballot,
          nCommit: ballot?.counter,
          nH,
          quorumSetHash,
          raw: stmt,
        };
      }
      default:
        throw new Error(`Unknown SCP statement type ${String(switchName)}`);
    }
  }

  private parseStatementObject(obj: Record<string, unknown>): ScpStatementData {
    const nodeId = String(obj['nodeId'] ?? obj['node_id'] ?? 'UNKNOWN_NODE');
    const rawSlot = obj['slotIndex'] ?? obj['slot_index'] ?? obj['slot'] ?? 0;
    const slotIndex = BigInt(String(rawSlot));
    const rawPhase = String(obj['phase'] ?? '').toLowerCase();
    const rawType = String(obj['statementType'] ?? obj['type'] ?? '');

    let phase: ScpPhase = 'nomination';
    let statementType = 'SCP_ST_NOMINATE';

    if (rawPhase === 'prepare' || rawType.includes('PREPARE')) {
      phase = 'prepare';
      statementType = 'SCP_ST_PREPARE';
    } else if (
      rawPhase === 'commit' ||
      rawPhase === 'confirm' ||
      rawPhase === 'externalize' ||
      rawType.includes('COMMIT') ||
      rawType.includes('CONFIRM') ||
      rawType.includes('EXTERNALIZE')
    ) {
      phase = 'commit';
      statementType = 'SCP_ST_COMMIT';
    }

    return {
      nodeId,
      slotIndex,
      phase,
      statementType,
      ballot: parseBallot(obj['ballot']),
      prepared: parseBallot(obj['prepared']),
      preparedPrime: parseBallot(obj['preparedPrime']),
      nC: typeof obj['nC'] === 'number' ? obj['nC'] : undefined,
      nH: typeof obj['nH'] === 'number' ? obj['nH'] : undefined,
      nCommit: typeof obj['nCommit'] === 'number' ? obj['nCommit'] : undefined,
      votes: Array.isArray(obj['votes']) ? (obj['votes'] as string[]) : undefined,
      accepted: Array.isArray(obj['accepted']) ? (obj['accepted'] as string[]) : undefined,
      quorumSetHash: typeof obj['quorumSetHash'] === 'string' ? obj['quorumSetHash'] : undefined,
    };
  }

  /**
   * Records an SCP payload (Envelope, Statement, or XDR bytes) into the tracer timeline.
   */
  public record(
    payload:
      xdr.ScpEnvelope | xdr.ScpStatement | Uint8Array | Buffer | string | Record<string, unknown>,
    timestampMs?: number,
  ): ScpTraceEvent {
    const statement = this.parseStatement(payload);
    const time = timestampMs ?? Date.now();

    const event: ScpTraceEvent = {
      slotIndex: statement.slotIndex,
      nodeId: statement.nodeId,
      phase: statement.phase,
      timestampMs: time,
      statement,
    };

    this.events.push(event);

    const slotKey = statement.slotIndex.toString();
    const existing = this.slots.get(slotKey) ?? [];
    existing.push(event);
    this.slots.set(slotKey, existing);

    return event;
  }

  public recordEnvelope(
    envelope: xdr.ScpEnvelope | Uint8Array | Buffer | string,
    timestampMs?: number,
  ): ScpTraceEvent {
    return this.record(envelope, timestampMs);
  }

  public recordStatement(
    statement: xdr.ScpStatement | Uint8Array | Buffer | string,
    timestampMs?: number,
  ): ScpTraceEvent {
    return this.record(statement, timestampMs);
  }

  /**
   * Traces consensus progression for a specific slot.
   */
  public traceSlot(
    slotIndex: number | bigint | string,
    evaluationTimeMs?: number,
  ): SlotConsensusTrace | undefined {
    const slotKey = slotIndex.toString();
    const events = this.slots.get(slotKey);
    if (!events || events.length === 0) return undefined;

    const slotBigInt = BigInt(slotKey);
    const sorted = [...events].sort((a, b) => a.timestampMs - b.timestampMs);
    const firstEvent = sorted[0]!;
    const lastEvent = sorted[sorted.length - 1]!;
    const startTimeMs = firstEvent.timestampMs;
    const latestTimeMs = lastEvent.timestampMs;

    const checkTime = evaluationTimeMs ?? latestTimeMs;
    const durationMs = checkTime - startTimeMs;

    const phasesObserved = Array.from(new Set(sorted.map((e) => e.phase)));
    const nodesParticipating = Array.from(new Set(sorted.map((e) => e.nodeId))).sort();

    const isConfirmed = phasesObserved.includes('commit') || phasesObserved.includes('externalize');

    const nominationRounds = sorted.filter((e) => e.phase === 'nomination').length;

    const preparedBallots: ScpBallotInfo[] = [];
    const committedBallots: ScpBallotInfo[] = [];

    for (const ev of sorted) {
      if (ev.statement.ballot) {
        if (ev.phase === 'prepare') {
          preparedBallots.push(ev.statement.ballot);
        } else if (ev.phase === 'commit' || ev.phase === 'externalize') {
          committedBallots.push(ev.statement.ballot);
        }
      }
    }

    const isStalled = !isConfirmed && durationMs > this.stallTimeoutMs;
    const stallReason = isStalled
      ? `Slot ${slotKey} failed to reach consensus commit within ${durationMs}ms (timeout: ${this.stallTimeoutMs}ms). Last phase: ${lastEvent.phase}.`
      : undefined;

    return {
      slotIndex: slotBigInt,
      startTimeMs,
      latestTimeMs,
      durationMs,
      phasesObserved,
      isConfirmed,
      isStalled,
      stallReason,
      nodesParticipating,
      nominationRounds,
      preparedBallots,
      committedBallots,
      events: sorted,
    };
  }

  /**
   * Retrieves traces for all observed slots.
   */
  public getAllTraces(evaluationTimeMs?: number): SlotConsensusTrace[] {
    const traces: SlotConsensusTrace[] = [];
    for (const slotKey of this.slots.keys()) {
      const trace = this.traceSlot(slotKey, evaluationTimeMs);
      if (trace) traces.push(trace);
    }
    return traces.sort((a, b) =>
      a.slotIndex < b.slotIndex ? -1 : a.slotIndex > b.slotIndex ? 1 : 0,
    );
  }

  /**
   * Detects consensus stalls where ballots fail to confirm within normal ledger time limits (~5s).
   */
  public detectStalls(timeoutMs?: number, evaluationTimeMs?: number): ConsensusStall[] {
    const threshold = timeoutMs ?? this.stallTimeoutMs;
    const stalls: ConsensusStall[] = [];

    for (const [slotKey, events] of this.slots.entries()) {
      if (events.length === 0) continue;
      const sorted = [...events].sort((a, b) => a.timestampMs - b.timestampMs);
      const startTime = sorted[0]!.timestampMs;
      const lastEvent = sorted[sorted.length - 1]!;
      const checkTime = evaluationTimeMs ?? lastEvent.timestampMs;
      const durationMs = checkTime - startTime;

      const isConfirmed = sorted.some((e) => e.phase === 'commit' || e.phase === 'externalize');

      if (!isConfirmed && durationMs > threshold) {
        const participatingNodes = Array.from(new Set(sorted.map((e) => e.nodeId))).sort();
        stalls.push({
          slotIndex: BigInt(slotKey),
          durationMs,
          lastPhase: lastEvent.phase,
          participatingNodes,
          reason: `Ballot failed to confirm within ${durationMs}ms (exceeds ${threshold}ms limit). Current phase: ${lastEvent.phase}.`,
        });
      }
    }

    return stalls.sort((a, b) =>
      a.slotIndex < b.slotIndex ? -1 : a.slotIndex > b.slotIndex ? 1 : 0,
    );
  }

  public reset(): void {
    this.events.length = 0;
    this.slots.clear();
  }
}
