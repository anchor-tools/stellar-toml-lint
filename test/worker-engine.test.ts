import { describe, expect, it } from 'vitest';
import {
  WebWorkerLinterEngine,
  decodeLintSource,
  encodeLintSource,
  type LintWorkerMessage,
  type LintWorkerResponse,
  type WorkerPort,
} from '../src/wasm/workerEngine.js';
import { handleLintWorkerMessage } from '../src/wasm/linter.worker.js';

interface MockPort extends WorkerPort {
  received: { message: LintWorkerMessage; transfer: ArrayBuffer[] }[];
  terminated: boolean;
  reply(message: LintWorkerResponse, transfer?: ArrayBuffer[]): void;
}

function mockPort(options: { autoReply?: boolean } = {}): MockPort {
  const messageHandlers: ((data: unknown) => void)[] = [];
  const errorHandlers: ((error: Error) => void)[] = [];
  const port: MockPort = {
    received: [],
    terminated: false,
    postMessage(message, transfer = []) {
      const typed = message as LintWorkerMessage;
      port.received.push({ message: typed, transfer });
      if (options.autoReply === false) return;
      queueMicrotask(() => {
        const response = handleLintWorkerMessage(typed);
        if (response !== undefined) {
          const buffers = response.type === 'result' ? [response.payload] : [];
          for (const handler of messageHandlers) handler(response);
          void buffers;
        }
      });
    },
    terminate() {
      port.terminated = true;
    },
    onMessage(handler) {
      messageHandlers.push(handler);
    },
    onError(handler) {
      errorHandlers.push(handler);
    },
    reply(message, transfer = []) {
      for (const handler of messageHandlers) handler(message);
      void transfer;
      void errorHandlers;
    },
  };
  return port;
}

const SAMPLE = `VERSION="2.0.0"\nNETWORK_PASSPHRASE="Test SDF Network ; September 2015"\n`;

describe('transferable buffer codec', () => {
  it('round-trips UTF-8 source exactly', () => {
    const source = 'VERSION="2.0.0" # ünïcode ✓\n';
    expect(decodeLintSource(encodeLintSource(source))).toBe(source);
  });
});

describe('worker message handler', () => {
  it('lints and returns a transferable payload', () => {
    const response = handleLintWorkerMessage({
      type: 'lint',
      id: 'a',
      source: encodeLintSource(SAMPLE),
    });
    expect(response?.type).toBe('result');
    if (response?.type !== 'result') throw new Error('expected result');
    expect(response.payload).toBeInstanceOf(ArrayBuffer);
  });

  it('rejects a non-buffer source with an error response', () => {
    const response = handleLintWorkerMessage({ type: 'lint', id: 'b', source: 'string' });
    expect(response).toEqual({
      type: 'error',
      id: 'b',
      message: 'source must be a transferred ArrayBuffer',
    });
  });

  it('ignores unknown messages', () => {
    expect(handleLintWorkerMessage({ type: 'other' })).toBeUndefined();
    expect(handleLintWorkerMessage(null)).toBeUndefined();
  });
});

describe('WebWorkerLinterEngine', () => {
  it('spawns a pool and transfers the source buffer', async () => {
    const ports = [mockPort(), mockPort()];
    let created = 0;
    const engine = new WebWorkerLinterEngine({
      poolSize: 2,
      workerFactory: () => ports[created++] as WorkerPort,
    });

    expect(engine.poolSize).toBe(2);
    const result = await engine.run(SAMPLE);
    expect(result.counts.error).toBeGreaterThanOrEqual(0);
    const transfer = ports[0]?.received[0]?.transfer[0];
    expect(transfer).toBeInstanceOf(ArrayBuffer);
    engine.terminate();
  });

  it('runs jobs in parallel across the pool', async () => {
    const ports = [mockPort(), mockPort()];
    let created = 0;
    const engine = new WebWorkerLinterEngine({
      poolSize: 2,
      workerFactory: () => ports[created++] as WorkerPort,
    });

    const outcomes = await engine.runAll([
      { id: 'one', source: SAMPLE },
      { id: 'two', source: SAMPLE },
      { id: 'three', source: SAMPLE },
    ]);
    expect(outcomes.map((outcome) => outcome.status)).toEqual([
      'completed',
      'completed',
      'completed',
    ]);
    engine.terminate();
  });

  it('cancels an in-flight job by terminating its worker', async () => {
    const ports = [mockPort({ autoReply: false }), mockPort({ autoReply: false })];
    let created = 0;
    const engine = new WebWorkerLinterEngine({
      poolSize: 1,
      workerFactory: () => ports[created++] as WorkerPort,
    });

    const pending = engine.runAll([{ id: 'slow', source: SAMPLE }]);
    expect(engine.cancel('slow')).toBe(true);
    const outcomes = await pending;
    expect(outcomes[0]?.status).toBe('cancelled');
    expect(ports[0]?.terminated).toBe(true);
    expect(engine.stats().cancelled).toBe(1);
    engine.terminate();
  });

  it('cancels a queued job without dispatching it', async () => {
    const ports = [mockPort({ autoReply: false })];
    const engine = new WebWorkerLinterEngine({ poolSize: 1, workerFactory: () => ports[0] as WorkerPort });

    const first = engine.runAll([{ id: 'a', source: SAMPLE }]);
    const second = engine.runAll([{ id: 'b', source: SAMPLE }]);
    expect(engine.cancel('b')).toBe(true);
    const secondOutcome = await second;
    expect(secondOutcome[0]?.status).toBe('cancelled');
    expect(ports[0]?.received).toHaveLength(1);
    engine.cancel('a');
    await first;
    engine.terminate();
  });

  it('falls back to synchronous linting without workers', async () => {
    const engine = new WebWorkerLinterEngine({ fallbackLint: () => lintStub });
    expect(engine.isParallel).toBe(false);
    const outcome = await engine.run(SAMPLE);
    expect(outcome).toBe(lintStub);
    engine.terminate();
  });

  it('surfaces a worker error as a failed job', async () => {
    const port = mockPort({ autoReply: false });
    const engine = new WebWorkerLinterEngine({ poolSize: 1, workerFactory: () => port });
    const pending = engine.runAll([{ id: 'bad', source: SAMPLE }]);
    port.reply({ type: 'error', id: 'bad', message: 'boom' });
    const outcomes = await pending;
    expect(outcomes[0]?.status).toBe('failed');
    expect(outcomes[0]?.error).toBe('boom');
    engine.terminate();
  });

  it('terminate resolves outstanding work and is idempotent', () => {
    const port = mockPort({ autoReply: false });
    const engine = new WebWorkerLinterEngine({ poolSize: 1, workerFactory: () => port });
    void engine.runAll([{ id: 'x', source: SAMPLE }]);
    engine.terminate();
    expect(() => engine.terminate()).not.toThrow();
    expect(engine.stats().poolSize).toBe(0);
  });
});

const lintStub = {
  diagnostics: [],
  ok: true,
  counts: { error: 0, warning: 0, info: 0 },
};

