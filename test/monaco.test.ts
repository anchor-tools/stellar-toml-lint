import { describe, expect, it, vi } from 'vitest';

import {
  setupMonacoStellarToml,
  toMonacoHover,
  toMonacoMarkers,
} from '../packages/monaco/src/index.js';
import type {
  LintResultLike,
  MonacoHover,
  MonacoLike,
  MonacoMarker,
  MonacoModel,
  WorkerLike,
} from '../packages/monaco/src/index.js';

const DOC = 'TRANSFER_SERVER = "https://example.com/sep6/"\n';

const RESULT: LintResultLike = {
  diagnostics: [
    {
      rule: 'general/trailing-slash-in-endpoint',
      severity: 'error',
      message: 'TRANSFER_SERVER must not end with a slash',
      suggestion: 'Remove the trailing slash',
      path: 'TRANSFER_SERVER',
      position: { line: 1, column: 20 },
    },
  ],
};

function flush(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

class FakeWorker implements WorkerLike {
  onmessage: ((event: { data: unknown }) => void) | null = null;
  readonly requests: Record<string, unknown>[] = [];
  terminated = false;

  postMessage(message: unknown): void {
    const request = message as Record<string, unknown>;
    this.requests.push(request);
    const id = request.id;
    setTimeout(() => {
      if (request.type === 'lint') {
        this.onmessage?.({ data: { type: 'result', id, result: RESULT } });
      } else if (request.type === 'hover') {
        this.onmessage?.({
          data: {
            type: 'hover',
            id,
            hover: {
              contents: { kind: 'markdown', value: '`TRANSFER_SERVER` — endpoint' },
              range: { start: { line: 0, character: 0 }, end: { line: 0, character: 15 } },
            },
          },
        });
      }
    }, 0);
  }

  terminate(): void {
    this.terminated = true;
  }
}

function harness() {
  const markerCalls: { owner: string; markers: MonacoMarker[] }[] = [];
  let changeListener: (() => void) | undefined;
  let hoverProvider: ((model: MonacoModel, position: unknown) => Promise<unknown>) | undefined;

  const model: MonacoModel = {
    getValue: () => DOC,
    getLanguageId: () => 'toml',
    uri: { toString: () => 'file:///stellar.toml' },
    onDidChangeContent(listener) {
      changeListener = () => listener({});
      return { dispose: () => (changeListener = undefined) };
    },
  };

  const monaco: MonacoLike = {
    editor: {
      setModelMarkers(_model, owner, markers) {
        markerCalls.push({ owner, markers });
      },
      getModels: () => [model],
    },
    languages: {
      registerHoverProvider(_selector, provider) {
        hoverProvider = provider.provideHover as typeof hoverProvider;
        return { dispose: () => undefined };
      },
    },
    MarkerSeverity: { Error: 8, Warning: 4, Info: 2, Hint: 1 },
    Range: class {
      constructor(
        readonly startLineNumber: number,
        readonly startColumn: number,
        readonly endLineNumber: number,
        readonly endColumn: number,
      ) {}
    },
  };

  return {
    monaco,
    model,
    worker: new FakeWorker(),
    markerCalls,
    change: () => changeListener?.(),
    hover: () => hoverProvider,
  };
}

describe('Monaco integration', () => {
  it('sets markers on the model when the worker reports a lint error', async () => {
    const h = harness();
    setupMonacoStellarToml(h.monaco, 'worker.js', { worker: h.worker, debounceMs: 0 });
    await flush();

    expect(h.markerCalls).toHaveLength(1);
    expect(h.markerCalls[0]?.owner).toBe('stellar-toml-lint');
    expect(h.markerCalls[0]?.markers).toEqual([
      {
        severity: 8,
        message: 'TRANSFER_SERVER must not end with a slash',
        source: 'stellar-toml-lint',
        code: 'general/trailing-slash-in-endpoint',
        startLineNumber: 1,
        startColumn: 20,
        endLineNumber: 1,
        endColumn: 21,
      },
    ]);
  });

  it('debounces edits and re-lints the model', async () => {
    vi.useFakeTimers();
    try {
      const h = harness();
      const controller = setupMonacoStellarToml(h.monaco, 'worker.js', {
        worker: h.worker,
        debounceMs: 5,
      });
      // Process initial lint
      await vi.runAllTimersAsync();
      expect(h.markerCalls).toHaveLength(1);

      h.change();
      // Advance past debounce and worker response
      await vi.advanceTimersByTimeAsync(10);
      expect(h.markerCalls).toHaveLength(2);
      controller.dispose();
      expect(h.worker.terminated).toBe(true);
      expect(h.markerCalls.at(-1)?.markers).toEqual([]);
    } finally {
      vi.useRealTimers();
    }
  });

  it('registers a hover provider that asks the worker for SEP-1 docs', async () => {
    const h = harness();
    setupMonacoStellarToml(h.monaco, 'worker.js', { worker: h.worker, debounceMs: 0 });
    await flush();

    const provider = h.hover();
    expect(provider).toBeDefined();
    const hover = (await provider!(h.model, { lineNumber: 1, column: 3 })) as MonacoHover;

    expect(hover.contents[0]?.value).toContain('TRANSFER_SERVER');
    expect(hover.range).toMatchObject({ startLineNumber: 1, startColumn: 1, endColumn: 16 });
    expect(h.worker.requests.some((request) => request.type === 'hover')).toBe(true);
  });

  it('maps diagnostics without a position to the first line', () => {
    const markers = toMonacoMarkers([
      { rule: 'file/missing', severity: 'warning', message: 'Missing table' },
    ]);

    expect(markers[0]).toMatchObject({
      severity: 4,
      startLineNumber: 1,
      startColumn: 1,
      endLineNumber: 1,
      endColumn: 2,
    });
  });

  it('converts LSP ranges to 1-based Monaco ranges', () => {
    const hover = toMonacoHover(
      {
        contents: { kind: 'markdown', value: 'docs' },
        range: { start: { line: 4, character: 2 }, end: { line: 4, character: 8 } },
      },
      { Range: harness().monaco.Range },
    );

    expect(hover.range).toMatchObject({
      startLineNumber: 5,
      startColumn: 3,
      endLineNumber: 5,
      endColumn: 9,
    });
  });
});
