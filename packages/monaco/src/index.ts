/**
 * Drop-in Monaco Editor integration for `stellar.toml`.
 *
 * ```ts
 * import * as monaco from 'monaco-editor';
 * import { setupMonacoStellarToml } from 'stellar-toml-lint-monaco';
 *
 * const stellar = setupMonacoStellarToml(
 *   monaco,
 *   new URL('stellar-toml-lint-monaco/worker', import.meta.url),
 * );
 * ```
 *
 * The helper attaches to every TOML model Monaco has (and to models created
 * later), debounces edits, runs the linter in a Web Worker, and publishes the
 * diagnostics as markers. It also registers a hover provider so the same
 * worker can answer SEP-1 field documentation questions.
 */
import type {
  HoverLike,
  LintDiagnostic,
  LintResultLike,
  MonacoHover,
  MonacoLike,
  MonacoMarker,
  MonacoModel,
  MonacoRange,
  SetupOptions,
  StellarTomlMonacoController,
  WorkerLike,
} from './types.js';

export type {
  HoverLike,
  LintDiagnostic,
  LintResultLike,
  MonacoDisposable,
  MonacoHover,
  MonacoHoverProvider,
  MonacoLike,
  MonacoMarker,
  MonacoModel,
  MonacoPosition,
  MonacoRange,
  SetupOptions,
  StellarTomlMonacoController,
  WorkerLike,
} from './types.js';

const DEFAULT_DEBOUNCE_MS = 250;
const DEFAULT_OWNER = 'stellar-toml-lint';
const DEFAULT_LANGUAGES = ['toml', 'stellar-toml'];

const SEVERITY = {
  Error: 8,
  Warning: 4,
  Info: 2,
  Hint: 1,
} as const;

interface PendingRequest<T> {
  resolve(value: T): void;
  reject(error: Error): void;
}

interface HoverResult {
  hover: HoverLike | null;
}

/**
 * Installs the linter on a Monaco instance.
 *
 * @param monacoInstance The namespace object exported by `monaco-editor`.
 * @param workerUrl      URL of the bundled lint worker.
 * @param options        Debounce, selector, and test hooks.
 */
export function setupMonacoStellarToml(
  monacoInstance: MonacoLike,
  workerUrl: string | URL,
  options: SetupOptions = {},
): StellarTomlMonacoController {
  const owner = options.owner ?? DEFAULT_OWNER;
  const debounceMs = options.debounceMs ?? DEFAULT_DEBOUNCE_MS;
  const languageIds = options.languageIds ?? DEFAULT_LANGUAGES;
  const lintOptions = options.lintOptions ?? {};

  const worker = options.worker ?? createWorker(String(workerUrl), options);
  const pending = new Map<number, PendingRequest<unknown>>();
  const listeners = new Map<MonacoModel, { dispose(): void }>();
  const timers = new Map<MonacoModel, ReturnType<typeof setTimeout>>();
  let nextId = 1;
  let disposed = false;

  const failAll = (error: Error): void => {
    for (const request of pending.values()) request.reject(error);
    pending.clear();
    options.onError?.(error);
  };

  const settle = (data: unknown): void => {
    if (!isRecord(data)) return;
    const id = typeof data.id === 'number' ? data.id : undefined;
    if (id === undefined) return;
    const request = pending.get(id);
    if (request === undefined) return;
    pending.delete(id);

    if (data.type === 'error') {
      const message = typeof data.message === 'string' ? data.message : 'worker request failed';
      request.reject(new Error(message));
      return;
    }

    if (data.type === 'result') {
      request.resolve(data.result);
      return;
    }

    if (data.type === 'hover') {
      const result: HoverResult = { hover: (data.hover as HoverLike | null) ?? null };
      request.resolve(result);
    }
  };

  if (worker !== undefined) {
    if (typeof worker.onmessage !== 'undefined' || worker.onmessage === null) {
      worker.onmessage = (event) => settle(event.data);
    } else if (worker.addEventListener !== undefined) {
      worker.addEventListener('message', (event) => settle(event.data));
    }
    if (worker.onerror !== undefined) {
      worker.onerror = (event) => failAll(asError(event));
    } else if (worker.addEventListener !== undefined) {
      worker.addEventListener('error', (event) => failAll(asError(event)));
    }
  }

  const request = <T>(message: Record<string, unknown>): Promise<T> => {
    if (worker === undefined) {
      return Promise.reject(new Error('No stellar.toml lint worker is available.'));
    }
    const id = nextId++;
    return new Promise<T>((resolve, reject) => {
      pending.set(id, { resolve: resolve as (value: unknown) => void, reject });
      worker.postMessage({ ...message, id });
    });
  };

  const runLint = async (model: MonacoModel): Promise<LintResultLike | undefined> => {
    const content = model.getValue();
    try {
      const result = options.lint
        ? await options.lint(content, lintOptions)
        : await request<LintResultLike>({ type: 'lint', content, options: lintOptions });
      if (disposed || result === undefined) return undefined;
      options.onDiagnostics?.(result, model);
      publishMarkers(monacoInstance, owner, model, result);
      return result;
    } catch (error) {
      if (!disposed) options.onError?.(asError(error));
      return undefined;
    }
  };

  const schedule = (model: MonacoModel): void => {
    const existing = timers.get(model);
    if (existing !== undefined) clearTimeout(existing);
    if (debounceMs <= 0) {
      timers.delete(model);
      void runLint(model);
      return;
    }
    timers.set(
      model,
      setTimeout(() => {
        timers.delete(model);
        void runLint(model);
      }, debounceMs),
    );
  };

  const attach = (model: MonacoModel): void => {
    if (disposed || listeners.has(model)) return;
    if (!isLintable(model, languageIds)) return;

    listeners.set(
      model,
      model.onDidChangeContent(() => schedule(model)),
    );
    void runLint(model);
  };

  const detach = (model: MonacoModel): void => {
    const listener = listeners.get(model);
    if (listener !== undefined) listener.dispose();
    listeners.delete(model);

    const timer = timers.get(model);
    if (timer !== undefined) clearTimeout(timer);
    timers.delete(model);

    if (!disposed) monacoInstance.editor.setModelMarkers(model, owner, []);
  };

  const hoverProvider = {
    provideHover: async (
      model: MonacoModel,
      position: { lineNumber: number; column: number },
    ): Promise<MonacoHover | null> => {
      if (disposed) return null;
      const content = model.getValue();
      const at = { line: position.lineNumber - 1, character: position.column - 1 };
      try {
        const hover = options.hover
          ? options.hover(content, at)
          : (
              await request<HoverResult>({
                type: 'hover',
                content,
                position: at,
              })
            ).hover;
        if (disposed || hover === null || hover === undefined) return null;
        return toMonacoHover(hover, monacoInstance);
      } catch (error) {
        options.onError?.(asError(error));
        return null;
      }
    },
  };

  const selector =
    languageIds.length === 1 ? (languageIds[0] ?? 'toml') : languageIds.map((id) => id);
  const hoverDisposable = monacoInstance.languages.registerHoverProvider(selector, hoverProvider);

  const modelDisposable = monacoInstance.editor.onDidCreateModel?.((model) => attach(model));
  for (const model of monacoInstance.editor.getModels?.() ?? []) attach(model);

  return {
    get worker() {
      return worker;
    },
    lintModel: runLint,
    attach,
    detach,
    dispose() {
      if (disposed) return;
      disposed = true;
      for (const timer of timers.values()) clearTimeout(timer);
      timers.clear();
      for (const model of listeners.keys()) {
        monacoInstance.editor.setModelMarkers(model, owner, []);
      }
      for (const listener of listeners.values()) listener.dispose();
      listeners.clear();
      hoverDisposable.dispose();
      modelDisposable?.dispose();
      pending.clear();
      worker?.terminate?.();
    },
  };
}

/** Alias for callers that import the helper by the issue's original name. */
export const setupStellarToml = setupMonacoStellarToml;

/**
 * Maps linter diagnostics onto Monaco's marker shape.
 *
 * Monaco positions are 1-based and end-exclusive-ish: a marker that starts and
 * ends on the same column is invisible, so the end column is advanced by one.
 * Diagnostics about an absent key have no position and land on line 1.
 */
export function toMonacoMarkers(
  input: LintResultLike | readonly LintDiagnostic[],
  monaco?: Pick<MonacoLike, 'MarkerSeverity'>,
): MonacoMarker[] {
  const diagnostics = isLintResult(input) ? input.diagnostics : input;
  const severity = monaco?.MarkerSeverity ?? SEVERITY;
  return diagnostics.map((diagnostic) => markerFor(diagnostic, severity));
}

function isLintResult(input: LintResultLike | readonly LintDiagnostic[]): input is LintResultLike {
  return !Array.isArray(input);
}

/** Aliases kept for discoverability in playground code. */
export const diagnosticsToMarkers = toMonacoMarkers;
export const mapDiagnosticsToMarkers = toMonacoMarkers;

function markerFor(
  diagnostic: LintDiagnostic,
  severity: { Error: number; Warning: number; Info: number; Hint?: number },
): MonacoMarker {
  const line = diagnostic.position?.line ?? 1;
  const column = diagnostic.position?.column ?? 1;
  return {
    severity:
      diagnostic.severity === 'error'
        ? severity.Error
        : diagnostic.severity === 'warning'
          ? severity.Warning
          : severity.Info,
    message: diagnostic.message,
    source: DEFAULT_OWNER,
    code: diagnostic.rule,
    startLineNumber: line,
    startColumn: column,
    endLineNumber: line,
    endColumn: column + 1,
  };
}

function publishMarkers(
  monaco: MonacoLike,
  owner: string,
  model: MonacoModel,
  result: LintResultLike,
): void {
  monaco.editor.setModelMarkers(model, owner, toMonacoMarkers(result, monaco));
}

/** Converts the worker's LSP-shaped hover into Monaco's markdown contents. */
export function toMonacoHover(hover: HoverLike, monaco?: Pick<MonacoLike, 'Range'>): MonacoHover {
  const contents = [{ value: hover.contents.value }];
  if (hover.range === undefined) return { contents };

  const startLineNumber = hover.range.start.line + 1;
  const startColumn = hover.range.start.character + 1;
  const endLineNumber = hover.range.end.line + 1;
  const endColumn = hover.range.end.character + 1;
  const range: MonacoRange = monaco?.Range
    ? new monaco.Range(startLineNumber, startColumn, endLineNumber, endColumn)
    : { startLineNumber, startColumn, endLineNumber, endColumn };
  return { contents, range };
}

function isLintable(model: MonacoModel, languageIds: string[]): boolean {
  if (typeof model.getLanguageId !== 'function') return true;
  return languageIds.includes(model.getLanguageId());
}

function createWorker(url: string, options: SetupOptions): WorkerLike | undefined {
  if (options.workerFactory !== undefined) return options.workerFactory(url);

  const ctor = (globalThis as { Worker?: new (url: string | URL, options?: object) => WorkerLike })
    .Worker;
  if (ctor === undefined) return undefined;
  return new ctor(url, { type: 'module' });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function asError(event: unknown): Error {
  if (event instanceof Error) return event;
  if (isRecord(event) && typeof event.message === 'string') return new Error(event.message);
  return new Error('stellar.toml worker failed');
}

export default setupMonacoStellarToml;
