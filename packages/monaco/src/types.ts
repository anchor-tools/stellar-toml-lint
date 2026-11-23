/**
 * Structural Monaco types.
 *
 * The package deliberately does not import `monaco-editor`: a playground may
 * load Monaco from a CDN, an AMD bundle, or `@monaco-editor/react`, and all
 * three expose the same runtime API. Typing only the slice used here keeps the
 * package dependency-free and lets a caller pass whatever instance they have.
 */

export interface MonacoPosition {
  lineNumber: number;
  column: number;
}

export interface MonacoRange {
  startLineNumber: number;
  startColumn: number;
  endLineNumber: number;
  endColumn: number;
}

export interface MonacoModel {
  getValue(): string;
  getLanguageId?(): string;
  uri?: { toString(): string };
  onDidChangeContent(listener: (event: unknown) => void): { dispose(): void };
}

export interface MonacoMarker {
  severity: number;
  message: string;
  source?: string;
  code?: string;
  startLineNumber: number;
  startColumn: number;
  endLineNumber: number;
  endColumn: number;
}

export interface MonacoHover {
  contents: { value: string }[];
  range?: MonacoRange;
}

export interface MonacoHoverProvider {
  provideHover(
    model: MonacoModel,
    position: MonacoPosition,
  ): MonacoHover | null | Promise<MonacoHover | null>;
}

export interface MonacoDisposable {
  dispose(): void;
}

export interface MonacoLanguages {
  registerHoverProvider(
    selector: string | string[],
    provider: MonacoHoverProvider,
  ): MonacoDisposable;
}

export interface MonacoEditor {
  setModelMarkers(model: MonacoModel, owner: string, markers: MonacoMarker[]): void;
  getModels?(): MonacoModel[];
  onDidCreateModel?(listener: (model: MonacoModel) => void): MonacoDisposable;
}

export interface MonacoMarkerSeverity {
  Error: number;
  Warning: number;
  Info: number;
  Hint: number;
}

export interface MonacoRangeConstructor {
  new (
    startLineNumber: number,
    startColumn: number,
    endLineNumber: number,
    endColumn: number,
  ): MonacoRange;
}

export interface MonacoLike {
  editor: MonacoEditor;
  languages: MonacoLanguages;
  MarkerSeverity?: MonacoMarkerSeverity;
  Range?: MonacoRangeConstructor;
}

/** The subset of a linter diagnostic this package reads. */
export interface LintDiagnostic {
  rule: string;
  severity: 'error' | 'warning' | 'info';
  message: string;
  suggestion?: string;
  path?: string;
  position?: { line: number; column: number };
}

/** The shape `stellar-toml-lint`'s worker returns. */
export interface LintResultLike {
  diagnostics: LintDiagnostic[];
  ok?: boolean;
  counts?: Record<string, number>;
}

export interface HoverLike {
  contents: { kind: 'markdown' | 'plaintext'; value: string };
  range?: {
    start: { line: number; character: number };
    end: { line: number; character: number };
  };
}

export interface WorkerLike {
  postMessage(message: unknown): void;
  terminate?(): void;
  onmessage?: ((event: { data: unknown }) => void) | null;
  onerror?: ((event: unknown) => void) | null;
  addEventListener?(type: 'message' | 'error', listener: (event: { data?: unknown }) => void): void;
}

export interface SetupOptions {
  /** Quiet period before a keystroke is linted. Defaults to 250 ms. */
  debounceMs?: number;
  /** Marker owner. Defaults to `stellar-toml-lint`. */
  owner?: string;
  /** Language ids that should be linted. Defaults to `toml` and `stellar-toml`. */
  languageIds?: string[];
  /** Injected worker, mainly for tests and editors with their own worker pool. */
  worker?: WorkerLike;
  /** Builds the worker when an injected one is not supplied. */
  workerFactory?: (url: string) => WorkerLike;
  /** Options forwarded to every lint request (`strict`, `rules`, ...). */
  lintOptions?: Record<string, unknown>;
  /** Called with every lint result before markers are published. */
  onDiagnostics?: (result: LintResultLike, model: MonacoModel) => void;
  /** Called when a worker request fails; the returned promise still resolves. */
  onError?: (error: Error) => void;
  /** Direct in-process lint hook for environments without Web Workers. */
  lint?: (content: string, options: Record<string, unknown>) => Promise<LintResultLike>;
  /** Direct in-process hover hook for environments without Web Workers. */
  hover?: (content: string, position: { line: number; character: number }) => HoverLike | null;
}

export interface StellarTomlMonacoController {
  /** Starts (or re-runs) linting for one model. */
  lintModel(model: MonacoModel): Promise<LintResultLike | undefined>;
  /** Subscribes to one model and lints it immediately. */
  attach(model: MonacoModel): void;
  /** Stops listening to a model and clears its markers. */
  detach(model: MonacoModel): void;
  /** Disposes every subscription, timer, and the worker. */
  dispose(): void;
  /** The worker in use, when one could be created. */
  readonly worker: WorkerLike | undefined;
}
