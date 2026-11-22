/**
 * Monaco Editor language bundle for `stellar.toml`.
 *
 * This is the browser half of the tool: the grammar, the SEP-1 completion
 * catalog and the marker mapping a playground needs, without the linter core.
 * The split is deliberate and measurable — the core, with its rules and
 * `@stellar/stellar-base`, gzips to ~146KB on its own, so importing it here
 * would make every bundle in this directory overshoot the 150KB budget the
 * language features are supposed to sit *inside*. Validation therefore arrives
 * through an injected {@link LintValidator}: either a result the page already
 * has, pushed in with {@link MonacoRegistration.publish}, or
 * {@link createWorkerValidator}, which speaks the existing worker's protocol.
 *
 * ```ts
 * const monaco = await import('monaco-editor');
 * const worker = new Worker(new URL('stellar-toml-lint/worker', import.meta.url), { type: 'module' });
 * register(monaco, { validator: createWorkerValidator(worker) }).observe(model);
 * ```
 *
 * `monaco-editor` is never imported: only the slice of its runtime API used
 * here is declared structurally, so a page loading Monaco from a CDN, an AMD
 * bundle or `@monaco-editor/react` can pass whatever instance it has. Marker
 * mapping is kept identical to `packages/monaco` — 1-based positions, an end
 * column advanced by one so a marker is never invisible, and line 1 for the
 * diagnostics about keys that are absent — because two integrations of one tool
 * disagreeing about where a violation sits is a bug users see.
 */
import {
  ARRAY_HEADER_PATTERN,
  ASSIGNED_KEY_PATTERN,
  ENDPOINT_KEY_PATTERN,
  FILE_EXTENSIONS,
  FILENAMES,
  KNOWN_KEY_PATTERN,
  LANGUAGE_ALIASES,
  LANGUAGE_ID,
  LANGUAGE_NAME,
  SEP_ARRAY_HEADER_PATTERN,
  SEP_TABLE_HEADER_PATTERN,
  STRKEY_PATTERNS,
  TABLE_HEADER_PATTERN,
  completeStellarToml,
} from './language.js';
import type { CompletionQuery, CompletionSuggestion, DiagnosticSource } from './language.js';
import type { Diagnostic } from '../types.js';

const DEFAULT_OWNER = 'stellar-toml-lint';
const DEFAULT_DEBOUNCE_MS = 250;

/** Monaco's numeric severities, matching `packages/monaco` and Monaco itself. */
const SEVERITY: MonacoMarkerSeverity = { Error: 8, Warning: 4, Info: 2, Hint: 1 };

/** The completion kinds this bundle uses, by Monaco enum name. */
type CompletionKindName = 'Property' | 'Keyword' | 'Enum' | 'Value' | 'Snippet';

/** Monaco's zero-based `CompletionItemKind` values, used when it is not supplied. */
const COMPLETION_KIND: Readonly<Record<CompletionKindName, number>> = {
  Property: 9,
  Keyword: 13,
  Enum: 12,
  Value: 11,
  Snippet: 14,
};

const KIND_BY_CONTEXT: Readonly<Record<CompletionSuggestion['context'], CompletionKindName>> = {
  key: 'Property',
  table: 'Keyword',
  value: 'Enum',
};

// ── structural Monaco API ────────────────────────────────────────────────────

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

export interface MonacoDisposable {
  dispose(): void;
}

export interface MonacoModel {
  getValue(): string;
  /** Monaco supplies this; absent on a minimal fake, so completions fall back. */
  getWordUntilPosition?(position: MonacoPosition): {
    word: string;
    startColumn: number;
    endColumn: number;
  };
  onDidChangeContent?(listener: (event: unknown) => void): MonacoDisposable;
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

export interface MonacoMarkerSeverity {
  Error: number;
  Warning: number;
  Info: number;
  Hint: number;
}

export interface MonacoMarkdown {
  value: string;
}

export interface MonacoCompletionItem {
  label: string;
  kind: number;
  insertText: string;
  filterText?: string;
  detail?: string;
  documentation?: MonacoMarkdown;
  range?: MonacoRange;
}

export interface MonacoCompletionList {
  suggestions: MonacoCompletionItem[];
}

/**
 * The two-argument shape of Monaco's provider. Monaco passes four arguments; a
 * function that ignores the extra two satisfies its interface.
 */
export interface MonacoCompletionProvider {
  provideCompletionItems(model: MonacoModel, position: MonacoPosition): MonacoCompletionList;
}

/** A Monarch rule, in the documented `[pattern, action]` / `[pattern, action, next]` form. */
export type MonarchRule =
  | readonly [pattern: string, action: string]
  | readonly [pattern: string, action: string, next: string]
  | { readonly include: string };

export interface MonarchDefinition {
  readonly tokenPostfix: string;
  readonly defaultToken: string;
  readonly ignoreCase: boolean;
  readonly tokenizer: Readonly<Record<string, readonly MonarchRule[]>>;
}

export interface MonacoLanguageConfiguration {
  readonly comments?: { readonly lineComment?: string };
  readonly brackets?: readonly (readonly [string, string])[];
  readonly autoClosingPairs?: readonly {
    readonly open: string;
    readonly close: string;
    readonly notIn?: readonly string[];
  }[];
  readonly surroundingPairs?: readonly { readonly open: string; readonly close: string }[];
  readonly wordPattern?: RegExp;
}

export interface MonacoLanguageRegistration {
  readonly id: string;
  readonly extensions?: readonly string[];
  readonly aliases?: readonly string[];
  readonly filenames?: readonly string[];
}

export interface MonacoLanguages {
  register?(language: MonacoLanguageRegistration): MonacoDisposable;
  setMonarchTokensProvider(languageId: string, monarch: MonarchDefinition): MonacoDisposable;
  setLanguageConfiguration(
    languageId: string,
    configuration: MonacoLanguageConfiguration,
  ): MonacoDisposable;
  registerCompletionProvider(
    selector: string | string[],
    provider: MonacoCompletionProvider,
  ): MonacoDisposable;
  /** Read when present, so the numeric kinds come from Monaco rather than here. */
  CompletionItemKind?: Partial<Record<CompletionKindName, number>>;
}

export interface MonacoEditorApi {
  setModelMarkers(model: MonacoModel, owner: string, markers: MonacoMarker[]): void;
}

export interface MonacoLike {
  editor: MonacoEditorApi;
  languages: MonacoLanguages;
  MarkerSeverity?: MonacoMarkerSeverity;
}

/** The subset of a Web Worker this bundle drives. */
export interface WorkerLike {
  postMessage(message: unknown): void;
  terminate?(): void;
  onmessage?: ((event: { data: unknown }) => void) | null;
  addEventListener?(type: 'message', listener: (event: { data: unknown }) => void): void;
}

/** How a page feeds findings to the bundle: the worker, `lintBrowser`, or a stub. */
export type LintValidator = (
  content: string,
  options: Record<string, unknown>,
) => DiagnosticSource | Promise<DiagnosticSource>;

// ── tokenizer ────────────────────────────────────────────────────────────────

const ESCAPE_RULE: readonly [string, string] = [
  '\\\\(?:u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|.)',
  'string.escape',
];

/** Strkey shapes recognised inside a value, each anchored to its closing quote. */
function stellarInString(lookahead: string): MonarchRule[] {
  return [
    [`(?:${STRKEY_PATTERNS.accountId})${lookahead}`, 'string.stellar.account-id'],
    [`(?:${STRKEY_PATTERNS.contractId})${lookahead}`, 'string.stellar.contract-id'],
    [`(?:${STRKEY_PATTERNS.muxedAccountId})${lookahead}`, 'string.stellar.muxed-account-id'],
    [`(?:${STRKEY_PATTERNS.assetCode})${lookahead}`, 'string.stellar.asset-code'],
  ];
}

const ACCOUNT_IN_MULTILINE: MonarchRule[] = stellarInString('(?=")');

/**
 * The Monarch grammar.
 *
 * Flat except where TOML forces state: multi-line strings span lines, and
 * Monarch is line-based, so those forms are the only pushed states. Known keys
 * are recognised by name from the SEP-1 catalog rather than by position, which
 * is what keeps the grammar out of the per-table state machine a
 * section-aware version would need — and an unknown field is reported by the
 * markers anyway.
 */
export const monarchDefinition: MonarchDefinition = {
  tokenPostfix: '.stellar-toml',
  defaultToken: '',
  ignoreCase: false,
  tokenizer: {
    root: [
      { include: '@whitespace' },
      [SEP_ARRAY_HEADER_PATTERN, 'keyword.table.sep'],
      [SEP_TABLE_HEADER_PATTERN, 'keyword.table.sep'],
      [ARRAY_HEADER_PATTERN, 'keyword.table.array'],
      [TABLE_HEADER_PATTERN, 'keyword.table'],
      [ENDPOINT_KEY_PATTERN, 'constant.language.endpoint'],
      [KNOWN_KEY_PATTERN, 'identifier.key.sep'],
      [ASSIGNED_KEY_PATTERN, 'identifier.key'],
      ['=', 'operator'],
      ['"""', 'string.quote', '@multilineBasic'],
      ["'''", 'string.quote', '@multilineLiteral'],
      ['"', 'string.quote', '@basicString'],
      ["'", 'string.quote', '@literalString'],
      ['\\b(?:true|false)\\b', 'constant.language.boolean'],
      [
        '\\d{4}-\\d{2}-\\d{2}(?:[Tt ][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.\\d+)?(?:[Zz]|[+-][0-9]{2}:[0-9]{2})?)?',
        'constant.datetime',
      ],
      ['[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.\\d+)?', 'constant.datetime'],
      ['[+-]?(?:inf|nan)', 'constant.language.number'],
      ['(?:0x|0o|0b)[0-9A-Fa-f_]+', 'number'],
      ['[+-]?[0-9][0-9_]*(?:\\.[0-9_]+)?(?:[eE][+-]?[0-9_]+)?', 'number'],
      ['\\[', 'delimiter.bracket'],
      ['\\]', 'delimiter.bracket'],
      [',', 'delimiter.comma'],
    ],
    whitespace: [
      ['[ \\t\\r]+', ''],
      ['#[^\\n]*', 'comment'],
    ],
    basicString: [
      ...stellarInString('(?=")'),
      ESCAPE_RULE,
      ['"', 'string.quote', '@pop'],
      ['[^"\\\\]+', 'string'],
    ],
    literalString: [
      ...stellarInString("(?=')"),
      ["'", 'string.quote', '@pop'],
      ["[^']+", 'string'],
    ],
    multilineBasic: [
      ...ACCOUNT_IN_MULTILINE,
      ESCAPE_RULE,
      ['"""', 'string.quote', '@pop'],
      ['"{1,2}', 'string'],
      ['[^"\\\\]+', 'string'],
    ],
    multilineLiteral: [
      ["'''", 'string.quote', '@pop'],
      ["'{1,2}", 'string'],
      ["[^']+", 'string'],
    ],
  },
};

export const languageConfiguration: MonacoLanguageConfiguration = {
  comments: { lineComment: '#' },
  brackets: [
    ['[', ']'],
    ['{', '}'],
    ['(', ')'],
  ],
  autoClosingPairs: [
    { open: '[', close: ']', notIn: ['string', 'comment'] },
    { open: '"', close: '"', notIn: ['comment'] },
    { open: "'", close: "'", notIn: ['string', 'comment'] },
  ],
  surroundingPairs: [
    { open: '[', close: ']' },
    { open: '"', close: '"' },
    { open: "'", close: "'" },
  ],
  wordPattern: /[A-Za-z0-9_.-]+/,
};

// ── markers ──────────────────────────────────────────────────────────────────

function diagnosticsOf(input: DiagnosticSource): readonly Diagnostic[] {
  return 'diagnostics' in input ? input.diagnostics : input;
}

/** Maps findings to Monaco markers, exactly as `packages/monaco` maps them. */
export function toMonacoMarkers(
  input: DiagnosticSource,
  monaco?: Pick<MonacoLike, 'MarkerSeverity'>,
  owner: string = DEFAULT_OWNER,
): MonacoMarker[] {
  const severity = monaco?.MarkerSeverity ?? SEVERITY;
  return diagnosticsOf(input).map((diagnostic) => markerFor(diagnostic, severity, owner));
}

function markerFor(
  diagnostic: Diagnostic,
  severity: MonacoMarkerSeverity,
  owner: string,
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
    source: owner,
    code: diagnostic.rule,
    startLineNumber: line,
    startColumn: column,
    endLineNumber: line,
    endColumn: column + 1,
  };
}

// ── completions ──────────────────────────────────────────────────────────────

/**
 * The completion range for a cursor.
 *
 * Monaco answers this with `getWordUntilPosition`; the fallback keeps the
 * provider usable against a minimal model and is what lets a `[`-prefixed table
 * suggestion replace the brackets the user has already typed.
 */
function completionRange(model: MonacoModel, position: MonacoPosition): MonacoRange {
  const word = model.getWordUntilPosition?.(position);
  if (word !== undefined) {
    return {
      startLineNumber: position.lineNumber,
      startColumn: word.startColumn,
      endLineNumber: position.lineNumber,
      endColumn: position.column,
    };
  }

  const line = model.getValue().split('\n')[position.lineNumber - 1] ?? '';
  const run = /[[A-Za-z0-9_.-]*$/.exec(line.slice(0, position.column - 1))?.[0] ?? '';
  return {
    startLineNumber: position.lineNumber,
    startColumn: Math.max(position.column - run.length, 1),
    endLineNumber: position.lineNumber,
    endColumn: position.column,
  };
}

export function toMonacoCompletions(
  suggestions: readonly CompletionSuggestion[],
  languages: Pick<MonacoLanguages, 'CompletionItemKind'> | undefined,
  model: MonacoModel,
  position: MonacoPosition,
): MonacoCompletionList {
  const kinds = languages?.CompletionItemKind;
  const range = completionRange(model, position);

  return {
    suggestions: suggestions.map((suggestion) => {
      const kindName = KIND_BY_CONTEXT[suggestion.context];
      return {
        label: suggestion.label,
        kind: kinds?.[kindName] ?? COMPLETION_KIND[kindName],
        insertText: suggestion.insertText,
        filterText: suggestion.label,
        detail: suggestion.detail,
        documentation:
          suggestion.documentation === undefined ? undefined : { value: suggestion.documentation },
        range,
      };
    }),
  };
}

function completionsAt(query: CompletionQuery): CompletionSuggestion[] {
  return completeStellarToml(query);
}

// ── worker validator ─────────────────────────────────────────────────────────

interface PendingRequest {
  resolve(result: unknown): void;
  reject(error: Error): void;
}

/**
 * A {@link LintValidator} backed by the shipped lint worker.
 *
 * The protocol is the one `src/worker.ts` already speaks (`{ type: 'lint',
 * content, options, id }`), so this adds no build output of its own: it is what
 * keeps the ~146KB core out of the language bundle while a page still gets live
 * markers. Requests carry an id because a fast typist overlaps them.
 */
export function createWorkerValidator(
  worker: WorkerLike,
  options: { lintOptions?: Record<string, unknown>; onError?: (error: Error) => void } = {},
): LintValidator {
  const pending = new Map<number, PendingRequest>();
  const defaults = options.lintOptions ?? {};
  let nextId = 1;

  const settle = (data: unknown): void => {
    if (typeof data !== 'object' || data === null) return;
    const message = data as {
      id?: unknown;
      type?: unknown;
      result?: unknown;
      message?: unknown;
    };
    if (typeof message.id !== 'number') return;
    const request = pending.get(message.id);
    if (request === undefined) return;
    pending.delete(message.id);

    if (message.type === 'error') {
      const detail = typeof message.message === 'string' ? message.message : 'lint failed';
      request.reject(new Error(detail));
      return;
    }
    if (message.type === 'result') request.resolve(message.result);
  };

  if (typeof worker.onmessage === 'function' || worker.onmessage === null) {
    worker.onmessage = (event) => settle(event.data);
  } else {
    worker.addEventListener?.('message', (event) => settle(event.data));
  }

  return (content, extra) =>
    new Promise<DiagnosticSource>((resolve, reject) => {
      const id = nextId++;
      pending.set(id, {
        resolve: (result) => resolve(result as DiagnosticSource),
        reject: (error) => {
          options.onError?.(error);
          reject(error);
        },
      });
      worker.postMessage({ type: 'lint', content, options: { ...defaults, ...extra }, id });
    });
}

// ── the bundle ───────────────────────────────────────────────────────────────

export interface MonacoLanguageBundleOptions {
  /** Language id to attach to. Defaults to `stellar-toml`. */
  languageId?: string;
  /** Marker owner. Defaults to `stellar-toml-lint`. */
  owner?: string;
}

/** Everything one Monaco language mode needs, as data plus the two mappings. */
export interface MonacoLanguageBundle {
  readonly id: string;
  readonly name: string;
  readonly aliases: readonly string[];
  readonly extensions: readonly string[];
  readonly filenames: readonly string[];
  readonly owner: string;
  readonly languageConfiguration: MonacoLanguageConfiguration;
  readonly monarch: MonarchDefinition;
  /** A provider ready to hand to `registerCompletionProvider`. */
  readonly completionProvider: MonacoCompletionProvider;
  /** SEP-1 completions for a 1-based cursor, independent of any editor. */
  completions(query: CompletionQuery): CompletionSuggestion[];
  /** Monaco markers for a lint result or a bare diagnostic list. */
  markers(input: DiagnosticSource, monaco?: Pick<MonacoLike, 'MarkerSeverity'>): MonacoMarker[];
  /** Publishes markers for one model through `monaco.editor.setModelMarkers`. */
  publish(monaco: MonacoLike, model: MonacoModel, input: DiagnosticSource): MonacoMarker[];
}

export function monacoLanguageBundle(
  options: MonacoLanguageBundleOptions = {},
): MonacoLanguageBundle {
  const id = options.languageId ?? LANGUAGE_ID;
  const owner = options.owner ?? DEFAULT_OWNER;

  const bundle: MonacoLanguageBundle = {
    id,
    name: LANGUAGE_NAME,
    aliases: LANGUAGE_ALIASES,
    extensions: FILE_EXTENSIONS,
    filenames: FILENAMES,
    owner,
    languageConfiguration,
    monarch: monarchDefinition,
    completionProvider: {
      provideCompletionItems: (model, position) =>
        toMonacoCompletions(
          completionsAt({
            content: model.getValue(),
            lineNumber: position.lineNumber,
            column: position.column,
          }),
          undefined,
          model,
          position,
        ),
    },
    completions: completionsAt,
    markers: (input, monaco) => toMonacoMarkers(input, monaco, owner),
    publish: (monaco, model, input) => {
      const markers = toMonacoMarkers(input, monaco, owner);
      monaco.editor.setModelMarkers(model, owner, markers);
      return markers;
    },
  };

  return bundle;
}

export interface RegisterOptions extends MonacoLanguageBundleOptions {
  /** Where findings come from. Required before `validate` can run. */
  validator?: LintValidator;
  /** Options forwarded to the validator with every document. */
  lintOptions?: Record<string, unknown>;
  /** Quiet period before an edit is validated. Defaults to 250 ms. */
  debounceMs?: number;
  /** Replaces the generated grammar, for a page with its own tokens. */
  monarch?: MonarchDefinition;
  /** Replaces the generated language configuration. */
  configuration?: MonacoLanguageConfiguration;
}

export interface MonacoRegistration extends MonacoDisposable {
  readonly bundle: MonacoLanguageBundle;
  /** Runs the validator once and publishes the markers it returns. */
  validate(model: MonacoModel): Promise<MonacoMarker[]>;
  /** Publishes markers the caller already has, e.g. a worker response. */
  publish(model: MonacoModel, input: DiagnosticSource): MonacoMarker[];
  /** Validates `model` on every change, debounced, until disposed. */
  observe(model: MonacoModel): MonacoDisposable;
  /** Clears every marker this registration owns on `model`. */
  clear(model: MonacoModel): void;
}

/**
 * Attaches the bundle to a Monaco instance: grammar, language configuration and
 * completion provider, plus the validation entry points.
 *
 * Everything registered is disposable, because every Monaco API called here
 * returns a disposable and a hot-reloading playground must be able to undo all
 * three at once.
 */
export function register(monaco: MonacoLike, options: RegisterOptions = {}): MonacoRegistration {
  const bundle = monacoLanguageBundle(options);
  const owner = bundle.owner;
  const validator = options.validator;
  const lintOptions = options.lintOptions ?? {};
  const debounceMs = options.debounceMs ?? DEFAULT_DEBOUNCE_MS;

  const disposables: MonacoDisposable[] = [];
  if (monaco.languages.register !== undefined) {
    disposables.push(
      monaco.languages.register({
        id: bundle.id,
        extensions: [...bundle.extensions],
        aliases: [...bundle.aliases],
        filenames: [...bundle.filenames],
      }),
    );
  }
  disposables.push(
    monaco.languages.setMonarchTokensProvider(bundle.id, options.monarch ?? bundle.monarch),
  );
  disposables.push(
    monaco.languages.setLanguageConfiguration(
      bundle.id,
      options.configuration ?? bundle.languageConfiguration,
    ),
  );
  disposables.push(
    monaco.languages.registerCompletionProvider(bundle.id, {
      provideCompletionItems: (model, position) =>
        toMonacoCompletions(
          completionsAt({
            content: model.getValue(),
            lineNumber: position.lineNumber,
            column: position.column,
          }),
          monaco.languages,
          model,
          position,
        ),
    }),
  );

  const timers = new Map<MonacoModel, ReturnType<typeof setTimeout>>();

  const validate = async (model: MonacoModel): Promise<MonacoMarker[]> => {
    if (validator === undefined) {
      throw new Error(
        'stellar.toml validation needs a validator: register(monaco, { validator }) with ' +
          'createWorkerValidator(worker), or a function that wraps lintBrowser.',
      );
    }
    const findings = await validator(model.getValue(), lintOptions);
    return bundle.publish(monaco, model, findings);
  };

  const clear = (model: MonacoModel): void => {
    monaco.editor.setModelMarkers(model, owner, []);
  };

  const observe = (model: MonacoModel): MonacoDisposable => {
    const listener = model.onDidChangeContent?.(() => {
      const existing = timers.get(model);
      if (existing !== undefined) clearTimeout(existing);
      if (debounceMs <= 0) {
        void validate(model);
        return;
      }
      timers.set(
        model,
        setTimeout(() => {
          timers.delete(model);
          void validate(model);
        }, debounceMs),
      );
    });

    return {
      dispose: () => {
        listener?.dispose();
        const timer = timers.get(model);
        if (timer !== undefined) clearTimeout(timer);
        timers.delete(model);
        clear(model);
      },
    };
  };

  return {
    bundle,
    validate,
    publish: (model, input) => bundle.publish(monaco, model, input),
    observe,
    clear,
    dispose: () => {
      for (const timer of timers.values()) clearTimeout(timer);
      timers.clear();
      for (const disposable of disposables) disposable.dispose();
      disposables.length = 0;
    },
  };
}

export { LANGUAGE_ID, LANGUAGE_NAME } from './language.js';
export type { CompletionQuery, CompletionSuggestion, DiagnosticSource } from './language.js';

export default monacoLanguageBundle;
