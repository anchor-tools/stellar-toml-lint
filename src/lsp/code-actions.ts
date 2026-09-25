/**
 * LSP `textDocument/codeAction` providers — interactive quick fixes (#42).
 *
 * Editors request code actions over a range; for every diagnostic that
 * carries a {@link Fix} and falls inside that range we return a `quickfix`
 * `CodeAction` whose `WorkspaceEdit` replaces only the offending value.
 * Unfixable findings (parse errors, missing required tables, …) produce no
 * action rather than an empty edit.
 */
import { computeFixEdits } from '../fix.js';
import type { Diagnostic } from '../types.js';

/** 0-based LSP position. */
export interface LspPosition {
  line: number;
  character: number;
}

/** 0-based LSP range (end exclusive). */
export interface LspRange {
  start: LspPosition;
  end: LspPosition;
}

export interface LspTextEdit {
  range: LspRange;
  newText: string;
}

export interface LspWorkspaceEdit {
  changes: Record<string, LspTextEdit[]>;
}

export interface LspDiagnostic {
  range: LspRange;
  severity?: number;
  code?: string;
  source?: string;
  message: string;
}

export interface LspCodeAction {
  title: string;
  kind: 'quickfix';
  diagnostics?: LspDiagnostic[];
  isPreferred?: boolean;
  edit?: LspWorkspaceEdit;
}

/**
 * Builds quick-fix code actions for diagnostics under `range`.
 *
 * @param source Document text the actions apply to.
 * @param uri    Document URI editors key `WorkspaceEdit.changes` by.
 * @param range  Requested range (0-based, end exclusive).
 */
export function codeActionsFor(
  source: string,
  uri: string,
  diagnostics: Diagnostic[],
  range: LspRange,
): LspCodeAction[] {
  const actions: LspCodeAction[] = [];

  for (const diagnostic of diagnostics) {
    if (!diagnostic.fix || !diagnostic.path || !diagnostic.position) continue;

    const start = {
      line: diagnostic.position.line - 1,
      character: diagnostic.position.column - 1,
    };
    const end = { line: start.line, character: start.character + 1 };
    if (!rangeCovers(range, start, end)) continue;

    const title = titleFor(diagnostic);
    if (!title) continue;

    const edit = singleTextEdit(source, diagnostic);
    if (!edit) continue;

    actions.push({
      title,
      kind: 'quickfix',
      diagnostics: [toLspDiagnostic(diagnostic)],
      isPreferred: true,
      edit: { changes: { [uri]: [edit] } },
    });
  }

  return actions;
}

/** Maps a package diagnostic onto the LSP shape editors understand. */
export function toLspDiagnostic(d: Diagnostic): LspDiagnostic {
  const start = {
    line: (d.position?.line ?? 1) - 1,
    character: (d.position?.column ?? 1) - 1,
  };
  return {
    range: {
      start,
      end: { line: start.line, character: start.character + (d.position ? 1 : 0) },
    },
    severity: d.severity === 'error' ? 1 : d.severity === 'warning' ? 2 : 3,
    code: d.rule,
    source: 'stellar-toml-lint',
    message: d.suggestion ? `${d.message}. ${d.suggestion}` : d.message,
  };
}

function singleTextEdit(source: string, diagnostic: Diagnostic): LspTextEdit | undefined {
  const edits = computeFixEdits(source, [diagnostic]);
  const edit = edits[0];
  if (!edit) return undefined;
  return {
    range: { start: offsetToPosition(source, edit.start), end: offsetToPosition(source, edit.end) },
    newText: edit.text,
  };
}

function titleFor(d: Diagnostic): string | undefined {
  switch (d.rule) {
    case 'general/trailing-slash-in-endpoint':
      return `Fix: Strip trailing slash from ${d.path}`;
    case 'network/passphrase':
      return 'Fix: Normalize NETWORK_PASSPHRASE to the known passphrase';
    case 'documentation/social-handles':
    case 'principals/social-handles':
    case 'general/invalid-twitter-handle':
      return `Fix: Use bare handle for ${d.path}`;
    case 'documentation/phone-e164':
      return `Fix: Format ${d.path} as E.164`;
    default:
      return undefined;
  }
}

function rangeCovers(range: LspRange, start: LspPosition, end: LspPosition): boolean {
  return (
    positionInRange(start, range) ||
    positionInRange(end, range) ||
    spansOverlap(range, {
      start,
      end,
    })
  );
}

function positionInRange(position: LspPosition, range: LspRange): boolean {
  if (position.line < range.start.line || position.line > range.end.line) return false;
  if (position.line === range.start.line && position.character < range.start.character)
    return false;
  if (position.line === range.end.line && position.character > range.end.character) return false;
  return true;
}

function spansOverlap(a: LspRange, b: LspRange): boolean {
  return compare(a.start, b.end) <= 0 && compare(b.start, a.end) <= 0;
}

function compare(a: LspPosition, b: LspPosition): number {
  if (a.line !== b.line) return a.line - b.line;
  return a.character - b.character;
}

/** 0-based LSP position for a source offset. */
export function offsetToPosition(source: string, offset: number): LspPosition {
  let line = 0;
  let character = 0;
  const limit = Math.min(offset, source.length);
  for (let i = 0; i < limit; i++) {
    if (source.charCodeAt(i) === 10) {
      line++;
      character = 0;
    } else {
      character++;
    }
  }
  return { line, character };
}
